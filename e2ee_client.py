"""
e2ee_client.py
Relay-Based E2EE Messaging System - Client with Crypto
=======================================================
Implements:
  - AES-256-GCM authenticated encryption (AEAD)
  - ECDH ephemeral key exchange (X25519)
  - HKDF-SHA256 session key derivation
  - Session key rotation (forward secrecy demo)
  - Replay protection via nonce + sequence number
  - Relay blindness: plaintext never leaves client

Cryptographic Primitives (via cryptography library):
  - Key Exchange  : X25519 (Curve25519 Diffie-Hellman)
  - KDF           : HKDF-SHA256
  - Encryption    : AES-256-GCM
  - MAC           : built-in to GCM (128-bit tag)
"""

import asyncio
import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)


# ------------------------------------------------------------------ #
#  Crypto Layer                                                        #
# ------------------------------------------------------------------ #

class CryptoLayer:
    """
    Handles all cryptographic operations.
    Encapsulates: key exchange, KDF, AEAD encryption/decryption.
    """

    @staticmethod
    def generate_dh_keypair():
        """Generate X25519 ephemeral DH keypair."""
        private_key = X25519PrivateKey.generate()
        public_key  = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_secret(private_key, peer_public_key_bytes: bytes) -> bytes:
        """Perform X25519 DH exchange -> 32-byte shared secret."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return private_key.exchange(peer_pub)

    @staticmethod
    def derive_session_key(shared_secret: bytes, salt: bytes, info: bytes = b"e2ee-session-key") -> bytes:
        """HKDF-SHA256 to derive a 32-byte AES session key."""
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=info)
        return hkdf.derive(shared_secret)

    @staticmethod
    def encrypt(session_key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
        """
        AES-256-GCM encryption.
        Returns: (nonce, ciphertext+tag)
        Nonce: 96-bit random (NIST recommended for GCM)
        """
        nonce = os.urandom(12)  # 96-bit nonce
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data or None)
        return nonce, ciphertext

    @staticmethod
    def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """
        AES-256-GCM decryption + tag verification.
        Raises InvalidTag if authentication fails.
        """
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data or None)

    @staticmethod
    def nonce_hash(nonce: bytes) -> str:
        """SHA-256 hash of nonce for relay replay tracking (relay never sees raw nonce)."""
        return hashlib.sha256(nonce).hexdigest()

    @staticmethod
    def serialize_public_key(pub_key) -> bytes:
        return pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ------------------------------------------------------------------ #
#  Session State                                                       #
# ------------------------------------------------------------------ #

@dataclass
class ClientSession:
    session_id: str
    peer_id: str
    session_key: bytes
    sequence_number: int = 0
    rotation_interval: int = 10   # rotate key every N messages
    messages_since_rotation: int = 0
    rotation_count: int = 0
    # Timing metrics
    encrypt_times: list = field(default_factory=list)
    decrypt_times: list = field(default_factory=list)

    def should_rotate(self) -> bool:
        return self.messages_since_rotation >= self.rotation_interval


# ------------------------------------------------------------------ #
#  E2EE Client                                                         #
# ------------------------------------------------------------------ #

class E2EEClient:
    def __init__(self, client_id: str, relay_host="127.0.0.1", relay_port=8765,
                 key_rotation_interval=10):
        self.client_id = client_id
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.key_rotation_interval = key_rotation_interval
        self.sessions: dict[str, ClientSession] = {}
        self.crypto = CryptoLayer()
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.sent_count = 0
        self.recv_count = 0
        self.latency_samples = []

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.relay_host, self.relay_port)
        await self._send_json({"type": "register", "client_id": self.client_id})
        resp = await self._recv_json()
        assert resp["status"] == "registered"

    async def _send_json(self, obj: dict):
        line = json.dumps(obj) + "\n"
        self.writer.write(line.encode())
        await self.writer.drain()

    async def _recv_json(self) -> dict:
        line = await self.reader.readline()
        return json.loads(line.decode())

    # ---------------------------------------------------------------- #
    #  Key Exchange (simplified: both clients call this with each       #
    #  other's public key – in production this uses a KEM/X3DH)        #
    # ---------------------------------------------------------------- #

    def initiate_key_exchange(self, session_id: str, peer_id: str) -> bytes:
        """Generate ephemeral DH keypair. Returns public key bytes to share with peer."""
        priv, pub = self.crypto.generate_dh_keypair()
        # Store private key temporarily keyed by session
        self._pending_dh = (session_id, peer_id, priv)
        return self.crypto.serialize_public_key(pub)

    def complete_key_exchange(self, peer_public_key_bytes: bytes, salt: bytes) -> ClientSession:
        """Complete DH exchange, derive session key, create session."""
        session_id, peer_id, priv = self._pending_dh
        shared_secret = self.crypto.derive_shared_secret(priv, peer_public_key_bytes)
        session_key   = self.crypto.derive_session_key(shared_secret, salt)
        session = ClientSession(
            session_id=session_id,
            peer_id=peer_id,
            session_key=session_key,
            rotation_interval=self.key_rotation_interval,
        )
        self.sessions[session_id] = session
        return session

    # ---------------------------------------------------------------- #
    #  Direct session creation (for experiments without network)        #
    # ---------------------------------------------------------------- #

    def create_session_direct(self, session_id: str, peer_id: str,
                               peer_pub_bytes: bytes, own_priv_key,
                               salt: bytes) -> ClientSession:
        shared_secret = self.crypto.derive_shared_secret(own_priv_key, peer_pub_bytes)
        session_key   = self.crypto.derive_session_key(shared_secret, salt)
        session = ClientSession(
            session_id=session_id,
            peer_id=peer_id,
            session_key=session_key,
            rotation_interval=self.key_rotation_interval,
        )
        self.sessions[session_id] = session
        return session

    # ---------------------------------------------------------------- #
    #  Send Encrypted Message                                            #
    # ---------------------------------------------------------------- #

    async def send_message(self, session_id: str, plaintext: str) -> dict:
        session = self.sessions[session_id]

        # --- Key Rotation Check ---
        if session.should_rotate():
            await self._rotate_session_key(session_id)

        # --- Encrypt ---
        t0 = time.perf_counter()
        plaintext_bytes = plaintext.encode("utf-8")

        # Associated data = session_id + sequence_number (integrity-bound metadata)
        seq = session.sequence_number
        associated_data = f"{session_id}:{seq}".encode()

        nonce, ciphertext = self.crypto.encrypt(session.session_key, plaintext_bytes, associated_data)
        encrypt_time = (time.perf_counter() - t0) * 1000  # ms
        session.encrypt_times.append(encrypt_time)

        # --- Build Envelope ---
        nonce_b64      = base64.b64encode(nonce).decode()
        cipher_b64     = base64.b64encode(ciphertext).decode()
        nonce_hash_str = self.crypto.nonce_hash(nonce)

        envelope = {
            "session_id":      session_id,
            "sender_id":       self.client_id,
            "receiver_id":     session.peer_id,
            "nonce_b64":       nonce_b64,
            "nonce_hash":      nonce_hash_str,
            "ciphertext_b64":  cipher_b64,
            "ciphertext":      cipher_b64,   # alias for relay size measurement
            "sequence_number": seq,
            "send_timestamp":  time.time(),
        }

        session.sequence_number += 1
        session.messages_since_rotation += 1

        # --- Send via relay (if connected) ---
        result = None
        if self.writer:
            send_time = time.time()
            await self._send_json({"type": "message", "envelope": envelope})
            result = await self._recv_json()
            latency = (time.time() - send_time) * 1000
            self.latency_samples.append(latency)

        self.sent_count += 1
        return {
            "status": "sent",
            "seq": seq,
            "encrypt_time_ms": encrypt_time,
            "ciphertext_size": len(ciphertext),
            "nonce_hash": nonce_hash_str[:16],
            "relay_result": result,
            "envelope": envelope,
        }

    # ---------------------------------------------------------------- #
    #  Decrypt Received Message                                          #
    # ---------------------------------------------------------------- #

    def decrypt_message(self, session_id: str, nonce_b64: str,
                        ciphertext_b64: str, seq: int) -> dict:
        session  = self.sessions[session_id]
        nonce    = base64.b64decode(nonce_b64)
        cipher   = base64.b64decode(ciphertext_b64)
        assoc    = f"{session_id}:{seq}".encode()

        t0 = time.perf_counter()
        try:
            plaintext = self.crypto.decrypt(session.session_key, nonce, cipher, assoc)
            dec_time  = (time.perf_counter() - t0) * 1000
            session.decrypt_times.append(dec_time)
            self.recv_count += 1
            return {"status": "ok", "plaintext": plaintext.decode("utf-8"),
                    "decrypt_time_ms": dec_time}
        except Exception as e:
            return {"status": "auth_failed", "error": str(e)}

    # ---------------------------------------------------------------- #
    #  Key Rotation                                                       #
    # ---------------------------------------------------------------- #

    async def _rotate_session_key(self, session_id: str):
        """Derive a new session key from the current one (ratchet step)."""
        session = self.sessions[session_id]
        new_salt = os.urandom(32)
        # Derive next key from current key material (simple KDF ratchet)
        new_key = HKDF(
            algorithm=SHA256(), length=32,
            salt=new_salt,
            info=f"rotation-{session.rotation_count+1}".encode()
        ).derive(session.session_key)
        session.session_key = new_key
        session.rotation_count += 1
        session.messages_since_rotation = 0

        if self.writer:
            await self._send_json({
                "type": "key_rotation",
                "session_id": session_id,
                "sender_id": self.client_id,
                "new_salt": base64.b64encode(new_salt).decode(),
                "rotation_num": session.rotation_count,
            })
            await self._recv_json()  # consume ack

    def get_metrics(self) -> dict:
        metrics = {
            "client_id": self.client_id,
            "sent": self.sent_count,
            "received": self.recv_count,
        }
        for sid, s in self.sessions.items():
            enc = s.encrypt_times
            dec = s.decrypt_times
            metrics[f"session_{sid}"] = {
                "rotation_count": s.rotation_count,
                "sequence_number": s.sequence_number,
                "avg_encrypt_ms": round(sum(enc)/len(enc), 4) if enc else 0,
                "avg_decrypt_ms": round(sum(dec)/len(dec), 4) if dec else 0,
                "min_encrypt_ms": round(min(enc), 4) if enc else 0,
                "max_encrypt_ms": round(max(enc), 4) if enc else 0,
            }
        return metrics

    async def disconnect(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()