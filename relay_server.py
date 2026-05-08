"""
relay_server.py
Relay-Based E2EE Messaging System - Demo Relay Server
======================================================
The relay server is intentionally "blind":
  - It NEVER sees plaintext message content.
  - It DOES observe metadata: sender_id, receiver_id, timestamp, message_size, session_id.
  - It enforces replay protection by rejecting duplicate nonces per session.
  - It routes ciphertext blobs without decryption.

Security Properties Demonstrated:
  - Relay Blindness: relay only handles encrypted blobs
  - Replay Protection: nonce deduplication per session
  - Metadata Exposure: logs observable fields for analysis
  - Session Management: tracks active sessions
"""

import asyncio
import json
import logging
import time
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, Set, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RELAY] %(message)s")
log = logging.getLogger("relay")


@dataclass
class RelayMetadata:
    """Metadata observable by the relay (no plaintext)."""
    sender_id: str
    receiver_id: str
    session_id: str
    sequence_number: int
    message_size: int       # bytes of ciphertext
    timestamp: float
    nonce_hash: str         # hash of nonce – relay never sees raw nonce


@dataclass
class SessionState:
    session_id: str
    participant_a: str
    participant_b: str
    created_at: float = field(default_factory=time.time)
    message_count: int = 0
    seen_nonces: Set[str] = field(default_factory=set)
    key_rotation_count: int = 0
    last_sequence: Dict[str, int] = field(default_factory=dict)


class RelayServer:
    def __init__(self, host="127.0.0.1", port=8765):
        self.host = host
        self.port = port
        self.sessions: Dict[str, SessionState] = {}
        self.connected_clients: Dict[str, asyncio.StreamWriter] = {}
        self.metadata_log: list = []          # observable metadata store
        self.replay_rejections: int = 0
        self.total_messages: int = 0
        self.latency_samples: list = []

    # ------------------------------------------------------------------ #
    #  Session Management                                                  #
    # ------------------------------------------------------------------ #
    def create_session(self, session_id: str, a: str, b: str) -> SessionState:
        s = SessionState(session_id=session_id, participant_a=a, participant_b=b)
        self.sessions[session_id] = s
        log.info(f"Session created: {session_id} ({a} <-> {b})")
        return s

    # ------------------------------------------------------------------ #
    #  Replay Protection                                                   #
    # ------------------------------------------------------------------ #
    def check_replay(self, session_id: str, nonce_hash: str, seq: int, sender: str) -> bool:
        """
        Returns True if message is VALID (not a replay).
        Relay stores nonce hashes – never raw nonces or plaintext.
        """
        s = self.sessions.get(session_id)
        if s is None:
            return False

        # Nonce uniqueness check
        if nonce_hash in s.seen_nonces:
            self.replay_rejections += 1
            log.warning(f"REPLAY DETECTED  session={session_id} nonce={nonce_hash[:8]}...")
            return False
        s.seen_nonces.add(nonce_hash)

        # Sequence number monotonicity check (per-sender)
        last_seq = s.last_sequence.get(sender, -1)
        if seq <= last_seq:
            self.replay_rejections += 1
            log.warning(f"SEQ REPLAY  session={session_id} sender={sender} seq={seq} last={last_seq}")
            return False
        s.last_sequence[sender] = seq
        return True

    # ------------------------------------------------------------------ #
    #  Message Routing                                                     #
    # ------------------------------------------------------------------ #
    async def route_message(self, envelope: dict) -> dict:
        """
        Core relay routing logic. Returns a result dict.
        Relay sees: session_id, sender_id, receiver_id, nonce_hash, seq, ciphertext (opaque blob).
        Relay NEVER sees plaintext.
        """
        recv_time = time.time()
        session_id  = envelope["session_id"]
        sender_id   = envelope["sender_id"]
        receiver_id = envelope["receiver_id"]
        nonce_hash  = envelope["nonce_hash"]
        seq         = envelope["sequence_number"]
        ciphertext  = envelope["ciphertext"]       # opaque bytes (base64 string)
        send_time   = envelope.get("send_timestamp", recv_time)

        # --- Relay Protection Check ---
        if not self.check_replay(session_id, nonce_hash, seq, sender_id):
            return {"status": "rejected", "reason": "replay_detected"}

        # --- Record observable metadata ---
        meta = RelayMetadata(
            sender_id=sender_id,
            receiver_id=receiver_id,
            session_id=session_id,
            sequence_number=seq,
            message_size=len(ciphertext),
            timestamp=recv_time,
            nonce_hash=nonce_hash[:16] + "...",
        )
        self.metadata_log.append(asdict(meta))
        self.sessions[session_id].message_count += 1
        self.total_messages += 1

        # --- Latency sample ---
        latency_ms = (recv_time - send_time) * 1000
        self.latency_samples.append(latency_ms)

        log.info(
            f"ROUTE  {sender_id}->{receiver_id}  session={session_id}"
            f"  seq={seq}  size={len(ciphertext)}B  latency={latency_ms:.2f}ms"
        )

        # --- Forward to receiver (if connected) ---
        receiver_writer = self.connected_clients.get(receiver_id)
        if receiver_writer:
            forward = json.dumps({"type": "message", "envelope": envelope}) + "\n"
            receiver_writer.write(forward.encode())
            await receiver_writer.drain()

        return {
            "status": "delivered",
            "relay_timestamp": recv_time,
            "latency_ms": latency_ms,
            "session_id": session_id,
            "seq": seq,
        }

    async def handle_key_rotation(self, session_id: str, sender_id: str, full_msg: dict):
        s = self.sessions.get(session_id)
        if s:
            s.key_rotation_count += 1
            log.info(f"KEY ROTATION  session={session_id}  rotation_count={s.key_rotation_count}")
            # Forward the full message (including new_salt) to the other participant
            other_id = s.participant_b if sender_id == s.participant_a else s.participant_a
            other_writer = self.connected_clients.get(other_id)
            if other_writer:
                fwd = json.dumps(full_msg) + "\n"
                other_writer.write(fwd.encode())
                await other_writer.drain()

    # ------------------------------------------------------------------ #
    #  TCP Server Handler                                                  #
    # ------------------------------------------------------------------ #
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        client_id = None
        log.info(f"New connection from {peer}")
        try:
            async for raw_line in reader:
                if not raw_line.strip():
                    continue
                try:
                    msg = json.loads(raw_line.decode())
                except json.JSONDecodeError:
                    continue

                mtype = msg.get("type")

                if mtype == "register":
                    client_id = msg["client_id"]
                    self.connected_clients[client_id] = writer
                    log.info(f"Registered client: {client_id}")
                    writer.write(json.dumps({"status": "registered", "client_id": client_id}).encode() + b"\n")
                    await writer.drain()

                elif mtype == "create_session":
                    s = self.create_session(msg["session_id"], msg["participant_a"], msg["participant_b"])
                    writer.write(json.dumps({"status": "session_created", "session_id": s.session_id}).encode() + b"\n")
                    await writer.drain()

                elif mtype == "message":
                    result = await self.route_message(msg["envelope"])
                    writer.write(json.dumps(result).encode() + b"\n")
                    await writer.drain()

                elif mtype == "key_rotation":
                    await self.handle_key_rotation(msg["session_id"], msg["sender_id"], msg)
                    writer.write(json.dumps({"status": "rotation_noted"}).encode() + b"\n")
                    await writer.drain()

                # elif mtype == "relay_forward":
                #     # Key-exchange passthrough
                #     to_id = msg.get("to")
                #     to_writer = self.connected_clients.get(to_id)
                #     if to_writer:
                #         fwd = json.dumps({
                #             "type": "relay_forward",
                #             "from": client_id,
                #             "payload": msg.get("payload", {})
                #         }) + "\n"
                #         to_writer.write(fwd.encode())
                #         await to_writer.drain()
                #         log.info(f"FORWARD {client_id} -> {to_id}")
                #         writer.write(json.dumps({"status": "forwarded"}).encode() + b"\n")
                #     else:
                #         writer.write(json.dumps({"status": "peer_not_connected"}).encode() + b"\n")
                #     await writer.drain()

                elif mtype == "get_stats":
                    writer.write(json.dumps(self.get_stats()).encode() + b"\n")
                    await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        finally:
            if client_id and client_id in self.connected_clients:
                del self.connected_clients[client_id]
            writer.close()
            log.info(f"Connection closed: {peer}")

    def get_stats(self) -> dict:
        latencies = self.latency_samples
        return {
            "total_messages": self.total_messages,
            "replay_rejections": self.replay_rejections,
            "active_sessions": len(self.sessions),
            "connected_clients": len(self.connected_clients),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0,
            "min_latency_ms": round(min(latencies), 3) if latencies else 0,
            "max_latency_ms": round(max(latencies), 3) if latencies else 0,
            "metadata_records": len(self.metadata_log),
        }

    async def run(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        log.info(f"Relay server listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    relay = RelayServer()
    asyncio.run(relay.run())
