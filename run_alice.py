"""
run_alice.py  —  Terminal 2: Start AFTER relay AND bob are running
Key exchange via session.json: reads bob public key, writes alice public key + salt
"""
import asyncio, base64, hashlib, json, os, sys, time
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from e2ee_client import CryptoLayer
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

C   = CryptoLayer()
DIR = Path(__file__).parent
SESSION_FILE = DIR / "session.json"

BL = "\033[94m"; G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
C2 = "\033[96m"; P = "\033[95m"; D = "\033[2m"; B = "\033[1m"; X = "\033[0m"

def pr(msg): print(f"{D}{time.strftime('%H:%M:%S')}{X} {BL}{B}[ALICE]{X} {msg}", flush=True)

def read_session() -> dict:
    try:
        return json.loads(SESSION_FILE.read_text())
    except Exception:
        return {}

def write_session(data: dict):
    """Atomic write to session.json via a temp file."""
    tmp = SESSION_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(SESSION_FILE)

async def send_json(w, obj): w.write((json.dumps(obj)+"\n").encode()); await w.drain()
async def recv_json(r):      return json.loads((await r.readline()).decode())

SESSION_ID = "alice-bob-demo"

MESSAGES = [
    "Hello Bob! Secure channel established.",
    "Sending auth token: Bearer eyJhbGciOiJSUzI1NiJ9...",
    "Status update: pipeline stage 2 complete.",
    "Requesting data chunk at offset=4096.",
    "ACK received — all good on my end.",
    "About to rotate session key for forward secrecy...",
    "Post-rotation msg 1 — new session key active.",
    "Post-rotation msg 2 — forward secrecy confirmed. Done!",
]

async def main():
    print(f"\n{B}{BL}{'='*52}{X}")
    print(f"{B}{BL}  Alice — E2EE Client (Initiator)  —  Terminal 2{X}")
    print(f"{B}{BL}{'='*52}{X}\n")

    reader, writer = await asyncio.open_connection("127.0.0.1", 8765)
    await send_json(writer, {"type": "register", "client_id": "alice"})
    await recv_json(reader)
    pr(f"{G}Registered with relay [OK]{X}")

    # ── Key Exchange via session.json ─────────────────────────────
    pr(f"{Y}Waiting for Bob to write session.json (bob_ready=true)...{X}")

    # Poll until Bob has written his public key
    while True:
        await asyncio.sleep(0.3)
        data = read_session()
        if data.get("bob_ready") and "bob_pub_key" in data:
            break

    bob_pub = base64.b64decode(data["bob_pub_key"])
    pr(f"Bob pub_key read ← {C2}session.json{X}")
    pr(f"  pub_key = {C2}{bob_pub.hex()[:20]}... (32 B){X}")

    pr("Generating X25519 ephemeral keypair...")
    priv_a, pub_a = C.generate_dh_keypair()
    pub_a_bytes   = C.serialize_public_key(pub_a)
    salt          = os.urandom(32)
    pr(f"  pub_key = {C2}{pub_a_bytes.hex()[:20]}... (32 B){X}")
    pr(f"  salt    = {D}{salt.hex()[:20]}... (32 B){X}")

    # Update session.json with Alice's fields (preserve Bob's data)
    data.update({
        "alice_ready": True,
        "alice_pub_key": base64.b64encode(pub_a_bytes).decode(),
        "salt": base64.b64encode(salt).decode(),
    })
    write_session(data)
    pr(f"Public key + salt written → {C2}session.json{X}  (alice_ready=true)")

    shared      = C.derive_shared_secret(priv_a, bob_pub)
    session_key = C.derive_session_key(shared, salt)
    pr(f"X25519 DH   → shared_secret = {P}{shared.hex()[:20]}...{X}")
    pr(f"HKDF-SHA256 → session_key   = {P}{session_key.hex()[:20]}...{X}")
    pr(f"{G}Session key established [OK]{X}")

    await send_json(writer, {"type": "create_session", "session_id": SESSION_ID,
                             "participant_a": "alice", "participant_b": "bob"})
    await recv_json(reader)
    pr(f"Relay session created: {C2}{SESSION_ID}{X}\n")

    # ── Send Messages ─────────────────────────────────────────────
    pr(f"{B}─── Sending {len(MESSAGES)} encrypted messages ────────────────{X}")
    rot = 0
    for seq, plaintext in enumerate(MESSAGES):

        if seq == 6:
            rot += 1
            print()
            pr(f"{Y}⟳  Triggering key rotation #{rot} (forward secrecy){X}")
            new_salt    = os.urandom(32)
            session_key = HKDF(SHA256(), 32, new_salt,
                               f"rotation-{rot}".encode()).derive(session_key)
            pr(f"   HKDF ratchet → new session_key = {P}{session_key.hex()[:20]}...{X}")
            await send_json(writer, {"type": "key_rotation",
                                     "session_id": SESSION_ID, "sender_id": "alice",
                                     "new_salt": base64.b64encode(new_salt).decode(),
                                     "rotation_num": rot})
            await recv_json(reader)
            pr(f"   {G}Rotation complete [OK]  Bob will ratchet on next recv{X}\n")

        assoc  = f"{SESSION_ID}:{seq}".encode()
        t0     = time.perf_counter()
        nonce, ciphertext = C.encrypt(session_key, plaintext.encode(), assoc)
        enc_us = (time.perf_counter() - t0) * 1e6
        nonce_hash = hashlib.sha256(nonce).hexdigest()

        pr(f"→ seq={C2}{seq}{X}  plain={G}\"{plaintext}\"{X}")
        pr(f"  nonce   = {D}{nonce.hex()[:20]}...{X}")
        pr(f"  encrypt = {C2}{enc_us:.1f}µs{X}  size={C2}{len(ciphertext)}B{X}  overhead={C2}+16B GCM tag{X}")

        envelope = {
            "session_id": SESSION_ID, "sender_id": "alice", "receiver_id": "bob",
            "nonce_b64": base64.b64encode(nonce).decode(),
            "nonce_hash": nonce_hash,
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "sequence_number": seq, "send_timestamp": time.time(),
        }
        await send_json(writer, {"type": "message", "envelope": envelope})
        resp = await recv_json(reader)
        if resp.get("status") == "delivered":
            pr(f"  relay   → {G}delivered [OK]{X}  latency={C2}{resp.get('latency_ms',0):.2f}ms{X}")
        else:
            pr(f"  relay   → {R}REJECTED: {resp.get('reason')}{X}")
        await asyncio.sleep(1.2)
        
    print()
    pr(f"{G}{B}All {len(MESSAGES)} messages sent. Demo complete [OK]{X}")
    # print()
    # pr(f"{Y}Sending shutdown signal to Bob...{X}")
    # await send_json(writer, {"type": "session_close"})
    writer.close()
    await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())