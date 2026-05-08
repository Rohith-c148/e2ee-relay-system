"""
run_bob.py  —  Terminal 3: Start AFTER relay, BEFORE alice
Key exchange via session.json: writes bob public key, reads alice public key + salt
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

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
C2 = "\033[96m"; P = "\033[95m"; D = "\033[2m"; B = "\033[1m"; X = "\033[0m"

def pr(msg): print(f"{D}{time.strftime('%H:%M:%S')}{X} {G}{B}[BOB  ]{X} {msg}", flush=True)

def write_session(data: dict):
    """Atomic write to session.json via a temp file."""
    tmp = SESSION_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(SESSION_FILE)

def read_session() -> dict:
    try:
        return json.loads(SESSION_FILE.read_text())
    except Exception:
        return {}

async def send_json(w, obj): w.write((json.dumps(obj)+"\n").encode()); await w.drain()
async def recv_json(r):      return json.loads((await r.readline()).decode())

SESSION_ID = "alice-bob-demo"

async def main():
    # Bob owns cleanup of session.json at startup
    SESSION_FILE.unlink(missing_ok=True)

    print(f"\n{B}{G}{'='*52}{X}")
    print(f"{B}{G}  Bob — E2EE Client (Receiver)  —  Terminal 3{X}")
    print(f"{B}{G}{'='*52}{X}\n")

    reader, writer = await asyncio.open_connection("127.0.0.1", 8765)
    await send_json(writer, {"type": "register", "client_id": "bob"})
    await recv_json(reader)
    pr(f"{G}Registered with relay [OK]{X}")

    # ── Key Exchange via session.json ─────────────────────────────
    pr("Generating X25519 ephemeral keypair...")
    priv_b, pub_b = C.generate_dh_keypair()
    pub_b_bytes   = C.serialize_public_key(pub_b)
    pr(f"  pub_key = {C2}{pub_b_bytes.hex()[:20]}... (32 B){X}")

    # Write Bob's public key to session.json — signals Alice that Bob is ready
    write_session({
        "bob_ready": True,
        "bob_pub_key": base64.b64encode(pub_b_bytes).decode(),
    })
    pr(f"Public key written → {C2}session.json{X}  (bob_ready=true)")
    pr(f"{Y}Waiting for Alice to write her public key + salt into session.json...{X}")

    # Poll until Alice adds her fields
    while True:
        await asyncio.sleep(0.3)
        data = read_session()
        if data.get("alice_ready") and "alice_pub_key" in data and "salt" in data:
            break

    alice_pub = base64.b64decode(data["alice_pub_key"])
    salt      = base64.b64decode(data["salt"])
    pr(f"Alice pub_key read ← {C2}session.json{X}")
    pr(f"  pub_key = {C2}{alice_pub.hex()[:20]}... (32 B){X}")
    pr(f"  salt    = {D}{salt.hex()[:20]}... (32 B){X}")

    shared      = C.derive_shared_secret(priv_b, alice_pub)
    session_key = C.derive_session_key(shared, salt)
    pr(f"X25519 DH   → shared_secret = {P}{shared.hex()[:20]}...{X}")
    pr(f"HKDF-SHA256 → session_key   = {P}{session_key.hex()[:20]}...{X}")
    pr(f"{G}Session key established [OK]  (matches Alice's key){X}")

    print()
    pr(f"{B}─── Listening for encrypted messages ────────────────{X}")

    rot = 0
    while True:
        try:
            msg = await asyncio.wait_for(recv_json(reader), timeout=60)
        except (asyncio.TimeoutError, Exception):
            break

        mtype = msg.get("type")

        if mtype == "session_close":
            pr(f"{Y}Received shutdown signal from Alice. Closing session.{X}")
            break

        if mtype == "key_rotation":
            rot += 1
            new_salt     = base64.b64decode(msg["new_salt"])
            rotation_num = msg.get("rotation_num", rot)
            session_key  = HKDF(SHA256(), 32, new_salt,
                                f"rotation-{rotation_num}".encode()).derive(session_key)
            pr(f"{Y}⟳  Key rotation #{rotation_num} received — ratcheting session key{X}")
            pr(f"   new session_key = {P}{session_key.hex()[:20]}...{X}")
            continue

        env = msg.get("envelope") or (msg if "nonce_b64" in msg else None)
        if env is None:
            continue

        seq        = env.get("sequence_number", "?")
        nonce      = base64.b64decode(env["nonce_b64"])
        ciphertext = base64.b64decode(env["ciphertext_b64"])
        assoc      = f"{SESSION_ID}:{seq}".encode()

        t0 = time.perf_counter()
        try:
            plaintext = C.decrypt(session_key, nonce, ciphertext, assoc)
            dec_us    = (time.perf_counter() - t0) * 1e6
            pr(f"← seq={C2}{seq}{X}  decrypt={C2}{dec_us:.1f}µs{X}  "
               f"plain={G}\"{plaintext.decode()}\"{X}")
        except Exception as e:
            pr(f"{R}← seq={seq}  AUTH FAILED: {e}{X}")

    print()
    pr(f"{G}{B}Session ended. Goodbye.{X}")
    writer.close()

if __name__ == "__main__":
    asyncio.run(main())