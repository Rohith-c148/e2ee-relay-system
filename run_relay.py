"""
run_relay.py  —  Terminal 1: Start this FIRST
Starts the relay server. Keep this running throughout the demo.
"""
import asyncio, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from relay_server import RelayServer

async def main():
    print("\n" + "="*52)
    print("  [RELAY] E2EE Relay Server  —  127.0.0.1:8765")
    print("  Relay is BLIND: never stores or sees plaintext")
    print("="*52 + "\n")
    relay = RelayServer()
    await relay.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[RELAY] Shutting down.")
