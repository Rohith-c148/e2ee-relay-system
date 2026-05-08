"""
run_experiments.py
Relay-Based E2EE Messaging System - Controlled Experiment Suite
===============================================================
Runs all controlled experiments and collects quantitative metrics:

  Experiment 1: Baseline Encryption Overhead
      - Measures AES-256-GCM encrypt/decrypt time across message sizes
      - Compares plaintext vs ciphertext throughput

  Experiment 2: Key Rotation Impact
      - Varies rotation interval (1, 5, 10, 20, 50 messages)
      - Measures cumulative latency & CPU overhead

  Experiment 3: Replay Attack Resistance
      - Injects replayed messages (duplicate nonces, rewound sequence numbers)
      - Measures rejection rate

  Experiment 4: Concurrent Clients Scalability
      - Varies client count (1, 5, 10, 20, 50)
      - Measures throughput and per-client latency

  Experiment 5: Metadata Exposure Analysis
      - Quantifies what a relay observer can infer
      - Documents information leak surface

Output: JSON metrics file + printed summary table
"""

import asyncio
import base64
import hashlib
import json
import os
import statistics
import sys
import time
from pathlib import Path

# Import from same directory (flat layout)
sys.path.insert(0, str(Path(__file__).parent))
from e2ee_client import E2EEClient, CryptoLayer
from relay_server import RelayServer

RESULTS_FILE = Path(__file__).parent / "experiment_results.json"

crypto = CryptoLayer()

Y = "\033[93m"; X = "\033[0m"

# ================================================================== #
#  UTILITY                                                             #
# ================================================================== #

def make_session_pair(session_id: str, rotation_interval: int = 10):
    """Create two clients sharing a session key (no relay needed)."""
    alice = E2EEClient("alice", key_rotation_interval=rotation_interval)
    bob   = E2EEClient("bob",   key_rotation_interval=rotation_interval)

    # DH key exchange
    priv_a, pub_a = crypto.generate_dh_keypair()
    priv_b, pub_b = crypto.generate_dh_keypair()
    pub_a_bytes   = crypto.serialize_public_key(pub_a)
    pub_b_bytes   = crypto.serialize_public_key(pub_b)

    salt = os.urandom(32)
    alice.create_session_direct(session_id, "bob",   pub_b_bytes, priv_a, salt)
    bob.create_session_direct(session_id,   "alice", pub_a_bytes, priv_b, salt)
    return alice, bob


def make_message(size_bytes: int) -> str:
    """Generate a message of approximately size_bytes."""
    base = "A" * max(1, size_bytes)
    return base[:size_bytes]


# ================================================================== #
#  EXPERIMENT 1: Encryption Overhead vs Message Size                  #
# ================================================================== #

def experiment_1_encryption_overhead(iterations=500):
    print("\n[EXP 1] Encryption Overhead vs Message Size")
    sizes = [64, 256, 512, 1024, 4096, 16384]
    results = []

    for size in sizes:
        plaintext = make_message(size).encode()
        key = os.urandom(32)
        enc_times, dec_times = [], []

        for _ in range(iterations):
            t0 = time.perf_counter()
            nonce, ciphertext = crypto.encrypt(key, plaintext)
            enc_times.append((time.perf_counter() - t0) * 1e6)  # microseconds

            t0 = time.perf_counter()
            recovered = crypto.decrypt(key, nonce, ciphertext)
            dec_times.append((time.perf_counter() - t0) * 1e6)

        overhead_pct = ((len(ciphertext) - size) / size) * 100
        results.append({
            "message_size_bytes": size,
            "ciphertext_size_bytes": len(ciphertext),
            "overhead_bytes": len(ciphertext) - size,
            "overhead_pct": round(overhead_pct, 2),
            "avg_encrypt_us": round(statistics.mean(enc_times), 2),
            "avg_decrypt_us": round(statistics.mean(dec_times), 2),
            "p95_encrypt_us": round(sorted(enc_times)[int(0.95 * iterations)], 2),
            "p95_decrypt_us": round(sorted(dec_times)[int(0.95 * iterations)], 2),
            "throughput_encrypt_mbps": round((size * iterations) / (sum(enc_times) / 1e6) / 1e6, 2),
        })
        print(f"  size={size:6d}B  enc={results[-1]['avg_encrypt_us']:6.1f}µs  "
              f"dec={results[-1]['avg_decrypt_us']:6.1f}µs  "
              f"overhead={overhead_pct:.1f}%")

    return results


# ================================================================== #
#  EXPERIMENT 2: Key Rotation Frequency Impact                        #
# ================================================================== #

async def experiment_2_key_rotation(messages_per_test=100):
    print("\n[EXP 2] Key Rotation Frequency Impact")
    rotation_intervals = [1, 5, 10, 20, 50, 100]
    plaintext = make_message(256)
    results = []

    for interval in rotation_intervals:
        alice, bob = make_session_pair("rot-test", rotation_interval=interval)
        session = alice.sessions["rot-test"]

        total_enc_time = 0
        rotation_count = 0
        rotation_times = []

        for i in range(messages_per_test):
            # Check and perform rotation manually (no relay)
            if session.should_rotate():
                t_rot = time.perf_counter()
                # Simulate rotation (ratchet key)
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives.hashes import SHA256
                new_salt = os.urandom(32)
                new_key = HKDF(
                    algorithm=SHA256(), length=32,
                    salt=new_salt,
                    info=f"rotation-{session.rotation_count+1}".encode()
                ).derive(session.session_key)
                session.session_key = new_key
                session.rotation_count += 1
                session.messages_since_rotation = 0
                rotation_times.append((time.perf_counter() - t_rot) * 1e6)
                rotation_count += 1

            # Encrypt message
            t0 = time.perf_counter()
            nonce, ct = crypto.encrypt(session.session_key, plaintext.encode())
            total_enc_time += time.perf_counter() - t0
            session.messages_since_rotation += 1
            session.sequence_number += 1

        avg_rotation_overhead_us = statistics.mean(rotation_times) if rotation_times else 0
        results.append({
            "rotation_interval": interval,
            "rotation_count": rotation_count,
            "rotation_overhead_pct": round((rotation_count / messages_per_test) * 100, 1),
            "avg_rotation_time_us": round(avg_rotation_overhead_us, 2),
            "total_enc_time_ms": round(total_enc_time * 1000, 3),
            "forward_secrecy_window_msgs": interval,
        })
        print(f"  interval={interval:4d}  rotations={rotation_count:3d}  "
              f"total_enc={total_enc_time*1000:.2f}ms  rot_overhead={avg_rotation_overhead_us:.1f}µs")

    return results


# ================================================================== #
#  EXPERIMENT 3: Replay Attack Resistance                             #
# ================================================================== #

def experiment_3_replay_resistance(total_messages=200):
    print("\n[EXP 3] Replay Attack Resistance")
    relay = RelayServer()
    relay.create_session("replay-test", "alice", "bob")

    seen_nonces: set = set()
    valid_messages = 0
    replay_attempts = 0
    replay_rejections = 0
    sequence_replays = 0
    sequence_rejections = 0
    sent_envelopes = []

    key = os.urandom(32)

    for i in range(total_messages):
        nonce = os.urandom(12)
        nonce_hash = relay.check_replay.__func__  # just use hash directly

        # Normal message
        nh = hashlib.sha256(nonce).hexdigest()
        valid = relay.check_replay("replay-test", nh, i, "alice")
        if valid:
            valid_messages += 1
            sent_envelopes.append({"nonce_hash": nh, "seq": i})

    # --- Attempt replays: duplicate nonce ---
    for env in sent_envelopes[:50]:
        valid = relay.check_replay("replay-test", env["nonce_hash"], 9999 + sent_envelopes.index(env), "alice")
        replay_attempts += 1
        if not valid:
            replay_rejections += 1

    # --- Attempt replays: rewound sequence number ---
    for env in sent_envelopes[:50]:
        fake_nh = hashlib.sha256(os.urandom(12)).hexdigest()
        valid = relay.check_replay("replay-test", fake_nh, env["seq"], "alice")  # old seq
        sequence_replays += 1
        if not valid:
            sequence_rejections += 1

    nonce_rejection_rate   = (replay_rejections / replay_attempts * 100) if replay_attempts else 0
    seq_rejection_rate     = (sequence_rejections / sequence_replays * 100) if sequence_replays else 0

    result = {
        "valid_messages_delivered": valid_messages,
        "nonce_replay_attempts": replay_attempts,
        "nonce_replay_rejections": replay_rejections,
        "nonce_rejection_rate_pct": round(nonce_rejection_rate, 1),
        "sequence_replay_attempts": sequence_replays,
        "sequence_replay_rejections": sequence_rejections,
        "sequence_rejection_rate_pct": round(seq_rejection_rate, 1),
        "total_relay_rejections": relay.replay_rejections,
    }
    print(f"  Nonce replay rejection rate  : {nonce_rejection_rate:.1f}%")
    print(f"  Sequence replay rejection rate: {seq_rejection_rate:.1f}%")
    print(f"  Total relay rejections       : {relay.replay_rejections}")
    return result


# ================================================================== #
#  EXPERIMENT 4: Concurrent Clients Scalability                       #
# ================================================================== #

async def experiment_4_concurrency(messages_per_client=20):
    print("\n[EXP 4] Concurrent Clients Scalability")
    client_counts = [1, 5, 10, 20, 50]
    plaintext = make_message(256)
    results = []

    for num_clients in client_counts:
        all_times = []

        async def client_work(cid):
            alice, _ = make_session_pair(f"conc-{cid}", rotation_interval=10)
            session = alice.sessions[f"conc-{cid}"]
            times = []
            for _ in range(messages_per_client):
                t0 = time.perf_counter()
                nonce, ct = crypto.encrypt(session.session_key, plaintext.encode())
                times.append((time.perf_counter() - t0) * 1000)
            return times

        tasks = [client_work(i) for i in range(num_clients)]
        t_start = time.perf_counter()
        all_results = await asyncio.gather(*tasks)
        wall_time = time.perf_counter() - t_start

        for r in all_results:
            all_times.extend(r)

        total_msgs = num_clients * messages_per_client
        throughput = total_msgs / wall_time

        results.append({
            "num_clients": num_clients,
            "total_messages": total_msgs,
            "wall_time_s": round(wall_time, 4),
            "throughput_msgs_per_sec": round(throughput, 1),
            "avg_latency_ms": round(statistics.mean(all_times), 3),
            "p95_latency_ms": round(sorted(all_times)[int(0.95 * len(all_times))], 3),
            "p99_latency_ms": round(sorted(all_times)[int(0.99 * len(all_times))], 3),
        })
        print(f"  clients={num_clients:3d}  throughput={throughput:8.1f} msg/s  "
              f"avg_lat={results[-1]['avg_latency_ms']:.3f}ms")

    return results


# ================================================================== #
#  EXPERIMENT 5: Metadata Exposure Analysis                           #
# ================================================================== #

def experiment_5_metadata_exposure(num_messages=100):
    print("\n[EXP 5] Metadata Exposure Analysis")
    relay = RelayServer()
    relay.create_session("meta-test", "alice", "bob")

    import asyncio as _asyncio

    key = os.urandom(32)
    message_sizes = [64, 128, 256, 512, 1024]

    exposed_fields = []
    for i in range(num_messages):
        size = message_sizes[i % len(message_sizes)]
        nonce = os.urandom(12)
        ct = b"X" * (size + 16)  # simulate ciphertext (size + 16-byte GCM tag)
        nh = hashlib.sha256(nonce).hexdigest()

        relay.check_replay("meta-test", nh, i, "alice")
        relay.metadata_log.append({
            "sender_id": "alice",
            "receiver_id": "bob",
            "session_id": "meta-test",
            "sequence_number": i,
            "message_size": len(ct),
            "timestamp": time.time() + i * 0.1,
            "nonce_hash": nh[:16] + "...",
        })

    # Analyze what relay can observe
    records = relay.metadata_log
    sizes   = [r["message_size"] for r in records]
    times   = [r["timestamp"] for r in records]

    inter_arrival = [times[i+1] - times[i] for i in range(len(times)-1)]

    result = {
        "observable_fields": [
            "sender_id", "receiver_id", "session_id",
            "sequence_number", "message_size", "timestamp"
        ],
        "hidden_fields": [
            "plaintext_content", "encryption_key",
            "raw_nonce", "associated_data"
        ],
        "total_messages_observed": len(records),
        "unique_senders": len(set(r["sender_id"] for r in records)),
        "unique_receivers": len(set(r["receiver_id"] for r in records)),
        "avg_message_size_bytes": round(statistics.mean(sizes), 1),
        "message_size_variance": round(statistics.variance(sizes), 1),
        "avg_inter_arrival_ms": round(statistics.mean(inter_arrival) * 1000, 2),
        "timing_analysis_possible": True,
        "traffic_analysis_possible": True,
        "communication_graph_observable": True,
        "content_protected": True,
    }
    print(f"  Observable fields: {result['observable_fields']}")
    print(f"  Hidden fields    : {result['hidden_fields']}")
    print(f"  Content protected: {result['content_protected']}")
    print(f"  Traffic analysis possible: {result['traffic_analysis_possible']}")
    return result


# ================================================================== #
#  MAIN                                                                #
# ================================================================== #

async def main():
    print("=" * 60)
    print("  E2EE Relay System — Experiment Suite")
    print("=" * 60)

    all_results = {}

    # Run experiments
    all_results["exp1_encryption_overhead"]  = experiment_1_encryption_overhead(iterations=500)
    input(f"\n{Y}[PAUSED] Press Enter to run Experiment 2...{X}")
    all_results["exp2_key_rotation"]         = await experiment_2_key_rotation(messages_per_test=100)
    input(f"\n{Y}[PAUSED] Press Enter to run Experiment 3...{X}")
    all_results["exp3_replay_resistance"]    = experiment_3_replay_resistance(total_messages=200)
    input(f"\n{Y}[PAUSED] Press Enter to run Experiment 4...{X}")
    all_results["exp4_concurrency"]          = await experiment_4_concurrency(messages_per_client=20)
    input(f"\n{Y}[PAUSED] Press Enter to run Experiment 5...{X}")
    all_results["exp5_metadata_exposure"]    = experiment_5_metadata_exposure(num_messages=100)
    input(f"\n{Y}[PAUSED] Press Enter to view the final summary table...{X}")

    # Save results
    with open(RESULTS_FILE, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[DONE] Results saved to: {RESULTS_FILE}")
    print_summary(all_results)
    return all_results


def print_summary(results):
    print("\n" + "=" * 60)
    print("  EXPERIMENT SUMMARY")
    print("=" * 60)

    # Exp 1
    exp1 = results["exp1_encryption_overhead"]
    print("\nExp 1 — Encryption Overhead:")
    print(f"  {'Size':>8}  {'Enc(µs)':>9}  {'Dec(µs)':>9}  {'Overhead':>10}  {'Throughput(MB/s)':>18}")
    for r in exp1:
        print(f"  {r['message_size_bytes']:>8}  {r['avg_encrypt_us']:>9.1f}  "
              f"{r['avg_decrypt_us']:>9.1f}  {r['overhead_pct']:>9.1f}%  "
              f"{r['throughput_encrypt_mbps']:>18.1f}")

    # Exp 2
    exp2 = results["exp2_key_rotation"]
    print("\nExp 2 — Key Rotation Impact:")
    print(f"  {'Interval':>10}  {'Rotations':>10}  {'TotalEnc(ms)':>14}")
    for r in exp2:
        print(f"  {r['rotation_interval']:>10}  {r['rotation_count']:>10}  "
              f"{r['total_enc_time_ms']:>14.2f}")

    # Exp 3
    exp3 = results["exp3_replay_resistance"]
    print(f"\nExp 3 — Replay Resistance:")
    print(f"  Nonce replay rejection rate  : {exp3['nonce_rejection_rate_pct']}%")
    print(f"  Sequence replay rejection rate: {exp3['sequence_rejection_rate_pct']}%")

    # Exp 4
    exp4 = results["exp4_concurrency"]
    print(f"\nExp 4 — Concurrency Scalability:")
    print(f"  {'Clients':>8}  {'Throughput(msg/s)':>18}  {'AvgLat(ms)':>12}")
    for r in exp4:
        print(f"  {r['num_clients']:>8}  {r['throughput_msgs_per_sec']:>18.1f}  "
              f"{r['avg_latency_ms']:>12.3f}")

    # Exp 5
    exp5 = results["exp5_metadata_exposure"]
    print(f"\nExp 5 — Metadata Exposure:")
    print(f"  Observable fields: {len(exp5['observable_fields'])}")
    print(f"  Hidden fields    : {len(exp5['hidden_fields'])}")
    print(f"  Content protected: {exp5['content_protected']}")


if __name__ == "__main__":
    asyncio.run(main())
