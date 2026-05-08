# Relay-Based E2EE Messaging System

A Python prototype and experiment suite for studying security-performance trade-offs in relay-based end-to-end encrypted (E2EE) messaging.

This project implements:
- X25519 ephemeral Diffie-Hellman key exchange.
- HKDF-SHA256 session key derivation and key rotation ratchet.
- AES-256-GCM authenticated encryption.
- Relay-side replay protection using nonce-hash deduplication and per-sender sequence monotonicity.
- Controlled experiments for latency, scalability, replay resistance, and metadata exposure.

## Why This Project

Modern secure messengers protect content with E2EE, but real systems still need a relay to route messages. That relay cannot read plaintext, yet it can observe metadata. This project provides a controlled framework to measure both:
- Security properties (confidentiality, integrity, forward secrecy, replay resistance).
- Operational behavior (micro-latency, throughput, concurrency scaling, observable metadata).

## Repository Structure

- `relay_server.py`: Async blind relay server with session management, routing, replay checks, and stats.
- `e2ee_client.py`: Crypto layer + reusable E2EE client/session logic.
- `run_relay.py`: Starts relay server (`127.0.0.1:8765`).
- `run_bob.py`: Bob receiver flow and decryption output.
- `run_alice.py`: Alice initiator flow, encrypted sends, mid-session key rotation.
- `run_experiments.py`: Five controlled experiments, writes `experiment_results.json`.
- `experiment_results.json`: Example output from a previous experiment run.

## Threat Model and Security Properties

Assumptions:
- Relay is honest-but-curious for content (routes messages correctly but may inspect metadata).
- Attackers may replay captured envelopes.
- Session key compromise risk is reduced using periodic ratcheting.

Properties achieved by design:
- Confidentiality: relay receives only ciphertext.
- Integrity/authentication: AES-GCM tag verification on decrypt.
- Forward secrecy (demo ratchet): HKDF-based key evolution over message sequence.
- Replay resistance: relay rejects duplicate nonce hashes and non-monotonic sequence numbers.
- Relay blindness to content: relay never receives plaintext or session keys.

## End-to-End Flow (What Happens Internally)

1. Relay boots and waits for client registration.
2. Bob starts first, generates X25519 ephemeral keypair, writes `bob_pub_key` to `session.json`.
3. Alice starts, reads Bob key, generates her own X25519 keypair + random salt, writes `alice_pub_key` and `salt`.
4. Both derive identical shared secret via X25519, then derive `session_key` with HKDF-SHA256.
5. Alice creates relay session and sends encrypted envelopes:
- Nonce: 96-bit random per message.
- Associated data: `session_id:sequence_number`.
- Ciphertext: AES-256-GCM output (includes 16-byte auth tag).
6. Relay validates replay conditions and routes ciphertext to Bob.
7. Bob decrypts and authenticates each message.
8. Alice triggers key rotation; both ratchet to a new key via HKDF with fresh salt.

## Setup

### 1) Prerequisites

- Python 3.10+.
- `cryptography` package.

### 2) Install dependency

```bash
pip install cryptography
```

### 3) Run live messaging demo (3 terminals)

Terminal 1:

```bash
python run_relay.py
```

Terminal 2 (start after Bob is running):

```bash
python run_alice.py
```

Terminal 3 (start after relay, before Alice):

```bash
python run_bob.py
```

Expected behavior:
- Alice and Bob establish the same session key.
- Alice sends encrypted messages and performs one key rotation.
- Relay logs routing metadata but no plaintext.
- Bob decrypts successfully unless envelope integrity is violated.

### 4) Run experiment suite

```bash
python run_experiments.py
```

The runner pauses between experiments. Press Enter to continue at each checkpoint.

Outputs:
- Console summary table.
- `experiment_results.json` with detailed metrics.

## Experiment Design

`run_experiments.py` includes five experiments:
- Experiment 1: Encryption overhead vs message size (64B to 16KB).
- Experiment 2: Key rotation interval impact (1, 5, 10, 20, 50, 100).
- Experiment 3: Replay attack resistance (nonce replay + sequence replay).
- Experiment 4: Concurrent client scalability (1 to 50 clients).
- Experiment 5: Relay metadata exposure characterization.

## Key Findings (From Report and Runs)

- AES-256-GCM encryption/decryption is microsecond-scale for typical message sizes.
- Ciphertext overhead is fixed at 16 bytes per message (GCM tag), so percentage overhead shrinks as payload grows.
- Replay protection reached 100% rejection in injected nonce and sequence replay tests.
- Frequent key rotation provides stronger forward secrecy at low absolute overhead.
- Relay can infer communication metadata (sender/receiver, timing, size, ordering) even when content is fully encrypted.

## Limitations

- Prototype uses simplified key exchange coordination (`session.json`) for demo reproducibility.
- No network emulation in experiments; most measurements isolate cryptographic/runtime cost.
- Python runtime concurrency is subject to interpreter/runtime constraints.
- Metadata privacy hardening techniques (padding, cover traffic, routing obfuscation) are not implemented here.

## Recommended Next Extensions

- Replace file-based key exchange with authenticated in-band handshake.
- Add bounded replay window/bloom-filter strategy for long-lived sessions.
- Add WAN latency/loss emulation experiments.
- Add optional metadata-hardening mode (padding + cover traffic).
- Compare classical X25519 with post-quantum/hybrid key exchange options.

## Notes

This repository intentionally focuses on source code plus this README to keep the project lightweight and reproducible.
