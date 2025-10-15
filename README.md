# Secure Messaging Coursework (Project 1)

This repository contains a small Python-based secure messaging demo implemented for a coursework assignment. The project demonstrates textbook cryptographic building blocks and how they can be combined to provide confidentiality, integrity and authentication for simple messages exchanged between two parties (Alice and Bob).



## Overview

The project walks through these steps:
- Diffie–Hellman key exchange (with RSA-signed public values) to establish a shared secret between Alice and Bob.
- A simple key-derivation function (KDF) that hashes the shared secret iteratively to produce an encryption key.
- A PRNG module that can be used to generate IVs/nonces for symmetric encryption.
- Symmetric authenticated encryption using AES (CBC or CTR) + HMAC-SHA256 (Encrypt-then-MAC).
- Simple RSA digital signatures used to authenticate Diffie–Hellman public values.

This is an educational implementation intended for coursework and learning. It uses the `cryptography` Python package for primitives; it is NOT intended to be production cryptographic code.

## What this repo contains (key files)

- `alice_diffie.py` — Alice's interactive Diffie–Hellman terminal. Generates RSA keys, computes g^a mod p, signs the value and writes `alice_dh_data.txt` for Bob.
- `bob_diffie.py` — Bob's interactive counterpart: reads Alice's file, verifies signature, creates and signs his public value, and writes `bob_dh_data.txt`.
- `task3_key_derivation.py` — A simple iterative KDF (hash N times) to derive a symmetric encryption key from the shared secret g^ab mod p.
- `task4_prng.py` — A deterministic PRNG based on SHA-256 (for demonstration of seeding/reseeding and determinism).
- `secure_messaging.py` — Core symmetric primitives: AES encrypt/decrypt (CBC/CTR), HMAC compute/verify, and high-level Encrypt-then-MAC helper functions.
- `alice_send.py` — Alice's authenticated encryption sender. Uses `SecureMessaging` to encrypt a plaintext, compute HMAC, and save `alice_message.txt`.
- `bob_receive.py` — Bob's receiver: reads `alice_message.txt`, verifies HMAC, and decrypts if verification succeeds.
- `digital_signature.py` — Utilities for RSA key generation, signing and verification (used by the DH scripts).
- `derived_encryption_key.txt`, `alice_dh_data.txt`, `bob_dh_data.txt`, `alice_message.txt` — example/working files produced by the interactive scripts.

## Requirements

- Python 3.8+ (or newer)
- The `cryptography` package

Install dependency (PowerShell):

```powershell
python -m pip install --upgrade pip
python -m pip install cryptography
```

(If you prefer virtual environments, create and activate one before installing.)

## Usage / Typical workflow

This project is interactive. A typical run order for the exercises is:

1. Establish authenticated Diffie–Hellman shared secret
   - In one terminal run Alice's DH:

```powershell
python alice_diffie.py
```

   - In a second terminal run Bob's DH:

```powershell
python bob_diffie.py
```

   The two scripts exchange files (`alice_dh_data.txt` and `bob_dh_data.txt`) and each side computes the shared secret (g^ab mod p). Public values are signed with RSA to prevent active tampering in the demo.

2. Derive an encryption key from the shared secret

```powershell
python task3_key_derivation.py
```

   This asks for the shared secret and an iteration count and prints (and optionally saves) the derived key.

3. (Optional) Use the PRNG for generating IV/nonce values

```powershell
python task4_prng.py
```

   This provides a deterministic (seedable) PRNG demonstration. The encryption scripts can also generate `os.urandom` IVs.

4. Alice encrypts and sends an authenticated message

```powershell
python alice_send.py
```

   This script uses the key (you can paste the derived key), chooses AES mode (CBC or CTR), and saves `alice_message.txt` which contains the IV, ciphertext and HMAC.

5. Bob receives and verifies/decrypts the message

```powershell
python bob_receive.py
```

   The receiver reads `alice_message.txt`, verifies the HMAC, and decrypts the ciphertext if verification succeeds.

## Example (quick demo)

1. Run `alice_diffie.py` and `bob_diffie.py` in separate PowerShell windows and complete the guided steps to compute the shared secret.
2. Run `task3_key_derivation.py` and provide the shared secret printed by both sides; choose a small iteration count for a quick demo (e.g., 1000).
3. Run `alice_send.py`, choose the derived key (paste hex), choose a mode and IV method (random), enter a short message and save.
4. Run `bob_receive.py` to verify and decrypt.

## Security notes and limitations (important)

- This is an educational/demo implementation. Do NOT use this code for real production systems.
- Key management: The demo sometimes (optionally) stores keys in plaintext files (e.g., `derived_encryption_key.txt`) — this is insecure for real applications.
- AES key lengths and IV reuse: The scripts allow demo behavior (reusing a key for HMAC and encryption); in production, use separate keys derived via a secure KDF, and never reuse IVs for CTR mode.
- The KDF implemented here is intentionally simple (iterative hashing). In practice use an established KDF such as HKDF or PBKDF2 with proper parameters.
- The PRNG is a deterministic construction for teaching purposes. For cryptographic randomness use `os.urandom()` or a secure CSPRNG.

## Coursework / Attribution

This repository was prepared as part of course work for a Principal of Info & Security class (Project 1). Use the code for demonstration and learning. When reusing or referencing this material, please cite the repository and author appropriately.

## Troubleshooting

- If you get import errors for `cryptography`, ensure your Python environment is active and the package installed.
- On Windows, if `python` is not recognized, point to the correct Python executable, e.g., `py -3.10` or use full path.

## Extending this project (suggestions)

- Replace the custom KDF with HKDF or PBKDF2 and add salt handling.
- Split HMAC and encryption keys using an HKDF-Expand step.
- Add unit tests for `secure_messaging.py` functions.
- Add command-line flags to the scripts for non-interactive usage (helpful for automated testing).

## License

This repository contains coursework material. Check with the course policies or instructor for redistribution rules. For personal use and learning, you may reuse code with attribution.
