# I Built a PC-Based PS5 PUP Decrypt Tool — Need Someone to Dump the EncryptService Key So It Works Forever

**TL;DR:** I built a Python tool that can parse and partially decrypt PS5 PUP files on PC — no console needed. It handles BLS containers, PUP structure analysis, and inner firmware decryption with known keys. I confirmed PBKDF2-HMAC-SHA256 as the Layer 0 derivation algorithm (exact match to Titania Rev 2 master key). Then I exhaustively tested every known key and derivation chain against real PUPs from **two different firmware versions (14.00 and 14.10)** and hit a wall: **the PUP container encryption key is not in the public key dump.** It lives inside the Titania Security Processor, used by `encsrv_decrypt_header()`. The key is almost certainly **burned into ROM or silicon** — it's universal across all consoles and has been there since FW 1.0. That means extracting it once = permanent solution for every firmware version, past and future. **I need someone with console access to either dump the EncryptService software or peek inside the Security Processor to find what key `encsrv_decrypt_header()` actually uses.**

---

## Background

After the PS5 bootrom key leak (Dec 31, 2025), a significant amount of key material became publicly documented — ROM key blocks, keyseeds (Key 2-9), OTP/KDF parameters, Titania master keys, and inner firmware AES keys. These are cataloged on psdevwiki.

The existing on-console tool (`ps5-pup-decrypt`) works by calling the PS5's EncryptService via ioctl, meaning it requires a jailbroken console. No PC-based PUP decryption tool existed publicly. I don't have a PS5, so I set out to build a tool that works entirely on PC — something designed to last. The architecture is modular: once the missing key is found, it drops into the tool and every PUP from every firmware version becomes decryptable without a console.

## What I Built

A Python CLI tool (`pup-decrypt-tool`) that handles the layers we have keys for:

- **BLS Parser** — Parses the outer SLB2 container (magic `0x32424C53`), extracts entry metadata
- **PUP Parser** — Reads the inner PUP structure (magic `0xEEF51454`), segment table, flags
- **Layer 3 Decryptor** — AES-128-CBC decryption of inner firmware blobs using known static keys (EMC IPL header/body, EAP KBL, EAP Kernel, EAP Kernel SELF, Titania Rev 2)
- **Key Derivation Module** — PBKDF2 + KMB_AES chain replication for research
- **Bruteforce Mode** — Tries all known keys against unknown blobs, uses Shannon entropy to score results

Requires only Python 3 + pycryptodome. No console needed.

## Finding 1: PBKDF2 Layer 0 Derivation Confirmed

The psdevwiki documents OTP_AES_ROOT, KDF_SALT1, and 1000 iterations as KDF parameters, but doesn't specify the hash function or output length.

I tested PBKDF2-HMAC with SHA-256, SHA-1, and SHA-512 at 16-byte and 32-byte output lengths:

| Hash | dklen | Match? |
|------|-------|--------|
| SHA-256 | 16 | **YES — exact match to Titania Rev 2 master key** |
| SHA-256 | 32 | First 16 bytes match (as expected) |
| SHA-1 | 16 | No |
| SHA-512 | 16 | No |

**Conclusion:** Layer 0 is PBKDF2-HMAC-SHA256 with 16-byte output. This is the algorithm that derives the Titania Rev 2 master key from OTP_AES_ROOT + KDF_SALT1.

## Finding 2: Real PUP Structure (14.00 and 14.10)

Tested against two retail PS5UPDATE.PUP files:
- **FW 14.00** — 1,260,600,832 bytes, BLS entry size 0x4B2339D5
- **FW 14.10** — 1,261,408,256 bytes, BLS entry size 0x4B2F8A3D

**BLS Container (plaintext):**
- Both: Version 3, 1 inner entry (`PS5UPDATE1.PUP`), offset 0x400

**PUP File Header (first 16 bytes — plaintext):**
- Both firmwares have **identical** plaintext headers:
  - Magic: `0xEEF51454` (valid)
  - Field at offset 0x04: `0x32010110` (likely format version, not firmware version)
  - Header size: `0x5B0` (1456 bytes) — implies ~44 segments at 32 bytes each
  - Hash/signature table size: `0xDE0` (3552 bytes)

**Encrypted content comparison (14.00 vs 14.10):**
- 256 out of 256 bytes differ in the encrypted extended header — completely different ciphertext
- Confirms: different firmware content, but same encryption scheme and key hierarchy
- All encrypted regions: ~7.15-7.29 bits/byte entropy (near max 8.0) — confirmed encryption, not compression

## Finding 3: Layer 1 Gap — Exhaustive Negative Result (Both Firmwares)

This is the main research contribution. I replicated the KMB_AES derivation chain documented on psdevwiki and tested every resulting key against the encrypted PUP headers **from both 14.00 and 14.10** simultaneously.

**Derivation chain tested:**
