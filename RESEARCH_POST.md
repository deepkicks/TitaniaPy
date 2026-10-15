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

```
PBKDF2 master (slot 0) ──┬── CBC(KEY_4_KEYSEEDS) → slot 4
                          ├── CBC(KEY_5_KEYSEEDS) → slot 5  
                          ├── CBC(KEY_7_KEYSEEDS) → slot 7
                          │       ├── ECB(KEY_8_KEYSEEDS) → slot 8
                          │       └── ECB(KEY_9_KEYSEEDS) → slot 9
                          └── CBC/ECB(KEY_2_KEYSEEDS) → slot 2
```

For each derived key, tested both first-16 and last-16 bytes of 32-byte results, in CBC, ECB, and CTR modes, with zeroed IV and all known Titania IVs.

**Full 8-phase scan (all negative on BOTH firmwares):**
1. All 17 known static keys × 6 IV variants × 3 modes (CBC/ECB/CTR)
2. KMB_AES derivation chain: slots 4, 5, 7, 8, 9 (both halves, key+IV combos)
3. ROM key blocks: every 16-byte window + derived chains through key7 → key8/key9
4. XOR combinations: master^OTP, master^SALT, OTP^SALT, master^ROM, master^K8/K9
5. AES-256 with all 32-byte keys (ROM windows, PBKDF2-256, keyseeds raw)
6. PBKDF2 variants: SHA-256/SHA-1/SHA-512, 16+32 byte output, header-mixed salts
7. Sliding window: every possible 16-byte key from all keyseed material concatenated (257 windows × 2 PUPs × 2 modes)
8. AES encrypt (reversed direction) with master, EMC header key, and K8 keyseed

**Validation method:** Decrypted the first 32 bytes of each PUP's extended header and checked if `file_size` falls within ~1MB of the known BLS entry size and `segment_count` is between 1-99.

**Result: Zero matches across hundreds of combinations on both firmware versions.**

## What This Means

The PS5 crypto architecture has (at least) these distinct layers:

| Layer | Purpose | Status |
|-------|---------|--------|
| 0 | PBKDF2 master key derivation | **Solved** — SHA-256, 16-byte output |
| 1 | PUP container encryption (header + segments) | **Blocked** — key not in public dump |
| 2 | PUP segment-level encryption | **Blocked** — depends on Layer 1 |
| 3 | Inner firmware encryption (EMC, EAP, etc.) | **Solved** — static keys known |

The bootrom key leak provided Layer 0 parameters and Layer 3 static keys. The KMB_AES keyseeds (Key 2-9) appear to be for Layer 3 inner firmware operations, **not** for Layer 1 PUP container crypto.

The `encsrv_decrypt_header()` ioctl (0xC0184402) used by the on-console tool accesses a key that is:
- Universal (all consoles decrypt the same PUP, so it's not per-console)
- Not in the public key dump
- Likely locked in the security processor's CCP hardware key slots
- Separate from the bootrom key hierarchy

## Why This Key Is the Nail in the Coffin

Here's why finding this one key is worth the effort:

**The PUP container key is almost certainly burned into ROM or silicon.** Every PS5 ever made — launch day consoles running FW 1.0 through the latest — must be able to decrypt every PUP Sony distributes. There's no per-console provisioning for system updates. The key has to be:
- **Universal** — identical on every console
- **Permanent** — present since the very first firmware, can't be rotated without bricking existing consoles
- **Unpatchable** — if it's in ROM/silicon (which the evidence strongly suggests), Sony can't change it even if they wanted to

Testing across two firmware versions (14.00 and 14.10) confirms this: both use identical plaintext header structures (`unknown_04=0x32010110`, `header_size=0x5B0`, `hash_size=0xDE0`) despite having completely different encrypted content. Same key hierarchy, same format — just different payloads.

**Once extracted, this key works forever.** It decrypts every past PUP and every future PUP. It's not like a signing key that can be rotated — it's a decryption key baked into hardware that already shipped. A PC tool with this key makes on-console decryption unnecessary for all time.

## What I Need — The Ask

The tool is one key away from being a complete, permanent PC-based PUP decryptor. That key lives inside the Titania Security Processor and is used by `encsrv_decrypt_header()` (ioctl `0xC0184402`). It's universal — every PS5 uses the same one — so it only needs to be extracted once.

**If you have a jailbroken PS5, here's what would crack this open:**

1. **Dump the EncryptService** — Extract the code behind the `/dev/pup_update0` ioctls so we can see how it selects and uses the PUP header key. Even a disassembly of the handler for `0xC0184402` would tell us which key slot it reads from.

2. **Peek inside the Security Processor during a PUP update** — Dump the CCP LSB slot contents while `encsrv_decrypt_header()` is running. The key is loaded into a hardware slot before the AES operation — if we can read the slots at that moment, we have it.

3. **Reverse engineer the Titania firmware** — The security processor firmware contains the key hierarchy. Deeper RE of how it handles PUP operations would reveal where the container key sits relative to the keys we already know.

Any one of these gives us the missing piece. Once that key is in the tool, it works for every PUP on every firmware — no console needed, forever.

## I Already Built the Extraction Payload

To make this as easy as possible for anyone with a jailbroken 13.60 PS5, I wrote a ready-to-compile C payload (`ps5_key_extract.c`) that does all three of the above automatically. It implements four approaches:

1. **CCP LSB Key Slot Dump** — Maps the AMD CCP v5 MMIO region via `/dev/dmem0`, reads all 128 hardware key slots (8 LSBs x 16 slots x 32 bytes each). If the PUP key is in any slot, this grabs it.

2. **EncryptService ioctl Handler Scan** — Searches kernel memory for the `pup_update0` device driver's `cdevsw` structure, follows the `d_ioctl` function pointer, and dumps 4KB of the handler code. Disassemble on PC with Ghidra/IDA to find which CCP key slot the decrypt function references.

3. **Instrumented PUP Decrypt** — Snapshots all CCP LSB slots before and after a `DecryptPupHeader` ioctl call. Any slot that changes during the call = the key that was loaded for decryption.

4. **Kernel Memory Scan** — Searches near strings like `encsrv`, `decrypt_header`, `Titania`, `ccp_key` and dumps surrounding context.

All operations are **read-only** — nothing is written to kernel or CCP state. Output goes to `/data/pup_key_dump.bin`, which you transfer to PC and run through the companion `analyze_dump.py` script. That script automatically tests every captured key candidate against encrypted PUP headers from FW 14.00 and 14.10.

**Requirements:** A PS5 on FW 13.60 or below with kernel R/W access (Byepervisor Reborn + Relapse + etaHEN or similar). Compile for FreeBSD 11 amd64 and load via payload loader. You'll need to plug in your framework's `kernel_read64` / `kernel_copyout` functions.

## Tool Availability

The tool works today for everything except the one missing key:
- Parse any PS5 PUP file's BLS container and show structure
- Estimate segment count from the plaintext header
- Decrypt inner firmware blobs if you have them extracted by other means
- Run the PBKDF2 derivation to verify/experiment with Layer 0
- Bruteforce-test unknown blobs against all known keys with entropy scoring
- Tested against real retail PUPs from FW 14.00 and FW 14.10
- **Ready to accept the Layer 1 key** — the crypto module just needs one more key added and the full pipeline connects
- **Extraction payload ready** — `ps5_key_extract.c` + `analyze_dump.py` for someone with console access

Source is published: **https://github.com/deepkicks/TitaniaPy** — drop in your PUP files and go. DMs open if you have console access and want to collaborate — this is a one-key problem with a permanent payoff.

---

*All research conducted on personally owned hardware for educational purposes. No proprietary key values are reproduced in this post — all referenced keys are already publicly documented on psdevwiki. This work builds on research by the PS5 security community, the dayzerosec CCP architecture writeup, and fail0verflow's PS4 Aeolia documentation.*
