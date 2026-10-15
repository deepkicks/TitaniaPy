# PS5 PUP Decrypt Tool

PC-based Python tool for parsing and decrypting PS5 PUP (PlayStation Update Package) files. No console needed.

## Status

The tool handles 3 of 4 crypto layers. **Layer 1 (PUP container encryption) is the one missing piece** — see [RESEARCH_POST.md](RESEARCH_POST.md) for the full technical write-up and what's needed.

| Layer | Purpose | Status |
|-------|---------|--------|
| 0 | PBKDF2 master key derivation | Solved |
| 1 | PUP container encryption | **Blocked — key not public** |
| 2 | PUP segment-level encryption | Blocked (depends on Layer 1) |
| 3 | Inner firmware encryption | Solved |

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.10+ and [pycryptodome](https://pypi.org/project/pycryptodome/).

## Usage

```bash
# Show PUP file structure (BLS container + PUP header)
python main.py info PS5UPDATE.PUP

# Extract inner entries from BLS container
python main.py extract PS5UPDATE.PUP -o output_dir/

# Decrypt inner firmware blobs with known Layer 3 keys
python main.py decrypt firmware_blob.bin -k emc_ipl_header

# Bruteforce-test an unknown blob against all known keys
python main.py bruteforce unknown_blob.bin

# Analyze entropy of a binary blob
python main.py analyze blob.bin

# Show all known keys and derivation results
python main.py keys

# Decompress a zlib-compressed segment
python main.py decompress segment.bin -o decompressed.bin
```

## Files

### Core Tool
| File | Description |
|------|-------------|
| `main.py` | CLI entry point — 7 commands |
| `keys.py` | All known PS5 keys (ROM, keyseeds, OTP/KDF, Titania, firmware) |
| `bls.py` | BLS (SLB2) outer container parser |
| `pup.py` | PUP inner structure parser |
| `crypto.py` | AES-128-CBC/ECB, PBKDF2, Layer 3 decrypt functions |
| `firmware.py` | Inner firmware decryptor with entropy analysis |

### Key Extraction (for jailbroken PS5)
| File | Description |
|------|-------------|
| `ps5_key_extract.c` | C payload — 4 approaches to extract the missing PUP container key |
| `analyze_dump.py` | Parses the dump from `ps5_key_extract.c` and tests key candidates |

### Documentation
| File | Description |
|------|-------------|
| `RESEARCH_POST.md` | Full technical write-up of findings |

## Key Extraction Payload (v2)

If you have a jailbroken PS5 on FW 13.60 or below, `ps5_key_extract.c` implements a **chained extraction strategy**:

**The chain: Approach 2 → Approach 1/5**
1. Dump the `pup_update0` ioctl/open/close handler code (only needs kernel R/W)
2. Disassemble on PC to find where the key comes from
3. Re-run the payload with `-a <address>` to read that specific location

**All five approaches:**
1. **CCP LSB Key Slot Dump + Queue Registers** — Reads all 128 hardware key slots AND queue config registers (shows which slots are CPU-readable)
2. **Full EncryptService Handler Dump** — Dumps 16KB each of `d_ioctl`, `d_open`, and `d_close` handlers plus the full `cdevsw` struct
3. **Instrumented PUP Decrypt** — Pre/post LSB snapshots around a decrypt call
4. **Kernel Memory Scan** — Searches near crypto-related strings
5. **Targeted Address Read** — Re-run mode: reads a specific kernel or physical address after RE reveals the key location

```bash
# Full scan — run all approaches
./ps5_key_extract

# Targeted read — after disassembling the handler dump
./ps5_key_extract -a 0xFFFFFFFF82345678
./ps5_key_extract -a 0xFFFFFFFF82345678 -s 256

# Analyze on PC
python analyze_dump.py pup_key_dump.bin --pup14 PS5UPDATE14.00.PUP --pup14_1 PS5UPDATE14.10.PUP
```

**Requirements:** FreeBSD 11 amd64 cross-compiler, kernel R/W via Byepervisor Reborn + Relapse + etaHEN or similar. You'll need to provide your framework's `kernel_read64` / `kernel_copyout` functions.

## Contributing

The tool is one key away from full PUP decryption. If you have console access and can run the extraction payload or dump the EncryptService, open an issue or DM.

---

*All research conducted on personally owned hardware for educational purposes. Referenced keys are publicly documented on psdevwiki.*
