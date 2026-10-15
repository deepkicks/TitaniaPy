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

## Key Extraction Payload

If you have a jailbroken PS5 on FW 13.60 or below, `ps5_key_extract.c` implements four extraction approaches:

1. **CCP LSB Key Slot Dump** — Reads all 128 hardware key slots via MMIO
2. **EncryptService ioctl Handler Scan** — Finds and dumps the `pup_update0` decrypt handler code
3. **Instrumented PUP Decrypt** — Snapshots key slots before/after a decrypt call to catch the key being loaded
4. **Kernel Memory Scan** — Searches near crypto-related strings for key material

All read-only. Output goes to `/data/pup_key_dump.bin`. Transfer to PC and run:

```bash
python analyze_dump.py pup_key_dump.bin --pup14 PS5UPDATE14.00.PUP --pup14_1 PS5UPDATE14.10.PUP
```

**Requirements:** FreeBSD 11 amd64 cross-compiler, kernel R/W via Byepervisor Reborn + Relapse + etaHEN or similar. You'll need to provide your framework's `kernel_read64` / `kernel_copyout` functions.

## Contributing

The tool is one key away from full PUP decryption. If you have console access and can run the extraction payload or dump the EncryptService, open an issue or DM.

---

*All research conducted on personally owned hardware for educational purposes. Referenced keys are publicly documented on psdevwiki.*
