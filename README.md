# PS5 CCP Key Extraction Research

Hardware security research targeting AES-128-CBC key extraction from AMD CCP v5 hardware keyslots on the PlayStation 5.

**Target:** PS5 CFI-1015A, FW 1.02 | **SoC:** AMD Zen 2 "Oberon" | **Status:** Active research

## Overview

The PS5 uses a dedicated **Crypto Co-Processor (CCP v5)** managed by an ARM-based **Platform Security Processor (PSP/ASP)** to handle all firmware decryption. Keys are held exclusively in CCP hardware keyslots and never exposed to system memory. The kernel interacts with the PSP through an opaque session-based protocol — it passes encrypted blobs and receives decrypted results, never touching key material directly.

This project systematically maps the hardware attack surface and develops extraction vectors through a series of incremental, safety-gated payloads executed on real hardware.

### Key Findings

- **CCP access is gated by an SMN/IOHC-level firewall**, not by NPT page tables — hypervisor-level bypasses alone cannot reach CCP registers
- **The PSP operates as a session-based crypto oracle** — the kernel submits work through a shared DMA command buffer and receives opaque session handles, never raw keys
- **AES keys never touch kernel-accessible RAM** — extraction must go *through* the PSP, not around it
- **A working PUP decrypt oracle** has been established with known plaintext/ciphertext/IV pairs for AES-128-CBC key verification
- **CVE-2023-20599** (ASP out-of-bounds access on Zen 2) is likely unpatched on FW 1.02 (shipped late 2020, CVE disclosed Aug 2023) — a viable path to PSP compromise
- **Complete IOHC MISC register map** built across multiple probing phases — SMN firewall configuration documented

## Architecture

```
┌───────────────────────────────────────────────────┐
│   x86 Kernel (FreeBSD-based, Byepervisor active)  │
│                                                    │
│   ENCSRV ioctls ──► DMA cmd_buf ──► PSP (ARM)     │
│   (verify/decrypt)   (shared mem)    (firmware)    │
│                                          │         │
│   SMN I/O ports ──► IOHC firewall        ▼         │
│   (0xCF8/0xCFC)     (locked regs)    CCP v5       │
│                                      (keyslots)   │
└───────────────────────────────────────────────────┘
```

The x86 side can read/write kernel memory (with Byepervisor active) and access SMN registers via PCI config-space I/O ports. But the CCP's queue registers are behind an IOHC firewall that blocks direct access. The only sanctioned path to the CCP is through the PSP firmware, which validates and dispatches crypto operations.

## Prerequisites

- PS5 CFI-1015A on FW 1.02
- [ps5-payload-sdk](https://github.com/john-tornblom/ps5-payload-sdk) cross-compiler toolchain
- Byepervisor active (kernel r/w + TEXT write capability)
- Webkit + kernel exploit chain running ([PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak))
- PUP file on PS5 filesystem

## Building

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
cd ccp_extractor/ccp_probe
make phase5_29   # builds sbl_phase5_29_cmdbuf_recon.elf
```

Each phase builds as a standalone `.elf` payload. See the Makefile for all targets.

## Deployment

```bash
# Upload payload via FTP
curl -T sbl_phase5_29_cmdbuf_recon.elf "ftp://<PS5_IP>:2121/data/sbl_phase5_29_cmdbuf_recon.elf"

# Execute via hbldr
curl "http://<PS5_IP>:8080/hbldr?path=/data/sbl_phase5_29_cmdbuf_recon.elf&pipe=1&daemon=0"
```

Logs are written to `/data/sbl_phase5_XX.log` on the PS5 and can be retrieved via FTP.

## Research Phases

The project is structured as a series of incremental payloads, each building on data from the previous.

| Phase | Focus | Summary |
|-------|-------|---------|
| 1–9 | **Foundation** | DMAP r/w confirmed, CCP MMIO located, PSP command path traced, DMA buffer sniffing infrastructure built |
| 10–13 | **Descriptor analysis** | CCP v5 command descriptor layout fully reverse-engineered (8 dwords, 32 bytes), key slot indexing understood, faulTPM-style attack path evaluated |
| 14–18 | **Hardware discovery** | Full PCI/SMN enumeration, PSP gateway functions located in kernel, Byepervisor TEXT write confirmed safe, IO port access established |
| 19–22 | **Mailbox mapping** | PSP mailbox register safe ranges identified, ECAM crash boundaries documented, bus topology mapped |
| 23–26 | **PSP session protocol** | Session handles captured across multiple boots, DMA command buffer structure mapped, hidden channel (constant vs session fields) classified, cross-boot differential analysis |
| 27–28 | **IOHC firewall mapping** | Complete IOHC MISC register map built, PSP/SMU MMIO bases found, aperture configuration cluster discovered, SMN firewall confirmed as the CCP access barrier |
| 29+ | **PSP exploitation** | Full cmd_buf recon across all ENCSRV pipeline stages, CCP descriptor pattern matching, field classification, PSP command enumeration — building toward PSP compromise via CVE-2023-20599 |

## Active Attack Vectors

1. **CCP Descriptor Injection** — Modify the DMA command buffer between kernel memcpy and PSP consumption (TOCTOU on shared memory)
2. **CVE-2023-20599** — ASP out-of-bounds r/w on unpatched Zen 2, potential path to PSP code execution
3. **PSP Command Enumeration** — Discover undocumented PSP command types beyond the ENCSRV interface
4. **IOHC Firewall Analysis** — Mapped registers may reveal reconfiguration paths for SMN access control

## Safety Model

> **Crashes are acceptable** (power cycle recovers). **Permanent brick must be avoided at all cost.**

Every payload follows a strict safety protocol:

- **BRICK-class** operations (writes to PSP/NBIO/SRAM regions) require documented review with FOR/AGAINST arguments before execution
- **CRASH-class** operations (reads from unprobed SMN ranges, wide scans) are acceptable but minimized
- All payloads are **read-only by default** — any write operation is explicitly called out and justified
- Dangerous address ranges are documented and avoided (known-crash SMN blocks, MMIO BAR regions via DMAP, high physical addresses)
- Logs are fsynced between operation groups so data survives crashes

## Project Structure

```
ps5-research/
├── README.md
├── OD.txt                              # Strategic analysis / attack path evaluation
├── keys.py                             # Key verification utilities
├── ccp_extractor/
│   ├── ccp_probe/
│   │   ├── Makefile                    # Build system (68+ payload targets)
│   │   ├── sbl_phase5_XX_*.c           # Research payloads (one per phase)
│   │   ├── oracle_brute/               # Brute-force key verification tools
│   │   ├── bindumps/                   # Raw binary captures from PS5
│   │   ├── results/                    # Captured logs and binary data
│   │   └── *.py                        # Analysis and parsing scripts
│   ├── sbl_srv_analysis/               # SBL service reverse engineering
│   │   ├── *.bin                       # Dumped kernel code sections
│   │   ├── *.py                        # Disassembly scripts
│   │   └── sbl_srv_analysis.md         # Analysis notes
│   └── logs/                           # Archived payload output logs
├── PS5-UMTX-Jailbreak/                 # Exploit chain (submodule)
└── ps5-payload-sdk/                    # Build toolchain (submodule)
```

## References & Resources

- **AMD CCP Driver (Linux):** [drivers/crypto/ccp](https://github.com/torvalds/linux/tree/master/drivers/crypto/ccp) — open-source CCP v5 command submission reference.
 
- **AMD PPR (Processor Programming Reference):** Family 17h documentation for SMN, IOHC, NBIO register layouts.

- **CVE-2023-20599:** [AMD Security Bulletin SA-2023-011](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7008.html) — "Improper access control in the ASP"

- **PS5 Payload SDK:** [john-tornblom/ps5-payload-sdk](https://github.com/john-tornblom/ps5-payload-sdk) — cross-compilation toolchain for PS5 ELF payloads.

- **PS5-UMTX-Jailbreak:** [PS5Dev/PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak) — webkit + kernel exploit chain.

- **Byepervisor:** PS5 hypervisor bypass enabling kernel TEXT writes and full DMAP r/w.

- **IOActive CCP Research:** Prior work on AMD PSP/CCP security architecture

## Credits

**Claude (Anthropic)** — AI-assisted payload development, code generation, and strategic analysis across Phases 5.10+.

**[deepkick-stacks](https://github.com/deepkick-stacks)** — Lead researcher, hardware testing, payload execution, strategic direction. All research conducted on personally-owned hardware.

## Disclaimer

This research is conducted on personally-owned hardware for educational and security research purposes. No online services are contacted or affected. All work targets a single offline console running outdated firmware (1.02). No attempt is made to circumvent current-generation security measures or enable piracy.

## License

This project is provided for educational and research purposes only. Use at your own risk.
