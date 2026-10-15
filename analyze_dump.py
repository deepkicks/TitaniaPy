"""
analyze_dump.py — Parse pup_key_dump.bin, test key candidates, and auto-disassemble handlers.

Reads the structured dump from ps5_key_extract.c v2, extracts all key candidates
from CCP LSB slots, tries AES-128-CBC/ECB decryption against encrypted PUP headers,
and automatically disassembles handler code to find where the key comes from.

Usage:
    python analyze_dump.py pup_key_dump.bin
    python analyze_dump.py pup_key_dump.bin --pup14 path/to/14.00.PUP --pup14_1 path/to/14.10.PUP
    python analyze_dump.py pup_key_dump.bin --save-handlers    # also save .bin files for Ghidra
"""

import argparse
import re
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERROR: pycryptodome required. Install with: pip install pycryptodome")
    sys.exit(1)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# --- Dump format constants (must match ps5_key_extract.c v2) ---
DUMP_MAGIC       = 0x505550444D50
SECTION_LSB      = 0x01
SECTION_IOCTL    = 0x02
SECTION_SNAP_PRE = 0x03
SECTION_SNAP_POST = 0x04
SECTION_MEMSCAN  = 0x05
SECTION_CDEVSW   = 0x06
SECTION_CCP_REGS = 0x07
SECTION_ADDR_READ = 0x08
SECTION_HANDLER_OPEN  = 0x09
SECTION_HANDLER_CLOSE = 0x0A

SECTION_NAMES = {
    SECTION_LSB: "CCP LSB Key Slots",
    SECTION_IOCTL: "d_ioctl Handler Code",
    SECTION_SNAP_PRE: "Pre-Decrypt LSB Snapshot",
    SECTION_SNAP_POST: "Post-Decrypt LSB Snapshot",
    SECTION_MEMSCAN: "Kernel Memory Scan",
    SECTION_CDEVSW: "cdevsw Struct",
    SECTION_CCP_REGS: "CCP Queue Registers",
    SECTION_ADDR_READ: "Targeted Address Read",
    SECTION_HANDLER_OPEN: "d_open Handler Code",
    SECTION_HANDLER_CLOSE: "d_close Handler Code",
}

HANDLER_SECTIONS = {SECTION_IOCTL, SECTION_HANDLER_OPEN, SECTION_HANDLER_CLOSE}

CCP_QUEUE_REG_NAMES = [
    "CONTROL", "TAIL_LO", "HEAD_LO", "INT_ENABLE", "INT_STATUS",
    "STATUS", "PUBLIC_MASK_LO", "PUBLIC_MASK_HI",
    "PRIVATE_MASK_LO", "PRIVATE_MASK_HI", "STATUS2",
]
CCP_NUM_QUEUES = 5

LSB_COUNT = 8
SLOTS_PER_LSB = 16
SLOT_SIZE = 32
LSB_TOTAL_SIZE = LSB_COUNT * SLOTS_PER_LSB * SLOT_SIZE

PUP_HEADER_OFFSET = 0x410
PUP_HEADER_READ_SIZE = 64

PUP_14_00_BLS_SIZE = 0x4B2339D5
PUP_14_10_BLS_SIZE = 0x4B2F8A3D

DEFAULT_PUP_14_00 = "PS5UPDATE14.00.PUP"
DEFAULT_PUP_14_10 = "PS5UPDATE14.10.PUP"

# Crypto-related strings to watch for in call target vicinity
CRYPTO_HINTS = [
    "ccp", "aes", "sbl", "encsrv", "crypto", "cipher", "decrypt", "encrypt",
    "key", "lsb", "passthru", "sha", "hmac",
]

# Known ioctl codes from ps5-pup-decrypt encryptsrv.c
IOCTL_MAP = {
    0xC0104401: "VerifyBlsHeader",
    0xC0184402: "DecryptHeader",
    0xC0184403: "VerifyPupAdditionalSign",
    0xC0184404: "VerifyPupWatermark",
    0xC0184405: "DecryptSegment",
    0xC0284406: "DecryptSegmentBlock",
}

# decrypt_header_args struct: { void* buffer, size_t length, int type }
# type comes from translate_type(): 0,3->0  1,4->1  2,5->2
# PS5UPDATE1.PUP = type 1, PS5UPDATE2.PUP = type 0


# =====================================================================
# Dump parsing
# =====================================================================

def parse_dump(data: bytes) -> dict | None:
    if len(data) < 16:
        print(f"[!] Dump file too small ({len(data)} bytes)")
        return None

    magic, version, section_count = struct.unpack_from("<QII", data, 0)
    if magic != DUMP_MAGIC:
        print(f"[!] Bad magic: 0x{magic:012x} (expected 0x{DUMP_MAGIC:012x})")
        return None

    print(f"[+] Dump version {version}, {section_count} sections")

    section_table_offset = 16
    max_sections = 64
    sections = []

    for i in range(min(section_count, max_sections)):
        off = section_table_offset + i * 16
        stype, ssize, soffset, _ = struct.unpack_from("<IIII", data, off)
        name = SECTION_NAMES.get(stype, f"Unknown(0x{stype:02x})")
        print(f"  Section {i}: {name}, {ssize} bytes at offset 0x{soffset:x}")

        if soffset + ssize <= len(data):
            section_data = data[soffset:soffset + ssize]
        else:
            print(f"  [!] Section data extends past end of file")
            section_data = data[soffset:] if soffset < len(data) else b""

        sections.append({
            "type": stype, "size": ssize, "offset": soffset,
            "data": section_data, "name": name,
        })

    return {"version": version, "sections": sections}


# =====================================================================
# Key candidate extraction
# =====================================================================

def extract_key_candidates(sections: list) -> list:
    candidates = []
    seen = set()

    for sec in sections:
        if sec["type"] not in (SECTION_LSB, SECTION_SNAP_PRE, SECTION_SNAP_POST, SECTION_ADDR_READ):
            continue

        data = sec["data"]
        total_slots = len(data) // SLOT_SIZE
        for slot_idx in range(total_slots):
            slot = data[slot_idx * SLOT_SIZE:(slot_idx + 1) * SLOT_SIZE]
            if slot == b"\x00" * SLOT_SIZE:
                continue

            key16 = slot[:16]
            key_hex = key16.hex()
            if key_hex not in seen:
                seen.add(key_hex)
                candidates.append({
                    "key": key16, "source": sec["name"],
                    "slot": slot_idx, "full_slot": slot,
                })

            key16b = slot[16:32]
            key_hex_b = key16b.hex()
            if key_hex_b not in seen and key16b != b"\x00" * 16:
                seen.add(key_hex_b)
                candidates.append({
                    "key": key16b, "source": sec["name"] + " (upper half)",
                    "slot": slot_idx, "full_slot": slot,
                })

    for sec in sections:
        data = sec["data"]
        if len(data) < 16:
            continue
        for i in range(0, len(data) - 15, 4):
            window = data[i:i + 16]
            if window == b"\x00" * 16:
                continue
            whex = window.hex()
            if whex not in seen:
                seen.add(whex)
                candidates.append({
                    "key": window,
                    "source": f"{sec['name']} @ offset 0x{i:x}",
                    "slot": -1, "full_slot": None,
                })

    return candidates


def find_lsb_diff(sections: list) -> list:
    pre_data = post_data = None
    for sec in sections:
        if sec["type"] == SECTION_SNAP_PRE:
            pre_data = sec["data"]
        elif sec["type"] == SECTION_SNAP_POST:
            post_data = sec["data"]

    if pre_data is None or post_data is None:
        return []

    changed = []
    total_slots = min(len(pre_data), len(post_data)) // SLOT_SIZE
    for slot_idx in range(total_slots):
        pre_slot = pre_data[slot_idx * SLOT_SIZE:(slot_idx + 1) * SLOT_SIZE]
        post_slot = post_data[slot_idx * SLOT_SIZE:(slot_idx + 1) * SLOT_SIZE]
        if pre_slot != post_slot:
            print(f"[!] LSB slot {slot_idx} CHANGED during decrypt:")
            print(f"    Before: {pre_slot.hex()}")
            print(f"    After:  {post_slot.hex()}")
            changed.append({"slot": slot_idx, "before": pre_slot, "after": post_slot})

    return changed


# =====================================================================
# PUP header testing
# =====================================================================

def read_pup_header(pup_path: str, offset: int = PUP_HEADER_OFFSET,
                    size: int = PUP_HEADER_READ_SIZE) -> bytes | None:
    path = Path(pup_path)
    if not path.exists():
        print(f"[!] PUP file not found: {pup_path}")
        return None
    file_size = path.stat().st_size
    if file_size < offset + size:
        print(f"[!] PUP file too small: {file_size} bytes")
        return None
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def validate_decrypted_header(decrypted: bytes, expected_bls_size: int,
                              pup_name: str) -> bool:
    if len(decrypted) < 16:
        return False
    file_size = struct.unpack_from("<Q", decrypted, 0)[0]
    segment_count = struct.unpack_from("<H", decrypted, 8)[0]
    size_diff = abs(int(file_size) - int(expected_bls_size))
    if size_diff < (1024 * 1024) and 1 <= segment_count <= 99:
        print(f"  [!!!] MATCH on {pup_name}!")
        print(f"        file_size=0x{file_size:x} (diff={size_diff} from BLS 0x{expected_bls_size:x})")
        print(f"        segment_count={segment_count}")
        print(f"        Full decrypted: {decrypted[:32].hex()}")
        return True
    return False


def test_key_against_pups(key: bytes, pup_headers: dict) -> bool:
    matched = False
    for pup_name, (header_data, bls_size) in pup_headers.items():
        if header_data is None:
            continue
        enc_block = header_data[:32]
        try:
            dec_cbc = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(enc_block)
            if validate_decrypted_header(dec_cbc, bls_size, f"{pup_name} (CBC)"):
                matched = True
        except (ValueError, KeyError):
            pass
        try:
            dec_ecb = AES.new(key, AES.MODE_ECB).decrypt(enc_block)
            if validate_decrypted_header(dec_ecb, bls_size, f"{pup_name} (ECB)"):
                matched = True
        except (ValueError, KeyError):
            pass
    return matched


# =====================================================================
# Display helpers
# =====================================================================

def hexdump_section(data: bytes, label: str, max_bytes: int = 256):
    print(f"\n--- {label} ---")
    show = min(len(data), max_bytes)
    for i in range(0, show, 16):
        hex_part = " ".join(f"{b:02x}" for b in data[i:i + 16])
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i + 16])
        print(f"  {i:04x}: {hex_part:<48s}  {ascii_part}")
    if show < len(data):
        print(f"  ... ({len(data) - show} more bytes)")


def display_cdevsw(data: bytes) -> dict:
    print(f"\n--- cdevsw Struct (pup_update0) ---")
    ptrs = {}
    if len(data) < 0x58:
        print(f"  [!] Too small ({len(data)} bytes)")
        return ptrs
    fields = [
        (0x00, "d_version"), (0x04, "d_flags"), (0x08, "d_name (ptr)"),
        (0x10, "d_open"), (0x18, "d_close"), (0x20, "d_read"),
        (0x28, "d_write"), (0x30, "d_ioctl"), (0x38, "d_poll"),
        (0x40, "d_mmap"), (0x48, "d_strategy"), (0x58, "d_kqfilter"),
    ]
    for off, name in fields:
        if off + 8 <= len(data):
            val = struct.unpack_from("<Q", data, off)[0]
            print(f"  +0x{off:02x} {name:16s} = 0x{val:016x}")
            ptrs[name] = val
    return ptrs


def display_ccp_regs(data: bytes) -> dict:
    print(f"\n--- CCP Queue Registers ---")
    info = {"readable_slots": set(), "protected_slots": set()}
    regs_per_queue = len(CCP_QUEUE_REG_NAMES)
    bytes_per_queue = regs_per_queue * 4
    num_queues = min(CCP_NUM_QUEUES, len(data) // bytes_per_queue)

    for q in range(num_queues):
        base = q * bytes_per_queue
        print(f"  Queue {q}:")
        for r in range(regs_per_queue):
            val = struct.unpack_from("<I", data, base + r * 4)[0]
            print(f"    {CCP_QUEUE_REG_NAMES[r]:20s} = 0x{val:08x}")

        pub_lo = struct.unpack_from("<I", data, base + 6 * 4)[0]
        pub_hi = struct.unpack_from("<I", data, base + 7 * 4)[0]
        pub_mask = (pub_hi << 32) | pub_lo
        priv_lo = struct.unpack_from("<I", data, base + 8 * 4)[0]
        priv_hi = struct.unpack_from("<I", data, base + 9 * 4)[0]
        priv_mask = (priv_hi << 32) | priv_lo

        readable = pub_mask & ~priv_mask
        print(f"    CPU-readable slots mask: 0x{readable:016x}")
        if readable == 0:
            print(f"    [!] No CPU-readable slots on this queue")
        else:
            for bit in range(64):
                if readable & (1 << bit):
                    print(f"    [+] Slot {bit} is CPU-readable")
                    info["readable_slots"].add(bit)

        for bit in range(64):
            if priv_mask & (1 << bit):
                info["protected_slots"].add(bit)

    return info


# =====================================================================
# Automated handler disassembly and pattern analysis
# =====================================================================

def analyze_handler(code: bytes, base_addr: int, label: str) -> dict | None:
    """Disassemble handler code and find key-related patterns."""
    if not HAS_CAPSTONE:
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    results = {
        "label": label,
        "base_addr": base_addr,
        "kernel_addr_refs": [],
        "rip_relative_refs": [],
        "call_targets": [],
        "slot_candidates": [],
        "aes_size_refs": [],
        "ioctl_cmd_refs": [],
        "type_dispatch_refs": [],
        "instruction_count": 0,
    }

    for insn in md.disasm(code, base_addr):
        results["instruction_count"] += 1
        mnem = insn.mnemonic
        ops = insn.op_str

        # 1) Kernel address immediates (mov reg, 0xffffffff8...)
        for match in re.finditer(r'0x(f{8,16}[0-9a-f]+)', ops, re.I):
            val = int(match.group(), 16)
            if val > 0xFFFFFFFF00000000:
                val = val & 0xFFFFFFFFFFFFFFFF
                if 0xFFFFFFFF80000000 <= val <= 0xFFFFFFFFFFFFFFFF:
                    results["kernel_addr_refs"].append({
                        "addr": insn.address,
                        "target": val,
                        "insn": f"{mnem} {ops}",
                    })

        # 2) RIP-relative LEA/MOV (data references)
        if mnem in ("lea", "mov") and "rip" in ops.lower():
            rip_match = re.search(r'\[rip\s*([+-])\s*0x([0-9a-f]+)\]', ops, re.I)
            if rip_match:
                sign = 1 if rip_match.group(1) == '+' else -1
                disp = int(rip_match.group(2), 16)
                target = insn.address + insn.size + sign * disp
                results["rip_relative_refs"].append({
                    "addr": insn.address,
                    "target": target & 0xFFFFFFFFFFFFFFFF,
                    "insn": f"{mnem} {ops}",
                    "type": mnem,
                })

        # 3) Call targets
        if mnem == "call":
            call_match = re.match(r'0x([0-9a-f]+)', ops, re.I)
            if call_match:
                target = int(call_match.group(), 16) & 0xFFFFFFFFFFFFFFFF
                results["call_targets"].append({
                    "addr": insn.address,
                    "target": target,
                })

        # 4) Small immediate values (CCP slot candidates)
        #    Only in mov/or instructions, values 0-127
        if mnem in ("mov", "or", "and", "cmp", "test"):
            for match in re.finditer(r'(?<![0-9a-fx])0x([0-9a-f]{1,2})(?![0-9a-f])', ops, re.I):
                val = int(match.group(1), 16)
                if 0 <= val <= 127:
                    results["slot_candidates"].append({
                        "addr": insn.address,
                        "value": val,
                        "insn": f"{mnem} {ops}",
                    })
            # Also catch plain decimal-looking hex
            imm_match = re.search(r',\s*(\d+)$', ops)
            if imm_match:
                val = int(imm_match.group(1))
                if 0 <= val <= 127:
                    results["slot_candidates"].append({
                        "addr": insn.address,
                        "value": val,
                        "insn": f"{mnem} {ops}",
                    })

        # 5) AES key size references (16, 32 as immediate)
        if mnem == "mov":
            for sz in (0x10, 0x20):
                if f"0x{sz:x}" in ops or f", {sz}" in ops:
                    results["aes_size_refs"].append({
                        "addr": insn.address,
                        "size": sz,
                        "insn": f"{mnem} {ops}",
                    })

        # 6) All known ioctl command references
        ops_lower = ops.lower()
        for ioctl_code, ioctl_name in IOCTL_MAP.items():
            hex_str = f"0x{ioctl_code:x}"
            if hex_str in ops_lower:
                results["ioctl_cmd_refs"].append({
                    "addr": insn.address,
                    "insn": f"{mnem} {ops}",
                    "ioctl": ioctl_name,
                    "code": ioctl_code,
                })

        # 7) Type dispatch detection — cmp/test with 0, 1, 2 near branch
        #    The decrypt_header ioctl takes a type arg (0, 1, or 2) that
        #    selects the key. Look for cmp reg, 0/1/2 patterns.
        if mnem == "cmp":
            for tv in (0, 1, 2):
                if ops.endswith(f", {tv}") or ops.endswith(f", 0x{tv:x}"):
                    results["type_dispatch_refs"].append({
                        "addr": insn.address,
                        "value": tv,
                        "insn": f"{mnem} {ops}",
                    })

    return results


def print_analysis(results: dict):
    """Print a formatted analysis report for one handler."""
    label = results["label"]
    base = results["base_addr"]
    count = results["instruction_count"]

    print(f"\n{'=' * 70}")
    print(f"  DISASSEMBLY ANALYSIS: {label}")
    print(f"  Base address: 0x{base:x}, {count} instructions decoded")
    print(f"{'=' * 70}")

    # Kernel address references (HIGH priority)
    kaddrs = results["kernel_addr_refs"]
    if kaddrs:
        # Deduplicate by target
        seen_targets = {}
        for ref in kaddrs:
            t = ref["target"]
            if t not in seen_targets:
                seen_targets[t] = ref
        unique = list(seen_targets.values())

        print(f"\n  [HIGH] Kernel Address References ({len(unique)} unique):")
        print(f"  These may be pointers to key data in kernel memory.")
        for ref in unique[:20]:
            print(f"    0x{ref['addr']:x}: {ref['insn']}")
            print(f"      -> TARGET: 0x{ref['target']:x}")
            print(f"         Try: ./ps5_key_extract -a 0x{ref['target']:x} -s 256")
    else:
        print(f"\n  [HIGH] Kernel Address References: none found")

    # RIP-relative data references (HIGH priority)
    rip_refs = results["rip_relative_refs"]
    if rip_refs:
        seen_targets = {}
        for ref in rip_refs:
            t = ref["target"]
            if t not in seen_targets:
                seen_targets[t] = ref
        unique = list(seen_targets.values())

        print(f"\n  [HIGH] RIP-Relative Data References ({len(unique)} unique):")
        print(f"  These load data from nearby kernel memory — could be key tables.")
        for ref in unique[:20]:
            print(f"    0x{ref['addr']:x}: {ref['insn']}")
            print(f"      -> DATA AT: 0x{ref['target']:x}")
            print(f"         Try: ./ps5_key_extract -a 0x{ref['target']:x} -s 256")
    else:
        print(f"\n  [HIGH] RIP-Relative Data References: none found")

    # Slot candidates (MEDIUM priority)
    slots = results["slot_candidates"]
    if slots:
        # Count frequency of each value
        freq = {}
        for s in slots:
            v = s["value"]
            if v not in freq:
                freq[v] = []
            freq[v].append(s)

        # Filter: values 0-15 used more than once are interesting (CCP slot numbers)
        interesting = {v: refs for v, refs in freq.items()
                       if v <= 15 and len(refs) >= 1}
        # Also flag anything 16-127 that appears 2+ times
        interesting.update({v: refs for v, refs in freq.items()
                            if 16 <= v <= 127 and len(refs) >= 2})

        if interesting:
            print(f"\n  [MED]  Potential CCP Slot Numbers:")
            for v in sorted(interesting.keys()):
                refs = interesting[v]
                print(f"    Slot {v} — referenced {len(refs)} time(s):")
                for ref in refs[:3]:
                    print(f"      0x{ref['addr']:x}: {ref['insn']}")
    else:
        print(f"\n  [MED]  Potential CCP Slot Numbers: none found")

    # AES key size references
    aes_refs = results["aes_size_refs"]
    if aes_refs:
        print(f"\n  [MED]  AES Key Size References:")
        for ref in aes_refs[:10]:
            bits = ref["size"] * 8
            print(f"    0x{ref['addr']:x}: {ref['insn']}  (AES-{bits})")

    # Call targets (LOW priority — for mapping the call graph)
    calls = results["call_targets"]
    if calls:
        # Deduplicate
        unique_targets = {}
        for c in calls:
            t = c["target"]
            if t not in unique_targets:
                unique_targets[t] = 0
            unique_targets[t] += 1

        print(f"\n  [LOW]  Function Calls ({len(unique_targets)} unique targets):")
        for target, count in sorted(unique_targets.items(), key=lambda x: -x[1])[:15]:
            in_handler = base <= target < base + 16384
            loc = "(within this handler)" if in_handler else "(external function)"
            print(f"    0x{target:x} — called {count}x {loc}")

    # Ioctl command references
    if results["ioctl_cmd_refs"]:
        print(f"\n  [INFO] Ioctl Command References:")
        for ref in results["ioctl_cmd_refs"]:
            name = ref.get("ioctl", "unknown")
            print(f"    0x{ref['addr']:x}: {ref['insn']}  ({name})")

    # Type dispatch (key selection based on PUP type 0/1/2)
    type_refs = results.get("type_dispatch_refs", [])
    if type_refs:
        print(f"\n  [HIGH] Type Dispatch Detection ({len(type_refs)} cmp instructions):")
        print(f"  The handler selects a key based on a 'type' argument (0, 1, or 2).")
        print(f"  Trace the branch targets from these comparisons to find the key load.")
        for ref in type_refs[:10]:
            print(f"    0x{ref['addr']:x}: {ref['insn']}")
        print(f"  Context: PS5UPDATE1.PUP = type 1, PS5UPDATE2.PUP = type 0")
        print(f"  The code after 'cmp ..., 1' + branch leads to the key for system updates.")


def generate_recommendations(all_analysis: list, ccp_info: dict | None):
    """Combine analysis from all handlers and generate actionable next steps."""
    print(f"\n{'=' * 70}")
    print(f"  AUTOMATED RECOMMENDATIONS")
    print(f"{'=' * 70}")

    # Collect all findings across all handlers
    all_kaddr_targets = []
    all_rip_targets = []
    all_slots = {}
    all_ioctls = []
    all_type_dispatch = []
    has_aes128 = False
    has_aes256 = False

    for analysis in all_analysis:
        if analysis is None:
            continue
        for ref in analysis["kernel_addr_refs"]:
            all_kaddr_targets.append(ref)
        for ref in analysis["rip_relative_refs"]:
            all_rip_targets.append(ref)
        for ref in analysis["slot_candidates"]:
            v = ref["value"]
            if v not in all_slots:
                all_slots[v] = 0
            all_slots[v] += 1
        for ref in analysis["aes_size_refs"]:
            if ref["size"] == 0x10:
                has_aes128 = True
            elif ref["size"] == 0x20:
                has_aes256 = True
        for ref in analysis.get("ioctl_cmd_refs", []):
            all_ioctls.append(ref)
        for ref in analysis.get("type_dispatch_refs", []):
            all_type_dispatch.append(ref)

    # Deduplicate kernel targets
    unique_kaddrs = list({ref["target"]: ref for ref in all_kaddr_targets}.values())
    unique_rip = list({ref["target"]: ref for ref in all_rip_targets}.values())

    # Score and rank targets
    ranked_targets = []

    for ref in unique_kaddrs:
        ranked_targets.append({
            "type": "kernel_addr",
            "target": ref["target"],
            "confidence": "HIGH",
            "reason": f"Direct kernel address reference at 0x{ref['addr']:x}",
            "command": f"./ps5_key_extract -a 0x{ref['target']:x} -s 256",
        })

    for ref in unique_rip:
        ranked_targets.append({
            "type": "rip_data",
            "target": ref["target"],
            "confidence": "HIGH",
            "reason": f"RIP-relative data load at 0x{ref['addr']:x}",
            "command": f"./ps5_key_extract -a 0x{ref['target']:x} -s 256",
        })

    # Slot-based targets
    readable_slots = ccp_info.get("readable_slots", set()) if ccp_info else set()
    protected_slots = ccp_info.get("protected_slots", set()) if ccp_info else set()

    frequent_slots = sorted(
        [(v, c) for v, c in all_slots.items() if v <= 15 and c >= 2],
        key=lambda x: -x[1]
    )
    for slot_val, count in frequent_slots:
        if slot_val in readable_slots:
            ranked_targets.append({
                "type": "ccp_slot_readable",
                "target": slot_val,
                "confidence": "HIGH",
                "reason": f"CCP slot {slot_val} referenced {count}x and IS CPU-readable",
                "command": f"Check LSB dump section for slot {slot_val}",
            })
        elif slot_val in protected_slots:
            ranked_targets.append({
                "type": "ccp_slot_protected",
                "target": slot_val,
                "confidence": "MED",
                "reason": f"CCP slot {slot_val} referenced {count}x but is hardware-PROTECTED",
                "command": "Need to find where this slot is loaded from (trace the loading code)",
            })
        else:
            ranked_targets.append({
                "type": "ccp_slot_unknown",
                "target": slot_val,
                "confidence": "MED",
                "reason": f"CCP slot {slot_val} referenced {count}x (protection status unknown)",
                "command": f"./ps5_key_extract -a 0x{slot_val:x}  # if physical CCP offset known",
            })

    # Print recommendations
    if not ranked_targets:
        print("\n  No high-confidence key source candidates identified.")
        print("  Manual Ghidra/IDA analysis of the handler .bin files is needed.")
        print("  Save handlers with: python analyze_dump.py dump.bin --save-handlers")
        return ranked_targets

    # Sort by confidence
    conf_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    ranked_targets.sort(key=lambda x: conf_order.get(x["confidence"], 99))

    print(f"\n  Found {len(ranked_targets)} potential key source(s):\n")

    for i, t in enumerate(ranked_targets):
        print(f"  [{t['confidence']}] Candidate {i + 1}: ", end="")
        if t["type"] in ("kernel_addr", "rip_data"):
            print(f"Kernel address 0x{t['target']:x}")
        elif t["type"].startswith("ccp_slot"):
            print(f"CCP slot {t['target']}")
        print(f"        Reason:  {t['reason']}")
        print(f"        Action:  {t['command']}")
        print()

    # Key size hint
    if has_aes128 and not has_aes256:
        print("  [INFO] AES-128 (16-byte) key size detected in handler code.")
    elif has_aes256 and not has_aes128:
        print("  [INFO] AES-256 (32-byte) key size detected — use -s 32 on reads.")
    elif has_aes128 and has_aes256:
        print("  [INFO] Both AES-128 and AES-256 references found — try both key sizes.")

    # Ioctl dispatch summary
    if all_ioctls:
        found_names = set(ref.get("ioctl", "") for ref in all_ioctls)
        print(f"\n  [INFO] Ioctl dispatch codes found: {', '.join(sorted(found_names))}")
        if "DecryptHeader" in found_names:
            print("         DecryptHeader (0xC0184402) is present — this handler does PUP decryption.")

    # Type dispatch summary
    if all_type_dispatch:
        type_vals = sorted(set(ref["value"] for ref in all_type_dispatch))
        print(f"\n  [INFO] Type dispatch detected (cmp against: {type_vals})")
        print("         The handler uses a 'type' arg to select different keys:")
        print("           type 0 = PS5UPDATE2.PUP (recovery update)")
        print("           type 1 = PS5UPDATE1.PUP (system update) <-- primary target")
        print("           type 2 = unknown/reserved")
        print("         Trace the branch after 'cmp ..., 1' to find the system update key.")

    # Summary action
    high_targets = [t for t in ranked_targets if t["confidence"] == "HIGH"]
    if high_targets:
        best = high_targets[0]
        print(f"\n  >>> RECOMMENDED NEXT STEP:")
        print(f"      {best['command']}")
        print(f"      Then re-run: python analyze_dump.py pup_key_dump.bin")

    return ranked_targets


def save_handler_binaries(sections: list, cdevsw_ptrs: dict, output_dir: Path):
    """Save handler sections as .bin files for Ghidra/IDA import."""
    output_dir.mkdir(parents=True, exist_ok=True)

    section_to_name = {
        SECTION_IOCTL: ("d_ioctl", "d_ioctl"),
        SECTION_HANDLER_OPEN: ("d_open", "d_open"),
        SECTION_HANDLER_CLOSE: ("d_close", "d_close"),
        SECTION_CDEVSW: ("cdevsw", None),
    }

    for sec in sections:
        if sec["type"] in section_to_name:
            filename, ptr_key = section_to_name[sec["type"]]
            outpath = output_dir / f"{filename}.bin"
            outpath.write_bytes(sec["data"])
            addr = cdevsw_ptrs.get(ptr_key, 0) if ptr_key else 0
            print(f"  Saved {outpath} ({len(sec['data'])} bytes)", end="")
            if addr:
                print(f" — load at base 0x{addr:x} in Ghidra")
            else:
                print()

    # Write a Ghidra loader script
    script_path = output_dir / "ghidra_import.py"
    lines = ["# Ghidra script: run in Ghidra's Script Manager after importing .bin files",
             "# This sets the correct base addresses for each handler binary.", ""]
    for sec in sections:
        if sec["type"] in section_to_name:
            filename, ptr_key = section_to_name[sec["type"]]
            if ptr_key and ptr_key in cdevsw_ptrs:
                addr = cdevsw_ptrs[ptr_key]
                lines.append(f"# {filename}.bin: base address = 0x{addr:x}")
    lines.append("")
    lines.append("# Import each .bin as Raw Binary, x86:LE:64:default")
    lines.append("# Set the base address listed above for each file")
    script_path.write_text("\n".join(lines))
    print(f"  Saved {script_path} — Ghidra base address reference")


# =====================================================================
# Main
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze PS5 PUP key dump — test keys and auto-disassemble handlers")
    parser.add_argument("dumpfile", help="Path to pup_key_dump.bin")
    parser.add_argument("--pup14", default=DEFAULT_PUP_14_00,
                        help="Path to PS5UPDATE14.00.PUP")
    parser.add_argument("--pup14_1", default=DEFAULT_PUP_14_10,
                        help="Path to PS5UPDATE14.10.PUP")
    parser.add_argument("--save-handlers", action="store_true",
                        help="Save handler .bin files for Ghidra/IDA import")
    args = parser.parse_args()

    dump_path = Path(args.dumpfile)
    if not dump_path.exists():
        print(f"[!] Dump file not found: {args.dumpfile}")
        sys.exit(1)

    print(f"[*] Reading dump: {args.dumpfile}")
    dump_data = dump_path.read_bytes()
    parsed = parse_dump(dump_data)
    if parsed is None:
        sys.exit(1)

    # ---- Phase 1: Display metadata sections ----
    cdevsw_ptrs = {}
    ccp_info = None

    for sec in parsed["sections"]:
        if sec["type"] == SECTION_CDEVSW:
            cdevsw_ptrs = display_cdevsw(sec["data"])
        elif sec["type"] == SECTION_CCP_REGS:
            ccp_info = display_ccp_regs(sec["data"])
        elif sec["type"] == SECTION_ADDR_READ:
            hexdump_section(sec["data"], "Targeted Address Read")
        elif sec["type"] == SECTION_MEMSCAN:
            hexdump_section(sec["data"], "Kernel Memory Scan Match")

    # ---- Phase 2: Test LSB key candidates ----
    changed_slots = find_lsb_diff(parsed["sections"])
    if changed_slots:
        print(f"\n[+] {len(changed_slots)} LSB slots changed during decrypt — high-priority candidates")

    candidates = extract_key_candidates(parsed["sections"])
    print(f"\n[*] Extracted {len(candidates)} unique key candidates")

    pup_headers = {}
    header_14 = read_pup_header(args.pup14)
    if header_14:
        print(f"  14.00: {len(header_14)} bytes from offset 0x{PUP_HEADER_OFFSET:x}")
        pup_headers["FW 14.00"] = (header_14, PUP_14_00_BLS_SIZE)
    header_14_1 = read_pup_header(args.pup14_1)
    if header_14_1:
        print(f"  14.10: {len(header_14_1)} bytes from offset 0x{PUP_HEADER_OFFSET:x}")
        pup_headers["FW 14.10"] = (header_14_1, PUP_14_10_BLS_SIZE)

    matches = []
    if candidates and pup_headers:
        print(f"\n[*] Testing {len(candidates)} candidates against {len(pup_headers)} PUP files...")
        for i, cand in enumerate(candidates):
            if i > 0 and i % 100 == 0:
                print(f"  ... tested {i}/{len(candidates)}")
            if test_key_against_pups(cand["key"], pup_headers):
                matches.append(cand)
                print(f"  KEY FOUND: {cand['key'].hex()}")
                print(f"  Source: {cand['source']}, slot {cand['slot']}")

        if changed_slots:
            print(f"\n[*] Priority testing {len(changed_slots)} changed LSB slots...")
            for cs in changed_slots:
                for offset in (0, 16):
                    key = cs["after"][offset:offset + 16]
                    if key == b"\x00" * 16:
                        continue
                    print(f"  Testing changed slot {cs['slot']} offset {offset}: {key.hex()}")
                    if test_key_against_pups(key, pup_headers):
                        matches.append({
                            "key": key,
                            "source": f"Changed LSB slot {cs['slot']} (post-decrypt)",
                            "slot": cs["slot"], "full_slot": cs["after"],
                        })
    elif candidates and not pup_headers:
        print("[!] No PUP files available for testing")
        print("[*] Listing key candidates:\n")
        for i, cand in enumerate(candidates[:30]):
            print(f"  {i}: {cand['key'].hex()} — {cand['source']}")

    # ---- Phase 2 results ----
    print(f"\n{'=' * 60}")
    if matches:
        print(f"[+] FOUND {len(matches)} MATCHING KEY(S)!")
        for m in matches:
            print(f"    Key:    {m['key'].hex()}")
            print(f"    Source: {m['source']}")
        print(f"{'=' * 60}")
        print("\n[+] Add this key to keys.py as PUP_CONTAINER_KEY and you're done!")
        return
    else:
        print("[*] No matching keys in LSB data — moving to handler analysis...")
    print(f"{'=' * 60}")

    # ---- Phase 3: Automated handler disassembly ----
    if not HAS_CAPSTONE:
        print("\n[!] capstone not installed — skipping automated disassembly")
        print("    Install with: pip install capstone")
        print("    Or manually extract handler .bin files with --save-handlers")
    else:
        print(f"\n[*] Automated handler disassembly (capstone)...")

        handler_map = {
            SECTION_IOCTL: ("d_ioctl (DecryptPupHeader)", "d_ioctl"),
            SECTION_HANDLER_OPEN: ("d_open (device open)", "d_open"),
            SECTION_HANDLER_CLOSE: ("d_close (device close)", "d_close"),
        }

        all_analysis = []
        for sec in parsed["sections"]:
            if sec["type"] in handler_map:
                label, ptr_key = handler_map[sec["type"]]
                base_addr = cdevsw_ptrs.get(ptr_key, 0)
                if base_addr == 0:
                    base_addr = 0xFFFFFFFF82200000
                    print(f"\n[!] No cdevsw base for {label}, using default 0x{base_addr:x}")

                analysis = analyze_handler(sec["data"], base_addr, label)
                if analysis:
                    all_analysis.append(analysis)
                    print_analysis(analysis)

        # Generate combined recommendations
        if all_analysis:
            generate_recommendations(all_analysis, ccp_info)

    # ---- Save handler binaries if requested ----
    if args.save_handlers:
        out_dir = dump_path.parent / "handlers"
        print(f"\n[*] Saving handler binaries to {out_dir}/")
        save_handler_binaries(parsed["sections"], cdevsw_ptrs, out_dir)

    # ---- Final summary ----
    print(f"\n{'=' * 60}")
    print("[*] Analysis complete.")
    if not matches:
        print("[*] No key found in direct LSB data.")
        print("[*] Check the AUTOMATED RECOMMENDATIONS above for next steps.")
        if not args.save_handlers:
            print("[*] For manual Ghidra RE, re-run with --save-handlers")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
