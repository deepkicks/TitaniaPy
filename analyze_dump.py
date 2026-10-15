"""
analyze_dump.py — Parse pup_key_dump.bin and test key candidates against PUP headers.

Reads the structured dump from ps5_key_extract.c, extracts all key candidates
from CCP LSB slots, and tries AES-128-CBC/ECB decryption against the encrypted
PUP headers from two firmware files.

Usage:
    python analyze_dump.py pup_key_dump.bin
    python analyze_dump.py pup_key_dump.bin --pup14 path/to/14.00.PUP --pup14_1 path/to/14.10.PUP
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERROR: pycryptodome required. Install with: pip install pycryptodome")
    sys.exit(1)

# --- Dump format constants (must match ps5_key_extract.c) ---
DUMP_MAGIC       = 0x505550444D50  # "PUPDMP\0\0" as uint64 LE
SECTION_LSB      = 0x01
SECTION_IOCTL    = 0x02
SECTION_SNAP_PRE = 0x03
SECTION_SNAP_POST = 0x04
SECTION_MEMSCAN  = 0x05

SECTION_NAMES = {
    SECTION_LSB: "CCP LSB Key Slots",
    SECTION_IOCTL: "ioctl Handler Code",
    SECTION_SNAP_PRE: "Pre-Decrypt LSB Snapshot",
    SECTION_SNAP_POST: "Post-Decrypt LSB Snapshot",
    SECTION_MEMSCAN: "Kernel Memory Scan",
}

# LSB geometry
LSB_COUNT = 8
SLOTS_PER_LSB = 16
SLOT_SIZE = 32
LSB_TOTAL_SIZE = LSB_COUNT * SLOTS_PER_LSB * SLOT_SIZE  # 4096

# PUP header constants
PUP_HEADER_OFFSET = 0x410
PUP_HEADER_READ_SIZE = 64  # read enough for testing

# Known BLS entry sizes for validation
PUP_14_00_BLS_SIZE = 0x4B2339D5
PUP_14_10_BLS_SIZE = 0x4B2F8A3D

# Default PUP file paths (set to your local paths or pass via --pup14 / --pup14_1)
DEFAULT_PUP_14_00 = "PS5UPDATE14.00.PUP"
DEFAULT_PUP_14_10 = "PS5UPDATE14.10.PUP"


def parse_dump(data: bytes) -> dict:
    """Parse the structured dump file."""
    if len(data) < 16:
        print(f"[!] Dump file too small ({len(data)} bytes)")
        return None

    magic, version, section_count = struct.unpack_from("<QII", data, 0)

    if magic != DUMP_MAGIC:
        print(f"[!] Bad magic: 0x{magic:012x} (expected 0x{DUMP_MAGIC:012x})")
        return None

    print(f"[+] Dump version {version}, {section_count} sections")

    header_size = 16  # dump_header_t
    section_hdr_size = 16  # section_header_t
    max_sections = 32
    section_table_offset = header_size

    sections = []
    for i in range(min(section_count, max_sections)):
        off = section_table_offset + i * section_hdr_size
        stype, ssize, soffset, _ = struct.unpack_from("<IIII", data, off)
        name = SECTION_NAMES.get(stype, f"Unknown(0x{stype:02x})")
        print(f"  Section {i}: {name}, {ssize} bytes at offset 0x{soffset:x}")

        if soffset + ssize <= len(data):
            section_data = data[soffset:soffset + ssize]
        else:
            print(f"  [!] Section data extends past end of file")
            section_data = data[soffset:] if soffset < len(data) else b""

        sections.append({
            "type": stype,
            "size": ssize,
            "offset": soffset,
            "data": section_data,
            "name": name,
        })

    return {"version": version, "sections": sections}


def extract_key_candidates(sections: list) -> list:
    """Extract all possible 16-byte key candidates from LSB sections."""
    candidates = []
    seen = set()

    for sec in sections:
        if sec["type"] not in (SECTION_LSB, SECTION_SNAP_PRE, SECTION_SNAP_POST):
            continue

        data = sec["data"]
        # Extract each 32-byte slot, then take the first 16 bytes as AES-128 key
        total_slots = len(data) // SLOT_SIZE
        for slot_idx in range(total_slots):
            slot = data[slot_idx * SLOT_SIZE:(slot_idx + 1) * SLOT_SIZE]

            if slot == b"\x00" * SLOT_SIZE:
                continue

            # AES-128 key = first 16 bytes of the slot
            key16 = slot[:16]
            key_hex = key16.hex()
            if key_hex not in seen:
                seen.add(key_hex)
                candidates.append({
                    "key": key16,
                    "source": sec["name"],
                    "slot": slot_idx,
                    "full_slot": slot,
                })

            # Also try second 16 bytes (AES-128 key might be in upper half)
            key16b = slot[16:32]
            key_hex_b = key16b.hex()
            if key_hex_b not in seen and key16b != b"\x00" * 16:
                seen.add(key_hex_b)
                candidates.append({
                    "key": key16b,
                    "source": sec["name"] + " (upper half)",
                    "slot": slot_idx,
                    "full_slot": slot,
                })

    # Also do sliding 16-byte window over all section data
    for sec in sections:
        data = sec["data"]
        if len(data) < 16:
            continue
        for i in range(0, len(data) - 15, 4):  # 4-byte aligned
            window = data[i:i + 16]
            if window == b"\x00" * 16:
                continue
            whex = window.hex()
            if whex not in seen:
                seen.add(whex)
                candidates.append({
                    "key": window,
                    "source": f"{sec['name']} @ offset 0x{i:x}",
                    "slot": -1,
                    "full_slot": None,
                })

    return candidates


def find_lsb_diff(sections: list) -> list:
    """Find LSB slots that changed between pre and post snapshots."""
    pre_data = None
    post_data = None

    for sec in sections:
        if sec["type"] == SECTION_SNAP_PRE:
            pre_data = sec["data"]
        elif sec["type"] == SECTION_SNAP_POST:
            post_data = sec["data"]

    if pre_data is None or post_data is None:
        return []

    changed = []
    min_len = min(len(pre_data), len(post_data))
    total_slots = min_len // SLOT_SIZE

    for slot_idx in range(total_slots):
        pre_slot = pre_data[slot_idx * SLOT_SIZE:(slot_idx + 1) * SLOT_SIZE]
        post_slot = post_data[slot_idx * SLOT_SIZE:(slot_idx + 1) * SLOT_SIZE]

        if pre_slot != post_slot:
            print(f"[!] LSB slot {slot_idx} CHANGED during decrypt:")
            print(f"    Before: {pre_slot.hex()}")
            print(f"    After:  {post_slot.hex()}")
            changed.append({
                "slot": slot_idx,
                "before": pre_slot,
                "after": post_slot,
            })

    return changed


def read_pup_header(pup_path: str, offset: int = PUP_HEADER_OFFSET,
                    size: int = PUP_HEADER_READ_SIZE) -> bytes | None:
    """Read encrypted header bytes from a PUP file."""
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
    """
    Check if decrypted data looks like a valid PUP segment table entry.
    Expected layout:
      offset 0: uint64 LE — file_size (should be within 1MB of BLS entry size)
      offset 8: uint16 LE — segment_count (should be 1-99)
    """
    if len(decrypted) < 16:
        return False

    file_size = struct.unpack_from("<Q", decrypted, 0)[0]
    segment_count = struct.unpack_from("<H", decrypted, 8)[0]

    size_diff = abs(int(file_size) - int(expected_bls_size))
    size_ok = size_diff < (1024 * 1024)  # within 1MB
    count_ok = 1 <= segment_count <= 99

    if size_ok and count_ok:
        print(f"  [!!!] MATCH on {pup_name}!")
        print(f"        file_size=0x{file_size:x} (diff={size_diff} from BLS 0x{expected_bls_size:x})")
        print(f"        segment_count={segment_count}")
        print(f"        Full decrypted: {decrypted[:32].hex()}")
        return True

    return False


def test_key_against_pups(key: bytes, pup_headers: dict) -> bool:
    """Try a key with AES-128-CBC (zero IV) and AES-128-ECB on each PUP header."""
    matched = False

    for pup_name, (header_data, bls_size) in pup_headers.items():
        if header_data is None:
            continue

        enc_block = header_data[:32]  # first 32 bytes (2 AES blocks)

        # AES-128-CBC with zero IV
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
            dec_cbc = cipher.decrypt(enc_block)
            if validate_decrypted_header(dec_cbc, bls_size, f"{pup_name} (CBC)"):
                matched = True
        except (ValueError, KeyError):
            pass

        # AES-128-ECB
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            dec_ecb = cipher.decrypt(enc_block)
            if validate_decrypted_header(dec_ecb, bls_size, f"{pup_name} (ECB)"):
                matched = True
        except (ValueError, KeyError):
            pass

    return matched


def hexdump_section(data: bytes, label: str, max_bytes: int = 256):
    """Print a hex dump of section data."""
    print(f"\n--- {label} ---")
    show = min(len(data), max_bytes)
    for i in range(0, show, 16):
        hex_part = " ".join(f"{b:02x}" for b in data[i:i + 16])
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in data[i:i + 16]
        )
        print(f"  {i:04x}: {hex_part:<48s}  {ascii_part}")
    if show < len(data):
        print(f"  ... ({len(data) - show} more bytes)")


def main():
    parser = argparse.ArgumentParser(description="Analyze PS5 PUP key dump")
    parser.add_argument("dumpfile", help="Path to pup_key_dump.bin")
    parser.add_argument("--pup14", default=DEFAULT_PUP_14_00,
                        help="Path to PS5UPDATE14.00.PUP")
    parser.add_argument("--pup14_1", default=DEFAULT_PUP_14_10,
                        help="Path to PS5UPDATE14.10.PUP")
    args = parser.parse_args()

    # Read dump file
    dump_path = Path(args.dumpfile)
    if not dump_path.exists():
        print(f"[!] Dump file not found: {args.dumpfile}")
        sys.exit(1)

    print(f"[*] Reading dump: {args.dumpfile}")
    dump_data = dump_path.read_bytes()
    parsed = parse_dump(dump_data)
    if parsed is None:
        sys.exit(1)

    # Display ioctl handler sections
    for sec in parsed["sections"]:
        if sec["type"] == SECTION_IOCTL:
            hexdump_section(sec["data"], "ioctl Handler Code (DecryptPupHeader)")
        elif sec["type"] == SECTION_MEMSCAN:
            hexdump_section(sec["data"], f"Kernel Memory Scan Match")

    # Check for LSB diff (approach 3)
    changed_slots = find_lsb_diff(parsed["sections"])
    if changed_slots:
        print(f"\n[+] {len(changed_slots)} LSB slots changed during decrypt — high-priority candidates")

    # Extract key candidates
    candidates = extract_key_candidates(parsed["sections"])
    print(f"\n[*] Extracted {len(candidates)} unique key candidates")

    if not candidates:
        print("[!] No key candidates found in dump. Possible issues:")
        print("    - CCP LSB region not accessible via MMIO")
        print("    - LSB contents cleared after use")
        print("    - Key stored in PSP SRAM, not CCP LSB")
        sys.exit(1)

    # Read PUP headers
    print(f"\n[*] Reading PUP headers...")
    pup_headers = {}

    header_14 = read_pup_header(args.pup14)
    if header_14:
        print(f"  14.00: {len(header_14)} bytes from offset 0x{PUP_HEADER_OFFSET:x}")
        pup_headers["FW 14.00"] = (header_14, PUP_14_00_BLS_SIZE)

    header_14_1 = read_pup_header(args.pup14_1)
    if header_14_1:
        print(f"  14.10: {len(header_14_1)} bytes from offset 0x{PUP_HEADER_OFFSET:x}")
        pup_headers["FW 14.10"] = (header_14_1, PUP_14_10_BLS_SIZE)

    if not pup_headers:
        print("[!] No PUP files available for testing")
        print("[*] Listing all key candidates instead:\n")
        for i, cand in enumerate(candidates):
            print(f"  Candidate {i}: {cand['key'].hex()}")
            print(f"    Source: {cand['source']}, slot {cand['slot']}")
            if cand['full_slot']:
                print(f"    Full:   {cand['full_slot'].hex()}")
        sys.exit(0)

    # Test each candidate
    print(f"\n[*] Testing {len(candidates)} candidates against {len(pup_headers)} PUP files...")
    matches = []

    for i, cand in enumerate(candidates):
        if i > 0 and i % 100 == 0:
            print(f"  ... tested {i}/{len(candidates)}")

        if test_key_against_pups(cand["key"], pup_headers):
            matches.append(cand)
            print(f"  KEY FOUND: {cand['key'].hex()}")
            print(f"  Source: {cand['source']}, slot {cand['slot']}")

    # Priority test: changed slots from approach 3
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
                        "slot": cs["slot"],
                        "full_slot": cs["after"],
                    })

    # Report
    print(f"\n{'=' * 60}")
    if matches:
        print(f"[+] FOUND {len(matches)} MATCHING KEY(S)!")
        for m in matches:
            print(f"    Key:    {m['key'].hex()}")
            print(f"    Source: {m['source']}")
    else:
        print("[*] No matching keys found.")
        print("[*] Possible reasons:")
        print("    - Key is AES-256, not AES-128")
        print("    - Different cipher mode (CTR, XTS, etc.)")
        print("    - Header structure differs from expected layout")
        print("    - Key not present in dumped LSB data")
        print("[*] Next steps:")
        print("    - Try AES-256 with 32-byte slot data")
        print("    - Reverse the ioctl handler code to find the exact algorithm")
        print("    - Use approach 3 with real DMA memory for live capture")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
