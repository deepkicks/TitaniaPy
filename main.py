"""
PS5 PUP Decrypt Tool - CLI Entry Point
Partial PC-based tool for PS5 firmware analysis.

What works (Layer 3 - known keys):
  - BLS container parsing (outer SLB2 format)
  - PUP header/segment structure parsing
  - Inner firmware decryption (EMC IPL, EAP KBL, EAP Kernel, Titania)

What's missing (Layer 1 - key derivation):
  - PUP segment decryption (needs KMB_AES derivation chain)
  - Full end-to-end PUP decryption pipeline
"""
import argparse
import os
import sys
import zlib

from bls import parse_bls_header, extract_bls_entry, BLS_MAGIC
from pup import parse_pup_header, parse_pup_segments, try_parse_pup, PUP_MAGIC
from firmware import (
    detect_firmware_type,
    decrypt_firmware_blob,
    try_all_decryptions,
    analyze_emc_ipl,
)
from crypto import show_experimental_derivation


def cmd_info(args):
    """Show BLS and PUP structure info for a PUP file."""
    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return 1

    print(f"=== PS5 PUP Info: {os.path.basename(filepath)} ===")
    print(f"File size: {os.path.getsize(filepath):,} bytes")
    print()

    with open(filepath, "rb") as f:
        # Check BLS magic
        magic_bytes = f.read(4)
        f.seek(0)

        import struct
        magic = struct.unpack_from("<I", magic_bytes, 0)[0]

        if magic == BLS_MAGIC:
            print("[BLS Container]")
            try:
                header = parse_bls_header(f)
                print(f"  Version:    {header.version}")
                print(f"  Flags:      0x{header.flags:X}")
                print(f"  File count: {header.file_count}")
                print(f"  Block count: {header.block_count}")
                print()

                print(f"{'#':<4} {'Name':<32} {'Offset':<14} {'Size':<14}")
                print("-" * 68)
                for entry in header.entries:
                    print(
                        f"{entry.index:<4} {entry.name:<32} "
                        f"0x{entry.byte_offset:<12X} 0x{entry.size:<12X}"
                    )
                print()

                # Try to parse each entry as PUP
                for entry in header.entries:
                    f.seek(entry.byte_offset)
                    pup_peek = f.read(min(entry.size, 0x2000))
                    pup_info = try_parse_pup(pup_peek)
                    if pup_info and pup_info.get("magic_valid"):
                        _print_pup_info(entry.name, pup_info, entry.size)

            except Exception as e:
                print(f"  Error parsing BLS: {e}")
        elif magic == PUP_MAGIC:
            print("[Raw PUP (no BLS wrapper)]")
            data = f.read()
            pup_info = try_parse_pup(data)
            if pup_info:
                _print_pup_info("(root)", pup_info)
        else:
            print(f"Unknown file format. Magic: 0x{magic:08X}")
            print("Expected BLS (0x32424C53) or PUP (0xEEF51454)")
            return 1

    return 0


def _print_pup_info(name, pup_info, bls_entry_size=0):
    """Print PUP structure details."""
    print(f"[PUP Entry: {name}]")

    header = pup_info.get("header")
    is_encrypted = pup_info.get("encrypted", False)

    if header:
        fh = header.file_header
        print(f"  Magic:         0x{fh.magic:08X} (valid)")
        print(f"  unknown_04:    0x{fh.unknown_04:08X}")
        print(f"  Header size:   0x{fh.header_size:X} ({fh.header_size} bytes)")
        print(f"  Hash size:     0x{fh.hash_size:X} ({fh.hash_size} bytes)")

        if is_encrypted:
            # Estimate segment count from header_size
            seg_table_bytes = fh.header_size - 0x20
            est_segs = seg_table_bytes // 32
            data_offset = fh.header_size + fh.hash_size
            print()
            print(f"  Status: ENCRYPTED")
            print(f"    - File header (16 bytes): plaintext")
            print(f"    - Extended header + segment table (0x10 to 0x{fh.header_size:X}): encrypted")
            print(f"    - Hash/signature table (0x{fh.header_size:X} to 0x{data_offset:X}): encrypted")
            print(f"    - Segment data (0x{data_offset:X}+): encrypted")
            print(f"    - Estimated segment count: ~{est_segs} (from header_size)")
            if bls_entry_size:
                print(f"    - Total PUP size: {bls_entry_size:,} bytes ({bls_entry_size/1024/1024:.1f} MB)")
            print(f"    - Decryption requires: Layer 1 key derivation (KMB_AES chain)")
        else:
            print(f"  File size:     0x{header.file_size:X}")
            print(f"  Segments:      {header.segment_count}")

        print()

    segments = pup_info.get("segments", [])
    if segments and not is_encrypted:
        print(f"  {'#':<4} {'ID':<6} {'Name':<28} {'Compressed':<14} {'Uncompressed':<14} {'Flags'}")
        print("  " + "-" * 90)
        for seg in segments:
            if seg.segment_type in (0xE, 0xF):
                print(f"  {seg.index:<4} {'--':<6} {seg.type_name:<28} {'--':<14} {'--':<14} 0x{seg.flags:08X}")
            else:
                flags_parts = []
                if seg.is_compressed:
                    flags_parts.append("ZLIB")
                if seg.is_blocked:
                    flags_parts.append(f"BLK(0x{seg.block_size:X})")
                if seg.is_table:
                    flags_parts.append("TBL")
                flags_str = " ".join(flags_parts) if flags_parts else "SIMPLE"

                print(
                    f"  {seg.index:<4} 0x{seg.segment_id:<4X} {seg.name:<28} "
                    f"0x{seg.compressed_size:<12X} 0x{seg.uncompressed_size:<12X} {flags_str}"
                )
        print()


def cmd_extract(args):
    """Extract BLS entries to disk."""
    filepath = args.file
    output_dir = args.output or os.path.splitext(filepath)[0] + "_extracted"

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return 1

    os.makedirs(output_dir, exist_ok=True)

    with open(filepath, "rb") as f:
        try:
            header = parse_bls_header(f)
        except ValueError as e:
            print(f"Error: {e}")
            return 1

        print(f"Extracting {header.file_count} BLS entries to {output_dir}/")
        for entry in header.entries:
            data = extract_bls_entry(f, entry)
            out_path = os.path.join(output_dir, entry.name)
            with open(out_path, "wb") as out:
                out.write(data)
            print(f"  {entry.name} ({len(data):,} bytes)")

    print(f"\nExtracted {header.file_count} entries.")
    return 0


def cmd_decrypt(args):
    """Decrypt an extracted firmware blob with known keys."""
    filepath = args.file
    fw_type = args.type
    titania_rev = args.titania_rev

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return 1

    with open(filepath, "rb") as f:
        data = f.read()

    if not fw_type:
        fw_type = detect_firmware_type(data, os.path.basename(filepath))
        if fw_type:
            print(f"Auto-detected firmware type: {fw_type}")
        else:
            print("Could not auto-detect firmware type.")
            print("Use --type with one of: emc_ipl_header, emc_ipl, eap_kbl, eap_kernel, eap_self, titania")
            return 1

    print(f"Decrypting {os.path.basename(filepath)} as {fw_type}...")
    result = decrypt_firmware_blob(data, fw_type, titania_rev)

    if result is None:
        print(f"No key available for type '{fw_type}' (rev {titania_rev})")
        return 1

    output = args.output
    if not output:
        base, ext = os.path.splitext(filepath)
        output = f"{base}.dec{ext}"

    with open(output, "wb") as f:
        f.write(result)

    print(f"Decrypted {len(result):,} bytes -> {output}")

    # Show first 64 bytes hex dump
    print("\nFirst 64 bytes of decrypted output:")
    _hexdump(result[:64])

    return 0


def cmd_bruteforce(args):
    """Try all known keys against a firmware blob."""
    filepath = args.file
    output_dir = args.output or os.path.splitext(filepath)[0] + "_bruteforce"

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return 1

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"Trying all known keys against {os.path.basename(filepath)}...")
    print(f"Output dir: {output_dir}/")
    print()

    results = try_all_decryptions(data, output_dir, os.path.splitext(os.path.basename(filepath))[0])

    print(f"{'Key':<20} {'Description':<30} {'Result'}")
    print("-" * 80)
    for key_name, description, verdict in results:
        marker = ">>>" if "likely correct" in verdict.lower() or "POSSIBLE" in verdict else "   "
        print(f"{marker} {key_name:<20} {description:<30} {verdict}")

    print()
    print("LOW_ENTROPY = likely correct decryption (structured data)")
    print("POSSIBLE_MATCH = has null runs and ASCII (worth investigating)")
    print("HIGH_ENTROPY = still looks encrypted or wrong key")
    return 0


def cmd_analyze(args):
    """Analyze an EMC IPL blob in detail."""
    filepath = args.file

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return 1

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"=== EMC IPL Analysis: {os.path.basename(filepath)} ===")
    print(f"Size: {len(data):,} bytes")
    print()

    info = analyze_emc_ipl(data)

    if "header_magic" in info:
        print(f"Decrypted header magic: {info['header_magic']}")
    if "possible_hdr_len" in info:
        print(f"Possible header length: 0x{info['possible_hdr_len']:X}")
    if "possible_body_len" in info:
        print(f"Possible body length:   0x{info['possible_body_len']:X}")

    if "header_decrypted" in info:
        print("\nDecrypted header (first 0x80 bytes):")
        _hexdump(info["header_decrypted"])

    return 0


def cmd_decompress(args):
    """Decompress a zlib-compressed segment."""
    filepath = args.file

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return 1

    with open(filepath, "rb") as f:
        data = f.read()

    try:
        decompressed = zlib.decompress(data)
    except zlib.error as e:
        print(f"Decompression failed: {e}")
        print("Data may not be zlib-compressed, or may still be encrypted.")
        return 1

    output = args.output
    if not output:
        base, ext = os.path.splitext(filepath)
        output = f"{base}.decompressed{ext}"

    with open(output, "wb") as f:
        f.write(decompressed)

    ratio = len(decompressed) / len(data) if data else 0
    print(f"Decompressed: {len(data):,} -> {len(decompressed):,} bytes ({ratio:.1f}x)")
    print(f"Output: {output}")
    return 0


def cmd_keys(args):
    """Show known keys and experimental derivation."""
    show_experimental_derivation()


def _hexdump(data: bytes, width: int = 16):
    """Print a hex dump of data."""
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"  {offset:08X}  {hex_part:<{width * 3}}  {ascii_part}")


def main():
    parser = argparse.ArgumentParser(
        description="PS5 PUP Decrypt Tool - Partial PC-based firmware analyzer",
        epilog=(
            "Layer 3 (known keys) is fully functional.\n"
            "Layer 1 (PUP segment decryption) requires key derivation research.\n"
            "For security research on personally owned hardware only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # info
    p_info = subparsers.add_parser("info", help="Show PUP/BLS structure info")
    p_info.add_argument("file", help="Path to PS5UPDATE.PUP or extracted PUP")
    p_info.set_defaults(func=cmd_info)

    # extract
    p_extract = subparsers.add_parser("extract", help="Extract BLS entries to disk")
    p_extract.add_argument("file", help="Path to PS5UPDATE.PUP")
    p_extract.add_argument("-o", "--output", help="Output directory")
    p_extract.set_defaults(func=cmd_extract)

    # decrypt
    p_decrypt = subparsers.add_parser("decrypt", help="Decrypt firmware blob with known key")
    p_decrypt.add_argument("file", help="Path to extracted firmware blob")
    p_decrypt.add_argument(
        "-t", "--type",
        choices=["emc_ipl_header", "emc_ipl", "eap_kbl", "eap_kernel", "eap_self", "titania"],
        help="Firmware type (auto-detected from filename if omitted)",
    )
    p_decrypt.add_argument("-o", "--output", help="Output file path")
    p_decrypt.add_argument("--titania-rev", type=int, default=2, choices=[1, 2, 3],
                           help="Titania hardware revision (default: 2)")
    p_decrypt.set_defaults(func=cmd_decrypt)

    # bruteforce
    p_brute = subparsers.add_parser("bruteforce", help="Try all known keys against a blob")
    p_brute.add_argument("file", help="Path to firmware blob")
    p_brute.add_argument("-o", "--output", help="Output directory")
    p_brute.set_defaults(func=cmd_bruteforce)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze EMC IPL blob structure")
    p_analyze.add_argument("file", help="Path to EMC IPL blob")
    p_analyze.set_defaults(func=cmd_analyze)

    # decompress
    p_decomp = subparsers.add_parser("decompress", help="Zlib-decompress a segment")
    p_decomp.add_argument("file", help="Path to compressed segment")
    p_decomp.add_argument("-o", "--output", help="Output file path")
    p_decomp.set_defaults(func=cmd_decompress)

    # keys
    p_keys = subparsers.add_parser("keys", help="Show known keys and derivation experiments")
    p_keys.set_defaults(func=cmd_keys)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Error: pycryptodome is required. Install it with:")
        print("  pip install pycryptodome")
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
