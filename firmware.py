"""
Inner Firmware Decryptor
Decrypts already-extracted firmware segments using known keys.
This is Layer 3 - works on raw firmware blobs, not on encrypted PUP segments.
"""
import os
import struct
from typing import Optional

from crypto import (
    aes_128_cbc_decrypt,
    decrypt_emc_ipl_header,
    decrypt_emc_ipl_body,
    decrypt_eap_kbl,
    decrypt_eap_kernel,
    decrypt_eap_kernel_self,
    decrypt_with_titania_key,
)


def detect_firmware_type(data: bytes, filename: str = "") -> Optional[str]:
    """Guess the firmware type from filename or content."""
    fn = filename.lower()
    if "emc_salina" in fn or "emc_ipl" in fn:
        return "emc_ipl"
    if "eap_kbl" in fn:
        return "eap_kbl"
    if "eap_kernel" in fn or "eap_kern" in fn:
        return "eap_kernel"
    if "titania" in fn:
        return "titania"
    if fn.endswith(".self"):
        return "eap_self"
    return None


def decrypt_firmware_blob(
    data: bytes, fw_type: str, titania_rev: int = 2
) -> Optional[bytes]:
    """
    Decrypt a firmware blob using the appropriate known key.

    Args:
        data: raw encrypted firmware bytes
        fw_type: one of 'emc_ipl', 'emc_ipl_header', 'eap_kbl',
                 'eap_kernel', 'eap_self', 'titania'
        titania_rev: Titania hardware revision (1, 2, or 3)

    Returns:
        Decrypted bytes, or None if key not available for this type
    """
    if fw_type == "emc_ipl_header":
        return decrypt_emc_ipl_header(data)
    elif fw_type == "emc_ipl":
        return decrypt_emc_ipl_body(data)
    elif fw_type == "eap_kbl":
        return decrypt_eap_kbl(data)
    elif fw_type == "eap_kernel":
        return decrypt_eap_kernel(data)
    elif fw_type == "eap_self":
        return decrypt_eap_kernel_self(data)
    elif fw_type == "titania":
        return decrypt_with_titania_key(data, titania_rev)
    return None


def try_all_decryptions(data: bytes, output_dir: str, base_name: str):
    """
    Try decrypting data with all known keys and save results.
    Useful for identifying which key works on unknown segments.
    """
    os.makedirs(output_dir, exist_ok=True)

    attempts = [
        ("emc_ipl_header", "EMC IPL Header Key"),
        ("emc_ipl", "EMC IPL Cipher Key (rev c0)"),
        ("eap_kbl", "EAP KBL Key"),
        ("eap_kernel", "EAP KBL Kernel Key"),
        ("eap_self", "EAP Kernel SELF Key"),
    ]

    # Also try Titania keys
    for rev in (1, 2, 3):
        attempts.append((f"titania_rev{rev}", f"Titania Rev {rev} Key"))

    results = []
    for key_name, description in attempts:
        try:
            if key_name.startswith("titania_rev"):
                rev = int(key_name[-1])
                decrypted = decrypt_with_titania_key(data[:256], rev)
            else:
                decrypted = decrypt_firmware_blob(data[:256], key_name)

            if decrypted is None:
                results.append((key_name, description, "NO KEY AVAILABLE"))
                continue

            # Check if decrypted data looks reasonable
            entropy = _estimate_entropy(decrypted[:64])
            has_nulls = b"\x00\x00\x00\x00" in decrypted[:64]
            has_ascii = any(32 <= b <= 126 for b in decrypted[:32])

            verdict = "HIGH_ENTROPY"
            if entropy < 4.0:
                verdict = "LOW_ENTROPY (likely correct!)"
            elif has_nulls and has_ascii:
                verdict = "POSSIBLE_MATCH"

            results.append((key_name, description, verdict))

            # Save first 256 bytes for inspection
            out_path = os.path.join(output_dir, f"{base_name}.{key_name}.bin")
            with open(out_path, "wb") as f:
                f.write(decrypted)

        except Exception as e:
            results.append((key_name, description, f"ERROR: {e}"))

    return results


def _estimate_entropy(data: bytes) -> float:
    """Rough Shannon entropy estimate (0-8 bits per byte)."""
    import math

    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def analyze_emc_ipl(data: bytes) -> dict:
    """
    Analyze an EMC IPL blob structure.
    Based on PS4 Aeolia IPL header (fail0verflow), adapted for PS5.
    """
    result = {"size": len(data)}

    # Try decrypting header with known key
    if len(data) >= 0x80:
        dec_header = decrypt_emc_ipl_header(data[:0x80])
        result["header_decrypted"] = dec_header

        # Check for PS4-style magic at start
        magic = struct.unpack_from("<I", dec_header, 0)[0]
        result["header_magic"] = f"0x{magic:08X}"

        # Try to extract fields similar to PS4 aeolia_ipl_hdr
        if len(dec_header) >= 0x20:
            result["possible_hdr_len"] = struct.unpack_from("<I", dec_header, 8)[0]
            result["possible_body_len"] = struct.unpack_from("<I", dec_header, 12)[0]

    return result
