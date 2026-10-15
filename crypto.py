"""
PS5 Crypto Operations
- AES-128-CBC decryption with known keys (Layer 3)
- PBKDF2 key derivation (Layer 0 - experimental)
- Key derivation infrastructure for when Layer 1 gaps are filled
"""
import hashlib
import struct
from typing import Optional

from Crypto.Cipher import AES


def aes_128_cbc_decrypt(data: bytes, key: bytes, iv: bytes = None) -> bytes:
    """Standard AES-128-CBC decryption."""
    if iv is None:
        iv = b"\x00" * 16
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
    # Pad data to 16-byte boundary if needed
    padded = data
    remainder = len(data) % 16
    if remainder:
        padded = data + b"\x00" * (16 - remainder)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result = cipher.decrypt(padded)
    return result[: len(data)]


def aes_128_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-ECB decryption (single block or multiple)."""
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    padded = data
    remainder = len(data) % 16
    if remainder:
        padded = data + b"\x00" * (16 - remainder)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.decrypt(padded)
    return result[: len(data)]


def pbkdf2_derive(
    password: bytes, salt: bytes, iterations: int, key_len: int = 16
) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation."""
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=key_len)


def decrypt_emc_ipl_header(data: bytes) -> bytes:
    """
    Decrypt EMC IPL header using the known CP key.
    Key: F0332357C8CFAE7E7E26E52BE9E3AED4
    AES-128-CBC with zeroed IV.
    """
    from keys import EMC_IPL_HEADER_KEY

    return aes_128_cbc_decrypt(data, EMC_IPL_HEADER_KEY)


def decrypt_emc_ipl_body(data: bytes) -> bytes:
    """
    Decrypt EMC IPL body (rev c0 only).
    Key: D5C92E39759A3E5CE954E772B1C2B651
    AES-128-CBC with zeroed IV.
    """
    from keys import EMC_IPL_CIPHER_KEY

    return aes_128_cbc_decrypt(data, EMC_IPL_CIPHER_KEY)


def decrypt_eap_kbl(data: bytes) -> bytes:
    """
    Decrypt EAP KBL.
    Key: 262555E3CF062B070B5AA2CDDF3A5D0E
    AES-128-CBC with zeroed IV.
    """
    from keys import EAP_KBL_KEY

    return aes_128_cbc_decrypt(data, EAP_KBL_KEY)


def decrypt_eap_kernel(data: bytes) -> bytes:
    """
    Decrypt EAP Kernel (from KBL).
    Key: CBCC1E53F42C1CB44D965E233CD792A8
    AES-128-CBC with zeroed IV.
    """
    from keys import EAP_KBL_KERNEL_KEY

    return aes_128_cbc_decrypt(data, EAP_KBL_KERNEL_KEY)


def decrypt_eap_kernel_self(data: bytes) -> bytes:
    """
    Decrypt EAP Kernel SELF modules.
    Key: 32D00F27AE38FE4AC88A352313A2BFB4
    IV:  08FEA1ACC37A630999745386168812EC
    AES-128-CBC.
    """
    from keys import EAP_KERNEL_SELF_KEY, EAP_KERNEL_SELF_IV

    return aes_128_cbc_decrypt(data, EAP_KERNEL_SELF_KEY, EAP_KERNEL_SELF_IV)


def decrypt_with_titania_key(data: bytes, revision: int) -> Optional[bytes]:
    """
    Decrypt using Titania master key for a given hardware revision.
    Only revision 2 has a known key; 1 and 3 have only IVs.
    """
    from keys import TITANIA_KEYS

    if revision not in TITANIA_KEYS:
        return None
    tk = TITANIA_KEYS[revision]
    if "key" not in tk:
        return None
    return aes_128_cbc_decrypt(data, tk["key"], tk["iv"])


# --- Experimental: PS4-style key derivation (adapted for PS5) ---

def ps4_decrypt_with_seed(
    rom_constant: bytes, key_seed: bytes, fuse_key: bytes
) -> bytes:
    """
    PS4 Aeolia-style key derivation (fail0verflow).
    Builds 32-byte input: key_seed[8] repeated twice + rom_constant[16]
    AES-128-CBC decrypt with zeroed IV using fuse_key.
    Returns second 16 bytes of result.

    NOTE: PS5 probably uses a different scheme (PBKDF2 + KMB_AES).
    This is here for reference/experimentation.
    """
    if len(key_seed) < 8:
        key_seed = key_seed + b"\x00" * (8 - len(key_seed))
    plaintext = key_seed[:8] + key_seed[:8] + rom_constant[:16]
    decrypted = aes_128_cbc_decrypt(plaintext, fuse_key)
    return decrypted[16:32]


def experimental_pbkdf2_master_key() -> bytes:
    """
    Experimental: derive master key using OTP_AES_ROOT + KDF_SALT1 + 1000 iters.
    This is Layer 0 of the PS5 key derivation.
    The exact parameters (hash function, key length) are not fully confirmed.
    Trying PBKDF2-HMAC-SHA256 with 16-byte output.
    """
    from keys import OTP_AES_ROOT, KDF_SALT1, KDF_ITERS

    return pbkdf2_derive(OTP_AES_ROOT, KDF_SALT1, KDF_ITERS, key_len=16)


def show_experimental_derivation():
    """Show experimental PBKDF2 derivation results for research."""
    from keys import OTP_AES_ROOT, KDF_SALT1, KDF_ITERS

    print("=== Experimental PBKDF2 Key Derivation ===")
    print(f"OTP_AES_ROOT:  {OTP_AES_ROOT.hex()}")
    print(f"KDF_SALT1:     {KDF_SALT1.hex()}")
    print(f"KDF_ITERS:     {KDF_ITERS}")
    print()

    for hash_fn in ("sha256", "sha1", "sha512"):
        for kl in (16, 32):
            derived = hashlib.pbkdf2_hmac(
                hash_fn, OTP_AES_ROOT, KDF_SALT1, KDF_ITERS, dklen=kl
            )
            print(f"PBKDF2-HMAC-{hash_fn.upper()} (dklen={kl}): {derived.hex()}")

    print()
    print("NOTE: The correct hash function and key length are not confirmed.")
    print("These are candidates to test against known Titania master keys.")
    print()

    from keys import TITANIA_KEYS
    for rev, tk in TITANIA_KEYS.items():
        if "key" in tk:
            print(f"Titania {rev} known key: {tk['key'].hex()}")
            print(f"Titania {rev} known IV:  {tk['iv'].hex()}")
