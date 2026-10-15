"""
PUP Header and Segment Parser
Parses PS5 PUP inner structure (magic: 0xEEF51454)
Works on both encrypted PUPs (limited) and decrypted PUPs (full).
"""
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional
from keys import SEGMENT_NAMES


PUP_MAGIC = 0xEEF51454


@dataclass
class PUPFileHeader:
    magic: int
    unknown_04: int
    unknown_08: int
    flags: int
    unknown_0B: int
    header_size: int
    hash_size: int

    @property
    def is_valid(self) -> bool:
        return self.magic == PUP_MAGIC


@dataclass
class PUPHeader:
    file_header: PUPFileHeader
    file_size: int
    segment_count: int
    unknown_1A: int
    unknown_1C: int


@dataclass
class PUPSegment:
    index: int
    flags: int
    flags2: int
    offset: int
    compressed_size: int
    uncompressed_size: int

    @property
    def segment_id(self) -> int:
        return (self.flags >> 20) & 0xFFF

    @property
    def segment_type(self) -> int:
        return (self.flags >> 28) & 0xF

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & 0x8)

    @property
    def is_blocked(self) -> bool:
        return bool(self.flags & 0x800)

    @property
    def is_table(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def block_size(self) -> int:
        return 1 << (((self.flags & 0xF000) >> 12) + 12)

    @property
    def name(self) -> str:
        sid = self.segment_id
        if sid in SEGMENT_NAMES:
            return SEGMENT_NAMES[sid]
        return f"unknown_0x{sid:03X}"

    @property
    def type_name(self) -> str:
        t = self.segment_type
        if t == 0xE:
            return "additional_sig"
        if t == 0xF:
            return "watermark"
        return f"type_{t:X}"

    def __repr__(self) -> str:
        flags_str = []
        if self.is_compressed:
            flags_str.append("COMPRESSED")
        if self.is_blocked:
            flags_str.append(f"BLOCKED(bs=0x{self.block_size:X})")
        if self.is_table:
            flags_str.append("TABLE")
        flags_info = " ".join(flags_str) if flags_str else "SIMPLE"

        special = self.segment_type
        if special in (0xE, 0xF):
            return (
                f"PUPSegment(#{self.index} {self.type_name} "
                f"flags=0x{self.flags:08X})"
            )

        return (
            f"PUPSegment(#{self.index} id=0x{self.segment_id:03X} "
            f"'{self.name}' offset=0x{self.offset:X} "
            f"compressed=0x{self.compressed_size:X} "
            f"uncompressed=0x{self.uncompressed_size:X} "
            f"{flags_info})"
        )


def parse_pup_file_header(data: bytes) -> PUPFileHeader:
    """Parse the 16-byte PUP file header."""
    if len(data) < 16:
        raise ValueError("Data too small for PUP file header")

    magic, unknown_04 = struct.unpack_from("<II", data, 0)
    unknown_08, flags, unknown_0B = struct.unpack_from("<HBB", data, 8)
    header_size, hash_size = struct.unpack_from("<HH", data, 12)

    return PUPFileHeader(
        magic=magic,
        unknown_04=unknown_04,
        unknown_08=unknown_08,
        flags=flags,
        unknown_0B=unknown_0B,
        header_size=header_size,
        hash_size=hash_size,
    )


def parse_pup_header(data: bytes) -> PUPHeader:
    """Parse the 32-byte PUP header (file_header + extended fields)."""
    fh = parse_pup_file_header(data)

    file_size = struct.unpack_from("<Q", data, 16)[0]
    segment_count, unknown_1A, unknown_1C = struct.unpack_from("<HHI", data, 24)

    return PUPHeader(
        file_header=fh,
        file_size=file_size,
        segment_count=segment_count,
        unknown_1A=unknown_1A,
        unknown_1C=unknown_1C,
    )


def parse_pup_segments(data: bytes, segment_count: int, offset: int = 0x20) -> list:
    """Parse segment table entries. Each entry is 32 bytes."""
    segments = []
    for i in range(segment_count):
        pos = offset + (i * 32)
        if pos + 32 > len(data):
            break
        flags, flags2 = struct.unpack_from("<II", data, pos)
        seg_offset = struct.unpack_from("<q", data, pos + 8)[0]
        compressed_size = struct.unpack_from("<Q", data, pos + 16)[0]
        uncompressed_size = struct.unpack_from("<Q", data, pos + 24)[0]

        segments.append(PUPSegment(
            index=i,
            flags=flags,
            flags2=flags2,
            offset=seg_offset,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
        ))

    return segments


def try_parse_pup(data: bytes) -> Optional[dict]:
    """
    Try to parse PUP data. Works fully on decrypted PUPs.
    On encrypted PUPs, can only verify magic and show raw header bytes.
    """
    if len(data) < 16:
        return None

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != PUP_MAGIC:
        return None

    result = {"magic": magic, "magic_valid": True, "encrypted": False}

    try:
        header = parse_pup_header(data)
        result["header"] = header

        if header.segment_count > 0 and header.segment_count < 1000:
            segments = parse_pup_segments(data, header.segment_count)
            result["segments"] = segments

            # Sanity check: if segment offsets look reasonable, data is likely decrypted
            for seg in segments:
                if seg.segment_type in (0xE, 0xF):
                    continue
                if seg.offset > len(data) or seg.offset < 0:
                    result["encrypted"] = True
                    break
        else:
            result["encrypted"] = True
    except Exception:
        result["encrypted"] = True

    return result
