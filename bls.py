"""
BLS (SLB2) Container Parser
Parses the outer BLS container of PS5 PUP files.
Magic: 0x32424C53 ("SLB2")
"""
import struct
from dataclasses import dataclass
from typing import BinaryIO


BLS_MAGIC = 0x32424C53  # "SLB2" little-endian


@dataclass
class BLSEntry:
    index: int
    block_offset: int  # multiply by 512 for byte offset
    size: int
    name: str

    @property
    def byte_offset(self) -> int:
        return self.block_offset * 512

    def __repr__(self) -> str:
        return (
            f"BLSEntry(#{self.index} name='{self.name}' "
            f"offset=0x{self.byte_offset:X} size=0x{self.size:X})"
        )


@dataclass
class BLSHeader:
    magic: int
    version: int
    flags: int
    file_count: int
    block_count: int
    entries: list

    def __repr__(self) -> str:
        return (
            f"BLSHeader(magic=0x{self.magic:08X} version={self.version} "
            f"flags=0x{self.flags:X} files={self.file_count} blocks={self.block_count})"
        )


def parse_bls_header(f: BinaryIO) -> BLSHeader:
    """Parse a BLS (SLB2) header from the current file position."""
    data = f.read(32)
    if len(data) < 32:
        raise ValueError("File too small for BLS header")

    magic, version, flags, file_count, block_count = struct.unpack_from("<5I", data)

    if magic != BLS_MAGIC:
        raise ValueError(
            f"Invalid BLS magic: 0x{magic:08X} (expected 0x{BLS_MAGIC:08X})"
        )

    entries = []
    for i in range(file_count):
        entry_data = f.read(48)
        if len(entry_data) < 48:
            raise ValueError(f"Truncated BLS entry at index {i}")

        block_offset, size = struct.unpack_from("<II", entry_data, 0)
        # 8 bytes reserved
        name_bytes = entry_data[16:48]
        name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")

        entries.append(BLSEntry(
            index=i,
            block_offset=block_offset,
            size=size,
            name=name,
        ))

    return BLSHeader(
        magic=magic,
        version=version,
        flags=flags,
        file_count=file_count,
        block_count=block_count,
        entries=entries,
    )


def extract_bls_entry(f: BinaryIO, entry: BLSEntry) -> bytes:
    """Read the raw data of a BLS entry."""
    f.seek(entry.byte_offset)
    return f.read(entry.size)


def list_bls_entries(filepath: str) -> BLSHeader:
    """Open a PUP file and list all BLS entries."""
    with open(filepath, "rb") as f:
        return parse_bls_header(f)
