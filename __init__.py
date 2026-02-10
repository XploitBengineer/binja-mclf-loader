"""
MobiCore Loadable Format (MCLF) Loader for Binary Ninja

This plugin adds support for loading Samsung/Mediatek MobiCore trustlet
and driver binaries in the MCLF format.

Based on the IDA loader by Gassan Idriss (https://github.com/ghassani/mclf-ida-loader)

License: GPLv2
"""

import struct
from binaryninja import (
    BinaryView,
    Architecture,
    SegmentFlag,
    SectionSemantics,
    Symbol,
    SymbolType,
    log_info,
    log_error,
)


MCLF_HEADER_MAGIC = b"MCLF"
MCLF_TEXT_INFO_OFFSET = 128
MCLF_TEXT_INFO_SIZE = 36
MCLF_HEADER_SIZE = MCLF_TEXT_INFO_OFFSET + MCLF_TEXT_INFO_SIZE

# Known address for tlApiLibEntry (32-bit)
TL_API_LIB_ENTRY = 0x108C

# Flag bits
MCLF_FLAG_64BIT = 0x20  # Bit 5 indicates 64-bit architecture


class MCLFHeader:
    """Parser for MCLF header structure."""

    def __init__(self, data: bytes):
        if len(data) < 72:
            raise ValueError("Data too small for MCLF header")

        offset = 0

        # Magic (4 bytes)
        self.magic = data[offset:offset + 4]
        offset += 4

        # Version (4 bytes - 2 bytes minor, 2 bytes major)
        self.version_minor, self.version_major = struct.unpack_from("<HH", data, offset)
        offset += 4

        # Flags (4 bytes)
        self.flags = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Determine if this is a 64-bit MCLF (affects architecture, not header format)
        self.is_64bit = (self.flags & MCLF_FLAG_64BIT) != 0

        # Memory type (4 bytes)
        self.mem_type = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Service type (4 bytes)
        self.service_type = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Number of instances (4 bytes)
        self.num_instances = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # UUID (16 bytes)
        self.uuid = struct.unpack_from("<IIII", data, offset)
        offset += 16

        # Driver ID (4 bytes)
        self.driver_id = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Number of threads (4 bytes)
        self.num_threads = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Segment info uses 32-bit fields regardless of architecture
        # Text segment VA (4 bytes)
        self.text_va = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Text segment length (4 bytes)
        self.text_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Data segment VA (4 bytes)
        self.data_va = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Data segment length (4 bytes)
        self.data_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # BSS length (4 bytes)
        self.bss_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Entry point (4 bytes)
        self.entry = struct.unpack_from("<I", data, offset)[0]
        offset += 4

    def uuid_str(self) -> str:
        """Return UUID as a formatted string."""
        return "{:08x}-{:08x}-{:08x}-{:08x}".format(*self.uuid)

    def is_thumb_entry(self) -> bool:
        """Check if entry point is Thumb mode. Only for 32-bit ARM.

        Matches IDA loader behavior: entry % 4 == 1 indicates Thumb mode
        (Thumb address at 4-byte aligned location with T-bit set).
        """
        if self.is_64bit:
            return False
        return (self.entry % 4) == 1

    def entry_address(self) -> int:
        """Return the actual entry address (without Thumb bit for 32-bit)."""
        if not self.is_64bit and self.is_thumb_entry():
            return self.entry - 1
        return self.entry


class MCLFView(BinaryView):
    """Binary Ninja BinaryView for MCLF files."""

    name = "MCLF"
    long_name = "MobiCore Loadable Format"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        """Check if the data is a valid MCLF file."""
        try:
            if data.length < 8:
                return False

            magic = data.read(0, 4)
            if magic is None or len(magic) < 4:
                return False
            if magic != MCLF_HEADER_MAGIC:
                return False

            # Check version (major should be 2)
            version_data = data.read(4, 4)
            if version_data is None or len(version_data) < 4:
                return False

            version_minor, version_major = struct.unpack("<HH", version_data)

            # Support versions 2.x
            if version_major != 2:
                return False

            return True
        except Exception:
            return False

    def init(self) -> bool:
        """Initialize the MCLF binary view."""
        try:
            # Read enough data for both 32-bit and 64-bit headers
            header_data = self.raw.read(0, 128)
            if len(header_data) < 72:
                log_error("MCLF: Failed to read header")
                return False

            self.header = MCLFHeader(header_data)

            arch_str = "64-bit" if self.header.is_64bit else "32-bit"
            log_info(f"MCLF: Loading v{self.header.version_major}.{self.header.version_minor} ({arch_str})")
            log_info(f"MCLF: Flags 0x{self.header.flags:08x}")
            log_info(f"MCLF: UUID {self.header.uuid_str()}")
            log_info(f"MCLF: Text VA 0x{self.header.text_va:x}, len 0x{self.header.text_len:x}")
            log_info(f"MCLF: Data VA 0x{self.header.data_va:x}, len 0x{self.header.data_len:x}")
            log_info(f"MCLF: BSS len 0x{self.header.bss_len:x}")
            log_info(f"MCLF: Entry point 0x{self.header.entry:x}")

            # Set architecture based on 32-bit or 64-bit
            if self.header.is_64bit:
                self.arch = Architecture["aarch64"]
            else:
                self.arch = Architecture["armv7"]
            self.platform = self.arch.standalone_platform

            # Add .text segment
            text_flags = (
                SegmentFlag.SegmentReadable |
                SegmentFlag.SegmentExecutable |
                SegmentFlag.SegmentContainsCode
            )
            self.add_auto_segment(
                self.header.text_va,
                self.header.text_len,
                0,  # File offset
                self.header.text_len,
                text_flags
            )
            self.add_auto_section(
                ".text",
                self.header.text_va,
                self.header.text_len,
                SectionSemantics.ReadOnlyCodeSectionSemantics
            )

            # Add .data segment
            data_flags = (
                SegmentFlag.SegmentReadable |
                SegmentFlag.SegmentWritable |
                SegmentFlag.SegmentContainsData
            )
            self.add_auto_segment(
                self.header.data_va,
                self.header.data_len,
                self.header.text_len,  # File offset after .text
                self.header.data_len,
                data_flags
            )
            self.add_auto_section(
                ".data",
                self.header.data_va,
                self.header.data_len,
                SectionSemantics.ReadWriteDataSectionSemantics
            )

            # Add .bss segment (no file data)
            bss_start = self.header.data_va + self.header.data_len
            if self.header.bss_len > 0:
                bss_flags = (
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable |
                    SegmentFlag.SegmentContainsData
                )
                self.add_auto_segment(
                    bss_start,
                    self.header.bss_len,
                    0,  # No file offset
                    0,  # No file data
                    bss_flags
                )
                self.add_auto_section(
                    ".bss",
                    bss_start,
                    self.header.bss_len,
                    SectionSemantics.ReadWriteDataSectionSemantics
                )

            # Add entry point
            entry_addr = self.header.entry_address()
            if not self.header.is_64bit and self.header.is_thumb_entry():
                # Force Thumb mode at entry point (32-bit only)
                self.add_function(entry_addr, self.arch.get_associated_arch_by_address(entry_addr | 1))
            else:
                self.add_function(entry_addr)

            self.add_entry_point(entry_addr)
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, entry_addr, "_entry"))

            # Add tlApiLibEntry symbol if within a valid segment
            # IDA loader always creates this as a 4-byte DWORD at 0x108C
            if self._is_address_valid(TL_API_LIB_ENTRY):
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, TL_API_LIB_ENTRY, "tlApiLibEntry")
                )
                # Always 4 bytes (DWORD) to match IDA loader behavior
                self.define_data_var(TL_API_LIB_ENTRY, self.parse_type_string("uint32_t")[0])

            return True

        except Exception as e:
            log_error(f"MCLF: Failed to load: {e}")
            return False

    def _is_address_valid(self, addr: int) -> bool:
        """Check if an address falls within a defined segment."""
        for segment in self.segments:
            if segment.start <= addr < segment.end:
                return True
        return False

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        if hasattr(self, 'header'):
            return self.header.entry_address()
        return 0

    def perform_get_address_size(self) -> int:
        if hasattr(self, 'header') and self.header.is_64bit:
            return 8
        return 4


# Register the view type
MCLFView.register()
