"""
MobiCore Loadable Format (MCLF) Loader for Binary Ninja

This plugin adds support for loading Samsung/Mediatek MobiCore trustlet
and driver binaries in the MCLF format.

Based on the IDA loader by Gassan Idriss (https://github.com/ghassani/mclf-ida-loader)
and the official MCLF specification from Trustonic.

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

# Header sizes from spec
MCLF_HEADER_SIZE_V2 = 76  # mclfHeaderV2_t size (ends after serviceVersion)
MCLF_HEADER_SIZE_V23 = 0x80  # 128 bytes

# Text header offset (relative to text segment start, i.e., file offset 0x80)
MCLF_TEXT_HEADER_OFFSET = 0x80

# Offsets within mclfTextHeader_t
MCLF_TEXT_HEADER_MCLIB_ENTRY_OFFSET = 0x0C  # Offset of mcLibEntry within text header

# Service header flags (from spec)
MC_SERVICE_HEADER_FLAGS_PERMANENT = 1 << 0  # Cannot be unloaded
MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE = 1 << 1  # No WSM control interface
MC_SERVICE_HEADER_FLAGS_DEBUGGABLE = 1 << 2  # Service can be debugged
MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT = 1 << 3  # New-layout TA or driver

MC_SERVICE_HEADER_FLAGS_AARCH64 = 1 << 5

# Service types (from spec)
SERVICE_TYPE_ILLEGAL = 0
SERVICE_TYPE_DRIVER = 1
SERVICE_TYPE_SP_TRUSTLET = 2
SERVICE_TYPE_SYSTEM_TRUSTLET = 3
SERVICE_TYPE_MIDDLEWARE = 4

# Memory types (from spec)
MCLF_MEM_TYPE_INTERNAL_PREFERRED = 0
MCLF_MEM_TYPE_INTERNAL = 1
MCLF_MEM_TYPE_EXTERNAL = 2


class MCLFHeader:
    """Parser for MCLF header structure (mclfHeaderV2_t and extensions)."""

    def __init__(self, data: bytes):
        if len(data) < MCLF_HEADER_SIZE_V2:
            raise ValueError("Data too small for MCLF header")

        offset = 0

        # mclfIntro_t
        self.magic = data[offset : offset + 4]
        offset += 4

        # Version (4 bytes - packed as minor:major in little-endian)
        self.version_minor, self.version_major = struct.unpack_from("<HH", data, offset)
        offset += 4

        # Flags (4 bytes)
        self.flags = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Determine architecture from flags
        # Note: AARCH64 flag (bit 5) is empirically determined, not in official spec
        self.is_64bit = (self.flags & MC_SERVICE_HEADER_FLAGS_AARCH64) != 0

        # Memory type (4 bytes) - memType_t enum
        self.mem_type = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Service type (4 bytes) - serviceType_t enum
        self.service_type = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Number of instances (4 bytes)
        self.num_instances = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # UUID (16 bytes) - mcUuid_t
        self.uuid = struct.unpack_from("<IIII", data, offset)
        offset += 16

        # Driver ID (4 bytes) - mcDriverId_t
        self.driver_id = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Number of threads (4 bytes)
        self.num_threads = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Text segment descriptor - segmentDescriptor_t
        self.text_va = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        self.text_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Data segment descriptor - segmentDescriptor_t
        self.data_va = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        self.data_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # BSS length (4 bytes)
        self.bss_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Entry point (4 bytes)
        self.entry = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Service version (4 bytes) - added in V2
        self.service_version = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # V2.3+ extensions
        self.permitted_suid = None
        self.permitted_hw_cfg = None
        self.gp_level = None
        self.attestation_offset = None

        # Parse V2.3 extensions if version >= 2.3
        if self._version_at_least(2, 3) and len(data) >= MCLF_HEADER_SIZE_V23:
            # permittedSuid (16 bytes) - mcSuid_t
            self.permitted_suid = struct.unpack_from("<IIII", data, offset)
            offset += 16

            # permittedHwCfg (4 bytes)
            self.permitted_hw_cfg = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            # V2.4+ extensions
            if self._version_at_least(2, 4) and len(data) >= offset + 8:
                # gp_level (4 bytes) - 0 for legacy, 1 for Potato TAs
                self.gp_level = struct.unpack_from("<I", data, offset)[0]
                offset += 4

                # attestationOffset (4 bytes)
                self.attestation_offset = struct.unpack_from("<I", data, offset)[0]
                offset += 4

    def _version_at_least(self, major: int, minor: int) -> bool:
        """Check if version is at least major.minor."""
        if self.version_major > major:
            return True
        if self.version_major == major and self.version_minor >= minor:
            return True
        return False

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

    def service_type_str(self) -> str:
        """Return service type as a string."""
        types = {
            SERVICE_TYPE_ILLEGAL: "Illegal",
            SERVICE_TYPE_DRIVER: "Driver",
            SERVICE_TYPE_SP_TRUSTLET: "SP Trustlet",
            SERVICE_TYPE_SYSTEM_TRUSTLET: "System Trustlet",
            SERVICE_TYPE_MIDDLEWARE: "Middleware",
        }
        return types.get(self.service_type, f"Unknown ({self.service_type})")

    def mem_type_str(self) -> str:
        """Return memory type as a string."""
        types = {
            MCLF_MEM_TYPE_INTERNAL_PREFERRED: "Internal Preferred",
            MCLF_MEM_TYPE_INTERNAL: "Internal",
            MCLF_MEM_TYPE_EXTERNAL: "External",
        }
        return types.get(self.mem_type, f"Unknown ({self.mem_type})")

    def flags_str(self) -> str:
        """Return flags as a descriptive string."""
        parts = []
        if self.flags & MC_SERVICE_HEADER_FLAGS_PERMANENT:
            parts.append("PERMANENT")
        if self.flags & MC_SERVICE_HEADER_FLAGS_NO_CONTROL_INTERFACE:
            parts.append("NO_CONTROL_INTERFACE")
        if self.flags & MC_SERVICE_HEADER_FLAGS_DEBUGGABLE:
            parts.append("DEBUGGABLE")
        if self.flags & MC_SERVICE_HEADER_FLAGS_EXTENDED_LAYOUT:
            parts.append("EXTENDED_LAYOUT")
        if self.flags & MC_SERVICE_HEADER_FLAGS_AARCH64:
            parts.append("AARCH64")
        return " | ".join(parts) if parts else "NONE"


class MCLFTextHeader:
    """Parser for MCLF text segment header (mclfTextHeader_t).

    Located at offset 0x80 from start of text segment (virtual address text_va + 0x80).
    """

    def __init__(self, data: bytes):
        if len(data) < 36:
            raise ValueError("Data too small for MCLF text header")

        offset = 0

        # Version (4 bytes)
        self.version = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Text header length (4 bytes)
        self.text_header_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Required features flags (4 bytes)
        self.required_feat = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # McLib entry address (4 bytes) - this is what tlApiLibEntry points to
        self.mc_lib_entry = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # McLib Internal Management Data (mclfIMD_t) - 12 bytes
        # cfg union: either mcLibData (segmentDescriptor_t) or heapSize (heapSize_t)
        self.mclib_data_start = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        self.mclib_data_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        self.mclib_base = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # TlApi version (4 bytes)
        self.tlapi_vers = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # DrApi version (4 bytes) - 0 for trustlets
        self.drapi_vers = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # TA properties address (4 bytes)
        self.ta_properties = struct.unpack_from("<I", data, offset)[0]
        offset += 4


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

            # Support versions 2.x (major > 1 and major < 3, per spec)
            if version_major != 2:
                return False

            return True
        except Exception:
            return False

    def init(self) -> bool:
        """Initialize the MCLF binary view."""
        try:
            # Read header (at least V2.3 size to support extensions)
            header_data = self.raw.read(0, MCLF_HEADER_SIZE_V23)
            if len(header_data) < MCLF_HEADER_SIZE_V2:
                log_error("MCLF: Failed to read header")
                return False

            self.header = MCLFHeader(header_data)

            # Log header info
            arch_str = "AArch64" if self.header.is_64bit else "ARM"
            log_info(
                f"MCLF: Loading v{self.header.version_major}.{self.header.version_minor} ({arch_str})"
            )
            log_info(
                f"MCLF: Type: {self.header.service_type_str()}, Memory: {self.header.mem_type_str()}"
            )
            log_info(
                f"MCLF: Flags: 0x{self.header.flags:08x} ({self.header.flags_str()})"
            )
            log_info(f"MCLF: UUID: {self.header.uuid_str()}")
            log_info(
                f"MCLF: Text: VA 0x{self.header.text_va:x}, len 0x{self.header.text_len:x}"
            )
            log_info(
                f"MCLF: Data: VA 0x{self.header.data_va:x}, len 0x{self.header.data_len:x}"
            )
            log_info(f"MCLF: BSS: len 0x{self.header.bss_len:x}")
            log_info(f"MCLF: Entry: 0x{self.header.entry:x}")

            # Set architecture based on flags
            if self.header.is_64bit:
                self.arch = Architecture["aarch64"]
            else:
                self.arch = Architecture["armv7"]
            self.platform = self.arch.standalone_platform

            # Add .text segment
            text_flags = (
                SegmentFlag.SegmentReadable
                | SegmentFlag.SegmentExecutable
                | SegmentFlag.SegmentContainsCode
            )
            self.add_auto_segment(
                self.header.text_va,
                self.header.text_len,
                0,  # File offset
                self.header.text_len,
                text_flags,
            )
            self.add_auto_section(
                ".text",
                self.header.text_va,
                self.header.text_len,
                SectionSemantics.ReadOnlyCodeSectionSemantics,
            )

            # Add .data segment
            data_flags = (
                SegmentFlag.SegmentReadable
                | SegmentFlag.SegmentWritable
                | SegmentFlag.SegmentContainsData
            )
            self.add_auto_segment(
                self.header.data_va,
                self.header.data_len,
                self.header.text_len,  # File offset after .text
                self.header.data_len,
                data_flags,
            )
            self.add_auto_section(
                ".data",
                self.header.data_va,
                self.header.data_len,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )

            # Add .bss segment (no file data)
            bss_start = self.header.data_va + self.header.data_len
            if self.header.bss_len > 0:
                bss_flags = (
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentWritable
                    | SegmentFlag.SegmentContainsData
                )
                self.add_auto_segment(
                    bss_start,
                    self.header.bss_len,
                    0,  # No file offset
                    0,  # No file data
                    bss_flags,
                )
                self.add_auto_section(
                    ".bss",
                    bss_start,
                    self.header.bss_len,
                    SectionSemantics.ReadWriteDataSectionSemantics,
                )

            # Add entry point
            entry_addr = self.header.entry_address()
            if not self.header.is_64bit and self.header.is_thumb_entry():
                # Force Thumb mode at entry point (32-bit only)
                self.add_function(
                    entry_addr, self.arch.get_associated_arch_by_address(entry_addr | 1)
                )
            else:
                self.add_function(entry_addr)

            self.add_entry_point(entry_addr)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, entry_addr, "_entry")
            )

            # Parse and apply text header symbols
            self._parse_text_header()

            return True

        except Exception as e:
            log_error(f"MCLF: Failed to load: {e}")
            return False

    def _parse_text_header(self):
        """Parse the mclfTextHeader_t and create symbols."""
        # Text header is at file offset 0x80 (MCLF_TEXT_HEADER_OFFSET)
        # which maps to virtual address text_va + 0x80
        text_header_file_offset = MCLF_TEXT_HEADER_OFFSET
        text_header_va = self.header.text_va + MCLF_TEXT_HEADER_OFFSET

        # Check if text header is within the text segment
        if text_header_file_offset + 36 > self.header.text_len:
            log_info("MCLF: Text header extends beyond text segment, skipping")
            return

        text_header_data = self.raw.read(text_header_file_offset, 36)
        if text_header_data is None or len(text_header_data) < 36:
            log_info("MCLF: Failed to read text header")
            return

        try:
            self.text_header = MCLFTextHeader(text_header_data)

            # mcLibEntry is at offset 0x0C within the text header
            # Virtual address: text_va + 0x80 + 0x0C = text_va + 0x8C
            mclib_entry_va = (
                self.header.text_va
                + MCLF_TEXT_HEADER_OFFSET
                + MCLF_TEXT_HEADER_MCLIB_ENTRY_OFFSET
            )

            if self._is_address_valid(mclib_entry_va):
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, mclib_entry_va, "mcLibEntry")
                )
                self.define_data_var(
                    mclib_entry_va, self.parse_type_string("uint32_t")[0]
                )
                log_info(f"MCLF: mcLibEntry at 0x{mclib_entry_va:x}")

            # Also create symbol for the mcLibEntry value if it points to valid code
            if self.text_header.mc_lib_entry != 0 and self._is_address_valid(
                self.text_header.mc_lib_entry
            ):
                self.add_function(self.text_header.mc_lib_entry)
                self.define_auto_symbol(
                    Symbol(
                        SymbolType.FunctionSymbol,
                        self.text_header.mc_lib_entry,
                        "tlApiLibEntry",
                    )
                )
                log_info(
                    f"MCLF: tlApiLibEntry function at 0x{self.text_header.mc_lib_entry:x}"
                )

            # Create symbol for TA properties if valid
            if self.text_header.ta_properties != 0 and self._is_address_valid(
                self.text_header.ta_properties
            ):
                self.define_auto_symbol(
                    Symbol(
                        SymbolType.DataSymbol,
                        self.text_header.ta_properties,
                        "_TA_Properties",
                    )
                )
                log_info(
                    f"MCLF: _TA_Properties at 0x{self.text_header.ta_properties:x}"
                )

        except Exception as e:
            log_info(f"MCLF: Failed to parse text header: {e}")

    def _is_address_valid(self, addr: int) -> bool:
        """Check if an address falls within a defined segment."""
        for segment in self.segments:
            if segment.start <= addr < segment.end:
                return True
        return False

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        if hasattr(self, "header"):
            return self.header.entry_address()
        return 0

    def perform_get_address_size(self) -> int:
        if hasattr(self, "header") and self.header.is_64bit:
            return 8
        return 4


MCLFView.register()
