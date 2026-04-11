"""
SQLModel ORM definitions for blackadder.

Defines models for both rootfs database (binary metadata) and process database
(runtime analysis). All models are type-safe with Pydantic validation.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

import struct

from pydantic import BaseModel, field_validator
from sqlalchemy import UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

_INT64_MAX = (1 << 63) - 1
_UINT64_MASK = (1 << 64) - 1


def addr_to_db(addr: int) -> int:
    """
    Convert an unsigned 64-bit address to a signed 64-bit integer for SQLite storage.

    SQLite INTEGER is signed 64-bit. Linux kernel addresses (0xffff...) exceed
    INT64_MAX and must be reinterpreted as signed to avoid overflow errors.
    Python's arbitrary-precision int transparently undoes this on read.
    """
    if addr > _INT64_MAX:
        return addr - (1 << 64)
    return addr


def addr_from_db(val: int) -> int:
    """Recover unsigned address from signed DB value."""
    if val < 0:
        return val + (1 << 64)
    return val

# ============================================================================
# Pydantic models for validation and API
# ============================================================================


class BacktraceRequest(BaseModel):
    """Request to decode a backtrace."""

    pid: int
    addresses: list[int]


class ResolvedFrame(BaseModel):
    """A resolved backtrace frame."""

    address: int
    frame_num: int
    symbol: str
    file: str | None = None
    line: int | None = None

    @field_validator("symbol")
    @classmethod
    def format_symbol(cls, v: str) -> str:
        """Ensure symbol is formatted correctly."""
        return v if v else "???"


# ============================================================================
# Rootfs Database Models (static binary metadata)
# ============================================================================


class Binary(SQLModel, table=True):
    """
    Represents a unique binary identified by MD5 checksum.

    Multiple file paths can reference the same binary via BinaryLocator.
    """

    id: int | None = Field(default=None, primary_key=True)
    md5sum: str = Field(unique=True, index=True, max_length=32)
    name: str = Field(index=True)  # e.g., "libc.so.6"
    debug_link: str | None = None  # Path to separate debug symbols

    # Relationships
    sections: list["SectionHeader"] = Relationship(back_populates="binary")
    symbols: list["Symbol"] = Relationship(back_populates="binary")
    fingerprints: list["FunctionFingerprint"] = Relationship(back_populates="binary")


class SectionHeader(SQLModel, table=True):
    """
    ELF section metadata extracted via objdump -h.

    Includes .text, .bss, .rodata, .debug_info, etc.
    """

    id: int | None = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    idx: int  # Section index
    name: str = Field(index=True, max_length=32)  # ".text", ".bss", etc.
    size: int
    vma: int  # Virtual memory address
    lma: int  # Load memory address
    off: int  # File offset
    align: int  # Alignment

    # Relationships
    binary: Binary = Relationship(back_populates="sections")


class Symbol(SQLModel, table=True):
    """
    Symbol table entry extracted via objdump --syms.

    Used for address-to-symbol resolution.
    """

    id: int | None = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    address: int = Field(index=True)
    scope: str = Field(max_length=1)  # "l" (local), "g" (global), "w" (weak)
    sym_type: str = Field(max_length=1)  # "F" (function), "O" (object), etc.
    section: str = Field(index=True, max_length=32)  # ".text", ".bss", "*UND*", etc.
    size: int
    name: str = Field(index=True, max_length=256)  # Function/variable name

    # Relationships
    binary: Binary = Relationship(back_populates="symbols")


class FunctionFingerprint(SQLModel, table=True):
    """
    Hash of function body for version-mismatch matching (Phase 2).

    Enables binary matching when MD5 differs but code is similar.
    """

    id: int | None = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    func_name: str = Field(index=True, max_length=256)
    func_offset: int  # Offset in binary
    func_size: int
    # Ignore addresses/relocations, hash the instruction bytes
    content_hash: str = Field(max_length=64)  # SHA256 of normalized function body

    # Relationships
    binary: Binary = Relationship(back_populates="fingerprints")


class SymbolCache(SQLModel, table=True):
    """
    Persistent cache of addr2line/objdump results keyed by (binary_id, offset).

    Survives process restarts — avoids re-running addr2line for the same
    binary:offset across sessions. One row per unique (binary, offset) pair.
    """

    id: int | None = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    offset: int  # File offset within binary (not virtual address)
    symbol: str | None = Field(default=None, max_length=512)   # demangled symbol name
    source_file: str | None = Field(default=None, max_length=512)
    source_line: int | None = None

    __table_args__ = (UniqueConstraint("binary_id", "offset", name="uq_symbolcache_binary_offset"),)


class DwarfType(SQLModel, table=True):
    """
    DWARF type definition extracted from a binary via objdump --dwarf=info.

    Covers: structure_type, union_type, base_type, typedef, pointer_type,
    const_type, volatile_type, array_type, enumeration_type.

    die_offset is the DIE offset in .debug_info — unique per binary, used for
    cross-references between types (type_ref, DwarfMember.member_type_ref).
    """

    id: int | None = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    die_offset: int                            # Hex offset in .debug_info (unique per binary)
    tag: str = Field(max_length=32)            # "structure_type", "base_type", "typedef", etc.
    name: str | None = Field(default=None, index=True, max_length=256)
    byte_size: int | None = None               # Total size in bytes (None for const/volatile wrappers)
    type_ref: int | None = None                # die_offset of referenced DwarfType (typedef→underlying, pointer→target)
    encoding: str | None = Field(default=None, max_length=32)  # "signed", "unsigned", "float", etc. (base_type only)

    __table_args__ = (UniqueConstraint("binary_id", "die_offset", name="uq_dwarftype_binary_offset"),)

    members: list["DwarfMember"] = Relationship(back_populates="dwarf_type")


class DwarfMember(SQLModel, table=True):
    """
    Field within a DW_TAG_structure_type or DW_TAG_union_type.

    byte_offset is DW_AT_data_member_location — byte offset from struct start.
    member_type_ref is the die_offset of the DwarfType describing this field's type.
    """

    id: int | None = Field(default=None, primary_key=True)
    type_id: int = Field(foreign_key="dwarftype.id", index=True)
    name: str | None = Field(default=None, max_length=256)  # None for anonymous embedded structs
    byte_offset: int                   # DW_AT_data_member_location (decimal bytes from struct start)
    member_type_ref: int               # die_offset of the DwarfType for this member's type

    dwarf_type: "DwarfType" = Relationship(back_populates="members")


class DebugLine(SQLModel, table=True):
    """
    Source line → address mapping from .debug_line section.

    Extracted via readelf --debug-dump=decodedline. Enables line2addr lookups
    (reverse of addr2line) and DB-backed source location resolution.

    source_file stores the full path when available, basename otherwise.
    address is the binary offset (not virtual address).
    """

    id: int | None = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    source_file: str = Field(index=True, max_length=512)
    line_number: int
    address: int = Field(index=True)

    __table_args__ = (UniqueConstraint(
        "binary_id", "source_file", "line_number", "address",
        name="uq_debugline",
    ),)


class BinaryLocator(SQLModel, table=True):
    """
    Maps a file path to a binary identified by MD5.

    Allows deduplication: same binary at multiple paths only stored once.
    """

    id: int | None = Field(default=None, primary_key=True)
    path: str = Field(unique=True, index=True)  # Full file path
    md5sum: str = Field(foreign_key="binary.md5sum")
    mtime: int  # Modification time (unix timestamp) for cache validation
    debug_file: str | None = None  # Resolved path to companion debug file (if found)


# ============================================================================
# Process Database Models (dynamic runtime analysis)
# ============================================================================


class Thread(SQLModel, table=True):
    """
    A thread within a process snapshot.

    Populated from /proc/PID/task/TID/ (live) or GDB thread dump (offline).
    stack_start/stack_end are derived from [stack:TID] mappings in /proc/maps.
    """

    id: int | None = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    tid: int                            # Thread ID (LWP)
    name: str | None = None             # Thread name from /proc/PID/task/TID/comm
    wchan: str | None = None            # Kernel wait channel (/proc/PID/task/TID/wchan)
    syscall: str | None = None          # Current syscall + args, raw text
    stack_start: int | None = None      # Stack region start address
    stack_end: int | None = None        # Stack region end address

    # Relationships
    process: "ProcessSnapshot" = Relationship(back_populates="threads")


class ProcessSnapshot(SQLModel, table=True):
    """
    Represents a process at a point in time (live or core dump).

    Multiple analyses (backtraces, address resolutions) reference this.
    """

    __table_args__ = (UniqueConstraint("tag", name="uq_processsnapshot_tag"),)

    id: int | None = Field(default=None, primary_key=True)
    pid: int | None = None  # None for offline/core dump analysis
    created_at: datetime = Field(default_factory=datetime.now)
    description: str = ""  # e.g., "core dump from crash at 2026-04-06 14:30:00"
    tag: str | None = Field(default=None)  # Human-readable label (UNIQUE, nullable)

    # Data source tracking
    source_type: str = Field(default="maps")  # primary source: "maps", "core_dump", "gdb_dump"
    source_path: str | None = None           # path to primary source file
    sources_json: str = Field(default="[]")  # JSON array of all sources added via merge

    # Relationships
    mappings: list["MemoryMapping"] = Relationship(back_populates="process")
    process_binaries: list["ProcessBinary"] = Relationship(back_populates="process")
    register_state: Optional["ProcessRegisterState"] = Relationship(back_populates="process")
    threads: list["Thread"] = Relationship(back_populates="process")


class MemoryMapping(SQLModel, table=True):
    """
    Virtual memory mapping from /proc/PID/maps.

    Describes which binary is loaded at which address range.
    Addresses are stored as signed 64-bit integers (SQLite INTEGER) via addr_to_db()
    so that kernel-space addresses (0xffff...) which exceed INT64_MAX are handled
    correctly. Use addr_from_db() to recover the original unsigned value for display.
    """

    id: int | None = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    start_addr: int = Field(index=True)
    end_addr: int = Field(index=True)
    perms: str = Field(max_length=4)  # "r-xp", "rw-p", etc.
    offset: int  # File offset into binary
    dev: str | None = Field(default=None, max_length=16)  # Device "fc:01"
    inode: int | None = None  # Inode number (0 for anonymous)
    pathname: str = Field(index=True, max_length=256)  # Path or "[heap]", "[stack]", etc.

    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="mappings")
    analysis: Optional["MemoryRegionAnalysis"] = Relationship(back_populates="mapping")


class ProcessBinary(SQLModel, table=True):
    """
    Link between a loaded binary and a process.

    Tracks which binary is loaded where in which process.
    """

    id: int | None = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    binary_id: int | None = Field(default=None, foreign_key="binary.id")  # None if binary not found
    mapping_id: int = Field(foreign_key="memorymapping.id")
    binary_load_addr: int  # Base address where binary is loaded

    # Phase 2: assembly matching fields
    match_score: float | None = None  # 0.0-1.0, 1.0 = exact match
    match_method: str | None = None  # "exact", "hash", "symbol", "partial"

    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="process_binaries")


class BacktraceEntry(SQLModel, table=True):
    """
    A single frame in a decoded backtrace.

    Stores both raw address and resolved symbol information.
    """

    id: int | None = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    frame_num: int
    address: int = Field(index=True)
    resolved_symbol: str = Field(max_length=512)  # "function_name+0x123"
    resolved_file: str | None = Field(default=None, max_length=512)  # "src/file.c"
    resolved_line: int | None = None
    match_confidence: float = Field(default=1.0)  # 0.0-1.0 for fuzzy matches
    thread_id: int | None = Field(default=None, foreign_key="thread.id", index=True)  # None for single-thread


# ============================================================================
# Phase 2.3: Enhanced Memory Analysis Models
# ============================================================================


class MemoryRegionType(str, Enum):
    """Classification of memory region type."""

    UNKNOWN = "unknown"
    TEXT = "text"  # .text section (executable)
    DATA = "data"  # .data section
    HEAP = "heap"  # Heap region
    STACK = "stack"  # Stack region
    VDSO = "vdso"  # Virtual dynamic shared object
    VSYSCALL = "vsyscall"  # vsyscall page
    JIT = "jit"  # JIT compiled code
    MMAP = "mmap"  # mmap'd region
    VVAR = "vvar"  # vvar region
    ANON = "anon"  # Anonymous mapping


class ProcessRegisterState(SQLModel, table=True):
    """
    CPU register state — architecture-agnostic, stored as JSON.

    Supports any architecture (x86-64, ARM64, ARM32, RISC-V, ...).
    Populated from core dump PT_NOTE sections or GDB 'info registers' output.

    registers_json: JSON object mapping register name → integer value, e.g.:
        {"rip": 4198908, "rsp": 140737488347120, "rax": 0, ...}   # x86-64
        {"pc": 4198908, "sp": 140737488347120, "x0": 0, ...}      # ARM64

    thread_id: optional FK to Thread — None means "main thread / unknown".
    """

    id: int | None = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    thread_id: int | None = Field(default=None, foreign_key="thread.id", index=True)

    # Architecture identifier, e.g. "x86_64", "arm64", "arm", "riscv64"
    # Detected from ELF e_machine or left as None when unknown.
    arch: str | None = None

    # All registers as JSON: {"reg_name": int_value, ...}
    registers_json: str = Field(default="{}")

    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="register_state")


class MemoryRegionAnalysis(SQLModel, table=True):
    """
    Analysis results for a memory region (Phase 2.3).

    Stores classification, anomalies, and corruption risk for each mapping.
    """

    id: int | None = Field(default=None, primary_key=True)
    mapping_id: int = Field(foreign_key="memorymapping.id", index=True)

    # Classification
    region_type: str = Field(default=MemoryRegionType.UNKNOWN)  # Enum as string
    confidence: float = Field(default=0.0)  # 0.0-1.0 confidence

    # Analysis results
    is_writable: bool = False
    is_executable: bool = False
    likely_corrupted: bool = False
    anomalies: str = ""  # JSON-serialized list of anomalies

    # Relationships
    mapping: MemoryMapping = Relationship(back_populates="analysis")
