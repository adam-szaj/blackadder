"""
SQLModel ORM definitions for blackadder.

Defines models for both rootfs database (binary metadata) and process database
(runtime analysis). All models are type-safe with Pydantic validation.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator
from sqlmodel import SQLModel, Field, Relationship


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
    file: Optional[str] = None
    line: Optional[int] = None

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

    id: Optional[int] = Field(default=None, primary_key=True)
    md5sum: str = Field(unique=True, index=True, max_length=32)
    name: str = Field(index=True)  # e.g., "libc.so.6"
    debug_link: Optional[str] = None  # Path to separate debug symbols

    # Relationships
    sections: list["SectionHeader"] = Relationship(back_populates="binary")
    symbols: list["Symbol"] = Relationship(back_populates="binary")
    fingerprints: list["FunctionFingerprint"] = Relationship(back_populates="binary")


class SectionHeader(SQLModel, table=True):
    """
    ELF section metadata extracted via objdump -h.

    Includes .text, .bss, .rodata, .debug_info, etc.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
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

    id: Optional[int] = Field(default=None, primary_key=True)
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

    id: Optional[int] = Field(default=None, primary_key=True)
    binary_id: int = Field(foreign_key="binary.id", index=True)
    func_name: str = Field(index=True, max_length=256)
    func_offset: int  # Offset in binary
    func_size: int
    # Ignore addresses/relocations, hash the instruction bytes
    content_hash: str = Field(max_length=64)  # SHA256 of normalized function body

    # Relationships
    binary: Binary = Relationship(back_populates="fingerprints")


class BinaryLocator(SQLModel, table=True):
    """
    Maps a file path to a binary identified by MD5.

    Allows deduplication: same binary at multiple paths only stored once.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    path: str = Field(unique=True, index=True)  # Full file path
    md5sum: str = Field(foreign_key="binary.md5sum")
    mtime: int  # Modification time (unix timestamp) for cache validation


# ============================================================================
# Process Database Models (dynamic runtime analysis)
# ============================================================================


class ProcessSnapshot(SQLModel, table=True):
    """
    Represents a process at a point in time (live or core dump).

    Multiple analyses (backtraces, address resolutions) reference this.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    pid: Optional[int] = None  # None for offline/core dump analysis
    created_at: datetime = Field(default_factory=datetime.now)
    description: str = ""  # e.g., "core dump from crash at 2026-04-06 14:30:00"

    # Phase 2.2: Core dump parsing support
    source_type: str = Field(default="maps")  # "maps", "core_dump", "gdb_live"
    source_path: Optional[str] = None  # Path to core dump file if applicable

    # Relationships
    mappings: list["MemoryMapping"] = Relationship(back_populates="process")
    process_binaries: list["ProcessBinary"] = Relationship(back_populates="process")
    register_state: Optional["ProcessRegisterState"] = Relationship(back_populates="process")


class MemoryMapping(SQLModel, table=True):
    """
    Virtual memory mapping from /proc/PID/maps.

    Describes which binary is loaded at which address range.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    start_addr: int = Field(index=True)
    end_addr: int = Field(index=True)
    perms: str = Field(max_length=4)  # "r-xp", "rw-p", etc.
    offset: int  # File offset into binary
    pathname: str = Field(index=True, max_length=256)  # Path or "[heap]", "[stack]", etc.

    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="mappings")
    analysis: Optional["MemoryRegionAnalysis"] = Relationship(back_populates="mapping")


class ProcessBinary(SQLModel, table=True):
    """
    Link between a loaded binary and a process.

    Tracks which binary is loaded where in which process.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    binary_id: Optional[int] = Field(
        default=None, foreign_key="binary.id"
    )  # None if binary not found
    mapping_id: int = Field(foreign_key="memorymapping.id")
    binary_load_addr: int  # Base address where binary is loaded

    # Phase 2: assembly matching fields
    match_score: Optional[float] = None  # 0.0-1.0, 1.0 = exact match
    match_method: Optional[str] = None  # "exact", "hash", "symbol", "partial"

    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="process_binaries")


class BacktraceEntry(SQLModel, table=True):
    """
    A single frame in a decoded backtrace.

    Stores both raw address and resolved symbol information.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)
    frame_num: int
    address: int = Field(index=True)
    resolved_symbol: str = Field(max_length=512)  # "function_name+0x123"
    resolved_file: Optional[str] = Field(default=None, max_length=512)  # "src/file.c"
    resolved_line: Optional[int] = None
    match_confidence: float = Field(default=1.0)  # 0.0-1.0 for fuzzy matches


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
    CPU register state from core dump PT_NOTE sections (Phase 2.3).

    Stores x86-64 general purpose and special registers from core dump.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    process_id: int = Field(foreign_key="processsnapshot.id", index=True)

    # General purpose registers (x86-64)
    rax: Optional[int] = None
    rbx: Optional[int] = None
    rcx: Optional[int] = None
    rdx: Optional[int] = None
    rsi: Optional[int] = None
    rdi: Optional[int] = None
    rbp: Optional[int] = None  # Frame pointer
    rsp: Optional[int] = None  # Stack pointer
    rip: Optional[int] = None  # Instruction pointer (crash location)

    # Extended registers
    r8: Optional[int] = None
    r9: Optional[int] = None
    r10: Optional[int] = None
    r11: Optional[int] = None
    r12: Optional[int] = None
    r13: Optional[int] = None
    r14: Optional[int] = None
    r15: Optional[int] = None

    # Flags
    eflags: Optional[int] = None

    # Relationships
    process: ProcessSnapshot = Relationship(back_populates="register_state")


class MemoryRegionAnalysis(SQLModel, table=True):
    """
    Analysis results for a memory region (Phase 2.3).

    Stores classification, anomalies, and corruption risk for each mapping.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
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


# Add relationships to ProcessSnapshot
ProcessSnapshot.update_forward_refs()


# Add relationships to MemoryMapping (update after MemoryRegionAnalysis defined)
MemoryMapping.update_forward_refs()
