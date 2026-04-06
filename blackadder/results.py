"""
Typed result objects for operations that can fail gracefully.

These dataclasses provide structured returns for operations where:
- Returning an empty/null result is valid (continue operation)
- But callers need to know WHY the result is empty
- Status and reason fields enable diagnostic visibility
"""

from dataclasses import dataclass, field


@dataclass
class FingerprintResult:
    """Result of computing function fingerprints from a binary."""

    fingerprints: dict[str, str] = field(default_factory=dict)
    status: str = (
        "success"  # "success", "file_not_found", "not_elf", "no_functions", "parse_error", "permission_denied"
    )
    reason: str | None = None
    binary_path: str | None = None


@dataclass
class CoreDumpResult:
    """Result of parsing an ELF core dump."""

    mappings: list[dict] = field(default_factory=list)
    elf_headers: dict = field(default_factory=dict)
    pid: int | None = None
    signal: int | None = None
    status: str = (
        "success"  # "success", "file_not_found", "not_elf", "not_core_dump", "parse_error", "corrupted"
    )
    reason: str | None = None
    core_path: str | None = None


@dataclass
class MapsParseResult:
    """Result of parsing /proc/maps format."""

    mappings: list[dict] = field(default_factory=list)
    failed_lines: int = 0
    parse_errors: list[str] = field(default_factory=list)


@dataclass
class SymbolResolutionResult:
    """Result of resolving an address to a symbol."""

    symbol: str = "???"
    status: str = "success"  # "success", "not_found", "binary_not_found", "error"
    reason: str | None = None
    binary_path: str | None = None
    offset: int | None = None


@dataclass
class BacktraceDecodeResult:
    """Result of decoding a backtrace."""

    frames: list = field(default_factory=list)
    failed_count: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class MemoryAnalysisResult:
    """Result of analyzing memory layout."""

    regions_analyzed: int = 0
    anomalies: list[str] = field(default_factory=list)
    corruption_count: int = 0
    corruption_risk: float = 0.0
    status: str = "success"  # "success", "invalid_process_id", "error"
    reason: str | None = None
