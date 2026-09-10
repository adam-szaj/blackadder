"""
Custom exceptions for Baldrick.

Provides typed exceptions for different failure modes, enabling
precise error handling and clear error messages.
"""


class BaldrickException(Exception):
    """Base exception for all Baldrick errors."""

    pass


# Database Exceptions
class DatabaseError(BaldrickException):
    """Base exception for database errors."""

    pass


class DatabaseConnectionError(DatabaseError):
    """Failed to connect to database."""

    pass


class DatabaseQueryError(DatabaseError):
    """Database query failed."""

    pass


class DatabaseConstraintError(DatabaseError):
    """Database constraint violation (e.g., duplicate key)."""

    pass


# File Exceptions
class FileError(BaldrickException):
    """Base exception for file errors."""

    pass


class FileNotFoundError(FileError):
    """File does not exist."""

    pass


class FileAccessError(FileError):
    """Permission denied or cannot read file."""

    pass


class FileFormatError(FileError):
    """File format invalid or corrupted."""

    pass


class FileTooLargeError(FileError):
    """File exceeds size limit."""

    pass


# ELF/Binary Exceptions
class ELFError(BaldrickException):
    """Base exception for ELF binary errors."""

    pass


class ELFMagicError(ELFError):
    """File is not a valid ELF binary."""

    pass


class ELFHeaderError(ELFError):
    """ELF header parsing failed."""

    pass


class ELFCoreDumpError(ELFError):
    """File is not an ELF core dump."""

    pass


class BinaryNotFoundError(ELFError):
    """Binary file not found in rootfs."""

    pass


# Memory/Process Exceptions
class ProcessError(BaldrickException):
    """Base exception for process-related errors."""

    pass


class ProcessNotFoundError(ProcessError):
    """Process snapshot not found in database."""

    pass


class InvalidAddressError(ProcessError):
    """Address is invalid or out of range."""

    pass


class MemoryMappingError(ProcessError):
    """Memory mapping lookup failed."""

    pass


class MemoryAnalysisError(ProcessError):
    """Memory analysis failed."""

    pass


# Symbol Resolution Exceptions
class SymbolError(BaldrickException):
    """Base exception for symbol resolution errors."""

    pass


class SymbolNotFoundError(SymbolError):
    """Symbol not found at address."""

    pass


class SymbolResolutionError(SymbolError):
    """Symbol resolution tool failed."""

    pass


# Subprocess Exceptions
class SubprocessError(BaldrickException):
    """Base exception for subprocess errors."""

    pass


class ToolNotFoundError(SubprocessError):
    """Required tool (objdump, readelf, etc.) not found."""

    pass


class ToolExecutionError(SubprocessError):
    """Tool execution failed."""

    pass


class ToolTimeoutError(SubprocessError):
    """Tool execution timed out."""

    pass


# Validation Exceptions
class ValidationError(BaldrickException):
    """Base exception for validation errors."""

    pass


class InvalidArgumentError(ValidationError):
    """Invalid argument provided."""

    pass


class InvalidConfigError(ValidationError):
    """Configuration is invalid."""

    pass


# Resource Limit Exceptions
class ResourceLimitError(BaldrickException):
    """Base exception for resource limit violations."""

    pass


class TooManyRegionsError(ResourceLimitError):
    """Process has too many memory regions."""

    pass


class OversizedAllocationError(ResourceLimitError):
    """Allocation size exceeds limit."""

    pass


class QueryTimeoutError(ResourceLimitError):
    """Database query exceeded time limit."""

    pass


# Parsing Exceptions
class ParseError(BaldrickException):
    """Base exception for parsing errors."""

    pass


class BacktraceParseError(ParseError):
    """Backtrace format invalid or not recognized."""

    pass


class SymbolParseError(ParseError):
    """Symbol table parsing failed."""

    pass


class FingerprintParseError(ParseError):
    """Fingerprint data invalid."""

    pass


class CoreDumpParseError(ParseError):
    """Core dump parsing failed."""

    pass
