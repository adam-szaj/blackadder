"""
Configuration management for blackadder.

Uses Pydantic Settings for type-safe config loading from environment,
.env files, or defaults. Supports dynamic concurrency tuning.
"""

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BlackadderConfig(BaseSettings):
    """
    Application configuration.

    Loads from environment variables, .env file, or defaults.
    Can be overridden per-command via CLI arguments.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # =========================================================================
    # Database configuration
    # =========================================================================

    db: str = Field(
        default="sqlite+aiosqlite:///blackadder.db",
        description="Path to the unified database (binary metadata + process snapshots)",
    )

    # =========================================================================
    # Binary search paths
    # =========================================================================

    rootfs_paths: list[str] = Field(
        default_factory=lambda: ["/"],
        description="Colon-separated paths to search for binaries",
    )

    debugfs_paths: list[str] = Field(
        default_factory=lambda: ["/usr/lib/debug"],
        description="Paths to search for debug symbols",
    )

    source_paths: list[str] = Field(
        default_factory=list,
        description="Colon-separated paths to search for source files",
    )

    # =========================================================================
    # Binutils tool paths
    # =========================================================================

    objdump_path: str = Field(
        default="/usr/bin/objdump",
        description="Path to objdump binary",
    )

    readelf_path: str = Field(
        default="/usr/bin/readelf",
        description="Path to readelf binary",
    )

    addr2line_path: str = Field(
        default="/usr/bin/addr2line",
        description="Path to addr2line binary",
    )

    # =========================================================================
    # Concurrency and performance tuning
    # =========================================================================

    max_subprocess_workers: int = Field(
        default_factory=lambda: min(32, (os.cpu_count() or 4) * 2),
        description="Max concurrent subprocess (objdump/addr2line) calls. "
        "Auto-detected based on CPU count, capped at 32.",
    )

    max_symbol_cache_size: int = Field(
        default=100_000,
        description="Max symbols to cache in memory (~100k typical)",
    )

    db_pool_size: int = Field(
        default=10,
        description="Max concurrent database connections (mostly for compatibility)",
    )

    db_max_overflow: int = Field(
        default=5,
        description="Extra database connections for load spikes",
    )

    symbol_batch_size: int = Field(
        default=100,
        description="Batch size for symbol resolution (tune based on system)",
    )

    frame_batch_size: int = Field(
        default=50,
        description="Batch size for backtrace frame decoding",
    )

    # =========================================================================
    # Resource limits (Phase 2 hardening)
    # =========================================================================

    max_memory_regions: int = Field(
        default=10000,
        description="Max memory regions per process (prevent DOS)",
    )

    max_region_size: int = Field(
        default=0x40000000,  # 1GB
        description="Max single region size (bytes)",
    )

    max_core_dump_size: int = Field(
        default=0x40000000,  # 1GB
        description="Max core dump file size (bytes)",
    )

    max_backtraces_cached: int = Field(
        default=100_000,
        description="Max backtraces in analysis (prevent memory growth)",
    )

    query_timeout_seconds: int = Field(
        default=30,
        description="Max time for database queries (seconds)",
    )

    subprocess_timeout_seconds: float = Field(
        default=10,
        description="Max time for tool execution (objdump, readelf, etc.)",
    )

    # =========================================================================
    # Logging and debug
    # =========================================================================

    debug: bool = Field(
        default=False,
        description="Enable debug logging",
    )

    sql_echo: bool = Field(
        default=False,
        description="Log all SQL queries",
    )

    log_file: str | None = Field(
        default=None,
        description="Optional path to log file",
    )

    # =========================================================================
    # Validation and defaults
    # =========================================================================

    def __init__(self, **data):
        """Initialize config with auto-detection."""
        super().__init__(**data)

        # Auto-detect CPU count if not explicitly set
        if "max_subprocess_workers" not in data:
            cpu_count = os.cpu_count() or 4
            self.max_subprocess_workers = min(32, cpu_count * 2)


def get_config() -> BlackadderConfig:
    """Get global config instance (singleton-like)."""
    return BlackadderConfig()
