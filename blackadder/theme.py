"""
Color theme and value formatting for baldrick CLI output.

Default palette: Tokyo Night (https://github.com/folke/tokyonight.nvim)
Configurable via [theme] section in ~/.baldrick.toml or ./baldrick.toml.

Data types and their semantic meaning:
  address  — hex addresses, virtual addresses      format: hex (0x7f001000)
  offset   — file offsets within a binary          format: hex (0x1000)
  size     — byte sizes, counts                    format: human (4.0 KB)
  symbol   — function/variable names
  binary   — binary names, file paths, pathnames
  flags    — permissions (rwxp), ELF flags
  section  — ELF section names (.text, .data, ...)
  debug    — debug file paths, source locations
  meta     — IDs, frame numbers, indices, timestamps
  description — human-readable text, query descriptions
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

# Valid format values per type
_VALID_FORMATS = {
    "address": ("hex", "dec"),
    "offset": ("hex", "dec"),
    "size": ("human", "hex", "dec"),
}


@dataclass
class ColorTheme:
    # Colors (Rich-compatible: hex "#rrggbb" or named "cyan")
    address: str = "#7aa2f7"      # blue       — hex addresses
    symbol: str = "#e0af68"       # gold       — function/variable names
    binary: str = "#bb9af7"       # purple     — binary names, file paths
    size: str = "#9ece6a"         # green      — byte sizes, counts
    flags: str = "#f7768e"        # red/pink   — permissions, ELF flags
    section: str = "#2ac3de"      # cyan       — ELF section names
    debug: str = "#565f89"        # dim blue   — debug files, source locations
    meta: str = "#737aa2"         # grey       — IDs, indices, frame numbers
    description: str = "#a9b1d6"  # light grey — human-readable text

    # Formats for numeric types ("hex", "dec", "human")
    address_format: str = "hex"    # addresses shown as 0xNNNNNNNN
    offset_format: str = "hex"     # file offsets shown as 0xNNNN
    size_format: str = "human"     # sizes shown as 4.0 KB / 2.0 MB


# Tokyo Night default (same as field defaults above, explicit for clarity)
TOKYO_NIGHT = ColorTheme()

# Column name → semantic type mapping
# type name is either a color field name on ColorTheme, or one of the
# special format-aware types: "address", "offset", "size"
COLUMN_TYPE_MAP: dict[str, str] = {
    # addresses
    "address": "address",
    "start_addr": "address",
    "end_addr": "address",
    "vma": "address",
    "lma": "address",
    "binary_load_addr": "address",
    # offsets (file-relative, not virtual)
    "offset": "offset",
    "off": "offset",
    # sizes
    "size": "size",
    "align": "size",
    # symbols
    "name": "symbol",
    "resolved_symbol": "symbol",
    "func_name": "symbol",
    # binaries / paths
    "pathname": "binary",
    "binary_name": "binary",
    "path": "binary",
    "debug_file": "debug",
    "debug_link": "debug",
    "resolved_file": "debug",
    # flags / permissions
    "perms": "flags",
    "scope": "flags",
    "sym_type": "flags",
    "source_type": "flags",
    # sections
    "section": "section",
    # meta / ids
    "id": "meta",
    "idx": "meta",
    "binary_id": "meta",
    "process_id": "meta",
    "mapping_id": "meta",
    "frame_num": "meta",
    "pid": "meta",
    "inode": "meta",
    "mtime": "meta",
    "created_at": "meta",
    "md5sum": "meta",
    "tid": "meta",
    "wchan": "description",
    "syscall": "flags",
    "stack_start": "address",
    "stack_end": "address",
    "dev": "meta",
    # description / text
    "description": "description",
    "tag": "description",
    "match_method": "description",
    "match_score": "description",
    "resolved_line": "description",
    "match_confidence": "description",
}


def _load_toml_theme(path: Path) -> dict[str, str]:
    """Extract [theme] section from a baldrick.toml file."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    section = data.get("theme", {})
    return {k: v for k, v in section.items() if isinstance(v, str)}


def load_theme() -> ColorTheme:
    """
    Load the color theme, merging user and local config over the default.

    Priority (highest wins):
      1. ./baldrick.toml  [theme]
      2. ~/.baldrick.toml [theme]
      3. Built-in Tokyo Night defaults
    """
    overrides: dict[str, str] = {}

    user_toml = Path.home() / ".baldrick.toml"
    overrides.update(_load_toml_theme(user_toml))

    local_toml = Path.cwd() / "baldrick.toml"
    if local_toml != user_toml:
        overrides.update(_load_toml_theme(local_toml))

    theme = ColorTheme()
    for key, value in overrides.items():
        if hasattr(theme, key):
            setattr(theme, key, value)

    return theme


def column_style(col_name: str, theme: ColorTheme) -> str:
    """Return the Rich style string for a given SQL column name."""
    type_name = COLUMN_TYPE_MAP.get(col_name.lower())
    if type_name is None:
        return ""
    # address/offset/size share color with the "address"/"size" color fields
    color_field = type_name if type_name not in ("offset",) else "address"
    return getattr(theme, color_field, "")


def _fmt_human(n: int) -> str:
    """Format an integer as human-readable byte size."""
    if abs(n) >= 1024 ** 3:
        return f"{n / 1024**3:.1f} GB"
    if abs(n) >= 1024 ** 2:
        return f"{n / 1024**2:.1f} MB"
    if abs(n) >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def format_value(col_name: str, value: Any, theme: ColorTheme) -> str:
    """
    Format a value for display, applying type-specific formatting to integers.

    Non-integer values (or None) are always returned as plain strings.
    Integer formatting is controlled by theme.*_format fields:
      address_format: "hex" | "dec"
      offset_format:  "hex" | "dec"
      size_format:    "human" | "hex" | "dec"
    """
    if value is None:
        return ""

    type_name = COLUMN_TYPE_MAP.get(col_name.lower())

    if type_name in ("address", "offset", "size") and isinstance(value, int):
        fmt_field = f"{type_name}_format"
        fmt = getattr(theme, fmt_field, None)
        if fmt == "hex":
            # Recover unsigned address from signed DB storage
            if value < 0:
                value = value + (1 << 64)
            return f"{value:#x}"
        if fmt == "human" and type_name == "size":
            return _fmt_human(value)
        # "dec" or fallback
        return str(value)

    return str(value)
