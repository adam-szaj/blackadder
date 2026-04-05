"""Binutils integration layer for parsing ELF metadata and resolving symbols."""

from .parser import BinToolsParser
from .resolver import resolve_symbol, parse_backtrace_auto

__all__ = ["BinToolsParser", "resolve_symbol", "parse_backtrace_auto"]
