"""Binutils integration layer for parsing ELF metadata and resolving symbols."""

from .parser import BinToolsParser, init_parser
from .resolver import resolve_symbol, parse_backtrace_auto

__all__ = ["BinToolsParser", "resolve_symbol", "parse_backtrace_auto", "init_parser"]
