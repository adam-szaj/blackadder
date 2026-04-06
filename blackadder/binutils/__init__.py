"""Binutils integration layer for parsing ELF metadata and resolving symbols."""

from .parser import BinToolsParser, init_parser
from .resolver import parse_backtrace_auto, resolve_symbol

__all__ = ["BinToolsParser", "resolve_symbol", "parse_backtrace_auto", "init_parser"]
