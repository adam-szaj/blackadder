"""
Blackadder - High-level Linux binutils wrapper for debugging.

Provides backtrace decoding, symbol resolution, and memory analysis
for debugging core dumps, process traces, and production issues.
"""

from blackadder.query import BlackadderQuery

__version__ = "0.1.0"
GDB_PLUGIN_API_VERSION = 1
__author__ = "Adam Szaj"

__all__ = ["BlackadderQuery", "GDB_PLUGIN_API_VERSION"]
