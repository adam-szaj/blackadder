"""
Symbol resolution for addresses in binaries.

Provides high-level functions for resolving instruction pointer addresses
to function names, using both database lookups and external tools (addr2line).
"""

import re

from blackadder.binutils.parser import BinToolsParser


async def resolve_symbol(binary_path: str, offset: int, config) -> str:
    """
    Resolve a binary offset to symbol name.

    Strategy:
    1. Try addr2line (if available, provides symbol + line number)
    2. Fall back to objdump symbol table lookup
    3. Return "???" if not found

    Uses subprocess_sem to limit concurrent process spawning.

    Args:
        binary_path: Path to ELF binary
        offset: Offset within binary
        config: BlackadderConfig with tool paths

    Returns:
        Symbol name in format "function_name+0x123" or "???"
    """
    # Try addr2line first (gives best results with debug symbols)
    symbol = await _resolve_with_addr2line(binary_path, offset, config)

    if symbol and symbol != "??":
        return symbol

    # Fall back to objdump symbol table
    symbol = await _resolve_with_objdump(binary_path, offset, config)

    return symbol if symbol else "???"


async def _resolve_with_addr2line(
    binary_path: str, offset: int, config
) -> str | None:
    """
    Use addr2line to resolve address to function name and line number.

    This works best with debug symbols (.debug_info section).

    Args:
        binary_path: Path to ELF binary (or separate debug file)
        offset: Offset within binary
        config: BlackadderConfig

    Returns:
        Symbol in format "function_name at file.c:123" or None
    """
    parser = BinToolsParser(config)

    result = None

    def on_line(line: str):
        nonlocal result
        if line and line != "??":
            result = line
            # Don't try to parse, just store raw output
            # addr2line -f output is "function_name" on first line

    try:
        cmd = [
            config.addr2line_path,
            "-f",  # Print function name
            "-C",  # Demangle C++ names
            "-e",
            binary_path,
            hex(offset),
        ]

        await parser.run_command_limited(cmd, on_line)

        if result:
            # addr2line -f gives: function_name\nfile:line
            # We want just the function name
            return result.split("\n")[0] if "\n" in result else result

    except Exception:
        # If addr2line fails, fall through to objdump
        pass

    return None


async def _resolve_with_objdump(
    binary_path: str, offset: int, config
) -> str | None:
    """
    Resolve address using objdump symbol table.

    Finds the symbol whose address is closest to (but <=) the target offset.

    Args:
        binary_path: Path to ELF binary
        offset: Offset within binary
        config: BlackadderConfig

    Returns:
        Symbol name or None
    """
    parser = BinToolsParser(config)

    try:
        symbols = await parser.parse_objdump_syms(binary_path)

        if not symbols:
            return None

        # Find nearest symbol <= offset
        # Sort addresses and find best match
        best_addr = None
        best_name = None

        for addr in sorted(symbols.keys()):
            if addr <= offset:
                best_addr = addr
                best_name = symbols[addr]
            else:
                break

        if best_name and best_addr is not None:
            if best_addr == offset:
                return best_name
            else:
                # Add offset
                diff = offset - best_addr
                return f"{best_name}+{diff:#x}"

    except Exception:
        pass

    return None


def parse_backtrace_auto(trace_text: str) -> list[int]:
    """
    Auto-detect backtrace format and extract addresses.

    Supported formats:
    1. Raw hex addresses (one per line):
        0x400a1c
        0x400a2c
        ...

    2. GDB backtrace format:
        #0  0x0000555555554cc5 in main (argc=1, argv=0x7fffffffde88) at main.c:42
        #1  0x00007ffff7a05f45 in __libc_start_main (main=0x555555554c00 <main>, ...
        ...

    3. Kernel/system backtrace (with brackets):
        [<ffffffff81010001>] function_name+0x42/0x100
        [<ffffffff81010002>] another_function+0x10/0x50
        ...

    Args:
        trace_text: Raw backtrace text

    Returns:
        List of instruction pointer addresses (as integers)
    """
    addresses = []

    # Pattern 1: GDB format - extract hex after '#N  '
    gdb_pattern = re.compile(
        r"#\d+\s+(?:0x)?([0-9a-f]{1,16})", re.IGNORECASE | re.MULTILINE
    )

    # Pattern 2: Kernel format - extract hex in brackets
    kernel_pattern = re.compile(
        r"\[<(?:0x)?([0-9a-f]{1,16})>\]", re.IGNORECASE | re.MULTILINE
    )

    # Pattern 3: Raw hex (with or without 0x prefix)
    raw_pattern = re.compile(r"(?:^|\n)(0x)?([0-9a-f]{1,16})(?:\s|$)", re.IGNORECASE)

    # Try GDB format first (most specific)
    gdb_matches = gdb_pattern.findall(trace_text)
    if gdb_matches:
        for match in gdb_matches:
            try:
                addr = int(match, 16)
                addresses.append(addr)
            except ValueError:
                pass
        return addresses

    # Try kernel format
    kernel_matches = kernel_pattern.findall(trace_text)
    if kernel_matches:
        for match in kernel_matches:
            try:
                addr = int(match, 16)
                addresses.append(addr)
            except ValueError:
                pass
        return addresses

    # Fall back to raw hex format
    # Split by lines and look for hex patterns
    for line in trace_text.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Try to parse line as hex address (with or without 0x prefix)
        if line.startswith('0x') or line.startswith('0X'):
            try:
                addr = int(line, 16)
                addresses.append(addr)
                continue
            except ValueError:
                pass

        # Try without 0x prefix
        if len(line) <= 16 and all(c in '0123456789abcdefABCDEF' for c in line):
            try:
                addr = int(line, 16)
                addresses.append(addr)
                continue
            except ValueError:
                pass

    return addresses
