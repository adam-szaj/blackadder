"""
Symbol resolution for addresses in binaries.

Provides high-level functions for resolving instruction pointer addresses
to function names, using both database lookups and external tools (addr2line).
"""

import re

from baldrick.binutils.parser import BinToolsParser


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
        config: BaldrickConfig with tool paths

    Returns:
        Symbol name in format "function_name+0x123" or "???"
    """
    result = await resolve_symbol_full(binary_path, offset, config)
    return result[0]


async def resolve_symbol_full(
    binary_path: str, offset: int, config
) -> tuple[str, str | None, int | None]:
    """
    Resolve a binary offset to symbol name plus source file and line.

    Returns:
        (symbol, source_file, source_line) — source_file/source_line may be None
    """
    sym, src_file, src_line = await _resolve_with_addr2line(binary_path, offset, config)

    if sym and sym != "??":
        return sym, src_file, src_line

    # Fall back to objdump symbol table (no source info available)
    sym2 = await _resolve_with_objdump(binary_path, offset, config)
    return (sym2 if sym2 else "???"), None, None


async def _resolve_with_addr2line(
    binary_path: str, offset: int, config
) -> tuple[str | None, str | None, int | None]:
    """
    Use addr2line to resolve address to function name, source file, and line.

    addr2line -f output:
        function_name
        file.c:42

    Returns:
        (function_name, source_file, source_line) — all may be None on failure
    """
    parser = BinToolsParser(config)
    lines: list[str] = []

    def on_line(line: str) -> None:
        lines.append(line)

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

        if not lines or lines[0] in ("??", ""):
            return None, None, None

        func = lines[0]
        src_file: str | None = None
        src_line: int | None = None

        if len(lines) >= 2:
            # Format: "path/file.c:42" or "??:0" or "path/file.c:42 (discriminator 1)"
            raw_loc = lines[1].split(" ")[0]  # strip discriminator suffix
            if raw_loc and raw_loc != "??:0":
                parts = raw_loc.rsplit(":", 1)
                if parts[0] != "??":
                    src_file = parts[0]
                if len(parts) > 1:
                    try:
                        src_line = int(parts[1])
                    except ValueError:
                        pass

        return func, src_file, src_line

    except Exception:
        pass

    return None, None, None


async def _resolve_with_objdump(binary_path: str, offset: int, config) -> str | None:
    """
    Resolve address using objdump symbol table.

    Finds the symbol whose address is closest to (but <=) the target offset.

    Args:
        binary_path: Path to ELF binary
        offset: Offset within binary
        config: BaldrickConfig

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
    gdb_pattern = re.compile(r"#\d+\s+(?:0x)?([0-9a-f]{1,16})", re.IGNORECASE | re.MULTILINE)

    # Pattern 2: Kernel format - extract hex in brackets
    kernel_pattern = re.compile(r"\[<(?:0x)?([0-9a-f]{1,16})>\]", re.IGNORECASE | re.MULTILINE)

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
    for line in trace_text.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Try to parse line as hex address (with or without 0x prefix)
        if line.startswith("0x") or line.startswith("0X"):
            try:
                addr = int(line, 16)
                addresses.append(addr)
                continue
            except ValueError:
                pass

        # Try without 0x prefix
        if len(line) <= 16 and all(c in "0123456789abcdefABCDEF" for c in line):
            try:
                addr = int(line, 16)
                addresses.append(addr)
                continue
            except ValueError:
                pass

    return addresses
