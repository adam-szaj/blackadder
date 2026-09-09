"""
Async binutils parser for symbol and section extraction.

Replaces legacy threading-based commands.py with modern asyncio approach.
Implements subprocess pooling via semaphore and CPU-bound work via thread pool.
"""

import asyncio
import re
from collections.abc import Callable

from blackadder.binutils.runner import SubprocessRunner, get_shared_runner


class BinToolsParser:
    """
    Async wrapper around objdump/readelf with resource pooling.

    Features:
    - Subprocess semaphore to limit concurrent process spawning
    - Thread pool for CPU-bound regex parsing (doesn't block event loop)
    - Configurable resource limits
    """

    def __init__(self, config, runner: SubprocessRunner | None = None):
        """
        Initialize binutils parser with resource limits.

        Args:
            config: BlackadderConfig with tool paths and limits
        """
        self.config = config
        self.runner = runner or get_shared_runner(config)
        self.subprocess_sem = self.runner.semaphore

        # Pre-compile regex patterns for symbol/section parsing
        self.symbol_regex = re.compile(
            r"^([0-9a-f]+)\s+"  # address
            r"(.{1,2})\s+"  # flags (l/g/w)
            r"(.{1,2})\s+"  # type (F/O/d/etc)
            r"(\S+)\s+"  # section name
            r"([0-9a-f]+)\s+"  # size
            r"(\S+)"  # symbol name
        )

        self.section_regex = re.compile(
            r"^\s*(\d+)\s+"  # index
            r"(\S+)\s+"  # section name
            r"([0-9a-fA-F]+)\s+"  # size (hex)
            r"([0-9a-fA-F]+)\s+"  # vma (hex)
            r"([0-9a-fA-F]+)\s+"  # lma (hex)
            r"([0-9a-fA-F]+)\s+"  # file off (hex)
            r"\d+\*\*(\d+)"  # alignment
        )

    async def run_command_limited(
        self,
        cmd: list[str],
        on_line: Callable[[str], None] | None = None,
    ) -> list[str]:
        """
        Execute command with subprocess limiting (semaphore).

        Waits if at resource limit, then executes subprocess asynchronously.
        Collects output lines and optionally calls on_line callback per line.

        Args:
            cmd: Command and arguments to execute
            on_line: Optional callback invoked per output line

        Returns:
            List of all output lines
        """
        return await self.runner.run(cmd, on_line)

    async def _run_command_internal(
        self,
        cmd: list[str],
        on_line: Callable[[str], None] | None = None,
    ) -> list[str]:
        """
        Internal: execute command and stream output asynchronously.

        Reads stdout and stderr concurrently without blocking each other.

        Args:
            cmd: Command and arguments
            on_line: Optional callback per line

        Returns:
            List of all output lines
        """
        return await self.runner.run(cmd, on_line)

    async def parse_objdump_syms(self, binary_path: str) -> dict[int, str]:
        """
        Parse objdump --syms output asynchronously.

        Subprocess call is made via run_command_limited (respects semaphore).
        Regex parsing is offloaded to thread pool (CPU-bound).

        Args:
            binary_path: Path to ELF binary

        Returns:
            Dict mapping address -> symbol name
        """
        # Call objdump via subprocess (async, semaphore-limited)
        lines = await self.run_command_limited([self.config.objdump_path, "--syms", binary_path])

        # Parse lines in thread pool (CPU-bound regex)
        def parse_symbols(all_lines):
            """CPU-bound parsing of symbol lines."""
            result = {}
            for line in all_lines:
                m = self.symbol_regex.match(line)
                if m:
                    addr = int(m.group(1), 16)
                    name = m.group(6)
                    result[addr] = name
            return result

        symbols = await asyncio.to_thread(parse_symbols, lines)
        return symbols

    async def parse_objdump_sections(self, binary_path: str) -> dict[str, dict]:
        """
        Parse objdump -h (section headers) asynchronously.

        Args:
            binary_path: Path to ELF binary

        Returns:
            Dict mapping section name -> {name, size, vma, lma, off, align}
        """
        # Call objdump via subprocess
        lines = await self.run_command_limited([self.config.objdump_path, "-h", binary_path])

        # Parse in thread pool
        def parse_sections(all_lines):
            """CPU-bound parsing of section lines."""
            result = {}
            for line in all_lines:
                m = self.section_regex.match(line)
                if m:
                    name = m.group(2)
                    size = int(m.group(3), 16)
                    vma = int(m.group(4), 16)
                    lma = int(m.group(5), 16)
                    off = int(m.group(6), 16)
                    align = int(m.group(7))

                    result[name] = {
                        "name": name,
                        "size": size,
                        "vma": vma,
                        "lma": lma,
                        "off": off,
                        "align": align,
                    }
            return result

        sections = await asyncio.to_thread(parse_sections, lines)
        return sections

    async def parse_objdump_syms_full(self, binary_path: str) -> list[dict]:
        """
        Parse objdump symbol output with all symbol fields.

        Tries --syms first (static symbol table). If that yields nothing (stripped
        binary), falls back to --dynamic-syms (.dynsym — exported symbols of shared
        libraries). Both sets are merged when both produce results.

        Args:
            binary_path: Path to ELF binary

        Returns:
            List of dicts with keys: address, scope, sym_type, section, size, name
        """
        static_lines, dynamic_lines = await asyncio.gather(
            self.run_command_limited([self.config.objdump_path, "--syms", binary_path]),
            self.run_command_limited([self.config.objdump_path, "--dynamic-syms", binary_path]),
        )

        def parse_all(all_lines: list[str]) -> list[dict]:
            result = []
            for line in all_lines:
                m = self.symbol_regex.match(line)
                if m:
                    result.append(
                        {
                            "address": int(m.group(1), 16),
                            "scope": (m.group(2).strip() or "l")[0],
                            "sym_type": (m.group(3).strip() or " ")[0],
                            "section": m.group(4)[:32],
                            "size": int(m.group(5), 16),
                            "name": m.group(6)[:256],
                        }
                    )
            return result

        # --dynamic-syms has extra version/binding column before the name;
        # the name is always the last whitespace-separated token on the line.
        def parse_dynamic(all_lines: list[str]) -> list[dict]:
            result = []
            for line in all_lines:
                m = self.symbol_regex.match(line)
                if not m:
                    continue
                tokens = line.split()
                name = tokens[-1][:256] if tokens else m.group(6)[:256]
                result.append(
                    {
                        "address": int(m.group(1), 16),
                        "scope": (m.group(2).strip() or "g")[0],
                        "sym_type": (m.group(3).strip() or " ")[0],
                        "section": m.group(4)[:32],
                        "size": int(m.group(5), 16),
                        "name": name,
                    }
                )
            return result

        static = await asyncio.to_thread(parse_all, static_lines)
        dynamic = await asyncio.to_thread(parse_dynamic, dynamic_lines)

        # Merge: deduplicate by (address, name); static takes priority
        seen: set[tuple[int, str]] = {(s["address"], s["name"]) for s in static}
        merged = static + [d for d in dynamic if (d["address"], d["name"]) not in seen]
        return merged

    async def parse_readelf_debug_link(self, binary_path: str) -> str | None:
        """
        Extract .gnu_debuglink section using readelf.

        Args:
            binary_path: Path to ELF binary

        Returns:
            Debug link filename or None if not found
        """
        lines = await self.run_command_limited(
            [self.config.readelf_path, "--string-dump=.gnu_debuglink", binary_path]
        )

        # Lines come pre-stripped by run_command_limited; look for: [    0]  libfoo.so.debug
        # Mirrors the bash: sed -n '/]/{s/.* //;p;q}'
        # Take the last token from the first line that contains ']'
        for line in lines:
            if "]" in line:
                token = line.rsplit(None, 1)[-1]
                if token.isprintable():
                    return token
                break  # First ']' line is always the name; stop here

        return None


# Global parser instance (initialized by config system)
_parser: BinToolsParser | None = None


def init_parser(config):
    """Initialize global parser instance."""
    global _parser
    _parser = BinToolsParser(config)


def get_parser() -> BinToolsParser:
    """Get global parser instance (must be initialized first)."""
    if _parser is None:
        raise RuntimeError("Parser not initialized. Call init_parser(config) first.")
    return _parser
