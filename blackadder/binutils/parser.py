"""
Async binutils parser for symbol and section extraction.

Replaces legacy threading-based commands.py with modern asyncio approach.
Implements subprocess pooling via semaphore and CPU-bound work via thread pool.
"""

import asyncio
import re
from typing import Callable, Optional


class BinToolsParser:
    """
    Async wrapper around objdump/readelf with resource pooling.

    Features:
    - Subprocess semaphore to limit concurrent process spawning
    - Thread pool for CPU-bound regex parsing (doesn't block event loop)
    - Configurable resource limits
    """

    def __init__(self, config):
        """
        Initialize binutils parser with resource limits.

        Args:
            config: BlackadderConfig with tool paths and limits
        """
        self.config = config

        # Subprocess limiting semaphore
        # Default 32 concurrent processes to avoid resource exhaustion
        self.subprocess_sem = asyncio.Semaphore(config.max_subprocess_workers)

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
        on_line: Optional[Callable[[str], None]] = None,
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
        async with self.subprocess_sem:  # Wait if at resource limit
            return await self._run_command_internal(cmd, on_line)

    async def _run_command_internal(
        self,
        cmd: list[str],
        on_line: Optional[Callable[[str], None]] = None,
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
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=32 * 1024,  # 32KB buffer per stream
        )

        lines: list[str] = []

        async def read_stream(stream):
            """Read stream line-by-line, invoke callback if provided."""
            while True:
                line = await stream.readline()
                if not line:
                    break

                decoded = line.decode().strip()
                lines.append(decoded)

                if on_line:
                    on_line(decoded)

        # Concurrent stdout + stderr reading (won't block each other)
        await asyncio.gather(
            read_stream(proc.stdout),
            read_stream(proc.stderr),
        )
        await proc.wait()

        return lines

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
        lines = await self.run_command_limited(
            [self.config.objdump_path, "--syms", binary_path]
        )

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
        lines = await self.run_command_limited(
            [self.config.objdump_path, "-h", binary_path]
        )

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

    async def parse_readelf_debug_link(self, binary_path: str) -> Optional[str]:
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

        # Look for line like: [    0]  ./libfoo.so.1.debug
        debug_link_regex = re.compile(r"^\s+\[.*\]\s+(\S+)\s*$")

        for line in lines:
            m = debug_link_regex.match(line)
            if m:
                return m.group(1)

        return None


# Global parser instance (initialized by config system)
_parser: Optional[BinToolsParser] = None


def init_parser(config):
    """Initialize global parser instance."""
    global _parser
    _parser = BinToolsParser(config)


def get_parser() -> BinToolsParser:
    """Get global parser instance (must be initialized first)."""
    if _parser is None:
        raise RuntimeError(
            "Parser not initialized. Call init_parser(config) first."
        )
    return _parser
