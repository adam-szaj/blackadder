"""
Process database access layer for runtime analysis.

Provides ProcessDatabase class for managing process snapshots, memory mappings,
and backtrace decoding with parallel processing and caching.
"""

import asyncio
import re
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from blackadder.models import (
    ProcessSnapshot,
    MemoryMapping,
    ProcessBinary,
    ResolvedFrame,
    Binary,
)

from .base import AsyncDatabaseManager


class ProcessDatabase:
    """
    Database access layer for process snapshots and analysis.

    Handles /proc/maps loading, address-to-binary resolution, and parallel
    backtrace decoding with resource limiting and symbol caching.
    """

    def __init__(self, manager: AsyncDatabaseManager, config):
        """
        Initialize ProcessDatabase.

        Args:
            manager: AsyncDatabaseManager instance
            config: BlackadderConfig with concurrency settings
        """
        self.manager = manager
        self.config = config

        # Subprocess limiting semaphore - prevent resource exhaustion
        # Default: 32 concurrent processes, but respects config override
        self.subprocess_sem = asyncio.Semaphore(config.max_subprocess_workers)

        # Symbol resolution cache: {(binary_path, offset): "symbol_name"}
        # Avoids repeated subprocess calls for same symbol
        self.symbol_cache: dict[tuple[str, int], str] = {}

    async def load_maps(self, pid: Optional[int], maps_text: str) -> ProcessSnapshot:
        """
        Parse /proc/PID/maps and create ProcessSnapshot with MemoryMappings.

        CPU-bound parsing is offloaded to thread pool to avoid blocking event loop.

        Args:
            pid: Process ID (can be None for offline analysis)
            maps_text: Content of /proc/PID/maps or similar format

        Returns:
            ProcessSnapshot with all MemoryMapping objects created
        """
        async with self.manager.get_session() as session:
            # Create process snapshot
            process = ProcessSnapshot(
                pid=pid,
                description=f"Process {pid}" if pid else "Offline analysis",
            )

            # Parse maps lines in thread pool (CPU-bound regex)
            lines = maps_text.strip().split("\n")
            parsed_maps = await asyncio.to_thread(self._parse_maps_lines, lines)

            # Create MemoryMapping objects
            for map_data in parsed_maps:
                mapping = MemoryMapping(**map_data)
                process.mappings.append(mapping)

            session.add(process)
            await session.commit()
            await session.refresh(process)

        return process

    async def address_to_binary(
        self, pid: int, addr: int
    ) -> Optional[tuple[str, int]]:
        """
        Resolve an address to its binary path and offset.

        Uses database query to find which MemoryMapping contains the address.

        Args:
            pid: Process ID
            addr: Virtual address to resolve

        Returns:
            Tuple of (binary_path, offset) or None if address not found
        """
        async with self.manager.get_session() as session:
            statement = select(MemoryMapping).where(
                (MemoryMapping.process_id == pid)
                & (MemoryMapping.start_addr <= addr)
                & (MemoryMapping.end_addr > addr)
            )
            result = await session.exec(statement)
            mapping = result.first()

            if mapping:
                offset = addr - mapping.start_addr + mapping.offset
                return mapping.pathname, offset

        return None

    async def decode_backtrace(
        self, pid: int, addresses: list[int]
    ) -> list[ResolvedFrame]:
        """
        Decode backtrace addresses to symbols in parallel.

        This is the main MVP feature: takes raw addresses and produces
        resolved frames with function names and optionally line numbers.

        Parallelization:
        - Concurrent frame resolution via asyncio.gather()
        - Subprocess limiting via semaphore (prevent resource exhaustion)
        - Symbol caching (avoid duplicate subprocess calls)
        - One failure doesn't cancel others (return_exceptions=True)

        Args:
            pid: Process ID
            addresses: List of instruction pointers to resolve

        Returns:
            List of ResolvedFrame objects sorted by frame number
        """
        # Create concurrent tasks for each frame
        # Each task is limited by subprocess_sem and uses symbol cache
        tasks = [
            self._resolve_frame(pid, frame_num, addr)
            for frame_num, addr in enumerate(addresses)
        ]

        # Gather with return_exceptions so one failure doesn't cancel all
        frames = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and return valid frames
        valid_frames = [f for f in frames if isinstance(f, ResolvedFrame)]

        # Sort by frame number for output
        valid_frames.sort(key=lambda f: f.frame_num)

        return valid_frames

    async def _resolve_frame(
        self, pid: int, frame_num: int, addr: int
    ) -> ResolvedFrame:
        """
        Resolve a single backtrace frame (called in parallel).

        Args:
            pid: Process ID
            frame_num: Frame number in backtrace
            addr: Instruction pointer address

        Returns:
            ResolvedFrame with resolved symbol or "???" if not found
        """
        # Find which binary this address belongs to
        binary_info = await self.address_to_binary(pid, addr)

        if not binary_info:
            return ResolvedFrame(
                address=addr,
                frame_num=frame_num,
                symbol="???",
            )

        binary_path, offset = binary_info

        # Resolve symbol (with caching and semaphore limiting)
        symbol = await self._get_cached_symbol(binary_path, offset)

        return ResolvedFrame(
            address=addr,
            frame_num=frame_num,
            symbol=symbol,
        )

    async def _get_cached_symbol(self, binary_path: str, offset: int) -> str:
        """
        Get symbol for binary:offset pair with caching.

        Implements LRU-like caching to avoid repeated subprocess calls.
        Uses subprocess_sem to limit concurrent addr2line/objdump calls.

        Args:
            binary_path: Path to binary
            offset: Offset within binary

        Returns:
            Symbol name or "???" if not found
        """
        cache_key = (binary_path, offset)

        # Check cache first (fast path)
        if cache_key in self.symbol_cache:
            return self.symbol_cache[cache_key]

        # Resolve via subprocess (with semaphore limit)
        # Import here to avoid circular import
        from blackadder.binutils import resolve_symbol

        async with self.subprocess_sem:
            symbol = await resolve_symbol(binary_path, offset, self.config)

        # Cache result with size limit
        if len(self.symbol_cache) > self.config.max_symbol_cache_size:
            # Simple FIFO eviction (could use OrderedDict for true LRU)
            self.symbol_cache.pop(next(iter(self.symbol_cache)))

        self.symbol_cache[cache_key] = symbol
        return symbol

    async def load_core_dump(self, core_path: str) -> ProcessSnapshot:
        """
        Load process state from ELF core dump file (Phase 2.2).

        Parallel to load_maps():
        1. Parse core dump via CoreDumpParser
        2. Create ProcessSnapshot (pid from core, or None)
        3. Create MemoryMapping objects for each segment
        4. Store in database

        Args:
            core_path: Path to ELF core dump file

        Returns:
            ProcessSnapshot with memory mappings from core dump
        """
        from blackadder.binutils.coredump import CoreDumpParser

        # Parse the core dump
        parser = CoreDumpParser(self.config)
        core_data = await parser.parse_core_dump(core_path)

        if not core_data:
            raise ValueError(f"Failed to parse core dump: {core_path}")

        # Create process snapshot
        async with self.manager.get_session() as session:
            process = ProcessSnapshot(
                pid=core_data.get("pid"),
                description=f"Core dump from {core_path}",
                source_type="core_dump",
                source_path=core_path,
            )

            # Create memory mappings from core dump segments
            for map_data in core_data["mappings"]:
                mapping = MemoryMapping(**map_data)
                process.mappings.append(mapping)

            session.add(process)
            await session.commit()
            await session.refresh(process)

        return process

    async def identify_process_binaries_fuzzy(
        self,
        process_id: int,
        rootfs_session: AsyncSession,
        match_threshold: float = 0.7,
    ) -> None:
        """
        Identify binaries in process using fuzzy matching (Phase 2).

        For each MemoryMapping in the process:
        1. Try exact match first (MD5)
        2. If no match, compute fingerprints
        3. Find best match in rootfs via BinaryMatcher
        4. Update ProcessBinary with match_score and match_method

        Sets: match_method = "exact" or "hash", match_score = 0.0-1.0

        Args:
            process_id: ProcessSnapshot ID
            rootfs_session: AsyncSession for rootfs database
            match_threshold: Min score to accept fuzzy match
        """
        from blackadder.binutils.hasher import FunctionHasher
        from blackadder.binutils.matcher import BinaryMatcher

        async with self.manager.get_session() as session:
            # Load all memory mappings for this process
            statement = select(MemoryMapping).where(
                MemoryMapping.process_id == process_id
            )
            result = await session.exec(statement)
            mappings = result.all()

            for mapping in mappings:
                # Skip non-file mappings
                if not mapping.pathname or mapping.pathname.startswith("["):
                    continue

                # Try to find ProcessBinary record
                pb_statement = select(ProcessBinary).where(
                    ProcessBinary.mapping_id == mapping.id
                )
                pb_result = await session.exec(pb_statement)
                process_binary = pb_result.first()

                if not process_binary:
                    continue

                # If already has exact match, skip fuzzy matching
                if process_binary.binary_id is not None:
                    # Set match method for exact match
                    process_binary.match_method = "exact"
                    process_binary.match_score = 1.0
                    continue

                # Compute fingerprints for process binary
                hasher = FunctionHasher(self.config)
                target_fps = await hasher.compute_fingerprints(mapping.pathname)

                if not target_fps:
                    # Can't compute fingerprints, skip
                    process_binary.match_method = "symbol"
                    continue

                # Find matching binaries by name in rootfs
                name_statement = select(Binary).where(
                    Binary.name == mapping.pathname.split("/")[-1]
                )
                name_result = await rootfs_session.exec(name_statement)
                candidates = name_result.all()

                if not candidates:
                    # No candidates found
                    process_binary.match_method = "symbol"
                    continue

                # Score matches
                matches = await BinaryMatcher.find_matches(
                    target_fps, candidates, rootfs_session, match_threshold
                )

                if matches:
                    # Use best match
                    best_binary, score, method = matches[0]
                    process_binary.binary_id = best_binary.id
                    process_binary.match_score = score
                    process_binary.match_method = method
                else:
                    # No fuzzy match either
                    process_binary.match_method = "symbol"

            # Commit updates
            await session.commit()

    @staticmethod
    def _parse_maps_lines(lines: list[str]) -> list[dict]:
        """
        Parse /proc/maps format lines (CPU-bound, runs in thread pool).

        Example line:
            7f1234567000-7f1234789000 r-xp 00000000 08:01 12345678  /lib/libc.so.6

        Args:
            lines: Lines from /proc/PID/maps

        Returns:
            List of dicts with keys: start_addr, end_addr, perms, offset, pathname
        """
        # Regex pattern for /proc/maps format
        maps_pattern = re.compile(
            r"^([0-9a-f]+)-([0-9a-f]+)\s+"
            r"([r\-][w\-][x\-][ps])\s+"
            r"([0-9a-f]+)\s+"
            r"[0-9a-f]+:[0-9a-f]+\s+"
            r"(\d+)\s+"
            r"(.*)$"
        )

        parsed = []
        for line in lines:
            line = line.strip()
            if not line:
                continue

            m = maps_pattern.match(line)
            if m:
                start_addr = int(m.group(1), 16)
                end_addr = int(m.group(2), 16)
                perms = m.group(3)
                offset = int(m.group(4), 16)
                pathname = m.group(6).strip() or "[anonymous]"

                parsed.append(
                    {
                        "start_addr": start_addr,
                        "end_addr": end_addr,
                        "perms": perms,
                        "offset": offset,
                        "pathname": pathname,
                    }
                )

        return parsed
