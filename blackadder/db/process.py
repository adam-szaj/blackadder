"""
Process database access layer for runtime analysis.

Provides ProcessDatabase class for managing process snapshots, memory mappings,
and backtrace decoding with parallel processing and caching.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import asyncio
import logging
import re
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlmodel import select

from blackadder.exceptions import (
    ParseError,
    ValidationError,
)
from blackadder.models import (
    Binary,
    MemoryMapping,
    ProcessBinary,
    ProcessSnapshot,
    ResolvedFrame,
    SymbolCache,
)

from .base import AsyncDatabaseManager

logger = logging.getLogger("blackadder.db.process")


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

    async def load_maps(
        self,
        pid: int | None,
        maps_text: str,
        rootfs: str = "/",
        debugfs: str | None = None,
        tag: str | None = None,
    ) -> ProcessSnapshot:
        """
        Parse /proc/PID/maps and create ProcessSnapshot with MemoryMappings.

        CPU-bound parsing is offloaded to thread pool to avoid blocking event loop.

        Args:
            pid: Process ID (can be None for offline analysis)
            maps_text: Content of /proc/PID/maps or similar format

        Returns:
            ProcessSnapshot with all MemoryMapping objects created

        Raises:
            ValidationError: If inputs are invalid
            ParseError: If maps parsing fails
        """
        # Input validation
        if pid is not None and pid < 0:
            logger.warning("negative_pid", extra={"pid": pid})
            raise ValidationError("pid must be non-negative")

        if not maps_text or not maps_text.strip():
            logger.warning("empty_maps_text")
            raise ValidationError("maps_text cannot be empty")

        logger.debug(
            "loading_maps",
            extra={
                "pid": pid,
                "text_size_bytes": len(maps_text),
            },
        )

        # Create process snapshot
        async with self.manager.get_session() as session:
            process = ProcessSnapshot(
                pid=pid,
                description=f"Process {pid}" if pid else "Offline analysis",
                tag=tag,
            )

            # Parse maps lines in thread pool (CPU-bound regex)
            lines = maps_text.strip().split("\n")
            parsed_maps = await asyncio.to_thread(self._parse_maps_lines, lines)

            if not parsed_maps:
                logger.warning(
                    "no_valid_maps_parsed",
                    extra={
                        "total_lines": len(lines),
                    },
                )
                raise ParseError("Failed to parse any memory mappings")

            # Create MemoryMapping objects (continue on error)
            skipped_count = 0
            for map_data in parsed_maps:
                try:
                    mapping = MemoryMapping(**map_data)
                    process.mappings.append(mapping)
                except Exception as e:
                    logger.debug(
                        "failed_to_create_mapping",
                        extra={
                            "error": str(e),
                        },
                    )
                    skipped_count += 1

            mapping_count = len(process.mappings)
            if mapping_count > self.config.max_memory_regions:
                logger.error(
                    "too_many_regions",
                    extra={
                        "region_count": mapping_count,
                        "max_allowed": self.config.max_memory_regions,
                    },
                )
                raise ValidationError(
                    f"Process has too many regions: {mapping_count} "
                    f"(max {self.config.max_memory_regions})"
                )

            session.add(process)
            await session.commit()
            process_id = process.id

            logger.info(
                "maps_loaded",
                extra={
                    "pid": pid,
                    "mapping_count": mapping_count,
                    "skipped_count": skipped_count,
                    "process_id": process_id,
                },
            )

        # Re-fetch with eagerly loaded mappings so callers can access them
        # outside the session context without hitting DetachedInstanceError.
        async with self.manager.get_session() as session:
            statement = (
                select(ProcessSnapshot)
                .where(ProcessSnapshot.id == process_id)
                .options(selectinload(ProcessSnapshot.mappings))
            )
            result = await session.execute(statement)  # type: ignore
            process = result.scalars().first()

        await self._link_binaries(process, rootfs=rootfs, debugfs=debugfs)
        return process

    async def address_to_binary(
        self, pid: int, addr: int
    ) -> tuple[str, int, int | None] | None:
        """
        Resolve an address to its binary path, offset within binary, and binary_id.

        Uses database query to find which MemoryMapping contains the address,
        then looks up the associated binary_id from ProcessBinary.

        Args:
            pid: Process ID (ProcessSnapshot.id)
            addr: Virtual address to resolve

        Returns:
            Tuple of (binary_path, offset, binary_id) or None if address not found.
            binary_id may be None if binary is not in the database.
        """
        logger.debug(
            "resolving_address",
            extra={
                "pid": pid,
                "address": hex(addr),
            },
        )

        async with self.manager.get_session() as session:
            statement = select(MemoryMapping).where(
                (MemoryMapping.process_id == pid)
                & (MemoryMapping.start_addr <= addr)
                & (MemoryMapping.end_addr > addr)
            )
            result = await session.execute(statement)  # type: ignore
            mapping = result.first()

            if not mapping:
                logger.debug(
                    "address_not_found_in_mappings",
                    extra={"pid": pid, "address": hex(addr)},
                )
                return None

            offset = addr - mapping.start_addr + mapping.offset

            # Look up binary_id from ProcessBinary for this mapping
            pb_stmt = select(ProcessBinary).where(
                ProcessBinary.mapping_id == mapping.id
            )
            pb_result = await session.execute(pb_stmt)  # type: ignore
            pb = pb_result.scalars().first()
            binary_id = pb.binary_id if pb else None

            logger.debug(
                "address_resolved",
                extra={
                    "pid": pid,
                    "address": hex(addr),
                    "binary": mapping.pathname,
                    "offset": hex(offset),
                    "binary_id": binary_id,
                },
            )
            return mapping.pathname, offset, binary_id

    async def decode_backtrace(self, pid: int, addresses: list[int]) -> list[ResolvedFrame]:
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

        Raises:
            ValidationError: If inputs are invalid
        """
        # Input validation
        if pid <= 0:
            logger.warning("invalid_pid", extra={"pid": pid})
            raise ValidationError("pid must be positive")

        if not addresses:
            logger.debug("empty_address_list")
            return []

        if len(addresses) > self.config.max_backtraces_cached:
            logger.warning(
                "too_many_addresses",
                extra={
                    "address_count": len(addresses),
                    "max_allowed": self.config.max_backtraces_cached,
                },
            )
            raise ValidationError(
                f"Too many frames to decode: {len(addresses)} "
                f"(max {self.config.max_backtraces_cached})"
            )

        logger.debug(
            "decoding_backtrace",
            extra={
                "pid": pid,
                "frame_count": len(addresses),
            },
        )

        # Create concurrent tasks for each frame
        # Each task is limited by subprocess_sem and uses symbol cache
        tasks = [
            self._resolve_frame(pid, frame_num, addr) for frame_num, addr in enumerate(addresses)
        ]

        # Gather with return_exceptions so one failure doesn't cancel all
        frames = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and return valid frames
        valid_frames = []
        failed_frames = 0

        for frame_result in frames:
            if isinstance(frame_result, ResolvedFrame):
                valid_frames.append(frame_result)
            else:
                logger.debug(
                    "frame_resolution_failed",
                    extra={
                        "error": str(frame_result),
                    },
                )
                failed_frames += 1

        # Sort by frame number for output
        valid_frames.sort(key=lambda f: f.frame_num)

        logger.info(
            "backtrace_decoded",
            extra={
                "pid": pid,
                "valid_frame_count": len(valid_frames),
                "failed_frame_count": failed_frames,
            },
        )
        return valid_frames

    async def _resolve_frame(self, pid: int, frame_num: int, addr: int) -> ResolvedFrame:
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

        binary_path, offset, binary_id = binary_info

        # Resolve symbol (with caching and semaphore limiting)
        symbol = await self._get_cached_symbol(binary_path, offset, binary_id)

        return ResolvedFrame(
            address=addr,
            frame_num=frame_num,
            symbol=symbol,
        )

    async def _get_cached_symbol(
        self, binary_path: str, offset: int, binary_id: int | None = None
    ) -> str:
        """
        Get symbol for binary:offset pair with three-tier caching.

        Tier 1 — in-memory dict (fastest, lost on restart)
        Tier 2 — SQLite SymbolCache (persistent, keyed by binary_id+offset)
        Tier 3 — addr2line/objdump subprocess (slowest, result persisted to SQLite)

        SQLite tier is only used when binary_id is known (binary is in DB).
        Falls back gracefully to in-memory + subprocess when binary_id is None.

        Args:
            binary_path: Path to binary file
            offset:      File offset within binary
            binary_id:   DB id of binary (None if not in DB)

        Returns:
            Symbol name or "???" if resolution fails
        """
        cache_key = (binary_path, offset)

        # Tier 1: in-memory cache (fastest)
        if cache_key in self.symbol_cache:
            logger.debug("symbol_cache_hit_memory", extra={"binary_path": binary_path, "offset": offset})
            return self.symbol_cache[cache_key]

        # Tier 2: SQLite persistent cache
        if binary_id is not None:
            async with self.manager.get_session() as session:
                stmt = select(SymbolCache).where(
                    (SymbolCache.binary_id == binary_id)
                    & (SymbolCache.offset == offset)
                )
                result = await session.execute(stmt)  # type: ignore
                cached = result.scalars().first()
                if cached is not None:
                    symbol = cached.symbol or "???"
                    logger.debug("symbol_cache_hit_db", extra={"binary_path": binary_path, "offset": offset})
                    self.symbol_cache[cache_key] = symbol
                    return symbol

        # Tier 3: subprocess resolution
        from blackadder.binutils import resolve_symbol

        try:
            async with self.subprocess_sem:
                symbol = await resolve_symbol(binary_path, offset, self.config)
        except Exception as e:
            logger.warning(
                "symbol_resolution_failed",
                extra={"binary_path": binary_path, "offset": offset, "error": str(e)},
            )
            return "???"

        # Persist to SQLite (fire-and-forget, don't block caller)
        if binary_id is not None:
            asyncio.ensure_future(
                self._persist_symbol_cache(binary_id, offset, symbol)
            )

        # Store in in-memory cache with FIFO eviction
        if len(self.symbol_cache) > self.config.max_symbol_cache_size:
            self.symbol_cache.pop(next(iter(self.symbol_cache)))
            logger.debug("symbol_cache_evicted", extra={"cache_size": len(self.symbol_cache)})

        self.symbol_cache[cache_key] = symbol
        logger.debug("symbol_resolved", extra={"binary_path": binary_path, "offset": offset, "symbol": symbol})
        return symbol

    async def _persist_symbol_cache(self, binary_id: int, offset: int, symbol: str) -> None:
        """Persist a resolved symbol to the SQLite SymbolCache table (INSERT OR IGNORE)."""
        try:
            async with self.manager.get_session() as session:
                # Use INSERT OR IGNORE semantics via merge/get pattern
                stmt = select(SymbolCache).where(
                    (SymbolCache.binary_id == binary_id)
                    & (SymbolCache.offset == offset)
                )
                result = await session.execute(stmt)  # type: ignore
                existing = result.scalars().first()
                if existing is None:
                    entry = SymbolCache(binary_id=binary_id, offset=offset, symbol=symbol)
                    session.add(entry)
                    await session.commit()
        except Exception as e:
            logger.debug("symbol_cache_persist_failed", extra={"binary_id": binary_id, "offset": offset, "error": str(e)})

    async def analyze_memory_layout(
        self,
        process_id: int,
        register_state: dict | None = None,
    ) -> dict:
        """
        Analyze and classify all memory regions (Phase 2.3).

        For each MemoryMapping:
        1. Classify region type (heap, stack, vdso, etc.)
        2. Detect anomalies
        3. Check for corruption markers

        Args:
            process_id: ProcessSnapshot ID
            register_state: Optional CPU register state (for stack detection)

        Returns:
            {
                'regions': {...},
                'anomalies': [...],
                'corruption_risk': float,
            }
        """
        from blackadder.memory_analyzer import MemoryAnalyzer

        logger.debug(
            "analyzing_memory_layout",
            extra={
                "process_id": process_id,
            },
        )

        async with self.manager.get_session() as session:
            statement = select(MemoryMapping).where(MemoryMapping.process_id == process_id)
            result = await session.execute(statement)  # type: ignore
            mappings = result.scalars().all()

            analyzer = MemoryAnalyzer(self.config)
            all_anomalies = []
            corruption_count = 0
            skipped_count = 0

            for mapping in mappings:
                try:
                    # Analyze region
                    analysis_data = analyzer.analyze_memory_region(
                        mapping.pathname,
                        mapping.start_addr,
                        mapping.end_addr,
                        mapping.perms,
                        mapping.offset,
                        register_state,
                    )

                    if analysis_data.get("anomalies"):
                        all_anomalies.extend(analysis_data["anomalies"])

                    if analysis_data.get("likely_corrupted"):
                        corruption_count += 1
                except Exception as e:
                    logger.debug(
                        "region_analysis_failed",
                        extra={
                            "region": mapping.pathname,
                            "error": str(e),
                        },
                    )
                    skipped_count += 1

            # Calculate corruption risk (0.0-1.0)
            corruption_risk = (
                min(corruption_count / max(len(mappings), 1), 1.0) if mappings else 0.0
            )

            logger.info(
                "memory_layout_analyzed",
                extra={
                    "process_id": process_id,
                    "regions_analyzed": len(mappings),
                    "anomaly_count": len(all_anomalies),
                    "corruption_count": corruption_count,
                    "corruption_risk": corruption_risk,
                    "skipped_count": skipped_count,
                },
            )

            return {
                "regions_analyzed": len(mappings),
                "anomalies": all_anomalies,
                "corruption_count": corruption_count,
                "corruption_risk": corruption_risk,
            }

    async def load_core_dump(
        self,
        core_path: str,
        rootfs: str = "/",
        debugfs: str | None = None,
        tag: str | None = None,
    ) -> ProcessSnapshot:
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

        Raises:
            ValidationError: If core_path is invalid
            ParseError: If core dump parsing fails
        """
        # Input validation
        if not core_path or not core_path.strip():
            logger.warning("empty_core_path")
            raise ValidationError("core_path cannot be empty")

        logger.debug("loading_core_dump", extra={"core_path": core_path})

        from blackadder.binutils.coredump import CoreDumpParser

        # Parse the core dump (CoreDumpParser handles errors)
        parser = CoreDumpParser(self.config)
        core_result = await parser.parse_core_dump(core_path)

        if core_result.status != "success":
            logger.warning(
                "core_dump_parse_failed",
                extra={
                    "core_path": core_path,
                    "status": core_result.status,
                    "reason": core_result.reason,
                },
            )
            raise ParseError(f"Failed to parse core dump: {core_result.reason}")

        if not core_result.mappings:
            logger.warning(
                "no_mappings_in_core_dump",
                extra={
                    "core_path": core_path,
                },
            )
            raise ParseError("No memory mappings found in core dump")

        # Create process snapshot
        async with self.manager.get_session() as session:
            process = ProcessSnapshot(
                pid=core_result.pid,
                description=f"Core dump from {core_path}",
                source_type="core_dump",
                source_path=core_path,
                tag=tag,
            )

            # Create memory mappings from core dump segments (continue on error)
            skipped_count = 0
            for map_data in core_result.mappings:
                try:
                    mapping = MemoryMapping(**map_data)
                    process.mappings.append(mapping)
                except Exception as e:
                    logger.debug(
                        "failed_to_create_mapping_from_core_dump",
                        extra={
                            "error": str(e),
                        },
                    )
                    skipped_count += 1

            if len(process.mappings) > self.config.max_memory_regions:
                logger.error(
                    "too_many_regions_in_core_dump",
                    extra={
                        "region_count": len(process.mappings),
                        "max_allowed": self.config.max_memory_regions,
                    },
                )
                raise ValidationError(f"Core dump has too many regions: {len(process.mappings)}")

            session.add(process)
            await session.commit()
            process_id = process.id

            logger.info(
                "core_dump_loaded",
                extra={
                    "core_path": core_path,
                    "mapping_count": len(process.mappings),
                    "skipped_count": skipped_count,
                    "pid": process.pid,
                },
            )

        # Re-fetch with eagerly loaded mappings
        async with self.manager.get_session() as session:
            statement = (
                select(ProcessSnapshot)
                .where(ProcessSnapshot.id == process_id)
                .options(selectinload(ProcessSnapshot.mappings))
            )
            result = await session.execute(statement)  # type: ignore
            process = result.scalars().first()

        await self._link_binaries(process, rootfs=rootfs, debugfs=debugfs)
        return process

    async def _link_binaries(
        self,
        process: ProcessSnapshot,
        rootfs: str = "/",
        debugfs: str | None = None,
    ) -> None:
        """
        Load binary metadata for each mapped file and create ProcessBinary links.

        For each MemoryMapping with a real binary path:
        1. Load binary into the unified DB via RootfsDatabase.load_binary()
           (skipped if binary not present on current filesystem)
        2. Create ProcessBinary linking snapshot → binary → mapping

        Each unique binary path is loaded only once even if mapped multiple times
        (e.g., libc appears 4+ times with different permissions).
        """
        from blackadder.db.rootfs import RootfsDatabase

        rootfs_db = RootfsDatabase(self.manager, self.config)

        # Deduplicate: load each unique binary path once
        binary_cache: dict[str, Binary | None] = {}
        for mapping in process.mappings:
            pathname = mapping.pathname
            if not pathname or pathname.startswith("["):
                continue
            if pathname in binary_cache:
                continue
            if not Path(pathname).is_file():
                logger.debug("binary_not_found_on_fs", extra={"path": pathname})
                binary_cache[pathname] = None
                continue
            try:
                binary, is_new, debug_file = await rootfs_db.load_binary(pathname, rootfs=rootfs, debugfs=debugfs)
                binary_cache[pathname] = binary
                logger.debug(
                    "binary_linked",
                    extra={"path": pathname, "binary_id": binary.id, "is_new": is_new, "debug_file": debug_file},
                )
            except Exception as e:
                logger.warning("binary_load_failed", extra={"path": pathname, "error": str(e)})
                binary_cache[pathname] = None

        # Create ProcessBinary records (one per mapping, skipping already-linked)
        async with self.manager.get_session() as session:
            for mapping in process.mappings:
                pathname = mapping.pathname
                if not pathname or pathname.startswith("["):
                    continue

                # Skip if already linked
                existing = await session.execute(
                    select(ProcessBinary).where(ProcessBinary.mapping_id == mapping.id)
                )
                if existing.scalars().first():
                    continue

                binary = binary_cache.get(pathname)
                pb = ProcessBinary(
                    process_id=process.id,
                    binary_id=binary.id if binary else None,
                    mapping_id=mapping.id,
                    binary_load_addr=mapping.start_addr,
                    match_score=1.0 if binary else None,
                    match_method="exact" if binary else None,
                )
                session.add(pb)

            await session.commit()

        logger.info(
            "binaries_linked",
            extra={
                "process_id": process.id,
                "total_mappings": len(process.mappings),
                "unique_binaries": len(binary_cache),
                "loaded": sum(1 for b in binary_cache.values() if b is not None),
                "not_found": sum(1 for b in binary_cache.values() if b is None),
            },
        )

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

        logger.debug(
            "identifying_process_binaries_fuzzy",
            extra={
                "process_id": process_id,
                "match_threshold": match_threshold,
            },
        )

        async with self.manager.get_session() as session:
            # Load all memory mappings for this process
            statement = select(MemoryMapping).where(MemoryMapping.process_id == process_id)
            result = await session.execute(statement)  # type: ignore
            mappings = result.scalars().all()

            exact_matches = 0
            fuzzy_matches = 0
            symbol_matches = 0
            skipped_count = 0

            for mapping in mappings:
                # Skip non-file mappings
                if not mapping.pathname or mapping.pathname.startswith("["):
                    continue

                try:
                    # Try to find ProcessBinary record
                    pb_statement = select(ProcessBinary).where(
                        ProcessBinary.mapping_id == mapping.id
                    )
                    pb_result = await session.exec(pb_statement)  # type: ignore
                    process_binary = pb_result.first()

                    if not process_binary:
                        continue

                    # If already has exact match, skip fuzzy matching
                    if process_binary.binary_id is not None:
                        # Set match method for exact match
                        process_binary.match_method = "exact"
                        process_binary.match_score = 1.0
                        exact_matches += 1
                        continue

                    # Compute fingerprints for process binary
                    hasher = FunctionHasher(self.config)
                    fp_result = await hasher.compute_fingerprints(mapping.pathname)

                    if fp_result.status != "success":
                        # Can't compute fingerprints, fall back to symbol matching
                        process_binary.match_method = "symbol"
                        symbol_matches += 1
                        continue

                    # Find matching binaries by name in rootfs
                    binary_name = mapping.pathname.split("/")[-1]
                    name_statement = select(Binary).where(Binary.name == binary_name)
                    name_result = await rootfs_session.execute(name_statement)  # type: ignore
                    candidates = name_result.scalars().all()

                    if not candidates:
                        # No candidates found
                        logger.debug(
                            "no_fuzzy_match_candidates",
                            extra={
                                "binary_name": binary_name,
                                "pathname": mapping.pathname,
                            },
                        )
                        process_binary.match_method = "symbol"
                        symbol_matches += 1
                        continue

                    # Score matches
                    matches = await BinaryMatcher.find_matches(
                        fp_result.fingerprints, candidates, rootfs_session, match_threshold
                    )

                    if matches:
                        # Use best match
                        best_binary, score, method = matches[0]
                        process_binary.binary_id = best_binary.id
                        process_binary.match_score = score
                        process_binary.match_method = method
                        fuzzy_matches += 1
                        logger.debug(
                            "fuzzy_match_found",
                            extra={
                                "pathname": mapping.pathname,
                                "binary_id": best_binary.id,
                                "score": score,
                            },
                        )
                    else:
                        # No fuzzy match either
                        process_binary.match_method = "symbol"
                        symbol_matches += 1

                except Exception as e:
                    logger.debug(
                        "binary_identification_failed",
                        extra={
                            "pathname": mapping.pathname,
                            "error": str(e),
                        },
                    )
                    skipped_count += 1

            # Commit updates
            await session.commit()

            logger.info(
                "binaries_identified",
                extra={
                    "process_id": process_id,
                    "exact_matches": exact_matches,
                    "fuzzy_matches": fuzzy_matches,
                    "symbol_matches": symbol_matches,
                    "skipped_count": skipped_count,
                    "total_mappings": len(mappings),
                },
            )

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
            r"([0-9a-f]+:[0-9a-f]+)\s+"
            r"(\d+)\s+"
            r"(.*)$"
        )

        parsed = []
        failed_lines = 0

        def to_signed_64bit(val: int) -> int:
            """Convert unsigned 64-bit value to signed (two's complement)."""
            if val >= 0x8000000000000000:
                return val - 0x10000000000000000
            return val

        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            m = maps_pattern.match(line)
            if not m:
                logger.debug(
                    "maps_line_format_mismatch",
                    extra={
                        "line_idx": idx,
                    },
                )
                failed_lines += 1
                continue

            try:
                start_addr = to_signed_64bit(int(m.group(1), 16))
                end_addr = to_signed_64bit(int(m.group(2), 16))
                perms = m.group(3)
                offset = int(m.group(4), 16)
                dev = m.group(5)
                inode = int(m.group(6))
                pathname = m.group(7).strip() or "[anonymous]"

                # Validate parsed values (from file)
                if start_addr >= end_addr:
                    logger.warning(
                        "invalid_address_range_in_maps",
                        extra={
                            "line_idx": idx,
                            "start_addr": start_addr,
                            "end_addr": end_addr,
                        },
                    )
                    failed_lines += 1
                    continue

                parsed.append(
                    {
                        "start_addr": start_addr,
                        "end_addr": end_addr,
                        "perms": perms,
                        "offset": offset,
                        "dev": dev,
                        "inode": inode,
                        "pathname": pathname,
                    }
                )
            except (ValueError, IndexError) as e:
                logger.warning(
                    "maps_line_parse_error",
                    extra={
                        "line_idx": idx,
                        "error": str(e),
                    },
                )
                failed_lines += 1

        logger.debug(
            "maps_lines_parsed",
            extra={
                "parsed_count": len(parsed),
                "total_lines": len(lines),
                "failed_lines": failed_lines,
            },
        )
        return parsed
