"""
Process database access layer for runtime analysis.

Provides ProcessDatabase class for managing process snapshots, memory mappings,
and backtrace decoding with parallel processing and caching.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import asyncio
import logging
import re
from collections import OrderedDict
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlmodel import select

from baldrick.exceptions import (
    ParseError,
    ValidationError,
)
from baldrick.models import (
    BacktraceEntry,
    Binary,
    MemoryMapping,
    ProcessBinary,
    ProcessRegisterState,
    ProcessSnapshot,
    ResolvedFrame,
    SymbolCache,
    Thread,
)

from .base import AsyncDatabaseManager

logger = logging.getLogger("baldrick.db.process")


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
            config: BaldrickConfig with concurrency settings
        """
        self.manager = manager
        self.config = config

        # Subprocess limiting semaphore - prevent resource exhaustion
        # Default: 32 concurrent processes, but respects config override
        self.subprocess_sem = asyncio.Semaphore(config.max_subprocess_workers)

        # Symbol resolution cache: key -> (symbol, source file, source line)
        # Avoids repeated subprocess calls for same symbol
        self.symbol_cache: OrderedDict[tuple[str, int], tuple[str, str | None, int | None]] = (
            OrderedDict()
        )

    def _cache_symbol(
        self,
        key: tuple[str, int],
        value: tuple[str, str | None, int | None],
    ) -> None:
        """Add one complete symbol result and enforce the configured LRU bound."""
        if self.config.max_symbol_cache_size <= 0:
            return
        self.symbol_cache[key] = value
        self.symbol_cache.move_to_end(key)
        while len(self.symbol_cache) > self.config.max_symbol_cache_size:
            self.symbol_cache.popitem(last=False)
            logger.debug(
                "symbol_cache_evicted",
                extra={"cache_size": len(self.symbol_cache)},
            )

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

            # Parsing the bounded /proc maps input is cheap enough to do inline.
            lines = maps_text.strip().split("\n")
            parsed_maps = self._parse_maps_lines(lines)

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
            if process_id is None:
                raise RuntimeError("Process snapshot was not assigned an ID")

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
                .options(selectinload(ProcessSnapshot.mappings))  # type: ignore[arg-type]
            )
            result = await session.execute(statement)  # type: ignore
            loaded_process = result.scalars().first()

        if loaded_process is None:
            raise RuntimeError(f"Process snapshot disappeared: id={process_id}")

        # Load thread info from /proc/PID/task/ if pid is available
        if pid is not None:
            await self._load_threads(process_id, pid, loaded_process.mappings)

        await self._link_binaries(loaded_process, rootfs=rootfs, debugfs=debugfs)
        return loaded_process

    async def _load_threads(
        self,
        process_id: int,
        pid: int,
        mappings: list[MemoryMapping],
    ) -> None:
        """
        Load thread info from /proc/PID/task/ and persist Thread records.

        Reads per-thread: TID, name (comm), wchan, syscall.
        Maps [stack:TID] entries from memory mappings to thread stack ranges.
        Silently skips if /proc/PID/task/ is not accessible (process exited, permission denied).

        Args:
            process_id: ProcessSnapshot.id
            pid:        OS process ID
            mappings:   Already-loaded MemoryMapping list (for stack range lookup)
        """
        task_dir = Path(f"/proc/{pid}/task")
        if not task_dir.exists():
            logger.debug("task_dir_not_found", extra={"pid": pid})
            return

        # Build stack range map from mappings: TID → (start, end)
        # /proc/maps shows "[stack:TID]" for thread stacks on older kernels,
        # and "[stack]" only for main thread on newer kernels.
        stack_ranges: dict[int, tuple[int, int]] = {}
        main_stack: tuple[int, int] | None = None
        for m in mappings:
            if m.pathname.startswith("[stack:"):
                try:
                    tid = int(m.pathname[7:-1])
                    stack_ranges[tid] = (m.start_addr, m.end_addr)
                except ValueError:
                    pass
            elif m.pathname == "[stack]":
                main_stack = (m.start_addr, m.end_addr)

        threads: list[Thread] = []
        try:
            tids = [int(t.name) for t in task_dir.iterdir() if t.name.isdigit()]
        except PermissionError:
            logger.debug("task_dir_permission_denied", extra={"pid": pid})
            return

        for tid in sorted(tids):
            name = wchan = syscall = None
            try:
                comm_path = task_dir / str(tid) / "comm"
                if comm_path.exists():
                    name = comm_path.read_text().strip()
            except OSError:
                pass
            try:
                wchan_path = task_dir / str(tid) / "wchan"
                if wchan_path.exists():
                    wchan = wchan_path.read_text().strip()
            except OSError:
                pass
            try:
                syscall_path = task_dir / str(tid) / "syscall"
                if syscall_path.exists():
                    syscall = syscall_path.read_text().strip()
            except OSError:
                pass

            # Stack range: prefer [stack:TID], fall back to [stack] for main thread
            stack_range = stack_ranges.get(tid) or (main_stack if tid == pid else None)
            stack_start = stack_range[0] if stack_range else None
            stack_end = stack_range[1] if stack_range else None

            threads.append(
                Thread(
                    process_id=process_id,
                    tid=tid,
                    name=name,
                    wchan=wchan,
                    syscall=syscall,
                    stack_start=stack_start,
                    stack_end=stack_end,
                )
            )

        if not threads:
            return

        async with self.manager.get_session() as session:
            for t in threads:
                session.add(t)
            await session.commit()

        logger.info(
            "threads_loaded",
            extra={"pid": pid, "thread_count": len(threads), "process_id": process_id},
        )

    async def address_to_binary(self, pid: int, addr: int) -> tuple[str, int, int | None] | None:
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
        return (await self.addresses_to_binaries(pid, [addr]))[addr]

    async def addresses_to_binaries(
        self, pid: int, addresses: list[int]
    ) -> dict[int, tuple[str, int, int | None] | None]:
        """Resolve several virtual addresses with one database round trip."""
        resolved: dict[int, tuple[str, int, int | None] | None] = {
            address: None for address in addresses
        }
        if not addresses:
            return resolved

        async with self.manager.get_session() as session:
            statement = (
                select(MemoryMapping, ProcessBinary.binary_id)
                .outerjoin(
                    ProcessBinary,
                    ProcessBinary.mapping_id == MemoryMapping.id,  # type: ignore[arg-type]
                )
                .where(MemoryMapping.process_id == pid)
            )
            rows = (await session.execute(statement)).all()

        for address in resolved:
            for mapping, binary_id in rows:
                if mapping.start_addr <= address < mapping.end_addr:
                    offset = address - mapping.start_addr + mapping.offset
                    resolved[address] = mapping.pathname, offset, binary_id
                    break
        return resolved

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
        symbol, source_file, source_line = await self._get_cached_symbol(
            binary_path, offset, binary_id
        )

        return ResolvedFrame(
            address=addr,
            frame_num=frame_num,
            symbol=symbol,
            file=source_file,
            line=source_line,
        )

    async def _get_cached_symbol(
        self, binary_path: str, offset: int, binary_id: int | None = None
    ) -> tuple[str, str | None, int | None]:
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
            (symbol, source_file, source_line) — source fields may be None
        """
        cache_key = (binary_path, offset)

        # Tier 1: in-memory cache (fastest)
        if cache_key in self.symbol_cache:
            logger.debug(
                "symbol_cache_hit_memory", extra={"binary_path": binary_path, "offset": offset}
            )
            self.symbol_cache.move_to_end(cache_key)
            return self.symbol_cache[cache_key]

        # Tier 2: SQLite persistent cache
        if binary_id is not None:
            async with self.manager.get_session() as session:
                stmt = select(SymbolCache).where(
                    (SymbolCache.binary_id == binary_id) & (SymbolCache.offset == offset)
                )
                result = await session.execute(stmt)  # type: ignore
                cached = result.scalars().first()
                if cached is not None:
                    symbol = cached.symbol or "???"
                    logger.debug(
                        "symbol_cache_hit_db", extra={"binary_path": binary_path, "offset": offset}
                    )
                    value = (symbol, cached.source_file, cached.source_line)
                    self._cache_symbol(cache_key, value)
                    return value

        # Tier 3: subprocess resolution
        from baldrick.binutils.resolver import resolve_symbol_full

        try:
            async with self.subprocess_sem:
                symbol, src_file, src_line = await resolve_symbol_full(
                    binary_path, offset, self.config
                )
        except Exception as e:
            logger.warning(
                "symbol_resolution_failed",
                extra={"binary_path": binary_path, "offset": offset, "error": str(e)},
            )
            return "???", None, None

        # Persistence is part of the operation so failures stay observable.
        if binary_id is not None:
            await self._persist_symbol_cache(binary_id, offset, symbol, src_file, src_line)

        self._cache_symbol(cache_key, (symbol, src_file, src_line))
        logger.debug(
            "symbol_resolved",
            extra={"binary_path": binary_path, "offset": offset, "symbol": symbol},
        )
        return symbol, src_file, src_line

    async def _persist_symbol_cache(
        self,
        binary_id: int,
        offset: int,
        symbol: str,
        source_file: str | None = None,
        source_line: int | None = None,
    ) -> None:
        """Persist a resolved symbol to the SQLite SymbolCache table (INSERT OR IGNORE)."""
        async with self.manager.get_session() as session:
            stmt = select(SymbolCache).where(
                (SymbolCache.binary_id == binary_id) & (SymbolCache.offset == offset)
            )
            result = await session.execute(stmt)  # type: ignore
            existing = result.scalars().first()
            if existing is None:
                entry = SymbolCache(
                    binary_id=binary_id,
                    offset=offset,
                    symbol=symbol,
                    source_file=source_file,
                    source_line=source_line,
                )
                session.add(entry)
                await session.commit()

    async def load_gdb_dump(self, process_id: int, gdb_text: str) -> int:
        """
        Parse a GDB text dump and persist threads + backtrace entries into DB.

        Intended to enrich an existing ProcessSnapshot (created via load_maps or
        load_core_dump) with per-thread backtraces and register state from GDB.

        For each GDB thread:
        - Creates or updates a Thread record (matched by TID if already exists)
        - Creates BacktraceEntry records linked to that Thread
        - Stores register state in ProcessRegisterState (one per thread via thread_id)

        Args:
            process_id: ProcessSnapshot.id to attach threads to
            gdb_text:   Raw GDB stdout from 'thread apply all bt full' + 'info registers'

        Returns:
            Number of threads parsed
        """
        from baldrick.binutils.gdb_dump import parse_gdb_dump

        dump = parse_gdb_dump(gdb_text)
        if not dump.threads:
            logger.warning("gdb_dump_no_threads", extra={"process_id": process_id})
            return 0

        async with self.manager.get_session() as session:
            for gdb_thread in dump.threads:
                # Find existing Thread by TID or create new one
                existing_stmt = select(Thread).where(
                    (Thread.process_id == process_id) & (Thread.tid == gdb_thread.tid)
                )
                result = await session.execute(existing_stmt)  # type: ignore
                thread = result.scalars().first()

                if thread is None:
                    thread = Thread(
                        process_id=process_id,
                        tid=gdb_thread.tid,
                        name=gdb_thread.name,
                    )
                    session.add(thread)
                    await session.flush()  # get thread.id
                elif gdb_thread.name and not thread.name:
                    thread.name = gdb_thread.name
                    session.add(thread)
                    await session.flush()

                # BacktraceEntry records for this thread
                for frame in gdb_thread.frames:
                    entry = BacktraceEntry(
                        process_id=process_id,
                        frame_num=frame.frame_num,
                        address=frame.address or 0,
                        resolved_symbol=frame.symbol or "???",
                        resolved_file=frame.source_file,
                        resolved_line=frame.source_line,
                        thread_id=thread.id,
                    )
                    session.add(entry)

                # Register state — stored as architecture-agnostic JSON.
                # crash_instruction (if captured via x/1i $pc) stored under
                # the special key "__crash_insn__" in the same JSON blob.
                if gdb_thread.registers or gdb_thread.crash_instruction:
                    import json

                    reg_data: dict = dict(gdb_thread.registers)
                    if gdb_thread.crash_instruction:
                        reg_data["__crash_insn__"] = gdb_thread.crash_instruction  # type: ignore[assignment]
                    reg_state = ProcessRegisterState(
                        process_id=process_id,
                        thread_id=thread.id,
                        registers_json=json.dumps(reg_data),
                    )
                    session.add(reg_state)

            await session.commit()

        logger.info(
            "gdb_dump_loaded",
            extra={"process_id": process_id, "thread_count": len(dump.threads)},
        )
        return len(dump.threads)

    async def get_latest_snapshot(self) -> ProcessSnapshot | None:
        """Return the most recently created ProcessSnapshot (highest id), or None if empty."""
        async with self.manager.get_session() as session:
            result = await session.execute(  # type: ignore
                select(ProcessSnapshot)
                .order_by(ProcessSnapshot.id.desc())  # type: ignore[union-attr]
                .limit(1)
            )
            return result.scalars().first()

    async def resolve_snapshot(
        self,
        tag: str | None,
        snapshot_id: int | None,
    ) -> ProcessSnapshot | None:
        """
        Resolve which existing snapshot to update, based on --tag / --snapshot-id rules.

        Rules:
          (no tag, no id)  → None  (caller creates a new snapshot)
          (tag, no id)     → snapshot with that tag, or None if not found
          (no tag, id)     → snapshot with that id (raises if not found)
          (tag, id)        → snapshot with that id (raises if not found);
                             also validates that the tag does not belong to a
                             *different* snapshot (caller handles --force logic)

        Returns:
            Existing ProcessSnapshot, or None when a new one should be created.

        Raises:
            ProcessNotFoundError: snapshot_id given but not found in DB
            DatabaseConstraintError: tag belongs to a different snapshot than snapshot_id
        """
        from baldrick.exceptions import DatabaseConstraintError, ProcessNotFoundError

        async with self.manager.get_session() as session:
            if snapshot_id is not None:
                result = await session.execute(  # type: ignore
                    select(ProcessSnapshot).where(ProcessSnapshot.id == snapshot_id)
                )
                snap = result.scalars().first()
                if snap is None:
                    raise ProcessNotFoundError(f"Snapshot {snapshot_id} not found")

                if tag is not None and snap.tag != tag:
                    # Check if the tag is already claimed by another snapshot
                    other = (
                        (
                            await session.execute(  # type: ignore
                                select(ProcessSnapshot).where(ProcessSnapshot.tag == tag)
                            )
                        )
                        .scalars()
                        .first()
                    )
                    if other is not None and other.id != snapshot_id:
                        raise DatabaseConstraintError(
                            f"Tag {tag!r} already assigned to snapshot {other.id}, not {snapshot_id}. "
                            f"Use --force / -f to steal the tag (the other snapshot will lose it)."
                        )
                return snap

            if tag is not None:
                result = await session.execute(  # type: ignore
                    select(ProcessSnapshot).where(ProcessSnapshot.tag == tag)
                )
                return result.scalars().first()  # None if not found → create new

        return None

    async def merge_into_snapshot(
        self,
        snapshot: ProcessSnapshot,
        *,
        pid: int | None = None,
        maps_text: str | None = None,
        core_path: str | None = None,
        gdb_text: str | None = None,
        rootfs: str = "/",
        debugfs: str | None = None,
        new_tag: str | None = None,
        force_tag: bool = False,
    ) -> ProcessSnapshot:
        """
        Merge additional data into an existing ProcessSnapshot (additive, no overwrites).

        All operations are additive:
          - MemoryMappings: added only if start_addr not already present
          - Threads: added by TID; None fields filled in if new source has them
          - BacktraceEntry: added only if (thread_id, frame_num) not already present
          - ProcessRegisterState: added per thread_id only if absent

        Also updates sources_json and source_type to reflect the new data sources.
        If new_tag is given and differs from the current tag, it is applied (the old
        tag owner is cleared when force_tag=True).

        Args:
            snapshot:   Existing ProcessSnapshot to enrich
            pid:        Process PID (used to load /proc threads when maps_text given)
            maps_text:  /proc/PID/maps content to merge
            core_path:  ELF core dump path to merge mappings from
            gdb_text:   GDB text dump to merge threads/backtraces from
            rootfs:     Rootfs prefix for binary resolution
            debugfs:    Debugfs prefix (defaults to rootfs)
            new_tag:    New tag to assign (if different from current)
            force_tag:  When True, clear the tag from any other snapshot that owns it

        Returns:
            Updated ProcessSnapshot (re-fetched with mappings eagerly loaded)
        """
        import json

        from baldrick.exceptions import ProcessNotFoundError

        process_id = snapshot.id
        assert process_id is not None

        sources: list[dict] = json.loads(snapshot.sources_json or "[]")
        source_types: list[str] = [s.strip() for s in snapshot.source_type.split("+")]
        new_mappings_added = False

        async with self.manager.get_session() as session:
            # Re-attach snapshot to this session
            snap = await session.get(ProcessSnapshot, process_id)
            if snap is None:
                raise ProcessNotFoundError(f"Snapshot {process_id} not found")

            # ── Tag update ────────────────────────────────────────────────────
            if new_tag is not None and snap.tag != new_tag:
                if force_tag:
                    # Clear tag from the current owner if it's a different snapshot
                    other = (
                        (
                            await session.execute(  # type: ignore
                                select(ProcessSnapshot).where(
                                    (ProcessSnapshot.tag == new_tag)
                                    & (ProcessSnapshot.id != process_id)
                                )
                            )
                        )
                        .scalars()
                        .first()
                    )
                    if other is not None:
                        other.tag = None
                        session.add(other)
                snap.tag = new_tag
                session.add(snap)

            # ── Merge memory mappings (maps_text or core_path) ────────────────
            if maps_text or core_path:
                # Collect existing start_addrs for dedup
                existing_addrs_result = await session.execute(  # type: ignore
                    select(MemoryMapping.start_addr).where(MemoryMapping.process_id == process_id)
                )
                existing_addrs: set[int] = set(existing_addrs_result.scalars().all())

                parsed_maps: list[dict] = []
                src_type: str = ""
                src_path: str | None = None

                if maps_text:
                    lines = maps_text.strip().split("\n")
                    parsed_maps = self._parse_maps_lines(lines)
                    src_type = "maps"
                elif core_path:
                    from baldrick.binutils.coredump import CoreDumpParser

                    parser = CoreDumpParser(self.config)
                    core_result = await parser.parse_core_dump(core_path)
                    if core_result.status == "success":
                        parsed_maps = core_result.mappings or []
                    src_type = "core_dump"
                    src_path = core_path

                added = 0
                for map_data in parsed_maps:
                    addr = map_data.get("start_addr")
                    if not isinstance(addr, int):
                        continue
                    if addr in existing_addrs:
                        continue
                    try:
                        mapping = MemoryMapping(process_id=process_id, **map_data)
                        session.add(mapping)
                        existing_addrs.add(addr)
                        added += 1
                    except Exception as e:
                        logger.debug("merge_mapping_skip", extra={"error": str(e)})

                if added:
                    new_mappings_added = True
                    logger.info(
                        "merge_mappings_added", extra={"process_id": process_id, "count": added}
                    )

                entry = {"type": src_type}
                if src_path:
                    entry["path"] = src_path
                if entry not in sources:
                    sources.append(entry)
                if src_type not in source_types:
                    source_types.append(src_type)

            # ── Merge GDB dump (threads + backtraces + registers) ─────────────
            if gdb_text:
                from baldrick.binutils.gdb_dump import parse_gdb_dump

                dump = parse_gdb_dump(gdb_text)
                for gdb_thread in dump.threads:
                    # Find or create Thread by TID
                    thr_result = await session.execute(  # type: ignore
                        select(Thread).where(
                            (Thread.process_id == process_id) & (Thread.tid == gdb_thread.tid)
                        )
                    )
                    thread = thr_result.scalars().first()

                    if thread is None:
                        thread = Thread(process_id=process_id, tid=gdb_thread.tid)
                        session.add(thread)
                        await session.flush()

                    # Fill None fields on existing thread
                    changed = False
                    if gdb_thread.name and not thread.name:
                        thread.name = gdb_thread.name
                        changed = True
                    if changed:
                        session.add(thread)
                        await session.flush()

                    # Existing (thread_id, frame_num) pairs for dedup
                    existing_frames_result = await session.execute(  # type: ignore
                        select(BacktraceEntry.frame_num).where(
                            (BacktraceEntry.process_id == process_id)
                            & (BacktraceEntry.thread_id == thread.id)
                        )
                    )
                    existing_frames: set[int] = set(existing_frames_result.scalars().all())

                    for frame in gdb_thread.frames:
                        if frame.frame_num in existing_frames:
                            continue
                        session.add(
                            BacktraceEntry(
                                process_id=process_id,
                                frame_num=frame.frame_num,
                                address=frame.address or 0,
                                resolved_symbol=frame.symbol or "???",
                                resolved_file=frame.source_file,
                                resolved_line=frame.source_line,
                                thread_id=thread.id,
                            )
                        )
                        existing_frames.add(frame.frame_num)

                    # Register state — add only if absent for this thread
                    if gdb_thread.registers:
                        existing_reg = (
                            (
                                await session.execute(  # type: ignore
                                    select(ProcessRegisterState).where(
                                        (ProcessRegisterState.process_id == process_id)
                                        & (ProcessRegisterState.thread_id == thread.id)
                                    )
                                )
                            )
                            .scalars()
                            .first()
                        )
                        if existing_reg is None:
                            import json as _json

                            session.add(
                                ProcessRegisterState(
                                    process_id=process_id,
                                    thread_id=thread.id,
                                    registers_json=_json.dumps(gdb_thread.registers),
                                )
                            )

                entry = {"type": "gdb_dump"}
                if entry not in sources:
                    sources.append(entry)
                if "gdb_dump" not in source_types:
                    source_types.append("gdb_dump")

            # ── Update snapshot metadata ──────────────────────────────────────
            snap.sources_json = json.dumps(sources)
            snap.source_type = "+".join(source_types)
            session.add(snap)
            await session.commit()

        # Re-fetch with eagerly loaded mappings
        async with self.manager.get_session() as session:
            result = await session.execute(  # type: ignore
                select(ProcessSnapshot)
                .where(ProcessSnapshot.id == process_id)
                .options(selectinload(ProcessSnapshot.mappings))  # type: ignore[arg-type]
            )
            loaded_process = result.scalars().first()

        if loaded_process is None:
            raise RuntimeError(f"Process snapshot disappeared: id={process_id}")

        # Load /proc threads if pid given (and maps were merged — implies live process)
        if pid is not None and new_mappings_added:
            await self._load_threads(process_id, pid, loaded_process.mappings)

        # Re-link binaries for any new mappings
        if new_mappings_added:
            await self._link_binaries(loaded_process, rootfs=rootfs, debugfs=debugfs)

        return loaded_process

    async def get_deadlock_report(self, process_id: int, lock_state_text: str | None = None):
        """
        Analyze threads of a process snapshot for deadlocks.

        Loads Thread records and per-thread BacktraceEntry records from the DB,
        then delegates to DeadlockAnalyzer.

        Args:
            process_id:       ProcessSnapshot.id
            lock_state_text:  Optional raw output from GDB ``bdr find-deadlock``.
                              When provided, enables Tier 0 analysis with exact
                              mutex ownership and condition-variable correlation.

        Returns:
            DeadlockReport dataclass
        """
        from baldrick.binutils.gdb_dump import parse_condition_state, parse_lock_state
        from baldrick.deadlock_analyzer import DeadlockAnalyzer

        async with self.manager.get_session() as session:
            # Load threads
            thread_stmt = select(Thread).where(Thread.process_id == process_id)
            thread_result = await session.execute(thread_stmt)  # type: ignore
            threads = thread_result.scalars().all()

            # Load backtrace entries per thread
            bt_stmt = select(BacktraceEntry).where(BacktraceEntry.process_id == process_id)
            bt_result = await session.execute(bt_stmt)  # type: ignore
            entries = bt_result.scalars().all()

        # Group backtrace symbols by thread.id (DB PK)
        backtraces: dict[int, list[str]] = {}
        for entry in entries:
            if entry.thread_id is not None:
                backtraces.setdefault(entry.thread_id, []).append(entry.resolved_symbol)

        # Convert Thread ORM objects to plain dicts for the analyzer
        thread_dicts = [
            {
                "id": t.id,
                "tid": t.tid,
                "name": t.name,
                "wchan": t.wchan,
                "syscall": t.syscall,
                "stack_start": t.stack_start,
                "stack_end": t.stack_end,
            }
            for t in threads
        ]

        lock_state = parse_lock_state(lock_state_text) if lock_state_text else None
        report = DeadlockAnalyzer(thread_dicts, backtraces, lock_state=lock_state).analyze()
        if lock_state_text:
            report.lock_state = lock_state or []
            report.condition_waits = parse_condition_state(lock_state_text)
            if report.condition_waits and report.evidence_level == "none":
                report.summary = (
                    "No mutex deadlock cycle detected; "
                    f"{len(report.condition_waits)} condition-variable wait(s) reported."
                )
        return report

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
        from baldrick.memory_analyzer import MemoryAnalyzer

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

        from baldrick.binutils.coredump import CoreDumpParser

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
                .options(selectinload(ProcessSnapshot.mappings))  # type: ignore[arg-type]
            )
            result = await session.execute(statement)  # type: ignore
            loaded_process = result.scalars().first()

        if loaded_process is None:
            raise RuntimeError(f"Process snapshot disappeared: id={process_id}")

        await self._link_binaries(loaded_process, rootfs=rootfs, debugfs=debugfs)
        return loaded_process

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
        from baldrick.db.rootfs import RootfsDatabase

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
                binary, is_new, debug_file = await rootfs_db.load_binary(
                    pathname, rootfs=rootfs, debugfs=debugfs
                )
                binary_cache[pathname] = binary
                logger.debug(
                    "binary_linked",
                    extra={
                        "path": pathname,
                        "binary_id": binary.id,
                        "is_new": is_new,
                        "debug_file": debug_file,
                    },
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

                linked_binary = binary_cache.get(pathname)
                pb = ProcessBinary(
                    process_id=process.id,
                    binary_id=linked_binary.id if linked_binary else None,
                    mapping_id=mapping.id,
                    binary_load_addr=mapping.start_addr,
                    match_score=1.0 if linked_binary else None,
                    match_method="exact" if linked_binary else None,
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
        from baldrick.binutils.hasher import FunctionHasher
        from baldrick.binutils.matcher import BinaryMatcher

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
                        fp_result.fingerprints,
                        list(candidates),
                        rootfs_session,
                        match_threshold,
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
            r"(\d+)"
            r"(?:\s+(.*))?$"
        )

        parsed = []
        failed_lines = 0

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
                start_addr = int(m.group(1), 16)
                end_addr = int(m.group(2), 16)
                perms = m.group(3)
                offset = int(m.group(4), 16)
                dev = m.group(5)
                inode = int(m.group(6))
                pathname = (m.group(7) or "").strip() or "[anonymous]"

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
