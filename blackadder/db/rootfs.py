"""
Rootfs database access layer for binary metadata.

Provides RootfsDatabase class for managing binaries, sections, symbols,
and function fingerprints extracted from binaries in the rootfs.
"""

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import text as _SA_TEXT
from sqlmodel import select

from blackadder.binutils.hasher import FunctionHasher
from blackadder.models import Binary, BinaryDwarfRef, BinaryLocator, CanonicalDwarfType, DebugLine, DwarfMember, FunctionFingerprint, SectionHeader, SourceFile, Symbol

from .base import AsyncDatabaseManager

logger = logging.getLogger("blackadder.db.rootfs")


@dataclass
class InsertBatch:
    """A chunk of parsed rows destined for the DB writer."""
    kind: Literal["dwarf", "debugline"]
    binary_id: int
    rows: list[dict]
    member_rows: list[dict] = field(default_factory=list)
    first_chunk: bool = False  # triggers idempotency check in writer


# Sentinel: put on the queue to signal end-of-stream to run_db_writer
DB_SENTINEL: InsertBatch | None = None


@dataclass
class BinaryPayload:
    """All data collected for one binary — pure I/O, no DB IDs."""
    binary_path: str
    md5sum: str
    name: str
    mtime: int
    debug_link: str | None
    debug_file_path: str | None
    sym_source: str               # debug_file_path or binary_path
    sections: dict                # {name: {size, vma, lma, off, align}}
    symbols: list[tuple]      # (address, scope, sym_type, section, size, name)
    dwarf_types: list[tuple]  # (die_offset, tag, name, byte_size, type_ref, encoding)
    dwarf_members: list[tuple]  # (parent_die_offset, name, byte_offset, member_type_ref)
    debug_lines: list[tuple]  # (source_file, line_number, address)
    load_types: bool
    load_lines: bool


# Sentinel for run_payload_writer queue
PAYLOAD_SENTINEL: BinaryPayload | None = None


class RootfsDatabase:
    """Database access for binary metadata (sections, symbols, fingerprints)."""

    def __init__(self, manager: AsyncDatabaseManager, config):
        """
        Initialize RootfsDatabase.

        Args:
            manager: AsyncDatabaseManager instance
            config: BlackadderConfig with tool paths
        """
        self.manager = manager
        self.config = config
        # Serializes the check-then-insert section so concurrent coroutines
        # don't both pass the SELECT and then race to INSERT the same binary.
        self._write_lock = asyncio.Lock()
        # Cumulative timing stats for the write lock (seconds).
        # "wait" = time spent blocked waiting to acquire; "held" = time inside CS.
        self._write_lock_stats: dict[str, float] = {"wait": 0.0, "held": 0.0}

    async def load_binary(
        self,
        binary_path: str,
        rootfs: str = "/",
        debugfs: str | None = None,
    ) -> tuple[Binary, bool, str | None]:
        """
        Load a binary into the rootfs database.

        Computes MD5, extracts sections/symbols/debug_link via objdump/readelf,
        and stores them. Returns existing record without re-parsing if MD5 matches.
        Also searches for and loads a companion debug file if one is found.

        Args:
            binary_path: Absolute path to the binary file
            rootfs:      Path to rootfs (used for debug-file search)
            debugfs:     Path to debugfs (defaults to rootfs)

        Returns:
            (Binary, is_new, debug_file_path) — debug_file_path is None if no
            debug file was found, or the resolved path when found.
        """
        from blackadder.binutils.parser import BinToolsParser

        def _compute_md5() -> str:
            md5 = hashlib.md5()
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
            return md5.hexdigest()

        md5sum = await asyncio.to_thread(_compute_md5)
        name = os.path.basename(binary_path)
        mtime = int(os.path.getmtime(binary_path))

        parser = BinToolsParser(self.config)
        from blackadder.binutils.debuginfo import find_debug_file

        # --- Phase 1: all I/O runs concurrently (no lock held) ---

        # Resolve debug file path (needed for both new and existing binaries)
        try:
            debug_link_name = await parser.parse_readelf_debug_link(binary_path)
        except Exception as e:
            logger.debug("debug_link_parse_failed", extra={"path": binary_path, "error": str(e)})
            debug_link_name = None

        debug_file_path = await asyncio.to_thread(
            find_debug_file, binary_path, debug_link_name, rootfs, debugfs
        )
        sym_source = debug_file_path or binary_path

        # Pre-fetch sections and symbols before touching the DB so that the
        # critical section (SELECT + INSERT) doesn't contain any awaits.
        sections_data: dict = {}
        try:
            sections_data = await parser.parse_objdump_sections(binary_path)
        except Exception as e:
            logger.debug("sections_parse_failed", extra={"path": binary_path, "error": str(e)})

        syms_data: list = []
        try:
            syms_data = await parser.parse_objdump_syms_full(sym_source)
            if not syms_data and sym_source != binary_path:
                syms_data = await parser.parse_objdump_syms_full(binary_path)
        except Exception as e:
            logger.debug("symbols_parse_failed", extra={"path": sym_source, "error": str(e)})

        # --- Phase 2: DB writes serialised via lock (no subprocess awaits inside) ---

        _wl_t0 = time.monotonic()
        async with self._write_lock:
            _wl_wait = time.monotonic() - _wl_t0
            self._write_lock_stats["wait"] += _wl_wait
            _wl_cs_t0 = time.monotonic()
            for _lb_attempt in range(8):
                try:
                    async with self.manager.get_session() as session:
                        # Check if binary already known by MD5
                        stmt = select(Binary).where(Binary.md5sum == md5sum)
                        result = await session.execute(stmt)
                        existing = result.scalars().first()

                        if existing:
                            # Register this path if not yet known; update debug_file if now resolved
                            loc_stmt = select(BinaryLocator).where(BinaryLocator.path == binary_path)
                            loc_result = await session.execute(loc_stmt)
                            locator = loc_result.scalars().first()
                            if not locator:
                                session.add(BinaryLocator(
                                    path=binary_path, md5sum=md5sum, mtime=mtime,
                                    debug_file=debug_file_path,
                                ))
                                await session.commit()
                            elif debug_file_path and not locator.debug_file:
                                locator.debug_file = debug_file_path
                                await session.commit()

                            sym_check = await session.execute(
                                select(Symbol).where(Symbol.binary_id == existing.id).limit(1)
                            )
                            has_symbols = sym_check.scalars().first() is not None

                            # Skip reload only if symbols exist AND we have no better source
                            if has_symbols and sym_source == binary_path:
                                return existing, False, debug_file_path

                            # Symbols missing OR debug file now available — DELETE + INSERT
                            if has_symbols:
                                await session.execute(
                                    Symbol.__table__.delete().where(Symbol.binary_id == existing.id)
                                )
                                logger.debug(
                                    "symbols_replacing_with_debug_file",
                                    extra={"binary": binary_path, "sym_source": sym_source},
                                )
                            else:
                                logger.debug(
                                    "symbols_missing_loading",
                                    extra={"binary": binary_path, "sym_source": sym_source},
                                )
                            binary_id = existing.id
                        else:
                            # New binary — store metadata
                            binary = Binary(md5sum=md5sum, name=name, debug_link=debug_link_name)
                            session.add(binary)
                            await session.flush()
                            binary_id = binary.id

                            # Sections (already fetched above)
                            for idx, (sec_name, sec) in enumerate(sections_data.items()):
                                session.add(
                                    SectionHeader(
                                        binary_id=binary_id,
                                        idx=idx,
                                        name=sec_name[:32],
                                        size=sec["size"],
                                        vma=sec["vma"],
                                        lma=sec["lma"],
                                        off=sec["off"],
                                        align=sec["align"],
                                    )
                                )

                            session.add(BinaryLocator(
                                path=binary_path, md5sum=md5sum, mtime=mtime,
                                debug_file=debug_file_path,
                            ))

                        # Load symbols (already fetched above) — shared path for new and existing-without-symbols
                        for sym in syms_data:
                            session.add(
                                Symbol(
                                    binary_id=binary_id,
                                    address=sym["address"],
                                    scope=sym["scope"],
                                    sym_type=sym["sym_type"],
                                    section=sym["section"],
                                    size=sym["size"],
                                    name=sym["name"],
                                )
                            )
                        logger.debug(
                            "symbols_loaded",
                            extra={"binary": binary_path, "source": sym_source, "count": len(syms_data)},
                        )

                        await session.commit()
                    break  # success
                except Exception as _e:
                    if ("database is locked" in str(_e) or "database table is locked" in str(_e)) and _lb_attempt < 7:
                        await asyncio.sleep(0.05 * (2 ** _lb_attempt))
                    else:
                        raise
            self._write_lock_stats["held"] += time.monotonic() - _wl_cs_t0

        # Re-fetch outside the session to avoid detached state
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.id == binary_id))
            binary = result.scalars().first()

        if binary is None:
            raise RuntimeError(f"Binary disappeared after insert: id={binary_id}")

        return binary, True, debug_file_path

    # =========================================================================
    # New bulk-load path: collect_binary_payload + run_payload_writer
    # Workers do pure I/O → BinaryPayload; single writer task does all DB writes.
    # =========================================================================

    async def collect_binary_payload(
        self,
        binary_path: str,
        rootfs: str = "/",
        debugfs: str | None = None,
        load_types: bool = False,
        load_lines: bool = False,
    ) -> BinaryPayload:
        """
        Collect all data for a binary without touching the DB.

        Runs md5, readelf, objdump, and optionally DWARF/debugline parsing.
        Safe to run concurrently — zero DB writes.
        """
        from blackadder.binutils.debuginfo import find_debug_file
        from blackadder.binutils.dwarf_parser import _sync_parse_debug_line, _sync_parse_dwarf_types
        from blackadder.binutils.parser import BinToolsParser

        def _compute_md5() -> str:
            md5 = hashlib.md5()
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
            return md5.hexdigest()

        md5sum = await asyncio.to_thread(_compute_md5)
        name = os.path.basename(binary_path)
        mtime = int(os.path.getmtime(binary_path))

        parser = BinToolsParser(self.config)

        try:
            debug_link_name = await parser.parse_readelf_debug_link(binary_path)
        except Exception:
            debug_link_name = None

        debug_file_path = await asyncio.to_thread(
            find_debug_file, binary_path, debug_link_name, rootfs, debugfs or rootfs
        )
        sym_source = debug_file_path or binary_path

        sections_data: dict = {}
        try:
            sections_data = await parser.parse_objdump_sections(binary_path)
        except Exception:
            pass

        syms_raw: list[dict] = []
        try:
            syms_raw = await parser.parse_objdump_syms_full(sym_source)
            if not syms_raw and sym_source != binary_path:
                syms_raw = await parser.parse_objdump_syms_full(binary_path)
        except Exception:
            pass
        # Convert to tuples upfront — avoids per-row dict lookup overhead at INSERT time
        syms_data: list[tuple] = [
            (s["address"], s["scope"], s["sym_type"], s["section"], s["size"], s["name"])
            for s in syms_raw
        ]

        dwarf_types: list[tuple] = []
        dwarf_members: list[tuple] = []
        debug_lines: list[tuple] = []

        # --types implies --lines
        effective_lines = load_lines or load_types

        if load_types:
            try:
                async with parser.subprocess_sem:
                    dt_raw, dm_raw = await asyncio.to_thread(
                        _sync_parse_dwarf_types, sym_source, self.config.objdump_path
                    )
                dwarf_types = [
                    (t["die_offset"], t["tag"], t["name"], t["byte_size"], t["type_ref"], t["encoding"])
                    for t in dt_raw
                ]
                dwarf_members = [
                    (m["parent_die_offset"], m.get("name"), m["byte_offset"], m["member_type_ref"])
                    for m in dm_raw
                ]
            except Exception as e:
                logger.debug("dwarf_collect_failed", extra={"binary": binary_path, "error": str(e)})

        if effective_lines:
            try:
                async with parser.subprocess_sem:
                    dl_raw = await asyncio.to_thread(
                        _sync_parse_debug_line, sym_source, self.config.readelf_path
                    )
                debug_lines = [
                    (dl["source_file"], dl["line_number"], dl["address"])
                    for dl in dl_raw
                ]
            except Exception as e:
                logger.debug("debugline_collect_failed", extra={"binary": binary_path, "error": str(e)})

        return BinaryPayload(
            binary_path=binary_path,
            md5sum=md5sum,
            name=name,
            mtime=mtime,
            debug_link=debug_link_name,
            debug_file_path=debug_file_path,
            sym_source=sym_source,
            sections=sections_data,
            symbols=syms_data,
            dwarf_types=dwarf_types,
            dwarf_members=dwarf_members,
            debug_lines=debug_lines,
            load_types=load_types,
            load_lines=effective_lines,
        )

    @staticmethod
    async def _raw_executemany(conn, sql: str, rows: list[tuple]) -> None:
        """Bypass SQLAlchemy dict-param overhead — use raw aiosqlite executemany (4x faster)."""
        if not rows:
            return
        raw = await conn.get_raw_connection()
        await raw.driver_connection.executemany(sql, rows)

    async def _apply_payload(
        self,
        conn,
        payload: BinaryPayload,
    ) -> dict[str, int]:
        """
        Write one BinaryPayload to DB within an already-open transaction.

        Returns counts: {loaded, skipped, types, members, lines}.
        """
        # Raw aiosqlite connection — reused for all bulk operations in this payload
        raw_conn = (await conn.get_raw_connection()).driver_connection

        # Idempotency: check if binary exists and already has symbols
        row = await conn.execute(
            _SA_TEXT("SELECT id FROM binary WHERE md5sum=:md5"),
            {"md5": payload.md5sum},
        )
        existing = row.first()

        if existing:
            binary_id = existing.id
            sym_row = await conn.execute(
                _SA_TEXT("SELECT 1 FROM symbol WHERE binary_id=:bid LIMIT 1"),
                {"bid": binary_id},
            )
            has_symbols = sym_row.first() is not None

            # Update locator if missing or debug_file newly resolved
            loc_row = await conn.execute(
                _SA_TEXT("SELECT id, debug_file FROM binarylocator WHERE path=:path"),
                {"path": payload.binary_path},
            )
            loc = loc_row.first()
            if not loc:
                await conn.execute(
                    _SA_TEXT(
                        "INSERT OR IGNORE INTO binarylocator (path, md5sum, mtime, debug_file)"
                        " VALUES (:path, :md5, :mtime, :dbg)"
                    ),
                    {"path": payload.binary_path, "md5": payload.md5sum,
                     "mtime": payload.mtime, "dbg": payload.debug_file_path},
                )
            elif payload.debug_file_path and not loc.debug_file:
                await conn.execute(
                    _SA_TEXT("UPDATE binarylocator SET debug_file=:dbg WHERE id=:id"),
                    {"dbg": payload.debug_file_path, "id": loc.id},
                )

            symbols_already_ok = has_symbols and payload.sym_source == payload.binary_path
            if symbols_already_ok:
                # Symbols already loaded — but still need to write types/lines if requested
                if not payload.load_types and not payload.load_lines:
                    return {"loaded": 0, "skipped": 1, "types": 0, "members": 0, "lines": 0}
                # Fall through to write types/lines; skip symbol reload below
            else:
                # Re-load symbols (debug file now available or symbols were missing)
                if has_symbols:
                    await conn.execute(
                        _SA_TEXT("DELETE FROM symbol WHERE binary_id=:bid"),
                        {"bid": binary_id},
                    )
        else:
            # New binary
            await conn.execute(
                _SA_TEXT(
                    "INSERT INTO binary (md5sum, name, debug_link)"
                    " VALUES (:md5, :name, :dblink)"
                ),
                {"md5": payload.md5sum, "name": payload.name, "dblink": payload.debug_link},
            )
            row2 = await conn.execute(
                _SA_TEXT("SELECT id FROM binary WHERE md5sum=:md5"),
                {"md5": payload.md5sum},
            )
            binary_id = row2.first().id

            # Sections (bulk)
            if payload.sections:
                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO sectionheader"
                    " (binary_id, idx, name, size, vma, lma, off, align)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    [(binary_id, idx, sname[:32], s["size"], s["vma"], s["lma"], s["off"], s["align"])
                     for idx, (sname, s) in enumerate(payload.sections.items())],
                )

            await conn.execute(
                _SA_TEXT(
                    "INSERT OR IGNORE INTO binarylocator (path, md5sum, mtime, debug_file)"
                    " VALUES (:path, :md5, :mtime, :dbg)"
                ),
                {"path": payload.binary_path, "md5": payload.md5sum,
                 "mtime": payload.mtime, "dbg": payload.debug_file_path},
            )

        # Symbols (bulk, shared path for new and reload — skip if already loaded)
        if payload.symbols and not symbols_already_ok:
            await raw_conn.executemany(
                "INSERT OR IGNORE INTO symbol"
                " (binary_id, address, scope, sym_type, section, size, name)"
                " VALUES (?,?,?,?,?,?,?)",
                [(binary_id, *s) for s in payload.symbols],
            )

        written_types = written_members = written_lines = 0

        if payload.load_types and payload.dwarf_types:
            # Skip if already loaded for this binary
            ref_check = await conn.execute(
                _SA_TEXT("SELECT 1 FROM binary_dwarf_ref WHERE binary_id=:bid LIMIT 1"),
                {"bid": binary_id},
            )
            if ref_check.first() is None:
                # 1. Upsert canonical types (global dedup by tag+name+byte_size+encoding)
                # dwarf_types tuple: (die_offset, tag, name, byte_size, type_ref, encoding)
                canonical_rows = list({
                    (t[1], t[2], t[3], t[5])  # (tag, name, byte_size, encoding)
                    for t in payload.dwarf_types
                })
                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO canonical_dwarf_type (tag, name, byte_size, encoding)"
                    " VALUES (?,?,?,?)",
                    canonical_rows,
                )

                # 2. Fetch canonical_id for each unique (tag, name, byte_size, encoding).
                # Multi-column IN fails for NULL values in SQLite (NULL != NULL in SQL).
                # Instead: SELECT by the distinct tags we inserted, then match in Python
                # using tuple equality (Python None == None).
                tags_needed = list({r[0] for r in canonical_rows})
                tag_ph = ",".join("?" * len(tags_needed))
                cursor = await raw_conn.execute(
                    f"SELECT id, tag, name, byte_size, encoding"
                    f" FROM canonical_dwarf_type WHERE tag IN ({tag_ph})",
                    tags_needed,
                )
                canon_map: dict[tuple, int] = {
                    (row[1], row[2], row[3], row[4]): row[0]
                    for row in await cursor.fetchall()
                }

                # 3. INSERT binary_dwarf_ref — die_offset → canonical_id + type_ref_die
                ref_rows = [
                    (binary_id, t[0], canon_map[(t[1], t[2], t[3], t[5])], t[4])
                    for t in payload.dwarf_types
                    if (t[1], t[2], t[3], t[5]) in canon_map
                ]
                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO binary_dwarf_ref"
                    " (binary_id, die_offset, canonical_id, type_ref_die)"
                    " VALUES (?,?,?,?)",
                    ref_rows,
                )
                written_types = len(ref_rows)

                # 4. INSERT dwarfmember — canonical_type_id via in-memory die_offset→canonical_id map
                if payload.dwarf_members:
                    die_to_canonical: dict[int, int] = {
                        t[0]: canon_map[(t[1], t[2], t[3], t[5])]
                        for t in payload.dwarf_types
                        if (t[1], t[2], t[3], t[5]) in canon_map
                    }
                    # dwarf_members tuple: (parent_die_offset, name, byte_offset, member_type_ref)
                    member_rows = [
                        (die_to_canonical[m[0]], m[1], m[2], m[3])
                        for m in payload.dwarf_members
                        if m[0] in die_to_canonical
                    ]
                    if member_rows:
                        await raw_conn.executemany(
                            "INSERT INTO dwarfmember"
                            " (canonical_type_id, name, byte_offset, member_type_ref)"
                            " VALUES (?,?,?,?)",
                            member_rows,
                        )
                        written_members = len(member_rows)

        if payload.load_lines and payload.debug_lines:
            dl_check = await conn.execute(
                _SA_TEXT("SELECT 1 FROM debugline WHERE binary_id=:bid LIMIT 1"),
                {"bid": binary_id},
            )
            if dl_check.first() is None:
                # Normalize source_file paths → sourcefile catalog
                # debug_lines tuples: (source_file, line_number, address)
                unique_paths = list({dl[0] for dl in payload.debug_lines})

                # Insert new paths (ignore existing)
                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO sourcefile (path) VALUES (?)",
                    [(p,) for p in unique_paths],
                )

                # Fetch all needed path→id mappings in one query
                placeholders = ",".join("?" * len(unique_paths))
                cursor = await raw_conn.execute(
                    f"SELECT id, path FROM sourcefile WHERE path IN ({placeholders})",
                    unique_paths,
                )
                path_to_id = {row[1]: row[0] for row in await cursor.fetchall()}

                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO debugline"
                    " (binary_id, source_file_id, line_number, address)"
                    " VALUES (?,?,?,?)",
                    [(binary_id, path_to_id[dl[0]], dl[1], dl[2])
                     for dl in payload.debug_lines],
                )
                written_lines = len(payload.debug_lines)

        return {
            "loaded": 1, "skipped": 0,
            "types": written_types, "members": written_members, "lines": written_lines,
        }

    async def apply_single_payload(self, payload: BinaryPayload) -> dict[str, int]:
        """Write one BinaryPayload in a single transaction. Used by load-types command."""
        async with self.manager.engine.begin() as conn:
            return await self._apply_payload(conn, payload)

    async def run_payload_writer(
        self,
        queue: asyncio.Queue,
        live: dict[str, int] | None = None,
    ) -> dict[str, int]:
        """
        Single-consumer writer for bulk load.

        Drains up to 8 payloads per transaction to amortize commit overhead.
        No lock needed — this is the only DB writer during bulk load.

        Send PAYLOAD_SENTINEL (None) to signal end of stream.
        Returns cumulative stats.
        """
        import time as _time
        total: dict[str, int] = {
            "loaded": 0, "skipped": 0, "types": 0, "members": 0, "lines": 0, "commits": 0,
            # timing accumulators (ms)
            "t_queue_ms": 0,   # blocking on queue.get()
            "t_apply_ms": 0,   # _apply_payload SQL statements
            "t_commit_ms": 0,  # COMMIT (engine.begin() exit)
        }
        retries = 0

        while True:
            _t0 = _time.monotonic()
            payload = await queue.get()
            total["t_queue_ms"] += int((_time.monotonic() - _t0) * 1000)
            if payload is PAYLOAD_SENTINEL:
                break

            # Drain up to 7 more without blocking
            pending: list[BinaryPayload] = [payload]
            while len(pending) < 8:
                try:
                    nxt = queue.get_nowait()
                    if nxt is PAYLOAD_SENTINEL:
                        await queue.put(PAYLOAD_SENTINEL)
                        break
                    pending.append(nxt)
                except asyncio.QueueEmpty:
                    break

            _max_attempts = 8
            for _attempt in range(_max_attempts):
                try:
                    _t_apply = 0.0
                    _t_txn_start = _time.monotonic()
                    async with self.manager.engine.begin() as conn:
                        for p in pending:
                            _ta = _time.monotonic()
                            counts = await self._apply_payload(conn, p)
                            _t_apply += _time.monotonic() - _ta
                            for k, v in counts.items():
                                total[k] = total.get(k, 0) + v
                        # Time from last apply to commit = commit overhead
                        _t_before_commit = _time.monotonic()
                    # engine.begin() exited = COMMIT done
                    _t_after_commit = _time.monotonic()
                    total["t_apply_ms"]  += int(_t_apply * 1000)
                    total["t_commit_ms"] += int((_t_after_commit - _t_before_commit) * 1000)
                    total["commits"] = total.get("commits", 0) + 1
                    break
                except Exception as e:
                    _is_locked = "database is locked" in str(e) or "database table is locked" in str(e)
                    if _is_locked and _attempt < _max_attempts - 1:
                        retries += 1
                        if live is not None:
                            live["retries"] = retries
                        await asyncio.sleep(0.05 * (2 ** _attempt))
                    else:
                        logger.error(
                            "payload_writer_error",
                            extra={"batches": len(pending), "attempt": _attempt + 1, "error": str(e)},
                        )
                        break

            if live is not None:
                live["loaded"]   = total["loaded"]
                live["skipped"]  = total["skipped"]
                live["types"]    = total["types"]
                live["lines"]    = total["lines"]
                live["t_wait"]   = total["t_queue_ms"]
                live["t_write"]  = total["t_apply_ms"] + total["t_commit_ms"]

            # WAL checkpoint every 50 commits, outside any transaction
            if total["commits"] > 0 and total["commits"] % 50 == 0:
                try:
                    async with self.manager.engine.connect() as ck:
                        await ck.execute(_SA_TEXT("PRAGMA wal_checkpoint(PASSIVE)"))
                except Exception:
                    pass

        # Final checkpoint
        try:
            async with self.manager.engine.connect() as ck:
                await ck.execute(_SA_TEXT("PRAGMA wal_checkpoint(PASSIVE)"))
        except Exception:
            pass

        return total

    async def find_symbol_at_offset(self, binary_path: str, offset: int) -> dict | None:
        """
        Find the nearest symbol at or before offset in a binary.

        Used by the syms command for --type and --section display flags.
        Requires the binary to have been loaded via load_binary() first.

        Args:
            binary_path: Path to the binary
            offset: Address/offset within the binary

        Returns:
            Dict with name, scope, sym_type, section, size, address; or None
        """
        async with self.manager.get_session() as session:
            loc_result = await session.execute(
                select(BinaryLocator).where(BinaryLocator.path == binary_path)
            )
            locator = loc_result.scalars().first()
            if not locator:
                return None

            bin_result = await session.execute(
                select(Binary).where(Binary.md5sum == locator.md5sum)
            )
            binary = bin_result.scalars().first()
            if not binary:
                return None

            sym_result = await session.execute(
                select(Symbol)
                .where(Symbol.binary_id == binary.id, Symbol.address <= offset)
                .order_by(Symbol.address.desc())
                .limit(1)
            )
            symbol = sym_result.scalars().first()
            if not symbol:
                return None

            return {
                "name": symbol.name,
                "scope": symbol.scope,
                "sym_type": symbol.sym_type,
                "section": symbol.section,
                "size": symbol.size,
                "address": symbol.address,
            }

    async def compute_and_cache_fingerprints(self, binary_id: int, binary_path: str) -> int:
        """
        Compute fingerprints for a binary and store in DB.

        Args:
            binary_id: Binary model ID in database
            binary_path: Path to binary file

        Returns:
            Count of fingerprints stored
        """
        hasher = FunctionHasher(self.config)
        fp_result = await hasher.compute_fingerprints(binary_path)

        if fp_result.status != "success" or not fp_result.fingerprints:
            return 0

        fingerprints = fp_result.fingerprints

        async with self.manager.get_session() as session:
            for func_name, content_hash in fingerprints.items():
                fp = FunctionFingerprint(
                    binary_id=binary_id,
                    func_name=func_name,
                    func_offset=0,
                    func_size=0,
                    content_hash=content_hash,
                )
                session.add(fp)

            await session.commit()

        return len(fingerprints)

    async def find_binaries_by_name(self, name: str) -> list[Binary]:
        """
        Find all binaries matching a name (e.g., 'libc.so.6').

        Args:
            name: Binary name

        Returns:
            List of matching Binary objects
        """
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.name == name))
            return list(result.scalars().all())

    async def find_binary_by_md5(self, md5sum: str) -> Binary | None:
        """
        Find a binary by MD5 checksum.

        Args:
            md5sum: MD5 hex string

        Returns:
            Binary object or None if not found
        """
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.md5sum == md5sum))
            return result.scalars().first()

    async def has_fingerprints(self, binary_id: int) -> bool:
        """
        Check if a binary has fingerprints computed.

        Args:
            binary_id: Binary model ID

        Returns:
            True if fingerprints exist
        """
        async with self.manager.get_session() as session:
            result = await session.execute(
                select(FunctionFingerprint).where(FunctionFingerprint.binary_id == binary_id)
            )
            return result.scalars().first() is not None

    async def _get_binary_id_for_path(self, binary_path: str) -> int | None:
        """Return binary.id for the given file path, or None if not in DB."""
        async with self.manager.get_session() as session:
            loc_result = await session.execute(
                select(BinaryLocator).where(BinaryLocator.path == binary_path)
            )
            locator = loc_result.scalars().first()
            if not locator:
                return None
            bin_result = await session.execute(
                select(Binary).where(Binary.md5sum == locator.md5sum)
            )
            binary = bin_result.scalars().first()
            return binary.id if binary else None

    async def load_dwarf_types(self, binary_path: str) -> tuple[int, int]:
        """
        Extract DWARF type definitions from a binary and store in DB.

        Idempotent: skips if DwarfType records already exist for this binary.

        Returns:
            (type_count, member_count) inserted
        """
        from blackadder.binutils.dwarf_parser import parse_dwarf_types

        binary_id = await self._get_binary_id_for_path(binary_path)
        if binary_id is None:
            raise ValueError(f"Binary not in DB: {binary_path}. Run 'load' first.")

        # Phase 1: parse subprocess I/O outside any lock
        types, members = await parse_dwarf_types(binary_path, self.config)

        if not types:
            return 0, 0

        # Phase 2: idempotency check + raw-SQL bulk insert under lock.
        # ORM add_all+flush was ~3 s/binary due to per-object Python overhead.
        # executemany with raw SQL is 20-50x faster and holds the lock far shorter.
        _wl_t0 = time.monotonic()
        async with self._write_lock:
            _wl_wait = time.monotonic() - _wl_t0
            self._write_lock_stats["wait"] += _wl_wait
            _wl_cs_t0 = time.monotonic()
            async with self.manager.engine.begin() as conn:
                # Idempotency check
                row = await conn.execute(
                    _SA_TEXT("SELECT 1 FROM dwarftype WHERE binary_id=:bid LIMIT 1"),
                    {"bid": binary_id},
                )
                if row.first() is not None:
                    logger.debug("dwarf_types_already_loaded", extra={"binary": binary_path})
                    self._write_lock_stats["held"] += time.monotonic() - _wl_cs_t0
                    return 0, 0

                # Bulk insert DwarfType rows
                await conn.execute(
                    _SA_TEXT(
                        "INSERT INTO dwarftype (binary_id, die_offset, tag, name, byte_size, type_ref, encoding)"
                        " VALUES (:binary_id, :die_offset, :tag, :name, :byte_size, :type_ref, :encoding)"
                    ),
                    [
                        {
                            "binary_id": binary_id,
                            "die_offset": t["die_offset"],
                            "tag": t["tag"],
                            "name": t.get("name"),
                            "byte_size": t.get("byte_size"),
                            "type_ref": t.get("type_ref"),
                            "encoding": t.get("encoding"),
                        }
                        for t in types
                    ],
                )

                # Fetch die_offset → db id for member linkage
                rows = await conn.execute(
                    _SA_TEXT("SELECT id, die_offset FROM dwarftype WHERE binary_id=:bid"),
                    {"bid": binary_id},
                )
                die_to_id: dict[int, int] = {r.die_offset: r.id for r in rows}

                # Bulk insert DwarfMember rows
                member_rows = [
                    {
                        "type_id": die_to_id[m["parent_die_offset"]],
                        "name": m.get("name"),
                        "byte_offset": m["byte_offset"],
                        "member_type_ref": m["member_type_ref"],
                    }
                    for m in members
                    if m["parent_die_offset"] in die_to_id
                ]
                if member_rows:
                    await conn.execute(
                        _SA_TEXT(
                            "INSERT INTO dwarfmember (type_id, name, byte_offset, member_type_ref)"
                            " VALUES (:type_id, :name, :byte_offset, :member_type_ref)"
                        ),
                        member_rows,
                    )
            self._write_lock_stats["held"] += time.monotonic() - _wl_cs_t0

        logger.debug(
            "dwarf_types_loaded",
            extra={"binary": binary_path, "types": len(types), "members": len(members)},
        )
        return len(types), len(members)

    async def load_debug_line(self, binary_path: str) -> int:
        """
        Extract source line→address mappings from a binary and store in DB.

        Idempotent: skips if DebugLine records already exist for this binary.

        Returns:
            Number of records inserted
        """
        from blackadder.binutils.dwarf_parser import parse_debug_line

        binary_id = await self._get_binary_id_for_path(binary_path)
        if binary_id is None:
            raise ValueError(f"Binary not in DB: {binary_path}. Run 'load' first.")

        # Phase 1: parse subprocess I/O outside any lock
        records = await parse_debug_line(binary_path, self.config)

        if not records:
            return 0

        # Deduplicate in memory before acquiring lock
        seen: set[tuple[str, int, int]] = set()
        deduped = []
        for r in records:
            key = (r["source_file"], r["line_number"], r["address"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        # Phase 2: idempotency check + raw-SQL bulk insert under lock
        _wl_t0 = time.monotonic()
        async with self._write_lock:
            _wl_wait = time.monotonic() - _wl_t0
            self._write_lock_stats["wait"] += _wl_wait
            _wl_cs_t0 = time.monotonic()
            async with self.manager.engine.begin() as conn:
                row = await conn.execute(
                    _SA_TEXT("SELECT 1 FROM debugline WHERE binary_id=:bid LIMIT 1"),
                    {"bid": binary_id},
                )
                if row.first() is not None:
                    logger.debug("debug_line_already_loaded", extra={"binary": binary_path})
                    self._write_lock_stats["held"] += time.monotonic() - _wl_cs_t0
                    return 0

                await conn.execute(
                    _SA_TEXT(
                        "INSERT INTO debugline (binary_id, source_file, line_number, address)"
                        " VALUES (:binary_id, :source_file, :line_number, :address)"
                    ),
                    [
                        {
                            "binary_id": binary_id,
                            "source_file": r["source_file"],
                            "line_number": r["line_number"],
                            "address": r["address"],
                        }
                        for r in deduped
                    ],
                )
            self._write_lock_stats["held"] += time.monotonic() - _wl_cs_t0

        logger.debug("debug_line_loaded", extra={"binary": binary_path, "count": len(seen)})
        return len(seen)

    # -------------------------------------------------------------------------
    # Streaming producer-consumer API
    # -------------------------------------------------------------------------

    async def load_dwarf_types_streaming(
        self,
        binary_path: str,
        queue: asyncio.Queue,
    ) -> None:
        """
        Parse DWARF types from binary and enqueue InsertBatch messages.

        Runs objdump + parsing in a thread pool worker via asyncio.to_thread so
        multiple binaries can be parsed in parallel on different CPU cores
        (the GIL is released during subprocess I/O in each thread).
        Does NOT write to DB — that is done by run_db_writer().
        """
        from blackadder.binutils.dwarf_parser import _sync_parse_dwarf_types
        from blackadder.binutils.parser import BinToolsParser

        binary_id = await self._get_binary_id_for_path(binary_path)
        if binary_id is None:
            logger.debug("dwarf_streaming_skip_not_loaded", extra={"binary": binary_path})
            return

        bintool = BinToolsParser(self.config)
        try:
            # Acquire subprocess semaphore before entering the thread so the
            # concurrency cap applies to threads the same way it did to coroutines.
            async with bintool.subprocess_sem:
                all_types, all_members = await asyncio.to_thread(
                    _sync_parse_dwarf_types,
                    binary_path,
                    self.config.objdump_path,
                )
        except Exception as e:
            logger.warning("dwarf_streaming_failed", extra={"binary": binary_path, "error": str(e)})
            return

        if not all_types and not all_members:
            return

        # Enqueue types in chunks; attach all members to the final chunk so
        # all die_offset→id mappings are resolved before members are inserted.
        chunk_size = 2000
        first = True
        if all_types:
            for i in range(0, len(all_types), chunk_size):
                is_last = (i + chunk_size >= len(all_types))
                await queue.put(InsertBatch(
                    kind="dwarf",
                    binary_id=binary_id,
                    rows=all_types[i:i + chunk_size],
                    member_rows=all_members if is_last else [],
                    first_chunk=first,
                ))
                first = False
        elif all_members:
            # No types but members exist (unusual); send members alone
            await queue.put(InsertBatch(
                kind="dwarf",
                binary_id=binary_id,
                rows=[],
                member_rows=all_members,
                first_chunk=True,
            ))

    async def load_debug_line_streaming(
        self,
        binary_path: str,
        queue: asyncio.Queue,
    ) -> None:
        """
        Parse debug line records from binary and enqueue InsertBatch messages.

        Runs readelf + parsing in a thread pool worker for multi-core parallelism.
        """
        from blackadder.binutils.dwarf_parser import _sync_parse_debug_line
        from blackadder.binutils.parser import BinToolsParser

        binary_id = await self._get_binary_id_for_path(binary_path)
        if binary_id is None:
            return

        bintool = BinToolsParser(self.config)
        try:
            async with bintool.subprocess_sem:
                records = await asyncio.to_thread(
                    _sync_parse_debug_line,
                    binary_path,
                    self.config.readelf_path,
                )
        except Exception as e:
            logger.warning("debugline_streaming_failed", extra={"binary": binary_path, "error": str(e)})
            return

        if not records:
            return

        chunk_size = 2000
        first = True
        for i in range(0, len(records), chunk_size):
            await queue.put(InsertBatch(
                kind="debugline",
                binary_id=binary_id,
                rows=records[i:i + chunk_size],
                first_chunk=first,
            ))
            first = False

    async def run_db_writer(
        self,
        queue: asyncio.Queue,
        live: dict[str, int] | None = None,
    ) -> dict[str, int]:
        """
        Single-consumer DB writer task for streaming load.

        Reads InsertBatch messages from queue, writes to DB using raw SQL.
        No _write_lock needed — this is the only writer for dwarf/debugline tables.
        WAL checkpoint issued every 50 commits to keep WAL file small.

        live: optional shared dict updated in-place with running counters:
            types, lines, retries — read by CLI progress refresh.

        Send DB_SENTINEL (None) to signal end of stream.

        Returns stats dict with written_types, written_members, written_lines, commits.
        """
        written_types = written_members = written_lines = commits = 0
        # binary_id sets for idempotency — checked only on first_chunk
        already_dwarf: set[int] = set()
        already_debugline: set[int] = set()
        # Per-binary die_offset → db id maps (needed for member linkage across chunks)
        die_to_id: dict[int, dict[int, int]] = {}  # binary_id → {die_offset: db_id}

        while True:
            # Block waiting for the first batch, then drain up to 32 more
            # without waiting — write them all in a single transaction.
            batch = await queue.get()
            if batch is DB_SENTINEL:
                break

            pending: list = [batch]
            while len(pending) < 8:
                try:
                    nxt = queue.get_nowait()
                    if nxt is DB_SENTINEL:
                        # Put sentinel back so the outer loop can see it
                        await queue.put(DB_SENTINEL)
                        break
                    pending.append(nxt)
                except asyncio.QueueEmpty:
                    break

            # Retry loop: SQLite "database is locked" can happen when load_binary
            # holds a write transaction concurrently.  WAL + busy_timeout handle
            # most cases at the driver level, but aiosqlite sometimes raises before
            # the timeout kicks in.  Retry up to 8 times with exponential backoff.
            _max_attempts = 8
            for _attempt in range(_max_attempts):
                try:
                    async with self.manager.engine.begin() as conn:
                        for b in pending:
                            if b.kind == "dwarf":
                                if b.first_chunk:
                                    row = await conn.execute(
                                        _SA_TEXT("SELECT 1 FROM dwarftype WHERE binary_id=:bid LIMIT 1"),
                                        {"bid": b.binary_id},
                                    )
                                    if row.first() is not None:
                                        already_dwarf.add(b.binary_id)
                                        logger.debug("dwarf_writer_skip_existing", extra={"binary_id": b.binary_id})

                                if b.binary_id in already_dwarf:
                                    continue

                                if b.rows:
                                    await conn.execute(
                                        _SA_TEXT(
                                            "INSERT OR IGNORE INTO dwarftype"
                                            " (binary_id, die_offset, tag, name, byte_size, type_ref, encoding)"
                                            " VALUES (:binary_id, :die_offset, :tag, :name,"
                                            " :byte_size, :type_ref, :encoding)"
                                        ),
                                        [{"binary_id": b.binary_id, **r} for r in b.rows],
                                    )
                                    written_types += len(b.rows)

                                    rows = await conn.execute(
                                        _SA_TEXT("SELECT id, die_offset FROM dwarftype WHERE binary_id=:bid"),
                                        {"bid": b.binary_id},
                                    )
                                    if b.binary_id not in die_to_id:
                                        die_to_id[b.binary_id] = {}
                                    die_to_id[b.binary_id].update({r.die_offset: r.id for r in rows})

                                if b.member_rows:
                                    d2i = die_to_id.get(b.binary_id, {})
                                    member_params = [
                                        {
                                            "type_id": d2i[m["parent_die_offset"]],
                                            "name": m.get("name"),
                                            "byte_offset": m["byte_offset"],
                                            "member_type_ref": m["member_type_ref"],
                                        }
                                        for m in b.member_rows
                                        if m["parent_die_offset"] in d2i
                                    ]
                                    if member_params:
                                        await conn.execute(
                                            _SA_TEXT(
                                                "INSERT INTO dwarfmember"
                                                " (type_id, name, byte_offset, member_type_ref)"
                                                " VALUES (:type_id, :name, :byte_offset, :member_type_ref)"
                                            ),
                                            member_params,
                                        )
                                        written_members += len(member_params)

                            elif b.kind == "debugline":
                                if b.first_chunk:
                                    row = await conn.execute(
                                        _SA_TEXT("SELECT 1 FROM debugline WHERE binary_id=:bid LIMIT 1"),
                                        {"bid": b.binary_id},
                                    )
                                    if row.first() is not None:
                                        already_debugline.add(b.binary_id)

                                if b.binary_id in already_debugline:
                                    continue

                                if b.rows:
                                    await conn.execute(
                                        _SA_TEXT(
                                            "INSERT OR IGNORE INTO debugline"
                                            " (binary_id, source_file, line_number, address)"
                                            " VALUES (:binary_id, :source_file, :line_number, :address)"
                                        ),
                                        [{"binary_id": b.binary_id, **r} for r in b.rows],
                                    )
                                    written_lines += len(b.rows)

                        commits += 1
                        if live is not None:
                            live["types"] = written_types
                            live["lines"] = written_lines
                    break  # transaction committed — exit retry loop

                except Exception as e:
                    _is_locked = "database is locked" in str(e) or "database table is locked" in str(e)
                    if _is_locked and _attempt < _max_attempts - 1:
                        _delay = 0.05 * (2 ** _attempt)  # 50ms, 100ms, 200ms … 6.4s
                        if live is not None:
                            live["retries"] = live.get("retries", 0) + 1
                        logger.debug(
                            "db_writer_retry",
                            extra={"attempt": _attempt + 1, "delay": _delay,
                                   "batches": len(pending)},
                        )
                        await asyncio.sleep(_delay)
                    else:
                        logger.error(
                            "db_writer_error",
                            extra={"batches": len(pending),
                                   "attempt": _attempt + 1, "error": str(e)},
                        )
                        break

            # WAL checkpoint outside any transaction, every 50 commits
            if commits > 0 and commits % 50 == 0:
                try:
                    async with self.manager.engine.connect() as ck_conn:
                        await ck_conn.execute(_SA_TEXT("PRAGMA wal_checkpoint(PASSIVE)"))
                except Exception:
                    pass

        # Final checkpoint
        try:
            async with self.manager.engine.connect() as ck_conn:
                await ck_conn.execute(_SA_TEXT("PRAGMA wal_checkpoint(PASSIVE)"))
        except Exception:
            pass

        logger.debug(
            "db_writer_done",
            extra={
                "written_types": written_types,
                "written_members": written_members,
                "written_lines": written_lines,
                "commits": commits,
            },
        )
        return {
            "written_types": written_types,
            "written_members": written_members,
            "written_lines": written_lines,
            "commits": commits,
        }
