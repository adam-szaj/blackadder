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
from dataclasses import dataclass

from sqlalchemy import text as _SA_TEXT
from sqlmodel import select

from blackadder.binutils.hasher import FunctionHasher
from blackadder.models import (
    Binary,
    BinaryLocator,
    FunctionFingerprint,
    SectionHeader,
    Symbol,
    addr_to_db,
    dwarf_identity_key,
)

from .base import AsyncDatabaseManager

logger = logging.getLogger("blackadder.db.rootfs")


@dataclass
class BinaryPayload:
    """All data collected for one binary — pure I/O, no DB IDs."""

    binary_path: str
    md5sum: str
    name: str
    mtime: int
    debug_link: str | None
    debug_file_path: str | None
    sym_source: str  # debug_file_path or binary_path
    sections: dict  # {name: {size, vma, lma, off, align}}
    symbols: list[tuple]  # (address, scope, sym_type, section, size, name)
    dwarf_types: list[tuple]  # (die_offset, tag, name, byte_size, type_ref, encoding)
    dwarf_members: list[tuple]  # (parent_die_offset, name, byte_offset, member_type_ref)
    dwarf_vars: list[
        tuple
    ]  # (subprogram_die_offset, die_offset, tag, name, type_ref, loc_type, loc_fbreg, loc_reg)
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
                            loc_stmt = select(BinaryLocator).where(
                                BinaryLocator.path == binary_path
                            )
                            loc_result = await session.execute(loc_stmt)
                            locator = loc_result.scalars().first()
                            if not locator:
                                session.add(
                                    BinaryLocator(
                                        path=binary_path,
                                        md5sum=md5sum,
                                        mtime=mtime,
                                        debug_file=debug_file_path,
                                    )
                                )
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
                                    Symbol.__table__.delete().where(  # type: ignore[attr-defined]
                                        Symbol.binary_id == existing.id
                                    )
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

                            session.add(
                                BinaryLocator(
                                    path=binary_path,
                                    md5sum=md5sum,
                                    mtime=mtime,
                                    debug_file=debug_file_path,
                                )
                            )

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
                            extra={
                                "binary": binary_path,
                                "source": sym_source,
                                "count": len(syms_data),
                            },
                        )

                        await session.commit()
                    break  # success
                except Exception as _e:
                    if (
                        "database is locked" in str(_e) or "database table is locked" in str(_e)
                    ) and _lb_attempt < 7:
                        await asyncio.sleep(0.05 * (2**_lb_attempt))
                    else:
                        raise
            self._write_lock_stats["held"] += time.monotonic() - _wl_cs_t0

        # Re-fetch outside the session to avoid detached state
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.id == binary_id))
            result_binary = result.scalars().first()

        if result_binary is None:
            raise RuntimeError(f"Binary disappeared after insert: id={binary_id}")

        return result_binary, True, debug_file_path

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
        dwarf_vars: list[tuple] = []
        debug_lines: list[tuple] = []

        # --types implies --lines
        effective_lines = load_lines or load_types

        if load_types:
            try:
                async with parser.subprocess_sem:
                    dt_raw, dm_raw, dv_raw = await asyncio.to_thread(
                        _sync_parse_dwarf_types, sym_source, self.config.objdump_path
                    )
                dwarf_types = [
                    (
                        t["die_offset"],
                        t["tag"],
                        t["name"],
                        t["byte_size"],
                        t["type_ref"],
                        t["encoding"],
                    )
                    for t in dt_raw
                ]
                dwarf_members = [
                    (m["parent_die_offset"], m.get("name"), m["byte_offset"], m["member_type_ref"])
                    for m in dm_raw
                ]
                dwarf_vars = [
                    (
                        v["subprogram_die_offset"],
                        v["die_offset"],
                        v["tag"],
                        v.get("name"),
                        v.get("type_ref"),
                        v.get("location_type"),
                        v.get("location_fbreg"),
                        v.get("location_register"),
                    )
                    for v in dv_raw
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
                    (dl["source_file"], dl["line_number"], dl["address"]) for dl in dl_raw
                ]
            except Exception as e:
                logger.debug(
                    "debugline_collect_failed", extra={"binary": binary_path, "error": str(e)}
                )

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
            dwarf_vars=dwarf_vars,
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
        symbols_already_ok = False

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
                    {
                        "path": payload.binary_path,
                        "md5": payload.md5sum,
                        "mtime": payload.mtime,
                        "dbg": payload.debug_file_path,
                    },
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
                    "INSERT INTO binary (md5sum, name, debug_link) VALUES (:md5, :name, :dblink)"
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
                    [
                        (
                            binary_id,
                            idx,
                            sname[:32],
                            s["size"],
                            addr_to_db(s["vma"]),
                            addr_to_db(s["lma"]),
                            s["off"],
                            s["align"],
                        )
                        for idx, (sname, s) in enumerate(payload.sections.items())
                    ],
                )

            await conn.execute(
                _SA_TEXT(
                    "INSERT OR IGNORE INTO binarylocator (path, md5sum, mtime, debug_file)"
                    " VALUES (:path, :md5, :mtime, :dbg)"
                ),
                {
                    "path": payload.binary_path,
                    "md5": payload.md5sum,
                    "mtime": payload.mtime,
                    "dbg": payload.debug_file_path,
                },
            )

        # Symbols (bulk, shared path for new and reload — skip if already loaded)
        if payload.symbols and not symbols_already_ok:
            await raw_conn.executemany(
                "INSERT OR IGNORE INTO symbol"
                " (binary_id, address, scope, sym_type, section, size, name)"
                " VALUES (?,?,?,?,?,?,?)",
                [(binary_id, addr_to_db(s[0]), *s[1:]) for s in payload.symbols],
            )

        written_types = written_members = written_lines = 0

        die_to_canonical: dict[int, int] = {}

        if payload.load_types and payload.dwarf_types:
            # Skip if already loaded for this binary
            ref_check = await conn.execute(
                _SA_TEXT("SELECT 1 FROM binary_dwarf_ref WHERE binary_id=:bid LIMIT 1"),
                {"bid": binary_id},
            )
            if ref_check.first() is None:
                # 1. Upsert canonical types (global dedup by tag+name+byte_size+encoding)
                # dwarf_types tuple: (die_offset, tag, name, byte_size, type_ref, encoding)
                canonical_rows = list(
                    {
                        (
                            dwarf_identity_key(t[1], t[2], t[3], t[5]),
                            t[1],
                            t[2],
                            t[3],
                            t[5],
                        )
                        for t in payload.dwarf_types
                    }
                )
                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO canonical_dwarf_type"
                    " (identity_key, tag, name, byte_size, encoding)"
                    " VALUES (?,?,?,?,?)",
                    canonical_rows,
                )

                # 2. Fetch canonical IDs by deterministic, non-null identity.
                keys_needed = [r[0] for r in canonical_rows]
                key_ph = ",".join("?" * len(keys_needed))
                cursor = await raw_conn.execute(
                    f"SELECT id, identity_key FROM canonical_dwarf_type"
                    f" WHERE identity_key IN ({key_ph})",
                    keys_needed,
                )
                canon_map: dict[str, int] = {row[1]: row[0] for row in await cursor.fetchall()}

                # 3. INSERT binary_dwarf_ref — die_offset → canonical_id + type_ref_die
                ref_rows = [
                    (
                        binary_id,
                        t[0],
                        canon_map[dwarf_identity_key(t[1], t[2], t[3], t[5])],
                        t[4],
                    )
                    for t in payload.dwarf_types
                    if dwarf_identity_key(t[1], t[2], t[3], t[5]) in canon_map
                ]
                await raw_conn.executemany(
                    "INSERT OR IGNORE INTO binary_dwarf_ref"
                    " (binary_id, die_offset, canonical_id, type_ref_die)"
                    " VALUES (?,?,?,?)",
                    ref_rows,
                )
                written_types = len(ref_rows)

                # Build binary-local maps used by members and variables.
                die_to_canonical = {
                    t[0]: canon_map[dwarf_identity_key(t[1], t[2], t[3], t[5])]
                    for t in payload.dwarf_types
                    if t[0] is not None and dwarf_identity_key(t[1], t[2], t[3], t[5]) in canon_map
                }
                ref_cursor = await raw_conn.execute(
                    "SELECT id, die_offset FROM binary_dwarf_ref WHERE binary_id=?",
                    (binary_id,),
                )
                die_to_ref = {row[1]: row[0] for row in await ref_cursor.fetchall()}

                # 4. INSERT dwarfmember owned by its binary-local parent DIE.
                if payload.dwarf_members:
                    # dwarf_members tuple: (parent_die_offset, name, byte_offset, member_type_ref)
                    member_rows = [
                        (die_to_ref[m[0]], m[1], m[2], m[3])
                        for m in payload.dwarf_members
                        if m[0] in die_to_ref
                    ]
                    if member_rows:
                        await raw_conn.executemany(
                            "INSERT INTO dwarfmember"
                            " (binary_ref_id, name, byte_offset, member_type_ref)"
                            " VALUES (?,?,?,?)",
                            member_rows,
                        )
                        written_members = len(member_rows)

                # 5. INSERT dwarfsubprogram + dwarfvariable
                if payload.dwarf_vars:
                    # Collect unique subprograms from types (tag="subprogram")
                    subprog_die_to_id: dict[int, int] = {}
                    subprog_tuples = [
                        (binary_id, t[0], t[2])  # (binary_id, die_offset, name)
                        for t in payload.dwarf_types
                        if t[1] == "subprogram" and t[0] is not None
                    ]
                    if subprog_tuples:
                        await raw_conn.executemany(
                            "INSERT OR IGNORE INTO dwarfsubprogram"
                            " (binary_id, die_offset, name) VALUES (?,?,?)",
                            subprog_tuples,
                        )
                        sp_cursor = await raw_conn.execute(
                            "SELECT id, die_offset FROM dwarfsubprogram WHERE binary_id=?",
                            (binary_id,),
                        )
                        subprog_die_to_id = {row[1]: row[0] for row in await sp_cursor.fetchall()}

                    # Resolve canonical_type_id for each variable's type_ref
                    # dwarf_vars tuple: (subprogram_die_offset, die_offset, tag, name,
                    #                    type_ref, location_type, location_fbreg, location_register)
                    var_rows = []
                    for v in payload.dwarf_vars:
                        (sp_die, v_die, vtag, vname, vtype_ref, vloc_type, vloc_fbreg, vloc_reg) = v
                        sp_id = subprog_die_to_id.get(sp_die) if sp_die is not None else None
                        # Resolve canonical_type_id via die_to_canonical (built above)
                        canon_type_id: int | None = None
                        if vtype_ref is not None:
                            canon_type_id = die_to_canonical.get(vtype_ref)
                        var_rows.append(
                            (
                                binary_id,
                                sp_id,
                                v_die,
                                vtag,
                                vname,
                                canon_type_id,
                                vloc_type,
                                vloc_fbreg,
                                vloc_reg,
                            )
                        )
                    if var_rows:
                        await raw_conn.executemany(
                            "INSERT OR IGNORE INTO dwarfvariable"
                            " (binary_id, subprogram_id, die_offset, tag, name,"
                            "  canonical_type_id, location_type, location_fbreg, location_register)"
                            " VALUES (?,?,?,?,?,?,?,?,?)",
                            var_rows,
                        )

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
                    [
                        (binary_id, path_to_id[dl[0]], dl[1], addr_to_db(dl[2]))
                        for dl in payload.debug_lines
                    ],
                )
                written_lines = len(payload.debug_lines)

        return {
            "loaded": 1,
            "skipped": 0,
            "types": written_types,
            "members": written_members,
            "lines": written_lines,
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
            "loaded": 0,
            "skipped": 0,
            "types": 0,
            "members": 0,
            "lines": 0,
            "commits": 0,
            # timing accumulators (ms)
            "t_queue_ms": 0,  # blocking on queue.get()
            "t_apply_ms": 0,  # _apply_payload SQL statements
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
                    batch_counts: dict[str, int] = {}
                    async with self.manager.engine.begin() as conn:
                        for p in pending:
                            _ta = _time.monotonic()
                            counts = await self._apply_payload(conn, p)
                            _t_apply += _time.monotonic() - _ta
                            for k, v in counts.items():
                                batch_counts[k] = batch_counts.get(k, 0) + v
                        # Time from last apply to commit = commit overhead
                        _t_before_commit = _time.monotonic()
                    # engine.begin() exited = COMMIT done
                    _t_after_commit = _time.monotonic()
                    for k, v in batch_counts.items():
                        total[k] = total.get(k, 0) + v
                    total["t_apply_ms"] += int(_t_apply * 1000)
                    total["t_commit_ms"] += int((_t_after_commit - _t_before_commit) * 1000)
                    total["commits"] = total.get("commits", 0) + 1
                    break
                except Exception as e:
                    _is_locked = "database is locked" in str(
                        e
                    ) or "database table is locked" in str(e)
                    if _is_locked and _attempt < _max_attempts - 1:
                        retries += 1
                        if live is not None:
                            live["retries"] = retries
                        await asyncio.sleep(0.05 * (2**_attempt))
                    else:
                        logger.error(
                            "payload_writer_error",
                            extra={
                                "batches": len(pending),
                                "attempt": _attempt + 1,
                                "error": str(e),
                            },
                        )
                        raise

            if live is not None:
                live["loaded"] = total["loaded"]
                live["skipped"] = total["skipped"]
                live["types"] = total["types"]
                live["lines"] = total["lines"]
                live["t_wait"] = total["t_queue_ms"]
                live["t_write"] = total["t_apply_ms"] + total["t_commit_ms"]

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
                .order_by(Symbol.address.desc())  # type: ignore[attr-defined]
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
