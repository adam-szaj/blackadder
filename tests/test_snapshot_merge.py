"""
Tests for ProcessSnapshot create/update semantics.

Covers:
- resolve_snapshot: 4 rules + edge cases (not found, tag conflict)
- merge_into_snapshot: additive maps, threads, backtraces, registers, tag, sources_json
"""

import json
import pytest
import pytest_asyncio

from blackadder.config import BlackadderConfig
from blackadder.db import AsyncDatabaseManager, ProcessDatabase
from blackadder.exceptions import DatabaseConstraintError, ProcessNotFoundError
from blackadder.models import (
    BacktraceEntry,
    MemoryMapping,
    ProcessRegisterState,
    ProcessSnapshot,
    Thread,
)
from sqlmodel import select


# ============================================================================
# Fixtures
# ============================================================================

MAPS_A = """\
555555554000-555555575000 r-xp 00000000 08:01 1  /bin/app
7ffff7e00000-7ffff7e1c000 r-xp 00000000 08:01 2  /lib/libc.so.6
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0  [stack]
"""

MAPS_B = """\
7ffff7c00000-7ffff7c28000 r-xp 00000000 08:01 3  /lib/ld.so
7ffff7fdd000-7ffff7ffe000 rw-p 00000000 00:00 0  [vvar]
"""

GDB_DUMP_SIMPLE = """\
Thread 1 (LWP 100 "worker"):
#0  0x00007f00 in pthread_mutex_lock ()
#1  0x00400a1c in main ()

Thread 2 (LWP 101 "helper"):
#0  0x00007f01 in sem_wait ()
"""

GDB_DUMP_WITH_REGS = """\
Thread 1 (LWP 200 "app"):
#0  0x00007f00 in do_work ()

(gdb)
rax            0x1   1
rbx            0x0   0
rip            0x7f00  0x7f00
"""


@pytest_asyncio.fixture
async def db() -> ProcessDatabase:
    config = BlackadderConfig(
        max_subprocess_workers=2,
        max_symbol_cache_size=100,
    )
    manager = AsyncDatabaseManager("sqlite+aiosqlite:///:memory:")
    await manager.create_all()
    proc_db = ProcessDatabase(manager, config)
    yield proc_db
    await manager.close()


async def _make_snapshot(db: ProcessDatabase, tag=None, pid=None) -> ProcessSnapshot:
    """Helper: create a minimal snapshot without /proc or binary resolution."""
    async with db.manager.get_session() as session:
        snap = ProcessSnapshot(
            pid=pid,
            description="test",
            source_type="maps",
            tag=tag,
        )
        session.add(snap)
        await session.commit()
        snap_id = snap.id

    async with db.manager.get_session() as session:
        result = await session.execute(
            select(ProcessSnapshot).where(ProcessSnapshot.id == snap_id)
        )
        return result.scalars().first()


async def _add_mapping(db: ProcessDatabase, process_id: int, start: int, end: int):
    async with db.manager.get_session() as session:
        m = MemoryMapping(
            process_id=process_id,
            start_addr=start,
            end_addr=end,
            perms="r-xp",
            offset=0,
            pathname="/bin/app",
        )
        session.add(m)
        await session.commit()


# ============================================================================
# resolve_snapshot — 4 rules
# ============================================================================


@pytest.mark.asyncio
class TestResolveSnapshot:

    async def test_rule1_no_tag_no_id_returns_none(self, db):
        """No tag, no id → always create new."""
        result = await db.resolve_snapshot(tag=None, snapshot_id=None)
        assert result is None

    async def test_rule2_tag_not_found_returns_none(self, db):
        """tag given but not in DB → create new."""
        result = await db.resolve_snapshot(tag="nonexistent", snapshot_id=None)
        assert result is None

    async def test_rule2_tag_found_returns_snapshot(self, db):
        """tag given and found → return existing snapshot."""
        snap = await _make_snapshot(db, tag="myapp")
        result = await db.resolve_snapshot(tag="myapp", snapshot_id=None)
        assert result is not None
        assert result.id == snap.id

    async def test_rule3_snapshot_id_found(self, db):
        """snapshot_id given and found → return it."""
        snap = await _make_snapshot(db)
        result = await db.resolve_snapshot(tag=None, snapshot_id=snap.id)
        assert result is not None
        assert result.id == snap.id

    async def test_rule3_snapshot_id_not_found(self, db):
        """snapshot_id given but not in DB → raise ProcessNotFoundError."""
        with pytest.raises(ProcessNotFoundError, match="9999"):
            await db.resolve_snapshot(tag=None, snapshot_id=9999)

    async def test_rule4_tag_and_id_consistent(self, db):
        """tag and id, tag matches snapshot's own tag → OK."""
        snap = await _make_snapshot(db, tag="crash")
        result = await db.resolve_snapshot(tag="crash", snapshot_id=snap.id)
        assert result is not None
        assert result.id == snap.id

    async def test_rule4_tag_and_id_new_tag_unclaimed(self, db):
        """tag and id, tag not used by anyone → OK (merge will set tag)."""
        snap = await _make_snapshot(db, tag=None)
        result = await db.resolve_snapshot(tag="newtag", snapshot_id=snap.id)
        assert result is not None
        assert result.id == snap.id

    async def test_rule4_tag_belongs_to_other_snapshot(self, db):
        """tag belongs to a different snapshot → raise DatabaseConstraintError."""
        snap_a = await _make_snapshot(db, tag="alpha")
        snap_b = await _make_snapshot(db, tag=None)
        with pytest.raises(DatabaseConstraintError, match="alpha"):
            await db.resolve_snapshot(tag="alpha", snapshot_id=snap_b.id)


# ============================================================================
# merge_into_snapshot — maps
# ============================================================================


@pytest.mark.asyncio
class TestMergeMaps:

    async def test_new_mappings_are_added(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(MemoryMapping).where(MemoryMapping.process_id == snap.id)
            )
            mappings = result.scalars().all()

        assert len(mappings) == 3

    async def test_duplicate_start_addr_skipped(self, db):
        snap = await _make_snapshot(db)
        await _add_mapping(db, snap.id, start=0x555555554000, end=0x555555575000)

        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(MemoryMapping).where(MemoryMapping.process_id == snap.id)
            )
            mappings = result.scalars().all()

        # Only 2 new added (first one was duplicate)
        assert len(mappings) == 3

    async def test_merge_twice_no_duplicates(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")
        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(MemoryMapping).where(MemoryMapping.process_id == snap.id)
            )
            assert len(result.scalars().all()) == 3

    async def test_different_maps_both_added(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")
        await db.merge_into_snapshot(snap, maps_text=MAPS_B, rootfs="/nonexistent")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(MemoryMapping).where(MemoryMapping.process_id == snap.id)
            )
            assert len(result.scalars().all()) == 5


# ============================================================================
# merge_into_snapshot — GDB dump (threads + backtraces + registers)
# ============================================================================


@pytest.mark.asyncio
class TestMergeGdbDump:

    async def test_new_threads_created(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(Thread).where(Thread.process_id == snap.id)
            )
            threads = result.scalars().all()

        assert len(threads) == 2
        tids = {t.tid for t in threads}
        assert tids == {100, 101}

    async def test_thread_names_set(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(Thread).where(Thread.process_id == snap.id)
            )
            names = {t.name for t in result.scalars().all()}

        assert "worker" in names
        assert "helper" in names

    async def test_backtraces_created(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(BacktraceEntry).where(BacktraceEntry.process_id == snap.id)
            )
            entries = result.scalars().all()

        assert len(entries) == 3  # 2 frames in thread 1, 1 frame in thread 2

    async def test_duplicate_backtrace_frames_skipped(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(BacktraceEntry).where(BacktraceEntry.process_id == snap.id)
            )
            assert len(result.scalars().all()) == 3

    async def test_thread_name_filled_from_gdb(self, db):
        """Existing thread with no name gets name from GDB dump."""
        snap = await _make_snapshot(db)
        async with db.manager.get_session() as session:
            t = Thread(process_id=snap.id, tid=200, name=None)
            session.add(t)
            await session.commit()

        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_WITH_REGS)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(Thread).where(
                    (Thread.process_id == snap.id) & (Thread.tid == 200)
                )
            )
            t = result.scalars().first()
        assert t.name == "app"

    async def test_registers_stored(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_WITH_REGS)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessRegisterState).where(
                    ProcessRegisterState.process_id == snap.id
                )
            )
            regs = result.scalars().all()

        assert len(regs) == 1
        parsed = json.loads(regs[0].registers_json)
        assert parsed["rax"] == 1
        assert parsed["rip"] == 0x7F00

    async def test_registers_not_duplicated(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_WITH_REGS)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_WITH_REGS)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessRegisterState).where(
                    ProcessRegisterState.process_id == snap.id
                )
            )
            assert len(result.scalars().all()) == 1


# ============================================================================
# merge_into_snapshot — tag + sources_json
# ============================================================================


@pytest.mark.asyncio
class TestMergeMetadata:

    async def test_tag_set_when_none(self, db):
        snap = await _make_snapshot(db, tag=None)
        updated = await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE, new_tag="crash")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap.id)
            )
            s = result.scalars().first()
        assert s.tag == "crash"

    async def test_tag_unchanged_when_same(self, db):
        snap = await _make_snapshot(db, tag="existing")
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE, new_tag="existing")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap.id)
            )
            s = result.scalars().first()
        assert s.tag == "existing"

    async def test_force_tag_steals_from_other(self, db):
        snap_a = await _make_snapshot(db, tag="shared")
        snap_b = await _make_snapshot(db, tag=None)

        await db.merge_into_snapshot(
            snap_b, gdb_text=GDB_DUMP_SIMPLE, new_tag="shared", force_tag=True
        )

        async with db.manager.get_session() as session:
            a = (await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap_a.id)
            )).scalars().first()
            b = (await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap_b.id)
            )).scalars().first()

        assert b.tag == "shared"
        assert a.tag is None

    async def test_sources_json_updated_for_gdb(self, db):
        snap = await _make_snapshot(db)
        assert json.loads(snap.sources_json) == []

        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap.id)
            )
            s = result.scalars().first()

        sources = json.loads(s.sources_json)
        assert {"type": "gdb_dump"} in sources

    async def test_sources_json_not_duplicated(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap.id)
            )
            s = result.scalars().first()

        sources = json.loads(s.sources_json)
        gdb_entries = [e for e in sources if e.get("type") == "gdb_dump"]
        assert len(gdb_entries) == 1

    async def test_source_type_extended(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap.id)
            )
            s = result.scalars().first()

        assert "maps" in s.source_type

    async def test_source_type_combined(self, db):
        snap = await _make_snapshot(db)
        await db.merge_into_snapshot(snap, maps_text=MAPS_A, rootfs="/nonexistent")
        await db.merge_into_snapshot(snap, gdb_text=GDB_DUMP_SIMPLE)

        async with db.manager.get_session() as session:
            result = await session.execute(
                select(ProcessSnapshot).where(ProcessSnapshot.id == snap.id)
            )
            s = result.scalars().first()

        assert "maps" in s.source_type
        assert "gdb_dump" in s.source_type
