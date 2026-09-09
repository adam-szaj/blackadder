"""Regression tests for the bulk rootfs database writer."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from blackadder.config import BlackadderConfig
from blackadder.db.rootfs import PAYLOAD_SENTINEL, BinaryPayload, RootfsDatabase


class _Result:
    def __init__(self, row=None):
        self._row = row

    def first(self):
        return self._row

    async def fetchall(self):
        return self._row or []


class _RawConnection:
    def __init__(self):
        self.executemany_calls = []
        self.canonical_rows = []
        self.reference_rows = []

    async def executemany(self, statement, rows):
        self.executemany_calls.append((statement, rows))
        if "INTO canonical_dwarf_type" in statement:
            self.canonical_rows = rows
        elif "INTO binary_dwarf_ref" in statement:
            self.reference_rows = rows

    async def execute(self, statement, _parameters=None):
        if "SELECT id, identity_key FROM canonical_dwarf_type" in statement:
            return _Result([(501, row[0]) for row in self.canonical_rows])
        if "SELECT id, die_offset FROM binary_dwarf_ref" in statement:
            return _Result([(701 + index, row[1]) for index, row in enumerate(self.reference_rows)])
        return _Result([])


class _Connection:
    def __init__(self):
        self.raw = _RawConnection()
        self._binary_selects = 0

    async def get_raw_connection(self):
        return SimpleNamespace(driver_connection=self.raw)

    async def execute(self, statement, _parameters=None):
        sql = str(statement)
        if sql.startswith("SELECT id FROM binary"):
            self._binary_selects += 1
            if self._binary_selects == 1:
                return _Result()
            return _Result(SimpleNamespace(id=17))
        return _Result()


class _Transaction:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, _exc_type, _exc, _traceback):
        return False


class _Engine:
    def begin(self):
        return _Transaction()

    def connect(self):
        return _Transaction()


class _RetryTransaction(_Transaction):
    def __init__(self, fail_commit):
        self.fail_commit = fail_commit

    async def __aexit__(self, exc_type, exc, traceback):
        if exc_type is None and self.fail_commit:
            raise RuntimeError("database is locked")
        return False


class _RetryEngine(_Engine):
    def __init__(self):
        self.begin_calls = 0

    def begin(self):
        self.begin_calls += 1
        return _RetryTransaction(fail_commit=self.begin_calls == 1)


def _payload() -> BinaryPayload:
    return BinaryPayload(
        binary_path="/bin/example",
        md5sum="abc",
        name="example",
        mtime=1,
        debug_link=None,
        debug_file_path=None,
        sym_source="/bin/example",
        sections={},
        symbols=[(0x10, "g", "F", ".text", 4, "main")],
        dwarf_types=[],
        dwarf_members=[],
        dwarf_vars=[],
        debug_lines=[],
        load_types=False,
        load_lines=False,
    )


@pytest.mark.asyncio
async def test_apply_payload_writes_symbols_for_new_binary():
    database = RootfsDatabase(SimpleNamespace(), BlackadderConfig())
    connection = _Connection()

    counts = await database._apply_payload(connection, _payload())

    assert counts["loaded"] == 1
    symbol_calls = [
        rows for statement, rows in connection.raw.executemany_calls if "INTO symbol" in statement
    ]
    assert symbol_calls == [[(17, 0x10, "g", "F", ".text", 4, "main")]]


@pytest.mark.asyncio
async def test_apply_payload_owns_members_through_binary_reference():
    database = RootfsDatabase(SimpleNamespace(), BlackadderConfig())
    connection = _Connection()
    payload = _payload()
    payload.symbols = []
    payload.load_types = True
    payload.dwarf_types = [(0x10, "structure_type", "sample", 8, None, None)]
    payload.dwarf_members = [(0x10, "field", 0, 0x20)]

    counts = await database._apply_payload(connection, payload)

    member_calls = [
        rows
        for statement, rows in connection.raw.executemany_calls
        if "INTO dwarfmember" in statement
    ]
    assert member_calls == [[(701, "field", 0, 0x20)]]
    assert counts["members"] == 1


@pytest.mark.asyncio
async def test_payload_writer_propagates_terminal_batch_error():
    database = RootfsDatabase(SimpleNamespace(engine=_Engine()), BlackadderConfig())
    database._apply_payload = AsyncMock(side_effect=ValueError("invalid payload"))
    queue = asyncio.Queue()
    await queue.put(_payload())
    await queue.put(PAYLOAD_SENTINEL)

    with pytest.raises(ValueError, match="invalid payload"):
        await database.run_payload_writer(queue)


@pytest.mark.asyncio
async def test_payload_writer_counts_only_committed_attempt():
    database = RootfsDatabase(SimpleNamespace(engine=_RetryEngine()), BlackadderConfig())
    database._apply_payload = AsyncMock(
        return_value={
            "loaded": 1,
            "skipped": 0,
            "types": 0,
            "members": 0,
            "lines": 0,
        }
    )
    queue = asyncio.Queue()
    await queue.put(_payload())
    await queue.put(PAYLOAD_SENTINEL)

    counts = await database.run_payload_writer(queue)

    assert counts["loaded"] == 1
    assert counts["commits"] == 1
    assert database._apply_payload.await_count == 2
