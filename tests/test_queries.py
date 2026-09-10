"""Regression tests for built-in SQL query definitions."""

import sqlite3

from baldrick.models import addr_to_db
from baldrick.queries import load_query_registry
from baldrick.query import BaldrickQuery


def test_deadlock_threads_uses_sqlmodel_table_name():
    sql = load_query_registry()["deadlock-threads"].sql

    assert "backtraceentry" in sql
    assert "backtrace_entry" not in sql


def test_snapshot_addr2line_accepts_unsigned_kernel_address(tmp_path):
    database_path = tmp_path / "kernel.db"
    load_address = 0xFFFF800000000000
    address = load_address + 0x10
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            "CREATE TABLE binary (id INTEGER PRIMARY KEY, name TEXT);"
            "CREATE TABLE memorymapping ("
            "id INTEGER PRIMARY KEY, process_id INTEGER, "
            "start_addr INTEGER, end_addr INTEGER);"
            "CREATE TABLE processbinary ("
            "process_id INTEGER, binary_id INTEGER, mapping_id INTEGER, "
            "binary_load_addr INTEGER);"
            "CREATE TABLE symbolcache ("
            "binary_id INTEGER, offset INTEGER, symbol TEXT, "
            "source_file TEXT, source_line INTEGER);"
        )
        connection.execute("INSERT INTO binary VALUES (1, 'kernel')")
        connection.execute(
            "INSERT INTO memorymapping VALUES (1, 7, ?, ?)",
            (addr_to_db(load_address), addr_to_db(load_address + 0x1000)),
        )
        connection.execute(
            "INSERT INTO processbinary VALUES (7, 1, 1, ?)",
            (addr_to_db(load_address),),
        )
        connection.execute("INSERT INTO symbolcache VALUES (1, 16, 'entry', 'kernel.c', 12)")

    frame = BaldrickQuery(str(database_path)).run("addr2line-snap", id=7, addr=hex(address))

    assert frame["symbol"].to_list() == ["entry"]
    assert frame["offset"].to_list() == [16]
