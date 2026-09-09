"""Tests for SQLite connection integrity and schema upgrades."""

import sqlite3

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

from blackadder.db.base import configure_sqlite_connection
from blackadder.db.migrations import LATEST_SCHEMA_VERSION, run_migrations


def test_sqlite_connections_enforce_foreign_keys():
    connection = sqlite3.connect(":memory:")
    configure_sqlite_connection(connection)
    connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
    connection.execute("CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))")

    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("INSERT INTO child (parent_id) VALUES (99)")


def test_legacy_dwarf_schema_migrates_binary_local_members():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE canonical_dwarf_type ("
                "id INTEGER PRIMARY KEY, tag TEXT NOT NULL, name TEXT, "
                "byte_size INTEGER, encoding TEXT)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE binary_dwarf_ref ("
                "id INTEGER PRIMARY KEY, binary_id INTEGER NOT NULL, "
                "die_offset INTEGER NOT NULL, canonical_id INTEGER NOT NULL, "
                "type_ref_die INTEGER)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE dwarfmember ("
                "id INTEGER PRIMARY KEY, canonical_type_id INTEGER NOT NULL, "
                "name TEXT, byte_offset INTEGER NOT NULL, "
                "member_type_ref INTEGER NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO canonical_dwarf_type "
                "(id, tag, name, byte_size, encoding) VALUES "
                "(10, 'structure_type', 'same', 8, NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO binary_dwarf_ref "
                "(id, binary_id, die_offset, canonical_id) VALUES "
                "(101, 1, 16, 10), (202, 2, 32, 10)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO dwarfmember "
                "(canonical_type_id, name, byte_offset, member_type_ref) "
                "VALUES (10, 'field', 0, 48)"
            )
        )

        run_migrations(connection)

        member_columns = {
            column["name"] for column in inspect(connection).get_columns("dwarfmember")
        }
        members = connection.execute(
            text("SELECT binary_ref_id, name FROM dwarfmember ORDER BY binary_ref_id")
        ).all()
        identity = connection.execute(
            text("SELECT identity_key FROM canonical_dwarf_type WHERE id=10")
        ).scalar_one()
        version = connection.exec_driver_sql("PRAGMA user_version").scalar_one()

    assert member_columns >= {"binary_ref_id", "name"}
    assert "canonical_type_id" not in member_columns
    assert members == [(101, "field"), (202, "field")]
    assert len(identity) == 64
    assert version == LATEST_SCHEMA_VERSION


def test_fresh_and_repeated_initialization_reach_latest_schema():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        run_migrations(connection)
        SQLModel.metadata.create_all(connection)
        run_migrations(connection)

        canonical_columns = {
            column["name"] for column in inspect(connection).get_columns("canonical_dwarf_type")
        }
        member_columns = {
            column["name"] for column in inspect(connection).get_columns("dwarfmember")
        }
        version = connection.exec_driver_sql("PRAGMA user_version").scalar_one()

    assert "identity_key" in canonical_columns
    assert "binary_ref_id" in member_columns
    assert "canonical_type_id" not in member_columns
    assert version == LATEST_SCHEMA_VERSION
