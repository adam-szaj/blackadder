"""Integration tests for Typer-native intelligent completion."""

import os
import shlex
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from baldrick.cli.main import app


@pytest.fixture
def completion_db(tmp_path: Path) -> Path:
    database = tmp_path / "completion.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE processsnapshot (
                id INTEGER, pid INTEGER, tag TEXT, created_at TEXT
            );
            INSERT INTO processsnapshot VALUES (7, 123, 'crash', '2026-09-10 12:00:00');
            INSERT INTO processsnapshot VALUES (12, NULL, NULL, '2026-09-11 09:00:00');

            CREATE TABLE binary (name TEXT, md5sum TEXT);
            INSERT INTO binary VALUES ('libdemo.so', 'aaa');
            INSERT INTO binary VALUES ('libother.so', 'bbb');

            CREATE TABLE canonical_dwarf_type (name TEXT, tag TEXT);
            INSERT INTO canonical_dwarf_type VALUES ('demo_mutex', 'structure_type');
            INSERT INTO canonical_dwarf_type VALUES ('demo_mutex_t', 'typedef');

            CREATE TABLE sectionheader (name TEXT);
            INSERT INTO sectionheader VALUES ('.text');
            """
        )
    return database


def _complete(*words: str) -> list[str]:
    if words[-1]:
        comp_words = shlex.join(words)
    else:
        comp_words = f"{shlex.join(words[:-1])} "
    result = CliRunner().invoke(
        app,
        [],
        prog_name="baldrick",
        env={
            "_BALDRICK_COMPLETE": "complete_bash",
            "COMP_WORDS": comp_words,
            "COMP_CWORD": str(len(words) - 1),
        },
    )
    assert result.exit_code == 0, result.exception
    return [line for line in result.stdout.splitlines() if line]


def test_snapshot_and_tag_completion_reads_selected_database(completion_db: Path):
    database = str(completion_db)

    assert _complete("baldrick", "--db", database, "report", "--snapshot-id", "") == [
        "12",
        "7",
    ]
    assert _complete("baldrick", "--db", database, "load-process", "--tag", "cr") == [
        "crash"
    ]


def test_completion_uses_configured_default_database(
    completion_db: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("DB", str(completion_db))

    assert _complete("baldrick", "report", "--snapshot-id", "") == ["12", "7"]


def test_cast_completion_reads_binary_and_dwarf_type_names(completion_db: Path):
    database = str(completion_db)

    assert _complete("baldrick", "--db", database, "cast-mem", "--binary", "libd") == [
        "libdemo.so"
    ]
    assert _complete("baldrick", "--db", database, "cast-mem", "--type", "demo_") == [
        "demo_mutex",
        "demo_mutex_t",
    ]


def test_query_completion_is_context_sensitive(completion_db: Path):
    database = str(completion_db)

    assert _complete("baldrick", "--db", database, "query", "thr") == ["threads"]
    assert _complete("baldrick", "--db", database, "query", "threads", "id=") == [
        "id=12",
        "id=7",
    ]
    assert _complete("baldrick", "--db", database, "query", "types", "binary=libd") == [
        "binary=libdemo.so"
    ]


def test_query_option_completion_uses_positional_query_name(completion_db: Path):
    assert _complete(
        "baldrick",
        "--db",
        str(completion_db),
        "query",
        "threads",
        "--param",
        "id=",
    ) == ["id=12", "id=7"]


def test_fixed_value_and_live_pid_completion():
    assert _complete("baldrick", "query", "threads", "--format", "j") == ["json"]
    assert str(os.getpid()) in _complete("baldrick", "load", "--pid", str(os.getpid()))


def test_missing_database_returns_no_domain_candidates(tmp_path: Path):
    missing = str(tmp_path / "missing.db")

    assert _complete("baldrick", "--db", missing, "report", "--snapshot-id", "") == []
    assert not Path(missing).exists()
