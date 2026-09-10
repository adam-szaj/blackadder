"""Characterization tests for the public command registry."""

import typer

from baldrick.cli.main import app


def test_top_level_command_set_is_stable():
    command = typer.main.get_command(app)

    assert set(command.commands) == {
        "load",
        "load-types",
        "cast-mem",
        "load-process",
        "decode-backtrace",
        "decode-address",
        "analyse-memory",
        "analyse-deadlock",
        "report",
        "tag",
        "query",
        "schema",
        "version",
        "gdb-path",
    }
