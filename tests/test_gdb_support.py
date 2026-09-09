from __future__ import annotations

import json
from importlib.machinery import ModuleSpec
from pathlib import Path

from typer.testing import CliRunner

from blackadder.cli import gdb_support
from blackadder.cli.main import app


def test_gdb_path_prints_installed_plugin(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "_gdb"
    package.mkdir()
    plugin = package / "blackadder_gdb.py"
    plugin.write_text("# plugin\n")
    spec = ModuleSpec("_gdb", loader=None, is_package=True)
    spec.submodule_search_locations = [str(package)]
    monkeypatch.setattr(gdb_support.importlib.util, "find_spec", lambda _name: spec)

    result = CliRunner().invoke(app, ["gdb-path"])

    assert result.exit_code == 0
    assert result.stdout.strip() == str(plugin)


def test_gdb_path_explains_missing_plugin(monkeypatch) -> None:
    monkeypatch.setattr(gdb_support.importlib.util, "find_spec", lambda _name: None)

    result = CliRunner().invoke(app, ["gdb-path"])

    assert result.exit_code == 1
    assert "pip install blackadder-gdb" in result.stdout


def test_python_paths_helper_prints_json(capsys) -> None:
    gdb_support.print_python_paths()

    assert isinstance(json.loads(capsys.readouterr().out), list)
