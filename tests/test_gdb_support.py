from __future__ import annotations

import json
from importlib.machinery import ModuleSpec
from pathlib import Path

from typer.testing import CliRunner

from baldrick.cli import gdb_support
from baldrick.cli.main import app


def test_gdb_path_prints_installed_plugin(monkeypatch, tmp_path: Path) -> None:
    package = tmp_path / "baldrick_gdb"
    package.mkdir()
    plugin = package / "baldrick_gdb.py"
    plugin.write_text("# plugin\n")
    spec = ModuleSpec("baldrick_gdb", loader=None, is_package=True)
    spec.submodule_search_locations = [str(package)]
    monkeypatch.setattr(gdb_support.importlib.util, "find_spec", lambda _name: spec)

    result = CliRunner().invoke(app, ["gdb-path"])

    assert result.exit_code == 0
    assert result.stdout.strip() == str(plugin)


def test_gdb_path_explains_missing_plugin(monkeypatch) -> None:
    monkeypatch.setattr(gdb_support.importlib.util, "find_spec", lambda _name: None)

    result = CliRunner().invoke(app, ["gdb-path"])

    assert result.exit_code == 1
    assert "pip install baldrick-gdb" in result.stdout


def test_python_paths_helper_prints_json(capsys) -> None:
    gdb_support.print_python_paths()

    assert isinstance(json.loads(capsys.readouterr().out), list)
