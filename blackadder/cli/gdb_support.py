"""Helpers used to locate and bootstrap the separately installed GDB plugin."""

import importlib.util
import json
import sys
from pathlib import Path

import typer
from rich.console import Console


def installed_plugin_path() -> Path:
    """Return the entry-point script from the installed blackadder-gdb package."""
    spec = importlib.util.find_spec("_gdb")
    locations = spec.submodule_search_locations if spec is not None else None
    if not locations:
        raise FileNotFoundError(
            "Blackadder GDB plugin is not installed; run 'pip install blackadder-gdb'."
        )
    plugin = Path(next(iter(locations))) / "blackadder_gdb.py"
    if not plugin.is_file():
        raise FileNotFoundError(
            "Installed blackadder-gdb package does not contain blackadder_gdb.py."
        )
    return plugin.resolve()


def register_gdb_commands(app: typer.Typer, console: Console) -> None:
    """Register commands integrating Blackadder with its separately shipped plugin."""

    @app.command("gdb-path")
    def gdb_path() -> None:
        """Print the path to the installed GDB plugin entry point."""
        try:
            typer.echo(installed_plugin_path())
        except FileNotFoundError as error:
            console.print(f"[red]Error: {error}[/red]")
            raise typer.Exit(1) from error


def print_python_paths() -> None:
    """Print import paths for GDB's bootstrap process as JSON."""
    typer.echo(json.dumps([path for path in sys.path if path]))
