"""Registration of small CLI metadata and schema commands."""

import sqlite3
from collections.abc import Callable

import typer
from rich.console import Console
from rich.table import Table

from baldrick.query import _db_path
from baldrick.theme import ColorTheme


def register_meta_commands(
    app: typer.Typer,
    console: Console,
    database_url: Callable[[], str],
    theme: Callable[[], ColorTheme],
) -> None:
    """Register commands that inspect Baldrick itself or its database."""

    @app.command()
    def schema() -> None:
        """Show all database tables with their columns and types."""
        db_url = database_url()
        db_file = _db_path(db_url) if db_url.startswith("sqlite") else db_url

        try:
            connection = sqlite3.connect(db_file)
        except Exception as error:
            console.print(f"[red]Cannot open database: {error}[/red]")
            raise typer.Exit(1) from error

        try:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
            if not tables:
                console.print("[yellow]No tables found in database.[/yellow]")
                return

            colors = theme()
            for table_name in tables:
                columns = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
                table = Table(
                    title=table_name,
                    title_style=f"bold {colors.section}",
                )
                table.add_column("Column", style=colors.symbol, no_wrap=True)
                table.add_column("Type", style=colors.flags, no_wrap=True)
                table.add_column("NotNull", style=colors.meta, no_wrap=True)
                table.add_column("Default", style=colors.description, no_wrap=True)
                table.add_column("PK", style=colors.meta, no_wrap=True)
                for column in columns:
                    _, name, column_type, not_null, default, primary_key = column
                    table.add_row(
                        name,
                        column_type or "",
                        "✓" if not_null else "",
                        str(default) if default is not None else "",
                        str(primary_key) if primary_key else "",
                    )
                console.print(table)
        finally:
            connection.close()

    @app.command()
    def version() -> None:
        """Show version information."""
        import baldrick

        console.print(f"Baldrick {baldrick.__version__}")
        console.print(f"Author: {baldrick.__author__}")
