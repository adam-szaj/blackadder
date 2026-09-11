"""Registration and rendering for the named SQL query command."""

from collections.abc import Callable

import typer
from rich.console import Console
from rich.table import Table

from baldrick.cli.completions import (
    complete_output_format,
    complete_query_argument,
    complete_query_parameter,
    complete_tag,
)
from baldrick.queries import load_query_registry
from baldrick.query import BaldrickQuery, _db_path, run_query
from baldrick.theme import ColorTheme, column_style, format_value


def register_query_command(
    app: typer.Typer,
    console: Console,
    database_url: Callable[[], str],
    theme: Callable[[], ColorTheme],
) -> None:
    """Register the query command without coupling it to CLI module globals."""

    @app.command()
    def query(
        args: list[str] = typer.Argument(
            default=None,
            help=(
                "Query name followed by optional key=value params. "
                "Use 'list' to show all queries. "
                'Use sql="SELECT ..." to run inline SQL. '
                'Examples: query threads id=1 | query sql="SELECT * FROM processsnapshot"'
            ),
            autocompletion=complete_query_argument,
        ),
        param: list[str] = typer.Option(
            [],
            "--param",
            "-p",
            help=(
                "Query parameter as key=value "
                "(can be repeated; alternative to positional key=value)"
            ),
            autocompletion=complete_query_parameter,
        ),
        tag: str | None = typer.Option(
            None,
            "--tag",
            "-T",
            help="Filter snapshots by tag",
            autocompletion=complete_tag,
        ),
        fmt: str = typer.Option(
            "rich",
            "--format",
            "-f",
            help="Output format: rich, json, csv",
            autocompletion=complete_output_format,
        ),
    ) -> None:
        """Run a named SQL query against the database."""
        registry = load_query_registry()

        if not args:
            console.print("[red]Query name required. Use 'list' to show available queries.[/red]")
            raise typer.Exit(1)

        first = args[0]
        rest = args[1:]
        inline_sql: str | None = None
        if first.startswith("sql="):
            inline_sql = first[4:].strip().strip('"').strip("'")
            name = "sql"
        else:
            name = first

        colors = theme()
        if name == "list":
            table = Table(title="Available Queries")
            table.add_column("Name", style=colors.symbol, no_wrap=True)
            table.add_column("Params", style=colors.flags, no_wrap=True)
            table.add_column("Description", style=colors.description)
            for query_definition in sorted(
                registry.values(), key=lambda definition: definition.name
            ):
                table.add_row(
                    query_definition.name,
                    ", ".join(f":{item}" for item in query_definition.params)
                    if query_definition.params
                    else "—",
                    query_definition.description,
                )
            console.print(table)
            return

        db_url = database_url()
        db_file = _db_path(db_url) if db_url.startswith("sqlite") else db_url

        try:
            import polars as pl
        except ImportError as error:
            console.print(
                "[red]polars is required for query command. Install with: pip install polars[/red]"
            )
            raise typer.Exit(1) from error

        if name == "sql":
            if not inline_sql:
                console.print(
                    "[red]sql=<SQL> is required when using inline SQL. "
                    "Example: query 'sql=\"SELECT * FROM processsnapshot\"'[/red]"
                )
                raise typer.Exit(1)
            try:
                frame = run_query(db_file, inline_sql)
            except Exception as error:
                console.print(f"[red]Query failed: {error}[/red]")
                raise typer.Exit(1) from error
            title = "sql"
        else:
            if name not in registry:
                console.print(
                    f"[red]Unknown query: {name!r}. Use 'list' to see available queries.[/red]"
                )
                raise typer.Exit(1)

            parameters: dict[str, str] = {}
            for key_value in [*rest, *param]:
                if "=" not in key_value:
                    console.print(
                        f"[red]Invalid parameter: {key_value!r} (expected key=value)[/red]"
                    )
                    raise typer.Exit(1)
                key, value = key_value.split("=", 1)
                parameters[key.strip()] = value.strip()

            query_definition = registry[name]
            post_filter_tag: str | None = None
            if tag:
                if "id" in query_definition.params and "id" not in parameters:
                    parameters["tag"] = tag
                else:
                    post_filter_tag = tag

            try:
                frame = BaldrickQuery(db_file).run(name, **parameters)
            except KeyError as error:
                console.print(f"[red]Error: {error}[/red]")
                raise typer.Exit(1) from error
            except Exception as error:
                console.print(f"[red]Query failed: {error}[/red]")
                raise typer.Exit(1) from error

            if post_filter_tag and "tag" in frame.columns:
                frame = frame.filter(pl.col("tag") == post_filter_tag)
            title = name

        if frame.is_empty():
            console.print("[yellow](no results)[/yellow]")
            return

        output_format = fmt.lower()
        if output_format == "json":
            console.print(frame.write_json())
        elif output_format == "csv":
            console.print(frame.write_csv(), end="")
        else:
            table = Table(title=title)
            for column in frame.columns:
                table.add_column(
                    column,
                    style=column_style(column, colors),
                    no_wrap=False,
                )
            for values in frame.iter_rows():
                table.add_row(
                    *[
                        format_value(column, value, colors)
                        for column, value in zip(frame.columns, values)
                    ]
                )
            console.print(table)
