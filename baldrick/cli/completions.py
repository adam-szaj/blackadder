"""Fast, read-only completion providers for the Typer CLI."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import typer

from baldrick.config import BaldrickConfig
from baldrick.queries import load_query_registry

Completion = str | tuple[str, str]


def _database_path(ctx: typer.Context) -> Path | None:
    """Resolve the completion database without creating or modifying it."""
    raw_path = ctx.find_root().params.get("db")
    if not raw_path:
        try:
            raw_path = BaldrickConfig().db
        except Exception:
            return None

    value = str(raw_path)
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    if "://" in value or value == ":memory:":
        return None
    return Path(value).expanduser()


def _fetch_rows(
    ctx: typer.Context,
    sql: str,
    parameters: tuple[Any, ...] = (),
) -> list[tuple[Any, ...]]:
    path = _database_path(ctx)
    if path is None or not path.is_file():
        return []

    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            return connection.execute(sql, parameters).fetchall()
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return []


def _like_prefix(incomplete: str) -> str:
    escaped = incomplete.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}%"


def complete_log_level(incomplete: str) -> list[str]:
    """Complete supported logging levels."""
    return [level for level in ("DEBUG", "INFO", "WARNING", "ERROR") if level.startswith(incomplete)]


def complete_output_format(incomplete: str) -> list[str]:
    """Complete query output formats."""
    return [value for value in ("rich", "json", "csv") if value.startswith(incomplete)]


def complete_pid(incomplete: str) -> list[Completion]:
    """Complete live process IDs, with process names when readable."""
    candidates: list[Completion] = []
    try:
        process_ids = sorted(
            (entry.name for entry in Path("/proc").iterdir() if entry.name.isdigit()),
            key=int,
        )
    except OSError:
        return candidates

    for process_id in process_ids:
        if not process_id.startswith(incomplete):
            continue
        try:
            process_name = (Path("/proc") / process_id / "comm").read_text().strip()
        except OSError:
            process_name = ""
        candidates.append((process_id, process_name) if process_name else process_id)
    return candidates


def complete_snapshot(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete snapshot IDs with PID, tag, and creation time."""
    rows = _fetch_rows(
        ctx,
        "SELECT id, pid, tag, created_at FROM processsnapshot "
        "WHERE CAST(id AS TEXT) LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 200",
        (_like_prefix(incomplete),),
    )
    candidates: list[Completion] = []
    for snapshot_id, pid, tag, created_at in rows:
        details = [f"PID {pid}" if pid is not None else "offline"]
        if tag:
            details.append(f"tag={tag}")
        if created_at:
            details.append(str(created_at))
        candidates.append((str(snapshot_id), ", ".join(details)))
    return candidates


def complete_tag(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete existing snapshot tags."""
    rows = _fetch_rows(
        ctx,
        "SELECT tag, MAX(id) FROM processsnapshot "
        "WHERE tag IS NOT NULL AND tag LIKE ? ESCAPE '\\' "
        "GROUP BY tag ORDER BY tag LIMIT 200",
        (_like_prefix(incomplete),),
    )
    return [(str(tag), f"latest snapshot #{snapshot_id}") for tag, snapshot_id in rows]


def complete_binary(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete binary names stored in the database."""
    rows = _fetch_rows(
        ctx,
        "SELECT name, MIN(md5sum) FROM binary "
        "WHERE name LIKE ? ESCAPE '\\' GROUP BY name ORDER BY name LIMIT 200",
        (_like_prefix(incomplete),),
    )
    return [(str(name), str(md5sum)) for name, md5sum in rows]


def complete_type(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete struct, union, and typedef names stored in the database."""
    rows = _fetch_rows(
        ctx,
        "SELECT name, GROUP_CONCAT(DISTINCT tag) FROM canonical_dwarf_type "
        "WHERE name IS NOT NULL "
        "AND tag IN ('structure_type', 'union_type', 'typedef') "
        "AND name LIKE ? ESCAPE '\\' GROUP BY name ORDER BY name LIMIT 200",
        (_like_prefix(incomplete),),
    )
    return [(str(name), str(tags)) for name, tags in rows]


def complete_section(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete ELF section names stored in the database."""
    rows = _fetch_rows(
        ctx,
        "SELECT name, COUNT(*) FROM sectionheader "
        "WHERE name LIKE ? ESCAPE '\\' GROUP BY name ORDER BY name LIMIT 200",
        (_like_prefix(incomplete),),
    )
    return [(str(name), f"{count} binary occurrence(s)") for name, count in rows]


def complete_query_name(incomplete: str) -> list[Completion]:
    """Complete built-in and configured query names."""
    candidates: list[Completion] = [
        ("list", "list available named queries"),
        ("sql=", "run an inline SQL query"),
    ]
    candidates.extend(
        (definition.name, definition.description)
        for definition in sorted(load_query_registry().values(), key=lambda item: item.name)
    )
    return [candidate for candidate in candidates if candidate[0].startswith(incomplete)]


def _previous_values(ctx: typer.Context, name: str) -> list[str]:
    values = ctx.params.get(name) or ()
    if name == "args" and not values:
        values = ctx.args
    if isinstance(values, str):
        return [values]
    return [str(value) for value in values]


def _prefixed_candidates(
    key: str,
    candidates: list[Completion],
) -> list[Completion]:
    result: list[Completion] = []
    for candidate in candidates:
        if isinstance(candidate, tuple):
            value, help_text = candidate
            result.append((f"{key}={value}", help_text))
        else:
            result.append(f"{key}={candidate}")
    return result


def _complete_query_value(
    ctx: typer.Context,
    query_name: str,
    previous_parameters: list[str],
    incomplete: str,
) -> list[Completion]:
    definition = load_query_registry().get(query_name)
    if definition is None or query_name.startswith("sql="):
        return []

    if "=" not in incomplete:
        used = {item.split("=", 1)[0] for item in previous_parameters if "=" in item}
        return [f"{name}=" for name in definition.params if name not in used]

    key, incomplete_value = incomplete.split("=", 1)
    if key not in definition.params:
        return []
    if key == "id":
        candidates = complete_snapshot(ctx, incomplete_value)
    elif key == "binary":
        candidates = complete_binary(ctx, incomplete_value)
    elif key == "tag":
        candidates = complete_tag(ctx, incomplete_value)
    elif key == "name" and query_name in {"struct", "type-offset"}:
        candidates = complete_type(ctx, incomplete_value)
    elif key == "section":
        candidates = complete_section(ctx, incomplete_value)
    else:
        return []
    return _prefixed_candidates(key, candidates)


def complete_query_argument(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete a query name or a positional key=value query parameter."""
    arguments = _previous_values(ctx, "args")
    if not arguments:
        return complete_query_name(incomplete)
    parameters = [*arguments[1:], *_previous_values(ctx, "param")]
    return _complete_query_value(ctx, arguments[0], parameters, incomplete)


def complete_query_parameter(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete a value passed through query --param/-p."""
    arguments = _previous_values(ctx, "args")
    if not arguments:
        return []
    parameters = [*arguments[1:], *_previous_values(ctx, "param")]
    return _complete_query_value(ctx, arguments[0], parameters, incomplete)


def complete_tag_argument(ctx: typer.Context, incomplete: str) -> list[Completion]:
    """Complete the optional snapshot ID and the following tag argument."""
    arguments = _previous_values(ctx, "args")
    if not arguments:
        return [*complete_snapshot(ctx, incomplete), *complete_tag(ctx, incomplete)]
    if len(arguments) == 1 and arguments[0].isdigit():
        return complete_tag(ctx, incomplete)
    return []
