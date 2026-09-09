"""
Baldrick CLI - main entry point for blackadder debugging tool.

Provides commands for:
- Loading binaries into rootfs database
- Loading process memory mappings
- Decoding backtraces
- Resolving addresses to symbols
- Analyzing memory layout
"""

import asyncio
import glob as glob_module
import logging
import re
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from blackadder.binutils import init_parser, parse_backtrace_auto
from blackadder.cli.meta_commands import register_meta_commands
from blackadder.cli.query_commands import register_query_command
from blackadder.config import BlackadderConfig
from blackadder.db import AsyncDatabaseManager, ProcessDatabase
from blackadder.db.rootfs import PAYLOAD_SENTINEL, RootfsDatabase
from blackadder.logging_config import setup_logging
from blackadder.theme import ColorTheme, load_theme

logger = logging.getLogger("blackadder.cli")

app = typer.Typer(
    name="baldrick",
    help="Baldrick - Linux debugging tool for backtrace decoding and symbol resolution",
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

# Module-level storage for global options set in callback
_global_db: str | None = None
_theme: ColorTheme = ColorTheme()  # default Tokyo Night; overridden in callback


@app.callback()
def _global_options(
    debug: bool = typer.Option(False, "--debug", help="Enable DEBUG level logging"),
    log_level: str = typer.Option(
        "WARNING", "--log-level", help="Log level (DEBUG, INFO, WARNING, ERROR)"
    ),
    log_file: str | None = typer.Option(None, "--log-file", help="Write logs to file"),
    db: str | None = typer.Option(
        None, "--db", "-d", help="Path to database (overrides config default)"
    ),
) -> None:
    """Global options applied to all commands."""
    global _global_db, _theme
    _global_db = db
    _theme = load_theme()
    level = "DEBUG" if debug else log_level.upper()
    setup_logging(level, log_file)


# ============================================================================
# Helpers
# ============================================================================


def _get_config_or_default() -> BlackadderConfig:
    """Get configuration from environment or use defaults."""
    try:
        return BlackadderConfig()
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
        return BlackadderConfig()


def _to_db_url(path_or_url: str) -> str:
    """Convert a file path or existing SQLAlchemy URL to an aiosqlite URL."""
    if path_or_url.startswith("sqlite+aiosqlite://"):
        return path_or_url
    return f"sqlite+aiosqlite:///{Path(path_or_url).resolve()}"


def _db_manager(db: str | None, config: BlackadderConfig) -> AsyncDatabaseManager:
    return AsyncDatabaseManager(_to_db_url(db or config.db))


async def _resolve_snapshot_id(
    db_proc: "ProcessDatabase",
    snapshot_id: int | None,
) -> int:
    """
    Return snapshot_id as-is, or fall back to the latest snapshot in the DB.
    Prints a dim hint when falling back. Exits with error if DB has no snapshots.
    """
    if snapshot_id is not None:
        return snapshot_id
    latest = await db_proc.get_latest_snapshot()
    if latest is None:
        console.print("[red]Error: No snapshots in database. Run load-process first.[/red]")
        raise typer.Exit(1)
    console.print(f"[dim]Using latest snapshot #{latest.id}[/dim]")
    return latest.id  # type: ignore[return-value]


def _parse_perm(perm_str: str) -> tuple[int, int]:
    """
    Parse a Unix permission string to a (mask, value) pair.

    Supports octal (0755, 755) and symbolic forms (u+x, +x, a+x).
    Returns (mask, value) such that file_mode & mask == value.
    """
    if re.match(r"^0?[0-7]{3}$", perm_str):
        val = int(perm_str, 8)
        return (0o777, val)
    m = re.match(r"^([ugoa]?)\+([rwx]+)$", perm_str)
    if m:
        who, what = m.group(1), m.group(2)
        x_bits = {"u": 0o100, "g": 0o010, "o": 0o001, "a": 0o111, "": 0o001}
        w_bits = {"u": 0o200, "g": 0o020, "o": 0o002, "a": 0o222, "": 0o002}
        r_bits = {"u": 0o400, "g": 0o040, "o": 0o004, "a": 0o444, "": 0o004}
        mask = value = 0
        if "x" in what:
            mask |= x_bits[who]
            value |= x_bits[who]
        if "w" in what:
            mask |= w_bits[who]
            value |= w_bits[who]
        if "r" in what:
            mask |= r_bits[who]
            value |= r_bits[who]
        return (mask, value)
    raise ValueError(f"Cannot parse permission string: {perm_str!r}")


def _is_elf(path: str) -> bool:
    """Return True if file starts with the ELF magic bytes \\x7fELF."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _collect_paths_from_maps_text(maps_text: str, rootfs: str) -> list[str]:
    """Extract unique binary paths from /proc/maps text, resolved against rootfs."""
    rootfs_base = rootfs.rstrip("/") or "/"
    paths: set[str] = set()
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            pathname = parts[-1].strip()
            if pathname and not pathname.startswith("["):
                full = str(Path(rootfs_base) / pathname.lstrip("/"))
                if Path(full).is_file():
                    paths.add(full)
    return sorted(paths)


_DEFAULT_SCAN_DIRS = "bin:sbin:lib:usr/bin:usr/sbin:usr/lib"


def _iter_binary_paths(
    rootfs: str,
    glob_pattern: str | None = None,
    perm: str | None = None,
    files_spec: str | None = None,
    dirs: str | None = None,
    maps_file: str | None = None,
    pid: int | None = None,
    core_file: str | None = None,
    max_depth: int | None = None,
) -> Iterator[str]:
    """
    Yield candidate binary file paths one by one from the given source.

    Yields absolute paths to ELF files (deduplicated via caller-maintained set).
    Filesystem sources (glob, perm, dirs) are filtered to ELF binaries only.
    Logging DEBUG messages describe each filesystem entry examined.
    """
    rootfs_base = rootfs.rstrip("/") or "/"

    if glob_pattern:
        full_pattern = str(Path(rootfs_base) / glob_pattern.lstrip("/"))
        logger.debug("glob_scan_start", extra={"pattern": full_pattern})
        rootfs_depth = len(Path(rootfs_base).parts)
        for match in glob_module.glob(full_pattern, recursive=True):
            if max_depth is not None:
                # depth 0 = files directly in rootfs (len - rootfs_depth == 1)
                if len(Path(match).parts) - rootfs_depth > max_depth + 1:
                    continue
            logger.debug("glob_candidate", extra={"path": match})
            if Path(match).is_file() and _is_elf(match):
                yield match

    if perm:
        mask, value = _parse_perm(perm)
        logger.debug("perm_scan_start", extra={"rootfs": rootfs_base, "perm": perm})
        rootfs_depth = len(Path(rootfs_base).parts)
        for p in Path(rootfs_base).rglob("*"):
            if max_depth is not None and len(p.parts) - rootfs_depth > max_depth + 1:
                continue
            logger.debug("perm_candidate", extra={"path": str(p)})
            if p.is_file():
                try:
                    if p.stat().st_mode & mask == value and _is_elf(str(p)):
                        yield str(p)
                except PermissionError:
                    pass

    if dirs:
        for d in dirs.split(":"):
            scan_dir = Path(rootfs_base) / d.lstrip("/")
            logger.debug("dirs_scan_start", extra={"dir": str(scan_dir)})
            if not scan_dir.is_dir():
                continue
            scan_depth = len(scan_dir.parts)
            for p in scan_dir.rglob("*"):
                # depth 0 = files directly in scan_dir (len(p.parts) - scan_depth == 1)
                if max_depth is not None and len(p.parts) - scan_depth > max_depth + 1:
                    continue
                logger.debug("dirs_candidate", extra={"path": str(p)})
                if p.is_file() and _is_elf(str(p)):
                    yield str(p)

    if files_spec:
        if files_spec.startswith("@"):
            with open(files_spec[1:]) as f:
                raw_paths = [line.strip() for line in f if line.strip()]
        else:
            raw_paths = [p for p in files_spec.split(":") if p]
        for raw_path in raw_paths:
            full = str(Path(rootfs_base) / raw_path.lstrip("/"))
            logger.debug("files_candidate", extra={"path": full})
            if Path(full).is_file():
                yield full
            elif Path(raw_path).is_file():
                yield raw_path

    if maps_file:
        with open(maps_file) as f:
            maps_text = f.read()
        for map_path in _collect_paths_from_maps_text(maps_text, rootfs):
            logger.debug("maps_candidate", extra={"path": map_path})
            yield map_path

    if pid:
        proc_maps = f"/proc/{pid}/maps"
        try:
            with open(proc_maps) as f:
                maps_text = f.read()
            for map_path in _collect_paths_from_maps_text(maps_text, rootfs):
                logger.debug("pid_maps_candidate", extra={"path": map_path})
                yield map_path
        except PermissionError:
            console.print(f"[yellow]Warning: Cannot read {proc_maps} (permission denied)[/yellow]")
        except FileNotFoundError:
            console.print(
                f"[yellow]Warning: {proc_maps} not found - process {pid} may not exist[/yellow]"
            )

    if core_file:
        from blackadder.binutils.coredump import CoreDumpParser

        config = _get_config_or_default()
        parser = CoreDumpParser(config)

        async def _get_core_paths():
            result = await parser.parse_core_dump(core_file)
            found = []
            if result.status == "success":
                for m in result.mappings:
                    pathname = m.get("pathname", "")
                    if pathname and not pathname.startswith("["):
                        full = str(Path(rootfs.rstrip("/")) / pathname.lstrip("/"))
                        if Path(full).is_file():
                            found.append(full)
            return found

        for p in asyncio.run(_get_core_paths()):
            logger.debug("core_candidate", extra={"path": p})
            yield p


def _collect_binary_paths(
    rootfs: str,
    glob_pattern: str | None = None,
    perm: str | None = None,
    files_spec: str | None = None,
    dirs: str | None = None,
    maps_file: str | None = None,
    pid: int | None = None,
    core_file: str | None = None,
) -> list[str]:
    """Collect and deduplicate binary file paths (no progress feedback)."""
    seen: set[str] = set()
    for p in _iter_binary_paths(
        rootfs, glob_pattern, perm, files_spec, dirs, maps_file, pid, core_file
    ):
        seen.add(p)
    return sorted(seen)


# ============================================================================
# Commands
# ============================================================================


@app.command()
async def load(
    rootfs: str = typer.Option("/", "--rootfs", "-R", help="Path to rootfs"),
    debugfs: str | None = typer.Option(None, "--debugfs", "-D", help="Path to debugfs"),
    glob_pattern: str | None = typer.Option(
        None, "--glob", "-g", help="Glob pattern to match binaries (e.g. **/*.so)"
    ),
    perm: str | None = typer.Option(
        None, "--perm", "-P", help="File permission filter (e.g. 0755, u+x)"
    ),
    files_spec: str | None = typer.Option(
        None,
        "--files",
        "-f",
        help="File list: colon-separated paths or @file with one path per line",
    ),
    maps_file: str | None = typer.Option(None, "--maps", "-m", help="Path to /proc/PID/maps file"),
    pid: int | None = typer.Option(
        None, "--pid", "-p", help="Running process PID (reads /proc/PID/maps)"
    ),
    core_file: str | None = typer.Option(
        None, "--coredump", "-C", help="Path to ELF core dump file"
    ),
    dirs: str | None = typer.Option(
        None,
        "--dirs",
        help=(
            "Colon-separated list of dirs to scan under rootfs for ELF binaries "
            "(e.g. /bin:/lib:/usr/lib). "
            f"Default when no source given: {_DEFAULT_SCAN_DIRS}"
        ),
    ),
    load_types: bool = typer.Option(
        False, "--types", "-t", help="Also load DWARF type info (implies --lines)"
    ),
    load_lines: bool = typer.Option(
        False, "--lines", "-l", help="Also load .debug_line addr→source mappings"
    ),
    max_bin: int | None = typer.Option(
        None, "--maxbin", help="Stop after loading N binaries (useful for testing)"
    ),
    max_depth: int | None = typer.Option(
        None, "--maxdepth", help="Max directory depth to recurse into (0 = only top-level dir)"
    ),
    slow_threshold: float = typer.Option(
        5.0,
        "--slow-threshold",
        help="Show a spinner for binaries taking longer than this many seconds",
    ),
    slow_top: int = typer.Option(
        5, "--slow-top", help="Max number of slow-binary spinners shown simultaneously"
    ),
) -> None:
    """
    Load binaries from rootfs into the rootfs database.

    Extracts sections, symbols, and debug info via objdump/readelf.
    Skips binaries already cached (identified by MD5).
    Only ELF binaries are loaded (filesystem sources are filtered automatically).

    Example:
        baldrick load --rootfs /target                          # scans default dirs
        baldrick load --rootfs /target --dirs /bin:/lib:/usr/lib
        baldrick load --rootfs /target --glob '**/*.so'
        baldrick load --rootfs /target --perm u+x
        baldrick load --rootfs /target --maps /proc/12345/maps
        baldrick load --rootfs /target --pid 12345
        baldrick load --rootfs /target --glob '**/*.so' --types
        baldrick load --rootfs /target --dirs /usr/lib --maxdepth 0 --maxbin 100
    """
    sources = [glob_pattern, perm, files_spec, dirs, maps_file, pid, core_file]
    if not any(s is not None for s in sources):
        dirs = _DEFAULT_SCAN_DIRS
        console.print(
            f"[dim]No source specified — scanning default dirs: {_DEFAULT_SCAN_DIRS}[/dim]"
        )

    config = _get_config_or_default()

    try:
        # Collect paths with live counter so the user sees progress during
        # potentially slow filesystem walks (large rootfs / deep glob patterns).
        seen: set[str] = set()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as collect_progress:
            scan_task = collect_progress.add_task("Scanning filesystem…", total=None)
            for raw_path in _iter_binary_paths(
                rootfs=rootfs,
                glob_pattern=glob_pattern,
                perm=perm,
                files_spec=files_spec,
                dirs=dirs,
                maps_file=maps_file,
                pid=pid,
                core_file=core_file,
                max_depth=max_depth,
            ):
                seen.add(raw_path)
                collect_progress.update(
                    scan_task,
                    description=f"Scanning… {len(seen)} found",
                )
                if max_bin is not None and len(seen) >= max_bin:
                    collect_progress.update(
                        scan_task,
                        description=f"Scanning… {len(seen)} found (--maxbin limit reached)",
                    )
                    break

        binary_paths = sorted(seen)

        if not binary_paths:
            console.print("[yellow]No binary files found matching the given criteria.[/yellow]")
            raise typer.Exit(0)

        console.print(f"[green]Found {len(binary_paths)} binary file(s)[/green]")

        manager = _db_manager(_global_db, config)
        await manager.create_all()
        rootfs_db_obj = RootfsDatabase(manager, config)

        # Limit how many binaries are processed concurrently.
        # Each binary may spawn several subprocesses internally; the subprocess
        # semaphore in BinToolsParser (default: min(32, cpu*2)) caps actual
        # subprocess parallelism.  We use a separate, coarser concurrency limit
        # here so we don't queue up thousands of DB sessions at once.
        concurrency = min(config.max_subprocess_workers, len(binary_paths))

        failed = active = 0
        t_io = 0.0
        tasks_done = 0

        # payload_queue: workers produce BinaryPayload, writer consumes.
        # maxsize=64 bounds memory: 64 payloads × ~500KB worst case ≈ 32 MB.
        payload_queue: asyncio.Queue = asyncio.Queue(maxsize=64)
        _live: dict[str, int] = {
            "loaded": 0,
            "skipped": 0,
            "types": 0,
            "lines": 0,
            "retries": 0,
            "t_wait": 0,
            "t_write": 0,
        }
        writer_task = asyncio.create_task(rootfs_db_obj.run_payload_writer(payload_queue, _live))

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        task_id = progress.add_task(
            f"Loading binaries [dim](0/{concurrency} active)[/dim]",
            total=len(binary_paths),
        )

        def _update_description() -> None:
            q_size = payload_queue.qsize()
            tw, twr = _live["t_wait"], _live["t_write"]
            writer_info = f" db={twr}ms idle={tw}ms" if (tw or twr) else ""
            extra = (
                (
                    f", q={q_size}/64"
                    f" types={_live['types']} lines={_live['lines']}"
                    + writer_info
                    + (f" [red]retries={_live['retries']}[/red]" if _live["retries"] else "")
                )
                if (load_types or load_lines)
                else writer_info
            )
            progress.update(
                task_id,
                description=(
                    f"Loading binaries [dim]({active}/{concurrency} active,"
                    f" {_live['loaded']} new, {_live['skipped']} cached{extra})[/dim]"
                ),
            )

        # Slow-task subtask tracker: show up to `slow_top` spinners for binaries
        # that have been running longer than `slow_threshold` seconds.
        # slow_threshold / slow_top come from CLI options

        # Map: path → (start_time, progress_task_id | None)
        _slow_running: dict[str, tuple[float, TaskID | None]] = {}

        def _slow_register(path: str) -> None:
            _slow_running[path] = (time.monotonic(), None)

        def _slow_unregister(path: str) -> None:
            entry = _slow_running.pop(path, None)
            if entry and entry[1] is not None:
                progress.remove_task(entry[1])

        def _slow_tick() -> None:
            """Called periodically; promote slow tasks to visible spinner rows."""
            now = time.monotonic()
            # Collect tasks past threshold that don't yet have a subtask row,
            # sorted oldest-first so we promote the slowest ones.
            pending = sorted(
                (
                    (p, t0)
                    for p, (t0, tid) in _slow_running.items()
                    if tid is None and now - t0 >= slow_threshold
                ),
                key=lambda x: x[1],
            )
            # Count how many slots are already occupied
            occupied = sum(1 for t0, tid in _slow_running.values() if tid is not None)
            for path, t0 in pending:
                if occupied >= slow_top:
                    break
                elapsed = now - t0
                tid = progress.add_task(
                    f"  [dim]{Path(path).name} ({elapsed:.0f}s…)[/dim]",
                    total=None,
                )
                _slow_running[path] = (t0, tid)
                occupied += 1
            # Update description of already-visible slow tasks; include slot info
            total_slow = sum(1 for t0, tid in _slow_running.values() if now - t0 >= slow_threshold)
            visible_slow = sum(1 for t0, tid in _slow_running.values() if tid is not None)
            for path, (t0, current_task_id) in _slow_running.items():
                if current_task_id is not None:
                    elapsed = now - t0
                    progress.update(
                        current_task_id,
                        description=f"  [dim]{Path(path).name} ({elapsed:.0f}s…) [{visible_slow}/{total_slow} slow][/dim]",
                    )

        async def _load_one(path: str) -> None:
            nonlocal failed, active, t_io, tasks_done
            active += 1
            _slow_register(path)
            _update_description()
            try:
                _t1 = time.monotonic()
                payload = await rootfs_db_obj.collect_binary_payload(
                    path,
                    rootfs=rootfs,
                    debugfs=debugfs or rootfs,
                    load_types=load_types,
                    load_lines=load_lines,
                )
                t_io += time.monotonic() - _t1
                tasks_done += 1
                await payload_queue.put(payload)
            except Exception as e:
                failed += 1
                tasks_done += 1
                progress.console.print(f"  [yellow]Skip {Path(path).name}: {e}[/yellow]")
            finally:
                active -= 1
                _slow_unregister(path)
                _update_description()
                progress.advance(task_id)

        async def _bounded_pool(paths: list[str], limit: int) -> None:
            """Run _load_one for all paths with at most `limit` truly concurrent tasks.

            Unlike gather+semaphore (which creates N coroutines upfront), this
            only creates a new task when a slot becomes free — no thundering herd,
            no N×overhead for 44k items.
            """
            it = iter(paths)
            running: set[asyncio.Task] = set()

            for path in it:
                if len(running) >= limit:
                    # Wait for any one task to finish before launching another
                    done, running = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
                t = asyncio.create_task(_load_one(path))
                running.add(t)

            # Drain remaining tasks
            if running:
                await asyncio.wait(running)

        async def _refresh_loop() -> None:
            while True:
                await asyncio.sleep(1.0)
                _slow_tick()
                _update_description()

        with progress:
            _refresh_task = asyncio.create_task(_refresh_loop())
            try:
                await _bounded_pool(binary_paths, concurrency)
            finally:
                _refresh_task.cancel()

        await payload_queue.put(PAYLOAD_SENTINEL)
        writer_stats = await writer_task

        loaded = _live["loaded"]
        skipped = _live["skipped"]
        console.print(
            f"[green]✓ Done: {loaded} loaded, {skipped} already cached, {failed} failed[/green]"
        )

        n = max(tasks_done, 1)
        timing_table = Table(
            title="Phase timing (wall-clock, cumulative across all tasks)",
            box=None,
            show_header=True,
        )
        timing_table.add_column("Phase", style="bold")
        timing_table.add_column("Total (s)", justify="right")
        timing_table.add_column("Avg/task (ms)", justify="right")
        timing_table.add_column("Note", style="dim")
        w_queue = writer_stats.get("t_queue_ms", 0)
        w_apply = writer_stats.get("t_apply_ms", 0)
        w_commit = writer_stats.get("t_commit_ms", 0)
        commits = writer_stats.get("commits", 0)
        avg_commit_ms = f"{w_commit // commits}ms/commit" if commits else "—"
        timing_table.add_row(
            "collect I/O",
            f"{t_io:.2f}",
            f"{t_io / n * 1000:.0f}",
            "md5 + readelf + objdump"
            + (" + DWARF" if load_types else "")
            + (" + debugline" if (load_lines and not load_types) else ""),
        )
        timing_table.add_row(
            "db INSERT (SQL)",
            f"{w_apply / 1000:.2f}",
            "—",
            f"{writer_stats.get('loaded', 0)} loaded, {writer_stats.get('skipped', 0)} skipped, "
            f"{writer_stats.get('types', 0)} types, {writer_stats.get('lines', 0)} lines",
        )
        timing_table.add_row(
            "db COMMIT", f"{w_commit / 1000:.2f}", "—", f"{commits} commits · {avg_commit_ms}"
        )
        timing_table.add_row(
            "db writer idle", f"{w_queue / 1000:.2f}", "—", "waiting for next payload from workers"
        )
        console.print(timing_table)
        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def load_types(
    binary: str = typer.Option(
        ..., "--binary", "-b", help="Path to binary (must be loaded via 'load' first)"
    ),
) -> None:
    """
    Load DWARF type info and .debug_line mappings from a single binary.

    The binary must already be indexed (run 'load' first).
    Idempotent — safe to run multiple times.

    Example:
        baldrick --db session.db load-types --binary /usr/lib/x86_64-linux-gnu/libpthread.so.0
    """
    config = _get_config_or_default()
    manager = _db_manager(_global_db, config)

    try:
        await manager.create_all()
        rootfs_db_obj = RootfsDatabase(manager, config)
        payload = await rootfs_db_obj.collect_binary_payload(
            binary, rootfs="/", debugfs=None, load_types=True
        )
        stats = await rootfs_db_obj.apply_single_payload(payload)
        console.print(
            f"[green]✓ {binary}: {stats['types']} types, {stats['members']} members, "
            f"{stats['lines']} line records[/green]"
        )
        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def cast_mem(
    type_name: str = typer.Option(..., "--type", help="Struct/typedef name to interpret memory as"),
    binary: str = typer.Option(..., "--binary", "-b", help="Binary name (e.g. libc.so.6)"),
    mem: str = typer.Option(..., "--mem", help="Hex bytes or @path to binary file"),
    addr: str = typer.Option("0x0", "--addr", help="Base address offset within mem (hex)"),
) -> None:
    """
    Interpret raw memory bytes as a named C struct.

    --mem can be a hex string (e.g. 0102030405060708) or @/path/to/dump.bin.
    --addr specifies the byte offset into the dump where the struct starts.

    Example:
        baldrick --db session.db cast-mem --type pthread_mutex_t --binary libc.so.6 \\
            --mem 0000000000000000010000000000000000000000
        baldrick --db session.db cast-mem --type pthread_mutex_t --binary libc.so.6 \\
            --mem @/tmp/memdump.bin --addr 0x1000
    """
    from blackadder.dwarf_query import get_binary_id, resolve_and_flatten

    # --- Parse memory bytes ---
    try:
        base_offset = int(addr, 16)
    except ValueError:
        console.print(f"[red]Error: invalid --addr: {addr!r}[/red]")
        raise typer.Exit(1)

    if mem.startswith("@"):
        file_path = mem[1:]
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
        except OSError as e:
            console.print(f"[red]Error reading {file_path}: {e}[/red]")
            raise typer.Exit(1)
        buf = raw[base_offset:]
    else:
        hex_str = mem.replace(" ", "").replace("0x", "")
        try:
            buf = bytes.fromhex(hex_str)
        except ValueError as e:
            console.print(f"[red]Error: invalid hex in --mem: {e}[/red]")
            raise typer.Exit(1)
        buf = buf[base_offset:]

    config = _get_config_or_default()
    manager = _db_manager(_global_db, config)

    try:
        await manager.create_all()

        bin_id = await get_binary_id(manager, binary)
        if bin_id is None:
            console.print(f"[red]Binary not found: {binary!r}[/red]")
            raise typer.Exit(1)

        result = await resolve_and_flatten(manager, type_name, bin_id)
        if result is None:
            console.print(f"[red]Type not found: {type_name!r} in {binary}[/red]")
            raise typer.Exit(1)

        root, flat = result
        if root.tag not in ("structure_type", "union_type"):
            console.print(
                f"[yellow]Warning: {type_name!r} resolves to tag={root.tag!r}, not a struct/union[/yellow]"
            )

        # --- Render table ---
        table = Table(title=f"cast-mem: {type_name} @ {binary}")
        table.add_column("Offset", style="cyan")
        table.add_column("Field", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Value (hex)", style="magenta")
        table.add_column("Value (dec)", style="white")

        for foffset, fpath, ftname, fbsize, fenc in flat:
            if fbsize and fbsize > 0 and foffset + fbsize <= len(buf):
                raw_bytes = buf[foffset : foffset + fbsize]
                hex_val = raw_bytes.hex()
                # Interpret as integer
                signed = fenc in ("signed", "signed_char") if fenc else False
                try:
                    int_val = int.from_bytes(raw_bytes, "little", signed=signed)
                    dec_val = str(int_val)
                except Exception:
                    dec_val = "?"
            else:
                hex_val = "?" if foffset >= len(buf) else "…"
                dec_val = "?"
            table.add_row(
                f"+{foffset:#06x}",
                fpath,
                ftname,
                hex_val,
                dec_val,
            )

        console.print(table)
        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def load_process(
    maps_file: str | None = typer.Option(None, "--maps", "-m", help="Path to /proc/PID/maps file"),
    pid: int | None = typer.Option(None, "--pid", "-p", help="Running process PID"),
    core_file: str | None = typer.Option(
        None, "--coredump", "-C", help="Path to ELF core dump file"
    ),
    gdb_dump_file: str | None = typer.Option(
        None,
        "--gdb-dump",
        "-G",
        help="Path to GDB text dump (output of 'thread apply all bt full' + 'info registers'). "
        "Can be combined with --coredump or --maps to add thread backtraces and registers.",
    ),
    rootfs: str = typer.Option("/", "--rootfs", "-R", help="Path to rootfs"),
    debugfs: str | None = typer.Option(None, "--debugfs", "-D", help="Path to debugfs"),
    tag: str | None = typer.Option(
        None, "--tag", "-T", help="Human-readable label for this snapshot"
    ),
    snapshot_id: int | None = typer.Option(
        None, "--snapshot-id", "-s", help="Merge data into this existing snapshot"
    ),
    update: bool = typer.Option(
        False, "--update", "-u", help="Allow updating/merging into an existing snapshot"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="When merging with --tag, steal the tag from another snapshot if needed",
    ),
) -> None:
    """
    Load process memory mappings into the database.

    Accepts /proc/maps, a live PID, or an ELF core dump as input.
    Optionally enrich with a GDB text dump (thread backtraces + registers).
    Also extracts and stores binary metadata (sections, symbols) for all mapped files.

    When --tag or --snapshot-id point to an existing snapshot, use --update / -u
    to merge new data into it instead of creating a new snapshot.

    Example:
        baldrick load-process --pid 12345
        baldrick load-process --pid 12345 --tag myapp
        baldrick load-process --coredump core.dump
        baldrick load-process --coredump core.dump --gdb-dump threads.txt
        baldrick load-process --snapshot-id 3 --gdb-dump threads.txt --update
        baldrick load-process --tag myapp --gdb-dump threads.txt --update
    """
    from blackadder.exceptions import DatabaseConstraintError, ProcessNotFoundError

    sources = [maps_file, pid, core_file, gdb_dump_file]
    if not any(s is not None for s in sources):
        console.print("[red]Error: Specify --maps, --pid, --coredump, or --gdb-dump[/red]")
        raise typer.Exit(1)

    config = _get_config_or_default()

    try:
        proc_manager = _db_manager(_global_db, config)
        await proc_manager.create_all()
        db_proc = ProcessDatabase(proc_manager, config)

        # ── Resolve existing snapshot ────────────────────────────────────────
        existing = None
        try:
            existing = await db_proc.resolve_snapshot(tag=tag, snapshot_id=snapshot_id)
        except ProcessNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        except DatabaseConstraintError as e:
            console.print(f"[red]Error: {e}[/red]")
            if not force:
                raise typer.Exit(1)
            # --force: re-resolve without raising, merge will steal the tag
            existing = await db_proc.resolve_snapshot(tag=None, snapshot_id=snapshot_id)

        # ── Guard: update requires -u ────────────────────────────────────────
        if existing is not None and not update:
            hint = f"--snapshot-id {existing.id}"
            if existing.tag:
                hint += f"  (tag: {existing.tag!r})"
            console.print(
                f"[red]Error: Snapshot already exists ({hint}).\n"
                f"Use --update / -u to merge new data into it.[/red]"
            )
            raise typer.Exit(1)

        # ── Read input files ─────────────────────────────────────────────────
        maps_text: str | None = None
        gdb_text: str | None = None

        if maps_file or (pid and not core_file):
            if pid and not maps_file:
                proc_maps_path = f"/proc/{pid}/maps"
                try:
                    with open(proc_maps_path) as f:
                        maps_text = f.read()
                except (FileNotFoundError, PermissionError) as e:
                    console.print(f"[red]Error: Cannot read {proc_maps_path}: {e}[/red]")
                    raise typer.Exit(1)
            elif maps_file:
                maps_path = Path(maps_file)
                if not maps_path.exists():
                    console.print(f"[red]Error: maps file not found: {maps_file}[/red]")
                    raise typer.Exit(1)
                with open(maps_path) as f:
                    maps_text = f.read()

        if gdb_dump_file:
            gdb_path = Path(gdb_dump_file)
            if not gdb_path.exists():
                console.print(f"[red]Error: GDB dump file not found: {gdb_dump_file}[/red]")
                raise typer.Exit(1)
            gdb_text = gdb_path.read_text(errors="replace")

        # ── Create or merge ──────────────────────────────────────────────────
        if existing is None:
            # ── CREATE new snapshot ──────────────────────────────────────────
            if core_file:
                core_path = Path(core_file)
                if not core_path.exists():
                    console.print(f"[red]Error: core dump file not found: {core_file}[/red]")
                    raise typer.Exit(1)
                console.print(f"[blue]Parsing core dump from {core_file}...[/blue]")
                process = await db_proc.load_core_dump(
                    str(core_path), rootfs=rootfs, debugfs=debugfs or rootfs, tag=tag
                )
            elif maps_text is not None:
                console.print("[blue]Loading memory mappings...[/blue]")
                process = await db_proc.load_maps(
                    pid, maps_text, rootfs=rootfs, debugfs=debugfs or rootfs, tag=tag
                )
            else:
                # gdb_dump only — create a minimal bare snapshot then load dump into it
                from sqlalchemy.orm import selectinload as _sil
                from sqlmodel import select as _sel

                from blackadder.models import ProcessSnapshot as _PS

                console.print("[blue]Creating snapshot from GDB dump...[/blue]")
                async with proc_manager.get_session() as _sess:
                    _snap = _PS(pid=pid, description="GDB dump", source_type="gdb_dump", tag=tag)
                    _sess.add(_snap)
                    await _sess.commit()
                    _snap_id = _snap.id
                await db_proc.load_gdb_dump(_snap_id, gdb_text)  # type: ignore[arg-type]
                async with proc_manager.get_session() as _sess:
                    _r = await _sess.execute(  # type: ignore
                        _sel(_PS).where(_PS.id == _snap_id).options(_sil(_PS.mappings))  # type: ignore[arg-type]
                    )
                    loaded_process = _r.scalars().first()
                    if loaded_process is None:
                        raise RuntimeError(f"Snapshot disappeared: id={_snap_id}")
                    process = loaded_process
                gdb_text = None  # already loaded above

            # Enrich with GDB dump if also provided alongside core/maps
            if gdb_text:
                console.print(f"[blue]Parsing GDB dump from {gdb_dump_file}...[/blue]")
                if process.id is None:
                    raise RuntimeError("Snapshot was not assigned an ID")
                await db_proc.load_gdb_dump(process.id, gdb_text)

            mode_label = "created"

        else:
            # ── MERGE into existing snapshot ─────────────────────────────────
            console.print(f"[blue]Merging into snapshot #{existing.id}...[/blue]")
            if core_file:
                core_path_str = str(Path(core_file).resolve())
                if not Path(core_file).exists():
                    console.print(f"[red]Error: core dump file not found: {core_file}[/red]")
                    raise typer.Exit(1)
            else:
                core_path_str = None

            process = await db_proc.merge_into_snapshot(
                existing,
                pid=pid,
                maps_text=maps_text,
                core_path=core_path_str,
                gdb_text=gdb_text,
                rootfs=rootfs,
                debugfs=debugfs or rootfs,
                new_tag=tag,
                force_tag=force,
            )
            mode_label = f"updated (merged into #{existing.id})"

        # Build section lookup and collect debug_file info in one DB pass
        from sqlmodel import select as sql_select

        from blackadder.models import BinaryLocator

        debug_file_map: dict[str, str] = {}  # binary pathname -> debug file path
        unique_paths = {
            m.pathname for m in process.mappings if m.pathname and not m.pathname.startswith("[")
        }
        async with proc_manager.get_session() as session:
            for path in unique_paths:
                loc = (
                    (
                        await session.execute(
                            sql_select(BinaryLocator).where(BinaryLocator.path == path)
                        )
                    )
                    .scalars()
                    .first()
                )
                if not loc:
                    continue
                if loc.debug_file:
                    debug_file_map[path] = loc.debug_file

        # Build process summary
        mappings = process.mappings
        total_size = sum(m.end_addr - m.start_addr for m in mappings)

        libs = {
            m.pathname
            for m in mappings
            if m.pathname and not m.pathname.startswith("[") and m.pathname != "[anonymous]"
        }
        heap_regions = [
            m
            for m in mappings
            if m.pathname in ("[heap]", "[anonymous]")
            or (not m.pathname or m.pathname == "[anonymous]")
            and "rw" in m.perms
        ]
        stack_regions = [
            m
            for m in mappings
            if m.pathname and (m.pathname == "[stack]" or m.pathname.startswith("[stack:"))
        ]
        anon_regions = [m for m in mappings if not m.pathname or m.pathname == "[anonymous]"]
        rwx_regions = [m for m in mappings if "r" in m.perms and "w" in m.perms and "x" in m.perms]

        def _fmt_size(n: int) -> str:
            if n >= 1024**3:
                return f"{n / 1024**3:.1f} GB"
            if n >= 1024**2:
                return f"{n / 1024**2:.1f} MB"
            if n >= 1024:
                return f"{n / 1024:.1f} KB"
            return f"{n} B"

        # Try to read thread count from /proc/PID/status (live process only)
        thread_count: int | None = None
        if pid:
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("Threads:"):
                            thread_count = int(line.split()[1])
                            break
            except OSError:
                pass

        summary = Table(title="Process Snapshot", show_header=False, box=None)
        summary.add_column("Key", style="bold cyan", no_wrap=True)
        summary.add_column("Value", style="white")

        pid_str = str(process.pid) if process.pid else "—"
        tag_str = f"  [dim](tag: {process.tag})[/dim]" if process.tag else ""
        summary.add_row("Snapshot ID", str(process.id))
        summary.add_row("Mode", mode_label)
        summary.add_row("PID", f"{pid_str}{tag_str}")
        summary.add_row("Mappings", str(len(mappings)))
        summary.add_row("Total mapped", _fmt_size(total_size))
        summary.add_row("Libraries", str(len(libs)))
        summary.add_row("Heap regions", str(len(heap_regions)))
        summary.add_row("Stack regions", str(len(stack_regions)))
        if thread_count is not None:
            summary.add_row("Threads", str(thread_count))
        summary.add_row("Anonymous regions", str(len(anon_regions)))
        if rwx_regions:
            summary.add_row("[yellow]RWX regions[/yellow]", f"[yellow]{len(rwx_regions)}[/yellow]")
        if debug_file_map:
            summary.add_row("Debug files", str(len(debug_file_map)))

        console.print()
        console.print(summary)

        if debug_file_map:
            console.print()
            dbg_table = Table(title="Debug Files", show_header=True)
            dbg_table.add_column("Binary", style=_theme.binary)
            dbg_table.add_column("Debug File", style=_theme.debug)
            for bin_path in sorted(debug_file_map):
                dbg_table.add_row(bin_path, debug_file_map[bin_path])
            console.print(dbg_table)

        # Show threads table if threads were loaded
        from sqlmodel import select as sqlmodel_select

        from blackadder.models import Thread as ThreadModel

        async with proc_manager.get_session() as _sess:
            _result = await _sess.execute(  # type: ignore
                sqlmodel_select(ThreadModel)
                .where(ThreadModel.process_id == process.id)
                .order_by(ThreadModel.tid)  # type: ignore[arg-type]
            )
            db_threads = _result.scalars().all()

        if db_threads:
            console.print()
            thr_table = Table(title="Threads")
            thr_table.add_column("TID", style=_theme.meta, no_wrap=True)
            thr_table.add_column("Name", style=_theme.symbol, no_wrap=True)
            thr_table.add_column("Wait (wchan)", style=_theme.description)
            thr_table.add_column("Syscall", style=_theme.flags)
            thr_table.add_column("Stack start", style=_theme.address, no_wrap=True)
            thr_table.add_column("Stack end", style=_theme.address, no_wrap=True)
            for t in db_threads:
                thr_table.add_row(
                    str(t.tid),
                    t.name or "—",
                    t.wchan or "—",
                    (t.syscall or "—")[:40],
                    f"{t.stack_start:#x}" if t.stack_start else "—",
                    f"{t.stack_end:#x}" if t.stack_end else "—",
                )
            console.print(thr_table)

        await proc_manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def decode_backtrace(
    trace_file: str | None = typer.Option(
        None, "--trace", "-t", help="Backtrace file (default: stdin)"
    ),
    snapshot_id: int | None = typer.Option(
        None, "--snapshot-id", "-s", help="Process snapshot ID (default: latest)"
    ),
    rootfs: str = typer.Option("/", "--rootfs", "-R", help="Path to rootfs"),
    debugfs: str | None = typer.Option(None, "--debugfs", "-D", help="Path to debugfs"),
    jobs: int = typer.Option(32, "--jobs", "-j", help="Max parallel symbol resolutions"),
) -> None:
    """
    Decode backtrace to function names and optional line numbers.

    Auto-detects input format:
    - Raw hex addresses (0x400a1c, one per line)
    - GDB backtrace format (#0 0x400a1c in function...)
    - Kernel format ([<ffffffff81000001>] function+0x42/0x100)

    Example:
        baldrick decode-backtrace --snapshot-id 1 --trace trace.txt
        cat trace.txt | baldrick decode-backtrace
    """
    config = _get_config_or_default()
    config.max_subprocess_workers = jobs

    try:
        if trace_file:
            trace_path = Path(trace_file)
            if not trace_path.exists():
                console.print(f"[red]Error: trace file not found: {trace_file}[/red]")
                raise typer.Exit(1)
            with open(trace_path) as f:
                trace_text = f.read()
        else:
            console.print("[blue]Reading backtrace from stdin...[/blue]")
            trace_text = sys.stdin.read()

        if not trace_text.strip():
            console.print("[red]Error: No backtrace input[/red]")
            raise typer.Exit(1)

        console.print("[blue]Parsing backtrace format...[/blue]")
        addresses = parse_backtrace_auto(trace_text)

        if not addresses:
            console.print("[red]Error: Could not parse any addresses from backtrace[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓ Found {len(addresses)} addresses[/green]")

        init_parser(config)

        console.print(f"[blue]Decoding backtrace with {jobs} parallel workers...[/blue]")

        manager = _db_manager(_global_db, config)
        db_proc = ProcessDatabase(manager, config)
        snapshot_id = await _resolve_snapshot_id(db_proc, snapshot_id)
        frames = await db_proc.decode_backtrace(snapshot_id, addresses)

        console.print()
        table = Table(title="Decoded Backtrace")
        table.add_column("#", style=_theme.meta, width=3)
        table.add_column("Address", style=_theme.address)
        table.add_column("Symbol", style=_theme.symbol)
        table.add_column("Location", style=_theme.debug)

        for frame in frames:
            location = ""
            if frame.file and frame.line:
                location = f"{frame.file}:{frame.line}"
            elif frame.file:
                location = frame.file

            table.add_row(
                str(frame.frame_num),
                f"{frame.address:#x}",
                frame.symbol,
                location,
            )

        console.print(table)
        console.print(f"\n[green]✓ Decoded {len(frames)} frames[/green]")
        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def decode_address(
    addresses: list[str] = typer.Argument(help="Addresses to resolve (hex)"),
    rootfs: str = typer.Option("/", "--rootfs", "-R", help="Path to rootfs"),
    debugfs: str | None = typer.Option(None, "--debugfs", "-D", help="Path to debugfs"),
    mapped: bool = typer.Option(
        False, "--mapped", "-a", help="Addresses are virtual (process address space)"
    ),
    unmapped: bool = typer.Option(
        False, "--unmapped", "-A", help="Addresses are offsets within a binary file"
    ),
    snapshot_id: int | None = typer.Option(
        None, "--snapshot-id", "-s", help="Process snapshot ID for --mapped mode (default: latest)"
    ),
    binary_file: str | None = typer.Option(
        None, "--binary", "-b", help="Binary file path (for --unmapped mode)"
    ),
    show_name: bool = typer.Option(False, "--name", "-n", help="Print only symbol name"),
    show_type: bool = typer.Option(False, "--type", "-t", help="Also show symbol type"),
    show_section: bool = typer.Option(False, "--section", "-j", help="Also show section name"),
    show_full: bool = typer.Option(False, "--full", "-F", help="Show all available fields"),
) -> None:
    """
    Resolve addresses to symbols and memory information.

    Two modes:
      --mapped   [--snapshot-id N]  address is virtual (from process address space)
      --unmapped --binary PATH      address is an offset within the binary file

    Multiple addresses can be passed as positional arguments.
    If --snapshot-id is omitted in --mapped mode, the latest snapshot is used.

    Example:
        baldrick decode-address --mapped --snapshot-id 1 -- 0x400a1c 0x400a2c
        baldrick decode-address --unmapped --binary /lib/libc.so.6 -- 0x1c5c0
        baldrick decode-address --mapped --snapshot-id 1 --full -- 0x400a1c
    """
    if not addresses:
        console.print("[red]Error: Provide at least one address[/red]")
        raise typer.Exit(1)

    # Infer mode from flags/params if not explicit
    if not mapped and not unmapped:
        if binary_file:
            unmapped = True
        else:
            mapped = True  # default

    if mapped and unmapped:
        console.print("[red]Error: --mapped and --unmapped are mutually exclusive[/red]")
        raise typer.Exit(1)

    if unmapped and not binary_file:
        console.print("[red]Error: --unmapped requires --binary <path>[/red]")
        raise typer.Exit(1)

    config = _get_config_or_default()

    # Parse addresses
    parsed_addrs: list[int] = []
    for raw in addresses:
        try:
            parsed_addrs.append(int(raw, 16))
        except ValueError:
            console.print(f"[red]Error: Invalid hex address: {raw!r}[/red]")
            raise typer.Exit(1)

    need_db_lookup = show_type or show_section or show_full
    shared_mgr = _db_manager(_global_db, config)
    rootfs_db_obj = RootfsDatabase(shared_mgr, config) if need_db_lookup else None

    init_parser(config)

    try:
        from blackadder.binutils import resolve_symbol
        from blackadder.db import ProcessDatabase

        rows: list[dict[str, Any]] = []

        if mapped:
            db_proc = ProcessDatabase(shared_mgr, config)
            snapshot_id = await _resolve_snapshot_id(db_proc, snapshot_id)

            for addr in parsed_addrs:
                binary_info = await db_proc.address_to_binary(snapshot_id, addr)
                if not binary_info:
                    rows.append({"address": addr, "binary": "???", "offset": 0, "symbol": "???"})
                    continue
                bin_path, offset, _binary_id = binary_info
                symbol = await resolve_symbol(bin_path, offset, config)
                resolved_row = {
                    "address": addr,
                    "binary": bin_path,
                    "offset": offset,
                    "symbol": symbol,
                }
                if need_db_lookup and rootfs_db_obj:
                    sym_info = await rootfs_db_obj.find_symbol_at_offset(bin_path, offset)
                    resolved_row["sym_type"] = sym_info["sym_type"] if sym_info else "?"
                    resolved_row["section"] = sym_info["section"] if sym_info else "?"
                rows.append(resolved_row)

        else:  # unmapped
            standalone_path = binary_file
            if standalone_path is None:
                raise RuntimeError("Binary path is required for unmapped addresses")
            for offset in parsed_addrs:
                symbol = await resolve_symbol(standalone_path, offset, config)
                resolved_row = {
                    "address": offset,
                    "binary": standalone_path,
                    "offset": offset,
                    "symbol": symbol,
                }
                if need_db_lookup and rootfs_db_obj:
                    sym_info = await rootfs_db_obj.find_symbol_at_offset(standalone_path, offset)
                    resolved_row["sym_type"] = sym_info["sym_type"] if sym_info else "?"
                    resolved_row["section"] = sym_info["section"] if sym_info else "?"
                rows.append(resolved_row)

        # Output
        if show_name:
            for display_row in rows:
                console.print(display_row["symbol"])
        else:
            table = Table(title="Address Resolution")
            table.add_column("Address", style=_theme.address)
            if mapped:
                table.add_column("Binary", style=_theme.binary)
                table.add_column("Offset", style=_theme.address)
            table.add_column("Symbol", style=_theme.symbol)
            if show_type or show_full:
                table.add_column("Type", style=_theme.flags)
            if show_section or show_full:
                table.add_column("Section", style=_theme.section)

            for display_row in rows:
                cells = [f"{display_row['address']:#x}"]
                if mapped:
                    cells += [display_row["binary"], f"{display_row['offset']:#x}"]
                cells.append(display_row["symbol"])
                if show_type or show_full:
                    cells.append(display_row.get("sym_type", "?"))
                if show_section or show_full:
                    cells.append(display_row.get("section", "?"))
                table.add_row(*cells)

            console.print(table)

        await shared_mgr.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def analyse_memory(
    rootfs: str = typer.Option("/", "--rootfs", "-R", help="Path to rootfs"),
    debugfs: str | None = typer.Option(None, "--debugfs", "-D", help="Path to debugfs"),
    maps_file: str | None = typer.Option(None, "--maps", "-m", help="Path to /proc/PID/maps file"),
    pid: int | None = typer.Option(None, "--pid", "-p", help="Running process PID"),
    core_file: str | None = typer.Option(
        None, "--coredump", "-C", help="Path to ELF core dump file"
    ),
) -> None:
    """
    Analyze memory layout and detect anomalies.

    Accepts a maps file, a live PID, or a core dump as input.
    If --db is given the snapshot is stored; otherwise analysis is transient (in-memory).

    Example:
        baldrick analyse-memory --pid 12345
        baldrick analyse-memory --maps my_process_maps.txt
        baldrick analyse-memory --coredump core.dump
    """
    sources = [maps_file, pid, core_file]
    if not any(s is not None for s in sources):
        console.print("[red]Error: Specify --maps, --pid, or --coredump[/red]")
        raise typer.Exit(1)

    config = _get_config_or_default()

    try:
        # Use provided DB or an in-memory DB for transient analysis
        db_url = _to_db_url(_global_db) if _global_db else "sqlite+aiosqlite:///:memory:"
        manager = AsyncDatabaseManager(db_url)
        await manager.create_all()
        db_proc = ProcessDatabase(manager, config)

        if core_file:
            core_path = Path(core_file)
            if not core_path.exists():
                console.print(f"[red]Error: core dump file not found: {core_file}[/red]")
                raise typer.Exit(1)
            console.print(f"[blue]Parsing core dump {core_file}...[/blue]")
            process = await db_proc.load_core_dump(str(core_path))
        else:
            if pid and not maps_file:
                proc_maps_path = f"/proc/{pid}/maps"
                try:
                    with open(proc_maps_path) as f:
                        maps_text = f.read()
                except (FileNotFoundError, PermissionError) as e:
                    console.print(f"[red]Error: Cannot read {proc_maps_path}: {e}[/red]")
                    raise typer.Exit(1)
            else:
                if not maps_file:
                    console.print("[red]Error: Specify --maps, --pid, or --coredump[/red]")
                    raise typer.Exit(1)
                maps_path = Path(maps_file)
                if not maps_path.exists():
                    console.print(f"[red]Error: maps file not found: {maps_file}[/red]")
                    raise typer.Exit(1)
                with open(maps_path) as f:
                    maps_text = f.read()

            console.print("[blue]Loading memory mappings...[/blue]")
            process = await db_proc.load_maps(pid, maps_text)

        console.print(f"[blue]Analyzing memory layout ({len(process.mappings)} regions)...[/blue]")
        if process.id is None:
            raise RuntimeError("Process snapshot was not assigned an ID")
        result = await db_proc.analyze_memory_layout(process.id)

        console.print()
        console.print("[green]Memory Analysis Results[/green]")
        console.print(f"Regions analyzed: {result['regions_analyzed']}")
        console.print(f"Anomalies detected: {len(result['anomalies'])}")
        console.print(
            f"Corruption risk: {result['corruption_risk']:.1%} "
            f"({result['corruption_count']} suspicious regions)"
        )

        if result["anomalies"]:
            console.print()
            console.print("[yellow]Detected Anomalies:[/yellow]")
            for i, anomaly in enumerate(result["anomalies"], 1):
                console.print(f"  {i}. {anomaly}")

        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def analyse_deadlock(
    snapshot_id: int | None = typer.Option(
        None, "--snapshot-id", "-s", help="ProcessSnapshot ID to analyze (default: latest)"
    ),
    lock_state_file: str | None = typer.Option(
        None,
        "--lock-state",
        "-L",
        help="Path to find_deadlock GDB output (enables exact mutex ownership analysis)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON instead of Rich tables"),
) -> None:
    """
    Analyze threads of a process snapshot for deadlocks.

    Detects deadlocks with three evidence levels:
      certain  — mutex ownership known (from --lock-state GDB output, or futex syscall)
      probable — pthread_mutex_lock / __lll_lock_wait in backtrace
      possible — wchan shows futex wait, multiple blocked threads

    For highest accuracy provide GDB lock state:
        gdb -batch -ex "source _gdb/find_deadlock.py" -ex find_deadlock ./binary core \\
          > lock.json
        baldrick --db session.db analyse-deadlock -s 1 --lock-state lock.json

    Example:
        baldrick --db session.db analyse-deadlock --snapshot-id 1
        baldrick --db session.db analyse-deadlock -s 1 --lock-state lock.json
        baldrick --db session.db analyse-deadlock -s 1 --json
    """
    config = _get_config_or_default()

    try:
        manager = _db_manager(_global_db, config)
        await manager.create_all()
        db_proc = ProcessDatabase(manager, config)

        snapshot_id = await _resolve_snapshot_id(db_proc, snapshot_id)

        lock_state_text: str | None = None
        if lock_state_file:
            ls_path = Path(lock_state_file)
            if not ls_path.exists():
                console.print(f"[red]Error: lock state file not found: {lock_state_file}[/red]")
                raise typer.Exit(1)
            lock_state_text = ls_path.read_text(errors="replace")

        report = await db_proc.get_deadlock_report(snapshot_id, lock_state_text=lock_state_text)
        await manager.close()

        if output_json:
            import json
            from dataclasses import asdict

            console.print(json.dumps(asdict(report), indent=2))
            return

        # ── Header ────────────────────────────────────────────────────────────
        level_color = {
            "certain": "red",
            "probable": "yellow",
            "possible": "cyan",
            "none": "green",
        }.get(report.evidence_level, "white")

        console.print()
        console.print(
            f"[bold]Deadlock Analysis[/bold] — snapshot [cyan]#{snapshot_id}[/cyan]"
            f"  Evidence: [{level_color}]{report.evidence_level}[/{level_color}]"
        )

        if report.evidence_level == "none":
            console.print("[green]✓ No blocked threads detected.[/green]")
            return

        # ── Cycles ────────────────────────────────────────────────────────────
        if report.cycles:
            for i, cycle in enumerate(report.cycles, 1):
                lvl_color = {
                    "certain": "red",
                    "probable": "yellow",
                    "possible": "cyan",
                }.get(cycle.evidence_level, "white")
                console.print()
                console.print(
                    f"[bold][{lvl_color}][CYCLE {i}][/{lvl_color}][/bold] "
                    f"({cycle.evidence_level}): "
                    + " → ".join(f"TID {t}" for t in cycle.tids)
                    + (f" → TID {cycle.tids[0]}" if len(cycle.tids) > 1 else "")
                )
                console.print(f"  {cycle.description}")

        # ── Suspected (blocked but no cycle) ─────────────────────────────────
        if report.suspected_threads:
            console.print()
            sus_table = Table(title="Suspected Blocked Threads", show_header=True)
            sus_table.add_column("TID", style=_theme.meta, no_wrap=True)
            sus_table.add_column("Name", style=_theme.symbol)
            sus_table.add_column("Evidence", style=_theme.flags)
            sus_table.add_column("Waiting for", style=_theme.address)
            for dt in report.suspected_threads:
                sus_table.add_row(
                    str(dt.tid),
                    dt.name or "—",
                    dt.evidence,
                    f"{dt.waiting_for:#x}" if dt.waiting_for else "—",
                )
            console.print(sus_table)

        # ── Summary ───────────────────────────────────────────────────────────
        if report.summary:
            console.print()
            console.print(f"[dim]{report.summary}[/dim]")

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def report(
    snapshot_id: int | None = typer.Option(
        None, "--snapshot-id", "-s", help="ProcessSnapshot ID (default: latest)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """
    Generate a comprehensive debug report for a process snapshot.

    Combines snapshot info, thread state, memory anomalies, deadlock analysis,
    and crash pattern detection into a single report.

    Example:
        baldrick --db session.db report
        baldrick --db session.db report --snapshot-id 1
        baldrick --db session.db report --snapshot-id 1 --json
    """
    import json as _json
    from dataclasses import asdict

    from sqlmodel import select as sql_select

    from blackadder.crash_patterns import CrashPatternEngine
    from blackadder.models import (
        BacktraceEntry,
        MemoryMapping,
        ProcessRegisterState,
        ProcessSnapshot,
        Thread,
    )

    config = _get_config_or_default()

    try:
        manager = _db_manager(_global_db, config)
        await manager.create_all()
        db_proc = ProcessDatabase(manager, config)

        snapshot_id = await _resolve_snapshot_id(db_proc, snapshot_id)

        async with manager.get_session() as session:
            snap_result = await session.execute(  # type: ignore
                sql_select(ProcessSnapshot).where(ProcessSnapshot.id == snapshot_id)
            )
            snapshot = snap_result.scalar_one_or_none()
            if snapshot is None:
                console.print(f"[red]Error: Snapshot #{snapshot_id} not found.[/red]")
                raise typer.Exit(1)

            threads = (
                (
                    await session.execute(  # type: ignore
                        sql_select(Thread).where(Thread.process_id == snapshot_id)
                    )
                )
                .scalars()
                .all()
            )

            backtraces = (
                (
                    await session.execute(  # type: ignore
                        sql_select(BacktraceEntry).where(BacktraceEntry.process_id == snapshot_id)
                    )
                )
                .scalars()
                .all()
            )

            mappings = (
                (
                    await session.execute(  # type: ignore
                        sql_select(MemoryMapping).where(MemoryMapping.process_id == snapshot_id)
                    )
                )
                .scalars()
                .all()
            )

            register_states = (
                (
                    await session.execute(  # type: ignore
                        sql_select(ProcessRegisterState).where(
                            ProcessRegisterState.process_id == snapshot_id
                        )
                    )
                )
                .scalars()
                .all()
            )

        deadlock_report = await db_proc.get_deadlock_report(snapshot_id)
        memory_result = await db_proc.analyze_memory_layout(snapshot_id)
        await manager.close()

        pattern_report = CrashPatternEngine(
            threads=list(threads),
            backtraces=list(backtraces),
            mappings=list(mappings),
            register_states=list(register_states),
            deadlock_report=deadlock_report,
        ).analyze()

        # ── JSON output ───────────────────────────────────────────────────────
        if output_json:
            result = {
                "snapshot": snapshot.model_dump(),
                "threads": [
                    {"tid": t.tid, "name": t.name, "wchan": t.wchan, "syscall": t.syscall}
                    for t in threads
                ],
                "memory": memory_result,
                "deadlock": asdict(deadlock_report),
                "crash_patterns": asdict(pattern_report),
            }
            console.print(_json.dumps(result, indent=2, default=str))
            return

        # ── Rich output ───────────────────────────────────────────────────────
        console.print()
        console.print("[bold cyan]═══ Blackadder Debug Report ═══[/bold cyan]")

        # 1. Header
        src = snapshot.source_type or "unknown"
        pid_str = str(snapshot.pid) if snapshot.pid else "—"
        tag_str = snapshot.tag or "—"
        console.print(
            f"  Snapshot [cyan]#{snapshot.id}[/cyan]  "
            f"PID [yellow]{pid_str}[/yellow]  "
            f"source=[dim]{src}[/dim]  "
            f"tag=[dim]{tag_str}[/dim]  "
            f"[dim]{snapshot.created_at}[/dim]"
        )

        # 2. Threads
        console.print()
        console.print("[bold]Threads[/bold]")
        if threads:
            t_table = Table(show_header=True, header_style="bold")
            t_table.add_column("TID", style=_theme.meta, no_wrap=True)
            t_table.add_column("Name", style=_theme.symbol)
            t_table.add_column("wchan", style=_theme.description)
            t_table.add_column("syscall", style=_theme.flags)
            for t in list(threads)[:20]:
                t_table.add_row(
                    str(t.tid),
                    t.name or "—",
                    t.wchan or "—",
                    (t.syscall or "—")[:40],
                )
            console.print(t_table)
            if len(threads) > 20:
                console.print(f"[dim]  … {len(threads) - 20} more threads[/dim]")
        else:
            console.print("  [dim]No thread data.[/dim]")

        # 3. Memory Anomalies
        console.print()
        console.print("[bold]Memory Anomalies[/bold]")
        anomalies = memory_result.get("anomalies", [])
        corruption_risk = memory_result.get("corruption_risk", 0.0)
        if anomalies:
            risk_color = (
                "red" if corruption_risk > 0.3 else "yellow" if corruption_risk > 0.1 else "green"
            )
            console.print(
                f"  Corruption risk: [{risk_color}]{corruption_risk:.0%}[/{risk_color}]  "
                f"({memory_result.get('corruption_count', 0)} region(s))"
            )
            for a in anomalies[:10]:
                console.print(f"  [yellow]•[/yellow] {a}")
            if len(anomalies) > 10:
                console.print(f"  [dim]… {len(anomalies) - 10} more anomalies[/dim]")
        else:
            console.print("  [green]✓ No anomalies detected.[/green]")

        # 4. Deadlock
        console.print()
        console.print("[bold]Deadlock Analysis[/bold]")
        dl_color = {
            "certain": "red",
            "probable": "yellow",
            "possible": "cyan",
            "none": "green",
        }.get(deadlock_report.evidence_level, "white")
        console.print(f"  Evidence: [{dl_color}]{deadlock_report.evidence_level}[/{dl_color}]")
        if deadlock_report.evidence_level != "none":
            for cycle in deadlock_report.cycles:
                console.print(
                    f"  [red]CYCLE[/red] ({cycle.evidence_level}): "
                    + " → ".join(f"TID {t}" for t in cycle.tids)
                )
            for st in deadlock_report.suspected_threads:
                console.print(
                    f"  [yellow]SUSPECT[/yellow] TID {st.tid} ({st.name or '?'}) — {st.evidence}"
                )

        # 5. Crash Patterns
        console.print()
        console.print("[bold]Crash Patterns[/bold]")
        if pattern_report.patterns:
            cp_table = Table(show_header=True, header_style="bold")
            cp_table.add_column("Pattern", style=_theme.symbol, no_wrap=True)
            cp_table.add_column("Confidence", no_wrap=True)
            cp_table.add_column("Description", style=_theme.description)
            cp_table.add_column("Suggestion", style=_theme.meta)
            conf_colors = {"certain": "red", "probable": "yellow", "possible": "cyan"}
            for p in pattern_report.patterns:
                cc = conf_colors.get(p.confidence, "white")
                cp_table.add_row(
                    p.name,
                    f"[{cc}]{p.confidence}[/{cc}]",
                    p.description,
                    p.suggestion[:60] + ("…" if len(p.suggestion) > 60 else ""),
                )
            console.print(cp_table)
            for p in pattern_report.patterns:
                if p.evidence:
                    console.print(f"  [dim]{p.name} evidence:[/dim]")
                    for ev in p.evidence:
                        console.print(f"    [dim]• {ev}[/dim]")
        else:
            console.print("  [green]✓ No crash patterns detected.[/green]")

        # 6. Summary
        console.print()
        deadlock_yn = "YES" if deadlock_report.evidence_level != "none" else "no"
        dl_sum_color = "red" if deadlock_report.evidence_level != "none" else "green"
        console.print(
            f"[bold]Summary:[/bold] "
            f"{len(threads)} thread(s)  "
            f"{len(anomalies)} anomaly(ies)  "
            f"deadlock=[{dl_sum_color}]{deadlock_yn}[/{dl_sum_color}]  "
            f"{len(pattern_report.patterns)} pattern(s)  "
            f"[dim]{pattern_report.summary}[/dim]"
        )
        console.print()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def tag(
    args: list[str] = typer.Argument(
        default=None, help="[SNAPSHOT_ID] TAG  — snapshot ID is optional (default: latest)"
    ),
) -> None:
    """
    Set or update the tag on an existing process snapshot.

    Pass an empty string as tag to remove it.
    If snapshot_id is omitted, the most recently loaded snapshot is used.

    Example:
        baldrick --db session.db tag 1 crash-2026
        baldrick --db session.db tag crash-2026
        baldrick --db session.db tag 1 ""
    """
    from sqlmodel import select as sql_select

    from blackadder.db import ProcessDatabase
    from blackadder.models import ProcessSnapshot

    # Parse args: either [tag] or [snapshot_id, tag]
    snapshot_id: int | None = None
    new_tag: str
    if not args:
        console.print("[red]Error: tag requires at least a TAG argument[/red]")
        raise typer.Exit(1)
    elif len(args) == 1:
        new_tag = args[0]
    elif len(args) == 2:
        try:
            snapshot_id = int(args[0])
        except ValueError:
            console.print(f"[red]Error: Expected snapshot ID (integer), got {args[0]!r}[/red]")
            raise typer.Exit(1)
        new_tag = args[1]
    else:
        console.print("[red]Error: too many arguments. Usage: tag [SNAPSHOT_ID] TAG[/red]")
        raise typer.Exit(1)

    config = _get_config_or_default()
    manager = _db_manager(_global_db, config)

    try:
        await manager.create_all()
        db_proc = ProcessDatabase(manager, config)
        snapshot_id = await _resolve_snapshot_id(db_proc, snapshot_id)
        async with manager.get_session() as session:
            result = await session.execute(
                sql_select(ProcessSnapshot).where(ProcessSnapshot.id == snapshot_id)
            )
            snapshot = result.scalars().first()
            if snapshot is None:
                console.print(f"[red]Error: No snapshot with id={snapshot_id}[/red]")
                raise typer.Exit(1)
            old_tag = snapshot.tag
            snapshot.tag = new_tag or None
            session.add(snapshot)
            await session.commit()

        action = "removed" if not new_tag else f"set to [cyan]{new_tag}[/cyan]"
        old_str = f" (was [dim]{old_tag}[/dim])" if old_tag else ""
        console.print(f"[green]✓ Snapshot {snapshot_id}: tag {action}{old_str}[/green]")
        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


register_query_command(
    app,
    console,
    database_url=lambda: _global_db or _get_config_or_default().db,
    theme=lambda: _theme,
)
register_meta_commands(
    app,
    console,
    database_url=lambda: _global_db or _get_config_or_default().db,
    theme=lambda: _theme,
)


def main():
    """Entry point for baldrick CLI."""
    import asyncio
    import os

    import click

    from blackadder.queries import expand_aliases

    sys.argv[1:] = expand_aliases(sys.argv[1:])

    result = app(standalone_mode=False)
    if asyncio.iscoroutine(result):
        try:
            asyncio.run(result)
        except (click.exceptions.Exit, SystemExit) as e:
            exit_code = getattr(e, "code", 1) or 1
            os._exit(int(exit_code) if exit_code else 1)
        except Exception:
            os._exit(1)


if __name__ == "__main__":
    main()
