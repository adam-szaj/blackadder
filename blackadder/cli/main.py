"""
Baldrick CLI - main entry point for blackadder debugging tool.

Provides commands for:
- Loading binaries into rootfs database
- Loading process memory mappings
- Decoding backtraces
- Resolving addresses to symbols
- Analyzing memory layout
"""

import glob as glob_module
import re
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from blackadder.binutils import init_parser, parse_backtrace_auto
from blackadder.config import BlackadderConfig
from blackadder.db import AsyncDatabaseManager, ProcessDatabase
from blackadder.db.rootfs import RootfsDatabase
from blackadder.logging_config import setup_logging
from blackadder.theme import ColorTheme, column_style, format_value, load_theme

app = typer.Typer(
    help="Baldrick - Linux debugging tool for backtrace decoding and symbol resolution"
)
console = Console()

# Module-level storage for global options set in callback
_global_db: str | None = None
_theme: ColorTheme = ColorTheme()  # default Tokyo Night; overridden in callback


@app.callback()
def _global_options(
    debug: bool = typer.Option(False, "--debug", help="Enable DEBUG level logging"),
    log_level: str = typer.Option("WARNING", "--log-level", help="Log level (DEBUG, INFO, WARNING, ERROR)"),
    log_file: str | None = typer.Option(None, "--log-file", help="Write logs to file"),
    db: str | None = typer.Option(None, "--db", "-d", help="Path to database (overrides config default)"),
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


def _collect_binary_paths(
    rootfs: str,
    glob_pattern: str | None = None,
    perm: str | None = None,
    files_spec: str | None = None,
    maps_file: str | None = None,
    pid: int | None = None,
    core_file: str | None = None,
) -> list[str]:
    """
    Collect binary file paths from the given source.

    Returns a sorted, deduplicated list of absolute paths to binary files.
    """
    paths: set[str] = set()

    rootfs_base = rootfs.rstrip("/") or "/"

    if glob_pattern:
        full_pattern = str(Path(rootfs_base) / glob_pattern.lstrip("/"))
        for match in glob_module.glob(full_pattern, recursive=True):
            if Path(match).is_file():
                paths.add(match)

    if perm:
        mask, value = _parse_perm(perm)
        for p in Path(rootfs_base).rglob("*"):
            if p.is_file():
                try:
                    if p.stat().st_mode & mask == value:
                        paths.add(str(p))
                except PermissionError:
                    pass

    if files_spec:
        if files_spec.startswith("@"):
            with open(files_spec[1:]) as f:
                raw_paths = [line.strip() for line in f if line.strip()]
        else:
            raw_paths = [p for p in files_spec.split(":") if p]
        for p in raw_paths:
            full = str(Path(rootfs_base) / p.lstrip("/"))
            if Path(full).is_file():
                paths.add(full)
            elif Path(p).is_file():
                paths.add(p)

    if maps_file:
        with open(maps_file) as f:
            maps_text = f.read()
        paths.update(_collect_paths_from_maps_text(maps_text, rootfs))

    if pid:
        proc_maps = f"/proc/{pid}/maps"
        try:
            with open(proc_maps) as f:
                maps_text = f.read()
            paths.update(_collect_paths_from_maps_text(maps_text, rootfs))
        except PermissionError:
            console.print(f"[yellow]Warning: Cannot read {proc_maps} (permission denied)[/yellow]")
        except FileNotFoundError:
            console.print(f"[yellow]Warning: {proc_maps} not found - process {pid} may not exist[/yellow]")

    if core_file:
        # Parse coredump and extract binary pathnames from PT_LOAD mappings
        # (CoreDumpParser result may have empty pathnames for anonymous segments)
        import asyncio
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

        core_paths = asyncio.run(_get_core_paths())
        paths.update(core_paths)

    return sorted(paths)


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
    maps_file: str | None = typer.Option(
        None, "--maps", "-m", help="Path to /proc/PID/maps file"
    ),
    pid: int | None = typer.Option(
        None, "--pid", "-p", help="Running process PID (reads /proc/PID/maps)"
    ),
    core_file: str | None = typer.Option(
        None, "--coredump", "-C", help="Path to ELF core dump file"
    ),
) -> None:
    """
    Load binaries from rootfs into the rootfs database.

    Extracts sections, symbols, and debug info via objdump/readelf.
    Skips binaries already cached (identified by MD5).

    Example:
        baldrick load --rootfs /target --glob '**/*.so'
        baldrick load --rootfs /target --perm u+x
        baldrick load --rootfs /target --maps /proc/12345/maps
        baldrick load --rootfs /target --pid 12345
    """
    sources = [glob_pattern, perm, files_spec, maps_file, pid, core_file]
    if not any(s is not None for s in sources):
        console.print("[red]Error: Specify at least one source: --glob, --perm, --files, --maps, --pid, or --coredump[/red]")
        raise typer.Exit(1)

    config = _get_config_or_default()

    try:
        console.print("[blue]Collecting binary paths...[/blue]")
        binary_paths = _collect_binary_paths(
            rootfs=rootfs,
            glob_pattern=glob_pattern,
            perm=perm,
            files_spec=files_spec,
            maps_file=maps_file,
            pid=pid,
            core_file=core_file,
        )

        if not binary_paths:
            console.print("[yellow]No binary files found matching the given criteria.[/yellow]")
            raise typer.Exit(0)

        console.print(f"[green]Found {len(binary_paths)} binary file(s)[/green]")

        manager = _db_manager(_global_db, config)
        await manager.create_all()
        rootfs_db_obj = RootfsDatabase(manager, config)

        loaded = skipped = failed = 0
        for path in binary_paths:
            try:
                _, is_new, debug_file = await rootfs_db_obj.load_binary(path, rootfs=rootfs, debugfs=debugfs or rootfs)
                if is_new:
                    loaded += 1
                    if debug_file:
                        console.print(f"  [dim]debug: {debug_file}[/dim]")
                else:
                    skipped += 1
            except Exception as e:
                failed += 1
                console.print(f"[yellow]  Skip {path}: {e}[/yellow]")

        console.print(
            f"\n[green]✓ Done: {loaded} loaded, {skipped} already cached, {failed} failed[/green]"
        )
        await manager.close()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def load_process(
    maps_file: str | None = typer.Option(
        None, "--maps", "-m", help="Path to /proc/PID/maps file"
    ),
    pid: int | None = typer.Option(None, "--pid", "-p", help="Running process PID"),
    core_file: str | None = typer.Option(
        None, "--coredump", "-C", help="Path to ELF core dump file"
    ),
    rootfs: str = typer.Option("/", "--rootfs", "-R", help="Path to rootfs"),
    debugfs: str | None = typer.Option(None, "--debugfs", "-D", help="Path to debugfs"),
    tag: str | None = typer.Option(None, "--tag", "-T", help="Human-readable label for this snapshot"),
) -> None:
    """
    Load process memory mappings into the database.

    Accepts /proc/maps, a live PID, or an ELF core dump as input.
    Also extracts and stores binary metadata (sections, symbols) for all mapped files.

    Example:
        baldrick load-process --maps /proc/12345/maps --pid 12345
        baldrick load-process --pid 12345
        baldrick load-process --coredump core.dump
    """
    sources = [maps_file, pid, core_file]
    if not any(s is not None for s in sources):
        console.print("[red]Error: Specify --maps, --pid, or --coredump[/red]")
        raise typer.Exit(1)

    config = _get_config_or_default()

    try:
        proc_manager = _db_manager(_global_db, config)
        await proc_manager.create_all()
        db_proc = ProcessDatabase(proc_manager, config)

        if core_file:
            core_path = Path(core_file)
            if not core_path.exists():
                console.print(f"[red]Error: core dump file not found: {core_file}[/red]")
                raise typer.Exit(1)

            console.print(f"[blue]Parsing core dump from {core_file}...[/blue]")
            process = await db_proc.load_core_dump(str(core_path), rootfs=rootfs, debugfs=debugfs or rootfs, tag=tag)

        else:
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
            else:
                console.print("[red]Error: Specify --maps, --pid, or --coredump[/red]")
                raise typer.Exit(1)

            console.print(f"[blue]Loading memory mappings...[/blue]")
            process = await db_proc.load_maps(pid, maps_text, rootfs=rootfs, debugfs=debugfs or rootfs, tag=tag)

        # Build section lookup and collect debug_file info in one DB pass
        from blackadder.models import BinaryLocator
        from sqlmodel import select as sql_select

        debug_file_map: dict[str, str] = {}  # binary pathname -> debug file path
        unique_paths = {m.pathname for m in process.mappings if m.pathname and not m.pathname.startswith("[")}
        async with proc_manager.get_session() as session:
            for path in unique_paths:
                loc = (await session.execute(
                    sql_select(BinaryLocator).where(BinaryLocator.path == path)
                )).scalars().first()
                if not loc:
                    continue
                if loc.debug_file:
                    debug_file_map[path] = loc.debug_file

        # Build process summary
        mappings = process.mappings
        total_size = sum(m.end_addr - m.start_addr for m in mappings)

        libs = {m.pathname for m in mappings
                if m.pathname and not m.pathname.startswith("[") and m.pathname != "[anonymous]"}
        heap_regions = [m for m in mappings if m.pathname in ("[heap]", "[anonymous]")
                        or (not m.pathname or m.pathname == "[anonymous]") and "rw" in m.perms]
        stack_regions = [m for m in mappings
                         if m.pathname and (m.pathname == "[stack]" or m.pathname.startswith("[stack:"))]
        anon_regions = [m for m in mappings
                        if not m.pathname or m.pathname == "[anonymous]"]
        rwx_regions = [m for m in mappings if "r" in m.perms and "w" in m.perms and "x" in m.perms]

        def _fmt_size(n: int) -> str:
            if n >= 1024 ** 3:
                return f"{n / 1024**3:.1f} GB"
            if n >= 1024 ** 2:
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
    pid: int = typer.Option(..., "--pid", "-p", help="Process snapshot ID"),
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
        baldrick decode-backtrace --pid 1 --trace trace.txt
        cat trace.txt | baldrick decode-backtrace --pid 1
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
        frames = await db_proc.decode_backtrace(pid, addresses)

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
    pid: int | None = typer.Option(
        None, "--pid", "-p", help="Process snapshot ID (for --mapped mode)"
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
      --mapped   [--pid N]    address is virtual (from process address space)
      --unmapped --binary PATH address is an offset within the binary file

    Multiple addresses can be passed as positional arguments.

    Example:
        baldrick decode-address --mapped --pid 1 -- 0x400a1c 0x400a2c
        baldrick decode-address --unmapped --binary /lib/libc.so.6 -- 0x1c5c0
        baldrick decode-address --mapped --pid 1 --full -- 0x400a1c
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

    if mapped and pid is None:
        console.print("[red]Error: --mapped requires --pid <snapshot-id>[/red]")
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

        rows: list[dict] = []

        if mapped:
            db_proc = ProcessDatabase(shared_mgr, config)

            for addr in parsed_addrs:
                binary_info = await db_proc.address_to_binary(pid, addr)
                if not binary_info:
                    rows.append({"address": addr, "binary": "???", "offset": 0, "symbol": "???"})
                    continue
                bin_path, offset = binary_info
                symbol = await resolve_symbol(bin_path, offset, config)
                row = {"address": addr, "binary": bin_path, "offset": offset, "symbol": symbol}
                if need_db_lookup and rootfs_db_obj:
                    sym_info = await rootfs_db_obj.find_symbol_at_offset(bin_path, offset)
                    row["sym_type"] = sym_info["sym_type"] if sym_info else "?"
                    row["section"] = sym_info["section"] if sym_info else "?"
                rows.append(row)

        else:  # unmapped
            bin_path = binary_file
            for offset in parsed_addrs:
                symbol = await resolve_symbol(bin_path, offset, config)
                row = {"address": offset, "binary": bin_path, "offset": offset, "symbol": symbol}
                if need_db_lookup and rootfs_db_obj:
                    sym_info = await rootfs_db_obj.find_symbol_at_offset(bin_path, offset)
                    row["sym_type"] = sym_info["sym_type"] if sym_info else "?"
                    row["section"] = sym_info["section"] if sym_info else "?"
                rows.append(row)

        # Output
        if show_name:
            for row in rows:
                console.print(row["symbol"])
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

            for row in rows:
                cells = [f"{row['address']:#x}"]
                if mapped:
                    cells += [row["binary"], f"{row['offset']:#x}"]
                cells.append(row["symbol"])
                if show_type or show_full:
                    cells.append(row.get("sym_type", "?"))
                if show_section or show_full:
                    cells.append(row.get("section", "?"))
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
    maps_file: str | None = typer.Option(
        None, "--maps", "-m", help="Path to /proc/PID/maps file"
    ),
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
async def tag(
    snapshot_id: int = typer.Argument(help="Snapshot ID to tag"),
    new_tag: str = typer.Argument(help="New tag value (empty string to remove)"),
) -> None:
    """
    Set or update the tag on an existing process snapshot.

    Pass an empty string to remove the tag.

    Example:
        baldrick --db session.db tag 1 crash-2026
        baldrick --db session.db tag 1 ""
    """
    from blackadder.models import ProcessSnapshot
    from sqlmodel import select as sql_select

    config = _get_config_or_default()
    manager = _db_manager(_global_db, config)

    try:
        await manager.create_all()
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


@app.command()
def query(
    name: str = typer.Argument(help="Query name or 'list' to show all available queries"),
    param: list[str] = typer.Option(
        [], "--param", "-p", help="Query parameter as key=value (can be repeated)"
    ),
    tag: str | None = typer.Option(None, "--tag", "-T", help="Filter snapshots by tag"),
    fmt: str = typer.Option(
        "rich", "--format", "-f", help="Output format: rich, json, csv"
    ),
) -> None:
    """
    Run a named SQL query against the database.

    Use 'list' to show all available queries. Parameters are passed as --param key=value.
    For snapshot queries use --param id=N or --tag <tag> to select the snapshot.

    Example:
        baldrick --db session.db query list
        baldrick --db session.db query snapshots
        baldrick --db session.db query snapshots --tag crash-2026
        baldrick --db session.db query mappings --param id=1
        baldrick --db session.db query libs --tag crash-2026
        baldrick --db session.db query symbols --param binary=libc.so.6 --format csv
    """
    from blackadder.queries import load_query_registry
    from blackadder.query import BlackadderQuery, _db_path

    registry = load_query_registry()

    if name == "list":
        table = Table(title="Available Queries")
        table.add_column("Name", style=_theme.symbol, no_wrap=True)
        table.add_column("Params", style=_theme.flags, no_wrap=True)
        table.add_column("Description", style=_theme.description)
        for qdef in sorted(registry.values(), key=lambda q: q.name):
            table.add_row(
                qdef.name,
                ", ".join(f":{p}" for p in qdef.params) if qdef.params else "—",
                qdef.description,
            )
        console.print(table)
        return

    if name not in registry:
        console.print(f"[red]Unknown query: {name!r}. Use 'list' to see available queries.[/red]")
        raise typer.Exit(1)

    # Parse --param key=value pairs
    params: dict[str, str] = {}
    for kv in param:
        if "=" not in kv:
            console.print(f"[red]Invalid --param format: {kv!r} (expected key=value)[/red]")
            raise typer.Exit(1)
        k, v = kv.split("=", 1)
        params[k.strip()] = v.strip()

    config = _get_config_or_default()
    db_url = _global_db or config.db
    db_file = _db_path(db_url) if db_url.startswith("sqlite") else db_url

    try:
        import polars as pl
    except ImportError:
        console.print("[red]polars is required for query command. Install with: pip install polars[/red]")
        raise typer.Exit(1)

    qdef = registry[name]

    # Route --tag: for snapshot queries (params include 'id'), pass tag to run_query
    # for resolution.  For other queries (e.g. snapshots), post-filter on tag column.
    post_filter_tag: str | None = None
    if tag:
        if "id" in qdef.params and "id" not in params:
            params["tag"] = tag  # run_query will resolve tag → snapshot id
        else:
            post_filter_tag = tag  # post-filter on result 'tag' column

    try:
        q = BlackadderQuery(db_file)
        df = q.run(name, **params)
    except KeyError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Query failed: {e}[/red]")
        raise typer.Exit(1)

    if post_filter_tag and "tag" in df.columns:
        df = df.filter(pl.col("tag") == post_filter_tag)

    if df.is_empty():
        console.print("[yellow](no results)[/yellow]")
        return

    fmt = fmt.lower()

    if fmt == "json":
        console.print(df.write_json())
    elif fmt == "csv":
        console.print(df.write_csv(), end="")
    else:  # rich (default)
        table = Table(title=name)
        for col in df.columns:
            table.add_column(col, style=column_style(col, _theme), no_wrap=False)
        for row in df.iter_rows():
            table.add_row(*[format_value(col, v, _theme) for col, v in zip(df.columns, row)])
        console.print(table)


@app.command()
def version() -> None:
    """Show version information."""
    import blackadder

    console.print(f"Baldrick {blackadder.__version__}")
    console.print(f"Author: {blackadder.__author__}")


def main():
    """Entry point for baldrick CLI."""
    import asyncio
    import click
    import os

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
