"""
Baldrick CLI - main entry point for blackadder debugging tool.

Provides commands for:
- Loading process memory mappings
- Decoding backtraces
- Resolving addresses to symbols
- Querying memory information
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from blackadder.config import BlackadderConfig
from blackadder.db import AsyncDatabaseManager, ProcessDatabase
from blackadder.binutils import init_parser, parse_backtrace_auto

app = typer.Typer(
    help="Baldrick - Linux debugging tool for backtrace decoding and symbol resolution"
)
console = Console()


def _get_config_or_default() -> BlackadderConfig:
    """Get configuration from environment or use defaults."""
    try:
        return BlackadderConfig()
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
        return BlackadderConfig()


@app.command()
async def load_process(
    maps_file: str = typer.Option(
        ..., "--maps", "-m", help="Path to /proc/PID/maps file"
    ),
    pid: Optional[int] = typer.Option(None, "--pid", "-p", help="Process ID"),
    db: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to process database (default: blackadder-process.db)"
    ),
) -> None:
    """
    Load process memory mapping from /proc/PID/maps.

    Creates a ProcessSnapshot with all memory mappings in the database.

    Example:
        baldrick load-process --maps /proc/12345/maps --pid 12345
        baldrick load-process --maps core_dump_maps.txt
    """
    config = _get_config_or_default()
    db_path = db or config.process_db

    try:
        # Read maps file
        maps_path = Path(maps_file)
        if not maps_path.exists():
            console.print(f"[red]Error: maps file not found: {maps_file}[/red]")
            raise typer.Exit(1)

        with open(maps_path) as f:
            maps_text = f.read()

        # Create database and load maps
        manager = AsyncDatabaseManager(db_path)
        db_proc = ProcessDatabase(manager, config)

        console.print(f"[blue]Loading memory mappings from {maps_file}...[/blue]")

        process = await db_proc.load_maps(pid, maps_text)

        console.print(
            f"[green]✓ Loaded process snapshot ID {process.id} "
            f"with {len(process.mappings)} memory mappings[/green]"
        )

        # Show summary
        table = Table(title="Memory Mappings Summary")
        table.add_column("Start Address", style="cyan")
        table.add_column("End Address", style="cyan")
        table.add_column("Permissions", style="magenta")
        table.add_column("Pathname", style="green")

        for mapping in list(process.mappings)[:10]:  # Show first 10
            table.add_row(
                f"{mapping.start_addr:#x}",
                f"{mapping.end_addr:#x}",
                mapping.perms,
                mapping.pathname[:50],
            )

        if len(process.mappings) > 10:
            table.add_row(
                "[yellow]...[/yellow]",
                "[yellow]...[/yellow]",
                "[yellow]...[/yellow]",
                f"[yellow]({len(process.mappings) - 10} more)[/yellow]",
            )

        console.print(table)

        await manager.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def decode_backtrace(
    trace_file: Optional[str] = typer.Option(
        None, "--trace", "-t", help="Backtrace file (or read from stdin)"
    ),
    pid: int = typer.Option(..., "--pid", "-p", help="Process ID or snapshot ID"),
    db: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to process database"
    ),
    jobs: int = typer.Option(
        32, "--jobs", "-j", help="Max parallel symbol resolutions"
    ),
) -> None:
    """
    Decode backtrace to function names and optional line numbers.

    Auto-detects input format:
    - Raw hex addresses (0x400a1c, one per line)
    - GDB backtrace format (#0 0x400a1c in function...)
    - Kernel format ([<ffffffff81000001>] function+0x42/0x100)

    Example:
        baldrick decode-backtrace --pid 12345 --trace trace.txt
        cat trace.txt | baldrick decode-backtrace --pid 12345
    """
    config = _get_config_or_default()
    db_path = db or config.process_db
    config.max_subprocess_workers = jobs

    try:
        # Read backtrace
        if trace_file:
            trace_path = Path(trace_file)
            if not trace_path.exists():
                console.print(f"[red]Error: trace file not found: {trace_file}[/red]")
                raise typer.Exit(1)
            with open(trace_path) as f:
                trace_text = f.read()
        else:
            # Read from stdin
            console.print("[blue]Reading backtrace from stdin...[/blue]")
            trace_text = sys.stdin.read()

        if not trace_text.strip():
            console.print("[red]Error: No backtrace input[/red]")
            raise typer.Exit(1)

        # Parse backtrace to addresses
        console.print("[blue]Parsing backtrace format...[/blue]")
        addresses = parse_backtrace_auto(trace_text)

        if not addresses:
            console.print("[red]Error: Could not parse any addresses from backtrace[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓ Found {len(addresses)} addresses[/green]")

        # Initialize parser
        init_parser(config)

        # Decode backtrace
        console.print(f"[blue]Decoding backtrace with {jobs} parallel workers...[/blue]")

        manager = AsyncDatabaseManager(db_path)
        db_proc = ProcessDatabase(manager, config)

        frames = await db_proc.decode_backtrace(pid, addresses)

        # Display results
        console.print()
        table = Table(title="Decoded Backtrace")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Address", style="cyan")
        table.add_column("Symbol", style="green")
        table.add_column("Location", style="yellow")

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

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def syms(
    pid: int = typer.Option(..., "--pid", "-p", help="Process ID"),
    address: Optional[str] = typer.Option(
        None, "--address", "-a", help="Address to resolve (hex)"
    ),
    db: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to process database"
    ),
) -> None:
    """
    Resolve an address to its symbol and memory mapping.

    Shows which binary is loaded at the address and the symbol name.

    Example:
        baldrick syms --pid 12345 --address 0x400a1c
    """
    config = _get_config_or_default()
    db_path = db or config.process_db

    try:
        if not address:
            console.print("[red]Error: --address required[/red]")
            raise typer.Exit(1)

        # Parse address
        try:
            if address.startswith("0x") or address.startswith("0X"):
                addr = int(address, 16)
            else:
                addr = int(address, 16)
        except ValueError:
            console.print(f"[red]Error: Invalid address: {address}[/red]")
            raise typer.Exit(1)

        # Resolve address
        manager = AsyncDatabaseManager(db_path)
        db_proc = ProcessDatabase(manager, config)

        console.print(f"[blue]Resolving address {address:#x}...[/blue]")

        binary_info = await db_proc.address_to_binary(pid, addr)

        if not binary_info:
            console.print(f"[yellow]Address {address:#x} not found in process memory[/yellow]")
            await manager.close()
            raise typer.Exit(1)

        binary_path, offset = binary_info

        # Initialize parser and resolve symbol
        init_parser(config)
        from blackadder.binutils import resolve_symbol

        symbol = await resolve_symbol(binary_path, offset, config)

        # Display result
        console.print()
        table = Table(title="Address Resolution")
        table.add_row("Address", f"{addr:#x}")
        table.add_row("Binary", binary_path)
        table.add_row("Offset", f"{offset:#x}")
        table.add_row("Symbol", symbol)

        console.print(table)

        await manager.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def load_core_dump(
    core_file: str = typer.Option(
        ..., "--core", "-c", help="Path to ELF core dump file"
    ),
    db: Optional[str] = typer.Option(
        None, "--db", "-d", help="Path to process database (default: blackadder-process.db)"
    ),
) -> None:
    """
    Load process state from ELF core dump file (Phase 2.2).

    Parses core dump to extract memory mappings and process metadata
    for offline crash analysis.

    Example:
        baldrick load-core-dump --core /tmp/core.12345
        baldrick load-core-dump --core ./core.dump --db my.db
    """
    config = _get_config_or_default()
    db_path = db or config.process_db

    try:
        # Check file exists
        core_path = Path(core_file)
        if not core_path.exists():
            console.print(f"[red]Error: core dump file not found: {core_file}[/red]")
            raise typer.Exit(1)

        # Create database and load core dump
        manager = AsyncDatabaseManager(db_path)
        db_proc = ProcessDatabase(manager, config)

        console.print(f"[blue]Parsing core dump from {core_file}...[/blue]")

        process = await db_proc.load_core_dump(str(core_path))

        console.print(
            f"[green]✓ Loaded core dump as process snapshot ID {process.id} "
            f"with {len(process.mappings)} memory segments[/green]"
        )

        # Show summary
        table = Table(title="Memory Segments from Core Dump")
        table.add_column("Start Address", style="cyan")
        table.add_column("End Address", style="cyan")
        table.add_column("Permissions", style="magenta")
        table.add_column("Offset", style="yellow")

        for mapping in list(process.mappings)[:10]:  # Show first 10
            size = mapping.end_addr - mapping.start_addr
            table.add_row(
                f"{mapping.start_addr:#x}",
                f"{mapping.end_addr:#x}",
                mapping.perms,
                f"{mapping.offset:#x} ({size:#x} bytes)",
            )

        if len(process.mappings) > 10:
            table.add_row(
                "[yellow]...[/yellow]",
                "[yellow]...[/yellow]",
                "[yellow]...[/yellow]",
                f"[yellow]({len(process.mappings) - 10} more segments)[/yellow]",
            )

        console.print(table)

        console.print(f"[blue]Source: {process.source_type} ({process.source_path})[/blue]")

        await manager.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
async def analyze_memory(
    pid: int = typer.Option(..., "--pid", "-p", help="Process snapshot ID"),
    db: Optional[str] = typer.Option(None, "--db", "-d", help="Path to process database"),
) -> None:
    """
    Analyze memory layout and detect anomalies (Phase 2.3).

    Shows:
    - Memory region classification (heap, stack, libraries, etc.)
    - Detected anomalies (executable heap, oversized regions, etc.)
    - Corruption risk assessment

    Example:
        baldrick analyze-memory --pid 1
    """
    config = _get_config_or_default()
    db_path = db or config.process_db

    try:
        manager = AsyncDatabaseManager(db_path)
        db_proc = ProcessDatabase(manager, config)

        console.print(f"[blue]Analyzing memory layout for process {pid}...[/blue]")

        result = await db_proc.analyze_memory_layout(pid)

        # Display results
        console.print()
        console.print(f"[green]Memory Analysis Results[/green]")
        console.print(f"Regions analyzed: {result['regions_analyzed']}")
        console.print(
            f"Regions with anomalies: {len(result['anomalies'])} anomalies detected"
        )
        console.print(
            f"Corruption risk: {result['corruption_risk']:.1%} "
            f"({result['corruption_count']} regions suspicious)"
        )

        if result["anomalies"]:
            console.print()
            console.print("[yellow]Detected Anomalies:[/yellow]")
            for i, anomaly in enumerate(result["anomalies"], 1):
                console.print(f"  {i}. {anomaly}")

        await manager.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    import blackadder

    console.print(f"Baldrick {blackadder.__version__}")
    console.print(f"Author: {blackadder.__author__}")


def main():
    """Entry point for baldrick CLI."""
    app()


if __name__ == "__main__":
    main()
