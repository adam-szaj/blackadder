"""Advanced CLI commands for Phase 3 features.

Provides commands for register interpretation, memory analysis,
and other advanced debugging features.
"""

import logging
import typer
from pathlib import Path
import json

from blackadder.db.base import AsyncDatabaseManager
from blackadder.config import BlackadderConfig
from blackadder.analysis_integration import AnalysisIntegration

logger = logging.getLogger("blackadder.cli.commands")

# Create sub-app for advanced commands
advanced_app = typer.Typer(help="Advanced analysis commands")


@advanced_app.command(name="analyze-registers")
async def analyze_registers(
    pid: int = typer.Option(..., help="Process ID to analyze"),
    process_db: str = typer.Option(
        "blackadder-process.db",
        help="Path to process database",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON instead of plain text",
    ),
    interesting_only: bool = typer.Option(
        False,
        "--interesting",
        help="Show only interesting registers (non-zero, non-unknown)",
    ),
) -> None:
    """Analyze and interpret CPU register values.

    Interprets register values to determine what they point to:
    - Code pointers (resolved to symbols)
    - Heap pointers (detected via memory region analysis)
    - Stack pointers and frame pointers
    - Data and constant values

    Supports x86-64, ARM, ARM64, and RISC-V architectures.

    Example:
        baldrick analyze-registers --pid 12345 --json
        baldrick analyze-registers --pid 12345 --interesting
    """
    try:
        # Load process from database and analyze registers
        config = BlackadderConfig()

        # Build database URL
        db_path = Path(process_db).resolve()
        db_url = f"sqlite+aiosqlite:///{db_path}"

        manager = AsyncDatabaseManager(db_url)
        integration = AnalysisIntegration(manager, config)

        # Load process by PID
        process = await integration.get_process_by_pid(pid)
        if not process:
            typer.echo(f"Error: Process {pid} not found in database", err=True)
            raise typer.Exit(code=1)

        # Analyze registers
        result = await integration.analyze_registers(
            process=process,
            register_state=None,
            interesting_only=interesting_only,
        )

        if json_output:
            typer.echo(json.dumps(result, indent=2, default=str))
        else:
            typer.echo(f"Register analysis for PID {pid}")
            typer.echo(f"Architecture: {result.get('architecture', 'unknown')}")
            typer.echo(f"Register count: {result.get('register_count', 0)}")

    except FileNotFoundError as e:
        typer.echo(f"Error: Database file not found: {process_db}", err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        logger.exception("analyze_registers_error", extra={"pid": pid, "error": str(e)})
        typer.echo(f"Error analyzing registers: {e}", err=True)
        raise typer.Exit(code=1)


@advanced_app.command(name="memory-report")
async def memory_report(
    pid: int = typer.Option(..., help="Process ID to analyze"),
    process_db: str = typer.Option(
        "blackadder-process.db",
        help="Path to process database",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON instead of plain text",
    ),
) -> None:
    """Generate a memory layout report for a process.

    Analyzes memory regions to provide:
    - Memory region classification (heap, stack, libraries, etc.)
    - Anomaly detection (executable heap, RWX regions, etc.)
    - Corruption risk indicators
    - Memory fragmentation analysis

    Example:
        baldrick memory-report --pid 12345
        baldrick memory-report --pid 12345 --json
    """
    try:
        config = BlackadderConfig()
        db_path = Path(process_db).resolve()
        db_url = f"sqlite+aiosqlite:///{db_path}"

        manager = AsyncDatabaseManager(db_url)
        integration = AnalysisIntegration(manager, config)

        # Load process by PID
        process = await integration.get_process_by_pid(pid)
        if not process:
            typer.echo(
                f"Error: Process {pid} not found in database",
                err=True,
            )
            raise typer.Exit(code=1)

        # Generate memory report
        result = {
            "process_id": process.id,
            "pid": process.pid,
            "description": process.description,
            "mapping_count": len(process.mappings),
            "mappings": [
                {
                    "start": hex(m.start_addr),
                    "end": hex(m.end_addr),
                    "perms": m.perms,
                    "pathname": m.pathname,
                }
                for m in process.mappings
            ],
        }

        if json_output:
            typer.echo(json.dumps(result, indent=2, default=str))
        else:
            typer.echo(f"Memory Report for PID {pid}")
            typer.echo(f"Process ID: {result['process_id']}")
            typer.echo(f"Mappings: {result['mapping_count']}")
            for m in result["mappings"][:10]:  # Show first 10
                typer.echo(
                    f"  {m['start']}-{m['end']} {m['perms']} {m['pathname']}"
                )
            if len(result["mappings"]) > 10:
                typer.echo(f"  ... and {len(result['mappings']) - 10} more")

    except FileNotFoundError as e:
        typer.echo(f"Error: Database file not found: {process_db}", err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        logger.exception("memory_report_error", extra={"pid": pid, "error": str(e)})
        typer.echo(f"Error generating memory report: {e}", err=True)
        raise typer.Exit(code=1)


@advanced_app.command(name="stack-validate")
async def stack_validate(
    pid: int = typer.Option(..., help="Process ID to analyze"),
    process_db: str = typer.Option(
        "blackadder-process.db",
        help="Path to process database",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON instead of plain text",
    ),
    frame_pointer: int = typer.Option(
        None,
        "--fp",
        help="Starting frame pointer (RBP/X29) in hex",
    ),
    return_address: int = typer.Option(
        None,
        "--ra",
        help="Starting return address in hex",
    ),
) -> None:
    """Validate stack frame chain integrity.

    Checks for:
    - Valid frame pointers (RBP/R29 chain)
    - Frame pointer cycles or corruption
    - Stack buffer overflow indicators
    - Suspicious return addresses

    Example:
        baldrick stack-validate --pid 12345
        baldrick stack-validate --pid 12345 --json
        baldrick stack-validate --pid 12345 --fp 0x7fffffffde00 --ra 0x400a1c
    """
    try:
        config = BlackadderConfig()
        db_path = Path(process_db).resolve()
        db_url = f"sqlite+aiosqlite:///{db_path}"

        manager = AsyncDatabaseManager(db_url)
        integration = AnalysisIntegration(manager, config)

        # Load process by PID
        process = await integration.get_process_by_pid(pid)
        if not process:
            typer.echo(
                f"Error: Process {pid} not found in database",
                err=True,
            )
            raise typer.Exit(code=1)

        # Validate stack
        result = await integration.validate_stack(
            process,
            frame_pointer=frame_pointer,
            return_address=return_address,
        )

        if json_output:
            typer.echo(json.dumps(result, indent=2, default=str))
        else:
            typer.echo(f"Stack Validation for PID {pid}")
            typer.echo(f"Architecture: {result['architecture']}")
            typer.echo(
                f"Frames: {result['total_frames']} total, "
                f"{result['valid_frames']} valid, "
                f"{result['corrupted_frames']} corrupted"
            )
            typer.echo(f"Chain integrity: {result['chain_integrity']:.1%}")
            if result["issues"]:
                typer.echo(f"Issues ({len(result['issues'])}):")
                for issue in result["issues"][:5]:  # Show first 5
                    typer.echo(
                        f"  - {issue['issue_type']}: {issue['description']}"
                    )

    except FileNotFoundError:
        typer.echo(f"Error: Database file not found: {process_db}", err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        logger.exception("stack_validate_error", extra={"pid": pid, "error": str(e)})
        typer.echo(f"Error validating stack: {e}", err=True)
        raise typer.Exit(code=1)


@advanced_app.command(name="heap-analyze")
async def heap_analyze(
    pid: int = typer.Option(..., help="Process ID to analyze"),
    process_db: str = typer.Option(
        "blackadder-process.db",
        help="Path to process database",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON instead of plain text",
    ),
    heap_start: int = typer.Option(
        None,
        "--heap-start",
        help="Heap start address in hex (auto-detect if not specified)",
    ),
    heap_end: int = typer.Option(
        None,
        "--heap-end",
        help="Heap end address in hex (auto-detect if not specified)",
    ),
) -> None:
    """Analyze heap structure and detect corruption.

    Detects:
    - Heap free list corruption
    - Buffer overflows and underflows
    - Use-after-free patterns
    - Heap metadata corruption
    - Double-free conditions

    Example:
        baldrick heap-analyze --pid 12345
        baldrick heap-analyze --pid 12345 --json
        baldrick heap-analyze --pid 12345 --heap-start 0x1000000 --heap-end 0x2000000
    """
    try:
        config = BlackadderConfig()
        db_path = Path(process_db).resolve()
        db_url = f"sqlite+aiosqlite:///{db_path}"

        manager = AsyncDatabaseManager(db_url)
        integration = AnalysisIntegration(manager, config)

        # Load process by PID
        process = await integration.get_process_by_pid(pid)
        if not process:
            typer.echo(
                f"Error: Process {pid} not found in database",
                err=True,
            )
            raise typer.Exit(code=1)

        # Analyze heap
        result = await integration.analyze_heap(
            process,
            heap_start=heap_start,
            heap_end=heap_end,
        )

        if json_output:
            typer.echo(json.dumps(result, indent=2, default=str))
        else:
            typer.echo(f"Heap Analysis for PID {pid}")
            if "error" in result:
                typer.echo(f"Error: {result['error']}")
            else:
                typer.echo(f"Heap: {result['heap_start']}-{result['heap_end']}")
                typer.echo(f"Size: {result['heap_size']} bytes")
                typer.echo(f"Allocated: {result['allocated_size']} bytes")
                typer.echo(f"Free: {result['free_size']} bytes")
                typer.echo(f"Fragmentation: {result['fragmentation']:.1%}")
                typer.echo(f"Anomalies: {len(result['anomalies'])}")
                typer.echo(
                    f"High-Risk Anomalies: {len(result['high_risk_anomalies'])}"
                )
                if result["anomalies"]:
                    typer.echo("Top anomalies:")
                    for anom in result["anomalies"][:3]:  # Show first 3
                        typer.echo(
                            f"  - {anom['anomaly_type']}: {anom['description']}"
                        )

    except FileNotFoundError:
        typer.echo(f"Error: Database file not found: {process_db}", err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        logger.exception("heap_analyze_error", extra={"pid": pid, "error": str(e)})
        typer.echo(f"Error analyzing heap: {e}", err=True)
        raise typer.Exit(code=1)


def register_advanced_commands(app: typer.Typer) -> None:
    """Register advanced commands with main CLI app.

    Args:
        app: Main Typer application
    """
    app.add_typer(advanced_app, name="advanced", help="Advanced analysis features")
