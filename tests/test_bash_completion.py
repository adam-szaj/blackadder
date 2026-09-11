"""Tests for the optional advanced Bash completion script."""

import os
import shlex
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[1]
COMPLETION_SCRIPT = PROJECT_ROOT / "bash" / "_baldrick-completion.bash"


def _run_bash(body: str, *, path: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if path is not None:
        env["PATH"] = f"{path}:{env['PATH']}"
    return subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            f"source {shlex.quote(str(COMPLETION_SCRIPT))}\n{body}",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_completion_script_has_valid_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", COMPLETION_SCRIPT], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr


def test_top_level_completion_contains_all_supported_commands():
    result = _run_bash(
        'COMP_WORDS=(baldrick ""); COMP_CWORD=1; _baldrick_complete; '
        'printf "%s\\n" "${COMPREPLY[@]}"'
    )

    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == {
        "load",
        "load-types",
        "cast-mem",
        "load-process",
        "decode-backtrace",
        "decode-address",
        "analyse-memory",
        "analyse-deadlock",
        "report",
        "tag",
        "query",
        "schema",
        "version",
        "gdb-path",
    }


def test_completion_check_matches_current_cli(tmp_path: Path):
    executable = tmp_path / "baldrick"
    executable.write_text(
        "#!/bin/sh\n"
        f"exec {shlex.quote(sys.executable)} -c "
        "'import sys; sys.argv[0] = \"baldrick\"; "
        "from baldrick.cli.main import main; main()' \"$@\"\n"
    )
    executable.chmod(0o755)

    result = _run_bash("baldrick-check-completion", path=tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Baldrick completion is up to date (14 commands).\n"


def test_completion_check_reports_missing_and_stale_commands(tmp_path: Path):
    executable = tmp_path / "baldrick"
    executable.write_text("#!/bin/sh\nprintf 'load\\nfuture-command\\n'\n")
    executable.chmod(0o755)

    result = _run_bash("baldrick-check-completion", path=tmp_path)

    assert result.returncode == 1
    assert "Missing completion commands: future-command" in result.stderr
    assert "Stale completion commands:" in result.stderr
    assert "report" in result.stderr


def test_sql_list_exposes_sqlite_output(tmp_path: Path):
    database = tmp_path / "baldrick.db"
    database.touch()
    result = _run_bash(
        "sqlite3() { printf 'first\\nsecond\\n'; }\n"
        f"BALDRICK_DB={shlex.quote(str(database))}\n"
        '_baldrick_sql_list "SELECT value FROM example"\n'
        'printf "%s" "$_BALDRICK_SQL_RESULT"'
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "first\nsecond"
