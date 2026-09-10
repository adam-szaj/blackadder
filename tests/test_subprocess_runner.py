"""Behavioral tests for supervised external commands."""

import sys

import pytest

from baldrick.binutils.runner import (
    SubprocessExecutionError,
    SubprocessRunner,
    SubprocessTimeoutError,
)
from baldrick.config import BaldrickConfig


@pytest.mark.asyncio
async def test_runner_collects_output_and_invokes_callback():
    runner = SubprocessRunner(BaldrickConfig())
    streamed = []

    lines = await runner.run(
        [sys.executable, "-c", "print('first'); print('second')"],
        streamed.append,
    )

    assert lines == ["first", "second"]
    assert streamed == lines


@pytest.mark.asyncio
async def test_runner_reports_nonzero_exit_with_stderr():
    runner = SubprocessRunner(BaldrickConfig())

    with pytest.raises(SubprocessExecutionError, match="failure detail") as error:
        await runner.run(
            [
                sys.executable,
                "-c",
                "import sys; print('failure detail', file=sys.stderr); sys.exit(7)",
            ]
        )

    assert error.value.returncode == 7


@pytest.mark.asyncio
async def test_runner_terminates_timed_out_process():
    runner = SubprocessRunner(BaldrickConfig(subprocess_timeout_seconds=0.05))

    with pytest.raises(SubprocessTimeoutError, match="timed out"):
        await runner.run([sys.executable, "-c", "import time; time.sleep(10)"])
