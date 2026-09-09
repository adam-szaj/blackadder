"""Shared lifecycle policy for asynchronous external commands."""

import asyncio
import shlex
import weakref
from collections.abc import Callable


class SubprocessExecutionError(RuntimeError):
    """Raised when an external command exits unsuccessfully."""

    def __init__(self, cmd: list[str], returncode: int, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        detail = stderr.strip() or "no stderr output"
        super().__init__(f"Command {shlex.join(cmd)} exited with status {returncode}: {detail}")


class SubprocessTimeoutError(TimeoutError):
    """Raised after a timed-out external command has been terminated."""


class SubprocessRunner:
    """Run commands with bounded concurrency, timeout, and checked status."""

    def __init__(self, config):
        self.timeout_seconds = config.subprocess_timeout_seconds
        self.semaphore = asyncio.Semaphore(config.max_subprocess_workers)

    async def run(
        self,
        cmd: list[str],
        on_line: Callable[[str], None] | None = None,
    ) -> list[str]:
        async with self.semaphore:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=32 * 1024,
            )
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    stdout, stderr = await process.communicate()
            except TimeoutError as error:
                await self._terminate(process)
                raise SubprocessTimeoutError(
                    f"Command {shlex.join(cmd)} timed out after {self.timeout_seconds} seconds"
                ) from error

            stdout_lines = stdout.decode("utf-8", errors="replace").splitlines()
            stderr_text = stderr.decode("utf-8", errors="replace")
            stderr_lines = stderr_text.splitlines()
            lines = [line.strip() for line in [*stdout_lines, *stderr_lines]]
            if on_line is not None:
                for line in lines:
                    on_line(line)

            if process.returncode != 0:
                raise SubprocessExecutionError(cmd, process.returncode or -1, stderr_text)
            return lines

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        process.terminate()
        try:
            async with asyncio.timeout(1):
                await process.wait()
        except TimeoutError:
            process.kill()
            await process.wait()


_SHARED_RUNNERS: dict[int, tuple[weakref.ReferenceType, SubprocessRunner]] = {}


def get_shared_runner(config) -> SubprocessRunner:
    """Return the runner shared by parser instances using the same config."""
    key = id(config)
    cached = _SHARED_RUNNERS.get(key)
    if cached is not None and cached[0]() is config:
        return cached[1]

    runner = SubprocessRunner(config)

    def discard(_reference, *, runner_key=key):
        _SHARED_RUNNERS.pop(runner_key, None)

    _SHARED_RUNNERS[key] = (weakref.ref(config, discard), runner)
    return runner
