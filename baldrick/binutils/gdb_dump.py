"""
Parser for GDB text dump output.

Parses the output of:
    gdb -batch \
        -ex "thread apply all bt full" \
        -ex "info registers" \
        ./binary [core]

Supports multi-thread backtraces, per-thread register state.
Used as an offline data source when /proc/PID/ is not available.

Output dataclasses:
    GdbFrame      — single backtrace frame
    GdbThread     — thread with frames and optional registers
    GdbDump       — full dump (all threads + metadata)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ============================================================================
# Data classes
# ============================================================================


@dataclass
class GdbFrame:
    """A single backtrace frame from GDB output."""

    frame_num: int
    address: int | None  # None when GDB omits the address (inline / no-debug)
    symbol: str | None  # Function name (demangled if GDB did it)
    args: str | None  # Raw argument string
    source_file: str | None  # "file.cpp"
    source_line: int | None  # Line number


@dataclass
class GdbThread:
    """A thread as reported by GDB 'thread apply all bt'."""

    gdb_thread_num: int  # GDB thread number (Thread N)
    tid: int  # OS LWP / TID
    name: str | None  # Thread name in quotes, if present
    frames: list[GdbFrame] = field(default_factory=list)
    registers: dict[str, int] = field(default_factory=dict)  # reg name → value
    crash_instruction: str | None = None  # raw asm text from "x/1i $pc", e.g. "movl $0x2a,(%rdi)"


@dataclass
class GdbDump:
    """Full parsed GDB dump."""

    threads: list[GdbThread] = field(default_factory=list)
    # Registers that appear before any "Thread N" header (single-thread dump
    # or registers printed at end without thread context)
    global_registers: dict[str, int] = field(default_factory=dict)


# ============================================================================
# Regex patterns
# ============================================================================

# "Thread 2 (LWP 12346 "deadlock_test"):"
# "Thread 1 (Thread 0xf7f... (LWP 12345)):"   ← older GDB format
_RE_THREAD_HEADER = re.compile(
    r'^Thread\s+(\d+)\s+\(.*?LWP\s+(\d+)(?:\s+"([^"]*)")?\)',
    re.IGNORECASE,
)

# "#0  0x00007f12 in symbol (args) at file.c:10"
# "#0  symbol () at file.c:10"              ← no address
# "#0  0x00007f12 in ?? ()"                ← unknown symbol
_RE_FRAME = re.compile(
    r"^#(\d+)\s+"
    r"(?:(0x[0-9a-fA-F]+)\s+in\s+)?"  # optional address + "in"
    r"([^\s(]+)"  # symbol name
    r"(?:\s*\(([^)]*)\))?"  # optional args
    r"(?:\s+at\s+([^:]+):(\d+))?",  # optional "at file:line"
)

# "rax            0x0   0"  or  "rip            0x400a1c  0x400a1c <main>"
_RE_REGISTER = re.compile(
    r"^(\w+)\s+(0x[0-9a-fA-F]+|\d+)\s",
)

# "=> 0x55555555512d <f0(int*)+4>:  movl   $0x2a,(%rdi)"
# "   0x55555555512d <f0+4>:        mov    eax,DWORD PTR [rdi]"
# Captures everything after the colon as the raw instruction text.
_RE_CRASH_INSN = re.compile(
    r"^(?:=>)?\s*0x[0-9a-fA-F]+(?:\s+<[^>]*>)?:\s+(?:[0-9a-fA-F]{2}\s+)*(.+)$"
)

# Registers to skip — GDB pseudo-regs and display-only fields that are not
# actual CPU registers (no fixed set per-arch: we accept everything else).
_SKIP_REGS = {
    "fctrl",
    "fstat",
    "ftag",
    "fiseg",
    "fioff",
    "foseg",
    "fooff",
    "fop",
    "mxcsr",
    "mxcr_mask",  # x87/SSE control
    "orig_rax",
    "orig_eax",  # Linux syscall restart pseudo-reg
    "fs_base",
    "gs_base",  # segment bases (rarely useful)
}


# ============================================================================
# Parser
# ============================================================================


def parse_gdb_dump(text: str) -> GdbDump:
    """
    Parse GDB multi-thread backtrace + register dump text.

    Handles output from:
        gdb -batch -ex "thread apply all bt full" -ex "info registers" binary [core]

    Threads appear in reverse order in GDB output (highest first); this parser
    preserves original order but callers can sort by tid if needed.

    Args:
        text: Raw GDB stdout text

    Returns:
        GdbDump with all parsed threads and their frames/registers
    """
    dump = GdbDump()
    current_thread: GdbThread | None = None
    in_registers = False
    expect_crash_insn = False  # True: next non-empty line is x/1i output

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            in_registers = False
            continue

        # ── Thread header ──────────────────────────────────────────────────
        m = _RE_THREAD_HEADER.match(line)
        if m:
            gdb_num = int(m.group(1))
            tid = int(m.group(2))
            name = m.group(3)  # may be None
            current_thread = GdbThread(gdb_thread_num=gdb_num, tid=tid, name=name)
            dump.threads.append(current_thread)
            in_registers = False
            continue

        # ── Crash instruction (from "x/1i $pc") ───────────────────────────
        # Marker "BALDRICK_CRASH_INSN" emitted by _collect_gdb_dump signals
        # that the next non-empty line is x/1i $pc output.
        if line == "BALDRICK_CRASH_INSN":
            in_registers = False
            expect_crash_insn = True
            continue

        if expect_crash_insn:
            expect_crash_insn = False
            m = _RE_CRASH_INSN.match(line)
            if m and current_thread is not None:
                current_thread.crash_instruction = m.group(1).strip()
            continue

        # ── Register section marker ────────────────────────────────────────
        if line.startswith("(gdb)") or "registers" in line.lower():
            in_registers = True
            continue

        # ── Register line ─────────────────────────────────────────────────
        if in_registers:
            m = _RE_REGISTER.match(line)
            if m:
                reg_name = m.group(1).lower()
                if reg_name not in _SKIP_REGS:
                    raw_val = m.group(2)
                    try:
                        value = int(raw_val, 16) if raw_val.startswith("0x") else int(raw_val)
                    except ValueError:
                        continue
                    if current_thread is not None:
                        current_thread.registers[reg_name] = value
                    else:
                        dump.global_registers[reg_name] = value
            continue

        # ── Backtrace frame ────────────────────────────────────────────────
        if line.startswith("#") and current_thread is not None:
            m = _RE_FRAME.match(line)
            if m:
                frame_num = int(m.group(1))
                addr_str = m.group(2)
                address = int(addr_str, 16) if addr_str else None
                symbol = m.group(3) or None
                args = m.group(4)
                src_file = m.group(5)
                src_line = int(m.group(6)) if m.group(6) else None

                # Normalize unknown symbols
                if symbol in ("??", "???", None):
                    symbol = None

                current_thread.frames.append(
                    GdbFrame(
                        frame_num=frame_num,
                        address=address,
                        symbol=symbol,
                        args=args.strip() if args else None,
                        source_file=src_file.strip() if src_file else None,
                        source_line=src_line,
                    )
                )
            continue

    return dump


@dataclass
class SyncObjectEntry:
    """A synchronization primitive resolved to an enclosing program object."""

    address: int
    type_name: str
    field: str
    field_offset: int
    source: str
    confidence: str
    frame_level: int | None = None


@dataclass
class SyncFrameEntry:
    """A stack/call-graph frame associated with a synchronization operation."""

    tid: int
    frame_level: int
    function: str
    operation: str
    call_depth: int
    confidence: str
    reason: str
    file: str | None = None
    line: int | None = None


@dataclass
class LockStateEntry:
    """One thread's lock blocking info from find_deadlock.py JSON output."""

    pid: int
    tid: int
    name: str | None
    gdb_thread_num: int
    blocking_function: str
    lock_type: str  # "mutex" | "rwlock_write" | "rwlock_read" | "unknown"
    waiting_for_addr: int | None  # Lock address (futex uaddr)
    lock_symbol: str | None  # Variable name e.g. "m1", "rw1"
    owner_tid: int | None  # TID of thread holding the lock (None = unknown)
    reader_count: int  # For rwlock_read: number of active readers
    confidence: str = "unknown"  # certain | heuristic | unknown
    abi_status: str = "unknown"
    mutex_object: SyncObjectEntry | None = None
    owner_acquisition: SyncFrameEntry | None = None
    analysis_call_depth: int = 3
    analysis_truncated: bool = False


@dataclass
class ConditionWaitEntry:
    """One condition-variable waiter and its correlated mutex/notifier data."""

    pid: int
    tid: int
    name: str | None
    gdb_thread_num: int
    blocking_function: str
    condition_address: int | None
    mutex_address: int | None
    condition_object: SyncObjectEntry | None
    mutex_object: SyncObjectEntry | None
    containing_object: SyncObjectEntry | None
    same_containing_object: bool
    wait_frame: SyncFrameEntry | None
    wake_candidates: list[SyncFrameEntry]
    confidence: str = "unknown"
    abi_status: str = "unknown"
    analysis_call_depth: int = 3
    analysis_truncated: bool = False


def _hex_address(raw) -> int | None:
    try:
        return int(raw, 16) if raw else None
    except (TypeError, ValueError):
        return None


def _sync_object(raw: dict | None) -> SyncObjectEntry | None:
    if not raw:
        return None
    address = _hex_address(raw.get("address"))
    if address is None:
        return None
    return SyncObjectEntry(
        address=address,
        type_name=raw.get("type", ""),
        field=raw.get("field", ""),
        field_offset=int(raw.get("field_offset", 0)),
        source=raw.get("source", ""),
        confidence=raw.get("confidence", "unknown"),
        frame_level=raw.get("frame_level"),
    )


def _sync_frame(raw: dict | None) -> SyncFrameEntry | None:
    if not raw:
        return None
    return SyncFrameEntry(
        tid=int(raw.get("tid", 0)),
        frame_level=int(raw.get("frame_level", 0)),
        function=raw.get("function", ""),
        operation=raw.get("operation", ""),
        call_depth=int(raw.get("call_depth", 0)),
        confidence=raw.get("confidence", "unknown"),
        reason=raw.get("reason", ""),
        file=raw.get("file") or None,
        line=raw.get("line"),
    )


def parse_lock_state(text: str) -> list[LockStateEntry]:
    """
    Parse output of the find_deadlock GDB command.

    Expects lines between BALDRICK_LOCK_STATE_BEGIN / BALDRICK_LOCK_STATE_END
    markers, each line being a JSON object as emitted by find_deadlock.py.

    Also accepts plain JSON lines without the markers (for piped usage).

    Args:
        text: Raw stdout from GDB running find_deadlock

    Returns:
        List of LockStateEntry (one per blocked thread)
    """
    import json

    entries: list[LockStateEntry] = []
    in_block = False
    has_markers = "BALDRICK_LOCK_STATE_BEGIN" in text

    for line in text.splitlines():
        line = line.strip()
        if line == "BALDRICK_LOCK_STATE_BEGIN":
            in_block = True
            continue
        if line == "BALDRICK_LOCK_STATE_END":
            in_block = False
            continue
        if has_markers and not in_block:
            continue
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in d:
            continue

        entries.append(
            LockStateEntry(
                pid=int(d.get("pid", 0)),
                tid=int(d.get("tid", 0)),
                name=d.get("name") or None,
                gdb_thread_num=int(d.get("gdb_thread_num", 0)),
                blocking_function=d.get("blocking_function", ""),
                lock_type=d.get("lock_type", "unknown"),
                waiting_for_addr=_hex_address(d.get("waiting_for_addr")),
                lock_symbol=d.get("lock_symbol") or None,
                owner_tid=d.get("owner_tid"),  # int or None
                reader_count=int(d.get("reader_count", 0)),
                confidence=d.get("confidence", "unknown"),
                abi_status=d.get("abi_status", "unknown"),
                mutex_object=_sync_object(d.get("mutex_object")),
                owner_acquisition=_sync_frame(d.get("owner_acquisition")),
                analysis_call_depth=int(d.get("analysis_call_depth", 3)),
                analysis_truncated=bool(d.get("analysis_truncated", False)),
            )
        )

    return entries


def parse_condition_state(text: str) -> list[ConditionWaitEntry]:
    """Parse condition wait records emitted by ``bdr find-deadlock``."""
    import json

    entries: list[ConditionWaitEntry] = []
    in_block = False
    has_markers = "BALDRICK_COND_STATE_BEGIN" in text
    for line in text.splitlines():
        line = line.strip()
        if line == "BALDRICK_COND_STATE_BEGIN":
            in_block = True
            continue
        if line == "BALDRICK_COND_STATE_END":
            in_block = False
            continue
        if has_markers and not in_block:
            continue
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in data or data.get("record_type") != "condition_wait":
            continue
        wait_frame = _sync_frame(data.get("wait_frame"))
        if wait_frame is not None and not wait_frame.tid:
            wait_frame.tid = int(data.get("tid", 0))
        entries.append(
            ConditionWaitEntry(
                pid=int(data.get("pid", 0)),
                tid=int(data.get("tid", 0)),
                name=data.get("name") or None,
                gdb_thread_num=int(data.get("gdb_thread_num", 0)),
                blocking_function=data.get("blocking_function", ""),
                condition_address=_hex_address(data.get("condition_address")),
                mutex_address=_hex_address(data.get("mutex_address")),
                condition_object=_sync_object(data.get("condition_object")),
                mutex_object=_sync_object(data.get("mutex_object")),
                containing_object=_sync_object(data.get("containing_object")),
                same_containing_object=bool(data.get("same_containing_object", False)),
                wait_frame=wait_frame,
                wake_candidates=[
                    frame
                    for item in data.get("wake_candidates", [])
                    if (frame := _sync_frame(item)) is not None
                ],
                confidence=data.get("confidence", "unknown"),
                abi_status=data.get("abi_status", "unknown"),
                analysis_call_depth=int(data.get("analysis_call_depth", 3)),
                analysis_truncated=bool(data.get("analysis_truncated", False)),
            )
        )
    return entries


def parse_gdb_registers_only(text: str) -> dict[str, int]:
    """
    Parse 'info registers' output (single-thread, no thread headers).

    Useful when GDB register dump is provided separately from backtrace.
    Accepts all registers except pseudo-regs in _SKIP_REGS.

    Returns:
        Dict of register name → integer value
    """
    regs: dict[str, int] = {}
    for line in text.splitlines():
        m = _RE_REGISTER.match(line.strip())
        if m:
            name = m.group(1).lower()
            if name not in _SKIP_REGS:
                raw = m.group(2)
                try:
                    regs[name] = int(raw, 16) if raw.startswith("0x") else int(raw)
                except ValueError:
                    pass
    return regs
