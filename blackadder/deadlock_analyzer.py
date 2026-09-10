"""
Deadlock detection engine for blackadder.

Analyzes Thread records and BacktraceEntry records to detect deadlocks.
Works in three degradation modes depending on available data:

  certain  — futex syscall with mutex address available (live /proc data)
  probable — backtrace contains pthread_mutex_lock / __lll_lock_wait symbols
  possible — wchan indicates futex wait but no address; ≥2 blocked threads

Input: Thread dataclass list + per-thread symbol lists (from BacktraceEntry).
Output: DeadlockReport with cycles and suspected threads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ============================================================================
# Data classes
# ============================================================================


@dataclass
class DeadlockThread:
    """A thread suspected of participating in a deadlock."""

    tid: int
    name: str | None
    evidence: str  # "futex_syscall" | "backtrace_lock" | "wchan_futex"
    waiting_for: int | None  # mutex/futex uaddr, None if unknown


@dataclass
class DeadlockCycle:
    """A detected cycle in the thread wait graph."""

    tids: list[int]
    evidence_level: str  # "certain" | "probable" | "possible"
    description: str


@dataclass
class DeadlockReport:
    """Full deadlock analysis result."""

    cycles: list[DeadlockCycle] = field(default_factory=list)
    # Threads that appear blocked but are not part of a confirmed cycle
    suspected_threads: list[DeadlockThread] = field(default_factory=list)
    evidence_level: str = "none"  # max level across cycles; "none" if no issues
    summary: str = ""
    lock_state: list[Any] = field(default_factory=list)
    condition_waits: list[Any] = field(default_factory=list)


# ============================================================================
# Symbol / wchan indicators
# ============================================================================

# Backtrace symbols that indicate a thread is waiting on a lock.
# Includes glibc internal variants (__GI___ prefix, ___ prefix) as seen in
# GDB backtraces from stripped or partially-stripped binaries.
_LOCK_SYMBOLS: frozenset[str] = frozenset(
    {
        # pthread mutex
        "pthread_mutex_lock",
        "pthread_mutex_timedlock",
        "__pthread_mutex_lock",
        "__pthread_mutex_lock_full",
        "__GI___pthread_mutex_lock",
        "___pthread_mutex_lock",
        # glibc low-level futex lock
        "__lll_lock_wait",
        "__lll_lock_wait_private",
        "__lll_timedlock_wait",
        # pthread rwlock
        "pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock",
        "pthread_rwlock_timedrdlock",
        "pthread_rwlock_timedwrlock",
        "__GI___pthread_rwlock_rdlock",
        "__GI___pthread_rwlock_wrlock",
        "___pthread_rwlock_rdlock",
        "___pthread_rwlock_wrlock",
        # semaphores
        "sem_wait",
        "__sem_wait_common",
        # kernel futex
        "futex_wait",
        "futex_wait_queue_me",
        "__futex_abstimed_wait_common",
        # syscall wrapper (GDB may show this when entering futex from userspace)
        "__libc_do_syscall",
    }
)

# wchan values that indicate a thread is blocked in the kernel on a futex/mutex
_WCHAN_BLOCKED: frozenset[str] = frozenset(
    {
        "futex_wait_queue_me",
        "futex_wait",
        "do_futex",
        "futex",
        "__se_sys_futex",
        "do_sys_futex",
    }
)

# Futex syscall numbers per architecture (we only have the syscall number, not arch)
# 202 = x86-64, 240 = x86 (32-bit), 98 = ARM64, 240 = ARM (same as x86 happens to be)
_FUTEX_SYSCALL_NRS: frozenset[int] = frozenset({202, 240, 98})

# futex op values that indicate FUTEX_WAIT (thread is waiting, not waking)
# FUTEX_WAIT=0, FUTEX_WAIT_BITSET=9, FUTEX_WAIT_PRIVATE=128, FUTEX_WAIT_BITSET_PRIVATE=137
_FUTEX_WAIT_OPS: frozenset[int] = frozenset({0, 9, 128, 137})

# Regex for /proc/PID/task/TID/syscall format:
# "<syscall_nr> <arg0_hex> <arg1_hex> ... <sp_hex> <pc_hex>"
# For futex: arg0=uaddr (mutex address), arg1=op, arg2=val
_RE_SYSCALL = re.compile(
    r"^(\d+)"  # syscall number
    r"\s+(0x[0-9a-f]+)"  # arg0: uaddr (futex address)
    r"\s+(0x[0-9a-f]+)"  # arg1: futex op
    r"(?:\s|$)",
    re.IGNORECASE,
)

# Regex to extract symbol base name (strip "+0x..." offset suffix)
_RE_SYMBOL_BASE = re.compile(r"^([^+@(]+)")


# ============================================================================
# Analyzer
# ============================================================================


class DeadlockAnalyzer:
    """
    Analyzes thread wait relationships to detect deadlocks.

    Usage:
        threads: list of thread dicts with keys:
            id, tid, name, wchan, syscall, stack_start, stack_end
        backtraces: dict mapping thread_id → list of resolved_symbol strings
        lock_state: optional list of LockStateEntry from find_deadlock GDB command
                    (provides exact mutex ownership — enables Tier 0 analysis)
    """

    def __init__(
        self,
        threads: list[dict],
        backtraces: dict[int, list[str]],
        lock_state: list | None = None,
    ) -> None:
        self._threads = threads
        self._backtraces = backtraces  # thread.id → [symbol, ...]
        self._lock_state = lock_state or []  # LockStateEntry list

    def analyze(self) -> DeadlockReport:
        """Run full deadlock analysis and return a report."""
        # ── Tier 0: GDB lock state with ownership (most authoritative) ────────
        if self._lock_state:
            return self._analyze_from_lock_state()

        blocked: list[DeadlockThread] = []

        for t in self._threads:
            dt = self._classify_thread(t)
            if dt is not None:
                blocked.append(dt)

        if not blocked:
            return DeadlockReport(
                evidence_level="none",
                summary="No blocked threads detected.",
            )

        # Build wait graph: tid → waiting_for (mutex addr or None)
        wait_graph: dict[int, int | None] = {dt.tid: dt.waiting_for for dt in blocked}

        cycles = _find_cycles(wait_graph)

        # Determine evidence level for each cycle
        tid_to_dt = {dt.tid: dt for dt in blocked}
        cycle_objs: list[DeadlockCycle] = []

        for cycle_tids in cycles:
            level = _cycle_evidence_level(cycle_tids, tid_to_dt)
            desc = _cycle_description(cycle_tids, tid_to_dt)
            cycle_objs.append(
                DeadlockCycle(
                    tids=cycle_tids,
                    evidence_level=level,
                    description=desc,
                )
            )

        # Threads not in any cycle but still blocked
        cycle_tid_set: set[int] = {tid for c in cycles for tid in c}
        suspected = [dt for dt in blocked if dt.tid not in cycle_tid_set]

        # If no cycles but ≥2 blocked threads → possible deadlock
        if not cycle_objs and len(blocked) >= 2:
            tids = [dt.tid for dt in blocked]
            desc = _cycle_description(tids, tid_to_dt)
            cycle_objs.append(
                DeadlockCycle(
                    tids=tids,
                    evidence_level="possible",
                    description=f"Multiple blocked threads (no confirmed cycle): {desc}",
                )
            )
            suspected = []

        # Overall evidence level = strongest cycle
        _ORDER = {"certain": 3, "probable": 2, "possible": 1, "none": 0}
        max_level = max(
            (c.evidence_level for c in cycle_objs),
            key=lambda level: _ORDER.get(level, 0),
            default="none",
        )

        summary = _build_summary(cycle_objs, suspected, max_level)

        return DeadlockReport(
            cycles=cycle_objs,
            suspected_threads=suspected,
            evidence_level=max_level,
            summary=summary,
        )

    def _analyze_from_lock_state(self) -> DeadlockReport:
        """
        Tier 0 analysis using exact mutex ownership from find_deadlock GDB output.

        Builds a precise wait graph: tid → owner_tid (who holds the lock I'm waiting for).
        Detects cycles with DFS. Evidence level = "certain".
        """
        # Build: tid → (waiting_for_addr, owner_tid, lock_symbol, lock_type)
        blocked: list[DeadlockThread] = []
        wait_owner: dict[int, int] = {}  # tid → owner_tid (if known)

        # Map tid → thread name from Thread records
        tid_to_name: dict[int, str | None] = {t["tid"]: t.get("name") for t in self._threads}

        for entry in self._lock_state:
            tid = entry.tid
            name = entry.name or tid_to_name.get(tid)
            dt = DeadlockThread(
                tid=tid,
                name=name,
                evidence="futex_syscall",  # GDB ownership = most certain
                waiting_for=entry.waiting_for_addr,
            )
            blocked.append(dt)
            if entry.owner_tid is not None:
                wait_owner[tid] = entry.owner_tid

        if not blocked:
            return DeadlockReport(
                evidence_level="none", summary="No blocked threads in lock state."
            )

        # Detect cycles in wait_owner graph using DFS
        cycles: list[list[int]] = _find_cycles_ownership(wait_owner)

        tid_to_dt = {dt.tid: dt for dt in blocked}
        cycle_objs: list[DeadlockCycle] = []
        cycle_tid_set: set[int] = set()

        for cycle_tids in cycles:
            cycle_tid_set.update(cycle_tids)
            # Build description with lock symbols
            entry_map = {e.tid: e for e in self._lock_state}
            parts = []
            for i, tid in enumerate(cycle_tids):
                e = entry_map.get(tid)
                cycle_thread = tid_to_dt.get(tid)
                label = f"TID {tid}"
                if cycle_thread and cycle_thread.name:
                    label += f" ({cycle_thread.name})"
                if e:
                    sym = e.lock_symbol or (hex(e.waiting_for_addr) if e.waiting_for_addr else "?")
                    label += f" waits {sym}"
                    if e.owner_tid:
                        label += f" (held by TID {e.owner_tid})"
                parts.append(label)
            desc = " → ".join(parts) + (f" → TID {cycle_tids[0]}" if len(cycle_tids) > 1 else "")
            cycle_objs.append(
                DeadlockCycle(
                    tids=cycle_tids,
                    evidence_level="certain",
                    description=desc,
                )
            )

        suspected = [dt for dt in blocked if dt.tid not in cycle_tid_set]

        # Threads with unknown owner → possible deadlock among themselves
        if not cycle_objs and len(blocked) >= 2:
            tids = [dt.tid for dt in blocked]
            cycle_objs.append(
                DeadlockCycle(
                    tids=tids,
                    evidence_level="probable",
                    description=_cycle_description(tids, tid_to_dt),
                )
            )
            suspected = []

        max_level = (
            "certain"
            if cycle_objs and any(c.evidence_level == "certain" for c in cycle_objs)
            else ("probable" if cycle_objs else "none")
        )
        summary = _build_summary(cycle_objs, suspected, max_level)

        return DeadlockReport(
            cycles=cycle_objs,
            suspected_threads=suspected,
            evidence_level=max_level,
            summary=summary,
        )

    def _classify_thread(self, t: dict) -> DeadlockThread | None:
        """
        Determine if a thread is blocked and on what.

        Returns DeadlockThread if blocked, None if not.
        """
        tid = t["tid"]
        name = t.get("name")
        thread_id = t.get("id")  # DB primary key (may differ from tid)

        # --- Tier 1: futex syscall (most reliable) ---
        syscall_raw = t.get("syscall") or ""
        if syscall_raw and syscall_raw != "running":
            m = _RE_SYSCALL.match(syscall_raw.strip())
            if m:
                syscall_nr = int(m.group(1))
                uaddr = int(m.group(2), 16)
                op = int(m.group(3), 16) & 0xFF  # mask off FUTEX_PRIVATE_FLAG etc.
                if syscall_nr in _FUTEX_SYSCALL_NRS and op in _FUTEX_WAIT_OPS:
                    return DeadlockThread(
                        tid=tid,
                        name=name,
                        evidence="futex_syscall",
                        waiting_for=uaddr,
                    )

        # --- Tier 2: backtrace lock symbols ---
        symbols: list[str] = self._backtraces.get(thread_id, []) if thread_id else []
        for sym_raw in symbols:
            m2 = _RE_SYMBOL_BASE.match(sym_raw.strip())
            base = m2.group(1).strip() if m2 else sym_raw.strip()
            if base in _LOCK_SYMBOLS:
                return DeadlockThread(
                    tid=tid,
                    name=name,
                    evidence="backtrace_lock",
                    waiting_for=None,
                )

        # --- Tier 3: wchan ---
        wchan = (t.get("wchan") or "").strip()
        if wchan and wchan in _WCHAN_BLOCKED:
            return DeadlockThread(
                tid=tid,
                name=name,
                evidence="wchan_futex",
                waiting_for=None,
            )

        return None


# ============================================================================
# Graph cycle detection
# ============================================================================


def _find_cycles_ownership(wait_owner: dict[int, int]) -> list[list[int]]:
    """
    Detect cycles in an exact ownership graph: tid → owner_tid.

    Uses DFS. Returns list of cycles, each as an ordered list of TIDs.
    Only TIDs present as keys in wait_owner are considered (blocked threads).
    """
    blocked_tids = set(wait_owner.keys())
    visited: set[int] = set()
    cycles: list[list[int]] = []

    def dfs(start: int) -> None:
        path: list[int] = []
        path_set: set[int] = set()
        tid = start

        while True:
            if tid in path_set:
                # Found a cycle — extract the cycle portion
                cycle_start = path.index(tid)
                cycle = path[cycle_start:]
                # Normalize: start from smallest TID
                min_idx = cycle.index(min(cycle))
                cycle = cycle[min_idx:] + cycle[:min_idx]
                # Deduplicate cycles (same set of TIDs)
                cycle_set = frozenset(cycle)
                if not any(frozenset(c) == cycle_set for c in cycles):
                    cycles.append(cycle)
                return
            if tid in visited or tid not in blocked_tids:
                return
            visited.add(tid)
            path.append(tid)
            path_set.add(tid)
            next_tid = wait_owner.get(tid)
            if next_tid is None:
                return
            tid = next_tid

    for start_tid in sorted(blocked_tids):
        if start_tid not in visited:
            dfs(start_tid)

    return cycles


def _find_cycles(wait_graph: dict[int, int | None]) -> list[list[int]]:
    """
    Find cycles in the wait graph.

    wait_graph: tid → mutex_addr (or None)

    A cycle exists only when mutex addresses are known (not None), because
    we need to know which thread *holds* the mutex another thread waits on.

    Since we don't track mutex ownership directly (only "waiting for addr X"),
    we detect cycles by treating it as: if two threads wait for each other's
    address, they form a cycle.

    In the full case (addresses known):
      Thread A waits on addr X  →  addr X is locked by Thread B
      Thread B waits on addr Y  →  addr Y is locked by Thread A
      Cycle: A → B → A

    Without ownership info we can only detect mutual waits by address match,
    i.e. if tid_A.waiting_for == addr_in_B's_stack and vice versa.
    We approximate: if N threads all wait on addresses and those addresses
    don't repeat, we can't confirm cycle without ownership — return empty.
    If two threads wait on the same address, one of them is the owner (odd).

    For now: DFS looking for tid appearing twice in the path of unique addresses.
    Since we lack mutex ownership, we emit cycles only when multiple threads
    wait on the *same* address (one holds, others wait — classic scenario is
    A holds mutex1 and waits for mutex2, B holds mutex2 and waits for mutex1).

    We build addr → [tids waiting] and then look for address groups that
    form a dependency cycle.
    """
    # Map: waiting_for_addr → list of tids waiting on it
    addr_waiters: dict[int, list[int]] = {}
    for tid, addr in wait_graph.items():
        if addr is not None:
            addr_waiters.setdefault(addr, []).append(tid)

    if not addr_waiters:
        return []  # No addresses known — caller will handle as "possible"

    # Build thread → set of addresses it's waiting on
    # Since we have no ownership, we attempt to find cycles heuristically:
    # - If thread A waits on addr X, and thread B also waits on some addr Y
    #   where both X and Y appear in the address set, and threads form groups.
    # Simple case: detect if any two threads cross-wait.
    # We look for strongly connected components using the address waiters.

    # Build: for each address, every waiter "depends on" every other thread
    # that holds a mutex they're waiting for. We don't know the holder, so
    # we assume: the holder is the thread waiting on a *different* address
    # that happens to be in the wait set. This is an approximation.

    # Practical heuristic for 2-thread deadlock (most common case):
    # Thread A waits on addr_X, Thread B waits on addr_Y.
    # If addr_X ≠ addr_Y and both threads are blocked → probable cycle.
    # We just return all blocked-with-address threads as one cycle when
    # each unique address is waited on by exactly 1 thread (classic deadlock).

    all_waiting_tids = list(wait_graph.keys())
    if not all_waiting_tids:
        return []

    # If all tids wait on unique addresses → classic deadlock (each holds
    # one lock the other wants). Return as one cycle.
    unique_addrs = {addr for addr in wait_graph.values() if addr is not None}
    tids_with_addr = [tid for tid, addr in wait_graph.items() if addr is not None]

    if len(unique_addrs) == len(tids_with_addr) and len(tids_with_addr) >= 2:
        return [tids_with_addr]

    # Multiple threads waiting on the same address (lock contention, not deadlock)
    # Return empty — this is not a deadlock cycle.
    return []


# ============================================================================
# Formatting helpers
# ============================================================================

_EVIDENCE_LABELS = {
    "futex_syscall": "futex syscall",
    "backtrace_lock": "backtrace symbol",
    "wchan_futex": "wchan",
}


def _cycle_evidence_level(tids: list[int], tid_map: dict[int, DeadlockThread]) -> str:
    """Determine cycle evidence level from the weakest thread evidence."""
    levels = []
    for tid in tids:
        dt = tid_map.get(tid)
        if dt is None:
            continue
        if dt.evidence == "futex_syscall":
            levels.append("certain")
        elif dt.evidence == "backtrace_lock":
            levels.append("probable")
        else:
            levels.append("possible")

    if not levels:
        return "possible"
    # Level is the weakest link
    _ORDER = {"certain": 3, "probable": 2, "possible": 1}
    return min(levels, key=lambda level: _ORDER.get(level, 0))


def _cycle_description(tids: list[int], tid_map: dict[int, DeadlockThread]) -> str:
    parts = []
    for tid in tids:
        dt = tid_map.get(tid)
        label = f"TID {tid}"
        if dt and dt.name:
            label += f" ({dt.name})"
        if dt and dt.waiting_for is not None:
            label += f" waiting on {dt.waiting_for:#x}"
        if dt:
            label += f" [{_EVIDENCE_LABELS.get(dt.evidence, dt.evidence)}]"
        parts.append(label)
    return " → ".join(parts) + (f" → TID {tids[0]}" if len(tids) > 1 else "")


def _build_summary(
    cycles: list[DeadlockCycle],
    suspected: list[DeadlockThread],
    level: str,
) -> str:
    lines = []
    if cycles:
        lines.append(f"Detected {len(cycles)} deadlock cycle(s) — evidence: {level}.")
        for i, c in enumerate(cycles, 1):
            lines.append(f"  Cycle {i}: {c.description}")
    if suspected:
        names = ", ".join(
            f"TID {dt.tid}" + (f" ({dt.name})" if dt.name else "") for dt in suspected
        )
        lines.append(f"Suspected blocked (no confirmed cycle): {names}")
    return "\n".join(lines)
