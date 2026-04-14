"""
Crash Pattern Engine for blackadder.

Detects known crash patterns from DB data (threads, backtraces, mappings,
register states, deadlock report). Operates on plain Python objects — no
async, no DB calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


# ============================================================================
# Data classes
# ============================================================================


@dataclass
class CrashPattern:
    """A single detected crash pattern."""

    name: str
    confidence: str          # "certain" | "probable" | "possible"
    description: str
    evidence: list[str]
    suggestion: str


@dataclass
class CrashPatternReport:
    """Full crash pattern analysis result."""

    patterns: list[CrashPattern] = field(default_factory=list)
    summary: str = "No patterns detected"


# ============================================================================
# Free symbols that indicate memory management operations
# ============================================================================

_FREE_SYMBOLS: frozenset[str] = frozenset({
    "free",
    "cfree",
    "__libc_free",
    "__GI___libc_free",
    "tcache_put",
    "_int_free",
})

_ALLOC_SYMBOLS: frozenset[str] = frozenset({
    "malloc",
    "calloc",
    "realloc",
    "__libc_malloc",
    "__GI___libc_malloc",
    "_int_malloc",
    "tcache_get",
})

# Instruction pointer register names per arch
_IP_REGS: tuple[str, ...] = ("rip", "pc", "eip", "ip")
# Stack pointer register names per arch
_SP_REGS: tuple[str, ...] = ("rsp", "sp", "esp")


# ============================================================================
# Engine
# ============================================================================


class CrashPatternEngine:
    """
    Analyze process snapshot data for known crash patterns.

    Args:
        threads:         Thread ORM objects (or plain dicts with same fields)
        backtraces:      BacktraceEntry ORM objects
        mappings:        MemoryMapping ORM objects
        register_states: ProcessRegisterState ORM objects
        deadlock_report: DeadlockReport from deadlock_analyzer
    """

    def __init__(
        self,
        threads: list,
        backtraces: list,
        mappings: list,
        register_states: list,
        deadlock_report,
    ) -> None:
        self._threads = threads
        self._backtraces = backtraces
        self._mappings = mappings
        self._register_states = register_states
        self._deadlock = deadlock_report

        # Pre-compute: thread db_id → list[resolved_symbol]
        self._bt_by_thread: dict[int, list[str]] = {}
        for bt in backtraces:
            tid = getattr(bt, "thread_id", None)
            sym = getattr(bt, "resolved_symbol", None) or ""
            if tid is not None:
                self._bt_by_thread.setdefault(tid, []).append(sym)

        # Pre-compute: thread db_id → registers dict
        self._regs_by_thread: dict[int | None, dict[str, int]] = {}
        for rs in register_states:
            tid = getattr(rs, "thread_id", None)
            raw = getattr(rs, "registers_json", None) or "{}"
            try:
                regs = json.loads(raw)
            except (ValueError, TypeError):
                regs = {}
            self._regs_by_thread[tid] = regs

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> CrashPatternReport:
        patterns: list[CrashPattern] = []

        for detector in (
            self._detect_deadlock,
            self._detect_stack_overflow,
            self._detect_null_deref,
            self._detect_use_after_free,
            self._detect_double_free,
            self._detect_rwx_anomaly,
        ):
            p = detector()
            if p is not None:
                patterns.append(p)

        if patterns:
            summary = f"{len(patterns)} pattern(s) detected: " + ", ".join(
                p.name for p in patterns
            )
        else:
            summary = "No patterns detected"

        return CrashPatternReport(patterns=patterns, summary=summary)

    # ------------------------------------------------------------------
    # Detectors
    # ------------------------------------------------------------------

    def _detect_deadlock(self) -> CrashPattern | None:
        dl = self._deadlock
        if dl.evidence_level == "none":
            return None

        evidence: list[str] = []
        if dl.cycles:
            for c in dl.cycles:
                evidence.append(
                    f"Cycle ({c.evidence_level}): "
                    + " → ".join(str(t) for t in c.tids)
                )
        for t in dl.suspected_threads:
            evidence.append(
                f"TID {t.tid} ({t.name or '?'}) blocked — {t.evidence}"
            )

        return CrashPattern(
            name="deadlock",
            confidence=dl.evidence_level,
            description=dl.summary or f"Deadlock detected ({dl.evidence_level})",
            evidence=evidence,
            suggestion="Use analyse-deadlock for full deadlock graph. "
                       "Provide --lock-state from find_deadlock.py for exact ownership.",
        )

    def _detect_stack_overflow(self) -> CrashPattern | None:
        """SP within 4096 bytes of stack_end → stack overflow."""
        evidence: list[str] = []

        for thread in self._threads:
            stack_end = getattr(thread, "stack_end", None)
            if stack_end is None:
                continue

            db_id: int | None = getattr(thread, "id", None)
            tid = getattr(thread, "tid", "?")

            # Try per-thread registers first, then main (None key)
            regs = (self._regs_by_thread.get(db_id) if db_id is not None else None) or self._regs_by_thread.get(None) or {}
            sp: int | None = None
            for reg in _SP_REGS:
                if reg in regs:
                    sp = regs[reg]
                    break

            if sp is None:
                continue

            distance = abs(stack_end - sp)
            if distance < 4096:
                evidence.append(
                    f"TID {tid}: SP=0x{sp:x} stack_end=0x{stack_end:x} "
                    f"(distance={distance} bytes)"
                )

        if not evidence:
            return None

        return CrashPattern(
            name="stack-overflow",
            confidence="probable",
            description=f"Stack pointer near stack boundary in {len(evidence)} thread(s)",
            evidence=evidence,
            suggestion="Check for unbounded recursion or large stack allocations. "
                       "Inspect backtrace for recursive call chains.",
        )

    def _detect_null_deref(self) -> CrashPattern | None:
        """IP/PC == 0 or crash address < 0x1000 → null dereference."""
        evidence: list[str] = []

        for tid_key, regs in self._regs_by_thread.items():
            ip: int | None = None
            for reg in _IP_REGS:
                if reg in regs:
                    ip = regs[reg]
                    break
            if ip is not None and ip < 0x1000:
                label = f"TID {tid_key}" if tid_key is not None else "main thread"
                evidence.append(f"{label}: IP/PC=0x{ip:x} (near NULL)")

        if not evidence:
            return None

        return CrashPattern(
            name="null-deref",
            confidence="probable",
            description="Instruction pointer near NULL — likely null pointer dereference",
            evidence=evidence,
            suggestion="Check pointers before dereference. "
                       "Look for uninitialized function pointers or vtable corruption.",
        )

    def _detect_use_after_free(self) -> CrashPattern | None:
        """free() + alloc() in same thread BT + RWX anon region → UAF."""
        rwx_anon = any(
            "rwx" in (getattr(m, "perms", "") or "")
            and not (getattr(m, "pathname", "") or "").endswith(".so")
            and not (getattr(m, "pathname", "") or "").startswith("[")
            for m in self._mappings
        )
        # Also count plain anonymous RWX
        rwx_anon = rwx_anon or any(
            "rwx" in (getattr(m, "perms", "") or "")
            and (getattr(m, "pathname", "") or "") in ("", "[anonymous]")
            for m in self._mappings
        )

        evidence: list[str] = []

        for thread in self._threads:
            db_id: int | None = getattr(thread, "id", None)
            tid = getattr(thread, "tid", "?")
            syms = self._bt_by_thread.get(db_id, []) if db_id is not None else []

            has_free = any(any(f in s for f in _FREE_SYMBOLS) for s in syms)
            has_alloc = any(any(a in s for a in _ALLOC_SYMBOLS) for s in syms)

            if has_free and has_alloc:
                evidence.append(f"TID {tid}: free() + alloc() in same backtrace")

        if not evidence:
            return None

        confidence = "possible"
        desc = f"free()+alloc() in {len(evidence)} thread(s)"
        if rwx_anon:
            desc += " + RWX anonymous region"
            confidence = "probable"
            evidence.append("RWX anonymous memory region present")

        return CrashPattern(
            name="use-after-free",
            confidence=confidence,
            description=desc,
            evidence=evidence,
            suggestion="Enable AddressSanitizer (-fsanitize=address) to confirm. "
                       "Check for dangling pointers after free().",
        )

    def _detect_double_free(self) -> CrashPattern | None:
        """free() appears ≥2 times in one thread's backtrace → double free."""
        evidence: list[str] = []

        for thread in self._threads:
            db_id: int | None = getattr(thread, "id", None)
            tid = getattr(thread, "tid", "?")
            syms = self._bt_by_thread.get(db_id, []) if db_id is not None else []

            free_count = sum(
                1 for s in syms if any(f in s for f in _FREE_SYMBOLS)
            )
            if free_count >= 2:
                evidence.append(
                    f"TID {tid}: free-related symbols appear {free_count}x in backtrace"
                )

        if not evidence:
            return None

        return CrashPattern(
            name="double-free",
            confidence="probable",
            description=f"Multiple free() calls in backtrace ({len(evidence)} thread(s))",
            evidence=evidence,
            suggestion="Enable AddressSanitizer or Valgrind. "
                       "Ensure ownership is clear — each allocation freed exactly once.",
        )

    def _detect_rwx_anomaly(self) -> CrashPattern | None:
        """RWX non-library anonymous region without JIT binary → suspicious."""
        rwx_regions: list[str] = []

        for m in self._mappings:
            perms = getattr(m, "perms", "") or ""
            pathname = getattr(m, "pathname", "") or ""
            if "rwx" not in perms:
                continue
            # Skip shared libraries (likely JIT in JS/Java runtimes)
            if ".so" in pathname:
                continue
            start = getattr(m, "start_addr", 0)
            end = getattr(m, "end_addr", 0)
            size_kb = (end - start) // 1024
            rwx_regions.append(
                f"0x{start:x}–0x{end:x} perms={perms} path={pathname or '(anon)'} ({size_kb} KB)"
            )

        if not rwx_regions:
            return None

        return CrashPattern(
            name="rwx-region",
            confidence="possible",
            description=f"{len(rwx_regions)} RWX non-library memory region(s) — potential code injection or JIT",
            evidence=rwx_regions,
            suggestion="Investigate anonymous RWX regions. "
                       "Legitimate JIT engines (e.g. V8, LuaJIT) produce these; "
                       "unexpected ones may indicate shellcode injection.",
        )
