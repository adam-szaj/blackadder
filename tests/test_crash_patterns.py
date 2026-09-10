"""Tests for CrashPatternEngine."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

from baldrick.crash_patterns import CrashPatternEngine

# ============================================================================
# Helpers — lightweight stand-ins for ORM objects
# ============================================================================


def _thread(
    tid: int,
    db_id: int,
    wchan: str = "",
    syscall: str = "",
    stack_start: int = 0x7FFF0000,
    stack_end: int = 0x7FFF8000,
):
    return SimpleNamespace(
        id=db_id,
        tid=tid,
        name=f"t{tid}",
        wchan=wchan,
        syscall=syscall,
        stack_start=stack_start,
        stack_end=stack_end,
    )


def _bt(thread_id: int, symbol: str, frame_num: int = 0, process_id: int = 1):
    return SimpleNamespace(
        thread_id=thread_id,
        resolved_symbol=symbol,
        frame_num=frame_num,
        process_id=process_id,
        address=0,
        resolved_file=None,
        resolved_line=None,
        match_confidence=None,
    )


def _mapping(perms: str, pathname: str = "", start: int = 0x7F000000, end: int = 0x7F100000):
    return SimpleNamespace(
        perms=perms,
        pathname=pathname,
        start_addr=start,
        end_addr=end,
        process_id=1,
        offset=0,
        dev="",
        inode=0,
    )


def _regstate(thread_id: int | None, registers: dict):
    import json

    return SimpleNamespace(
        thread_id=thread_id,
        registers_json=json.dumps(registers),
        arch="x86_64",
        process_id=1,
    )


@dataclass
class _FakeDeadlockReport:
    cycles: list = field(default_factory=list)
    suspected_threads: list = field(default_factory=list)
    evidence_level: str = "none"
    summary: str = ""


# ============================================================================
# Tests — no patterns
# ============================================================================


def _engine(threads=(), backtraces=(), mappings=(), register_states=(), deadlock=None):
    if deadlock is None:
        deadlock = _FakeDeadlockReport()
    return CrashPatternEngine(
        threads=list(threads),
        backtraces=list(backtraces),
        mappings=list(mappings),
        register_states=list(register_states),
        deadlock_report=deadlock,
    )


class TestNoPatterns:
    def test_empty_snapshot(self):
        report = _engine().analyze()
        assert report.patterns == []
        assert "No patterns" in report.summary

    def test_healthy_threads(self):
        t = _thread(100, 1)
        report = _engine(threads=[t]).analyze()
        assert report.patterns == []


# ============================================================================
# Tests — deadlock
# ============================================================================


class TestDeadlockPattern:
    def test_deadlock_forwarded(self):
        from baldrick.deadlock_analyzer import DeadlockCycle

        cycle = DeadlockCycle(tids=[1, 2], evidence_level="certain", description="A→B→A")

        @dataclass
        class FakeDL:
            cycles: list = field(default_factory=list)
            suspected_threads: list = field(default_factory=list)
            evidence_level: str = "certain"
            summary: str = "Deadlock detected"

        dl = FakeDL(cycles=[cycle])
        report = _engine(deadlock=dl).analyze()
        names = [p.name for p in report.patterns]
        assert "deadlock" in names

    def test_no_deadlock_when_none(self):
        report = _engine(deadlock=_FakeDeadlockReport(evidence_level="none")).analyze()
        assert not any(p.name == "deadlock" for p in report.patterns)


# ============================================================================
# Tests — stack overflow
# ============================================================================


class TestStackOverflow:
    def test_detects_sp_near_stack_end(self):
        t = _thread(200, 2, stack_end=0x7FFF8000)
        # SP 100 bytes from stack_end → overflow
        rs = _regstate(2, {"rsp": 0x7FFF8000 - 100})
        report = _engine(threads=[t], register_states=[rs]).analyze()
        assert any(p.name == "stack-overflow" for p in report.patterns)

    def test_no_overflow_when_sp_safe(self):
        t = _thread(200, 2, stack_end=0x7FFF8000)
        rs = _regstate(2, {"rsp": 0x7FFF0000})  # 32 KB away
        report = _engine(threads=[t], register_states=[rs]).analyze()
        assert not any(p.name == "stack-overflow" for p in report.patterns)

    def test_arm_sp_register(self):
        t = _thread(200, 2, stack_end=0x7FFF8000)
        rs = _regstate(2, {"sp": 0x7FFF8000 - 50})  # ARM sp
        report = _engine(threads=[t], register_states=[rs]).analyze()
        assert any(p.name == "stack-overflow" for p in report.patterns)

    def test_no_overflow_when_no_register_state(self):
        t = _thread(200, 2, stack_end=0x7FFF8000)
        report = _engine(threads=[t]).analyze()
        assert not any(p.name == "stack-overflow" for p in report.patterns)


# ============================================================================
# Tests — null dereference
# ============================================================================


class TestNullDeref:
    def test_detects_zero_ip(self):
        rs = _regstate(None, {"rip": 0x0})
        report = _engine(register_states=[rs]).analyze()
        assert any(p.name == "null-deref" for p in report.patterns)

    def test_detects_low_ip(self):
        rs = _regstate(None, {"rip": 0x8})
        report = _engine(register_states=[rs]).analyze()
        assert any(p.name == "null-deref" for p in report.patterns)

    def test_no_null_deref_for_normal_ip(self):
        rs = _regstate(None, {"rip": 0x7F1234567890})
        report = _engine(register_states=[rs]).analyze()
        assert not any(p.name == "null-deref" for p in report.patterns)

    def test_uses_pc_for_arm(self):
        rs = _regstate(None, {"pc": 0x0})
        report = _engine(register_states=[rs]).analyze()
        assert any(p.name == "null-deref" for p in report.patterns)

    def test_h2_crash_insn_att_syntax(self):
        # AT&T syntax: movl $0x2a,(%rdi) — rdi used as memory base
        # Exact backtrace_test scenario: rdi=0x0 at movl $0x2a,(%rdi)
        rs = _regstate(
            None,
            {
                "rip": 0x55555555512D,
                "rdi": 0x0,
                "__crash_insn__": "movl   $0x2a,(%rdi)",
            },
        )
        report = _engine(register_states=[rs]).analyze()
        p = next((x for x in report.patterns if x.name == "null-deref"), None)
        assert p is not None
        assert "rdi" in p.evidence[0]
        assert p.confidence == "probable"

    def test_h2_crash_insn_intel_syntax(self):
        # Intel syntax: mov DWORD PTR [rdi],0x2a
        rs = _regstate(
            None,
            {
                "rip": 0x400000,
                "rdi": 0x0,
                "__crash_insn__": "mov    DWORD PTR [rdi],0x2a",
            },
        )
        report = _engine(register_states=[rs]).analyze()
        p = next((x for x in report.patterns if x.name == "null-deref"), None)
        assert p is not None
        assert "rdi" in p.evidence[0]

    def test_h2_no_false_positive_nonzero_reg(self):
        # rdi in crash instruction but not NULL — no null-deref
        rs = _regstate(
            None,
            {
                "rip": 0x400000,
                "rdi": 0x7F1234567890,
                "__crash_insn__": "movl   $0x2a,(%rdi)",
            },
        )
        report = _engine(register_states=[rs]).analyze()
        assert not any(p.name == "null-deref" for p in report.patterns)

    def test_h3_fallback_zero_reg(self):
        # No crash instruction — h3 fallback: rdi=0 while rip is valid
        rs = _regstate(None, {"rip": 0x55555555512D, "rdi": 0x0})
        report = _engine(register_states=[rs]).analyze()
        p = next((x for x in report.patterns if x.name == "null-deref"), None)
        assert p is not None
        assert p.confidence == "possible"

    def test_h3_no_false_positive_normal_regs(self):
        # All regs have normal values — no null-deref
        rs = _regstate(None, {"rip": 0x55555555512D, "rdi": 0x7F1234567890})
        report = _engine(register_states=[rs]).analyze()
        assert not any(p.name == "null-deref" for p in report.patterns)

    def test_h1_takes_precedence_when_ip_null(self):
        # IP is NULL — h1 fires, h2/h3 skipped for same thread
        rs = _regstate(None, {"rip": 0x0, "rdi": 0x0, "__crash_insn__": "movl $0x2a,(%rdi)"})
        report = _engine(register_states=[rs]).analyze()
        patterns = [p for p in report.patterns if p.name == "null-deref"]
        assert len(patterns) == 1
        assert "IP/PC" in patterns[0].evidence[0]


# ============================================================================
# Tests — use-after-free
# ============================================================================


class TestUseAfterFree:
    def test_detects_free_and_alloc_same_thread(self):
        t = _thread(300, 3)
        bts = [_bt(3, "malloc"), _bt(3, "__GI___libc_free")]
        report = _engine(threads=[t], backtraces=bts).analyze()
        assert any(p.name == "use-after-free" for p in report.patterns)

    def test_possible_without_rwx(self):
        t = _thread(300, 3)
        bts = [_bt(3, "malloc"), _bt(3, "free")]
        report = _engine(threads=[t], backtraces=bts).analyze()
        p = next((x for x in report.patterns if x.name == "use-after-free"), None)
        assert p is not None
        assert p.confidence == "possible"

    def test_probable_with_rwx(self):
        t = _thread(300, 3)
        bts = [_bt(3, "malloc"), _bt(3, "free")]
        rwx = _mapping("rwxp", "")
        report = _engine(threads=[t], backtraces=bts, mappings=[rwx]).analyze()
        p = next((x for x in report.patterns if x.name == "use-after-free"), None)
        assert p is not None
        assert p.confidence == "probable"

    def test_no_uaf_only_free(self):
        t = _thread(300, 3)
        bts = [_bt(3, "free")]
        report = _engine(threads=[t], backtraces=bts).analyze()
        assert not any(p.name == "use-after-free" for p in report.patterns)


# ============================================================================
# Tests — double free
# ============================================================================


class TestDoubleFree:
    def test_detects_double_free(self):
        t = _thread(400, 4)
        bts = [_bt(4, "__GI___libc_free", 0), _bt(4, "tcache_put", 1)]
        report = _engine(threads=[t], backtraces=bts).analyze()
        assert any(p.name == "double-free" for p in report.patterns)

    def test_no_double_free_single_free(self):
        t = _thread(400, 4)
        bts = [_bt(4, "free")]
        report = _engine(threads=[t], backtraces=bts).analyze()
        assert not any(p.name == "double-free" for p in report.patterns)


# ============================================================================
# Tests — RWX anomaly
# ============================================================================


class TestRwxAnomaly:
    def test_detects_rwx_anon(self):
        rwx = _mapping("rwxp", "")
        report = _engine(mappings=[rwx]).analyze()
        assert any(p.name == "rwx-region" for p in report.patterns)

    def test_skips_so_library(self):
        rwx = _mapping("rwxp", "/usr/lib/libv8.so")
        report = _engine(mappings=[rwx]).analyze()
        assert not any(p.name == "rwx-region" for p in report.patterns)

    def test_no_rwx_for_normal_perms(self):
        m = _mapping("r-xp", "")
        report = _engine(mappings=[m]).analyze()
        assert not any(p.name == "rwx-region" for p in report.patterns)


# ============================================================================
# Tests — summary
# ============================================================================


class TestSummary:
    def test_summary_no_patterns(self):
        report = _engine().analyze()
        assert report.summary == "No patterns detected"

    def test_summary_with_patterns(self):
        rs = _regstate(None, {"rip": 0x0})
        report = _engine(register_states=[rs]).analyze()
        assert "1 pattern(s)" in report.summary
        assert "null-deref" in report.summary
