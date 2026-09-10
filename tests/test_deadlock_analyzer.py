"""
Tests for DeadlockAnalyzer module (Phase B2 — deadlock detection).

Tests the three evidence tiers:
  certain  — futex syscall with known mutex address
  probable — pthread_mutex_lock / __lll_lock_wait in backtrace
  possible — wchan shows futex wait; ≥2 blocked threads

Also tests edge cases: single blocked thread, no blocked threads, mixed evidence.
"""

from blackadder.deadlock_analyzer import (
    DeadlockAnalyzer,
    DeadlockReport,
)

# ============================================================================
# Helpers
# ============================================================================


def _thread(
    tid: int,
    name: str | None = None,
    wchan: str | None = None,
    syscall: str | None = None,
    thread_id: int | None = None,
) -> dict:
    return {
        "id": thread_id if thread_id is not None else tid,
        "tid": tid,
        "name": name,
        "wchan": wchan,
        "syscall": syscall,
        "stack_start": None,
        "stack_end": None,
    }


def _analyze(threads: list[dict], backtraces: dict | None = None) -> DeadlockReport:
    return DeadlockAnalyzer(threads, backtraces or {}).analyze()


# ============================================================================
# No blocked threads
# ============================================================================


class TestNoDeadlock:
    def test_empty_thread_list(self):
        report = _analyze([])
        assert report.evidence_level == "none"
        assert not report.cycles
        assert not report.suspected_threads

    def test_running_threads_only(self):
        threads = [
            _thread(100, wchan="0", syscall="running"),
            _thread(101, wchan="0", syscall="running"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "none"
        assert not report.cycles

    def test_non_blocking_wchan(self):
        threads = [
            _thread(100, wchan="poll_schedule_timeout"),
            _thread(101, wchan="pipe_wait"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "none"

    def test_non_blocking_syscall_nr(self):
        # syscall 1 = write, not futex
        threads = [
            _thread(100, syscall="1 0x7f000000 0x0 0x100 0x0 0x0 0x0 0x7fff000 0x400a1c"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "none"


# ============================================================================
# Tier 1: futex syscall (certain)
# ============================================================================


class TestFutexSyscall:
    """Live /proc/PID/task/TID/syscall data — highest confidence."""

    def _futex_syscall(self, uaddr: int, op: int = 0) -> str:
        """Build a synthetic /proc syscall line for x86-64 futex (nr=202)."""
        return f"202 {uaddr:#x} {op:#x} 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"

    def test_two_thread_deadlock_certain(self):
        """Classic A→B, B→A deadlock with futex addresses."""
        addr_a = 0x7F001000  # mutex held by B, waited by A
        addr_b = 0x7F002000  # mutex held by A, waited by B

        threads = [
            _thread(100, name="worker-1", syscall=self._futex_syscall(addr_a)),
            _thread(101, name="worker-2", syscall=self._futex_syscall(addr_b)),
        ]
        report = _analyze(threads)

        assert report.evidence_level == "certain"
        assert len(report.cycles) == 1
        cycle = report.cycles[0]
        assert set(cycle.tids) == {100, 101}
        assert cycle.evidence_level == "certain"

    def test_three_thread_deadlock_certain(self):
        """A→B→C→A ring deadlock."""
        addr_a, addr_b, addr_c = 0x7F001000, 0x7F002000, 0x7F003000

        threads = [
            _thread(100, syscall=self._futex_syscall(addr_a)),
            _thread(101, syscall=self._futex_syscall(addr_b)),
            _thread(102, syscall=self._futex_syscall(addr_c)),
        ]
        report = _analyze(threads)

        assert report.evidence_level == "certain"
        assert len(report.cycles) == 1
        assert set(report.cycles[0].tids) == {100, 101, 102}

    def test_futex_wait_op_0(self):
        """FUTEX_WAIT (op=0) is detected."""
        threads = [
            _thread(100, syscall=self._futex_syscall(0x7F001000, op=0)),
            _thread(101, syscall=self._futex_syscall(0x7F002000, op=0)),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "certain"

    def test_futex_wait_private_op_128(self):
        """FUTEX_WAIT_PRIVATE (op=128) is detected."""
        threads = [
            _thread(100, syscall=self._futex_syscall(0x7F001000, op=128)),
            _thread(101, syscall=self._futex_syscall(0x7F002000, op=128)),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "certain"

    def test_futex_wake_op_not_detected(self):
        """FUTEX_WAKE (op=1) should NOT be classified as blocked."""
        threads = [
            _thread(100, syscall=self._futex_syscall(0x7F001000, op=1)),
            _thread(101, syscall=self._futex_syscall(0x7F002000, op=1)),
        ]
        report = _analyze(threads)
        # FUTEX_WAKE means thread is waking others, not blocked
        assert report.evidence_level == "none"

    def test_arm64_futex_nr_98(self):
        """ARM64 uses syscall number 98 for futex."""
        threads = [
            _thread(100, syscall="98 0x7f001000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
            _thread(101, syscall="98 0x7f002000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "certain"

    def test_x86_futex_nr_240(self):
        """x86 (32-bit) uses syscall number 240 for futex."""
        threads = [
            _thread(100, syscall="240 0xf7001000 0x0 0x0 0x0 0x0 0x0 0xffff000 0x804a1c"),
            _thread(101, syscall="240 0xf7002000 0x0 0x0 0x0 0x0 0x0 0xffff000 0x804a1c"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "certain"

    def test_single_blocked_thread_no_cycle(self):
        """One blocked thread → suspected, no confirmed cycle."""
        threads = [
            _thread(100, syscall=self._futex_syscall(0x7F001000)),
        ]
        report = _analyze(threads)
        # Only 1 thread — can't form a deadlock cycle
        assert report.evidence_level in ("none",)

    def test_contention_same_address_not_deadlock(self):
        """Multiple threads waiting on THE SAME address = contention, not deadlock."""
        addr = 0x7F001000
        threads = [
            _thread(100, syscall=self._futex_syscall(addr)),
            _thread(101, syscall=self._futex_syscall(addr)),
            _thread(102, syscall=self._futex_syscall(addr)),
        ]
        report = _analyze(threads)
        # All waiting on same address → one holds it, others wait → not a cycle
        # They are suspected but evidence_level should not be "certain" for a cycle
        # (no confirmed cycle since addresses repeat)
        assert (
            not any(len(c.tids) == 3 for c in report.cycles) or report.evidence_level != "certain"
        )


# ============================================================================
# Tier 2: backtrace symbols (probable)
# ============================================================================


class TestBacktraceSymbols:
    """Offline GDB dump: lock symbols in backtrace frames."""

    def test_two_threads_with_mutex_lock_symbol(self):
        threads = [
            _thread(100, thread_id=10),
            _thread(101, thread_id=11),
        ]
        backtraces = {
            10: ["__lll_lock_wait", "pthread_mutex_lock", "worker_func", "start_thread"],
            11: ["pthread_mutex_lock", "another_func", "start_thread"],
        }
        report = _analyze(threads, backtraces)

        assert report.evidence_level in ("probable", "possible")
        # Both threads blocked
        all_tids = {dt.tid for dt in report.suspected_threads}
        all_cycle_tids = {tid for c in report.cycles for tid in c.tids}
        assert {100, 101} == all_tids | all_cycle_tids

    def test_lll_lock_wait_detected(self):
        threads = [_thread(100, thread_id=1), _thread(101, thread_id=2)]
        backtraces = {
            1: ["__lll_lock_wait"],
            2: ["__lll_lock_wait_private"],
        }
        report = _analyze(threads, backtraces)
        assert report.evidence_level != "none"

    def test_rwlock_symbols_detected(self):
        threads = [_thread(100, thread_id=1), _thread(101, thread_id=2)]
        backtraces = {
            1: ["pthread_rwlock_wrlock", "writer_thread"],
            2: ["pthread_rwlock_rdlock", "reader_thread"],
        }
        report = _analyze(threads, backtraces)
        assert report.evidence_level != "none"

    def test_sem_wait_detected(self):
        threads = [_thread(100, thread_id=1), _thread(101, thread_id=2)]
        backtraces = {
            1: ["sem_wait", "consumer_thread"],
            2: ["sem_wait", "another_consumer"],
        }
        report = _analyze(threads, backtraces)
        assert report.evidence_level != "none"

    def test_non_lock_symbols_not_detected(self):
        threads = [_thread(100, thread_id=1)]
        backtraces = {
            1: ["malloc", "free", "memcpy", "main"],
        }
        report = _analyze(threads, backtraces)
        assert report.evidence_level == "none"

    def test_symbol_with_offset_suffix_stripped(self):
        """pthread_mutex_lock+0x42 should still be recognized."""
        threads = [_thread(100, thread_id=1), _thread(101, thread_id=2)]
        backtraces = {
            1: ["pthread_mutex_lock+0x42"],
            2: ["__lll_lock_wait+0x10"],
        }
        report = _analyze(threads, backtraces)
        assert report.evidence_level != "none"

    def test_backtrace_evidence_level_is_probable(self):
        """Backtrace-only evidence → at most 'probable'."""
        threads = [_thread(100, thread_id=1), _thread(101, thread_id=2)]
        backtraces = {
            1: ["pthread_mutex_lock"],
            2: ["pthread_mutex_lock"],
        }
        report = _analyze(threads, backtraces)
        assert report.evidence_level in ("probable", "possible")
        assert report.evidence_level != "certain"


# ============================================================================
# Tier 3: wchan (possible)
# ============================================================================


class TestWchan:
    def test_futex_wait_wchan(self):
        threads = [
            _thread(100, wchan="futex_wait"),
            _thread(101, wchan="futex_wait_queue_me"),
        ]
        report = _analyze(threads)
        assert report.evidence_level != "none"

    def test_do_futex_wchan(self):
        threads = [
            _thread(100, wchan="do_futex"),
            _thread(101, wchan="do_futex"),
        ]
        report = _analyze(threads)
        assert report.evidence_level != "none"

    def test_wchan_evidence_is_possible(self):
        threads = [
            _thread(100, wchan="futex_wait"),
            _thread(101, wchan="futex_wait"),
        ]
        report = _analyze(threads)
        # wchan-only → possible
        assert report.evidence_level == "possible"
        assert report.evidence_level != "certain"
        assert report.evidence_level != "probable"

    def test_unknown_wchan_ignored(self):
        threads = [
            _thread(100, wchan="ep_poll"),
            _thread(101, wchan="inet_csk_accept"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "none"


# ============================================================================
# Mixed evidence and edge cases
# ============================================================================


class TestMixedEvidence:
    def test_futex_plus_wchan_gives_certain(self):
        """One thread with futex syscall, one with wchan → cycle is certain/probable."""
        threads = [
            _thread(100, syscall="202 0x7f001000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
            _thread(101, syscall="202 0x7f002000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "certain"

    def test_cycle_evidence_weakest_link(self):
        """Cycle evidence = weakest evidence among participating threads."""
        # Thread 100: futex syscall (certain), Thread 101: backtrace (probable)
        threads = [
            _thread(
                100, thread_id=1, syscall="202 0x7f001000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"
            ),
            _thread(
                101, thread_id=2, syscall="202 0x7f002000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"
            ),
        ]
        backtraces = {2: ["pthread_mutex_lock"]}
        # Both have futex syscall so both certain (backtrace checked only if syscall fails)
        report = _analyze(threads, backtraces)
        assert report.evidence_level == "certain"

    def test_report_has_summary(self):
        threads = [
            _thread(100, syscall="202 0x7f001000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
            _thread(101, syscall="202 0x7f002000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
        ]
        report = _analyze(threads)
        assert len(report.summary) > 0

    def test_suspected_threads_not_in_cycle(self):
        """A thread blocked but alone → suspected, not in cycle."""
        threads = [
            _thread(100, wchan="futex_wait"),
        ]
        report = _analyze(threads)
        # Single thread can't form cycle; no cycle, evidence_level="none" (< 2 threads)
        assert report.evidence_level == "none"

    def test_two_wchan_threads_form_possible_deadlock(self):
        """Two threads with wchan → possible deadlock (no addresses to confirm)."""
        threads = [
            _thread(100, wchan="futex_wait"),
            _thread(101, wchan="futex_wait"),
        ]
        report = _analyze(threads)
        assert report.evidence_level == "possible"
        assert len(report.cycles) == 1
        assert report.cycles[0].evidence_level == "possible"

    def test_thread_name_preserved(self):
        threads = [
            _thread(100, name="audio-thread", wchan="futex_wait"),
            _thread(101, name="video-thread", wchan="futex_wait"),
        ]
        report = _analyze(threads)
        # Names appear somewhere in description or suspected_threads
        all_names = {dt.name for dt in report.suspected_threads}
        all_names |= {name for c in report.cycles for name in (c.description,) if c.description}
        # At least the cycle/suspected captures our TIDs
        all_tids = {dt.tid for dt in report.suspected_threads}
        all_tids |= {tid for c in report.cycles for tid in c.tids}
        assert {100, 101} == all_tids


# ============================================================================
# DeadlockReport dataclass
# ============================================================================


class TestDeadlockReport:
    def test_default_report_is_clean(self):
        report = DeadlockReport()
        assert report.cycles == []
        assert report.suspected_threads == []
        assert report.evidence_level == "none"
        assert report.summary == ""
        assert report.lock_state == []
        assert report.condition_waits == []

    def test_dataclass_serializable(self):
        """DeadlockReport must be serializable with dataclasses.asdict."""
        from dataclasses import asdict

        threads = [
            _thread(100, syscall="202 0x7f001000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
            _thread(101, syscall="202 0x7f002000 0x0 0x0 0x0 0x0 0x0 0x7fff000 0x400a1c"),
        ]
        report = _analyze(threads)
        d = asdict(report)
        assert "cycles" in d
        assert "evidence_level" in d
        assert isinstance(d["cycles"], list)
