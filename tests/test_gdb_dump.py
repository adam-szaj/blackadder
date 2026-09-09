"""
Tests for blackadder/binutils/gdb_dump.py.

Covers:
  - parse_gdb_dump()       — multi-thread backtrace + register parsing
  - parse_gdb_registers_only() — standalone register parsing
  - parse_lock_state()     — find_deadlock JSON output parsing
  - LockStateEntry         — dataclass correctness
"""

from blackadder.binutils.gdb_dump import (
    parse_gdb_dump,
    parse_gdb_registers_only,
    parse_lock_state,
)

# ============================================================================
# Fixtures — realistic GDB output snippets
# ============================================================================

_GDB_TWO_THREADS = """\
Thread 2 (LWP 12346 "deadlock_test"):
#0  futex_wait (futex_word=0x7f001000 <m1>, expected=2, private=0) at futex-internal.h:146
#1  __GI___lll_lock_wait (futex=0x7f001000 <m1>, private=0) at lowlevellock.c:49
#2  ___pthread_mutex_lock (mutex=0x7f001000 <m1>) at pthread_mutex_lock.c:93
#3  worker (arg=0x0) at test.cpp:42

Thread 1 (LWP 12345 "deadlock_test"):
#0  __syscall_cancel_arch () at syscall_cancel.S:56
#1  pthread_join () at pthread_join.c:30
"""

_GDB_WITH_REGISTERS = """\
Thread 1 (LWP 99001 "myapp"):
#0  0x00007f001000 in main () at main.c:10

(gdb) info registers
rax            0x0                 0
rbx            0x400a1c            4197916
rip            0x400a1c            0x400a1c <main>
rsp            0x7fff000           134213632
eflags         0x202               514
mxcsr          0x1f80              8064
orig_rax       0xffffffffffffffff  -1
fs_base        0x700               1792
"""

_GDB_SINGLE_THREAD_OLDER_FORMAT = """\
Thread 1 (Thread 0xf7f12000 (LWP 55555)):
#0  0x0804a1c in some_func ()
#1  0x0804a2c in main ()
"""

_GDB_UNKNOWN_SYMBOLS = """\
Thread 1 (LWP 10001 "stripped"):
#0  0x00007f001234 in ?? ()
#1  0x00007f005678 in ??? ()
#2  0x00007f009abc in known_func (x=1) at known.c:5
"""

_GDB_EMPTY = ""

_GDB_NO_THREADS = """\
Starting program: /bin/true
[Inferior 1 (process 9999) exited normally]
"""

_LOCK_STATE_WITH_MARKERS = """\
[Thread debugging using libthread_db enabled]
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1000, "tid": 1001, "name": "worker-1", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x7f001234", "lock_symbol": "m1", "owner_tid": 1002, "reader_count": 0}
{"pid": 1000, "tid": 1002, "name": "worker-2", "gdb_thread_num": 3, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x7f005678", "lock_symbol": "m2", "owner_tid": 1001, "reader_count": 0}
BALDRICK_LOCK_STATE_END
[Inferior 1 detached]
"""

_LOCK_STATE_PLAIN_JSON = """\
{"pid": 2000, "tid": 2001, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_rwlock_wrlock", "lock_type": "rwlock_write", "waiting_for_addr": "0x7f009abc", "lock_symbol": "rw1", "owner_tid": null, "reader_count": 3}
{"pid": 2000, "tid": 2002, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": null, "lock_symbol": null, "owner_tid": null, "reader_count": 0}
"""

_LOCK_STATE_WITH_ERROR = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 3000, "tid": 3001, "name": "good", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x7f000001", "lock_symbol": "mtx", "owner_tid": 3002, "reader_count": 0}
{"tid": 3999, "error": "frame access failed"}
BALDRICK_LOCK_STATE_END
"""

_REGISTERS_X86_64 = """\
rax            0x0                 0
rbx            0x400a1c            4197916
rcx            0x7f000000          2130706432
rdx            0x1                 1
rsi            0x2                 2
rdi            0x3                 3
rbp            0x7fff1000          2147418112
rsp            0x7fff0ff0          2147418096
rip            0x400a1c            0x400a1c <main>
r8             0x0                 0
r9             0x0                 0
r10            0x0                 0
r11            0x202               514
r12            0x0                 0
r13            0x0                 0
r14            0x0                 0
r15            0x0                 0
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fctrl          0x37f               895
fstat          0x0                 0
mxcsr          0x1f80              8064
orig_rax       0xffffffffffffffff  -1
fs_base        0x7f000000          2130706432
gs_base        0x0                 0
"""

_REGISTERS_ARM64 = """\
x0             0x0                 0
x1             0x400a1c            4197916
x2             0x0                 0
x29            0x7fff1000          2147418112
x30            0x400abc            4196028
sp             0x7fff0ff0          2147418096
pc             0x400a1c            0x400a1c <main>
cpsr           0x60000000          1610612736
"""


# ============================================================================
# parse_gdb_dump — thread parsing
# ============================================================================


class TestParseGdbDumpThreads:
    def test_two_threads_parsed(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        assert len(dump.threads) == 2

    def test_thread_numbers_and_tids(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        t2, t1 = dump.threads
        assert t2.gdb_thread_num == 2
        assert t2.tid == 12346
        assert t1.gdb_thread_num == 1
        assert t1.tid == 12345

    def test_thread_name_parsed(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        assert dump.threads[0].name == "deadlock_test"
        assert dump.threads[1].name == "deadlock_test"

    def test_frames_count(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        assert len(dump.threads[0].frames) == 4
        assert len(dump.threads[1].frames) == 2

    def test_frame_numbers(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        frames = dump.threads[0].frames
        assert [f.frame_num for f in frames] == [0, 1, 2, 3]

    def test_frame_with_address(self):
        dump = parse_gdb_dump(_GDB_WITH_REGISTERS)
        frame = dump.threads[0].frames[0]
        assert frame.address == 0x00007F001000
        assert frame.symbol == "main"

    def test_frame_without_address(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        # frames without "0xADDR in" prefix
        frame0 = dump.threads[0].frames[0]
        assert frame0.address is None

    def test_frame_symbol_and_source(self):
        dump = parse_gdb_dump(_GDB_TWO_THREADS)
        frame3 = dump.threads[0].frames[3]
        assert frame3.symbol == "worker"
        assert frame3.source_file == "test.cpp"
        assert frame3.source_line == 42

    def test_unknown_symbol_normalized_to_none(self):
        dump = parse_gdb_dump(_GDB_UNKNOWN_SYMBOLS)
        assert dump.threads[0].frames[0].symbol is None  # "??"
        assert dump.threads[0].frames[1].symbol is None  # "???"

    def test_known_symbol_after_unknowns(self):
        dump = parse_gdb_dump(_GDB_UNKNOWN_SYMBOLS)
        frame2 = dump.threads[0].frames[2]
        assert frame2.symbol == "known_func"
        assert frame2.source_file == "known.c"
        assert frame2.source_line == 5

    def test_older_gdb_format_lwp(self):
        dump = parse_gdb_dump(_GDB_SINGLE_THREAD_OLDER_FORMAT)
        assert len(dump.threads) == 1
        assert dump.threads[0].tid == 55555
        assert dump.threads[0].name is None  # no name in older format

    def test_empty_input(self):
        dump = parse_gdb_dump(_GDB_EMPTY)
        assert dump.threads == []
        assert dump.global_registers == {}

    def test_no_threads_in_output(self):
        dump = parse_gdb_dump(_GDB_NO_THREADS)
        assert dump.threads == []


# ============================================================================
# parse_gdb_dump — register parsing
# ============================================================================


class TestParseGdbDumpRegisters:
    def test_registers_attached_to_thread(self):
        dump = parse_gdb_dump(_GDB_WITH_REGISTERS)
        regs = dump.threads[0].registers
        assert "rax" in regs
        assert regs["rax"] == 0x0
        assert regs["rbx"] == 0x400A1C
        assert regs["rip"] == 0x400A1C

    def test_skip_regs_excluded(self):
        dump = parse_gdb_dump(_GDB_WITH_REGISTERS)
        regs = dump.threads[0].registers
        # mxcsr, orig_rax, fs_base are in _SKIP_REGS
        assert "mxcsr" not in regs
        assert "orig_rax" not in regs
        assert "fs_base" not in regs

    def test_eflags_included(self):
        dump = parse_gdb_dump(_GDB_WITH_REGISTERS)
        regs = dump.threads[0].registers
        assert "eflags" in regs
        assert regs["eflags"] == 0x202

    def test_global_registers_before_thread(self):
        # Registers before any Thread header go to global_registers
        text = """\
(gdb) info registers
rax            0x42  66
rbx            0x0   0

Thread 1 (LWP 100 "test"):
#0  main ()
"""
        dump = parse_gdb_dump(text)
        assert dump.global_registers.get("rax") == 0x42
        assert dump.global_registers.get("rbx") == 0

    def test_register_value_hex(self):
        dump = parse_gdb_dump(_GDB_WITH_REGISTERS)
        regs = dump.threads[0].registers
        assert regs["rsp"] == 0x7FFF000

    def test_register_names_lowercased(self):
        text = """\
Thread 1 (LWP 1 "x"):
#0  main ()

(gdb) info registers
RAX            0x1   1
RIP            0x400a1c  4197916
"""
        dump = parse_gdb_dump(text)
        regs = dump.threads[0].registers
        assert "rax" in regs
        assert "rip" in regs
        assert "RAX" not in regs


# ============================================================================
# parse_gdb_registers_only
# ============================================================================


class TestParseGdbRegistersOnly:
    def test_x86_64_basic_registers(self):
        regs = parse_gdb_registers_only(_REGISTERS_X86_64)
        assert regs["rax"] == 0x0
        assert regs["rbx"] == 0x400A1C
        assert regs["rip"] == 0x400A1C
        assert regs["rsp"] == 0x7FFF0FF0

    def test_skip_regs_excluded(self):
        regs = parse_gdb_registers_only(_REGISTERS_X86_64)
        assert "fctrl" not in regs
        assert "fstat" not in regs
        assert "mxcsr" not in regs
        assert "orig_rax" not in regs
        assert "fs_base" not in regs
        assert "gs_base" not in regs

    def test_segment_registers_included(self):
        # cs, ss, ds, es, fs, gs are NOT in _SKIP_REGS
        regs = parse_gdb_registers_only(_REGISTERS_X86_64)
        assert "cs" in regs
        assert "ss" in regs

    def test_eflags_included(self):
        regs = parse_gdb_registers_only(_REGISTERS_X86_64)
        assert regs["eflags"] == 0x202

    def test_arm64_registers(self):
        regs = parse_gdb_registers_only(_REGISTERS_ARM64)
        assert regs["x0"] == 0
        assert regs["x1"] == 0x400A1C
        assert regs["sp"] == 0x7FFF0FF0
        assert regs["pc"] == 0x400A1C

    def test_empty_input(self):
        regs = parse_gdb_registers_only("")
        assert regs == {}

    def test_decimal_value_parsed(self):
        text = "pc             4197916             0x400a1c <main>\n"
        regs = parse_gdb_registers_only(text)
        assert regs["pc"] == 4197916

    def test_all_gp_registers_present(self):
        regs = parse_gdb_registers_only(_REGISTERS_X86_64)
        for reg in [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "rip",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        ]:
            assert reg in regs, f"Missing register: {reg}"


# ============================================================================
# parse_lock_state
# ============================================================================


class TestParseLockState:
    def test_with_markers_two_entries(self):
        entries = parse_lock_state(_LOCK_STATE_WITH_MARKERS)
        assert len(entries) == 2

    def test_entry_fields_mutex(self):
        entries = parse_lock_state(_LOCK_STATE_WITH_MARKERS)
        e = entries[0]
        assert e.pid == 1000
        assert e.tid == 1001
        assert e.name == "worker-1"
        assert e.gdb_thread_num == 2
        assert e.blocking_function == "___pthread_mutex_lock"
        assert e.lock_type == "mutex"
        assert e.waiting_for_addr == 0x7F001234
        assert e.lock_symbol == "m1"
        assert e.owner_tid == 1002
        assert e.reader_count == 0

    def test_entry_ownership_graph(self):
        entries = parse_lock_state(_LOCK_STATE_WITH_MARKERS)
        # 1001 waits on m1 owned by 1002; 1002 waits on m2 owned by 1001
        assert entries[0].owner_tid == 1002
        assert entries[1].owner_tid == 1001

    def test_markers_filter_noise(self):
        # Lines outside markers should be ignored
        entries = parse_lock_state(_LOCK_STATE_WITH_MARKERS)
        assert len(entries) == 2  # not 3+ from noise lines

    def test_plain_json_without_markers(self):
        entries = parse_lock_state(_LOCK_STATE_PLAIN_JSON)
        assert len(entries) == 2

    def test_rwlock_write_entry(self):
        entries = parse_lock_state(_LOCK_STATE_PLAIN_JSON)
        e = entries[0]
        assert e.lock_type == "rwlock_write"
        assert e.lock_symbol == "rw1"
        assert e.owner_tid is None
        assert e.reader_count == 3

    def test_null_addr_handled(self):
        entries = parse_lock_state(_LOCK_STATE_PLAIN_JSON)
        e = entries[1]
        assert e.waiting_for_addr is None
        assert e.lock_symbol is None

    def test_error_entries_skipped(self):
        entries = parse_lock_state(_LOCK_STATE_WITH_ERROR)
        assert len(entries) == 1
        assert entries[0].tid == 3001

    def test_empty_input(self):
        assert parse_lock_state("") == []

    def test_no_json_lines(self):
        text = "Thread debugging enabled\nAttaching to process 123\n"
        assert parse_lock_state(text) == []

    def test_addr_hex_parsing(self):
        entries = parse_lock_state(_LOCK_STATE_WITH_MARKERS)
        assert entries[0].waiting_for_addr == 0x7F001234
        assert entries[1].waiting_for_addr == 0x7F005678

    def test_confidence_field_is_backward_compatible(self):
        text = (
            '{"pid":1,"tid":2,"gdb_thread_num":1,"blocking_function":"syscall",'
            '"lock_type":"unknown","confidence":"heuristic"}'
        )

        entries = parse_lock_state(text)

        assert entries[0].confidence == "heuristic"
        assert parse_lock_state(_LOCK_STATE_WITH_MARKERS)[0].confidence == "unknown"

    def test_real_deadlock_test_output(self):
        """Simulate actual output from deadlock_test + find_deadlock.py."""
        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 9999, "tid": 9001, "name": "deadlock_test", "gdb_thread_num": 3, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x5cd2b4462140", "lock_symbol": "m3", "owner_tid": 9002, "reader_count": 0}
{"pid": 9999, "tid": 9002, "name": "deadlock_test", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x5cd2b4462180", "lock_symbol": "m2", "owner_tid": 9001, "reader_count": 0}
{"pid": 9999, "tid": 9003, "name": "deadlock_test", "gdb_thread_num": 4, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x5cd2b44621c0", "lock_symbol": "m1", "owner_tid": 9001, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = parse_lock_state(text)
        assert len(entries) == 3
        tids = {e.tid for e in entries}
        assert tids == {9001, 9002, 9003}
        # ownership: 9001→9002, 9002→9001 (cycle), 9003→9001 (suspected)
        owner_map = {e.tid: e.owner_tid for e in entries}
        assert owner_map[9001] == 9002
        assert owner_map[9002] == 9001
        assert owner_map[9003] == 9001


# ============================================================================
# DeadlockAnalyzer Tier 0 (lock_state integration)
# ============================================================================


class TestDeadlockAnalyzerTier0:
    """Tests for _analyze_from_lock_state() — exact ownership graph."""

    def _entries(self, text: str):
        return parse_lock_state(text)

    def test_two_thread_cycle_certain(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 101, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "ma", "owner_tid": 102, "reader_count": 0}
{"pid": 1, "tid": 102, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "mb", "owner_tid": 101, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        assert report.evidence_level == "certain"
        assert len(report.cycles) == 1
        assert set(report.cycles[0].tids) == {101, 102}
        assert report.cycles[0].evidence_level == "certain"

    def test_three_thread_cycle(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 101, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": 103, "reader_count": 0}
{"pid": 1, "tid": 102, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "m2", "owner_tid": 101, "reader_count": 0}
{"pid": 1, "tid": 103, "name": "t3", "gdb_thread_num": 3, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x3000", "lock_symbol": "m3", "owner_tid": 102, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        assert report.evidence_level == "certain"
        assert len(report.cycles) == 1
        assert set(report.cycles[0].tids) == {101, 102, 103}

    def test_suspected_thread_not_in_cycle(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        # tid 103 waits on m1 owned by 101, but 103 doesn't own anything 101 wants
        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 101, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "m2", "owner_tid": 102, "reader_count": 0}
{"pid": 1, "tid": 102, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": 101, "reader_count": 0}
{"pid": 1, "tid": 103, "name": "t3", "gdb_thread_num": 3, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": 101, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        assert len(report.cycles) == 1
        assert set(report.cycles[0].tids) == {101, 102}
        assert any(dt.tid == 103 for dt in report.suspected_threads)

    def test_unknown_owner_falls_back_to_probable(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        # No owner_tid known — can't confirm cycle
        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 101, "name": "t1", "gdb_thread_num": 1, "blocking_function": "__GI___lll_lock_wait", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": null, "reader_count": 0}
{"pid": 1, "tid": 102, "name": "t2", "gdb_thread_num": 2, "blocking_function": "__GI___lll_lock_wait", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "m2", "owner_tid": null, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        # No ownership → probable (not certain)
        assert report.evidence_level in ("probable", "possible")
        assert report.evidence_level != "certain"

    def test_lock_symbol_in_description(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 101, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "mylock", "owner_tid": 102, "reader_count": 0}
{"pid": 1, "tid": 102, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "otherlock", "owner_tid": 101, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        desc = report.cycles[0].description
        assert "mylock" in desc or "otherlock" in desc

    def test_empty_lock_state_falls_through_to_tier1(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        # Empty lock_state → falls back to normal tier 1/2/3 analysis
        threads = [
            {
                "id": 1,
                "tid": 100,
                "name": None,
                "wchan": "futex_wait",
                "syscall": None,
                "stack_start": None,
                "stack_end": None,
            },
            {
                "id": 2,
                "tid": 101,
                "name": None,
                "wchan": "futex_wait",
                "syscall": None,
                "stack_start": None,
                "stack_end": None,
            },
        ]
        report = DeadlockAnalyzer(threads, {}, lock_state=[]).analyze()
        # Should still detect via wchan (tier 3)
        assert report.evidence_level != "none"

    def test_empty_lock_state_list_returns_none_report(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        # lock_state=[] → falls through to tier 1/2/3 (not Tier 0)
        report = DeadlockAnalyzer([], {}, lock_state=[]).analyze()
        assert report.evidence_level == "none"

    def test_thread_without_name_in_description(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        # name is empty string → treated as None
        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 201, "name": "", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": 202, "reader_count": 0}
{"pid": 1, "tid": 202, "name": "", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "m2", "owner_tid": 201, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        assert report.evidence_level == "certain"
        # No crash even without names
        assert "TID 201" in report.cycles[0].description

    def test_chain_without_cycle_all_suspected(self):
        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        # 301→302→303 (linear chain, no cycle back to 301)
        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 301, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": 302, "reader_count": 0}
{"pid": 1, "tid": 302, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "m2", "owner_tid": 303, "reader_count": 0}
{"pid": 1, "tid": 303, "name": "t3", "gdb_thread_num": 3, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x3000", "lock_symbol": "m3", "owner_tid": null, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        # No cycle (303 has no owner) → probable (≥2 blocked)
        assert report.evidence_level in ("probable", "possible")
        assert len(report.cycles) == 1  # all-blocked group

    def test_json_serializable(self):
        import json
        from dataclasses import asdict

        from blackadder.deadlock_analyzer import DeadlockAnalyzer

        text = """\
BALDRICK_LOCK_STATE_BEGIN
{"pid": 1, "tid": 101, "name": "t1", "gdb_thread_num": 1, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x1000", "lock_symbol": "m1", "owner_tid": 102, "reader_count": 0}
{"pid": 1, "tid": 102, "name": "t2", "gdb_thread_num": 2, "blocking_function": "___pthread_mutex_lock", "lock_type": "mutex", "waiting_for_addr": "0x2000", "lock_symbol": "m2", "owner_tid": 101, "reader_count": 0}
BALDRICK_LOCK_STATE_END
"""
        entries = self._entries(text)
        report = DeadlockAnalyzer([], {}, lock_state=entries).analyze()
        d = asdict(report)
        # Should not raise
        json.dumps(d)
        assert d["evidence_level"] == "certain"
