# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Blackadder** is a production-ready Linux debugging engine written in modern Python 3.12+ (asyncio, SQLModel, Pydantic, Typer). It provides:
- High-speed backtrace decoding via parallel address resolution
- Binary metadata extraction (sections, symbols, debug info) using `objdump`/`readelf`
- Process memory analysis from `/proc/PID/maps`
- Binary matching for version mismatches via assembly fingerprints
- Core dump parsing (ELF PT_LOAD + PT_NOTE)
- Thread state capture from live process or GDB dump
- Deadlock detection (3-tier evidence degradation: certain/probable/possible)
- GDB extension (`find_deadlock`) for exact mutex ownership graphs

## Architecture

### MVP (v0.1.0) - Completed

**Modern Stack**:
- Python 3.12+ with asyncio for all I/O
- SQLModel ORM (combines SQLAlchemy + Pydantic validation)
- Single unified SQLite database (binary metadata + process snapshots)
- Typer CLI framework with async commands
- Subprocess pooling via asyncio.Semaphore (max 32 concurrent)
- LRU symbol cache (100k entries) to avoid duplicate subprocess calls

**Core Modules**:

1. **ORM Models** (`blackadder/models.py`)
   - **Rootfs DB**: Binary, SectionHeader, Symbol, BinaryLocator, FunctionFingerprint, SymbolCache
   - **Process DB**: ProcessSnapshot, Thread, MemoryMapping, ProcessBinary, BacktraceEntry, ProcessRegisterState, MemoryRegionAnalysis
   - Pydantic models: BacktraceRequest, ResolvedFrame (with validators)

2. **Async Database Layer** (`blackadder/db/`)
   - `base.py`: AsyncDatabaseManager wraps aiosqlite + connection pooling
   - `process.py`: ProcessDatabase — load-process (live/maps/coredump/GDB dump), backtrace decoding, memory analysis, deadlock report
   - `rootfs.py`: RootfsDatabase for binary metadata and fingerprint caching

3. **Architecture Abstraction Layer** (`blackadder/arch/`)
   - `base.py`: Abstract Architecture class with register definitions and normalization
   - `x86.py`: X86Architecture (32-bit) and X86_64Architecture (64-bit) implementations
   - `arm.py`: ARMArchitecture (32-bit) and ARM64Architecture (64-bit) implementations
   - `detector.py`: ELF-based architecture detection and factory functions
   - Supports: x86, x86-64, ARM, ARM64, RISC-V; extensible for PowerPC, MIPS, etc.
   - Used by: FunctionHasher (instruction normalization), MemoryAnalyzer (stack detection)

4. **Binutils Integration** (`blackadder/binutils/`)
   - `parser.py`: BinToolsParser wraps objdump/readelf with async subprocess limiting
   - `resolver.py`: Symbol resolution (addr2line + objdump fallback), backtrace format auto-detection
   - `hasher.py`: FunctionHasher extracts and normalizes assembly for fingerprinting
   - `matcher.py`: BinaryMatcher scores fingerprint similarity
   - `coredump.py`: CoreDumpParser — PT_LOAD segments → memory mappings, PT_NOTE → register state
   - `gdb_dump.py`: GDB text dump parser — threads, frames, registers, lock state (LockStateEntry)

5. **Analysis Engines**
   - `blackadder/memory_analyzer.py`: Classify regions, detect anomalies (RWX, executable heap, oversized)
   - `blackadder/deadlock_analyzer.py`: 3-tier deadlock detection (futex syscall, backtrace symbols, wchan)

6. **CLI** (`blackadder/cli/main.py`)
   - Commands: load, load-process, decode-backtrace, decode-address, analyse-memory, analyse-deadlock, tag, query, schema, version
   - Rich table output and progress bars
   - Configurable concurrency and caching

7. **Configuration** (`blackadder/config.py`)
   - Pydantic Settings: env vars, .env file, auto-detected CPU count
   - Configurable: rootfs/process DB paths, tool paths, semaphore workers, cache sizes

### Phase 2.1 - Binary Matching (Completed)

**Motivation**: Handle binaries that differ in MD5 due to version mismatches, custom builds, or minor edits.

**Implementation**:
- `FunctionHasher`: Extract function boundaries, normalize assembly (remove ASLR-dependent addresses), hash content
- `BinaryMatcher`: Score similarity between fingerprints
- `RootfsDatabase`: Store fingerprints permanently in DB
- `ProcessDatabase.identify_process_binaries_fuzzy()`: Fuzzy-match process binaries to rootfs candidates

**Files**:
- `blackadder/binutils/hasher.py` (217 lines)
- `blackadder/binutils/matcher.py` (126 lines)
- `blackadder/db/rootfs.py` (133 lines)
- `blackadder/models.py`: FunctionFingerprint model + Binary.fingerprints relationship

### Architecture Abstraction Layer (Refactoring)

**Goal**: Extract architecture-specific code (x86/ARM) into modular, extensible layer.

**Design**:
- `Architecture` abstract base class defines interface: registers, normalize_instruction(), classify_stack_region()
- Concrete implementations: X86Architecture, X86_64Architecture, ARMArchitecture, ARM64Architecture
- Factory functions: detect_architecture(binary_path) auto-detects from ELF e_machine
- get_architecture(variant) returns instance by name ("x86_64", "arm64", etc.)

**Integration Points**:
- **FunctionHasher**: Uses architecture-specific register patterns for assembly normalization during fingerprinting
- **MemoryAnalyzer**: Uses architecture-specific registers (RSP/RBP for x86-64, SP/X29 for ARM64) for stack detection

**Supported Architectures**:
- x86 (32-bit, EM_386)
- x86-64 (64-bit, EM_X86_64)
- ARM (32-bit, EM_ARM)
- ARM64 (64-bit, EM_AARCH64)
- RISC-V (RV32I 32-bit, RV64I 64-bit, EM_RISCV)

### Phase 2.2 - Core Dump Parsing (Completed)

**Goal**: Parse ELF core dump files to reconstruct process memory layout offline.

**Implementation**:
- `CoreDumpParser`: Parse core dump headers and program headers via readelf
- `ProcessDatabase.load_core_dump()`: Load core dump as ProcessSnapshot
- `ProcessSnapshot.source_type` and `source_path`: Track data source (maps/coredump/gdb_dump)

**Files**:
- `blackadder/binutils/coredump.py` (258 lines)
- `blackadder/db/process.py`: +load_core_dump() method

**Design**: Uses readelf to extract PT_LOAD segments from core dump, converts to /proc/maps-like format, reuses existing address resolution logic.

### Phase 2.3 - Enhanced Memory Analysis (Completed)

**Goal**: Classify memory regions, detect anomalies, and analyze corruption risks.

**Implementation**:
- `MemoryAnalyzer`: Classify regions, detect anomalies, check corruption markers
- `ProcessRegisterState`: Store CPU registers (architecture-agnostic JSON field)
- `MemoryRegionAnalysis`: Store classification and anomaly analysis per mapping
- `ProcessDatabase.analyze_memory_layout()`: Full memory analysis workflow
- CLI command: `analyse-memory`

**Files**:
- `blackadder/memory_analyzer.py` (227 lines)
- `blackadder/models.py`: +MemoryRegionType enum, +ProcessRegisterState, +MemoryRegionAnalysis

**Design**: Classify heap/stack/vdso/library/JIT regions via heuristics, detect executable heap/RWX/oversized allocations, assess corruption risk.

### Phase A1 - Thread State Capture (Completed)

**Goal**: Capture per-thread state (wchan, syscall, name, stack bounds) from live process or GDB dump.

**Implementation**:
- `Thread` ORM model: tid, name, wchan, syscall, stack_start, stack_end
- `ProcessDatabase.load_live_threads()`: reads `/proc/PID/task/TID/` (wchan, syscall, comm, status)
- `ProcessDatabase.load_gdb_dump()`: populates Thread + BacktraceEntry + ProcessRegisterState from GDB text output
- `BacktraceEntry.thread_id` FK links frames to threads
- `SymbolCache` model: persistent symbol resolution cache across sessions

**Files**:
- `blackadder/models.py`: +Thread, +SymbolCache (also updated ProcessRegisterState to use `registers_json: str`)
- `blackadder/db/process.py`: +load_live_threads(), +load_gdb_dump()
- `blackadder/cli/main.py`: +`--gdb-dump` option on `load-process`

### Phase A3 - GDB Dump Parser (Completed)

**Goal**: Parse GDB text output (`thread apply all bt full` + `info registers`) as offline data source.

**Implementation**:
- `parse_gdb_dump(text) -> GdbDump`: parses multi-thread backtraces and per-thread registers
- `LockStateEntry` dataclass: parsed representation of one blocked thread from `find_deadlock` GDB command
- `parse_lock_state(text) -> list[LockStateEntry]`: parses BALDRICK_LOCK_STATE_BEGIN/END markers + JSON lines
- `parse_gdb_registers_only(text) -> dict[str, int]`: single-thread register parse

**Files**:
- `blackadder/binutils/gdb_dump.py` (290 lines): GdbFrame, GdbThread, GdbDump, LockStateEntry dataclasses + 3 parse functions
- `tests/test_gdb_dump.py`: 49 tests covering all parse functions and edge cases

**Key design**:
- Register blacklist (`_SKIP_REGS`): skip x87/SSE control regs and pseudo-regs; accept everything else
- Thread header regex handles both `LWP 12345 "name"` and older `Thread 0x... (LWP 12345)` formats

### Phase B2 - Deadlock Detection (Completed)

**Goal**: Detect deadlocks from live process data or GDB dump with 3 evidence tiers.

**Implementation**:
- `DeadlockAnalyzer(threads, backtraces, lock_state=None).analyze() -> DeadlockReport`
- Tier 0 (certain): exact mutex ownership from `find_deadlock` GDB command → DFS cycle detection
- Tier 1 (certain): futex syscall with wait address → wait graph → DFS cycle
- Tier 2 (probable): `pthread_mutex_lock`/`__lll_lock_wait` in backtrace
- Tier 3 (possible): wchan in `{futex_wait, futex_wait_queue_me, do_futex, ...}`
- `ProcessDatabase.get_deadlock_report(process_id, lock_state_text=None) -> DeadlockReport`
- CLI command: `analyse-deadlock --snapshot-id N [--lock-state FILE] [--json]`

**Files**:
- `blackadder/deadlock_analyzer.py` (555 lines): DeadlockThread, DeadlockCycle, DeadlockReport + DeadlockAnalyzer
- `blackadder/db/process.py`: +get_deadlock_report()
- `blackadder/cli/main.py`: +analyse-deadlock command
- `blackadder/queries.py`: +deadlock-threads built-in query
- `tests/test_deadlock_analyzer.py` (32 tests)
- `tests/gdb-scripts/_gdb/find_deadlock.py`: GDB command extension (rewritten)

**Key design**:
- `_LOCK_SYMBOLS` frozenset includes glibc internal variants: `__GI___pthread_mutex_lock`, `___pthread_mutex_lock`, `__GI___pthread_rwlock_wrlock/rdlock`, `__libc_do_syscall`
- `_FUTEX_SYSCALL_NRS = {202, 240, 98}` (x86-64, x86, ARM64)
- `_FUTEX_WAIT_OPS = {0, 9, 128, 137}` — thread blocked if op in this set
- Deadlock vs contention: N threads waiting on N unique addresses = deadlock; multiple on same = contention

**`find_deadlock.py` GDB extension**:
- Registered as `find_deadlock` GDB command: run via `gdb -batch -ex "source find_deadlock.py" -ex "find_deadlock" ...`
- Outputs `BALDRICK_LOCK_STATE_BEGIN` / one JSON line per blocked thread / `BALDRICK_LOCK_STATE_END`
- Reads `mutex->__data.__owner` from outermost `___pthread_mutex_lock` frame (not innermost `__lll_lock_wait`)
- Reads `rwlock->__data.__cur_writer` and `__readers` for rwlock

## Key Design Patterns

### 1. Subprocess Pooling (Resource-Aware Concurrency)
```python
subprocess_sem = asyncio.Semaphore(32)  # Max 32 concurrent objdump/addr2line

async with subprocess_sem:
    symbol = await resolve_symbol(binary, offset)
```
**Why**: Prevents spawning 100+ processes that exhausts system resources. Queues them instead.

### 2. Symbol Caching (Deduplication)
```python
cache_key = (binary_path, offset)
if cache_key in symbol_cache:
    return symbol_cache[cache_key]
symbol = await resolve_symbol(binary, offset)
symbol_cache[cache_key] = symbol
```
**Why**: Multiple frames often reference the same binary:offset. One subprocess call, many hits.

### 3. Thread Pool for CPU Work (Non-Blocking)
```python
# Regex parsing runs in thread pool, doesn't block event loop
parsed_maps = await asyncio.to_thread(parse_maps_lines, lines)
```
**Why**: /proc/maps parsing and regex matching are CPU-bound; blocking the event loop would stall I/O.

### 4. Parallel Backtrace Decoding (Batching)
```python
frames = await asyncio.gather(
    *[resolve_frame(pid, addr) for addr in addresses],
    return_exceptions=True  # One failure doesn't cancel all
)
```
**Why**: Decode 100+ frames concurrently (limited by semaphore), achieving 10-15x speedup.

### 5. Assembly Normalization (Version-Independence)
```python
# Normalize: 0x401234 -> 0xADDR, %rax -> %REG_A, $0x1000 -> $IMM
# Result: Same code, different builds = same hash
normalized = normalize_function_body(asm_lines)
content_hash = hashlib.sha256(normalized).hexdigest()
```
**Why**: Fingerprints survive ASLR, minor edits, compiler variations.

### 6. Unified Database (Single SQLite file)
```
blackadder.db    # Binary metadata + process snapshots in one file
```
**Why**: `ProcessBinary` links process snapshots to binaries via FK — cross-file SQLite FKs are not supported. A single DB also simplifies CLI usage (one `--db` global option).

### 7. 3-Tier Evidence Degradation (Deadlock Detection)
```
Tier 0 (certain)  — GDB mutex ownership graph via find_deadlock.py
Tier 1 (certain)  — futex syscall with mutex address (live /proc)
Tier 2 (probable) — pthread_mutex_lock in backtrace (GDB dump or live)
Tier 3 (possible) — wchan=futex_wait (no lock address)
```
**Why**: Deadlock can be detected at various confidence levels depending on available data.

## Development Commands

```bash
# Install dev dependencies (requires pip/venv or uv)
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
python3 -m pytest tests/ -v

# Run specific test class
python3 -m pytest tests/test_deadlock_analyzer.py -v

# Run with coverage
python3 -m pytest tests/ --cov=blackadder --cov-report=html

# Run CLI commands  (--db is a global option, placed before subcommand)
baldrick --db session.db load-process --pid 12345
baldrick --db session.db load-process --gdb-dump gdb_out.txt
baldrick --db session.db analyse-deadlock --snapshot-id 1
baldrick --db session.db analyse-deadlock --snapshot-id 1 --lock-state lock.json
baldrick --db session.db query deadlock-threads --param id=1
baldrick --db session.db schema

# Type checking
mypy blackadder/ --ignore-missing-imports

# Code formatting
black blackadder/ tests/
ruff check blackadder/ tests/
```

## Database Schema

### blackadder.db (Unified — Binary Metadata + Process Analysis)

```sql
-- Binary metadata (static, cached by MD5)
binary (id, md5sum UNIQUE, name, debug_link)
section_header (id, binary_id FK, idx, name, size, vma, lma, off, align)
symbol (id, binary_id FK, address, scope, sym_type, section, size, name)
binary_locator (id, path UNIQUE, md5sum FK, mtime)
function_fingerprint (id, binary_id FK, func_name, func_offset, func_size, content_hash)
symbolcache (id, binary_path, offset, symbol, source_file, source_line)

-- Process snapshots (dynamic, per-session)
processsnapshot (id, pid, created_at, description, source_type, source_path)
thread (id, process_id FK, tid, name, wchan, syscall, stack_start, stack_end)
memorymapping (id, process_id FK, start_addr, end_addr, perms, offset, pathname)
processbinary (id, process_id FK, binary_id FK, mapping_id FK, binary_load_addr, match_score, match_method)
backtrace_entry (id, process_id FK, thread_id FK, frame_num, address, resolved_symbol, resolved_file, resolved_line, match_confidence)
processregisterstate (id, process_id FK, thread_id FK, arch, registers_json)
memoryregionanalysis (id, process_id FK, mapping_id FK, region_type, anomalies_json, is_corruption_indicator)
```

## Built-in Queries (`baldrick query <name>`)

| Name | Parameters | Description |
|------|-----------|-------------|
| snapshots | — | List all process snapshots |
| mappings | id | Memory mappings for a snapshot |
| binaries | — | All indexed binaries |
| symbols | binary | Symbols for a binary |
| sections | binary | Section headers for a binary |
| backtrace | id | Backtrace entries for a snapshot |
| libs | id | Shared libraries for a snapshot |
| rwx | id | RWX memory regions for a snapshot |
| process-binaries | id | ProcessBinary records for a snapshot |
| threads | id | Threads for a snapshot |
| symbol-cache | binary | Symbol cache entries for a binary |
| symbol-cache-stats | — | Symbol cache hit/miss stats |
| deadlock-threads | id | Threads likely blocked on a futex/mutex |

## Important Concurrency Notes

### Don't do this:
```python
# Spawning 100 concurrent addr2line calls = system overload
tasks = [resolve_symbol(binary, offset) for _ in range(100)]
results = await asyncio.gather(*tasks)
```

### Do this:
```python
# Semaphore queues them to max 32 concurrent
subprocess_sem = asyncio.Semaphore(32)

async def limited_resolve(binary, offset):
    async with subprocess_sem:
        return await resolve_symbol(binary, offset)

tasks = [limited_resolve(binary, offset) for _ in range(100)]
results = await asyncio.gather(*tasks)
```

## Backtrace Format Support

Auto-detects and parses:
1. **GDB format**: `#0  0x400a1c in main (...)`
2. **Kernel format**: `[<ffffffff81010001>] function_name+0x42/0x100`
3. **Raw hex**: `0x400a1c` (one per line)

See `blackadder/binutils/resolver.py:parse_backtrace_auto()` for regex patterns.

## Performance Characteristics

| Operation | Data | Time (Sync) | Time (Async) | Speedup |
|-----------|------|-----------|---------|---------|
| Decode 100 frames | 50 binaries | ~2.5s | ~200ms | 12-15x |
| Parse 10k symbols | 1 binary | ~800ms | ~100ms | 8x |
| Backtrace (1000 frames) | 100+ binaries | N/A | ~2-3s | - |

## Memory Region Classification

### Supported Types
- HEAP, STACK: Explicit markers or heuristics
- VDSO, VSYSCALL, VVAR: System regions
- TEXT, DATA: Binary sections
- MMAP: Shared libraries and mmap'd regions
- JIT: Runtime compiled code (RWX anonymous)
- ANON: Anonymous memory
- UNKNOWN: Unclassified

### Anomaly Detection
- **Executable heap**: Code injection marker (heap + x)
- **RWX region**: Unusual permissions (rwx)
- **Oversized region**: > 1GB allocation
- **Writable code**: Writable + executable libraries
- **Large stack**: > 256MB region

### Corruption Indicators
- Executable heap (code injection)
- RWX region (full permissions unusual)
- Writable vdso/vsyscall (should be read-only)

## Future Enhancements

- B3: Stack scanning — cross-thread pointer detection via /proc/PID/mem or GDB memory dump
- Extended register extraction (float, AVX via pyelftools)
- Heap structure analysis (free list corruption detection)
- Stack buffer overflow detection
- ROP gadget detection
- Memory diff (compare two core dumps)
- Live GDB session support (Phase 3)
- Remote service for embedded GDB clients (Phase 3)
- Stripped binary symbol recovery (Phase 3+)

## Testing Strategy

- Unit tests: `tests/test_*.py` with pytest-asyncio
- Async fixtures in `tests/conftest.py` (memory/temp databases, sample data)
- No external dependencies in tests (generates sample binaries programmatically)
- Coverage tracked via pytest-cov

## Important Notes

- All I/O operations are async; **never use blocking subprocess calls**
- Thread pool is for CPU work only (regex, parsing); use asyncio for I/O
- Database queries should use `await session.exec(statement)`, not sync methods
- Always limit subprocess calls with semaphore to prevent resource exhaustion
- Cache symbol lookups aggressively (50%+ hit rate typical)
- `ProcessRegisterState.registers_json` stores a JSON dict of `{reg_name: int_value}` — architecture-agnostic
- `find_deadlock.py` must be sourced in GDB before calling `find_deadlock` command
- ptrace_scope must be 0 for GDB live attach: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
