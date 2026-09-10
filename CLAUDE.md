# CLAUDE.md

Guidance for Claude Code (claude.ai/code) in this repo.

## Project Overview

**Baldrick** = prod-ready Linux debug engine, Python 3.12+ (asyncio, SQLModel, Pydantic, Typer):
- Fast backtrace decode via parallel addr resolution
- Binary metadata extract (sections, symbols, debug info) via `objdump`/`readelf`
- Process memory analysis from `/proc/PID/maps`
- Binary matching for version mismatches via asm fingerprints
- Core dump parsing (ELF PT_LOAD + PT_NOTE)
- Thread state capture from live proc or GDB dump
- Deadlock detect (3-tier evidence: certain/probable/possible)
- GDB ext (`find_deadlock`) for exact mutex ownership graphs

## Architecture

### MVP (v0.1.0) - Completed

**Modern Stack**:
- Python 3.12+ asyncio all I/O
- SQLModel ORM (SQLAlchemy + Pydantic)
- Single unified SQLite DB (binary metadata + proc snapshots)
- Typer CLI, async commands
- Subprocess pool via asyncio.Semaphore (max 32)
- LRU symbol cache (100k entries)

**Core Modules**:

1. **ORM Models** (`baldrick/models.py`)
   - **Rootfs DB**: Binary, SectionHeader, Symbol, BinaryLocator, FunctionFingerprint, SymbolCache
   - **Process DB**: ProcessSnapshot, Thread, MemoryMapping, ProcessBinary, BacktraceEntry, ProcessRegisterState, MemoryRegionAnalysis
   - Pydantic: BacktraceRequest, ResolvedFrame (with validators)

2. **Async Database Layer** (`baldrick/db/`)
   - `base.py`: AsyncDatabaseManager wraps aiosqlite + connection pool
   - `process.py`: ProcessDatabase — load-process (live/maps/coredump/GDB dump), backtrace decode, memory analysis, deadlock report
   - `rootfs.py`: RootfsDatabase — binary metadata + fingerprint cache

3. **Architecture Abstraction Layer** (`baldrick/arch/`)
   - `base.py`: Abstract Architecture class, register defs, normalization
   - `x86.py`: X86Architecture (32-bit) + X86_64Architecture (64-bit)
   - `arm.py`: ARMArchitecture (32-bit) + ARM64Architecture (64-bit)
   - `detector.py`: ELF-based arch detect + factory funcs
   - Supports: x86, x86-64, ARM, ARM64, RISC-V; extensible for PowerPC, MIPS
   - Used by: FunctionHasher (instr normalization), MemoryAnalyzer (stack detect)

4. **Binutils Integration** (`baldrick/binutils/`)
   - `parser.py`: BinToolsParser wraps objdump/readelf, async subprocess limit
   - `resolver.py`: Symbol resolve (addr2line + objdump fallback), backtrace format auto-detect
   - `hasher.py`: FunctionHasher extract+normalize asm for fingerprinting
   - `matcher.py`: BinaryMatcher scores fingerprint similarity
   - `coredump.py`: CoreDumpParser — PT_LOAD → mem mappings, PT_NOTE → reg state
   - `gdb_dump.py`: GDB text dump parser — threads, frames, regs, lock state (LockStateEntry)

5. **Analysis Engines**
   - `baldrick/memory_analyzer.py`: Classify regions, detect anomalies (RWX, exec heap, oversized)
   - `baldrick/deadlock_analyzer.py`: 3-tier deadlock detect (futex syscall, backtrace symbols, wchan)

6. **CLI** (`baldrick/cli/main.py`)
   - Commands: load, load-process, decode-backtrace, decode-address, analyse-memory, analyse-deadlock, tag, query, schema, version
   - Rich table output + progress bars
   - Configurable concurrency + caching

7. **Configuration** (`baldrick/config.py`)
   - Pydantic Settings: env vars, .env file, auto CPU count
   - Configurable: rootfs/process DB paths, tool paths, semaphore workers, cache sizes

### Phase 2.1 - Binary Matching (Completed)

**Motivation**: Handle binaries differing in MD5 (version mismatch, custom builds, minor edits).

**Implementation**:
- `FunctionHasher`: Extract func boundaries, normalize asm (strip ASLR addrs), hash content
- `BinaryMatcher`: Score similarity between fingerprints
- `RootfsDatabase`: Store fingerprints in DB
- `ProcessDatabase.identify_process_binaries_fuzzy()`: Fuzzy-match proc binaries → rootfs candidates

**Files**:
- `baldrick/binutils/hasher.py` (217 lines)
- `baldrick/binutils/matcher.py` (126 lines)
- `baldrick/db/rootfs.py` (133 lines)
- `baldrick/models.py`: FunctionFingerprint model + Binary.fingerprints relationship

### Architecture Abstraction Layer (Refactoring)

**Goal**: Extract arch-specific code (x86/ARM) into modular, extensible layer.

**Design**:
- `Architecture` abstract base: registers, normalize_instruction(), classify_stack_region()
- Impls: X86Architecture, X86_64Architecture, ARMArchitecture, ARM64Architecture
- Factory: detect_architecture(binary_path) auto-detects from ELF e_machine
- get_architecture(variant) returns instance by name ("x86_64", "arm64", etc.)

**Integration Points**:
- **FunctionHasher**: arch-specific reg patterns for asm normalization in fingerprinting
- **MemoryAnalyzer**: arch-specific regs (RSP/RBP x86-64, SP/X29 ARM64) for stack detect

**Supported Architectures**:
- x86 (32-bit, EM_386)
- x86-64 (64-bit, EM_X86_64)
- ARM (32-bit, EM_ARM)
- ARM64 (64-bit, EM_AARCH64)
- RISC-V (RV32I 32-bit, RV64I 64-bit, EM_RISCV)

### Phase 2.2 - Core Dump Parsing (Completed)

**Goal**: Parse ELF core dumps to reconstruct process memory layout offline.

**Implementation**:
- `CoreDumpParser`: Parse core dump headers + program headers via readelf
- `ProcessDatabase.load_core_dump()`: Load core dump as ProcessSnapshot
- `ProcessSnapshot.source_type` + `source_path`: Track data source (maps/coredump/gdb_dump)

**Files**:
- `baldrick/binutils/coredump.py` (258 lines)
- `baldrick/db/process.py`: +load_core_dump()

**Design**: readelf extracts PT_LOAD segments, converts to /proc/maps-like format, reuses existing addr resolution.

### Phase 2.3 - Enhanced Memory Analysis (Completed)

**Goal**: Classify memory regions, detect anomalies, analyze corruption risks.

**Implementation**:
- `MemoryAnalyzer`: Classify regions, detect anomalies, check corruption markers
- `ProcessRegisterState`: Store CPU regs (arch-agnostic JSON)
- `MemoryRegionAnalysis`: Store classification + anomaly analysis per mapping
- `ProcessDatabase.analyze_memory_layout()`: Full memory analysis workflow
- CLI: `analyse-memory`

**Files**:
- `baldrick/memory_analyzer.py` (227 lines)
- `baldrick/models.py`: +MemoryRegionType enum, +ProcessRegisterState, +MemoryRegionAnalysis

**Design**: Classify heap/stack/vdso/lib/JIT via heuristics, detect exec heap/RWX/oversized, assess corruption risk.

### Phase A1 - Thread State Capture (Completed)

**Goal**: Capture per-thread state (wchan, syscall, name, stack bounds) from live proc or GDB dump.

**Implementation**:
- `Thread` ORM: tid, name, wchan, syscall, stack_start, stack_end
- `ProcessDatabase.load_live_threads()`: reads `/proc/PID/task/TID/` (wchan, syscall, comm, status)
- `ProcessDatabase.load_gdb_dump()`: populates Thread + BacktraceEntry + ProcessRegisterState from GDB text
- `BacktraceEntry.thread_id` FK links frames to threads
- `SymbolCache`: persistent symbol resolution cache across sessions

**Files**:
- `baldrick/models.py`: +Thread, +SymbolCache (ProcessRegisterState uses `registers_json: str`)
- `baldrick/db/process.py`: +load_live_threads(), +load_gdb_dump()
- `baldrick/cli/main.py`: +`--gdb-dump` on `load-process`

### Phase A3 - GDB Dump Parser (Completed)

**Goal**: Parse GDB text output (`thread apply all bt full` + `info registers`) as offline source.

**Implementation**:
- `parse_gdb_dump(text) -> GdbDump`: parses multi-thread backtraces + per-thread regs
- `LockStateEntry` dataclass: one blocked thread from `find_deadlock` GDB command
- `parse_lock_state(text) -> list[LockStateEntry]`: parses BALDRICK_LOCK_STATE_BEGIN/END + JSON lines
- `parse_gdb_registers_only(text) -> dict[str, int]`: single-thread reg parse

**Files**:
- `baldrick/binutils/gdb_dump.py` (290 lines): GdbFrame, GdbThread, GdbDump, LockStateEntry + 3 parse funcs
- `tests/test_gdb_dump.py`: 49 tests

**Key design**:
- Register blacklist (`_SKIP_REGS`): skip x87/SSE control regs + pseudo-regs; accept rest
- Thread header regex handles `LWP 12345 "name"` and older `Thread 0x... (LWP 12345)`

### Phase B2 - Deadlock Detection (Completed)

**Goal**: Detect deadlocks from live proc or GDB dump with 3 evidence tiers.

**Implementation**:
- `DeadlockAnalyzer(threads, backtraces, lock_state=None).analyze() -> DeadlockReport`
- Tier 0 (certain): exact mutex ownership from `find_deadlock` → DFS cycle detect
- Tier 1 (certain): futex syscall + wait addr → wait graph → DFS cycle
- Tier 2 (probable): `pthread_mutex_lock`/`__lll_lock_wait` in backtrace
- Tier 3 (possible): wchan in `{futex_wait, futex_wait_queue_me, do_futex, ...}`
- `ProcessDatabase.get_deadlock_report(process_id, lock_state_text=None) -> DeadlockReport`
- CLI: `analyse-deadlock --snapshot-id N [--lock-state FILE] [--json]`

**Files**:
- `baldrick/deadlock_analyzer.py` (555 lines): DeadlockThread, DeadlockCycle, DeadlockReport + DeadlockAnalyzer
- `baldrick/db/process.py`: +get_deadlock_report()
- `baldrick/cli/main.py`: +analyse-deadlock command
- `baldrick/queries.py`: +deadlock-threads built-in query
- `tests/test_deadlock_analyzer.py` (32 tests)
- `baldrick-gdb` package: installed GDB commands, including `find_deadlock`

**Key design**:
- `_LOCK_SYMBOLS` frozenset: `__GI___pthread_mutex_lock`, `___pthread_mutex_lock`, `__GI___pthread_rwlock_wrlock/rdlock`, `__libc_do_syscall`
- `_FUTEX_SYSCALL_NRS = {202, 240, 98}` (x86-64, x86, ARM64)
- `_FUTEX_WAIT_OPS = {0, 9, 128, 137}` — blocked if op in set
- N threads waiting on N unique addrs = deadlock; multiple on same = contention

**`find_deadlock.py` GDB extension**:
- Registered as `find_deadlock` GDB command: `gdb -batch -ex "source $(baldrick gdb-path)" -ex "find_deadlock" ...`
- Outputs `BALDRICK_LOCK_STATE_BEGIN` / one JSON line per blocked thread / `BALDRICK_LOCK_STATE_END`
- Reads `mutex->__data.__owner` from outermost `___pthread_mutex_lock` frame (not innermost `__lll_lock_wait`)
- Reads `rwlock->__data.__cur_writer` + `__readers` for rwlock

## Key Design Patterns

### 1. Subprocess Pooling (Resource-Aware Concurrency)
```python
subprocess_sem = asyncio.Semaphore(32)  # Max 32 concurrent objdump/addr2line

async with subprocess_sem:
    symbol = await resolve_symbol(binary, offset)
```
**Why**: Prevents 100+ proc spawn exhausting resources. Queues instead.

### 2. Symbol Caching (Deduplication)
```python
cache_key = (binary_path, offset)
if cache_key in symbol_cache:
    return symbol_cache[cache_key]
symbol = await resolve_symbol(binary, offset)
symbol_cache[cache_key] = symbol
```
**Why**: Many frames hit same binary:offset. One subprocess call, many hits.

### 3. Thread Pool for CPU Work (Non-Blocking)
```python
# Regex parsing runs in thread pool, doesn't block event loop
parsed_maps = await asyncio.to_thread(parse_maps_lines, lines)
```
**Why**: /proc/maps parsing + regex = CPU-bound; blocking event loop stalls I/O.

### 4. Parallel Backtrace Decoding (Batching)
```python
frames = await asyncio.gather(
    *[resolve_frame(pid, addr) for addr in addresses],
    return_exceptions=True  # One failure doesn't cancel all
)
```
**Why**: 100+ frames concurrent (semaphore-limited) = 10-15x speedup.

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
baldrick.db    # Binary metadata + process snapshots in one file
```
**Why**: `ProcessBinary` links snapshots to binaries via FK — cross-file SQLite FKs unsupported. Single DB simplifies CLI (one `--db` option).

### 7. 3-Tier Evidence Degradation (Deadlock Detection)
```
Tier 0 (certain)  — GDB mutex ownership graph via find_deadlock.py
Tier 1 (certain)  — futex syscall with mutex address (live /proc)
Tier 2 (probable) — pthread_mutex_lock in backtrace (GDB dump or live)
Tier 3 (possible) — wchan=futex_wait (no lock address)
```
**Why**: Deadlock detectable at varying confidence depending on available data.

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
python3 -m pytest tests/ --cov=baldrick --cov-report=html

# Run CLI commands  (--db is a global option, placed before subcommand)
baldrick --db session.db load-process --pid 12345
baldrick --db session.db load-process --gdb-dump gdb_out.txt
baldrick --db session.db analyse-deadlock --snapshot-id 1
baldrick --db session.db analyse-deadlock --snapshot-id 1 --lock-state lock.json
baldrick --db session.db query deadlock-threads --param id=1
baldrick --db session.db schema

# Type checking
mypy baldrick/ --ignore-missing-imports

# Code formatting
black baldrick/ tests/
ruff check baldrick/ tests/
```

## Database Schema

Full ERD: `docs/schema.dot` (render: `dot -Tsvg docs/schema.dot -o docs/schema.svg`)

### baldrick.db (Unified — Binary Metadata + Process Analysis)

```sql
-- Binary metadata (static, cached by MD5)
binary              (id, md5sum UNIQUE, name, debug_link)
binarylocator       (id, path UNIQUE, md5sum FK→binary, mtime, debug_file)
sectionheader       (id, binary_id FK, idx, name, size, vma, lma, off, align)
symbol              (id, binary_id FK, address, scope, sym_type, section, size, name)
functionfingerprint (id, binary_id FK, func_name, func_offset, func_size, content_hash)
symbolcache         (id, binary_id FK, offset, symbol, source_file, source_line)

-- DWARF types (canonical global dictionary — deduplicated across all binaries)
canonical_dwarf_type (id, tag, name, byte_size, encoding)   -- ~41k rows for full system
binary_dwarf_ref     (id, binary_id FK, die_offset, canonical_id FK, type_ref_die)  -- per-binary mapping
dwarfmember          (id, canonical_type_id FK, name, byte_offset, member_type_ref)

-- Debug line info (source location ↔ address)
sourcefile          (id, path UNIQUE)                        -- normalized path catalog
debugline           (id, binary_id FK, source_file_id FK, line_number, address)

-- Process snapshots (dynamic, per-session)
processsnapshot      (id, pid, tag, created_at, description, source_type, source_path)
thread               (id, process_id FK, tid, name, wchan, syscall, stack_start, stack_end)
memorymapping        (id, process_id FK, start_addr, end_addr, perms, offset, dev, inode, pathname)
processbinary        (id, process_id FK, binary_id FK, mapping_id FK, binary_load_addr, match_score, match_method)
backtraceentry       (id, process_id FK, thread_id FK, frame_num, address, resolved_symbol, resolved_file, resolved_line, match_confidence)
processregisterstate (id, process_id FK, thread_id FK, arch, registers_json)
memoryregionanalysis (id, process_id FK, mapping_id FK, region_type, anomalies_json, is_corruption_indicator)
```

**DWARF dedup**: `canonical_dwarf_type` stores each unique type (tag, name, byte_size, encoding) once globally. `binary_dwarf_ref` maps per-binary `die_offset` → `canonical_id`, preserving `type_ref_die` for typedef/pointer chain resolution. Reduces ~12.8M rows → ~41k canonical + 12.8M lightweight refs.

## Built-in Queries (`baldrick query <name>`)

Full docs + example output: `docs/queries.md`

| Name | Parameters | Command | Description |
|------|-----------|---------|-------------|
| snapshots | — | load-process | List all process snapshots |
| mappings | id | load-process | Memory mappings for a snapshot |
| binaries | — | load | All indexed binaries |
| symbols | binary | load | Symbols for a binary |
| sections | binary | load | Section headers for a binary |
| backtrace | id | load-process | Backtrace entries for a snapshot |
| libs | id | load-process | Shared libraries for a snapshot |
| rwx | id | load-process | RWX memory regions for a snapshot |
| process-binaries | id | load-process | ProcessBinary records for a snapshot |
| threads | id | load-process | Threads for a snapshot |
| symbol-cache | binary | load | Symbol cache entries for a binary |
| symbol-cache-stats | — | load | Symbol cache hit counts per binary |
| deadlock-threads | id | analyse-deadlock | Threads likely blocked on a futex/mutex |
| types | binary | load --types | Structs/unions in a binary |
| struct | name, binary | load --types | Fields of a named struct with byte offsets |
| type-offset | name, offset, binary | load --types | Field at a given byte offset in a struct |
| line2addr | binary, file, line | load --lines | Source file:line → binary addresses |
| addr2line | binary, addr | load-process | Binary offset → symbol + source location (symbol cache) |
| addr2line-snap | id, addr | load-process | Virtual address → symbol + source via snapshot mapping |

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

Auto-detects:
1. **GDB format**: `#0  0x400a1c in main (...)`
2. **Kernel format**: `[<ffffffff81010001>] function_name+0x42/0x100`
3. **Raw hex**: `0x400a1c` (one per line)

See `baldrick/binutils/resolver.py:parse_backtrace_auto()` for regex patterns.

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
- MMAP: Shared libs + mmap'd regions
- JIT: Runtime compiled code (RWX anonymous)
- ANON: Anonymous memory
- UNKNOWN: Unclassified

### Anomaly Detection
- **Executable heap**: Code injection marker (heap + x)
- **RWX region**: Unusual perms (rwx)
- **Oversized region**: > 1GB alloc
- **Writable code**: Writable + exec libs
- **Large stack**: > 256MB region

### Corruption Indicators
- Executable heap (code injection)
- RWX region (full perms unusual)
- Writable vdso/vsyscall (should be read-only)

## Future Enhancements

- B3: Stack scanning — cross-thread ptr detect via /proc/PID/mem or GDB mem dump
- Extended reg extract (float, AVX via pyelftools)
- Heap structure analysis (free list corruption detect)
- Stack buffer overflow detect
- ROP gadget detect
- Memory diff (compare two core dumps)
- Live GDB session support (Phase 3)
- Remote service for embedded GDB clients (Phase 3)
- Stripped binary symbol recovery (Phase 3+)

## Testing Strategy

- Unit tests: `tests/test_*.py` with pytest-asyncio
- Async fixtures in `tests/conftest.py` (memory/temp DBs, sample data)
- No external deps in tests (generates sample binaries programmatically)
- Coverage via pytest-cov

## Important Notes

- All I/O async; **never use blocking subprocess calls**
- Thread pool for CPU work only (regex, parsing); asyncio for I/O
- DB queries: `await session.exec(statement)`, not sync methods
- Always semaphore-limit subprocess calls
- Cache symbol lookups aggressively (50%+ hit rate typical)
- `ProcessRegisterState.registers_json` = JSON dict `{reg_name: int_value}` — arch-agnostic
- The installed plugin must be sourced in GDB before calling `find_deadlock`
- ptrace_scope must be 0 for GDB live attach: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
