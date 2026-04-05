# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Blackadder** is a production-ready Linux debugging engine written in modern Python 3.12+ (asyncio, SQLModel, Pydantic, Typer). It provides:
- High-speed backtrace decoding via parallel address resolution
- Binary metadata extraction (sections, symbols, debug info) using `objdump`/`readelf`
- Process memory analysis from `/proc/PID/maps`
- Binary matching for version mismatches via assembly fingerprints (Phase 2.1)
- Core dump parsing (Phase 2.2 - planned)

## Architecture

### MVP (v0.1.0) - Completed

**Modern Stack**:
- Python 3.12+ with asyncio for all I/O
- SQLModel ORM (combines SQLAlchemy + Pydantic validation)
- Dual SQLite databases: `rootfs.db` (static), `process.db` (dynamic)
- Typer CLI framework with async commands
- Subprocess pooling via asyncio.Semaphore (max 32 concurrent)
- LRU symbol cache (100k entries) to avoid duplicate subprocess calls

**Core Modules**:

1. **ORM Models** (`blackadder/models.py` - 212 lines)
   - **Rootfs DB**: Binary, SectionHeader, Symbol, BinaryLocator, FunctionFingerprint
   - **Process DB**: ProcessSnapshot, MemoryMapping, ProcessBinary, BacktraceEntry
   - Pydantic models: BacktraceRequest, ResolvedFrame (with validators)

2. **Async Database Layer** (`blackadder/db/`)
   - `base.py`: AsyncDatabaseManager wraps aiosqlite + connection pooling
   - `process.py`: ProcessDatabase for backtrace decoding, /proc/maps loading, address resolution
   - `rootfs.py`: RootfsDatabase for binary metadata and fingerprint caching (Phase 2.1)

3. **Binutils Integration** (`blackadder/binutils/`)
   - `parser.py`: BinToolsParser wraps objdump/readelf with async subprocess limiting
   - `resolver.py`: Symbol resolution (addr2line + objdump fallback), backtrace format auto-detection
   - `hasher.py`: FunctionHasher extracts and normalizes assembly for fingerprinting (Phase 2.1)
   - `matcher.py`: BinaryMatcher scores fingerprint similarity (Phase 2.1)

4. **CLI** (`blackadder/cli/main.py` - 305 lines)
   - Typer async commands: load-process, decode-backtrace, syms, version
   - Rich table output and progress bars
   - Configurable concurrency and caching

5. **Configuration** (`blackadder/config.py`)
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
- `tests/test_hasher.py` (286 lines)
- `tests/test_matcher.py` (273 lines)
- `PHASE_2_1_STATUS.md` (comprehensive implementation details)

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

### 6. Dual Databases (Separation of Concerns)
```
rootfs.db        # Static binary metadata (sections, symbols, fingerprints)
process.db       # Dynamic process state (snapshots, mappings, analysis)
```
**Why**: rootfs can be pre-built and cached; process is ephemeral or per-analysis.

## Development Commands

```bash
# Install dev dependencies (requires pip/venv or uv)
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
python3 -m pytest tests/ -v

# Run specific test class
python3 -m pytest tests/test_models.py::TestResolvedFrame -v

# Run with coverage
python3 -m pytest tests/ --cov=blackadder --cov-report=html

# Run CLI commands
python3 -m blackadder.cli.main load-process --maps /proc/12345/maps --pid 12345
python3 -m blackadder.cli.main decode-backtrace --pid 12345 < backtrace.txt
python3 -m blackadder.cli.main syms --pid 12345 --address 0x400a1c

# Or use entry point (after install)
baldrick load-process --maps /proc/12345/maps --pid 12345

# Type checking
mypy blackadder/ --ignore-missing-imports

# Code formatting
black blackadder/ tests/
ruff check blackadder/ tests/
```

## Database Schemas

### rootfs.db (Binary Metadata)

```sql
binary (id, md5sum UNIQUE, name, debug_link)
section_header (id, binary_id FK, idx, name, size, vma, lma, off, align)
symbol (id, binary_id FK, address, scope, sym_type, section, size, name)
binary_locator (id, path UNIQUE, md5sum FK, mtime)
function_fingerprint (id, binary_id FK, func_name, func_offset, func_size, content_hash)
```

### process.db (Process Analysis)

```sql
processsnapshot (id, pid, created_at, description)
memorymapping (id, process_id FK, start_addr, end_addr, perms, offset, pathname)
processbinary (id, process_id FK, binary_id FK, mapping_id FK, binary_load_addr, match_score, match_method)
backtrace_entry (id, process_id FK, frame_num, address, resolved_symbol, resolved_file, resolved_line, match_confidence)
```

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

### Phase 2.2 - Core Dump Parsing (Completed)

**Goal**: Parse ELF core dump files to reconstruct process memory layout offline.

**Implementation**:
- `CoreDumpParser`: Parse core dump headers and program headers via readelf
- `ProcessDatabase.load_core_dump()`: Load core dump as ProcessSnapshot
- `ProcessSnapshot.source_type` and `source_path`: Track data source (maps vs core dump)
- CLI command: `load-core-dump`

**Files**:
- `blackadder/binutils/coredump.py` (258 lines)
- `blackadder/db/process.py`: +load_core_dump() method (40 lines)
- `blackadder/models.py`: +source_type, +source_path fields
- `blackadder/cli/main.py`: +load-core-dump command (70 lines)
- `tests/test_coredump.py` (350 lines)
- `PHASE_2_2_STATUS.md` (comprehensive implementation details)

**Design**: Uses readelf to extract PT_LOAD segments from core dump, converts to /proc/maps-like format, reuses existing address resolution logic.

### Phase 2.3 - Enhanced Memory Analysis (Completed)

**Goal**: Classify memory regions, detect anomalies, and analyze corruption risks.

**Implementation**:
- `MemoryAnalyzer`: Classify regions, detect anomalies, check corruption markers
- `ProcessRegisterState`: Store CPU registers from core dump PT_NOTE
- `MemoryRegionAnalysis`: Store classification and anomaly analysis per mapping
- `ProcessDatabase.analyze_memory_layout()`: Full memory analysis workflow
- CLI commands: `analyze-memory`

**Files**:
- `blackadder/memory_analyzer.py` (227 lines)
- `blackadder/models.py`: +MemoryRegionType enum, +ProcessRegisterState, +MemoryRegionAnalysis
- `blackadder/binutils/coredump.py`: +extract_register_state() method
- `blackadder/db/process.py`: +analyze_memory_layout() method
- `blackadder/cli/main.py`: +analyze-memory command (50 lines)
- `tests/test_memory_analyzer.py` (334 lines, 20 tests)
- `PHASE_2_3_STATUS.md` (comprehensive implementation details)

**Design**: Classify heap/stack/vdso/library/JIT regions via heuristics, detect executable heap/RWX/oversized allocations, assess corruption risk.

## Memory Region Classification (Phase 2.3)

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

- Extended register extraction (float, AVX via pyelftools)
- Heap structure analysis (free list corruption detection)
- Stack buffer overflow detection
- ROP gadget detection
- Memory diff (compare two core dumps)
- Memory layout visualization
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
- FunctionFingerprint.func_offset and func_size are stored but not yet computed by hasher
