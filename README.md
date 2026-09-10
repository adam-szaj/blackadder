# Baldrick

Linux binutils wrapper for debug. Backtrace decode, symbol resolution, memory analysis for core dumps, proc traces, prod issues.

## Features (MVP v0.1)

- **Backtrace Decoding**: IPs → func names + source locs
- **Address-to-Symbol Resolution**: addr → func + offset
- **Memory Type Classification**: ID memory regions (heap, stack, text, etc.)
- **Parallel Processing**: 10-15x faster via async/await + subprocess pool
- **Symbol Caching**: No dup symbol resolutions across backtraces
- **Multiple Input Formats**: raw hex, GDB, kernel backtrace formats

## Installation

Requires Python 3.12+ (tested with 3.14).

```bash
# Published package
pip install baldrick-binutils

# Using uv (recommended)
uv pip install -e .
uv pip install -e ".[dev]"  # For development

# Or with pip
pip install -e .
pip install -e ".[dev]"
```

## Quick Start

### Load process memory mappings
```bash
baldrick --db session.db load-process --pid 12345
```

### Decode a backtrace
```bash
baldrick --db session.db decode-backtrace --pid 12345 --trace backtrace.txt
cat backtrace.txt | baldrick --db session.db decode-backtrace --pid 12345
```

### Resolve an address
```bash
baldrick --db session.db decode-address --mapped --pid 12345 -- 0x400a1c
```

## Workflow

### 1. Capture Process State

For running proc:
```bash
# Capture memory mappings
cat /proc/12345/maps > my_process_maps.txt

# Capture backtrace (from GDB, crash logs, etc.)
# Example from GDB:
# (gdb) bt
# #0  0x00007ffff7e1c5c0 in __libc_start_main () from /lib64/libc.so.6
# #1  0x0000555555554a1c in main () at app.c:42
```

### 2. Load Process into Database

```bash
# Load from a live PID (reads /proc/PID/maps automatically)
baldrick --db session.db load-process --pid 12345

# Load from a saved maps file
baldrick --db session.db load-process --maps my_process_maps.txt

# Load from a core dump
baldrick --db session.db load-process --coredump core.dump
```

Creates `ProcessSnapshot` in DB with all memory regions, auto-extracts binary metadata (sections, symbols) for all mapped files.

### 3. Decode Backtraces

```bash
# From file
baldrick --db session.db decode-backtrace --pid 12345 --trace backtrace.txt

# From stdin
cat backtrace.txt | baldrick --db session.db decode-backtrace --pid 12345

# Auto-detects format:
# - Raw hex: 0x400a1c per line
# - GDB format: #0 0x400a1c in function_name ...
# - Kernel format: [<ffffffff81010001>] function+0x42/0x100
```

### 4. Resolve Individual Addresses

```bash
# Mapped mode: address is virtual (from process address space)
baldrick --db session.db decode-address --mapped --pid 12345 -- 0x7ffff7e1c5c0

# Unmapped mode: address is an offset within a binary
baldrick --db session.db decode-address --unmapped --binary /lib/libc.so.6 -- 0x1c5c0

# Show all available info
baldrick --db session.db decode-address --mapped --pid 12345 --full -- 0x7ffff7e1c5c0
```

### 5. Analyze Memory Layout

```bash
# Classify memory regions and detect anomalies (transient, no --db needed)
baldrick analyse-memory --pid 12345

# Or persist results
baldrick --db session.db analyse-memory --pid 12345

# From a core dump
baldrick analyse-memory --coredump core.dump
```

### 6. Preload Binary Metadata

```bash
# Preload all executables from a rootfs before any process analysis
baldrick --db session.db load --rootfs /path/to/rootfs --perm u+x
baldrick --db session.db load --rootfs /path/to/rootfs --glob '**/*.so*'
baldrick --db session.db load --rootfs /path/to/rootfs --maps /proc/12345/maps
```

### Example: End-to-End Debugging Session

```bash
# 1. Process crashes, get core dump
$ gdb /usr/bin/myapp core.dump
(gdb) bt
#0  0x00007ffff7e1c5c0 in __libc_start_main () from /lib64/libc.so.6
#1  0x0000555555554a1c in main () at app.c:42
(gdb) quit

# 2. Load core dump
$ baldrick --db debug.db load-process --coredump core.dump

# 3. Decode backtrace
$ cat << 'EOF' | baldrick --db debug.db decode-backtrace --pid 1
0x7ffff7e1c5c0
0x555555554a1c
EOF

# Output:
# #0  0x00007ffff7e1c5c0 in __libc_start_main () from /lib64/libc.so.6
# #1  0x0000555555554a1c in main () from /usr/bin/myapp

# 4. Investigate a specific address
$ baldrick --db debug.db syms --mapped --pid 1 -- 0x555555554a1c

# 5. Check for memory issues
$ baldrick --db debug.db analyse-memory --pid 1
```

### Database Structure

Single `baldrick.db` (or `--db` target) holds all data:

**Binary metadata** (static, cached by MD5 — reusable across procs):
- `binary`: ELF files + MD5 checksums
- `symbol`: func names + addresses
- `section_header`: code/data/debug sections
- `function_fingerprint`: asm hashes for version matching

**Process snapshots** (dynamic, one per `load-process`):
- `processsnapshot`: proc metadata
- `memorymapping`: vaddr ranges, perms, binary paths
- `processbinary`: links snapshots → binaries w/ match score
- `backtrace_entry`: decoded frames w/ symbols + source locs

### Performance Tips

```bash
# Parallel decoding: 100 frames → 200ms (vs 2.5s sequential)
baldrick --db session.db decode-backtrace --pid 12345 --trace huge_backtrace.txt

# Symbol caching: Repeated frames reuse cached lookups
# First 100 frames: ~800ms
# Next 100 frames: ~50ms (mostly cache hits)

# Configure concurrency
export MAX_SUBPROCESS_WORKERS=64  # Increase for many-core systems
baldrick --db session.db decode-backtrace --pid 12345
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Address not found in process memory" | Load mappings first with `load-process` |
| "Symbol not resolved (???)" | Binary may be stripped; use debug symbols if available |
| Slow decoding | Increase `MAX_SUBPROCESS_WORKERS` if system has capacity |

## Architecture

```
baldrick (CLI entry point)
  ↓
baldrick package
  ├─ config.py (Pydantic Settings)
  ├─ models.py (SQLModel ORM)
  ├─ cli/main.py (Typer CLI)
  ├─ db/
  │   ├─ base.py (AsyncDatabaseManager)
  │   ├─ rootfs.py (RootfsDatabase)
  │   └─ process.py (ProcessDatabase)
  └─ binutils/
      ├─ parser.py (async subprocess)
      └─ resolver.py (address → symbol)

Database
  └─ baldrick.db (unified: binary metadata + process snapshots)
```

### Modern Stack

- **Python 3.12+**: latest async/await, structural pattern matching
- **SQLModel**: unified ORM + Pydantic validation
- **asyncio**: non-blocking I/O for subprocess + DB queries
- **Typer**: modern async-friendly CLI
- **Pydantic Settings**: type-safe config w/ env var support
- **uv**: fast deterministic pkg mgmt

## Development

### Run tests
```bash
# All tests
uv run pytest

# With coverage
uv run pytest --cov=baldrick

# Specific test
uv run pytest tests/test_parser.py -v
```

### Code quality
```bash
uv run black baldrick tests  # Code formatting
uv run ruff check baldrick tests  # Linting
uv run mypy baldrick  # Type checking
```

## Performance Characteristics

| Operation | Throughput |
|-----------|-----------|
| Decode 100-frame backtrace | ~200ms (vs 2.5s sequential) |
| Parse 10,000 symbols | ~100ms (vs 800ms sequential) |
| Load 10 processes | ~500ms (vs 5s sequential) |

**With semaphore limiting** (default: 32 concurrent procs):
- Prevent resource exhaustion on many-core systems
- Configurable via `BaldrickConfig.max_subprocess_workers`

**With symbol caching**:
- Typical cache hit rate >50% for repeated frames
- Configurable size: default 100,000 symbols

## Configuration

Create `.env` in project root:

```bash
DB=sqlite+aiosqlite:///baldrick.db
MAX_SUBPROCESS_WORKERS=32
MAX_SYMBOL_CACHE_SIZE=100000
```

Or env vars:
```bash
export DB=/tmp/analysis.db
baldrick load-process --pid 12345
```

Or per-session via global `--db` flag:
```bash
baldrick --db /tmp/analysis.db load-process --pid 12345
```

## Project Status

### Implemented
- ✅ Backtrace decoding (raw hex, GDB, kernel formats)
- ✅ Address-to-binary mapping via /proc/maps
- ✅ Async subprocess execution w/ resource limits
- ✅ Symbol resolution via addr2line + objdump
- ✅ Async DB access (SQLModel + aiosqlite)
- ✅ Parallel frame decoding
- ✅ Symbol caching + LRU eviction
- ✅ Typer CLI w/ async commands + global `--db`
- ✅ Binary metadata auto-loaded on `load-process`
- ✅ Core dump parsing (`load-process --coredump`)
- ✅ Memory region classification + anomaly detection (`analyse-memory`)
- ✅ Arch abstraction layer (x86, x86-64, ARM, ARM64, RISC-V)
- ✅ Binary fingerprinting for version-mismatch matching
- ✅ Comprehensive pytest test suite

### Planned (Phase 3+)
- Live GDB session support
- Baldrick remote service (for embedded GDB)
- Stripped binary symbol recovery
- Heap structure analysis (free list corruption detection)
- Stack buffer overflow detection
- ROP gadget detection
- Memory diff (compare two core dumps)

## Contributing

See [CLAUDE.md](CLAUDE.md) for architecture details and dev notes.

## License

MIT
