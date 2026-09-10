# Baldrick

High-level Linux binutils wrapper for debugging. Provides backtrace decoding, symbol resolution, and memory analysis for debugging core dumps, process traces, and production issues.

## Features (MVP v0.1)

- **Backtrace Decoding**: Convert instruction pointers to function names and source locations
- **Address-to-Symbol Resolution**: Map any address to its function and offset
- **Memory Type Classification**: Identify memory regions (heap, stack, text, etc.)
- **Parallel Processing**: 10-15x faster than sequential via async/await and subprocess pooling
- **Symbol Caching**: Avoid duplicate symbol resolutions across backtraces
- **Multiple Input Formats**: Support raw hex, GDB, and kernel backtrace formats

## Installation

Requires Python 3.12+ (tested with 3.14).

```bash
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

For a running process:
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

This creates a `ProcessSnapshot` in the database with all memory regions and
automatically extracts binary metadata (sections, symbols) for all mapped files.

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

A single `baldrick.db` (or whatever `--db` points to) holds all data:

**Binary metadata** (static, cached by MD5 — reusable across processes):
- `binary`: ELF files with MD5 checksums
- `symbol`: Function names and addresses
- `section_header`: Code/data/debug sections
- `function_fingerprint`: Assembly hashes for version matching

**Process snapshots** (dynamic, one per `load-process` invocation):
- `processsnapshot`: Process metadata
- `memorymapping`: Virtual address ranges, permissions, binary paths
- `processbinary`: Links snapshots to binaries with match score
- `backtrace_entry`: Decoded frames with symbols and source locations

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

- **Python 3.12+**: Latest async/await, structural pattern matching
- **SQLModel**: Unified ORM + Pydantic validation
- **asyncio**: Non-blocking I/O for subprocess calls and database queries
- **Typer**: Modern async-friendly CLI framework
- **Pydantic Settings**: Type-safe configuration with env variable support
- **uv**: Fast deterministic package management

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

**With semaphore limiting** (default: 32 concurrent processes):
- Prevent resource exhaustion on systems with many cores
- Configurable via `BaldrickConfig.max_subprocess_workers`

**With symbol caching**:
- Typical cache hit rate >50% for repeated frames
- Configurable size: default 100,000 symbols

## Configuration

Create `.env` file in project root:

```bash
DB=sqlite+aiosqlite:///baldrick.db
MAX_SUBPROCESS_WORKERS=32
MAX_SYMBOL_CACHE_SIZE=100000
```

Or use environment variables:
```bash
export DB=/tmp/analysis.db
baldrick load-process --pid 12345
```

Or pass per-session via the global `--db` flag:
```bash
baldrick --db /tmp/analysis.db load-process --pid 12345
```

## Project Status

### Implemented
- ✅ Backtrace decoding (raw hex, GDB, kernel formats)
- ✅ Address-to-binary mapping via /proc/maps
- ✅ Async subprocess execution with resource limits
- ✅ Symbol resolution via addr2line + objdump
- ✅ Async database access (SQLModel + aiosqlite)
- ✅ Parallel frame decoding
- ✅ Symbol caching and LRU eviction
- ✅ Typer CLI with async commands and global `--db` option
- ✅ Binary metadata auto-loaded on `load-process`
- ✅ Core dump parsing (`load-process --coredump`)
- ✅ Memory region classification and anomaly detection (`analyse-memory`)
- ✅ Architecture abstraction layer (x86, x86-64, ARM, ARM64, RISC-V)
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

See [CLAUDE.md](CLAUDE.md) for architecture details and development notes.

## License

MIT
