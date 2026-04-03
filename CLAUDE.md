# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Blackadder** is a high-level Linux binutils wrapper written in Python 3. It analyzes binary files (ELF executables, shared libraries) by wrapping standard Linux tools (`objdump`, `readelf`) and storing extracted information (sections, symbols, debug metadata) in a SQLite database using SQLAlchemy ORM.

## Architecture

### Core Layers

1. **ORM Models** (`blackadder_types.py`)
   - `Binary` - Represents unique binaries identified by MD5 checksum
   - `BinaryLocator` - Maps file paths to binaries (same binary may exist at multiple paths)
   - `SectionHeader` - ELF section metadata (name, size, addresses, alignment)
   - `Symbol` - Symbol table entries (address, size, scope, type, section)
   - Uses SQLAlchemy declarative models with `DeclarativeBase` and mapped columns

2. **Database Access** (`blackadder_db.py`)
   - `DataBase` class wraps SQLAlchemy engine and session
   - Provides query methods for binaries by name, MD5, path
   - Handles insert/update operations for binaries and binary locators
   - Single SQLite database per instance (path configured in `blackadder.conf`)

3. **Binutils Integration** (`blackadder_binutils.py`)
   - Wrapper functions that parse output from external tools:
     - `readDebugLink()` - Extracts `.gnu_debuglink` section using `readelf`
     - `readSectionHeaders()` - Parses `objdump -h` output
     - `readSymbols()` - Parses `objdump --syms` output
     - `md5sum()` - Computes file checksums for deduplication
   - Uses regex parsing via `RegexpReaderListener` from commands module

4. **Process Execution Framework** (`commands.py`)
   - `Reader` - Thread that reads subprocess output line-by-line or in binary chunks
   - `ReaderListener` - Base class for handling output events (`onLine`, `onData`)
   - `RegexpReaderListener` - Parses lines matching regex patterns, calls callback per match
   - `runCommandWithoutInput*` - Spawns subprocess with reader threads for stdout/stderr
   - `CommandWithInput` - Variant with writable stdin

5. **Main Entry Point** (`baldrick.py`)
   - `BlackAdder` class orchestrates binary analysis workflow:
     - `loadBinary()` - Main entry point: loads binary, extracts metadata, stores in DB
     - `fetchOrCreateBinary()` - Deduplicates by MD5, extracts sections/symbols
     - `fetchOrCreateDebugBinary()` - Finds and recursively loads split debug files
   - Subcommands: `load`, `syms`, `addr2line`

### GDB Extensions (`scripts/gdb/`)

- `backtrace_ext.py` - Provides enhanced backtrace functionality in GDB
- `find_deadlock.py` - Analyzes thread state to detect deadlocks

## Configuration

Configuration is read from `blackadder.conf` (INI format):
- `[main]` section:
  - `database` - SQLAlchemy connection string (e.g., `sqlite+pysqlite:///blackadder.db`)
- `[paths]` section:
  - `rootfs` - Colon-separated paths to search for binaries
  - `debugfs` - Path to debug symbols directory
  - `sources` - Colon-separated source code directories

## Development Commands

```bash
# Run the main application
./scripts/baldrick.py load -e <binary_paths>

# Run test suite (ad-hoc test scripts)
./scripts/test.sh

# Run individual test scripts
python3 scripts/commands-test.py
python3 scripts/sqlite-test.py
python3 scripts/popen-test.py
python3 scripts/tqdm-test.py
python3 scripts/metaclass-test.py

# Query database directly
sqlite3 scripts/blackadder.db

# Run SQL test file
sqlite3 scripts/blackadder.db < scripts/test.sql
```

## Key Design Patterns

1. **Callback-based Output Parsing**
   - External command output is parsed via regex patterns with callbacks
   - Allows streaming processing without buffering entire output
   - Core pattern in `RegexpReaderListener` and `RegexpParser`

2. **Binary Deduplication**
   - Binaries identified by MD5 checksum, not path
   - Multiple paths can reference the same binary (via `BinaryLocator`)
   - Reduces database size, supports split debug files

3. **Lazy Loading with Caching**
   - Binary metadata extracted on-demand via external tool calls
   - Results cached in database to avoid re-processing
   - Modification time (`mtime`) checked to detect stale cache

4. **Split Debug Files**
   - Handles `.gnu_debuglink` to find separate debug symbol files
   - Recursively loads debug binaries into database
   - Supports debug symbol resolution workflows

## Dependencies

- **SQLAlchemy** - ORM framework
- **Standard Library**: pathlib, subprocess, threading, re, argparse, configparser, hashlib

## Testing Notes

- Test files are currently ad-hoc scripts rather than a formal test framework
- No pytest/unittest currently in use
- Database tests use temporary in-memory SQLite (see `blackadder.conf` commented example)
- Manual testing against sample binaries in configured rootfs/debugfs paths

## Important Notes

- The main entry point `baldrick.py load` is currently a placeholder printing "This software is not ready yet"
- Actual command logic is in `BlackAdder` class (appears in `baldrick.py` but referenced as main orchestrator)
- Binary paths configured via `blackadder.conf`, not command-line arguments (yet)
- No error handling for missing binaries or corrupted binaries; assumes valid ELF format
