# Quality and Architecture Remediation Design

## Context

Blackadder is a Typer CLI that imports binaries, DWARF metadata, process maps,
registers, stacks, and core dumps into SQLite through SQLModel, then runs symbol
resolution and analyzers over that data. The review found correctness defects at
the database boundary, binary-local DWARF data represented as global data,
inconsistent unsigned address handling, unsupervised cache writes, fragile
subprocess execution, stale CLI paths, and a non-green quality baseline.

## Goals

- Make imports atomic and make failures visible to callers.
- Restore a green, reproducible test suite and CI on supported Python versions.
- Preserve binary-local DWARF identity and layout.
- Represent 64-bit target addresses consistently while storing them in SQLite.
- Enforce relational integrity and support upgrades of existing databases.
- Keep complete symbol/source cache results and account for persistence work.
- Put timeout, termination, and exit-status policy in one subprocess runner.
- Reduce CLI and database modules to active, cohesive responsibilities.
- Finish with clean Ruff, formatting, Mypy, and test checks.

## Non-goals

- Changing the command-line vocabulary or output format without necessity.
- Replacing SQLite, SQLModel, Typer, or the analysis algorithms.
- Adding speculative extension points or supporting undocumented schemas.
- Reformatting the modified `tests/gdb-scripts` submodule or including it in any
  commit.

## Design

### 1. Atomic rootfs import

Initialize the symbol state for both new and existing binaries. Apply each queue
batch in one transaction, merge counters only after commit, and propagate a
terminal writer exception to the producer. This prevents false success and
incorrect counts after rollback/retry.

### 2. Reproducible baseline

Update tests to the current unified database configuration and current DWARF and
core-dump APIs. Accept anonymous `/proc/<pid>/maps` rows. Keep regression tests
focused on public behavior. CI will ultimately run the complete tests, Ruff, and
Mypy on the supported Python matrix.

### 3. Binary-local DWARF ownership

A canonical type describes reusable type identity. A `BinaryDwarfRef` identifies
one DIE in one binary. Members belong to that binary reference, not directly to
the canonical type. Canonical rows receive a deterministic, non-null identity
key so SQLite cannot create duplicates through nullable unique columns. Queries
must select a binary reference before traversing its members.

### 4. Unsigned address type

Use one SQLAlchemy type decorator for unsigned 64-bit addresses. Python code sees
values in `[0, 2**64 - 1]`; SQLite stores the two's-complement signed equivalent.
Bindings and result conversion happen at the type boundary. Raw SQL import paths
use the same conversion helpers. Address comparisons therefore work for kernel
addresses without scattered conversions.

### 5. Integrity and migrations

Enable `PRAGMA foreign_keys=ON` for every connection. Introduce an idempotent,
versioned SQLite migration runner using `PRAGMA user_version`; it upgrades the
pre-migration schema, including the DWARF ownership change, before normal use.
Fresh databases and upgraded databases converge on the same metadata schema.

### 6. Complete symbol cache

Cache `(symbol, source_file, line)` as one value and enforce the configured bound
without the current off-by-one. Persistence work is awaited or tracked and
drained explicitly, so errors cannot disappear in detached tasks.

### 7. Supervised subprocesses

One runner owns concurrency, timeout, output collection, termination/kill, and
non-zero exit handling. Binutils parsers delegate process lifecycle to it and
retain only parsing responsibilities. Errors include the executable and useful
stderr context.

### 8. Cohesive CLI and removal of stale paths

Move related command registration into focused modules while preserving the
existing root `app`. Remove only unregistered placeholders and legacy database
writers that target tables/columns no longer present. Shared CLI helpers remain
small and dependency direction stays CLI -> database/analyzers.

### 9. Quality gates

Apply formatter/linter fixes after functional changes, resolve type errors rather
than hiding them, exclude the independently managed GDB fixture submodule, and
add CI jobs for tests, Ruff, and Mypy. Configuration should match actual supported
Python versions and source paths.

## Compatibility and rollout

Commands and query output remain compatible. Database schema changes are handled
by migrations; a database is upgraded on initialization in one transaction per
migration. Each functional stage begins with a failing regression test and ends
with targeted plus broader verification. Each stage is committed separately so
it can be reviewed or reverted independently.

## Success criteria

- New and existing binary imports do not reference uninitialized state.
- A failed writer batch fails the overall operation and does not inflate counts.
- Two binaries may contain equal canonical types with different members safely.
- Kernel-space addresses round-trip and participate in lookups.
- Foreign-key violations are rejected and an old schema upgrades in place.
- Cache hits retain source locations and persistence failures are observable.
- Timed-out/non-zero subprocesses fail predictably without leaked children.
- No active code depends on obsolete DWARF tables or hidden CLI placeholders.
- Full tests, Ruff, formatting check, and Mypy pass in CI and locally.
