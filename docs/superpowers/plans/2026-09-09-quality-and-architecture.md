# Quality and Architecture Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the nine review recommendations as small, verified, independently committed stages without changing Blackadder's public CLI unnecessarily.

**Architecture:** Preserve the Typer -> database/services -> SQLModel structure while making database boundaries atomic, binary-local data explicitly owned, addresses type-safe, and external processes supervised. Remove obsolete paths only after confirming they have no active callers.

**Tech Stack:** Python 3.12-3.14, Typer, SQLModel/SQLAlchemy, SQLite/aiosqlite, asyncio, pytest, Ruff, Mypy, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-09-quality-and-architecture-design.md`

**Global Constraints:** Use test-driven development for behavior changes; make surgical edits; preserve CLI behavior; never stage `tests/gdb-scripts`; run targeted tests before each commit and the broadest practical checks after it.

## Task 0: Record the design and execution plan

**Files:**
- Create: `docs/superpowers/specs/2026-09-09-quality-and-architecture-design.md`
- Create: `docs/superpowers/plans/2026-09-09-quality-and-architecture.md`

- [ ] Review both documents for all nine recommendations and explicit success criteria.
- [ ] Verify with `git diff --check -- docs/superpowers`.
- [ ] Commit with `docs: plan quality and architecture remediation`.

## Task 1: Make rootfs indexing atomic and observable

**Files:**
- Modify: `blackadder/db/rootfs.py`
- Test: `tests/test_rootfs_db.py`

- [ ] Add a regression test applying a new-binary payload with symbols; verify it fails with the current uninitialized `symbols_already_ok` path.
- [ ] Add a writer test whose payload application repeatedly raises; verify the writer currently returns instead of propagating the terminal error.
- [ ] Initialize symbol state before both branches in `_apply_payload`.
- [ ] Accumulate counts per transaction and merge only after a successful commit; re-raise after the final retry.
- [ ] Run `pytest tests/test_rootfs_db.py --no-cov` and relevant rootfs/indexing tests.
- [ ] Commit with `fix: make rootfs indexing failures atomic`.

## Task 2: Restore the behavioral test baseline

**Files:**
- Modify: `tests/conftest.py`
- Modify: `tests/test_dwarf_parser.py`
- Modify: core-dump tests using the old result/fixture contract
- Modify: `blackadder/db/process.py`
- Test: process-map parser tests

- [ ] Update database fixtures to use the unified `config.db` settings.
- [ ] Update DWARF parser assertions to unpack types, members, and variables.
- [ ] Replace the missing core fixture dependency with a deterministic fixture or mock at the external parser boundary and assert the current result object.
- [ ] Confirm the anonymous process-map test fails, then relax parsing only for the optional pathname.
- [ ] Run the repaired test modules and then `pytest --no-cov` with a bounded timeout.
- [ ] Commit with `test: restore current API regression baseline`.

## Task 3: Correct DWARF ownership and canonical identity

**Files:**
- Modify: `blackadder/db/models.py`
- Modify: `blackadder/db/rootfs.py`
- Modify: `blackadder/db/dwarf_query.py`
- Modify: callers of member traversal
- Test: `tests/test_dwarf_query.py`
- Test: rootfs DWARF import tests

- [ ] Add a failing test importing the same canonical type from two binaries with different members and query each layout.
- [ ] Add a failing test for repeated canonical types containing nullable identity fields.
- [ ] Give each canonical type a deterministic non-null identity key.
- [ ] Make `DwarfMember` belong to `BinaryDwarfRef`; resolve parent DIE offsets to those rows during import.
- [ ] Scope member traversal through a selected binary reference and update callers.
- [ ] Run all DWARF/parser/rootfs tests.
- [ ] Commit with `fix: preserve binary-local DWARF layouts`.

## Task 4: Centralize unsigned 64-bit address storage

**Files:**
- Modify: `blackadder/db/models.py`
- Modify: raw SQL import/bind paths in `blackadder/db/rootfs.py` and `blackadder/db/process.py`
- Test: address/model/process lookup tests

- [ ] Add failing round-trip tests for `0`, `2**63 - 1`, `2**63`, and `2**64 - 1`.
- [ ] Add a failing process-map lookup test using a kernel-space address.
- [ ] Implement a SQLAlchemy unsigned-address type using the existing conversion semantics.
- [ ] Attach it to address columns and remove conflicting caller-side conversions; use the helpers for raw SQL bindings.
- [ ] Run model, rootfs, process, and core-dump tests.
- [ ] Commit with `fix: normalize unsigned address persistence`.

## Task 5: Enforce foreign keys and version the schema

**Files:**
- Create: `blackadder/db/migrations.py`
- Modify: `blackadder/db/manager.py`
- Modify: `blackadder/db/models.py`
- Test: `tests/test_db_migrations.py`

- [ ] Add a failing test showing a foreign-key violation is currently accepted.
- [ ] Add a fixture containing the pre-migration DWARF schema and a failing in-place upgrade test.
- [ ] Enable the foreign-key pragma for each connection.
- [ ] Implement ordered, idempotent migrations tracked by `PRAGMA user_version`, including the Task 3 schema transition.
- [ ] Ensure fresh initialization and upgraded initialization produce equivalent expected tables/columns/indexes.
- [ ] Run migration and all database tests.
- [ ] Commit with `feat: add sqlite integrity and schema migrations`.

## Task 6: Make symbol caching complete and supervised

**Files:**
- Modify: `blackadder/db/process.py`
- Test: `tests/test_process_db.py`

- [ ] Add a failing test proving a memory-cache hit loses source file and line.
- [ ] Add boundary tests proving the cache never exceeds its configured size.
- [ ] Add a failure test proving persistence errors are observable before shutdown/flush completes.
- [ ] Store the full `(symbol, file, line)` tuple and correct eviction ordering.
- [ ] Await persistence or track tasks in a bounded set and provide an awaited drain point used by lifecycle code.
- [ ] Run process database and symbol resolution tests.
- [ ] Commit with `fix: retain and supervise symbol cache results`.

## Task 7: Centralize subprocess lifecycle policy

**Files:**
- Create: `blackadder/binutils/runner.py`
- Modify: `blackadder/binutils/parser.py`
- Modify: binutils construction sites
- Test: `tests/test_subprocess_runner.py`
- Test: `tests/test_binutils_parser.py`

- [ ] Add failing tests for timeout, non-zero exit, stderr context, and successful streamed output.
- [ ] Implement a shared runner honoring `subprocess_timeout_seconds`, concurrency limits, graceful terminate, and kill fallback.
- [ ] Raise typed errors for timeout and non-zero exit; leave line parsing in `BinToolsParser`.
- [ ] Inject/share the runner where parser instances are constructed.
- [ ] Run binutils, symbol-resolution, and integration-adjacent tests.
- [ ] Commit with `feat: supervise binutils subprocesses`.

## Task 8: Split CLI responsibilities and delete obsolete paths

**Files:**
- Modify: `blackadder/cli/main.py`
- Create: focused modules under `blackadder/cli/`
- Delete: unregistered placeholder command module(s), after call-site verification
- Modify: `blackadder/db/rootfs.py`
- Test: CLI help and command tests

- [ ] Record `rg` evidence for active decorators, imports, and legacy method callers.
- [ ] Add/retain command registration tests that assert the existing top-level command set and help output.
- [ ] Move related commands into cohesive registration modules without changing names/options.
- [ ] Remove obsolete rootfs writers referencing superseded `dwarftype`/`debugline` shapes and unregistered placeholder commands with no callers.
- [ ] Run CLI tests, `python -m blackadder.cli.main --help`, and the database tests affected by deletion.
- [ ] Commit with `refactor: separate cli command responsibilities`.

## Task 9: Establish clean local and CI quality gates

**Files:**
- Modify: `pyproject.toml`
- Create: `.github/workflows/ci.yml`
- Modify: only source/tests required by Ruff or Mypy findings

- [ ] Configure Ruff paths/exclusions so the independent `tests/gdb-scripts` submodule is not rewritten.
- [ ] Apply mechanical Ruff formatting/import fixes, then make minimal manual fixes for remaining diagnostics.
- [ ] Resolve Mypy errors with accurate annotations and narrowing; do not silence whole modules.
- [ ] Add GitHub Actions for Python 3.12, 3.13, and 3.14 running tests, plus dedicated Ruff/format/Mypy gates.
- [ ] Run `ruff format --check`, `ruff check`, `mypy blackadder`, and `pytest --no-cov`.
- [ ] Inspect `git diff --check` and confirm `tests/gdb-scripts` is unstaged.
- [ ] Commit with `ci: enforce tests lint formatting and types`.

## Final verification

- [ ] Run the complete local gate set from Task 9 once more from a clean index/worktree except for the pre-existing submodule modification.
- [ ] Inspect `git log --oneline` for one commit per stage and `git status --short` for accidental files.
- [ ] Review the aggregate diff against the design goals and report any environment-only limitations precisely.
