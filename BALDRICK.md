# Baldrick semantics

Baldrick: debug/examine processes+coredumps. Collects max info from minimal input. Stores in single SQLite DB per session: binary metadata (symbols, sections, debug-info) + process data (mappings, snapshots, backtraces).

## Global options

Apply to all subcommands, placed before subcommand name:

    --db | -d <db-file>       Path to database (default from config / env)
    --debug                   Enable DEBUG level logging
    --log-level <level>       Log level: DEBUG, INFO, WARNING, ERROR (default: WARNING)
    --log-file <file>         Write logs to file

Example:

    baldrick --db session.db load-process --pid 12345
    baldrick --debug --db session.db analyse-memory --pid 12345

## rootfs and debugfs

### command line options:
    - rootfs: [--rootfs | -R] <path>, default: /
    - debugfs: [--debugfs | -D] <debugfs-path>, default: <same-as-rootfs>

rootfs = param, default `/`. Stripped binaries store debug-info/symbols in separate files via `.debug_link` section (abs or rel path or filename).

Binary at `<prefix>/lib/libfoo.so`. Check debug file at:

if debugfs is the same as rootfs:
    <rootfs><absolute-debug-link>
    <rootfs><prefix>/lib/<relative-debug-link>
    <rootfs><prefix>/lib/.debug/<relative-debug-link>
    <rootfs><prefix>/.debug/lib/<relative-debug-link>
    <rootfs><prefix>/.debug/**/<relative-debug-link>
else:
    <debugfs><absolute-debug-link>
    <debugfs><prefix>/lib/<relative-debug-link>
    <debugfs><prefix>/lib/.debug/<relative-debug-link>
    <debugfs><prefix>/.debug/lib/<relative-debug-link>
    <debugfs><prefix>/.debug/**/<relative-debug-link>

If `<debug-link>` absent in binary:

if debugfs is the same as rootfs:
    <prefix>/lib/libfoo.so<suffix>
    <prefix>/lib/.debug/libfoo.so<suffix>
    <prefix>/.debug/lib/libfoo.so<suffix>
    <prefix>/.debug/**/libfoo.so<suffix>
else:
    <debugfs><prefix>/lib/libfoo.so<suffix>
    <debugfs><prefix>/lib/.debug/libfoo.so<suffix>
    <debugfs><prefix>/.debug/lib/libfoo.so<suffix>
    <debugfs><prefix>/.debug/**/libfoo.so<suffix>

where:
<rootfs> : [path] - input parameter
<debugfs> : [path] - input parameter
<prefix> : [ path to binary installation base ], ie: / | /usr | /usr/local | etc...
<suffix> : one of: .dbg | .debug | -dbg | -debug
<debug-link> : read from libfoo.so
<absolute-debug-link> : read from libfoo.so if starts with /
<relative-debug-link> : read from libfoo.so if doesn't start with /

## Subcommands

**load <parameters>**

Populates only binary metadata (sections, symbols, debug-info). No process snapshot.

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
    [ --types | -t ]             - load DWARF type info (implies --lines)
    [ --lines | -l ]             - load .debug_line addr→source mappings only
    [ --slow-threshold <sec> ]   - show spinner for binaries running longer than N seconds (default: 5)
    [ --slow-top <n> ]           - max simultaneous slow-binary spinners (default: 5, 0=off)
    [ --maxbin <n> ]             - stop after loading N binaries (testing)
    [ --maxdepth <n> ]           - max directory recursion depth (0 = top-level only)
*mandatory one of the following:*
    [ --glob | -g <pattern> ] - load binaries matching given glob pattern
    [ --perm | -P <permission> ] - load binaries matching given permission (e.g. 0755, u+x)
    [ --files | -f <file-list-spec> ] - load binaries from given list
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]

<file-list-spec> : colon separated list of files | @file-name-with-list-of-files (one path per line)


**load-types <parameters>**

Load DWARF type defs + `.debug_line` mappings from single already-indexed binary. Idempotent — skips if already loaded.

parameters:
    --binary | -b <binary-path>   - path to the binary file

Example:
    baldrick --db session.db load-types --binary /usr/lib/x86_64-linux-gnu/libpthread.so.0


**cast-mem <parameters>**

Interpret raw memory bytes as named C struct/typedef from indexed binary. Recursively expands nested structs. Outputs table: byte offsets, field paths, types, hex+decimal values.

parameters:
    --type <name>           - struct/typedef name (e.g. pthread_mutex_t)
    --binary | -b <name>    - binary name as stored in DB (e.g. libc.so.6)
    --mem <hex>|@<file>     - memory bytes as hex string, or @path to binary dump
    [ --addr <0xOFFSET> ]   - byte offset within the dump where the struct starts (default: 0x0)

Example:
    baldrick --db session.db cast-mem --type pthread_mutex_t --binary libc.so.6 \
        --mem 0000000001000000000000000000000000000000
    baldrick --db session.db cast-mem --type pthread_mutex_t --binary libc.so.6 \
        --mem @/tmp/memdump.bin --addr 0x1000

**load-process <parameters>**

Creates process snapshot + populates binary metadata for all mapped files. Captures per-thread state (wchan, syscall, name, stack bounds) when possible.

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
*mandatory one of the following:*
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]
    [ --gdb-dump | -G <gdb-output-file> ]  - output of "gdb -batch -ex 'thread apply all bt full' -ex 'info registers'"


**decode-backtrace <parameters>**

Decode backtrace: resolve each addr → symbol + source location. Auto-detects input format (raw hex, GDB, kernel).

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
    --pid | -p <pid>            - process snapshot ID to use for address mapping
    [ --trace | -t <backtrace-file> ] - backtrace file (default: stdin)
    [ --jobs | -j <n> ]         - max parallel symbol resolutions (default: 32)

Input formats auto-detected:
    raw hex:    0x400a1c
    GDB:        #0 0x400a1c in function_name ...
    kernel:     [<ffffffff81010001>] function+0x42/0x100


**decode-address <parameters> -- <list-of-addresses>**

Translate addr → symbol + additional binary/process info.

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]

*one of the following (determines address interpretation):*
    [ --mapped | -a ] [ --pid | -p <pid> ]
                       - addresses are virtual (mapped into process address space)
    [ --unmapped | -A ] --binary | -b <binary-path>
                       - addresses are offsets within the given binary file

    [ --name | -n ]    - print only name of symbol
    [ --type | -t ]    - print type of data if available
    [ --section | -j ] - print section info
    [ --full | -F ]    - print all information


**analyse-memory <parameters>**

Analyze memory layout, detect anomalies. Different info available depending on input. No `--db` = transient in-memory analysis.

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
*mandatory one of the following:*
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]


**analyse-deadlock <parameters>**

Detect deadlocks in previously loaded process snapshot. 3-tier evidence: certain (futex syscall / GDB mutex graph) → probable (pthread_mutex_lock in backtrace) → possible (wchan=futex_wait).

parameters:
    --snapshot-id | -s <id>              - ID of ProcessSnapshot to analyse
    [ --lock-state | -L <file> ]         - output of GDB find_deadlock command
                                           (BALDRICK_LOCK_STATE_BEGIN … END format)
    [ --json ]                           - emit JSON instead of Rich table

Output: evidence level (certain/probable/possible/none), deadlock cycles with TIDs, suspected threads without cycle.

Example — live process:
    baldrick --db session.db load-process --pid 12345
    baldrick --db session.db analyse-deadlock --snapshot-id 1

Example — with exact mutex ownership (GDB find_deadlock extension):
    gdb -batch \
        -ex "source tests/gdb-scripts/_gdb/find_deadlock.py" \
        -ex "find_deadlock" \
        ./deadlock_test 12345 > lock.txt
    baldrick --db session.db analyse-deadlock --snapshot-id 1 --lock-state lock.txt

Note: GDB live attach requires ptrace_scope=0:
    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope


**report <parameters>**

Generate comprehensive debug report for a process snapshot. Combines snapshot info, thread state, memory anomalies, deadlock analysis, and crash pattern detection.

parameters:
    [ --snapshot-id | -s <id> ]   - snapshot ID (default: latest)
    [ --json ]                    - output as JSON

Crash patterns detected:
    deadlock         — forwarded from analyse-deadlock (certain/probable/possible)
    stack-overflow   — SP within 4096 bytes of stack boundary
    null-deref       — instruction pointer near NULL (< 0x1000)
    use-after-free   — free()+alloc() in same thread backtrace [+RWX region]
    double-free      — free() appears ≥2× in one thread backtrace
    rwx-region       — RWX non-library anonymous region (potential code injection)

Example:
    baldrick --db session.db report
    baldrick --db session.db report --snapshot-id 1
    baldrick --db session.db report --snapshot-id 1 --json


**query <name> [key=value ...]**

Run built-in or user-defined SQL query against DB. Params as positional `key=value`. Inline SQL via `sql="SELECT ..."`.

Built-in queries:

    snapshots                   List all process snapshots
    mappings     id=N           Memory mappings for snapshot N
    binaries                    All indexed binaries
    symbols      binary=NAME    Symbols for a binary (by name)
    sections     binary=NAME    Section headers for a binary
    backtrace    id=N           Backtrace entries for snapshot N
    libs         id=N           Shared libraries for snapshot N
    rwx          id=N           RWX memory regions for snapshot N
    process-binaries id=N       ProcessBinary records for snapshot N
    threads      id=N           Threads for snapshot N
    symbol-cache binary=NAME    Symbol cache entries for binary
    symbol-cache-stats          Symbol cache hit counts per binary
    deadlock-threads id=N       Threads likely blocked on a futex/mutex
    types        binary=NAME    Structs/unions defined in a binary (requires load-types)
    struct       name=NAME      Fields of a named struct/union with byte offsets
    type-offset  name=NAME offset=N  Field at or just before byte offset N in a struct
    line2addr    binary=NAME file=F line=N  Addresses for a source file:line (reverse addr2line)

parameters:
    <name>                      - built-in query name, 'list', or first arg as sql=...
    [key=value ...]             - bind query parameters (positional, repeatable)
    [ --param | -p key=value ]  - alternative to positional key=value (backward compat)
    [ --tag | -T <tag> ]        - filter snapshots by tag
    [ --format | -f rich|json|csv ] - output format (default: rich)

Examples:
    baldrick --db session.db query list
    baldrick --db session.db query threads id=1
    baldrick --db session.db query deadlock-threads id=1
    baldrick --db session.db query symbols binary=libc.so.6 --format csv
    baldrick --db session.db query 'sql="SELECT tid, wchan FROM thread WHERE process_id=1"'


**schema**

Print DB schema (all tables, columns, types).

    baldrick --db session.db schema


## Aliases

Aliases in `~/.baldrick.toml` (user) and `./baldrick.toml` (local, priority). Syntax mirrors gitconfig.

```toml
[alias]
dl   = "analyse-deadlock"
dls  = "analyse-deadlock --snapshot-id"
qt   = "query threads"
qdl  = "query deadlock-threads"
snap = "query snapshots"
```

Usage:

    baldrick --db session.db dl --snapshot-id 1
    baldrick --db session.db dls 1
    baldrick --db session.db qt id=1
    baldrick --db session.db qdl id=1

Aliases expanded before flag parsing — extra args appended verbatim (like git). One expansion level only; no alias chaining.