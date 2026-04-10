# Baldrick semantics

Baldrick is a tool that helps in debugging and examining processes and
coredumps. It collects as many information as possible from minimal input. It
stores collected information in a single SQLite database per debugging session,
holding both binary metadata (symbols, sections, debug-info) and process data
(memory mappings, snapshots, backtraces).

## Global options

The following options apply to all subcommands and must be placed before the
subcommand name:

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

Path to rootfs is a parameter and default is /
Often binaries are stripped and debug-info, symbols and other data are stored in
separated files. Typically .debug_link section is used which contains path
(absolute or relative) or just filename.

Let's assume the binary is under path:
<prefix>/lib/libfoo.so

Following paths should be checked for debug file.

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

If <debug-link> does not exist in binary (libfoo.so),

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

Populates only the binary metadata in the database (sections, symbols, debug-info).
Does not create a process snapshot.

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
*mandatory one of the following:*
    [ --glob | -g <pattern> ] - load binaries matching given glob pattern
    [ --perm | -P <permission> ] - load binaries matching given permission (e.g. 0755, u+x)
    [ --files | -f <file-list-spec> ] - load binaries from given list
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]

<file-list-spec> : colon separated list of files | @file-name-with-list-of-files (one path per line)

**load-process <parameters>**

Creates a process snapshot and populates binary metadata for all mapped files.
Also captures per-thread state (wchan, syscall, name, stack bounds) when possible.

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
*mandatory one of the following:*
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]
    [ --gdb-dump | -G <gdb-output-file> ]  - output of "gdb -batch -ex 'thread apply all bt full' -ex 'info registers'"


**decode-backtrace <parameters>**

Decode a backtrace by resolving each address to its symbol and source location.
Auto-detects input format (raw hex, GDB, kernel).

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

Translate address to symbol. Additionally prints other information collected from binary and process.

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

Analyze memory layout and detect anomalies.
Depending on provided data a different set of information can be provided.
When no --db is given, analysis is transient (in-memory only).

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
*mandatory one of the following:*
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]


**analyse-deadlock <parameters>**

Detect deadlocks in a previously loaded process snapshot.
Uses 3-tier evidence degradation: certain (futex syscall / GDB mutex graph) →
probable (pthread_mutex_lock in backtrace) → possible (wchan=futex_wait).

parameters:
    --snapshot-id | -s <id>              - ID of ProcessSnapshot to analyse
    [ --lock-state | -L <file> ]         - output of GDB find_deadlock command
                                           (BALDRICK_LOCK_STATE_BEGIN … END format)
    [ --json ]                           - emit JSON instead of Rich table

Output shows evidence level (certain / probable / possible / none), detected
deadlock cycles with participating TIDs, and suspected threads with no cycle.

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


**query <name> [key=value ...]**

Run a built-in or user-defined SQL query against the database.
Parameters are passed as positional `key=value` arguments after the query name.
Inline SQL is run by passing `sql="SELECT ..."` as the first argument.

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

Print the database schema (all tables, columns, and types).

    baldrick --db session.db schema


## Aliases

Baldrick supports command aliases in `~/.baldrick.toml` (user-level) and
`./baldrick.toml` (local, takes priority). Syntax mirrors gitconfig aliases.

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

Aliases are expanded before any flag parsing — extra arguments after the alias
are appended verbatim, exactly like git aliases. One level of expansion only
(aliases cannot reference other aliases).
