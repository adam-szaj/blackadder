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

parameters:
    [ --rootfs | -R <rootfs> ]
    [ --debugfs | -D <debugfs> ]
*mandatory one of the following:*
    [ --maps | -m <process-maps-file> ]
    [ --pid | -p <running-process-pid> ]
    [ --coredump | -C <coredump-file> ]


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
