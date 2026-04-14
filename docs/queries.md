# Blackadder — built-in queries

Run any query with:

```
baldrick --db <db> query <name> [key=value …] [--format rich|json|csv]
```

List all available queries (built-in + user-defined):

```
baldrick --db session.db query list
```

---

## Queries grouped by workflow

### Inspect indexed binaries (`load`)

#### `binaries` — all indexed binaries

```
baldrick --db session.db query binaries
```

```
 id  md5sum                            name                   debug_link
 ──  ────────────────────────────────  ─────────────────────  ──────────
  1  a1b2c3d4e5f6...                   libc.so.6              libc.so.6
  2  09fe12ab3c4d...                   libpthread.so.0        -
  3  deadbeef0011...                   libm.so.6              -
```

---

#### `sections` — ELF section headers for a binary

```
baldrick --db session.db query sections binary=libc.so.6
```

```
 id   idx  name           size        vma                 lma                 off       align
 ───  ───  ─────────────  ──────────  ──────────────────  ──────────────────  ────────  ─────
  1     0  (none)                  0  0x0000000000000000  0x0000000000000000         0      0
  2     1  .note.gnu...         0x24  0x0000000000000270  0x0000000000000270       624      4
  3    11  .text          0x168a20   0x0000000000029b60  0x0000000000029b60    170848     16
  4    26  .debug_info    0x4f2300   0x0000000000000000  0x0000000000000000   2752512      1
```

---

#### `symbols` — symbol table entries for a binary

```
baldrick --db session.db query symbols binary=libpthread.so.0
```

```
 id    address             scope  sym_type  section  size  name
 ────  ──────────────────  ─────  ────────  ───────  ────  ──────────────────────
  42   0x0000000000007800  g      F         .text     224  pthread_mutex_lock
  43   0x0000000000007900  g      F         .text     160  pthread_mutex_unlock
  44   0x0000000000007a10  g      F         .text      64  pthread_mutex_trylock
 100   0x0000000000000000  g      F         *UND*       0  __libc_start_main
```

---

#### `symbol-cache` — persistent addr2line cache entries for a binary

```
baldrick --db session.db query symbol-cache binary=libc.so.6
```

```
 offset              symbol                  source_file                   source_line  binary_name
 ──────────────────  ──────────────────────  ────────────────────────────  ───────────  ───────────
 0x00000000000814a0  malloc                  malloc/malloc.c                       123  libc.so.6
 0x0000000000081500  free                    malloc/malloc.c                       456  libc.so.6
```

---

#### `symbol-cache-stats` — cache size per binary

```
baldrick --db session.db query symbol-cache-stats
```

```
 binary_name      cached_symbols
 ───────────────  ──────────────
 libc.so.6                  4821
 libstdc++.so.6             3102
 libpthread.so.0             211
```

---

### DWARF type inspection (`load --types` / `load-types`)

#### `types` — structs and unions defined in a binary

```
baldrick --db session.db query types binary=libpthread.so.0
```

```
 name                   tag             byte_size  field_count
 ─────────────────────  ──────────────  ─────────  ───────────
 __pthread_mutex_s      structure_type         40           10
 pthread_attr_t         structure_type         56            1
 pthread_cond_t         union_type             48            2
 pthread_mutex_t        union_type             40            2
 pthread_rwlock_t       union_type             56            2
```

---

#### `struct` — fields of a named struct with byte offsets

```
baldrick --db session.db query struct name=pthread_mutex_t binary=libpthread.so.0
```

```
 byte_offset  name    type_name              byte_size  tag
 ───────────  ──────  ─────────────────────  ─────────  ──────────────
           0  __data  __pthread_mutex_s             40  structure_type
```

```
baldrick --db session.db query struct name=__pthread_mutex_s binary=libpthread.so.0
```

```
 byte_offset  name          type_name              byte_size  tag
 ───────────  ────────────  ─────────────────────  ─────────  ──────────────
           0  __lock        int                            4  base_type
           4  __count       unsigned int                   4  base_type
           8  __owner       int                            4  base_type
          12  __nusers      unsigned int                   4  base_type
          16  __kind        int                            4  base_type
          20  __spins       short int                      2  base_type
          22  __elision     short int                      2  base_type
          24  __list        __pthread_list_t               8  structure_type
```

---

#### `type-offset` — field at a given byte offset within a struct

```
baldrick --db session.db query type-offset name=__pthread_mutex_s offset=8 binary=libpthread.so.0
```

```
 byte_offset  name    type_name  byte_size
 ───────────  ──────  ─────────  ─────────
           8  __owner  int               4
```

Useful when analysing raw memory or crash dump: given a pointer offset into a
known struct, find which field it points to.

---

### Debug line info (`load --lines` / `load --types`)

#### `line2addr` — source file:line → binary addresses (reverse addr2line)

```
baldrick --db session.db query line2addr binary=libc.so.6 file=malloc.c line=123
```

```
 source_file                                    line_number  address
 ─────────────────────────────────────────────  ───────────  ──────────────────
 /build/glibc/malloc/malloc.c                           123  0x00000000000814a0
 /build/glibc/malloc/malloc.c                           123  0x00000000000814c8
```

Multiple addresses can correspond to the same source line due to inlining or
loop unrolling.

---

### Process snapshots (`load-process`)

#### `snapshots` — all recorded process snapshots

```
baldrick --db session.db query snapshots
```

```
 id  pid    tag   created_at                description  source_type
 ──  ─────  ────  ────────────────────────  ───────────  ───────────
  1  12345  -     2024-03-15 14:22:01.123   -            maps
  2  12345  -     2024-03-15 14:25:44.007   -            gdb_dump
  3      0  -     2024-03-15 14:30:11.889   -            coredump
```

---

#### `mappings` — memory mappings for a snapshot

```
baldrick --db session.db query mappings id=1
```

```
 id   start_addr          end_addr            perms  offset      dev    inode    pathname
 ───  ──────────────────  ──────────────────  ─────  ──────────  ─────  ───────  ──────────────────────────
   1  0x00007f8a20000000  0x00007f8a201c6000  r--p   0x00000000  fd:01  1835281  /usr/lib/x86_64.../libc.so.6
   2  0x00007f8a201c6000  0x00007f8a2033e000  r-xp   0x001c6000  fd:01  1835281  /usr/lib/x86_64.../libc.so.6
   3  0x00007ffe12340000  0x00007ffe12360000  rw-p   0x00000000  00:00        0  [stack]
   4  0x00007ffe12360000  0x00007ffe12364000  r--p   0x00000000  00:00        0  [vvar]
```

---

#### `libs` — shared libraries loaded by a snapshot

```
baldrick --db session.db query libs id=1
```

```
 pathname
 ──────────────────────────────────────────────────
 /usr/lib/x86_64-linux-gnu/libc.so.6
 /usr/lib/x86_64-linux-gnu/libm.so.6
 /usr/lib/x86_64-linux-gnu/libpthread.so.0
 /usr/lib/x86_64-linux-gnu/libstdc++.so.6
```

---

#### `threads` — threads in a snapshot with kernel wait info

```
baldrick --db session.db query threads id=1
```

```
 tid    name          wchan            syscall         stack_start         stack_end
 ─────  ────────────  ───────────────  ──────────────  ──────────────────  ──────────────────
 12345  main          do_epoll_wait    202 0x5 ...     0x00007ffe12340000  0x00007ffe12360000
 12346  worker-1      futex_wait_queue 202 0x1 ...     0x00007f8a10000000  0x00007f8a10800000
 12347  worker-2      futex_wait_queue 202 0x1 ...     0x00007f8a0f800000  0x00007f8a10000000
```

---

#### `process-binaries` — binaries matched to a snapshot

```
baldrick --db session.db query process-binaries id=1
```

```
 id  binary_load_addr    match_score  match_method  binary_name      pathname
 ──  ──────────────────  ───────────  ────────────  ───────────────  ──────────────────────────────
  1  0x00007f8a20000000         1.00  md5           libc.so.6        /usr/lib/.../libc.so.6
  2  0x00007f8a10000000         0.87  fingerprint   libssl.so.3      /usr/lib/.../libssl.so.3.1.4
  3  0x00007f8a0e000000         1.00  md5           libpthread.so.0  /usr/lib/.../libpthread.so.0
```

`match_method=fingerprint` means the binary on disk differs from the running
one (different build or version), but was matched by assembly similarity.

---

#### `backtrace` — decoded backtrace frames for a snapshot

```
baldrick --db session.db query backtrace id=1
```

```
 frame_num  address             resolved_symbol               resolved_file            resolved_line  match_confidence
 ─────────  ──────────────────  ────────────────────────────  ───────────────────────  ─────────────  ────────────────
         0  0x00007f8a2014a0c4  __lll_lock_wait               nptl/lowlevellock.c                 94  exact
         1  0x00007f8a20145782  pthread_mutex_lock             nptl/pthread_mutex_lock.c           80  exact
         2  0x000000000040128a  WorkQueue::push                src/workqueue.cpp                  142  exact
         3  0x0000000000401100  main                           src/main.cpp                        55  exact
```

---

#### `rwx` — RWX memory regions (potential anomalies)

```
baldrick --db session.db query rwx id=1
```

```
 id   start_addr          end_addr            perms  pathname
 ───  ──────────────────  ──────────────────  ─────  ──────────────────────
  47  0x00007f8a18000000  0x00007f8a18200000  rwxp   (anonymous)
```

An anonymous `rwxp` region is a strong indicator of JIT-compiled code or
(in malware analysis) code injection.

---

### Deadlock detection (`analyse-deadlock`)

#### `deadlock-threads` — threads likely blocked on a mutex/futex

```
baldrick --db session.db query deadlock-threads id=1
```

```
 tid    name      wchan            syscall    frame_count
 ─────  ────────  ───────────────  ─────────  ───────────
 12346  worker-1  futex_wait_queue  202 0x1…           8
 12347  worker-2  futex_wait_queue  202 0x1…           6
```

This query surfaces candidates. For confirmed deadlock cycles, use the full
`analyse-deadlock` command:

```
baldrick --db session.db analyse-deadlock --snapshot-id 1
```

---

## User-defined queries

Add custom queries to `~/.baldrick.toml` (user-wide) or `./baldrick.toml`
(project-local, takes priority):

```toml
[query.heap-anon]
description = "Large anonymous mappings (potential heap leaks)"
sql = """
    SELECT id, start_addr, end_addr,
           (end_addr - start_addr) / 1048576 AS size_mb
    FROM memorymapping
    WHERE process_id = :id
      AND pathname = '[anonymous]'
      AND (end_addr - start_addr) > 10485760
    ORDER BY size_mb DESC
"""
params = ["id"]

[query.funcs-in-section]
description = "All functions in a given ELF section"
sql = """
    SELECT s.address, s.size, s.name
    FROM symbol s
    JOIN binary b ON b.id = s.binary_id
    WHERE b.name = :binary AND s.section = :section AND s.sym_type = 'F'
    ORDER BY s.address
"""
params = ["binary", "section"]
```

Usage:

```
baldrick --db session.db query heap-anon id=1
baldrick --db session.db query funcs-in-section binary=libc.so.6 section=.text
```
