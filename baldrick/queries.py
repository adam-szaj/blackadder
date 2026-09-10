"""
Query registry for baldrick.

Built-in named SQL queries plus user-defined queries from ~/.baldrick.toml
and ./baldrick.toml (local overrides global).
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class QueryDef:
    name: str
    sql: str
    description: str
    params: list[str] = field(default_factory=list)
    address_params: list[str] = field(default_factory=list)


# ============================================================================
# Built-in queries
# ============================================================================

BUILTIN_QUERIES: list[QueryDef] = [
    QueryDef(
        name="snapshots",
        sql="SELECT id, pid, tag, created_at, description, source_type FROM processsnapshot ORDER BY id",
        description="All process snapshots",
    ),
    QueryDef(
        name="mappings",
        sql=(
            "SELECT id, start_addr, end_addr, perms, offset, dev, inode, pathname "
            "FROM memorymapping WHERE process_id = :id ORDER BY start_addr"
        ),
        description="Memory mappings for a process snapshot",
        params=["id"],
    ),
    QueryDef(
        name="binaries",
        sql="SELECT id, md5sum, name, debug_link FROM binary ORDER BY name",
        description="All binaries in the database",
    ),
    QueryDef(
        name="symbols",
        sql=(
            "SELECT s.id, s.address, s.scope, s.sym_type, s.section, s.size, s.name "
            "FROM symbol s "
            "JOIN binary b ON b.id = s.binary_id "
            "WHERE b.name = :binary "
            "ORDER BY s.address"
        ),
        description="Symbols for a binary (by name, e.g. libc.so.6)",
        params=["binary"],
    ),
    QueryDef(
        name="sections",
        sql=(
            "SELECT sh.id, sh.idx, sh.name, sh.size, sh.vma, sh.lma, sh.off, sh.align "
            "FROM sectionheader sh "
            "JOIN binary b ON b.id = sh.binary_id "
            "WHERE b.name = :binary "
            "ORDER BY sh.idx"
        ),
        description="ELF sections for a binary (by name)",
        params=["binary"],
    ),
    QueryDef(
        name="backtrace",
        sql=(
            "SELECT frame_num, address, resolved_symbol, resolved_file, resolved_line, match_confidence "
            "FROM backtraceentry WHERE process_id = :id ORDER BY frame_num"
        ),
        description="Decoded backtrace frames for a process snapshot",
        params=["id"],
    ),
    QueryDef(
        name="libs",
        sql=(
            "SELECT DISTINCT pathname "
            "FROM memorymapping "
            "WHERE process_id = :id AND pathname NOT LIKE '[%' AND pathname != '[anonymous]' "
            "ORDER BY pathname"
        ),
        description="Shared libraries loaded by a process snapshot",
        params=["id"],
    ),
    QueryDef(
        name="rwx",
        sql=(
            "SELECT id, start_addr, end_addr, perms, pathname "
            "FROM memorymapping "
            "WHERE process_id = :id AND perms LIKE '%rwx%' "
            "ORDER BY start_addr"
        ),
        description="RWX (read-write-execute) memory regions — potential anomalies",
        params=["id"],
    ),
    QueryDef(
        name="process-binaries",
        sql=(
            "SELECT pb.id, pb.binary_load_addr, pb.match_score, pb.match_method, "
            "       b.name AS binary_name, m.pathname "
            "FROM processbinary pb "
            "LEFT JOIN binary b ON b.id = pb.binary_id "
            "JOIN memorymapping m ON m.id = pb.mapping_id "
            "WHERE pb.process_id = :id "
            "ORDER BY pb.binary_load_addr"
        ),
        description="Binaries linked to a process snapshot with match info",
        params=["id"],
    ),
    QueryDef(
        name="threads",
        sql=(
            "SELECT tid, name, wchan, syscall, stack_start, stack_end "
            "FROM thread WHERE process_id = :id ORDER BY tid"
        ),
        description="Threads in a process snapshot with kernel wait info",
        params=["id"],
    ),
    QueryDef(
        name="symbol-cache",
        sql=(
            "SELECT sc.offset, sc.symbol, sc.source_file, sc.source_line, b.name AS binary_name "
            "FROM symbolcache sc "
            "JOIN binary b ON b.id = sc.binary_id "
            "WHERE b.name = :binary "
            "ORDER BY sc.offset"
        ),
        description="Persistent symbol cache entries for a binary",
        params=["binary"],
    ),
    QueryDef(
        name="deadlock-threads",
        sql=(
            "SELECT t.tid, t.name, t.wchan, t.syscall, COUNT(b.id) AS frame_count "
            "FROM thread t "
            "LEFT JOIN backtraceentry b ON b.thread_id = t.id "
            "WHERE t.process_id = :id "
            "  AND (t.wchan LIKE '%futex%' OR t.wchan LIKE '%mutex%' OR t.syscall LIKE '202 %' OR t.syscall LIKE '240 %' OR t.syscall LIKE '98 %') "
            "GROUP BY t.id "
            "ORDER BY t.tid"
        ),
        description="Threads in snapshot likely blocked on a mutex/futex (deadlock candidates)",
        params=["id"],
    ),
    QueryDef(
        name="symbol-cache-stats",
        sql=(
            "SELECT b.name AS binary_name, COUNT(*) AS cached_symbols "
            "FROM symbolcache sc "
            "JOIN binary b ON b.id = sc.binary_id "
            "GROUP BY b.name "
            "ORDER BY cached_symbols DESC"
        ),
        description="Symbol cache hit counts per binary",
    ),
    QueryDef(
        name="types",
        sql=(
            "SELECT ct.name, ct.tag, ct.byte_size, COUNT(m.id) AS field_count "
            "FROM canonical_dwarf_type ct "
            "JOIN binary_dwarf_ref r ON r.canonical_id = ct.id "
            "LEFT JOIN dwarfmember m ON m.binary_ref_id = r.id "
            "JOIN binary b ON b.id = r.binary_id "
            "WHERE b.name = :binary AND ct.tag IN ('structure_type','union_type') "
            "GROUP BY ct.id ORDER BY ct.name"
        ),
        description="Structs and unions defined in a binary (requires load-types)",
        params=["binary"],
    ),
    QueryDef(
        name="struct",
        sql=(
            "SELECT m.byte_offset, m.name, tr.name AS type_name, tr.byte_size, tr.tag "
            "FROM dwarfmember m "
            "JOIN binary_dwarf_ref r ON r.id = m.binary_ref_id "
            "JOIN canonical_dwarf_type t ON t.id = r.canonical_id "
            "JOIN binary b ON b.id = r.binary_id AND b.name = :binary "
            "LEFT JOIN binary_dwarf_ref rr ON rr.binary_id = b.id AND rr.die_offset = m.member_type_ref "
            "LEFT JOIN canonical_dwarf_type tr ON tr.id = rr.canonical_id "
            "WHERE t.name = :name "
            "ORDER BY m.byte_offset"
        ),
        description="Fields of a named struct/union with byte offsets",
        params=["name", "binary"],
    ),
    QueryDef(
        name="type-offset",
        sql=(
            "SELECT m.byte_offset, m.name, tr.name AS type_name, tr.byte_size "
            "FROM dwarfmember m "
            "JOIN binary_dwarf_ref r ON r.id = m.binary_ref_id "
            "JOIN canonical_dwarf_type t ON t.id = r.canonical_id "
            "JOIN binary b ON b.id = r.binary_id AND b.name = :binary "
            "LEFT JOIN binary_dwarf_ref rr ON rr.binary_id = b.id AND rr.die_offset = m.member_type_ref "
            "LEFT JOIN canonical_dwarf_type tr ON tr.id = rr.canonical_id "
            "WHERE t.name = :name AND m.byte_offset <= CAST(:offset AS INTEGER) "
            "ORDER BY m.byte_offset DESC LIMIT 1"
        ),
        description="Which struct field lies at (or just before) a given byte offset",
        params=["name", "offset", "binary"],
    ),
    QueryDef(
        name="line2addr",
        sql=(
            "SELECT sf.path AS source_file, d.line_number, d.address "
            "FROM debugline d "
            "JOIN binary b ON b.id = d.binary_id "
            "JOIN sourcefile sf ON sf.id = d.source_file_id "
            "WHERE b.name = :binary "
            "  AND sf.path LIKE '%' || :file || '%' "
            "  AND d.line_number = CAST(:line AS INTEGER) "
            "ORDER BY d.address"
        ),
        description="Addresses corresponding to a source file:line (reverse addr2line)",
        params=["binary", "file", "line"],
    ),
    QueryDef(
        name="addr2line",
        sql=(
            "SELECT b.name AS binary, sc.offset, sc.symbol, sc.source_file, sc.source_line "
            "FROM symbolcache sc "
            "JOIN binary b ON b.id = sc.binary_id "
            "WHERE b.name = :binary "
            "  AND sc.offset = CAST(:addr AS INTEGER) "
            "ORDER BY sc.source_file, sc.source_line"
        ),
        description="Binary offset → symbol + source location (symbol cache). addr = offset within binary.",
        params=["binary", "addr"],
    ),
    QueryDef(
        name="addr2line-snap",
        sql=(
            "SELECT b.name AS binary, "
            "       CAST(:addr AS INTEGER) - pb.binary_load_addr AS offset, "
            "       sc.symbol, sc.source_file, sc.source_line "
            "FROM processbinary pb "
            "JOIN binary b ON b.id = pb.binary_id "
            "JOIN memorymapping m ON m.id = pb.mapping_id "
            "JOIN symbolcache sc ON sc.binary_id = b.id "
            "  AND sc.offset = CAST(:addr AS INTEGER) - pb.binary_load_addr "
            "WHERE pb.process_id = CAST(:id AS INTEGER) "
            "  AND CAST(:addr AS INTEGER) >= m.start_addr "
            "  AND CAST(:addr AS INTEGER) <  m.end_addr "
            "ORDER BY sc.source_file, sc.source_line"
        ),
        description="Virtual address → symbol + source location via snapshot mapping. addr = runtime VA.",
        params=["id", "addr"],
        address_params=["addr"],
    ),
]

_BUILTIN_MAP: dict[str, QueryDef] = {q.name: q for q in BUILTIN_QUERIES}


# ============================================================================
# TOML loading
# ============================================================================


def _load_toml_queries(path: Path) -> dict[str, QueryDef]:
    """Parse a baldrick.toml file and return its [query.*] entries."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        import warnings

        warnings.warn(f"Could not parse {path}: {e}", stacklevel=2)
        return {}

    result: dict[str, QueryDef] = {}
    for name, entry in data.get("query", {}).items():
        if not isinstance(entry, dict) or "sql" not in entry:
            continue
        result[name] = QueryDef(
            name=name,
            sql=entry["sql"],
            description=entry.get("description", ""),
            params=list(entry.get("params", [])),
        )
    return result


def load_query_registry() -> dict[str, QueryDef]:
    """
    Build the full query registry.

    Priority (highest wins):
      1. ./baldrick.toml  (local, project-level)
      2. ~/.baldrick.toml (user-level)
      3. Built-in queries
    """
    registry: dict[str, QueryDef] = dict(_BUILTIN_MAP)

    # User-level (~/.baldrick.toml)
    user_toml = Path.home() / ".baldrick.toml"
    registry.update(_load_toml_queries(user_toml))

    # Local (./baldrick.toml) — overrides everything
    local_toml = Path.cwd() / "baldrick.toml"
    if local_toml != user_toml:
        registry.update(_load_toml_queries(local_toml))

    return registry


# ============================================================================
# Alias loading
# ============================================================================


def _load_toml_aliases(path: Path) -> dict[str, list[str]]:
    """
    Parse [alias] section from a baldrick.toml file.

    Each alias value is a string command (like gitconfig: alias.ci = commit -a)
    split into a list of tokens.

    Example baldrick.toml:
        [alias]
        dl = "analyse-deadlock"
        dls = "analyse-deadlock --snapshot-id"
        qt = "query threads --param"
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        import warnings

        warnings.warn(f"Could not parse {path}: {e}", stacklevel=2)
        return {}

    result: dict[str, list[str]] = {}
    for name, value in data.get("alias", {}).items():
        if isinstance(value, str):
            import shlex

            result[name] = shlex.split(value)
        elif isinstance(value, list):
            result[name] = [str(t) for t in value]
    return result


def load_aliases() -> dict[str, list[str]]:
    """
    Build alias map from ~/.baldrick.toml and ./baldrick.toml.

    Local overrides user-level (same priority as queries).
    """
    aliases: dict[str, list[str]] = {}

    user_toml = Path.home() / ".baldrick.toml"
    aliases.update(_load_toml_aliases(user_toml))

    local_toml = Path.cwd() / "baldrick.toml"
    if local_toml != user_toml:
        aliases.update(_load_toml_aliases(local_toml))

    return aliases


def expand_aliases(argv: list[str]) -> list[str]:
    """
    Expand a single alias at the first non-option argument position.

    Only one level of expansion (no recursive aliases).
    Mirrors git behaviour: baldrick <alias> [extra args]

    Args:
        argv: sys.argv[1:] — args after the program name

    Returns:
        Expanded argument list, or original if no alias matched.
    """
    aliases = load_aliases()
    if not argv:
        return argv

    # Global baldrick flags that consume the next token (value flags).
    # Boolean flags (--debug) do not consume next token.
    _VALUE_FLAGS = frozenset({"--db", "-d", "--log-level", "--log-file"})

    # Find first positional arg, skipping global flag tokens.
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            # Flag with embedded = never consumes next token
            if "=" not in arg and arg in _VALUE_FLAGS:
                skip_next = True
            continue
        if arg in aliases:
            expansion = aliases[arg]
            return argv[:i] + expansion + argv[i + 1 :]
        break  # first non-flag arg is not an alias

    return argv
