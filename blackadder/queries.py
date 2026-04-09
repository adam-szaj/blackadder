"""
Query registry for blackadder.

Built-in named SQL queries plus user-defined queries from ~/.baldrick.toml
and ./baldrick.toml (local overrides global).
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class QueryDef:
    name: str
    sql: str
    description: str
    params: list[str] = field(default_factory=list)


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
