"""
BlackadderQuery — synchronous Python API over the blackadder SQLite database.

Uses Polars + sqlite3 (Polars does not support aiosqlite).

Usage:
    from blackadder import BlackadderQuery
    import polars as pl

    q = BlackadderQuery("session.db")
    df = q.run("symbols", binary="libc.so.6")
    print(df.filter(pl.col("name").str.contains("malloc")))
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import polars as pl

from blackadder.queries import QueryDef, load_query_registry


def _db_path(path_or_url: str) -> str:
    """Strip SQLAlchemy URL prefixes and return a plain filesystem path."""
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if path_or_url.startswith(prefix):
            return path_or_url[len(prefix):]
    return path_or_url


def run_query(
    db_path: str,
    sql: str,
    params: dict[str, Any] | None = None,
) -> pl.DataFrame:
    """
    Execute a named-parameter SQL query against the database and return a DataFrame.

    Args:
        db_path: Path to SQLite database (or sqlite+aiosqlite:/// URL)
        sql:     SQL string with :param_name placeholders
        params:  Dict of parameter values

    Returns:
        polars.DataFrame with query results
    """
    clean_path = _db_path(db_path)
    conn = sqlite3.connect(clean_path)
    try:
        # Polars read_database wants the connection and an optional execute_options
        # for parameter binding.  Named params work via sqlite3 directly.
        cursor = conn.execute(sql, params or {})
        columns = [d[0] for d in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        return pl.DataFrame(
            {col: [row[i] for row in rows] for i, col in enumerate(columns)}
        )
    finally:
        conn.close()


class BlackadderQuery:
    """
    Convenience wrapper for ad-hoc Polars queries over a blackadder database.

    Example:
        q = BlackadderQuery("session.db")
        df = q.run("symbols", binary="libc.so.6")
        df = q.run("mappings", pid=1)
        df = q.run_sql("SELECT * FROM processsnapshot WHERE tag = :tag", tag="crash")
    """

    def __init__(self, db: str) -> None:
        self._db = _db_path(db)
        self._registry: dict[str, QueryDef] | None = None

    @property
    def registry(self) -> dict[str, QueryDef]:
        if self._registry is None:
            self._registry = load_query_registry()
        return self._registry

    def run(self, query_name: str, **params: Any) -> pl.DataFrame:
        """
        Run a named query (built-in or from ~/.baldrick.toml / ./baldrick.toml).

        Args:
            query_name: Query name (e.g. "snapshots", "symbols")
            **params:   Named parameters expected by the query

        Raises:
            KeyError: If query_name is not found in registry
        """
        qdef = self.registry[query_name]
        return run_query(self._db, qdef.sql, params)

    def run_sql(self, sql: str, **params: Any) -> pl.DataFrame:
        """Run an arbitrary SQL query."""
        return run_query(self._db, sql, params)

    def list_queries(self) -> list[QueryDef]:
        """Return all available queries sorted by name."""
        return sorted(self.registry.values(), key=lambda q: q.name)
