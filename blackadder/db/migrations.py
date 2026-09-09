"""Small, versioned SQLite migrations for Blackadder's unified database."""

from sqlalchemy.engine import Connection

from blackadder.models import dwarf_identity_key

LATEST_SCHEMA_VERSION = 1


def _table_names(connection: Connection) -> set[str]:
    rows = connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in rows}


def _column_names(connection: Connection, table: str) -> set[str]:
    rows = connection.exec_driver_sql(f'PRAGMA table_info("{table}")')
    return {row[1] for row in rows}


def _migrate_binary_local_dwarf_members(connection: Connection) -> None:
    tables = _table_names(connection)
    if "dwarfmember" not in tables or "binary_dwarf_ref" not in tables:
        return
    if "canonical_type_id" not in _column_names(connection, "dwarfmember"):
        return

    connection.exec_driver_sql(
        "CREATE TABLE dwarfmember_new ("
        "id INTEGER PRIMARY KEY, "
        "binary_ref_id INTEGER NOT NULL REFERENCES binary_dwarf_ref(id), "
        "name VARCHAR(256), "
        "byte_offset INTEGER NOT NULL, "
        "member_type_ref INTEGER NOT NULL)"
    )
    connection.exec_driver_sql(
        "INSERT INTO dwarfmember_new "
        "(binary_ref_id, name, byte_offset, member_type_ref) "
        "SELECT ref.id, member.name, member.byte_offset, member.member_type_ref "
        "FROM dwarfmember AS member "
        "JOIN binary_dwarf_ref AS ref "
        "ON ref.canonical_id = member.canonical_type_id"
    )
    connection.exec_driver_sql("DROP TABLE dwarfmember")
    connection.exec_driver_sql("ALTER TABLE dwarfmember_new RENAME TO dwarfmember")
    connection.exec_driver_sql(
        "CREATE INDEX ix_dwarfmember_binary_ref_id ON dwarfmember (binary_ref_id)"
    )


def _migrate_canonical_identity(connection: Connection) -> None:
    tables = _table_names(connection)
    if "canonical_dwarf_type" not in tables:
        return
    if "identity_key" not in _column_names(connection, "canonical_dwarf_type"):
        connection.exec_driver_sql(
            "ALTER TABLE canonical_dwarf_type ADD COLUMN identity_key VARCHAR(64)"
        )

    rows = connection.exec_driver_sql(
        "SELECT id, tag, name, byte_size, encoding FROM canonical_dwarf_type ORDER BY id"
    ).all()
    keeper_by_key: dict[str, int] = {}
    tables = _table_names(connection)
    for row in rows:
        identity_key = dwarf_identity_key(row[1], row[2], row[3], row[4])
        keeper_id = keeper_by_key.get(identity_key)
        if keeper_id is None:
            keeper_by_key[identity_key] = row[0]
            connection.exec_driver_sql(
                "UPDATE canonical_dwarf_type SET identity_key=? WHERE id=?",
                (identity_key, row[0]),
            )
            continue

        if "binary_dwarf_ref" in tables:
            connection.exec_driver_sql(
                "UPDATE binary_dwarf_ref SET canonical_id=? WHERE canonical_id=?",
                (keeper_id, row[0]),
            )
        if "dwarfvariable" in tables:
            connection.exec_driver_sql(
                "UPDATE dwarfvariable SET canonical_type_id=? WHERE canonical_type_id=?",
                (keeper_id, row[0]),
            )
        connection.exec_driver_sql("DELETE FROM canonical_dwarf_type WHERE id=?", (row[0],))

    connection.exec_driver_sql(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "ix_canonical_dwarf_type_identity_key "
        "ON canonical_dwarf_type (identity_key)"
    )


def run_migrations(connection: Connection) -> None:
    """Upgrade a SQLite connection to the latest supported schema version."""
    version = connection.exec_driver_sql("PRAGMA user_version").scalar_one()
    if version > LATEST_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {version} is newer than supported "
            f"version {LATEST_SCHEMA_VERSION}"
        )
    if version < 1:
        _migrate_binary_local_dwarf_members(connection)
        _migrate_canonical_identity(connection)
        connection.exec_driver_sql(f"PRAGMA user_version={LATEST_SCHEMA_VERSION}")
