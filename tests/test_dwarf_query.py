"""Tests for binary-local DWARF type layout queries."""

from contextlib import asynccontextmanager

import pytest

from blackadder.dwarf_query import get_members
from blackadder.models import DwarfMember, dwarf_identity_key


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _Session:
    def __init__(self, manager):
        self.manager = manager

    async def execute(self, statement):
        self.manager.statements.append(statement)
        params = statement.compile().params.values()
        bin_id = next(value for value in params if value in self.manager.rows_by_binary)
        return _Result(self.manager.rows_by_binary[bin_id])


class _Manager:
    def __init__(self, rows_by_binary):
        self.rows_by_binary = rows_by_binary
        self.statements = []

    @asynccontextmanager
    async def get_session(self):
        yield _Session(self)


def test_dwarf_identity_key_is_stable_for_nullable_fields():
    first = dwarf_identity_key("structure_type", None, None, None)
    second = dwarf_identity_key("structure_type", None, None, None)

    assert first == second
    assert len(first) == 64
    assert first != dwarf_identity_key("structure_type", "", None, None)


@pytest.mark.asyncio
async def test_members_are_scoped_to_binary_reference():
    left = DwarfMember(binary_ref_id=101, name="left", byte_offset=8, member_type_ref=1)
    right = DwarfMember(binary_ref_id=202, name="right", byte_offset=4, member_type_ref=2)
    manager = _Manager({1: [left], 2: [right]})

    assert await get_members(manager, canonical_type_id=99, bin_id=1) == [left]
    assert await get_members(manager, canonical_type_id=99, bin_id=2) == [right]

    sql = str(manager.statements[0])
    assert "JOIN binary_dwarf_ref" in sql
    assert "binary_dwarf_ref.canonical_id" in sql
    assert "binary_dwarf_ref.binary_id" in sql
