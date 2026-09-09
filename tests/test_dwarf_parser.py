"""
Tests for blackadder.binutils.dwarf_parser.

Tests parse_dwarf_types_from_text() and parse_debug_line_from_text() using
minimal synthetic inputs and (where available) the real dump file from
tests/gdb-scripts/tests/deadlock_test-debug-g.dump.
"""

from __future__ import annotations

import pytest

from blackadder.binutils.dwarf_parser import (
    parse_debug_line_from_text,
    parse_dwarf_types_from_text,
)

# ============================================================================
# Helpers
# ============================================================================


def _types_by_name(types: list[dict]) -> dict[str, dict]:
    return {t["name"]: t for t in types if t.get("name")}


def _members_for(members: list[dict], parent_offset: int) -> list[dict]:
    return [m for m in members if m["parent_die_offset"] == parent_offset]


# ============================================================================
# Minimal synthetic DWARF snippets
# ============================================================================

MINIMAL_BASE_TYPES = """\
<1><a4>: Abbrev Number: 160 (DW_TAG_base_type)
    <a6>   DW_AT_byte_size   : 4
    <a7>   DW_AT_encoding    : 5	(signed)
    <a8>   DW_AT_name        : int
<1><34>: Abbrev Number: 37 (DW_TAG_base_type)
    <35>   DW_AT_byte_size   : 1
    <36>   DW_AT_encoding    : 8	(unsigned char)
    <37>   DW_AT_name        : (indirect string, offset: 0xdc68): unsigned char
"""

MINIMAL_TYPEDEF = """\
<1><1a4>: Abbrev Number: 7 (DW_TAG_typedef)
    <1a5>   DW_AT_name        : (indirect string, offset: 0x1e1f8): size_t
    <1a9>   DW_AT_decl_file   : 5
    <1aa>   DW_AT_decl_line   : 24
    <1ab>   DW_AT_decl_column : 7
    <1ac>   DW_AT_type        : <0xac>
"""

MINIMAL_STRUCT = """\
<1><a4>: Abbrev Number: 160 (DW_TAG_base_type)
    <a6>   DW_AT_byte_size   : 4
    <a7>   DW_AT_encoding    : 5	(signed)
    <a8>   DW_AT_name        : int
<1><42>: Abbrev Number: 37 (DW_TAG_base_type)
    <43>   DW_AT_byte_size   : 4
    <44>   DW_AT_encoding    : 7	(unsigned)
    <45>   DW_AT_name        : (indirect string, offset: 0xa9fa): unsigned int
<1><2f6>: Abbrev Number: 25 (DW_TAG_structure_type)
    <2f7>   DW_AT_name        : (indirect string, offset: 0x1ae87): __pthread_mutex_s
    <2fb>   DW_AT_byte_size   : 40
    <2fc>   DW_AT_decl_file   : 28
    <2fd>   DW_AT_decl_line   : 22
    <2fe>   DW_AT_decl_column : 8
    <2ff>   DW_AT_sibling     : <0x36c>
 <2><303>: Abbrev Number: 8 (DW_TAG_member)
    <304>   DW_AT_name        : (indirect string, offset: 0x1a524): __lock
    <308>   DW_AT_decl_file   : 28
    <309>   DW_AT_decl_line   : 24
    <30a>   DW_AT_decl_column : 7
    <30b>   DW_AT_type        : <0xa4>
    <30f>   DW_AT_data_member_location: 0
 <2><310>: Abbrev Number: 8 (DW_TAG_member)
    <311>   DW_AT_name        : (indirect string, offset: 0x10b9b): __count
    <315>   DW_AT_decl_file   : 28
    <316>   DW_AT_decl_line   : 25
    <317>   DW_AT_decl_column : 16
    <318>   DW_AT_type        : <0x42>
    <31c>   DW_AT_data_member_location: 4
 <2><31d>: Abbrev Number: 8 (DW_TAG_member)
    <31e>   DW_AT_name        : (indirect string, offset: 0x9b88): __owner
    <322>   DW_AT_decl_file   : 28
    <323>   DW_AT_decl_line   : 26
    <324>   DW_AT_decl_column : 7
    <325>   DW_AT_type        : <0xa4>
    <329>   DW_AT_data_member_location: 8
 <2><32a>: Abbrev Number: 0
"""

MINIMAL_POINTER = """\
<1><198>: Abbrev Number: 37 (DW_TAG_base_type)
    <199>   DW_AT_byte_size   : 1
    <19a>   DW_AT_encoding    : 6	(signed_char)
    <19b>   DW_AT_name        : (indirect string, offset: 0xd08e): char
<1><193>: Abbrev Number: 11 (DW_TAG_pointer_type)
    <194>   DW_AT_byte_size   : 8
    <194>   DW_AT_type        : <0x198>
"""

MINIMAL_NESTED = """\
<1><10>: Abbrev Number: 1 (DW_TAG_base_type)
    <11>   DW_AT_byte_size   : 4
    <12>   DW_AT_encoding    : 5	(signed)
    <13>   DW_AT_name        : int
<1><20>: Abbrev Number: 2 (DW_TAG_structure_type)
    <21>   DW_AT_name        : (indirect string, offset: 0x0): inner
    <25>   DW_AT_byte_size   : 8
 <2><30>: Abbrev Number: 3 (DW_TAG_member)
    <31>   DW_AT_name        : (indirect string, offset: 0x10): x
    <35>   DW_AT_type        : <0x10>
    <39>   DW_AT_data_member_location: 0
 <2><3a>: Abbrev Number: 3 (DW_TAG_member)
    <3b>   DW_AT_name        : (indirect string, offset: 0x12): y
    <3f>   DW_AT_type        : <0x10>
    <43>   DW_AT_data_member_location: 4
 <2><44>: Abbrev Number: 0
<1><50>: Abbrev Number: 4 (DW_TAG_structure_type)
    <51>   DW_AT_name        : (indirect string, offset: 0x20): outer
    <55>   DW_AT_byte_size   : 12
 <2><60>: Abbrev Number: 3 (DW_TAG_member)
    <61>   DW_AT_name        : (indirect string, offset: 0x30): a
    <65>   DW_AT_type        : <0x20>
    <69>   DW_AT_data_member_location: 0
 <2><70>: Abbrev Number: 3 (DW_TAG_member)
    <71>   DW_AT_name        : (indirect string, offset: 0x32): b
    <75>   DW_AT_type        : <0x10>
    <79>   DW_AT_data_member_location: 8
 <2><80>: Abbrev Number: 0
"""

MINIMAL_ANON_MEMBER = """\
<1><10>: Abbrev Number: 1 (DW_TAG_base_type)
    <11>   DW_AT_byte_size   : 4
    <12>   DW_AT_encoding    : 7	(unsigned)
    <13>   DW_AT_name        : unsigned int
<1><20>: Abbrev Number: 2 (DW_TAG_structure_type)
    <21>   DW_AT_byte_size   : 4
 <2><30>: Abbrev Number: 3 (DW_TAG_member)
    <35>   DW_AT_type        : <0x10>
    <39>   DW_AT_data_member_location: 0
 <2><3a>: Abbrev Number: 0
"""


# ============================================================================
# Base type tests
# ============================================================================


class TestBaseTypes:
    def test_int_parsed(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_BASE_TYPES)
        by_name = _types_by_name(types)
        assert "int" in by_name
        t = by_name["int"]
        assert t["tag"] == "base_type"
        assert t["byte_size"] == 4
        assert t["encoding"] == "signed"
        assert t["die_offset"] == 0xA4

    def test_unsigned_char_parsed(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_BASE_TYPES)
        by_name = _types_by_name(types)
        assert "unsigned char" in by_name
        t = by_name["unsigned char"]
        assert t["byte_size"] == 1
        assert t["encoding"] == "unsigned_char"

    def test_no_members_for_base_types(self):
        _, members, _ = parse_dwarf_types_from_text(MINIMAL_BASE_TYPES)
        assert members == []


# ============================================================================
# Typedef tests
# ============================================================================


class TestTypedef:
    def test_typedef_name_and_ref(self):
        types, _, _ = parse_dwarf_types_from_text(MINIMAL_TYPEDEF)
        by_name = _types_by_name(types)
        assert "size_t" in by_name
        t = by_name["size_t"]
        assert t["tag"] == "typedef"
        assert t["type_ref"] == 0xAC
        assert t["byte_size"] is None  # typedef has no byte_size

    def test_typedef_die_offset(self):
        types, _, _ = parse_dwarf_types_from_text(MINIMAL_TYPEDEF)
        by_name = _types_by_name(types)
        assert by_name["size_t"]["die_offset"] == 0x1A4


# ============================================================================
# Struct tests
# ============================================================================


class TestStruct:
    def test_struct_parsed(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_STRUCT)
        by_name = _types_by_name(types)
        assert "__pthread_mutex_s" in by_name
        s = by_name["__pthread_mutex_s"]
        assert s["tag"] == "structure_type"
        assert s["byte_size"] == 40
        assert s["die_offset"] == 0x2F6

    def test_struct_member_count(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_STRUCT)
        by_name = _types_by_name(types)
        struct_offset = by_name["__pthread_mutex_s"]["die_offset"]
        struct_members = _members_for(members, struct_offset)
        assert len(struct_members) == 3

    def test_struct_member_names_and_offsets(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_STRUCT)
        by_name = _types_by_name(types)
        struct_offset = by_name["__pthread_mutex_s"]["die_offset"]
        struct_members = {m["name"]: m for m in _members_for(members, struct_offset)}

        assert "__lock" in struct_members
        assert struct_members["__lock"]["byte_offset"] == 0
        assert struct_members["__lock"]["member_type_ref"] == 0xA4

        assert "__count" in struct_members
        assert struct_members["__count"]["byte_offset"] == 4

        assert "__owner" in struct_members
        assert struct_members["__owner"]["byte_offset"] == 8

    def test_struct_member_type_refs(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_STRUCT)
        by_name = _types_by_name(types)
        struct_offset = by_name["__pthread_mutex_s"]["die_offset"]
        struct_members = {m["name"]: m for m in _members_for(members, struct_offset)}
        # __lock → int (0xa4), __count → unsigned int (0x42)
        assert struct_members["__lock"]["member_type_ref"] == 0xA4
        assert struct_members["__count"]["member_type_ref"] == 0x42


# ============================================================================
# Pointer type tests
# ============================================================================


class TestPointerType:
    def test_pointer_size(self):
        types, _, _ = parse_dwarf_types_from_text(MINIMAL_POINTER)
        ptrs = [t for t in types if t["tag"] == "pointer_type"]
        assert len(ptrs) == 1
        assert ptrs[0]["byte_size"] == 8

    def test_pointer_type_ref(self):
        types, _, _ = parse_dwarf_types_from_text(MINIMAL_POINTER)
        ptrs = [t for t in types if t["tag"] == "pointer_type"]
        assert ptrs[0]["type_ref"] == 0x198  # → char


# ============================================================================
# Nested struct tests
# ============================================================================


class TestNestedStruct:
    def test_both_structs_parsed(self):
        types, _, _ = parse_dwarf_types_from_text(MINIMAL_NESTED)
        by_name = _types_by_name(types)
        assert "inner" in by_name
        assert "outer" in by_name

    def test_inner_members(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_NESTED)
        by_name = _types_by_name(types)
        inner_offset = by_name["inner"]["die_offset"]
        inner_members = _members_for(members, inner_offset)
        assert len(inner_members) == 2
        offsets = {m["name"]: m["byte_offset"] for m in inner_members}
        assert offsets["x"] == 0
        assert offsets["y"] == 4

    def test_outer_members(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_NESTED)
        by_name = _types_by_name(types)
        outer_offset = by_name["outer"]["die_offset"]
        outer_members = _members_for(members, outer_offset)
        assert len(outer_members) == 2
        offsets = {m["name"]: m["byte_offset"] for m in outer_members}
        assert offsets["a"] == 0
        assert offsets["b"] == 8


# ============================================================================
# Anonymous member test
# ============================================================================


class TestAnonMember:
    def test_anonymous_member_name_is_none(self):
        types, members, _ = parse_dwarf_types_from_text(MINIMAL_ANON_MEMBER)
        assert len(members) == 1
        assert members[0]["name"] is None
        assert members[0]["byte_offset"] == 0


# ============================================================================
# Real dump file test (integration)
# ============================================================================


DUMP_PATH = "tests/gdb-scripts/tests/deadlock_test-debug-g.dump"


@pytest.mark.integration
def test_real_dump_pthread_mutex_s():
    """Parse the real objdump output and verify __pthread_mutex_s layout."""
    try:
        with open(DUMP_PATH) as f:
            text = f.read()
    except FileNotFoundError:
        pytest.skip(f"Dump file not found: {DUMP_PATH}")

    types, members, _ = parse_dwarf_types_from_text(text)
    by_name = _types_by_name(types)

    assert "__pthread_mutex_s" in by_name, "Expected __pthread_mutex_s in types"
    s = by_name["__pthread_mutex_s"]
    assert s["tag"] == "structure_type"
    assert s["byte_size"] == 40

    struct_members = {m["name"]: m for m in _members_for(members, s["die_offset"])}
    assert "__lock" in struct_members
    assert "__owner" in struct_members
    assert struct_members["__owner"]["byte_offset"] == 8


@pytest.mark.integration
def test_real_dump_type_count():
    """Real dump should produce a substantial number of types."""
    try:
        with open(DUMP_PATH) as f:
            text = f.read()
    except FileNotFoundError:
        pytest.skip(f"Dump file not found: {DUMP_PATH}")

    types, members, _ = parse_dwarf_types_from_text(text)
    assert len(types) > 100, "Expected many types in real binary dump"
    assert len(members) > 50, "Expected many struct members in real binary dump"


# ============================================================================
# debug_line parser tests
# ============================================================================


MINIMAL_DEBUG_LINE = """\
Contents of the .debug_line section:

deadlock_test.cpp:
File name                        Line number    Starting address    View    Stmt
deadlock_test.cpp                        129              0x2437               x
deadlock_test.cpp                        129              0x243f
deadlock_test.cpp                        130              0x2450               x
deadlock_test.cpp                          -              0x2460

/usr/include/c++/15/bits/std_thread.h:
std_thread.h                             154              0x2b77               x
std_thread.h                             159              0x2b7b

/home/user/project/main.cpp:
main.cpp                                  42              0x1234               x
"""


class TestDebugLineParser:
    def test_basic_records_parsed(self):
        records = parse_debug_line_from_text(MINIMAL_DEBUG_LINE)
        # line 129 appears twice (0x2437 and 0x243f), line 130 once, line "-" skipped
        # std_thread.h 154 and 159
        # main.cpp 42
        assert len(records) == 6

    def test_file_context_preserved(self):
        records = parse_debug_line_from_text(MINIMAL_DEBUG_LINE)
        cpp_recs = [r for r in records if "deadlock_test.cpp" in r["source_file"]]
        assert len(cpp_recs) == 3  # lines 129, 129, 130

    def test_end_sequence_marker_skipped(self):
        records = parse_debug_line_from_text(MINIMAL_DEBUG_LINE)
        line_numbers = [r["line_number"] for r in records]
        # '-' marker should be excluded
        assert all(isinstance(n, int) for n in line_numbers)

    def test_address_parsed_as_int(self):
        records = parse_debug_line_from_text(MINIMAL_DEBUG_LINE)
        assert records[0]["address"] == 0x2437
        assert records[1]["address"] == 0x243F

    def test_line_number_parsed(self):
        records = parse_debug_line_from_text(MINIMAL_DEBUG_LINE)
        assert records[0]["line_number"] == 129
        assert records[2]["line_number"] == 130

    def test_full_path_used_as_context(self):
        records = parse_debug_line_from_text(MINIMAL_DEBUG_LINE)
        thread_recs = [r for r in records if "std_thread" in r["source_file"]]
        assert len(thread_recs) == 2
        assert thread_recs[0]["source_file"] == "/usr/include/c++/15/bits/std_thread.h"

    def test_empty_input(self):
        records = parse_debug_line_from_text("")
        assert records == []

    def test_no_debug_line_section(self):
        records = parse_debug_line_from_text("Some other content\nwithout debug line data\n")
        assert records == []


@pytest.mark.integration
def test_real_debug_line():
    """Run readelf --debug-dump=decodedline on the real test binary."""
    import shutil
    import subprocess

    binary = "tests/gdb-scripts/tests/deadlock_test"
    if not shutil.which("readelf"):
        pytest.skip("readelf not available")

    try:
        result = subprocess.run(
            ["readelf", "--debug-dump=decodedline", binary],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("Could not run readelf on test binary")

    if result.returncode != 0:
        pytest.skip("readelf returned non-zero")

    records = parse_debug_line_from_text(result.stdout)
    assert len(records) > 50, "Expected many line records from real binary"
    # Should contain entries from deadlock_test.cpp
    cpp_recs = [r for r in records if "deadlock_test.cpp" in r.get("source_file", "")]
    assert len(cpp_recs) > 0


# ============================================================================
# Idempotency / edge cases
# ============================================================================


class TestEdgeCases:
    def test_empty_input(self):
        types, members, variables = parse_dwarf_types_from_text("")
        assert types == []
        assert members == []
        assert variables == []

    def test_no_interesting_tags(self):
        text = "<1><10>: Abbrev Number: 1 (DW_TAG_compile_unit)\n    <11>   DW_AT_name : foo.c\n"
        types, members, variables = parse_dwarf_types_from_text(text)
        assert types == []
        assert members == []
        assert variables == []

    def test_struct_without_name_is_stored(self):
        """Anonymous structs (no DW_AT_name) should still be stored for reference."""
        text = """\
<1><10>: Abbrev Number: 1 (DW_TAG_structure_type)
    <11>   DW_AT_byte_size   : 4
 <2><20>: Abbrev Number: 2 (DW_TAG_member)
    <21>   DW_AT_name        : x
    <25>   DW_AT_type        : <0x30>
    <29>   DW_AT_data_member_location: 0
 <2><2a>: Abbrev Number: 0
"""
        types, members, _ = parse_dwarf_types_from_text(text)
        structs = [t for t in types if t["tag"] == "structure_type"]
        assert len(structs) == 1
        assert structs[0]["name"] is None
        assert len(members) == 1
