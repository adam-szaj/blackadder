"""
DWARF debug info parser for type extraction and source line mapping.

Provides two parsers:
  parse_dwarf_types()  — extracts type definitions (structs, typedefs, base types, etc.)
                         from objdump --dwarf=info output
  parse_debug_line()   — extracts source line → address mappings
                         from readelf --debug-dump=decodedline output

Both functions are synchronous (CPU-bound regex work) and intended to be
called via asyncio.to_thread() from async contexts.
"""

from __future__ import annotations

import re
import logging

from blackadder.binutils.parser import BinToolsParser

logger = logging.getLogger("blackadder.dwarf_parser")

# DWARF tags we care about — everything else is skipped
_INTERESTING_TAGS = frozenset({
    "structure_type",
    "union_type",
    "base_type",
    "typedef",
    "pointer_type",
    "const_type",
    "volatile_type",
    "restrict_type",
    "array_type",
    "enumeration_type",
    "member",
    "subrange_type",
})

# DW_AT_encoding numeric code → human-readable string
_ENCODING_MAP = {
    1: "address",
    2: "boolean",
    3: "complex_float",
    4: "float",
    5: "signed",
    6: "signed_char",
    7: "unsigned",
    8: "unsigned_char",
    9: "imaginary_float",
    10: "packed_decimal",
    11: "numeric_string",
    12: "edited",
    13: "signed_fixed",
    14: "unsigned_fixed",
    15: "decimal_float",
    16: "utf",
    17: "ucs",
    18: "ascii",
}

# Regex: DIE header line  <depth><offset>: Abbrev Number: N (DW_TAG_xxx)
_RE_DIE = re.compile(
    r"<(\d+)><([0-9a-f]+)>:\s+Abbrev Number:\s+\d+\s+\(DW_TAG_(\w+)\)"
)

# Regex: attribute line (various formats)
# Examples:
#   <1234>   DW_AT_name        : (indirect string, offset: 0xabc): foo
#   <1234>   DW_AT_name        : bar
#   <1234>   DW_AT_byte_size   : 8
#   <1234>   DW_AT_type        : <0x1abc>
#   <1234>   DW_AT_data_member_location: 4
#   <1234>   DW_AT_encoding    : 7	(unsigned)
_RE_ATTR = re.compile(r"(?:<[0-9a-f]+>\s+)?DW_AT_(\w+)\s*:\s*(.*)", re.IGNORECASE)

# Regex: type reference  <0xHEX>
_RE_TYPE_REF = re.compile(r"<0x([0-9a-f]+)>")

# Regex: indirect string value  (indirect string, offset: 0xXXX): NAME
_RE_INDIRECT_STR = re.compile(r"\(indirect (?:string|line string)[^)]*\):\s*(.*)")

# Regex: decoded line table row  FILENAME  LINE  0xADDR
_RE_LINE_ROW = re.compile(r"^(\S+)\s+(\d+)\s+(0x[0-9a-f]+)", re.IGNORECASE)

# Regex: decoded line table header (file section context)
# e.g. "/usr/include/pthread.h:" or "deadlock_test.cpp:"
_RE_LINE_HEADER = re.compile(r"^(/\S+|[^/\s]\S+):$")


def _parse_attr_value(raw: str) -> str:
    """Extract clean attribute value from raw DW_AT line value."""
    raw = raw.strip()
    # Indirect string: "(indirect string, offset: 0xXXX): NAME"
    m = _RE_INDIRECT_STR.match(raw)
    if m:
        return m.group(1).strip()
    return raw


def _parse_name(raw: str) -> str | None:
    """Parse DW_AT_name value, returning None for empty/missing."""
    val = _parse_attr_value(raw).strip()
    return val if val else None


def _parse_type_ref(raw: str) -> int | None:
    """Parse DW_AT_type value like '<0x1abc>' → int."""
    m = _RE_TYPE_REF.search(raw)
    return int(m.group(1), 16) if m else None


def _parse_int(raw: str) -> int | None:
    """Parse an integer attribute value (decimal or hex)."""
    raw = raw.strip().split("\t")[0].split(" ")[0]  # strip trailing comments
    if raw.startswith("0x") or raw.startswith("0X"):
        try:
            return int(raw, 16)
        except ValueError:
            return None
    try:
        return int(raw)
    except ValueError:
        return None


def _parse_encoding(raw: str) -> str | None:
    """Parse DW_AT_encoding value like '7\t(unsigned)' → 'unsigned'."""
    # Try to extract parenthesized label first: "7\t(unsigned)"
    paren = re.search(r"\((\w+)\)", raw)
    if paren:
        return paren.group(1)
    # Fall back to numeric mapping
    code = _parse_int(raw)
    if code is not None:
        return _ENCODING_MAP.get(code)
    return None


def parse_dwarf_types_from_text(text: str) -> tuple[list[dict], list[dict]]:
    """
    Parse objdump --dwarf=info output into type and member records.

    Returns:
        (types, members) where:
          types  — list of dicts matching DwarfType fields (minus id/binary_id)
          members — list of dicts matching DwarfMember fields (minus id/type_id),
                    with extra 'parent_die_offset' key linking to parent DwarfType
    """
    types: list[dict] = []
    members: list[dict] = []

    # Parser state
    current_die: dict | None = None
    # Stack of (depth, die_offset) for struct/union parents
    parent_stack: list[tuple[int, int]] = []  # (depth, die_offset)

    def flush_die() -> None:
        """Finalize current DIE and emit to output lists."""
        nonlocal current_die
        if current_die is None:
            return
        tag = current_die.get("tag", "")
        die_offset = current_die.get("die_offset")
        depth = current_die.get("depth", 0)

        if tag == "member":
            # Find parent struct/union at depth - 1
            parent_offset = None
            for pdepth, poffset in reversed(parent_stack):
                if pdepth == depth - 1:
                    parent_offset = poffset
                    break
            type_ref = current_die.get("type_ref")
            if parent_offset is not None and "byte_offset" in current_die and type_ref is not None:
                members.append({
                    "parent_die_offset": parent_offset,
                    "name": current_die.get("name"),
                    "byte_offset": current_die["byte_offset"],
                    "member_type_ref": type_ref,
                })
        elif tag in _INTERESTING_TAGS and tag != "member":
            types.append({
                "die_offset": die_offset,
                "tag": tag,
                "name": current_die.get("name"),
                "byte_size": current_die.get("byte_size"),
                "type_ref": current_die.get("type_ref"),
                "encoding": current_die.get("encoding"),
            })
            # Push to parent stack if struct/union (can have member children)
            if tag in ("structure_type", "union_type"):
                parent_stack.append((depth, die_offset))

        current_die = None

    for line in text.splitlines():
        # Check for new DIE header
        m = _RE_DIE.search(line)
        if m:
            flush_die()
            depth = int(m.group(1))
            die_offset = int(m.group(2), 16)
            tag = m.group(3)

            # Pop parent stack entries that are at same or deeper depth
            while parent_stack and parent_stack[-1][0] >= depth:
                parent_stack.pop()

            if tag in _INTERESTING_TAGS:
                current_die = {"tag": tag, "die_offset": die_offset, "depth": depth}
            # else: not interesting, current_die stays None until next flush
            continue

        # Check for null DIE (end of children)  "Abbrev Number: 0"
        if "Abbrev Number: 0" in line:
            flush_die()
            continue

        # Attribute line — only process if inside an interesting DIE
        if current_die is None:
            continue

        m = _RE_ATTR.search(line)
        if not m:
            continue

        attr_name = m.group(1)
        attr_raw = m.group(2)

        if attr_name == "name":
            current_die["name"] = _parse_name(attr_raw)
        elif attr_name == "byte_size":
            current_die["byte_size"] = _parse_int(attr_raw)
        elif attr_name == "type":
            current_die["type_ref"] = _parse_type_ref(attr_raw)
        elif attr_name == "data_member_location":
            current_die["byte_offset"] = _parse_int(attr_raw) or 0
        elif attr_name == "encoding":
            current_die["encoding"] = _parse_encoding(attr_raw)

    flush_die()

    logger.debug(
        "dwarf_types_parsed",
        extra={"type_count": len(types), "member_count": len(members)},
    )
    return types, members


def parse_debug_line_from_text(text: str) -> list[dict]:
    """
    Parse readelf --debug-dump=decodedline output into source line records.

    Returns:
        list of dicts: {source_file, line_number, address}
        address is the binary offset (integer).
    """
    records: list[dict] = []
    current_file: str | None = None

    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue

        # Header line: full path or basename followed by ":"
        hm = _RE_LINE_HEADER.match(line)
        if hm:
            current_file = hm.group(1)
            continue

        # Data row: BASENAME  LINE  0xADDR  [View]  [Stmt]
        rm = _RE_LINE_ROW.match(line)
        if rm and current_file is not None:
            line_no_str = rm.group(2)
            addr_str = rm.group(3)
            if line_no_str == "-":
                continue  # End-of-sequence marker
            try:
                line_no = int(line_no_str)
                addr = int(addr_str, 16)
            except ValueError:
                continue
            records.append({
                "source_file": current_file,
                "line_number": line_no,
                "address": addr,
            })

    logger.debug("debug_line_parsed", extra={"record_count": len(records)})
    return records


async def parse_dwarf_types(binary_path: str, config) -> tuple[list[dict], list[dict]]:
    """
    Extract DWARF type definitions from a binary using objdump --dwarf=info.

    Runs objdump asynchronously, parses in thread pool.

    Returns:
        (types, members) — see parse_dwarf_types_from_text()
    """
    import asyncio

    parser = BinToolsParser(config)
    lines: list[str] = []

    def collect(line: str) -> None:
        lines.append(line)

    cmd = [config.objdump_path, "--dwarf=info", binary_path]
    try:
        await parser.run_command_limited(cmd, collect)
    except Exception as e:
        logger.warning("dwarf_info_failed", extra={"binary": binary_path, "error": str(e)})
        return [], []

    text = "\n".join(lines)
    return await asyncio.to_thread(parse_dwarf_types_from_text, text)


async def parse_debug_line(binary_path: str, config) -> list[dict]:
    """
    Extract source line → address mappings from a binary using readelf.

    Runs readelf --debug-dump=decodedline asynchronously, parses in thread pool.

    Returns:
        list of {source_file, line_number, address}
    """
    import asyncio

    parser = BinToolsParser(config)
    lines: list[str] = []

    def collect(line: str) -> None:
        lines.append(line)

    cmd = [config.readelf_path, "--debug-dump=decodedline", binary_path]
    try:
        await parser.run_command_limited(cmd, collect)
    except Exception as e:
        logger.warning("debug_line_failed", extra={"binary": binary_path, "error": str(e)})
        return []

    text = "\n".join(lines)
    return await asyncio.to_thread(parse_debug_line_from_text, text)
