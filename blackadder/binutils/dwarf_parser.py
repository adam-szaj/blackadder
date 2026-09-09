"""
DWARF debug info parser for type extraction and source line mapping.

Provides incremental (streaming) and batch parsers:
  DwarfTypeParser        — stateful incremental parser, feed one line at a time
  DebugLineParser        — stateful incremental parser for .debug_line output
  stream_dwarf_types()   — async generator yielding chunks, zero full-output buffer
  stream_debug_line()    — async generator yielding chunks
  parse_dwarf_types_from_text() — batch parser (kept for tests / compatibility)
  parse_debug_line_from_text()  — batch parser (kept for tests / compatibility)
  parse_dwarf_types()    — async wrapper around stream_dwarf_types (collects all)
  parse_debug_line()     — async wrapper around stream_debug_line (collects all)

Local variable records (yielded alongside types/members):
  Each variable record is a dict with keys:
    subprogram_die_offset: int | None   — parent subprogram DIE offset
    die_offset: int                     — variable/formal_parameter DIE offset
    tag: "variable" | "formal_parameter"
    name: str | None
    type_ref: int | None                — type DIE offset
    location_type: "fbreg" | "register" | "complex" | None
    location_fbreg: int | None          — DW_OP_fbreg offset (signed, bytes from frame base)
    location_register: str | None       — register name for "register" location
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess as _subprocess
from collections.abc import AsyncGenerator

from blackadder.binutils.parser import BinToolsParser

logger = logging.getLogger("blackadder.dwarf_parser")

# DWARF tags we care about — everything else is skipped
_INTERESTING_TAGS = frozenset(
    {
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
        # Local variable tracking
        "subprogram",
        "variable",
        "formal_parameter",
    }
)

# Tags that introduce a new subprogram scope (push onto subprogram stack)
_SUBPROGRAM_TAGS = frozenset({"subprogram"})

# Tags that represent local variables or parameters
_VAR_TAGS = frozenset({"variable", "formal_parameter"})

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
_RE_DIE = re.compile(r"<(\d+)><([0-9a-f]+)>:\s+Abbrev Number:\s+\d+\s+\(DW_TAG_(\w+)\)")

# Regex: attribute line (various formats)
_RE_ATTR = re.compile(r"(?:<[0-9a-f]+>\s+)?DW_AT_(\w+)\s*:\s*(.*)", re.IGNORECASE)

# Regex: type reference  <0xHEX>
_RE_TYPE_REF = re.compile(r"<0x([0-9a-f]+)>")

# Regex: indirect string value  (indirect string, offset: 0xXXX): NAME
# Also handles: (alt indirect string, offset: ...) and (GNU_str_index: ...)
_RE_INDIRECT_STR = re.compile(
    r"\((?:alt )?(?:indirect (?:string|line string)|GNU_str_index)[^)]*\):\s*(.*)"
)

# Regex: DW_AT_location fbreg  — matches "(DW_OP_fbreg: -96)" anywhere in the value
_RE_FBREG = re.compile(r"DW_OP_fbreg:\s*(-?\d+)")

# Regex: DW_AT_location register — matches "(DW_OP_reg\d+ (regname))" or "DW_OP_regx: N (regname)"
_RE_REG = re.compile(r"DW_OP_reg(?:x:\s*\d+)?\s+\((\w+)\)")

# Regex: decoded line table row  FILENAME  LINE  0xADDR
_RE_LINE_ROW = re.compile(r"^(\S+)\s+(\d+)\s+(0x[0-9a-f]+)", re.IGNORECASE)

# Regex: decoded line table header
_RE_LINE_HEADER = re.compile(r"^(/\S+|[^/\s]\S+):$")


# ============================================================================
# Attribute value helpers
# ============================================================================


def _parse_attr_value(raw: str) -> str:
    """Extract clean attribute value from raw DW_AT line value."""
    raw = raw.strip()
    m = _RE_INDIRECT_STR.match(raw)
    if m:
        return m.group(1).strip()
    return raw


def _parse_name(raw: str) -> str | None:
    val = _parse_attr_value(raw).strip()
    return val if val else None


def _parse_type_ref(raw: str) -> int | None:
    m = _RE_TYPE_REF.search(raw)
    return int(m.group(1), 16) if m else None


def _parse_int(raw: str) -> int | None:
    raw = raw.strip().split("\t")[0].split(" ")[0]
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
    paren = re.search(r"\((\w+)\)", raw)
    if paren:
        return paren.group(1)
    code = _parse_int(raw)
    if code is not None:
        return _ENCODING_MAP.get(code)
    return None


# ============================================================================
# Incremental (streaming) parsers
# ============================================================================


def _parse_location(raw: str) -> tuple[str | None, int | None, str | None]:
    """Parse DW_AT_location value into (location_type, fbreg_offset, register_name).

    Returns:
      ("fbreg",    offset, None)     — DW_OP_fbreg: N
      ("register", None,  regname)   — DW_OP_regN (rxx)
      ("complex",  None,  None)      — multi-op expression we don't fully decode
      (None,       None,  None)      — unrecognised / empty
    """
    m_fbreg = _RE_FBREG.search(raw)
    if m_fbreg:
        return "fbreg", int(m_fbreg.group(1)), None
    m_reg = _RE_REG.search(raw)
    if m_reg:
        return "register", None, m_reg.group(1)
    if "DW_OP_" in raw:
        return "complex", None, None
    return None, None, None


class DwarfTypeParser:
    """
    Incremental stateful parser for objdump --dwarf=info output.

    Feed one line at a time via feed(). Each call returns any type/member/var
    records that were finalized by that line. Call flush() after the last
    line to get the final pending record.

    Memory held at any point: current DIE dict + parent_stack + subprogram_stack
    + pending output (cleared after each feed() call) — O(depth) not O(file size).

    Yields three lists:
      types   — type DIE records (structure_type, base_type, typedef, ...)
      members — struct/union field records
      vars    — local variable / parameter records (variable, formal_parameter)
    """

    __slots__ = (
        "_current_die",
        "_parent_stack",
        "_subprogram_stack",
        "_out_types",
        "_out_members",
        "_out_vars",
    )

    def __init__(self) -> None:
        self._current_die: dict | None = None
        self._parent_stack: list[tuple[int, int]] = []  # (depth, die_offset) — struct/union
        self._subprogram_stack: list[tuple[int, int]] = []  # (depth, die_offset) — subprogram
        self._out_types: list[dict] = []
        self._out_members: list[dict] = []
        self._out_vars: list[dict] = []

    def feed(self, line: str) -> tuple[list[dict], list[dict], list[dict]]:
        """
        Process one line.

        Returns (new_types, new_members, new_vars) — records finalized by this line.
        The returned lists are consumed; caller should not hold references.
        """
        # DIE header?
        m = _RE_DIE.search(line)
        if m:
            self._flush_current()
            depth = int(m.group(1))
            die_offset = int(m.group(2), 16)
            tag = m.group(3)
            # Unwind struct/union parent stack
            while self._parent_stack and self._parent_stack[-1][0] >= depth:
                self._parent_stack.pop()
            # Unwind subprogram stack
            while self._subprogram_stack and self._subprogram_stack[-1][0] >= depth:
                self._subprogram_stack.pop()
            if tag in _INTERESTING_TAGS:
                self._current_die = {"tag": tag, "die_offset": die_offset, "depth": depth}
            return self._take_output()

        # Null DIE?
        if "Abbrev Number: 0" in line:
            self._flush_current()
            return self._take_output()

        # Attribute — only if inside an interesting DIE
        if self._current_die is None:
            return [], [], []

        m = _RE_ATTR.search(line)
        if not m:
            return [], [], []

        attr_name = m.group(1)
        attr_raw = m.group(2)
        tag = self._current_die.get("tag", "")

        if attr_name == "name":
            self._current_die["name"] = _parse_name(attr_raw)
        elif attr_name == "byte_size":
            self._current_die["byte_size"] = _parse_int(attr_raw)
        elif attr_name == "type":
            self._current_die["type_ref"] = _parse_type_ref(attr_raw)
        elif attr_name == "data_member_location":
            self._current_die["byte_offset"] = _parse_int(attr_raw) or 0
        elif attr_name == "encoding":
            self._current_die["encoding"] = _parse_encoding(attr_raw)
        elif attr_name == "location" and tag in _VAR_TAGS:
            loc_type, fbreg, reg = _parse_location(attr_raw)
            self._current_die["location_type"] = loc_type
            self._current_die["location_fbreg"] = fbreg
            self._current_die["location_register"] = reg

        return [], [], []

    def flush(self) -> tuple[list[dict], list[dict], list[dict]]:
        """Finalize the last pending DIE. Must be called after the last line."""
        self._flush_current()
        return self._take_output()

    def _flush_current(self) -> None:
        die = self._current_die
        self._current_die = None
        if die is None:
            return
        tag = die.get("tag", "")
        die_offset = die.get("die_offset")
        depth = die.get("depth", 0)

        if tag == "member":
            parent_offset = None
            for pdepth, poffset in reversed(self._parent_stack):
                if pdepth == depth - 1:
                    parent_offset = poffset
                    break
            type_ref = die.get("type_ref")
            if parent_offset is not None and "byte_offset" in die and type_ref is not None:
                self._out_members.append(
                    {
                        "parent_die_offset": parent_offset,
                        "name": die.get("name"),
                        "byte_offset": die["byte_offset"],
                        "member_type_ref": type_ref,
                    }
                )

        elif tag == "subprogram":
            # Push onto subprogram stack so nested variables know their parent.
            if die_offset is not None:
                self._subprogram_stack.append((depth, die_offset))
            # Emit as type record so binary_dwarf_ref can map its die_offset.
            self._out_types.append(
                {
                    "die_offset": die_offset,
                    "tag": tag,
                    "name": die.get("name"),
                    "byte_size": None,
                    "type_ref": None,
                    "encoding": None,
                }
            )

        elif tag in _VAR_TAGS:
            # Find innermost enclosing subprogram.
            subprog_offset: int | None = None
            for sdepth, soffset in reversed(self._subprogram_stack):
                if sdepth < depth:
                    subprog_offset = soffset
                    break
            self._out_vars.append(
                {
                    "subprogram_die_offset": subprog_offset,
                    "die_offset": die_offset,
                    "tag": tag,
                    "name": die.get("name"),
                    "type_ref": die.get("type_ref"),
                    "location_type": die.get("location_type"),
                    "location_fbreg": die.get("location_fbreg"),
                    "location_register": die.get("location_register"),
                }
            )

        elif tag in _INTERESTING_TAGS:
            self._out_types.append(
                {
                    "die_offset": die_offset,
                    "tag": tag,
                    "name": die.get("name"),
                    "byte_size": die.get("byte_size"),
                    "type_ref": die.get("type_ref"),
                    "encoding": die.get("encoding"),
                }
            )
            if tag in ("structure_type", "union_type") and die_offset is not None:
                self._parent_stack.append((depth, die_offset))

    def _take_output(self) -> tuple[list[dict], list[dict], list[dict]]:
        """Return accumulated output and reset buffers."""
        t, m, v = self._out_types, self._out_members, self._out_vars
        self._out_types = []
        self._out_members = []
        self._out_vars = []
        return t, m, v


class DebugLineParser:
    """
    Incremental stateful parser for readelf --debug-dump=decodedline output.

    Feed one line at a time via feed(). Returns list of records (0 or 1)
    per line. No internal accumulation beyond current file context.
    """

    __slots__ = ("_current_file",)

    def __init__(self) -> None:
        self._current_file: str | None = None

    def feed(self, line: str) -> list[dict]:
        """Process one line. Returns a list with 0 or 1 record dicts."""
        line = line.rstrip()
        if not line:
            return []

        hm = _RE_LINE_HEADER.match(line)
        if hm:
            self._current_file = hm.group(1)
            return []

        rm = _RE_LINE_ROW.match(line)
        if rm and self._current_file is not None:
            line_no_str = rm.group(2)
            addr_str = rm.group(3)
            if line_no_str == "-":
                return []
            try:
                return [
                    {
                        "source_file": self._current_file,
                        "line_number": int(line_no_str),
                        "address": int(addr_str, 16),
                    }
                ]
            except ValueError:
                return []
        return []


# ============================================================================
# Synchronous parse helpers — safe to call from a thread pool worker.
# These use subprocess.Popen (blocking) so they never touch the event loop.
# Run via asyncio.to_thread() for true multi-core parallelism.
# ============================================================================


def _sync_parse_dwarf_types(
    binary_path: str,
    objdump_path: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Run objdump --dwarf=info and parse all DWARF type DIEs synchronously.

    Designed to run inside asyncio.to_thread() — uses blocking subprocess,
    releases the GIL during I/O so other threads can parse in parallel.
    Returns (all_types, all_members, all_vars).
    """
    parser = DwarfTypeParser()
    all_types: list[dict] = []
    all_members: list[dict] = []
    all_vars: list[dict] = []
    try:
        proc = _subprocess.Popen(
            [objdump_path, "--dwarf=info", binary_path],
            stdout=_subprocess.PIPE,
            stderr=_subprocess.DEVNULL,
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            t, m, v = parser.feed(line)
            if t:
                all_types.extend(t)
            if m:
                all_members.extend(m)
            if v:
                all_vars.extend(v)
        proc.wait()
    except Exception:
        pass
    ft, fm, fv = parser.flush()
    all_types.extend(ft)
    all_members.extend(fm)
    all_vars.extend(fv)
    return all_types, all_members, all_vars


def _sync_parse_debug_line(
    binary_path: str,
    readelf_path: str,
) -> list[dict]:
    """
    Run readelf --debug-dump=decodedline and parse all source-line records synchronously.

    Designed to run inside asyncio.to_thread().
    """
    parser = DebugLineParser()
    records: list[dict] = []
    seen: set[tuple[str, int, int]] = set()
    try:
        proc = _subprocess.Popen(
            [readelf_path, "--debug-dump=decodedline", binary_path],
            stdout=_subprocess.PIPE,
            stderr=_subprocess.DEVNULL,
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            for rec in parser.feed(line):
                key = (rec["source_file"], rec["line_number"], rec["address"])
                if key not in seen:
                    seen.add(key)
                    records.append(rec)
        proc.wait()
    except Exception:
        pass
    return records


# ============================================================================
# Async streaming generators — kept for single-binary use (load-types command)
# and tests.  For bulk loads use the thread-based variants in rootfs.py.
# ============================================================================


async def stream_dwarf_types(
    binary_path: str,
    config,
    chunk_size: int = 500,
) -> AsyncGenerator[tuple[list[dict], list[dict], list[dict]], None]:
    """
    Yield (types_chunk, members_chunk, vars_chunk) as parsed from objdump output.

    Never holds more than chunk_size type records + current DIE state in memory.
    The subprocess semaphore in BinToolsParser limits concurrency.
    """
    bintool = BinToolsParser(config)
    cmd = [config.objdump_path, "--dwarf=info", binary_path]
    parser = DwarfTypeParser()
    acc_types: list[dict] = []
    acc_members: list[dict] = []
    acc_vars: list[dict] = []

    async with bintool.subprocess_sem:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=256 * 1024,
        )
        assert proc.stdout is not None
        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            new_t, new_m, new_v = parser.feed(line)
            if new_t:
                acc_types.extend(new_t)
            if new_m:
                acc_members.extend(new_m)
            if new_v:
                acc_vars.extend(new_v)
            if len(acc_types) >= chunk_size:
                yield acc_types, acc_members, acc_vars
                acc_types = []
                acc_members = []
                acc_vars = []
        await proc.wait()

    final_t, final_m, final_v = parser.flush()
    acc_types.extend(final_t)
    acc_members.extend(final_m)
    acc_vars.extend(final_v)
    if acc_types or acc_members or acc_vars:
        yield acc_types, acc_members, acc_vars


async def stream_debug_line(
    binary_path: str,
    config,
    chunk_size: int = 500,
) -> AsyncGenerator[list[dict], None]:
    """
    Yield chunks of debug line records as parsed from readelf output.

    Never holds more than chunk_size records in memory at once.
    """
    bintool = BinToolsParser(config)
    cmd = [config.readelf_path, "--debug-dump=decodedline", binary_path]
    parser = DebugLineParser()
    acc: list[dict] = []
    seen: set[tuple[str, int, int]] = set()

    async with bintool.subprocess_sem:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=256 * 1024,
        )
        assert proc.stdout is not None
        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            for rec in parser.feed(line):
                key = (rec["source_file"], rec["line_number"], rec["address"])
                if key not in seen:
                    seen.add(key)
                    acc.append(rec)
            if len(acc) >= chunk_size:
                yield acc
                acc = []
        await proc.wait()

    if acc:
        yield acc


# ============================================================================
# Batch parsers (kept for tests and load-types command)
# ============================================================================


def parse_dwarf_types_from_text(text: str) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Parse objdump --dwarf=info output into type, member, and variable records.

    Batch version — kept for tests and one-shot use.
    For large binaries prefer stream_dwarf_types() to avoid buffering.
    Returns (all_types, all_members, all_vars).
    """
    parser = DwarfTypeParser()
    all_types: list[dict] = []
    all_members: list[dict] = []
    all_vars: list[dict] = []
    for line in text.splitlines():
        t, m, v = parser.feed(line)
        all_types.extend(t)
        all_members.extend(m)
        all_vars.extend(v)
    ft, fm, fv = parser.flush()
    all_types.extend(ft)
    all_members.extend(fm)
    all_vars.extend(fv)
    logger.debug(
        "dwarf_types_parsed",
        extra={
            "type_count": len(all_types),
            "member_count": len(all_members),
            "var_count": len(all_vars),
        },
    )
    return all_types, all_members, all_vars


def parse_debug_line_from_text(text: str) -> list[dict]:
    """
    Parse readelf --debug-dump=decodedline output into source line records.

    Batch version — kept for tests and one-shot use.
    """
    parser = DebugLineParser()
    records: list[dict] = []
    seen: set[tuple[str, int, int]] = set()
    for line in text.splitlines():
        for rec in parser.feed(line):
            key = (rec["source_file"], rec["line_number"], rec["address"])
            if key not in seen:
                seen.add(key)
                records.append(rec)
    logger.debug("debug_line_parsed", extra={"record_count": len(records)})
    return records


async def parse_dwarf_types(
    binary_path: str,
    config,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Collect all DWARF types/vars from a binary. Thin wrapper over stream_dwarf_types.

    Returns (all_types, all_members, all_vars).
    """
    all_types: list[dict] = []
    all_members: list[dict] = []
    all_vars: list[dict] = []
    try:
        async for types_chunk, members_chunk, vars_chunk in stream_dwarf_types(binary_path, config):
            all_types.extend(types_chunk)
            all_members.extend(members_chunk)
            all_vars.extend(vars_chunk)
    except Exception as e:
        logger.warning("dwarf_info_failed", extra={"binary": binary_path, "error": str(e)})
        return [], [], []
    return all_types, all_members, all_vars


async def parse_debug_line(binary_path: str, config) -> list[dict]:
    """Collect all debug line records from a binary. Thin wrapper over stream_debug_line."""
    records: list[dict] = []
    try:
        async for chunk in stream_debug_line(binary_path, config):
            records.extend(chunk)
    except Exception as e:
        logger.warning("debug_line_failed", extra={"binary": binary_path, "error": str(e)})
        return []
    return records
