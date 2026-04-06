"""
Tests for SQLModel ORM definitions.

Validates model definitions, relationships, and Pydantic validation.
"""

import pytest
from datetime import datetime

from blackadder.models import (
    Binary,
    SectionHeader,
    Symbol,
    ProcessSnapshot,
    MemoryMapping,
    ResolvedFrame,
)
from blackadder.binutils.resolver import parse_backtrace_auto


def test_resolved_frame_valid():
    """Test ResolvedFrame model with valid data."""
    frame = ResolvedFrame(
        address=0x400A1C,
        frame_num=0,
        symbol="main",
    )

    assert frame.address == 0x400A1C
    assert frame.frame_num == 0
    assert frame.symbol == "main"


def test_resolved_frame_empty_symbol():
    """Test ResolvedFrame validates empty symbols."""
    frame = ResolvedFrame(
        address=0x400A1C,
        frame_num=0,
        symbol="",
    )

    # Empty symbol should be converted to "???"
    assert frame.symbol == "???"


def test_resolved_frame_with_line_info():
    """Test ResolvedFrame with source file and line number."""
    frame = ResolvedFrame(
        address=0x400A1C,
        frame_num=0,
        symbol="main",
        file="main.c",
        line=42,
    )

    assert frame.file == "main.c"
    assert frame.line == 42


def test_binary_model():
    """Test Binary model creation."""
    binary = Binary(
        md5sum="abc123def456",
        name="libc.so.6",
        debug_link="libc.so.6.debug",
    )

    assert binary.md5sum == "abc123def456"
    assert binary.name == "libc.so.6"
    assert binary.debug_link == "libc.so.6.debug"


def test_process_snapshot_model():
    """Test ProcessSnapshot model."""
    process = ProcessSnapshot(
        pid=12345,
        description="Process 12345 crash dump",
    )

    assert process.pid == 12345
    assert process.description == "Process 12345 crash dump"
    assert process.created_at is not None
    assert isinstance(process.created_at, datetime)


def test_memory_mapping_model():
    """Test MemoryMapping model."""
    mapping = MemoryMapping(
        start_addr=0x555555554000,
        end_addr=0x555555575000,
        perms="r-xp",
        offset=0,
        pathname="/home/user/myapp",
    )

    assert mapping.start_addr == 0x555555554000
    assert mapping.end_addr == 0x555555575000
    assert mapping.perms == "r-xp"


@pytest.mark.parametrize(
    "raw_trace,expected_count",
    [
        ("0x400a1c\n0x400a2c\n0x400a3c", 3),
        ("400a1c\n400a2c", 2),  # Without 0x prefix
        ("0x400a1c", 1),  # Single address
    ],
)
def test_parse_raw_hex_backtrace(raw_trace, expected_count):
    """Test parsing raw hex backtrace format (newline-separated)."""
    addresses = parse_backtrace_auto(raw_trace)
    assert len(addresses) == expected_count


def test_parse_gdb_backtrace():
    """Test parsing GDB-format backtrace."""
    gdb_trace = """#0  0x0000555555554c84 in main (argc=1, argv=0x7fffffffde88) at main.c:42
#1  0x00007ffff7e1c5c0 in __libc_start_main (main=0x555555554c00 <main>
#2  0x00007ffff7e1c5d2 in _start ()"""

    addresses = parse_backtrace_auto(gdb_trace)

    assert len(addresses) == 3
    assert addresses[0] == 0x555555554C84
    assert addresses[1] == 0x7FFFF7E1C5C0
    assert addresses[2] == 0x7FFFF7E1C5D2


def test_parse_kernel_backtrace():
    """Test parsing kernel-format backtrace."""
    kernel_trace = """[<ffffffff81010001>] function_name+0x42/0x100
[<ffffffff81010002>] another_function+0x10/0x50
[<ffffffff81010003>] third_function"""

    addresses = parse_backtrace_auto(kernel_trace)

    assert len(addresses) == 3
    assert addresses[0] == 0xFFFFFFFF81010001
    assert addresses[1] == 0xFFFFFFFF81010002
    assert addresses[2] == 0xFFFFFFFF81010003


def test_parse_mixed_format_prefers_gdb():
    """Test that GDB format is preferred over raw hex."""
    mixed_trace = """#0  0x0000555555554c84 in main
0x555555554d00
0x555555554d10"""

    addresses = parse_backtrace_auto(mixed_trace)

    # Should detect GDB format and only extract GDB addresses
    assert len(addresses) >= 1
    assert 0x555555554C84 in addresses
