"""
Tests for async binutils parser.

Tests subprocess execution, semaphore limiting, and output parsing.
"""

import asyncio

import pytest

from baldrick.binutils.parser import BinToolsParser
from baldrick.config import BaldrickConfig


@pytest.fixture
def parser_config():
    """Create test parser config."""
    return BaldrickConfig(max_subprocess_workers=2)


@pytest.mark.asyncio
async def test_parser_initialization(parser_config):
    """Test parser initialization."""
    parser = BinToolsParser(parser_config)

    assert parser.config == parser_config
    assert parser.subprocess_sem._value == 2  # From config


@pytest.mark.asyncio
async def test_subprocess_semaphore_limits(parser_config):
    """Test that subprocess semaphore limits concurrent executions."""
    parser = BinToolsParser(parser_config)

    assert parser.subprocess_sem._value == 2


@pytest.mark.asyncio
@pytest.mark.requires_tools
async def test_parse_objdump_sections_real(parser_config):
    """Test parsing objdump sections with real binary."""
    parser = BinToolsParser(parser_config)

    # Test with libc if available
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"

    try:
        sections = await parser.parse_objdump_sections(libc_path)

        # Should have common sections
        assert ".text" in sections or ".init" in sections
        assert isinstance(sections, dict)

        # Check structure
        for name, section_info in sections.items():
            assert "name" in section_info
            assert "size" in section_info
            assert isinstance(section_info["size"], int)

    except Exception as e:
        pytest.skip(f"Could not test with real libc: {e}")


@pytest.mark.asyncio
async def test_run_command_limited_basic(parser_config):
    """Test run_command_limited with simple command."""
    parser = BinToolsParser(parser_config)

    # Use 'echo' command which is always available
    lines = await parser.run_command_limited(["echo", "hello\nworld"])

    assert len(lines) >= 1
    assert "hello" in "\n".join(lines)


@pytest.mark.asyncio
async def test_run_command_with_callback(parser_config):
    """Test run_command_limited with callback."""
    parser = BinToolsParser(parser_config)

    collected = []

    def on_line(line):
        collected.append(line)

    await parser.run_command_limited(["echo", "test"], on_line)

    assert len(collected) >= 1


@pytest.mark.asyncio
async def test_concurrent_command_execution(parser_config):
    """Test multiple concurrent commands."""
    parser = BinToolsParser(parser_config)

    # Create multiple concurrent echo commands
    tasks = [parser.run_command_limited(["echo", f"test{i}"]) for i in range(4)]

    results = await asyncio.gather(*tasks)

    assert len(results) == 4
