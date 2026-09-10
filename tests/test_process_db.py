"""
Tests for ProcessDatabase functionality.

Tests core MVP features:
- Loading /proc/maps
- Address-to-binary resolution
- Backtrace decoding with parallel processing
- Symbol caching
"""

import pytest

from baldrick.db import ProcessDatabase


@pytest.mark.asyncio
async def test_load_maps(process_db, sample_maps_content):
    """Test loading /proc/maps into database."""
    process = await process_db.load_maps(12345, sample_maps_content)

    assert process.pid == 12345
    assert len(process.mappings) == 9  # Based on sample_maps_content
    assert process.mappings[0].start_addr == 0x555555554000
    assert process.mappings[0].end_addr == 0x555555575000


@pytest.mark.asyncio
async def test_address_to_binary(process_db, sample_maps_content):
    """Test address-to-binary resolution."""
    process = await process_db.load_maps(12345, sample_maps_content)

    # Test address in main binary
    binary_info = await process_db.address_to_binary(process.id, 0x555555554100)

    assert binary_info is not None
    binary_path, offset, binary_id = binary_info
    assert "/myapp" in binary_path
    assert offset == 0x100
    assert binary_id is None


@pytest.mark.asyncio
async def test_address_to_binary_not_found(process_db, sample_maps_content):
    """Test address-to-binary with unmapped address."""
    process = await process_db.load_maps(12345, sample_maps_content)

    # Address way outside mapped regions
    binary_info = await process_db.address_to_binary(process.id, 0xDEADBEEF)

    assert binary_info is None


@pytest.mark.asyncio
async def test_addresses_to_binaries_resolves_batch(process_db, sample_maps_content):
    process = await process_db.load_maps(12345, sample_maps_content)
    addresses = [0x555555554100, 0x7FFFF7E00100, 0xDEADBEEF]

    results = await process_db.addresses_to_binaries(process.id, addresses)

    assert results[0x555555554100] is not None
    assert results[0x555555554100][1] == 0x100
    assert results[0x7FFFF7E00100] is not None
    assert results[0xDEADBEEF] is None


@pytest.mark.asyncio
async def test_parse_maps_lines():
    """Test _parse_maps_lines regex parsing."""
    lines = [
        "555555554000-555555575000 r-xp 00000000 08:01 12345678  /home/user/myapp",
        "7ffff7e00000-7ffff7e1c000 r-xp 00000000 08:01 11111111  /lib/libc.so.6",
        "7ffff7ffe000-7ffff8000000 r-xp 00000000 00:00 0         [vdso]",
    ]

    parsed = ProcessDatabase._parse_maps_lines(lines)

    assert len(parsed) == 3
    assert parsed[0]["start_addr"] == 0x555555554000
    assert parsed[0]["end_addr"] == 0x555555575000
    assert parsed[0]["perms"] == "r-xp"
    assert "/myapp" in parsed[0]["pathname"]
    assert parsed[2]["pathname"] == "[vdso]"


@pytest.mark.asyncio
async def test_parse_maps_with_anonymous_memory():
    """Test parsing anonymous memory regions."""
    lines = [
        "7fffde000000-7ffffe000000 rw-p 00000000 00:00 0",  # No pathname
    ]

    parsed = ProcessDatabase._parse_maps_lines(lines)

    assert len(parsed) == 1
    assert parsed[0]["pathname"] == "[anonymous]"


@pytest.mark.asyncio
async def test_symbol_cache_basic(process_db):
    """Test symbol caching mechanism."""
    # Cache should start empty
    assert len(process_db.symbol_cache) == 0

    # Manually add to cache
    key = ("/lib/libc.so.6", 0x1000)
    process_db._cache_symbol(key, ("malloc", None, None))

    # Check it's cached
    assert len(process_db.symbol_cache) == 1
    assert process_db.symbol_cache[key] == ("malloc", None, None)


@pytest.mark.asyncio
async def test_symbol_cache_size_limit(process_db):
    """Test symbol cache respects size limit."""
    # Set small cache size for testing
    process_db.config.max_symbol_cache_size = 3

    # Add items beyond limit
    for i in range(5):
        process_db._cache_symbol((f"/lib/lib{i}.so", 0x1000), (f"func{i}", None, None))

    # Should evict oldest items
    assert len(process_db.symbol_cache) <= 3


@pytest.mark.asyncio
async def test_subprocess_semaphore_limits_resolve_frame(process_db, sample_maps_content):
    """Test that subprocess semaphore limits parallel frame resolution."""
    await process_db.load_maps(12345, sample_maps_content)

    # Check semaphore is properly initialized
    assert process_db.subprocess_sem._value <= process_db.config.max_subprocess_workers


@pytest.mark.asyncio
async def test_deadlock_report_preserves_condition_waits(process_db, sample_maps_content):
    process = await process_db.load_maps(12345, sample_maps_content)
    sync_state = """\
BALDRICK_LOCK_STATE_BEGIN
BALDRICK_LOCK_STATE_END
BALDRICK_COND_STATE_BEGIN
{"record_type":"condition_wait","pid":12345,"tid":7,"gdb_thread_num":2,"blocking_function":"pthread_cond_wait","condition_address":"0x1050","mutex_address":"0x1028","same_containing_object":false,"wake_candidates":[],"confidence":"probable","abi_status":"supported","analysis_call_depth":3}
BALDRICK_COND_STATE_END
"""

    report = await process_db.get_deadlock_report(process.id, sync_state)

    assert report.evidence_level == "none"
    assert len(report.condition_waits) == 1
    assert report.condition_waits[0].condition_address == 0x1050
    assert report.summary == (
        "No mutex deadlock cycle detected; 1 condition-variable wait(s) reported."
    )


@pytest.mark.asyncio
async def test_decode_backtrace_with_unmapped_address(process_db, sample_maps_content):
    """Test decode_backtrace with unmapped addresses."""
    process = await process_db.load_maps(12345, sample_maps_content)

    # Mix of valid and invalid addresses
    addresses = [
        0x555555554100,  # Valid: in main binary
        0xDEADBEEF,  # Invalid: unmapped
        0x7FFFF7E00100,  # Valid: in libc
    ]

    frames = await process_db.decode_backtrace(process.id, addresses)

    # Should have 3 frames, but some with "???" symbols
    assert len(frames) == 3
    assert frames[0].address == 0x555555554100
    assert frames[1].address == 0xDEADBEEF
    assert frames[1].symbol == "???"  # Unmapped
    assert frames[2].address == 0x7FFFF7E00100


@pytest.mark.asyncio
async def test_resolve_frame_structure(process_db, sample_maps_content):
    """Test that _resolve_frame returns proper ResolvedFrame."""
    process = await process_db.load_maps(12345, sample_maps_content)

    frame = await process_db._resolve_frame(process.id, 0, 0x555555554100)

    assert frame.frame_num == 0
    assert frame.address == 0x555555554100
    assert isinstance(frame.symbol, str)
