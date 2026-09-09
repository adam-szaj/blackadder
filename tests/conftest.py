"""
Pytest configuration and fixtures for blackadder tests.

Provides async fixtures, test databases, sample data, and utilities
for testing the complete blackadder stack.
"""

import asyncio
import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import pytest_asyncio

from blackadder.config import BlackadderConfig
from blackadder.db import AsyncDatabaseManager, ProcessDatabase
from tests.fixtures.phase3_data import (
    MOCK_MEMORY_MAPPINGS,
    MOCK_PROCESSES,
    MOCK_REGISTER_STATES,
)

# ============================================================================
# Async event loop configuration
# ============================================================================


@pytest_asyncio.fixture(scope="session")
def event_loop():
    """Create event loop for entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Configuration fixtures
# ============================================================================


@pytest.fixture
def test_config() -> BlackadderConfig:
    """Get test configuration with sensible defaults."""
    return BlackadderConfig(
        db="sqlite+aiosqlite:///:memory:",
        max_subprocess_workers=4,  # Limit for testing
        max_symbol_cache_size=1000,
    )


@pytest.fixture
def config(test_config) -> BlackadderConfig:
    """Alias for test_config for convenience."""
    return test_config


# ============================================================================
# Database fixtures
# ============================================================================


@pytest_asyncio.fixture
async def memory_db(test_config) -> AsyncGenerator[AsyncDatabaseManager, None]:
    """
    Create in-memory SQLite database for testing.

    Automatically creates all tables and cleans up after test.
    """
    manager = AsyncDatabaseManager(test_config.db)
    await manager.create_all()

    yield manager

    await manager.drop_all()
    await manager.close()


@pytest_asyncio.fixture
async def process_db(test_config) -> AsyncGenerator[ProcessDatabase, None]:
    """
    Create in-memory process database for testing.
    """
    manager = AsyncDatabaseManager(test_config.db)
    await manager.create_all()

    db = ProcessDatabase(manager, test_config)

    yield db

    await manager.close()


@pytest_asyncio.fixture
async def temp_databases(test_config) -> tuple[AsyncDatabaseManager, ProcessDatabase]:
    """
    Create temporary file-based databases for testing large operations.

    Useful for testing against more realistic database state.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        database_url = f"sqlite+aiosqlite:///{tmpdir_path / 'blackadder.db'}"

        config = BlackadderConfig(
            db=database_url,
            max_subprocess_workers=4,
        )

        manager = AsyncDatabaseManager(config.db)
        await manager.create_all()

        db = ProcessDatabase(manager, config)

        yield manager, db

        await manager.close()


# ============================================================================
# Sample data fixtures
# ============================================================================


@pytest.fixture
def sample_maps_content() -> str:
    """Sample /proc/PID/maps content for testing."""
    return """555555554000-555555575000 r-xp 00000000 08:01 12345678  /home/user/myapp
555555775000-555555776000 r--p 00020000 08:01 12345678  /home/user/myapp
555555776000-555555777000 rw-p 00021000 08:01 12345678  /home/user/myapp
7ffff7c00000-7ffff7c28000 r-xp 00000000 08:01 87654321  /__blackadder_missing__/lib64/ld-linux-x86-64.so.2
7ffff7e00000-7ffff7e1c000 r-xp 00000000 08:01 11111111  /__blackadder_missing__/lib/libc.so.6
7ffff7e1c000-7ffff7e7e000 rw-p 0001c000 08:01 11111111  /__blackadder_missing__/lib/libc.so.6
7ffff7fdd000-7ffff7ffe000 rw-p 00000000 00:00 0         [vvar]
7ffff7ffe000-7ffff8000000 r-xp 00000000 00:00 0         [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]
"""


@pytest.fixture
def sample_raw_backtrace() -> str:
    """Sample raw hex backtrace."""
    return """0x555555554c84
0x555555554c8f
0x7ffff7e1c5c0
0x7ffff7e1c5d2
"""


@pytest.fixture
def sample_gdb_backtrace() -> str:
    """Sample GDB-format backtrace."""
    return """#0  0x0000555555554c84 in main (argc=1, argv=0x7fffffffde88) at main.c:42
#1  0x00007ffff7e1c5c0 in __libc_start_main (main=0x555555554c00 <main>, argc=1, argv=0x7fffffffde88, init=<optimized out>, fini=<optimized out>, rtld_fini=0x7ffff7ffd980 <_dl_fini>, stack_end=0x7fffffffde78) at ../csu/libc-start.c:308
#2  0x00007ffff7e1c5d2 in _start () from /lib64/ld-linux-x86-64.so.2
"""


# ============================================================================
# Phase 3 mock data fixtures
# ============================================================================


@pytest.fixture
def mock_processes():
    """Provides all mock process snapshots (x86_64, arm64, arm)."""
    return MOCK_PROCESSES


@pytest.fixture
def mock_memory_mappings():
    """Provides mock memory layouts per architecture."""
    return MOCK_MEMORY_MAPPINGS


@pytest.fixture
def mock_register_states():
    """Provides mock register states with code/heap/stack pointers."""
    return MOCK_REGISTER_STATES


# ============================================================================
# Utility fixtures
# ============================================================================


@pytest.fixture
def temp_file() -> Path:
    """Create a temporary file path for testing."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        return Path(f.name)


# ============================================================================
# Markers and configuration
# ============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line(
        "markers", "requires_tools: marks tests that need external binutils tools"
    )


@pytest.fixture(scope="session", autouse=True)
def setup_logging():
    """Setup logging for tests."""
    import logging

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
