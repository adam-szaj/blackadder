"""Unit tests for the in-memory and persistent symbol cache policy."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from baldrick.config import BaldrickConfig
from baldrick.db.process import ProcessDatabase


class _FailingManager:
    @asynccontextmanager
    async def get_session(self):
        raise RuntimeError("cache database unavailable")
        yield


@pytest.mark.asyncio
async def test_memory_cache_hit_retains_source_location():
    database = ProcessDatabase(SimpleNamespace(), BaldrickConfig())
    key = ("/lib/libc.so.6", 0x123)
    database.symbol_cache[key] = ("malloc", "malloc.c", 42)

    result = await database._get_cached_symbol(*key)

    assert result == ("malloc", "malloc.c", 42)


def test_cache_bound_is_enforced_when_entries_are_added():
    config = BaldrickConfig(max_symbol_cache_size=2)
    database = ProcessDatabase(SimpleNamespace(), config)

    database._cache_symbol(("a", 1), ("one", None, None))
    database._cache_symbol(("b", 2), ("two", None, None))
    database._cache_symbol(("c", 3), ("three", None, None))

    assert list(database.symbol_cache) == [("b", 2), ("c", 3)]


@pytest.mark.asyncio
async def test_persistent_cache_failure_is_observable():
    database = ProcessDatabase(_FailingManager(), BaldrickConfig())

    with pytest.raises(RuntimeError, match="cache database unavailable"):
        await database._persist_symbol_cache(1, 2, "symbol")
