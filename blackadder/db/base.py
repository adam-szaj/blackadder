"""
Async database infrastructure for blackadder.

Provides AsyncDatabaseManager for managing async SQLite connections via aiosqlite.
Supports both rootfs and process databases with connection pooling.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlmodel import SQLModel


class AsyncDatabaseManager:
    """
    Manages async SQLite connections with connection pooling.

    Supports multiple databases (rootfs + process) via separate instances.
    """

    def __init__(self, db_url: str, echo: bool = False, pool_size: int = 10):
        """
        Initialize database manager.

        Args:
            db_url: SQLAlchemy async URL (e.g., "sqlite+aiosqlite:///blackadder.db")
            echo: Enable SQL logging
            pool_size: Max concurrent connections (ignored for SQLite, but set for compatibility)
        """
        if not db_url.startswith("sqlite+aiosqlite://"):
            # Support memory databases for testing
            if db_url == "sqlite+aiosqlite:///:memory:":
                pass  # OK
            else:
                raise ValueError(
                    f"Only aiosqlite:// URLs supported, got {db_url}"
                )

        self.db_url = db_url
        self.echo = echo
        self.pool_size = pool_size

        # Create async engine with SQLite optimizations
        # journal_mode=WAL for concurrent read/write
        # timeout for longer waits on locked database
        connect_args = {
            "timeout": 10.0,
            "check_same_thread": False,
        }

        self.engine = create_async_engine(
            db_url,
            echo=echo,
            future=True,
            connect_args=connect_args,
            pool_pre_ping=True,  # Test connections before using
        )

        # Session factory for creating new async sessions
        self.session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get a new async database session.

        Usage:
            async with manager.get_session() as session:
                result = await session.exec(query)

        Yields:
            AsyncSession: SQLAlchemy async session
        """
        async with self.session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    async def create_all(self) -> None:
        """
        Create all tables in the database (idempotent).

        Should be called once during initialization.
        """
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def drop_all(self) -> None:
        """
        Drop all tables from the database.

        Used for testing only.
        """
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.drop_all)

    async def close(self) -> None:
        """Close database connections."""
        await self.engine.dispose()

    async def __aenter__(self):
        """Context manager entry (for async with)."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close()

    @property
    def is_memory_db(self) -> bool:
        """Check if this is an in-memory database."""
        return ":memory:" in self.db_url
