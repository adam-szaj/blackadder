"""
Rootfs database access layer for binary metadata.

Provides RootfsDatabase class for managing binaries, sections, symbols,
and function fingerprints extracted from binaries in the rootfs.
"""

from sqlmodel import select

from blackadder.models import Binary, FunctionFingerprint
from blackadder.binutils.hasher import FunctionHasher

from .base import AsyncDatabaseManager


class RootfsDatabase:
    """Database access for binary metadata (sections, symbols, fingerprints)."""

    def __init__(self, manager: AsyncDatabaseManager, config):
        """
        Initialize RootfsDatabase.

        Args:
            manager: AsyncDatabaseManager instance
            config: BlackadderConfig with tool paths
        """
        self.manager = manager
        self.config = config

    async def compute_and_cache_fingerprints(
        self, binary_id: int, binary_path: str
    ) -> int:
        """
        Compute fingerprints for a binary and store in DB.

        Args:
            binary_id: Binary model ID in database
            binary_path: Path to binary file

        Returns:
            Count of fingerprints stored
        """
        # Compute fingerprints
        hasher = FunctionHasher(self.config)
        fingerprints = await hasher.compute_fingerprints(binary_path)

        if not fingerprints:
            return 0

        # Store in database
        async with self.manager.get_session() as session:
            # Create new fingerprint records
            # (We don't delete old ones - just add new ones)
            # This allows incremental updates and avoids the need for delete
            for func_name, content_hash in fingerprints.items():
                fp = FunctionFingerprint(
                    binary_id=binary_id,
                    func_name=func_name,
                    func_offset=0,  # Not computed by hasher yet
                    func_size=0,    # Not computed by hasher yet
                    content_hash=content_hash,
                )
                session.add(fp)

            await session.commit()

            count = len(fingerprints)

        return count

    async def find_binaries_by_name(self, name: str) -> list[Binary]:
        """
        Find all binaries matching a name (e.g., 'libc.so.6').

        Args:
            name: Binary name or pattern

        Returns:
            List of matching Binary objects
        """
        async with self.manager.get_session() as session:
            # Exact match on name
            statement = select(Binary).where(Binary.name == name)
            result = await session.exec(statement)
            binaries = result.all()

        return binaries

    async def find_binary_by_md5(self, md5sum: str) -> Binary | None:
        """
        Find a binary by MD5 checksum.

        Args:
            md5sum: MD5 hex string

        Returns:
            Binary object or None if not found
        """
        async with self.manager.get_session() as session:
            statement = select(Binary).where(Binary.md5sum == md5sum)
            result = await session.exec(statement)
            binary = result.first()

        return binary

    async def has_fingerprints(self, binary_id: int) -> bool:
        """
        Check if a binary has fingerprints computed.

        Args:
            binary_id: Binary model ID

        Returns:
            True if fingerprints exist
        """
        async with self.manager.get_session() as session:
            statement = select(FunctionFingerprint).where(
                FunctionFingerprint.binary_id == binary_id
            )
            result = await session.exec(statement)
            fp = result.first()

        return fp is not None
