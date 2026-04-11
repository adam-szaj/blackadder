"""
Rootfs database access layer for binary metadata.

Provides RootfsDatabase class for managing binaries, sections, symbols,
and function fingerprints extracted from binaries in the rootfs.
"""

import asyncio
import hashlib
import logging
import os

from sqlmodel import select

from blackadder.binutils.hasher import FunctionHasher
from blackadder.models import Binary, BinaryLocator, DebugLine, DwarfMember, DwarfType, FunctionFingerprint, SectionHeader, Symbol

from .base import AsyncDatabaseManager

logger = logging.getLogger("blackadder.db.rootfs")


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

    async def load_binary(
        self,
        binary_path: str,
        rootfs: str = "/",
        debugfs: str | None = None,
    ) -> tuple[Binary, bool, str | None]:
        """
        Load a binary into the rootfs database.

        Computes MD5, extracts sections/symbols/debug_link via objdump/readelf,
        and stores them. Returns existing record without re-parsing if MD5 matches.
        Also searches for and loads a companion debug file if one is found.

        Args:
            binary_path: Absolute path to the binary file
            rootfs:      Path to rootfs (used for debug-file search)
            debugfs:     Path to debugfs (defaults to rootfs)

        Returns:
            (Binary, is_new, debug_file_path) — debug_file_path is None if no
            debug file was found, or the resolved path when found.
        """
        from blackadder.binutils.parser import BinToolsParser

        def _compute_md5() -> str:
            md5 = hashlib.md5()
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
            return md5.hexdigest()

        md5sum = await asyncio.to_thread(_compute_md5)
        name = os.path.basename(binary_path)
        mtime = int(os.path.getmtime(binary_path))

        parser = BinToolsParser(self.config)
        from blackadder.binutils.debuginfo import find_debug_file

        # Resolve debug file path (needed for both new and existing binaries)
        try:
            debug_link_name = await parser.parse_readelf_debug_link(binary_path)
        except Exception as e:
            logger.debug("debug_link_parse_failed", extra={"path": binary_path, "error": str(e)})
            debug_link_name = None

        debug_file_path = await asyncio.to_thread(
            find_debug_file, binary_path, debug_link_name, rootfs, debugfs
        )
        sym_source = debug_file_path or binary_path

        async with self.manager.get_session() as session:
            # Check if binary already known by MD5
            stmt = select(Binary).where(Binary.md5sum == md5sum)
            result = await session.execute(stmt)
            existing = result.scalars().first()

            if existing:
                # Register this path if not yet known; update debug_file if now resolved
                loc_stmt = select(BinaryLocator).where(BinaryLocator.path == binary_path)
                loc_result = await session.execute(loc_stmt)
                locator = loc_result.scalars().first()
                if not locator:
                    session.add(BinaryLocator(
                        path=binary_path, md5sum=md5sum, mtime=mtime,
                        debug_file=debug_file_path,
                    ))
                    await session.commit()
                elif debug_file_path and not locator.debug_file:
                    locator.debug_file = debug_file_path
                    await session.commit()

                sym_check = await session.execute(
                    select(Symbol).where(Symbol.binary_id == existing.id).limit(1)
                )
                has_symbols = sym_check.scalars().first() is not None

                # Skip reload only if symbols exist AND we have no better source
                if has_symbols and sym_source == binary_path:
                    return existing, False, debug_file_path

                # Symbols missing OR debug file now available — DELETE + INSERT
                if has_symbols:
                    await session.execute(
                        Symbol.__table__.delete().where(Symbol.binary_id == existing.id)
                    )
                    logger.debug(
                        "symbols_replacing_with_debug_file",
                        extra={"binary": binary_path, "sym_source": sym_source},
                    )
                else:
                    logger.debug(
                        "symbols_missing_loading",
                        extra={"binary": binary_path, "sym_source": sym_source},
                    )
                binary_id = existing.id
            else:
                # New binary — parse and store everything
                # debug_link = raw name from .gnu_debuglink section
                binary = Binary(md5sum=md5sum, name=name, debug_link=debug_link_name)
                session.add(binary)
                await session.flush()
                binary_id = binary.id

                # Sections
                try:
                    sections_data = await parser.parse_objdump_sections(binary_path)
                    for idx, (sec_name, sec) in enumerate(sections_data.items()):
                        session.add(
                            SectionHeader(
                                binary_id=binary_id,
                                idx=idx,
                                name=sec_name[:32],
                                size=sec["size"],
                                vma=sec["vma"],
                                lma=sec["lma"],
                                off=sec["off"],
                                align=sec["align"],
                            )
                        )
                except Exception as e:
                    logger.debug("sections_parse_failed", extra={"path": binary_path, "error": str(e)})

                session.add(BinaryLocator(
                    path=binary_path, md5sum=md5sum, mtime=mtime,
                    debug_file=debug_file_path,
                ))

            # Load symbols — shared path for both new and existing-without-symbols
            try:
                syms_data = await parser.parse_objdump_syms_full(sym_source)
                if not syms_data and sym_source != binary_path:
                    syms_data = await parser.parse_objdump_syms_full(binary_path)
                for sym in syms_data:
                    session.add(
                        Symbol(
                            binary_id=binary_id,
                            address=sym["address"],
                            scope=sym["scope"],
                            sym_type=sym["sym_type"],
                            section=sym["section"],
                            size=sym["size"],
                            name=sym["name"],
                        )
                    )
                logger.debug(
                    "symbols_loaded",
                    extra={"binary": binary_path, "source": sym_source, "count": len(syms_data)},
                )
            except Exception as e:
                logger.debug("symbols_parse_failed", extra={"path": sym_source, "error": str(e)})

            await session.commit()

        # Re-fetch outside the session to avoid detached state
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.id == binary_id))
            binary = result.scalars().first()

        if binary is None:
            raise RuntimeError(f"Binary disappeared after insert: id={binary_id}")

        return binary, True, debug_file_path

    async def find_symbol_at_offset(self, binary_path: str, offset: int) -> dict | None:
        """
        Find the nearest symbol at or before offset in a binary.

        Used by the syms command for --type and --section display flags.
        Requires the binary to have been loaded via load_binary() first.

        Args:
            binary_path: Path to the binary
            offset: Address/offset within the binary

        Returns:
            Dict with name, scope, sym_type, section, size, address; or None
        """
        async with self.manager.get_session() as session:
            loc_result = await session.execute(
                select(BinaryLocator).where(BinaryLocator.path == binary_path)
            )
            locator = loc_result.scalars().first()
            if not locator:
                return None

            bin_result = await session.execute(
                select(Binary).where(Binary.md5sum == locator.md5sum)
            )
            binary = bin_result.scalars().first()
            if not binary:
                return None

            sym_result = await session.execute(
                select(Symbol)
                .where(Symbol.binary_id == binary.id, Symbol.address <= offset)
                .order_by(Symbol.address.desc())
                .limit(1)
            )
            symbol = sym_result.scalars().first()
            if not symbol:
                return None

            return {
                "name": symbol.name,
                "scope": symbol.scope,
                "sym_type": symbol.sym_type,
                "section": symbol.section,
                "size": symbol.size,
                "address": symbol.address,
            }

    async def compute_and_cache_fingerprints(self, binary_id: int, binary_path: str) -> int:
        """
        Compute fingerprints for a binary and store in DB.

        Args:
            binary_id: Binary model ID in database
            binary_path: Path to binary file

        Returns:
            Count of fingerprints stored
        """
        hasher = FunctionHasher(self.config)
        fp_result = await hasher.compute_fingerprints(binary_path)

        if fp_result.status != "success" or not fp_result.fingerprints:
            return 0

        fingerprints = fp_result.fingerprints

        async with self.manager.get_session() as session:
            for func_name, content_hash in fingerprints.items():
                fp = FunctionFingerprint(
                    binary_id=binary_id,
                    func_name=func_name,
                    func_offset=0,
                    func_size=0,
                    content_hash=content_hash,
                )
                session.add(fp)

            await session.commit()

        return len(fingerprints)

    async def find_binaries_by_name(self, name: str) -> list[Binary]:
        """
        Find all binaries matching a name (e.g., 'libc.so.6').

        Args:
            name: Binary name

        Returns:
            List of matching Binary objects
        """
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.name == name))
            return list(result.scalars().all())

    async def find_binary_by_md5(self, md5sum: str) -> Binary | None:
        """
        Find a binary by MD5 checksum.

        Args:
            md5sum: MD5 hex string

        Returns:
            Binary object or None if not found
        """
        async with self.manager.get_session() as session:
            result = await session.execute(select(Binary).where(Binary.md5sum == md5sum))
            return result.scalars().first()

    async def has_fingerprints(self, binary_id: int) -> bool:
        """
        Check if a binary has fingerprints computed.

        Args:
            binary_id: Binary model ID

        Returns:
            True if fingerprints exist
        """
        async with self.manager.get_session() as session:
            result = await session.execute(
                select(FunctionFingerprint).where(FunctionFingerprint.binary_id == binary_id)
            )
            return result.scalars().first() is not None

    async def _get_binary_id_for_path(self, binary_path: str) -> int | None:
        """Return binary.id for the given file path, or None if not in DB."""
        async with self.manager.get_session() as session:
            loc_result = await session.execute(
                select(BinaryLocator).where(BinaryLocator.path == binary_path)
            )
            locator = loc_result.scalars().first()
            if not locator:
                return None
            bin_result = await session.execute(
                select(Binary).where(Binary.md5sum == locator.md5sum)
            )
            binary = bin_result.scalars().first()
            return binary.id if binary else None

    async def load_dwarf_types(self, binary_path: str) -> tuple[int, int]:
        """
        Extract DWARF type definitions from a binary and store in DB.

        Idempotent: skips if DwarfType records already exist for this binary.

        Returns:
            (type_count, member_count) inserted
        """
        from blackadder.binutils.dwarf_parser import parse_dwarf_types

        binary_id = await self._get_binary_id_for_path(binary_path)
        if binary_id is None:
            raise ValueError(f"Binary not in DB: {binary_path}. Run 'load' first.")

        # Idempotency check
        async with self.manager.get_session() as session:
            result = await session.execute(
                select(DwarfType).where(DwarfType.binary_id == binary_id).limit(1)
            )
            if result.scalars().first() is not None:
                logger.debug("dwarf_types_already_loaded", extra={"binary": binary_path})
                return 0, 0

        types, members = await parse_dwarf_types(binary_path, self.config)

        if not types:
            return 0, 0

        # Build die_offset → db_id map for member linkage
        async with self.manager.get_session() as session:
            die_to_id: dict[int, int] = {}
            for t in types:
                obj = DwarfType(
                    binary_id=binary_id,
                    die_offset=t["die_offset"],
                    tag=t["tag"],
                    name=t.get("name"),
                    byte_size=t.get("byte_size"),
                    type_ref=t.get("type_ref"),
                    encoding=t.get("encoding"),
                )
                session.add(obj)
                await session.flush()
                die_to_id[t["die_offset"]] = obj.id  # type: ignore[index]

            for m in members:
                parent_id = die_to_id.get(m["parent_die_offset"])
                if parent_id is None:
                    continue
                session.add(DwarfMember(
                    type_id=parent_id,
                    name=m.get("name"),
                    byte_offset=m["byte_offset"],
                    member_type_ref=m["member_type_ref"],
                ))

            await session.commit()

        logger.debug(
            "dwarf_types_loaded",
            extra={"binary": binary_path, "types": len(types), "members": len(members)},
        )
        return len(types), len(members)

    async def load_debug_line(self, binary_path: str) -> int:
        """
        Extract source line→address mappings from a binary and store in DB.

        Idempotent: skips if DebugLine records already exist for this binary.

        Returns:
            Number of records inserted
        """
        from blackadder.binutils.dwarf_parser import parse_debug_line

        binary_id = await self._get_binary_id_for_path(binary_path)
        if binary_id is None:
            raise ValueError(f"Binary not in DB: {binary_path}. Run 'load' first.")

        # Idempotency check
        async with self.manager.get_session() as session:
            result = await session.execute(
                select(DebugLine).where(DebugLine.binary_id == binary_id).limit(1)
            )
            if result.scalars().first() is not None:
                logger.debug("debug_line_already_loaded", extra={"binary": binary_path})
                return 0

        records = await parse_debug_line(binary_path, self.config)

        if not records:
            return 0

        # Deduplicate before insert
        seen: set[tuple[str, int, int]] = set()
        async with self.manager.get_session() as session:
            for r in records:
                key = (r["source_file"], r["line_number"], r["address"])
                if key in seen:
                    continue
                seen.add(key)
                session.add(DebugLine(
                    binary_id=binary_id,
                    source_file=r["source_file"],
                    line_number=r["line_number"],
                    address=r["address"],
                ))
            await session.commit()

        logger.debug("debug_line_loaded", extra={"binary": binary_path, "count": len(seen)})
        return len(seen)
