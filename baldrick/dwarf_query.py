"""
DWARF type query helpers for baldrick.

Provides async functions for resolving DWARF types, typedef chains,
and struct field flattening from the canonical_dwarf_type / binary_dwarf_ref
/ dwarfmember schema.

Used by:
  - baldrick/cli/main.py  (cast-mem command)
  - the separately installed baldrick-gdb plugin
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from baldrick.db import AsyncDatabaseManager
    from baldrick.models import CanonicalDwarfType

# (byte_offset, field_path, type_name, byte_size, encoding)
FlatField = tuple[int, str, str, int | None, str | None]

_TRANSPARENT_TAGS = frozenset({"typedef", "const_type", "volatile_type", "restrict_type"})
_COMPOSITE_TAGS = frozenset({"structure_type", "union_type"})


# ============================================================================
# Low-level DB helpers
# ============================================================================


async def get_binary_id(manager: AsyncDatabaseManager, binary_name: str) -> int | None:
    """Return Binary.id for a binary name, or None if not found."""
    from sqlmodel import select

    from baldrick.models import Binary

    async with manager.get_session() as s:
        result = await s.execute(select(Binary).where(Binary.name == binary_name))
        obj = result.scalars().first()
        return obj.id if obj else None  # type: ignore[return-value]


async def get_type_by_name(
    manager: AsyncDatabaseManager,
    name: str,
    bin_id: int,
):
    """Find CanonicalDwarfType by name scoped to a binary."""
    from sqlmodel import select

    from baldrick.models import BinaryDwarfRef, CanonicalDwarfType

    async with manager.get_session() as s:
        result = await s.execute(
            select(CanonicalDwarfType)
            .join(  # type: ignore[arg-type]
                BinaryDwarfRef,
                BinaryDwarfRef.canonical_id == CanonicalDwarfType.id,  # type: ignore[arg-type]
            )
            .where((BinaryDwarfRef.binary_id == bin_id) & (CanonicalDwarfType.name == name))
            .limit(1)
        )
        return result.scalars().first()


async def get_type_by_die(
    manager: AsyncDatabaseManager,
    die_offset: int,
    bin_id: int,
):
    """Resolve die_offset → CanonicalDwarfType via binary_dwarf_ref."""
    from sqlmodel import select

    from baldrick.models import BinaryDwarfRef, CanonicalDwarfType

    async with manager.get_session() as s:
        result = await s.execute(
            select(CanonicalDwarfType)
            .join(  # type: ignore[arg-type]
                BinaryDwarfRef,
                BinaryDwarfRef.canonical_id == CanonicalDwarfType.id,  # type: ignore[arg-type]
            )
            .where((BinaryDwarfRef.binary_id == bin_id) & (BinaryDwarfRef.die_offset == die_offset))
            .limit(1)
        )
        return result.scalars().first()


async def get_type_ref_die(
    manager: AsyncDatabaseManager,
    die_offset: int,
    bin_id: int,
) -> int | None:
    """Get type_ref_die from binary_dwarf_ref (for typedef chain traversal)."""
    from sqlmodel import select

    from baldrick.models import BinaryDwarfRef

    async with manager.get_session() as s:
        result = await s.execute(
            select(BinaryDwarfRef)
            .where((BinaryDwarfRef.binary_id == bin_id) & (BinaryDwarfRef.die_offset == die_offset))
            .limit(1)
        )
        ref = result.scalars().first()
        return ref.type_ref_die if ref else None


async def find_die_for_canonical(
    manager: AsyncDatabaseManager,
    canonical_id: int,
    bin_id: int,
) -> int | None:
    """Find any die_offset for a canonical type in a binary (reverse lookup)."""
    from sqlmodel import select

    from baldrick.models import BinaryDwarfRef

    async with manager.get_session() as s:
        result = await s.execute(
            select(BinaryDwarfRef)
            .where(
                (BinaryDwarfRef.binary_id == bin_id) & (BinaryDwarfRef.canonical_id == canonical_id)
            )
            .limit(1)
        )
        ref = result.scalars().first()
        return ref.die_offset if ref else None


async def get_members(
    manager: AsyncDatabaseManager,
    canonical_type_id: int,
    bin_id: int,
) -> list:
    """Return members for one canonical type occurrence in one binary."""
    from sqlmodel import select

    from baldrick.models import BinaryDwarfRef, DwarfMember

    async with manager.get_session() as s:
        result = await s.execute(
            select(DwarfMember)
            .join(  # type: ignore[arg-type]
                BinaryDwarfRef,
                DwarfMember.binary_ref_id == BinaryDwarfRef.id,  # type: ignore[arg-type]
            )
            .where(
                (BinaryDwarfRef.canonical_id == canonical_type_id)
                & (BinaryDwarfRef.binary_id == bin_id)
            )
        )
        members = list(result.scalars().all())
    return sorted(members, key=lambda m: m.byte_offset)


# ============================================================================
# Typedef chain resolution
# ============================================================================


async def resolve_typedef_chain(
    manager: AsyncDatabaseManager,
    t,
    bin_id: int,
):
    """
    Follow typedef / const_type / volatile_type / restrict_type chain
    to the underlying concrete type (structure_type, base_type, etc.).

    Returns the resolved CanonicalDwarfType (may be same as input if not a typedef).
    """
    visited: set[int] = set()
    current = t
    while current.tag in _TRANSPARENT_TAGS:
        die = await find_die_for_canonical(manager, current.id, bin_id)  # type: ignore[arg-type]
        if die is None or die in visited:
            break
        visited.add(die)
        tref = await get_type_ref_die(manager, die, bin_id)
        if tref is None:
            break
        nxt = await get_type_by_die(manager, tref, bin_id)
        if nxt is None:
            break
        current = nxt
    return current


# ============================================================================
# Struct field flattening
# ============================================================================


async def flatten(
    manager: AsyncDatabaseManager,
    t,
    bin_id: int,
    prefix: str = "",
    base: int = 0,
    depth: int = 0,
) -> list[FlatField]:
    """
    Recursively flatten a struct/union into a list of leaf fields.

    Returns list of (byte_offset, field_path, type_name, byte_size, encoding).
    Nested structs are expanded inline. Max depth: 12.
    """
    if depth > 12:
        return []

    members = await get_members(manager, t.id, bin_id)  # type: ignore[arg-type]
    rows: list[FlatField] = []

    for m in members:
        field_path = f"{prefix}.{m.name}" if m.name else f"{prefix}.<anon>"
        abs_offset = base + m.byte_offset

        mtype = await get_type_by_die(manager, m.member_type_ref, bin_id)
        if mtype is None:
            rows.append((abs_offset, field_path, "?", None, None))
            continue

        # Resolve typedef chain for member type
        inner = await resolve_typedef_chain(manager, mtype, bin_id)

        if inner.tag in _COMPOSITE_TAGS:
            sub = await flatten(
                manager,
                inner,
                bin_id,
                prefix=field_path,
                base=abs_offset,
                depth=depth + 1,
            )
            rows.extend(sub)
        else:
            rows.append(
                (
                    abs_offset,
                    field_path,
                    inner.name or inner.tag,
                    inner.byte_size,
                    inner.encoding,
                )
            )

    return rows


# ============================================================================
# High-level entry point: resolve type by name + flatten
# ============================================================================


async def get_variables_for_subprogram(
    manager: AsyncDatabaseManager,
    subprogram_name: str,
    bin_id: int,
) -> list:
    """Return DwarfVariable records for a named subprogram in a binary."""
    from sqlmodel import select

    from baldrick.models import DwarfSubprogram, DwarfVariable

    async with manager.get_session() as s:
        sp_result = await s.execute(
            select(DwarfSubprogram)
            .where(
                (DwarfSubprogram.binary_id == bin_id) & (DwarfSubprogram.name == subprogram_name)
            )
            .limit(1)
        )
        sp = sp_result.scalars().first()
        if sp is None:
            return []
        var_result = await s.execute(
            select(DwarfVariable).where(DwarfVariable.subprogram_id == sp.id)
        )
        return list(var_result.scalars().all())


async def find_local_var_at_fbreg(
    manager: AsyncDatabaseManager,
    subprogram_name: str,
    bin_id: int,
    fbreg_offset: int,
) -> object | None:
    """Find a DwarfVariable covering a given frame-base offset.

    Returns the DwarfVariable whose fbreg range covers fbreg_offset, or None.
    For "fbreg" location types: variable spans [fbreg_offset, fbreg_offset+size).
    We find the variable with location_fbreg <= fbreg_offset and
    location_fbreg + type_size > fbreg_offset (if type size known).
    Falls back to exact match if size is unknown.
    """
    from sqlmodel import select

    from baldrick.models import CanonicalDwarfType, DwarfSubprogram, DwarfVariable

    async with manager.get_session() as s:
        sp_result = await s.execute(
            select(DwarfSubprogram)
            .where(
                (DwarfSubprogram.binary_id == bin_id) & (DwarfSubprogram.name == subprogram_name)
            )
            .limit(1)
        )
        sp = sp_result.scalars().first()
        if sp is None:
            return None

        # All fbreg variables in this subprogram
        var_result = await s.execute(
            select(DwarfVariable).where(
                (DwarfVariable.subprogram_id == sp.id) & (DwarfVariable.location_type == "fbreg")
            )
        )
        vars_ = list(var_result.scalars().all())

    # Match in Python: need type size — fetch canonical types
    for v in vars_:
        var_fbreg = v.location_fbreg
        if var_fbreg is None:
            continue
        if v.canonical_type_id is not None:
            async with manager.get_session() as s:
                ct_result = await s.execute(
                    select(CanonicalDwarfType).where(CanonicalDwarfType.id == v.canonical_type_id)
                )
                ct = ct_result.scalars().first()
            size = ct.byte_size if ct and ct.byte_size else 1
        else:
            size = 1
        # fbreg is signed, negative = below frame base
        # Variable spans [var_fbreg, var_fbreg + size)
        if var_fbreg <= fbreg_offset < var_fbreg + size:
            return v

    return None


async def resolve_and_flatten(
    manager: AsyncDatabaseManager,
    type_name: str,
    bin_id: int,
) -> tuple[CanonicalDwarfType, list[FlatField]] | None:
    """
    Resolve type_name in binary (bin_id), follow typedef chain,
    and flatten to leaf fields.

    Returns (root_type, flat_fields) or None if type not found.
    """
    root = await get_type_by_name(manager, type_name, bin_id)
    if root is None:
        return None

    root = await resolve_typedef_chain(manager, root, bin_id)
    flat = await flatten(manager, root, bin_id, prefix=type_name)
    return root, flat
