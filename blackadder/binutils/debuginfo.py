"""
Debug-info file discovery.

Implements the search logic from BALDRICK.md: given a binary and its
.gnu_debuglink value, searches for the matching debug file under rootfs/debugfs
using the standard GDB/debuginfod directory conventions.
"""

import glob as glob_module
import logging
from pathlib import Path

logger = logging.getLogger("blackadder.binutils.debuginfo")

_DEBUG_SUFFIXES = (".dbg", ".debug", "-dbg", "-debug")


def find_debug_file(
    binary_path: str,
    debug_link: str | None,
    rootfs: str = "/",
    debugfs: str | None = None,
) -> str | None:
    """
    Find the debug file for a binary.

    Searches paths defined in BALDRICK.md using the binary's .gnu_debuglink
    value and standard debug directory conventions.

    Args:
        binary_path: Absolute local path to the binary (may be under rootfs).
        debug_link:  Value of .gnu_debuglink section (filename or path),
                     or None if the section is absent.
        rootfs:      Path to rootfs (default: /).
        debugfs:     Path to separate debugfs; defaults to rootfs when None.

    Returns:
        Absolute local path to the debug file, or None if not found.
    """
    rootfs_abs = str(Path(rootfs).resolve())
    debugfs_abs = str(Path(debugfs).resolve()) if debugfs else rootfs_abs

    binary_abs = str(Path(binary_path).resolve())

    # Strip rootfs prefix to obtain the target-relative path.
    if binary_abs.startswith(rootfs_abs.rstrip("/") + "/"):
        target_path = binary_abs[len(rootfs_abs.rstrip("/")) :]
    else:
        target_path = binary_abs

    target_dir = str(Path(target_path).parent)  # e.g. /usr/lib
    target_parent = str(Path(target_dir).parent)  # e.g. /usr  (<prefix>)
    binary_name = Path(target_path).name  # e.g. libfoo.so

    candidates: list[str] = []

    if debug_link:
        is_absolute = debug_link.startswith("/")

        if is_absolute:
            # <debugfs><absolute-debug-link>
            candidates.append(debugfs_abs.rstrip("/") + debug_link)
        else:
            # Relative debug_link — search standard locations.
            rel = debug_link
            base = debugfs_abs.rstrip("/")
            dir_part = target_dir.lstrip("/")

            candidates += [
                f"{base}/{dir_part}/{rel}",
                f"{base}/{dir_part}/.debug/{rel}",
            ]
            if target_parent != target_dir:
                parent_part = target_parent.lstrip("/")
                candidates.append(f"{base}/{parent_part}/.debug/{dir_part.split('/')[-1]}/{rel}")

            # Glob: <debugfs><prefix>/.debug/**/<rel>
            glob_pattern = f"{base}/{target_parent.lstrip('/')}/.debug/**/{rel}"
            candidates += glob_module.glob(glob_pattern, recursive=True)
    else:
        # No debug_link — try known suffixes next to or below the binary.
        base = debugfs_abs.rstrip("/")
        dir_part = target_dir.lstrip("/")

        for suffix in _DEBUG_SUFFIXES:
            debug_name = binary_name + suffix
            candidates += [
                f"{base}/{dir_part}/{debug_name}",
                f"{base}/{dir_part}/.debug/{debug_name}",
            ]
            if target_parent != target_dir:
                parent_part = target_parent.lstrip("/")
                candidates.append(
                    f"{base}/{parent_part}/.debug/{dir_part.split('/')[-1]}/{debug_name}"
                )
            # Glob: <debugfs><prefix>/.debug/**/<debug_name>
            glob_pattern = f"{base}/{target_parent.lstrip('/')}/.debug/**/{debug_name}"
            candidates += glob_module.glob(glob_pattern, recursive=True)

    for path in candidates:
        p = Path(path)
        if p.is_file():
            logger.debug(
                "debug_file_found",
                extra={"binary": binary_path, "debug_file": str(p)},
            )
            return str(p)

    logger.debug(
        "debug_file_not_found",
        extra={"binary": binary_path, "debug_link": debug_link},
    )
    return None
