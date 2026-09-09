"""
Architecture detection from ELF files.

Determines the target architecture of a binary based on its ELF headers.
"""

import logging
from pathlib import Path

from blackadder.arch.arm import ARM64Architecture, ARMArchitecture
from blackadder.arch.base import Architecture
from blackadder.arch.riscv import RV32Architecture, RV64Architecture
from blackadder.arch.x86 import X86_64Architecture, X86Architecture
from blackadder.exceptions import FileFormatError

logger = logging.getLogger("blackadder.arch.detector")

# Map ELF e_machine values to Architecture classes
# Note: For RISC-V, we default to RV64I (64-bit) as the more common variant
ARCHITECTURE_MAP: dict[int, type[Architecture]] = {
    3: X86Architecture,  # EM_386
    62: X86_64Architecture,  # EM_X86_64
    40: ARMArchitecture,  # EM_ARM
    183: ARM64Architecture,  # EM_AARCH64
    243: RV64Architecture,  # EM_RISCV (defaults to 64-bit; refine with ELF class if needed)
}

# Architecture families
SUPPORTED_ARCHITECTURES = {
    "x86": (X86Architecture, X86_64Architecture),
    "arm": (ARMArchitecture, ARM64Architecture),
    "riscv": (RV32Architecture, RV64Architecture),
}


def detect_architecture(binary_path: str) -> Architecture:
    """
    Detect architecture from ELF binary.

    Reads the ELF header (e_machine field) and returns an appropriate
    Architecture instance.

    Args:
        binary_path: Path to ELF binary

    Returns:
        Architecture instance

    Raises:
        FileNotFoundError: If binary not found
        FileFormatError: If binary is not a valid ELF file
    """
    binary_file = Path(binary_path)

    if not binary_file.exists():
        logger.error(
            "binary_not_found_for_detection",
            extra={"binary_path": binary_path},
        )
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    try:
        with open(binary_file, "rb") as f:
            # Read ELF header
            elf_header = f.read(20)

            if len(elf_header) < 20:
                logger.error(
                    "invalid_elf_header_size",
                    extra={"binary_path": binary_path, "size": len(elf_header)},
                )
                raise FileFormatError("File too small to be ELF")

            # Check ELF magic number
            if elf_header[:4] != b"\x7fELF":
                logger.error(
                    "invalid_elf_magic",
                    extra={"binary_path": binary_path},
                )
                raise FileFormatError("Not an ELF file (invalid magic number)")

            # Get e_machine (bytes 18-19, little-endian)
            ei_data = elf_header[5]  # EI_DATA byte
            e_machine_bytes = elf_header[18:20]

            if ei_data == 1:  # ELFDATA2LSB (little-endian)
                e_machine = int.from_bytes(e_machine_bytes, byteorder="little")
            elif ei_data == 2:  # ELFDATA2MSB (big-endian)
                e_machine = int.from_bytes(e_machine_bytes, byteorder="big")
            else:
                logger.error(
                    "invalid_elf_data_encoding",
                    extra={"binary_path": binary_path, "ei_data": ei_data},
                )
                raise FileFormatError(f"Invalid ELF data encoding: {ei_data}")

            logger.debug(
                "detected_elf_machine",
                extra={"binary_path": binary_path, "e_machine": e_machine},
            )

            # Look up architecture
            if e_machine not in ARCHITECTURE_MAP:
                logger.warning(
                    "unsupported_architecture",
                    extra={
                        "binary_path": binary_path,
                        "e_machine": e_machine,
                    },
                )
                raise FileFormatError(f"Unsupported architecture: e_machine={e_machine}")

            arch_class = ARCHITECTURE_MAP[e_machine]
            arch = arch_class()

            logger.info(
                "architecture_detected",
                extra={
                    "binary_path": binary_path,
                    "architecture": arch.arch_variant,
                },
            )

            return arch

    except OSError as e:
        logger.error(
            "failed_to_read_binary",
            extra={"binary_path": binary_path, "error": str(e)},
        )
        raise FileFormatError(f"Failed to read binary: {e}") from e


def get_architecture(variant: str) -> Architecture:
    """
    Get an architecture instance by variant name.

    Args:
        variant: Architecture variant string
                 ("x86", "x86_64", "arm", "arm64", "rv32i", "rv64i")

    Returns:
        Architecture instance

    Raises:
        ValueError: If variant is not supported
    """
    if variant == "x86":
        return X86Architecture()
    elif variant == "x86_64":
        return X86_64Architecture()
    elif variant == "arm":
        return ARMArchitecture()
    elif variant == "arm64":
        return ARM64Architecture()
    elif variant == "rv32i" or variant == "riscv32":
        return RV32Architecture()
    elif variant == "rv64i" or variant == "riscv64":
        return RV64Architecture()
    else:
        raise ValueError(f"Unsupported architecture variant: {variant}")
