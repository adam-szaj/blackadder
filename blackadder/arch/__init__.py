"""
Architecture-specific modules for register handling and assembly normalization.

Supports: x86/x86-64, ARM/ARM64 (32/64-bit), and RISC-V (RV32I/RV64I).
"""

from blackadder.arch.arm import ARM64Architecture, ARMArchitecture
from blackadder.arch.base import Architecture, RegisterInfo
from blackadder.arch.detector import (
    SUPPORTED_ARCHITECTURES,
    detect_architecture,
    get_architecture,
)
from blackadder.arch.riscv import RV32Architecture, RV64Architecture
from blackadder.arch.x86 import X86_64Architecture, X86Architecture

__all__ = [
    "Architecture",
    "RegisterInfo",
    "X86Architecture",
    "X86_64Architecture",
    "ARMArchitecture",
    "ARM64Architecture",
    "RV32Architecture",
    "RV64Architecture",
    "detect_architecture",
    "get_architecture",
    "SUPPORTED_ARCHITECTURES",
]
