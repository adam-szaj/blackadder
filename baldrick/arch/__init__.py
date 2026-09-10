"""
Architecture-specific modules for register handling and assembly normalization.

Supports: x86/x86-64, ARM/ARM64 (32/64-bit), and RISC-V (RV32I/RV64I).
"""

from baldrick.arch.arm import ARM64Architecture, ARMArchitecture
from baldrick.arch.base import Architecture, RegisterInfo
from baldrick.arch.detector import (
    SUPPORTED_ARCHITECTURES,
    detect_architecture,
    get_architecture,
)
from baldrick.arch.riscv import RV32Architecture, RV64Architecture
from baldrick.arch.x86 import X86_64Architecture, X86Architecture

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
