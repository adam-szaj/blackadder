"""
RISC-V architecture implementations.

Provides register handling, assembly normalization, and stack detection
for 32-bit RISC-V (RV32I) and 64-bit RISC-V (RV64I) architectures.
"""

import re
from typing import ClassVar

from baldrick.arch.base import Architecture, RegisterInfo


class RV32Architecture(Architecture):
    """32-bit RISC-V (RV32I) architecture."""

    arch_family: ClassVar[str] = "riscv"
    arch_variant: ClassVar[str] = "rv32i"
    machine_type: ClassVar[int] = 243  # EM_RISCV

    # 32-bit RISC-V registers (x0-x31)
    registers: ClassVar[dict[str, RegisterInfo]] = {
        # Permanent registers
        "x0": RegisterInfo("x0", 32, ["zero"], "special"),  # Hardwired zero
        # Return address
        "x1": RegisterInfo("x1", 32, ["ra"], "special"),
        # Stack pointer
        "x2": RegisterInfo("x2", 32, ["sp"], "special"),
        # Global pointer
        "x3": RegisterInfo("x3", 32, ["gp"], "special"),
        # Thread pointer
        "x4": RegisterInfo("x4", 32, ["tp"], "special"),
        # Temporaries
        "x5": RegisterInfo("x5", 32, ["t0"], "general"),
        "x6": RegisterInfo("x6", 32, ["t1"], "general"),
        "x7": RegisterInfo("x7", 32, ["t2"], "general"),
        # Saved register / Frame pointer
        "x8": RegisterInfo("x8", 32, ["s0", "fp"], "special"),
        "x9": RegisterInfo("x9", 32, ["s1"], "general"),
        # Arguments / Return values
        "x10": RegisterInfo("x10", 32, ["a0"], "general"),
        "x11": RegisterInfo("x11", 32, ["a1"], "general"),
        # Arguments
        "x12": RegisterInfo("x12", 32, ["a2"], "general"),
        "x13": RegisterInfo("x13", 32, ["a3"], "general"),
        "x14": RegisterInfo("x14", 32, ["a4"], "general"),
        "x15": RegisterInfo("x15", 32, ["a5"], "general"),
        "x16": RegisterInfo("x16", 32, ["a6"], "general"),
        "x17": RegisterInfo("x17", 32, ["a7"], "general"),
        # Saved registers
        "x18": RegisterInfo("x18", 32, ["s2"], "general"),
        "x19": RegisterInfo("x19", 32, ["s3"], "general"),
        "x20": RegisterInfo("x20", 32, ["s4"], "general"),
        "x21": RegisterInfo("x21", 32, ["s5"], "general"),
        "x22": RegisterInfo("x22", 32, ["s6"], "general"),
        "x23": RegisterInfo("x23", 32, ["s7"], "general"),
        "x24": RegisterInfo("x24", 32, ["s8"], "general"),
        "x25": RegisterInfo("x25", 32, ["s9"], "general"),
        "x26": RegisterInfo("x26", 32, ["s10"], "general"),
        "x27": RegisterInfo("x27", 32, ["s11"], "general"),
        # Temporaries
        "x28": RegisterInfo("x28", 32, ["t3"], "general"),
        "x29": RegisterInfo("x29", 32, ["t4"], "general"),
        "x30": RegisterInfo("x30", 32, ["t5"], "general"),
        "x31": RegisterInfo("x31", 32, ["t6"], "general"),
    }

    gp_registers: ClassVar[list[str]] = [
        "x5",
        "x6",
        "x7",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x28",
        "x29",
        "x30",
        "x31",
    ]
    sp_register: ClassVar[str] = "x2"  # sp / x2
    bp_register: ClassVar[str] = "x8"  # fp / x8 (s0)
    pc_register: ClassVar[str] = "pc"

    def normalize_instruction(self, instruction: str) -> str:
        """Normalize RISC-V assembly instruction for fingerprinting."""
        # Remove comments
        if "#" in instruction:
            instruction = instruction.split("#")[0]

        instruction = instruction.strip()
        if not instruction:
            return ""

        # Normalize absolute addresses
        instruction = re.sub(r"0x[0-9a-f]+", "0xADDR", instruction)

        # Normalize register names
        for pattern, replacement in self.get_register_normalization_map().items():
            instruction = re.sub(pattern, replacement, instruction)

        # Normalize immediate values
        instruction = re.sub(r"\b0x[0-9a-f]+\b", "IMM", instruction)
        instruction = re.sub(r"\b-?\d+\b", "IMM", instruction)

        return instruction

    def get_register_normalization_map(self) -> dict[str, str]:
        """Get RISC-V register normalization patterns for assembly hashing."""
        return {
            # Arguments/Return values
            r"x1[0-1]\b": "%REG_ARG",  # x10-x11
            r"%a[0-7]\b": "%REG_ARG",  # a0-a7 aliases
            # Temporaries
            r"x[567]\b": "%REG_TEMP",  # x5-x7
            r"x2[89]\b": "%REG_TEMP",  # x28-x29
            r"x3[01]\b": "%REG_TEMP",  # x30-x31
            r"%t[0-6]\b": "%REG_TEMP",  # t0-t6 aliases
            # Saved registers
            r"x[89]\b": "%REG_SAVED",  # x8-x9 (s0-s1)
            r"x1[89]\b": "%REG_SAVED",  # x18-x19
            r"x2[0-7]\b": "%REG_SAVED",  # x20-x27
            r"%s[0-9]\b": "%REG_SAVED",  # s0-s9 aliases
            r"%s1[01]\b": "%REG_SAVED",  # s10-s11 aliases
            # Special registers
            r"x2\b": "%REG_SP",  # Stack pointer
            r"x8\b": "%REG_FP",  # Frame pointer (s0)
            r"%sp\b": "%REG_SP",  # sp alias
            r"%fp\b": "%REG_FP",  # fp alias
            r"x1\b": "%REG_LR",  # Link register (ra)
            r"%ra\b": "%REG_LR",  # ra alias
        }

    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """Detect stack region using SP (x2) and FP (x8)."""
        if not register_state:
            return (False, 0.0)

        sp = self.get_register_value(register_state, self.sp_register)
        fp = self.get_register_value(register_state, self.bp_register)

        # Stack pointer in region
        if sp and start_addr <= sp < end_addr:
            return (True, 0.95)

        # Frame pointer in region
        if fp and start_addr <= fp < end_addr:
            return (True, 0.90)

        return (False, 0.0)


class RV64Architecture(Architecture):
    """64-bit RISC-V (RV64I) architecture."""

    arch_family: ClassVar[str] = "riscv"
    arch_variant: ClassVar[str] = "rv64i"
    machine_type: ClassVar[int] = 243  # EM_RISCV (same as RV32I, distinguished by ELF class)

    # 64-bit RISC-V registers (x0-x31, same naming as RV32 but 64-bit values)
    registers: ClassVar[dict[str, RegisterInfo]] = {
        # Permanent registers
        "x0": RegisterInfo("x0", 64, ["zero"], "special"),  # Hardwired zero
        # Return address
        "x1": RegisterInfo("x1", 64, ["ra"], "special"),
        # Stack pointer
        "x2": RegisterInfo("x2", 64, ["sp"], "special"),
        # Global pointer
        "x3": RegisterInfo("x3", 64, ["gp"], "special"),
        # Thread pointer
        "x4": RegisterInfo("x4", 64, ["tp"], "special"),
        # Temporaries
        "x5": RegisterInfo("x5", 64, ["t0"], "general"),
        "x6": RegisterInfo("x6", 64, ["t1"], "general"),
        "x7": RegisterInfo("x7", 64, ["t2"], "general"),
        # Saved register / Frame pointer
        "x8": RegisterInfo("x8", 64, ["s0", "fp"], "special"),
        "x9": RegisterInfo("x9", 64, ["s1"], "general"),
        # Arguments / Return values
        "x10": RegisterInfo("x10", 64, ["a0"], "general"),
        "x11": RegisterInfo("x11", 64, ["a1"], "general"),
        # Arguments
        "x12": RegisterInfo("x12", 64, ["a2"], "general"),
        "x13": RegisterInfo("x13", 64, ["a3"], "general"),
        "x14": RegisterInfo("x14", 64, ["a4"], "general"),
        "x15": RegisterInfo("x15", 64, ["a5"], "general"),
        "x16": RegisterInfo("x16", 64, ["a6"], "general"),
        "x17": RegisterInfo("x17", 64, ["a7"], "general"),
        # Saved registers
        "x18": RegisterInfo("x18", 64, ["s2"], "general"),
        "x19": RegisterInfo("x19", 64, ["s3"], "general"),
        "x20": RegisterInfo("x20", 64, ["s4"], "general"),
        "x21": RegisterInfo("x21", 64, ["s5"], "general"),
        "x22": RegisterInfo("x22", 64, ["s6"], "general"),
        "x23": RegisterInfo("x23", 64, ["s7"], "general"),
        "x24": RegisterInfo("x24", 64, ["s8"], "general"),
        "x25": RegisterInfo("x25", 64, ["s9"], "general"),
        "x26": RegisterInfo("x26", 64, ["s10"], "general"),
        "x27": RegisterInfo("x27", 64, ["s11"], "general"),
        # Temporaries
        "x28": RegisterInfo("x28", 64, ["t3"], "general"),
        "x29": RegisterInfo("x29", 64, ["t4"], "general"),
        "x30": RegisterInfo("x30", 64, ["t5"], "general"),
        "x31": RegisterInfo("x31", 64, ["t6"], "general"),
    }

    gp_registers: ClassVar[list[str]] = [
        "x5",
        "x6",
        "x7",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x28",
        "x29",
        "x30",
        "x31",
    ]
    sp_register: ClassVar[str] = "x2"  # sp / x2
    bp_register: ClassVar[str] = "x8"  # fp / x8 (s0)
    pc_register: ClassVar[str] = "pc"

    def normalize_instruction(self, instruction: str) -> str:
        """Normalize RISC-V assembly instruction for fingerprinting."""
        # Remove comments
        if "#" in instruction:
            instruction = instruction.split("#")[0]

        instruction = instruction.strip()
        if not instruction:
            return ""

        # Normalize absolute addresses
        instruction = re.sub(r"0x[0-9a-f]+", "0xADDR", instruction)

        # Normalize register names
        for pattern, replacement in self.get_register_normalization_map().items():
            instruction = re.sub(pattern, replacement, instruction)

        # Normalize immediate values
        instruction = re.sub(r"\b0x[0-9a-f]+\b", "IMM", instruction)
        instruction = re.sub(r"\b-?\d+\b", "IMM", instruction)

        return instruction

    def get_register_normalization_map(self) -> dict[str, str]:
        """Get RISC-V register normalization patterns for assembly hashing."""
        return {
            # Arguments/Return values
            r"x1[0-1]\b": "%REG_ARG",  # x10-x11
            r"%a[0-7]\b": "%REG_ARG",  # a0-a7 aliases
            # Temporaries
            r"x[567]\b": "%REG_TEMP",  # x5-x7
            r"x2[89]\b": "%REG_TEMP",  # x28-x29
            r"x3[01]\b": "%REG_TEMP",  # x30-x31
            r"%t[0-6]\b": "%REG_TEMP",  # t0-t6 aliases
            # Saved registers
            r"x[89]\b": "%REG_SAVED",  # x8-x9 (s0-s1)
            r"x1[89]\b": "%REG_SAVED",  # x18-x19
            r"x2[0-7]\b": "%REG_SAVED",  # x20-x27
            r"%s[0-9]\b": "%REG_SAVED",  # s0-s9 aliases
            r"%s1[01]\b": "%REG_SAVED",  # s10-s11 aliases
            # Special registers
            r"x2\b": "%REG_SP",  # Stack pointer
            r"x8\b": "%REG_FP",  # Frame pointer (s0)
            r"%sp\b": "%REG_SP",  # sp alias
            r"%fp\b": "%REG_FP",  # fp alias
            r"x1\b": "%REG_LR",  # Link register (ra)
            r"%ra\b": "%REG_LR",  # ra alias
        }

    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """Detect stack region using SP (x2) and FP (x8)."""
        if not register_state:
            return (False, 0.0)

        sp = self.get_register_value(register_state, self.sp_register)
        fp = self.get_register_value(register_state, self.bp_register)

        # Stack pointer in region
        if sp and start_addr <= sp < end_addr:
            return (True, 0.95)

        # Frame pointer in region
        if fp and start_addr <= fp < end_addr:
            return (True, 0.90)

        return (False, 0.0)
