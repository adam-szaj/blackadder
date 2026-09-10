"""
ARM and ARM64 (AArch64) architecture implementations.

Provides register handling, assembly normalization, and stack detection
for 32-bit ARM and 64-bit ARM64 architectures.
"""

import re
from typing import ClassVar

from baldrick.arch.base import Architecture, RegisterInfo


class ARMArchitecture(Architecture):
    """32-bit ARM architecture."""

    arch_family: ClassVar[str] = "arm"
    arch_variant: ClassVar[str] = "arm"
    machine_type: ClassVar[int] = 40  # EM_ARM

    # 32-bit ARM registers
    registers: ClassVar[dict[str, RegisterInfo]] = {
        "r0": RegisterInfo("r0", 32, ["a1"], "general"),
        "r1": RegisterInfo("r1", 32, ["a2"], "general"),
        "r2": RegisterInfo("r2", 32, ["a3"], "general"),
        "r3": RegisterInfo("r3", 32, ["a4"], "general"),
        "r4": RegisterInfo("r4", 32, ["v1"], "general"),
        "r5": RegisterInfo("r5", 32, ["v2"], "general"),
        "r6": RegisterInfo("r6", 32, ["v3"], "general"),
        "r7": RegisterInfo("r7", 32, ["v4"], "general"),
        "r8": RegisterInfo("r8", 32, ["v5"], "general"),
        "r9": RegisterInfo("r9", 32, ["v6"], "general"),
        "r10": RegisterInfo("r10", 32, ["v7"], "general"),
        "r11": RegisterInfo("r11", 32, ["fp"], "special"),  # Frame pointer
        "r12": RegisterInfo("r12", 32, ["ip"], "special"),  # Intra-procedure call
        "r13": RegisterInfo("r13", 32, ["sp"], "special"),  # Stack pointer
        "r14": RegisterInfo("r14", 32, ["lr"], "special"),  # Link register
        "r15": RegisterInfo("r15", 32, ["pc"], "special"),  # Program counter
        "cpsr": RegisterInfo("cpsr", 32, [], "flag"),  # Current program status
    }

    gp_registers: ClassVar[list[str]] = [
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
    ]
    sp_register: ClassVar[str] = "r13"  # sp / r13
    bp_register: ClassVar[str] = "r11"  # fp / r11
    pc_register: ClassVar[str] = "r15"  # pc / r15

    def normalize_instruction(self, instruction: str) -> str:
        """Normalize ARM assembly instruction for fingerprinting."""
        # Remove comments
        if "@" in instruction:
            instruction = instruction.split("@")[0]
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
        instruction = re.sub(r"#0x[0-9a-f]+", "#IMM", instruction)
        instruction = re.sub(r"#-?\d+", "#IMM", instruction)

        return instruction

    def get_register_normalization_map(self) -> dict[str, str]:
        """Get ARM register normalization patterns for assembly hashing."""
        return {
            r"(r|a)[0-3]\b": "%REG_A",  # r0-r3, a1-a4 (argument/result registers)
            r"(r|v)[4-9]\b": "%REG_V",  # r4-r9, v1-v6 (variable/saved registers)
            r"r1[0-2]\b": "%REG_SPECIAL",  # r10, r11, r12 (special purpose)
            r"sp\b": "%REG_SP",  # Stack pointer
            r"fp\b": "%REG_FP",  # Frame pointer
            r"ip\b": "%REG_IP",  # Intra-procedure call
            r"lr\b": "%REG_LR",  # Link register
            r"pc\b": "%REG_PC",  # Program counter
        }

    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """Detect stack region using R13 (SP) and R11 (FP)."""
        if not register_state:
            return (False, 0.0)

        sp = self.get_register_value(register_state, self.sp_register)
        fp = self.get_register_value(register_state, self.bp_register)

        # Stack pointer (R13) in region
        if sp and start_addr <= sp < end_addr:
            return (True, 0.95)

        # Frame pointer (R11) in region
        if fp and start_addr <= fp < end_addr:
            return (True, 0.90)

        return (False, 0.0)


class ARM64Architecture(Architecture):
    """64-bit ARM64 (AArch64) architecture."""

    arch_family: ClassVar[str] = "arm"
    arch_variant: ClassVar[str] = "arm64"
    machine_type: ClassVar[int] = 183  # EM_AARCH64

    # 64-bit ARM64 registers
    registers: ClassVar[dict[str, RegisterInfo]] = {
        # General purpose registers (argument/result)
        "x0": RegisterInfo("x0", 64, ["w0"], "general"),
        "x1": RegisterInfo("x1", 64, ["w1"], "general"),
        "x2": RegisterInfo("x2", 64, ["w2"], "general"),
        "x3": RegisterInfo("x3", 64, ["w3"], "general"),
        "x4": RegisterInfo("x4", 64, ["w4"], "general"),
        "x5": RegisterInfo("x5", 64, ["w5"], "general"),
        "x6": RegisterInfo("x6", 64, ["w6"], "general"),
        "x7": RegisterInfo("x7", 64, ["w7"], "general"),
        # Callee-saved/temporary
        "x8": RegisterInfo("x8", 64, ["w8"], "general"),
        "x9": RegisterInfo("x9", 64, ["w9"], "general"),
        "x10": RegisterInfo("x10", 64, ["w10"], "general"),
        "x11": RegisterInfo("x11", 64, ["w11"], "general"),
        "x12": RegisterInfo("x12", 64, ["w12"], "general"),
        "x13": RegisterInfo("x13", 64, ["w13"], "general"),
        "x14": RegisterInfo("x14", 64, ["w14"], "general"),
        "x15": RegisterInfo("x15", 64, ["w15"], "general"),
        "x16": RegisterInfo("x16", 64, ["w16"], "general"),
        "x17": RegisterInfo("x17", 64, ["w17"], "general"),
        "x18": RegisterInfo("x18", 64, ["w18"], "general"),
        "x19": RegisterInfo("x19", 64, ["w19"], "general"),
        "x20": RegisterInfo("x20", 64, ["w20"], "general"),
        "x21": RegisterInfo("x21", 64, ["w21"], "general"),
        "x22": RegisterInfo("x22", 64, ["w22"], "general"),
        "x23": RegisterInfo("x23", 64, ["w23"], "general"),
        "x24": RegisterInfo("x24", 64, ["w24"], "general"),
        "x25": RegisterInfo("x25", 64, ["w25"], "general"),
        "x26": RegisterInfo("x26", 64, ["w26"], "general"),
        "x27": RegisterInfo("x27", 64, ["w27"], "general"),
        "x28": RegisterInfo("x28", 64, ["w28"], "general"),
        # Special registers
        "x29": RegisterInfo("x29", 64, ["w29", "fp"], "special"),  # Frame pointer
        "x30": RegisterInfo("x30", 64, ["w30", "lr"], "special"),  # Link register
        "sp": RegisterInfo("sp", 64, ["wsp"], "special"),  # Stack pointer
        "pc": RegisterInfo("pc", 64, [], "special"),  # Program counter
        "nzcv": RegisterInfo("nzcv", 64, [], "flag"),  # Status flags
    }

    gp_registers: ClassVar[list[str]] = [
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "x9",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x18",
        "x19",
        "x20",
        "x21",
        "x22",
        "x23",
        "x24",
        "x25",
        "x26",
        "x27",
        "x28",
    ]
    sp_register: ClassVar[str] = "sp"
    bp_register: ClassVar[str] = "x29"  # fp
    pc_register: ClassVar[str] = "pc"

    def normalize_instruction(self, instruction: str) -> str:
        """Normalize ARM64 assembly instruction for fingerprinting."""
        # Remove comments
        if "//" in instruction:
            instruction = instruction.split("//")[0]
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
        instruction = re.sub(r"#0x[0-9a-f]+", "#IMM", instruction)
        instruction = re.sub(r"#-?\d+", "#IMM", instruction)

        return instruction

    def get_register_normalization_map(self) -> dict[str, str]:
        """Get ARM64 register normalization patterns for assembly hashing."""
        return {
            r"[xw][0-7]\b": "%REG_ARG",  # x0-x7, w0-w7 (argument/result)
            r"[xw]([8-9]|1[0-8])\b": "%REG_TEMP",  # x8-x18, w8-w18 (temporary)
            r"[xw](1[9-9]|2[0-8])\b": "%REG_SAVED",  # x19-x28, w19-w28 (saved)
            r"[xw]29\b": "%REG_FP",  # x29, w29 (frame pointer)
            r"[xw]30\b": "%REG_LR",  # x30, w30 (link register)
            r"sp\b": "%REG_SP",  # Stack pointer
            r"fp\b": "%REG_FP",  # Frame pointer (alias for x29)
            r"lr\b": "%REG_LR",  # Link register (alias for x30)
            r"pc\b": "%REG_PC",  # Program counter
        }

    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """Detect stack region using SP and X29 (FP)."""
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
