"""
x86 and x86-64 architecture implementations.

Provides register handling, assembly normalization, and stack detection
for 32-bit x86 and 64-bit x86-64 architectures.
"""

import re
from typing import ClassVar

from blackadder.arch.base import Architecture, RegisterInfo


class X86Architecture(Architecture):
    """32-bit x86 (Intel 80386+) architecture."""

    arch_family: ClassVar[str] = "x86"
    arch_variant: ClassVar[str] = "x86"
    machine_type: ClassVar[int] = 3  # EM_386

    # 32-bit x86 registers
    registers: ClassVar[dict[str, RegisterInfo]] = {
        "eax": RegisterInfo("eax", 32, ["ax", "al", "ah"], "general"),
        "ebx": RegisterInfo("ebx", 32, ["bx", "bl", "bh"], "general"),
        "ecx": RegisterInfo("ecx", 32, ["cx", "cl", "ch"], "general"),
        "edx": RegisterInfo("edx", 32, ["dx", "dl", "dh"], "general"),
        "esi": RegisterInfo("esi", 32, ["si", "sil"], "general"),
        "edi": RegisterInfo("edi", 32, ["di", "dil"], "general"),
        "ebp": RegisterInfo("ebp", 32, ["bp"], "special"),  # Base/frame pointer
        "esp": RegisterInfo("esp", 32, ["sp"], "special"),  # Stack pointer
        "eip": RegisterInfo("eip", 32, ["ip"], "special"),  # Instruction pointer
        "eflags": RegisterInfo("eflags", 32, ["flags"], "flag"),
    }

    gp_registers: ClassVar[list[str]] = [
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "esp",
    ]
    sp_register: ClassVar[str] = "esp"
    bp_register: ClassVar[str] = "ebp"
    pc_register: ClassVar[str] = "eip"

    def normalize_instruction(self, instruction: str) -> str:
        """Normalize x86 assembly instruction for fingerprinting."""
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
        instruction = re.sub(r"\$0x[0-9a-f]+", "$IMM", instruction)
        instruction = re.sub(r"\$-?\d+", "$IMM", instruction)

        return instruction

    def get_register_normalization_map(self) -> dict[str, str]:
        """Get x86 register normalization patterns for assembly hashing."""
        return {
            r"%e?ax": "%REG_A",  # eax, ax -> REG_A
            r"%e?bx": "%REG_B",  # ebx, bx -> REG_B
            r"%e?cx": "%REG_C",  # ecx, cx -> REG_C
            r"%e?dx": "%REG_D",  # edx, dx -> REG_D
            r"%e?si": "%REG_IDX",  # esi, si -> REG_IDX
            r"%e?di": "%REG_IDI",  # edi, di -> REG_IDI
            r"%e?bp": "%REG_BP",  # ebp, bp -> REG_BP
            r"%e?sp": "%REG_SP",  # esp, sp -> REG_SP
        }

    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """Detect stack region using ESP (stack pointer)."""
        if not register_state:
            return (False, 0.0)

        esp = self.get_register_value(register_state, self.sp_register)
        ebp = self.get_register_value(register_state, self.bp_register)

        if esp and start_addr <= esp < end_addr:
            return (True, 0.95)

        if ebp and start_addr <= ebp < end_addr:
            return (True, 0.90)

        return (False, 0.0)


class X86_64Architecture(Architecture):
    """64-bit x86-64 (AMD64/Intel 64) architecture."""

    arch_family: ClassVar[str] = "x86"
    arch_variant: ClassVar[str] = "x86_64"
    machine_type: ClassVar[int] = 62  # EM_X86_64

    # 64-bit x86-64 registers
    registers: ClassVar[dict[str, RegisterInfo]] = {
        # 64-bit GP registers
        "rax": RegisterInfo("rax", 64, ["eax", "ax", "al"], "general"),
        "rbx": RegisterInfo("rbx", 64, ["ebx", "bx", "bl"], "general"),
        "rcx": RegisterInfo("rcx", 64, ["ecx", "cx", "cl"], "general"),
        "rdx": RegisterInfo("rdx", 64, ["edx", "dx", "dl"], "general"),
        "rsi": RegisterInfo("rsi", 64, ["esi", "si", "sil"], "general"),
        "rdi": RegisterInfo("rdi", 64, ["edi", "di", "dil"], "general"),
        "rbp": RegisterInfo("rbp", 64, ["ebp", "bp"], "special"),  # Base pointer
        "rsp": RegisterInfo("rsp", 64, ["esp", "sp"], "special"),  # Stack pointer
        "rip": RegisterInfo("rip", 64, ["eip", "ip"], "special"),  # Instruction pointer
        # Extended registers
        "r8": RegisterInfo("r8", 64, ["r8d", "r8w", "r8b"], "general"),
        "r9": RegisterInfo("r9", 64, ["r9d", "r9w", "r9b"], "general"),
        "r10": RegisterInfo("r10", 64, ["r10d", "r10w", "r10b"], "general"),
        "r11": RegisterInfo("r11", 64, ["r11d", "r11w", "r11b"], "general"),
        "r12": RegisterInfo("r12", 64, ["r12d", "r12w", "r12b"], "general"),
        "r13": RegisterInfo("r13", 64, ["r13d", "r13w", "r13b"], "general"),
        "r14": RegisterInfo("r14", 64, ["r14d", "r14w", "r14b"], "general"),
        "r15": RegisterInfo("r15", 64, ["r15d", "r15w", "r15b"], "general"),
        "rflags": RegisterInfo("rflags", 64, ["eflags", "flags"], "flag"),
    }

    gp_registers: ClassVar[list[str]] = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]
    sp_register: ClassVar[str] = "rsp"
    bp_register: ClassVar[str] = "rbp"
    pc_register: ClassVar[str] = "rip"

    def normalize_instruction(self, instruction: str) -> str:
        """Normalize x86-64 assembly instruction for fingerprinting."""
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
        instruction = re.sub(r"\$0x[0-9a-f]+", "$IMM", instruction)
        instruction = re.sub(r"\$-?\d+", "$IMM", instruction)

        return instruction

    def get_register_normalization_map(self) -> dict[str, str]:
        """Get x86-64 register normalization patterns for assembly hashing."""
        return {
            # RAX and variants
            r"%r?[0-9]?[a-d][xl]": "%REG_A",  # rax, eax, ax, al, etc.
            # RBX and variants
            r"%r?[0-9]?[b][xl]": "%REG_B",  # rbx, ebx, bx, bl
            # RCX and variants
            r"%r?[0-9]?[c][xl]": "%REG_C",  # rcx, ecx, cx, cl
            # RDX and variants
            r"%r?[0-9]?[d][xl]": "%REG_D",  # rdx, edx, dx, dl
            # RSI/RDI
            r"%r?[sd]i": "%REG_IDX",  # rsi, rdi, si, di
            # RBP
            r"%r?bp": "%REG_BP",  # rbp, ebp, bp
            # RSP
            r"%r?sp": "%REG_SP",  # rsp, esp, sp
        }

    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """Detect stack region using RSP (stack pointer) and RBP (base pointer)."""
        if not register_state:
            return (False, 0.0)

        rsp = self.get_register_value(register_state, self.sp_register)
        rbp = self.get_register_value(register_state, self.bp_register)

        # Stack typically contains RSP and grows downward
        if rsp and start_addr <= rsp < end_addr:
            return (True, 0.95)

        if rbp and start_addr <= rbp < end_addr:
            return (True, 0.90)

        return (False, 0.0)
