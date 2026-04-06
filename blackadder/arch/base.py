"""
Base classes for architecture-specific implementations.

Defines the interface for register handling, assembly normalization,
and stack detection across different CPU architectures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class RegisterInfo:
    """Metadata about a CPU register."""

    name: str  # Register name (e.g., "rax", "sp")
    width_bits: int  # Register width (8, 16, 32, 64)
    aliases: list[str]  # Alternative names (e.g., rax: [eax, ax, al])
    category: str  # "general", "special", "flag", etc.


class Architecture(ABC):
    """
    Abstract base class for architecture-specific implementations.

    Provides interfaces for:
    - Register definitions and metadata
    - Assembly instruction normalization
    - Stack frame detection
    """

    # Architecture identifier
    arch_family: ClassVar[str]  # "x86", "arm", etc.
    arch_variant: ClassVar[str]  # "x86", "x86_64", "arm", "arm64"
    machine_type: ClassVar[int]  # ELF e_machine value

    # Register definitions
    registers: ClassVar[dict[str, RegisterInfo]]
    gp_registers: ClassVar[list[str]]  # General purpose register names
    sp_register: ClassVar[str]  # Stack pointer register name
    bp_register: ClassVar[str]  # Base/frame pointer register name
    pc_register: ClassVar[str]  # Program counter/instruction pointer

    @abstractmethod
    def normalize_instruction(self, instruction: str) -> str:
        """
        Normalize assembly instruction for content hashing.

        Removes addresses, normalizes register names, and handles
        immediate values to make fingerprints version-independent.

        Args:
            instruction: Assembly instruction line

        Returns:
            Normalized instruction string
        """
        pass

    @abstractmethod
    def get_register_normalization_map(self) -> dict[str, str]:
        """
        Get regex patterns for normalizing register names.

        Returns:
            {pattern: normalized_name, ...} for use in re.sub()
        """
        pass

    @abstractmethod
    def classify_stack_region(
        self,
        register_state: dict[str, int | None] | None,
        start_addr: int,
        end_addr: int,
    ) -> tuple[bool, float]:
        """
        Detect if address range contains stack based on registers.

        Args:
            register_state: CPU register values {name: value, ...}
            start_addr: Region start address
            end_addr: Region end address

        Returns:
            (is_stack: bool, confidence: 0.0-1.0)
        """
        pass

    def get_register_value(
        self, register_state: dict[str, int | None] | None, reg_name: str
    ) -> int | None:
        """
        Get value of a register from state dict.

        Handles register name aliases and variations.

        Args:
            register_state: CPU register values
            reg_name: Register name (e.g., "rax", "eax", "ax")

        Returns:
            Register value or None if not found/not set
        """
        if not register_state:
            return None

        # Try exact match first
        if reg_name in register_state:
            return register_state[reg_name]

        # Try aliases (e.g., eax -> rax)
        if reg_name in self.registers:
            primary = self.registers[reg_name].aliases
            for alias in primary:
                if alias in register_state:
                    return register_state[alias]

        return None

    def display_registers(self, register_state: dict[str, int | None] | None) -> str:
        """
        Format registers for display.

        Args:
            register_state: CPU register values

        Returns:
            Formatted register display string
        """
        if not register_state:
            return "(no register state)"

        lines = []
        for reg in self.gp_registers:
            value = self.get_register_value(register_state, reg)
            if value is not None:
                lines.append(f"{reg:>4} = 0x{value:016x}")

        return "\n".join(lines) if lines else "(no registers set)"
