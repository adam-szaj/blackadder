"""Register value interpretation and analysis for debugging context.

Interprets CPU register values to determine what they point to:
- Code pointers (resolved to symbols)
- Heap pointers (detected via memory region classification)
- Stack pointers and frame pointers
- Data/string pointers

Supports x86, x86-64, ARM, ARM64, and RISC-V architectures.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from baldrick.arch import Architecture
from baldrick.models import MemoryMapping, ProcessSnapshot


class RegisterInterpretation(BaseModel):
    """Interpretation of a single register value."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "register_name": "rax",
                "raw_value": "0x10001000",
                "pointer_type": "heap",
                "resolved_symbol": None,
                "region_info": "heap allocation (0x10000000-0x10100000)",
                "confidence": 0.85,
                "notes": ["Points to heap region", "Allocation size: 0x100000 bytes"],
            }
        }
    )

    register_name: str = Field(description="Register name (e.g., 'rax', 'x0')")
    raw_value: str = Field(description="Hexadecimal value")
    pointer_type: Literal["code", "heap", "stack", "data", "unknown"] = Field(
        description="Classification of what the register points to"
    )
    resolved_symbol: str | None = Field(default=None, description="Symbol name if code pointer")
    region_info: str | None = Field(
        default=None, description="Memory region info if heap/stack pointer"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score (0.0-1.0)")
    notes: list[str] = Field(default_factory=list, description="Explanation of interpretation")


class RegisterAnalyzer:
    """Analyze register values to provide debugging context.

    Determines pointer types, resolves symbols, classifies memory regions,
    and estimates confidence in interpretations.
    """

    def __init__(
        self,
        process_snapshot: ProcessSnapshot,
        architecture: Architecture,
        symbols: dict[int, str] | None = None,
    ):
        """Initialize analyzer with process state and architecture.

        Args:
            process_snapshot: ProcessSnapshot with memory mappings
            architecture: Architecture instance (x86_64, arm64, etc.)
            symbols: Optional symbol table {address: symbol_name}
        """
        self.process = process_snapshot
        self.architecture = architecture
        self.symbols = symbols or {}

        # Build lookup tables
        self._build_region_map()

    def _build_region_map(self) -> None:
        """Build internal mapping of address ranges to regions."""
        self.regions: list[tuple[int, int, MemoryMapping]] = []
        for mapping in self.process.mappings:
            self.regions.append((mapping.start_addr, mapping.end_addr, mapping))

        # Sort by start address for binary search
        self.regions.sort(key=lambda x: x[0])

    def _find_region(self, addr: int) -> MemoryMapping | None:
        """Find memory region containing address."""
        for start, end, mapping in self.regions:
            if start <= addr < end:
                return mapping
        return None

    def _classify_region(self, mapping: MemoryMapping) -> str:
        """Classify memory region by pathname and permissions."""
        pathname = mapping.pathname.lower()

        # Heuristic classification
        if "[heap]" in pathname:
            return "heap"
        if "[stack]" in pathname:
            return "stack"
        if "[vdso]" in pathname:
            return "vdso"
        if "[vsyscall]" in pathname:
            return "vsyscall"
        if "[vvar]" in pathname:
            return "vvar"
        if "libc" in pathname or ".so" in pathname:
            return "library"
        if pathname.endswith(".so") or pathname.endswith(".so.6"):
            return "library"
        if "anonymous" in pathname or pathname == "":
            # Executable anonymous = JIT
            if "x" in mapping.perms:
                return "jit"
            return "anon"

        return "unknown"

    def interpret_register(self, reg_name: str, reg_value: int) -> RegisterInterpretation:
        """Interpret a single register value.

        Args:
            reg_name: Register name (case-insensitive)
            reg_value: Register value as integer

        Returns:
            RegisterInterpretation with pointer type and context
        """
        raw_value_hex = f"0x{reg_value:x}"

        # Find which region this address falls into
        region = self._find_region(reg_value)

        if region is None:
            # Address not in any mapped region
            return RegisterInterpretation(
                register_name=reg_name,
                raw_value=raw_value_hex,
                pointer_type="unknown",
                confidence=0.1,
                notes=["Address not found in process memory map"],
            )

        # Classify region
        region_type = self._classify_region(region)
        region_name = region.pathname

        # Check for code pointer (in executable region)
        if "x" in region.perms:
            # Try to resolve to symbol
            symbol = self.symbols.get(reg_value)

            if symbol:
                return RegisterInterpretation(
                    register_name=reg_name,
                    raw_value=raw_value_hex,
                    pointer_type="code",
                    resolved_symbol=symbol,
                    region_info=f"{region_type}: {region_name}",
                    confidence=0.95,
                    notes=[f"Resolved to symbol: {symbol}", f"Region: {region_name}"],
                )
            else:
                # No exact symbol, but it's in code region
                return RegisterInterpretation(
                    register_name=reg_name,
                    raw_value=raw_value_hex,
                    pointer_type="code",
                    region_info=f"{region_type}: {region_name}",
                    confidence=0.70,
                    notes=[
                        "Code region but symbol not resolved",
                        f"Region: {region_name}",
                    ],
                )

        # Check for stack pointer (stack region)
        if region_type == "stack":
            return RegisterInterpretation(
                register_name=reg_name,
                raw_value=raw_value_hex,
                pointer_type="stack",
                region_info=f"Stack region: {region.start_addr:#x}-{region.end_addr:#x}",
                confidence=0.90,
                notes=[
                    "Points to stack region",
                    f"Stack range: {region.start_addr:#x}-{region.end_addr:#x}",
                ],
            )

        # Check for heap pointer (heap region)
        if region_type == "heap":
            allocation_size = region.end_addr - region.start_addr
            return RegisterInterpretation(
                register_name=reg_name,
                raw_value=raw_value_hex,
                pointer_type="heap",
                region_info=f"Heap allocation: {region.start_addr:#x}-{region.end_addr:#x}",
                confidence=0.85,
                notes=[
                    "Points to heap region",
                    f"Allocation: {region.start_addr:#x}-{region.end_addr:#x}",
                    f"Size: {allocation_size:#x} bytes",
                ],
            )

        # Check if it's writable (could be data)
        if "w" in region.perms:
            return RegisterInterpretation(
                register_name=reg_name,
                raw_value=raw_value_hex,
                pointer_type="data",
                region_info=f"{region_type}: {region_name}",
                confidence=0.75,
                notes=[
                    "Points to writable data region",
                    f"Region: {region_name}",
                    f"Type: {region_type}",
                ],
            )

        # Fallback: readable region (likely data)
        return RegisterInterpretation(
            register_name=reg_name,
            raw_value=raw_value_hex,
            pointer_type="data",
            region_info=f"{region_type}: {region_name}",
            confidence=0.60,
            notes=[
                "Points to readable region",
                f"Region: {region_name}",
                f"Type: {region_type}",
            ],
        )

    def interpret_all_registers(
        self, register_state: dict[str, int]
    ) -> dict[str, RegisterInterpretation]:
        """Interpret all registers in a state dict.

        Args:
            register_state: Dict of {register_name: value}

        Returns:
            Dict of {register_name: RegisterInterpretation}
        """
        results = {}
        for reg_name, reg_value in register_state.items():
            results[reg_name] = self.interpret_register(reg_name, reg_value)
        return results

    def get_interesting_registers(
        self, register_state: dict[str, int]
    ) -> dict[str, RegisterInterpretation]:
        """Get interpretations for "interesting" registers (pointers, not fixed regs).

        Filters out registers that are unlikely to contain pointers
        (like flags, fixed registers).

        Args:
            register_state: Dict of {register_name: value}

        Returns:
            Dict of "interesting" registers with interpretations
        """
        # Get architecture-specific register info
        arch_registers = self.architecture.registers

        results = {}
        for reg_name, reg_value in register_state.items():
            # Check if this is a "interesting" register
            if reg_name.lower() in arch_registers:
                reg_info = arch_registers[reg_name.lower()]

                # Skip fixed/special registers
                if reg_info.category in ("special", "flags"):
                    continue

                results[reg_name] = self.interpret_register(reg_name, reg_value)

        return results
