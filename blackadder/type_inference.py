"""Type inference utilities for register analysis and pointer classification.

Provides heuristics for inferring pointer types and estimating confidence
in type interpretations based on register semantics, architecture conventions,
and memory layout analysis.
"""

from typing import Literal

from blackadder.arch import Architecture


def infer_pointer_type_heuristic(
    reg_name: str, architecture: Architecture
) -> Literal["likely_code", "likely_data", "likely_stack", "unknown"]:
    """Use architecture-specific semantics to infer pointer type from register.

    Different architectures have calling conventions and register semantics:
    - Argument registers (RDI, RSI for x86-64; X0, X1 for ARM64) typically pass pointers to data
    - Return registers (RAX, X0) can be code or data pointers
    - Stack pointers (RSP, RBP) are frame references, not data pointers
    - Link registers (LR, X30) store return addresses (code pointers)

    Args:
        reg_name: Register name (case-insensitive)
        architecture: Architecture instance for semantics

    Returns:
        Heuristic classification: likely_code, likely_data, likely_stack, or unknown
    """
    reg_lower = reg_name.lower()

    # Check architecture-specific registers
    arch_registers = architecture.registers

    if reg_lower not in arch_registers:
        return "unknown"

    reg_info = arch_registers[reg_lower]

    # Link register (return address) = code pointer
    if reg_info.category == "link":
        return "likely_code"

    # Stack pointer = frame, not data pointer
    if reg_info.category == "stack":
        return "likely_stack"

    # Argument registers = data pointers
    if reg_info.category == "argument":
        return "likely_data"

    # Return register = can be code or data
    if reg_info.category == "return":
        return "unknown"  # Ambiguous; actual context needed

    # General purpose = unknown without more context
    return "unknown"


def estimate_confidence(
    pointer_type: str,
    region_type: str,
    symbol_resolved: bool,
    heuristic_type: str | None = None,
) -> float:
    """Estimate confidence in pointer type classification.

    Combines multiple signals:
    1. Actual memory region type (if found)
    2. Symbol resolution success (for code pointers)
    3. Register heuristic (calling convention semantics)

    Args:
        pointer_type: Detected pointer type (code, heap, stack, data)
        region_type: Memory region type (heap, stack, vdso, library, etc.)
        symbol_resolved: Whether symbol was successfully resolved
        heuristic_type: Heuristic classification (likely_code, likely_data, etc.)

    Returns:
        Confidence score (0.0-1.0)
    """
    base_confidence = 0.5

    # Signal 1: Memory region type matches detected pointer type
    if pointer_type == "code" and region_type in ("code", "vdso", "library"):
        base_confidence = 0.80
    elif pointer_type == "heap" and region_type == "heap":
        base_confidence = 0.85
    elif pointer_type == "stack" and region_type == "stack":
        base_confidence = 0.90
    elif pointer_type == "data" and region_type in ("data", "library", "anon"):
        base_confidence = 0.75

    # Signal 2: Symbol resolution (only for code pointers)
    if pointer_type == "code":
        if symbol_resolved:
            base_confidence = min(0.95, base_confidence + 0.15)
        else:
            base_confidence = max(0.50, base_confidence - 0.20)

    # Signal 3: Heuristic alignment (register semantics)
    if heuristic_type:
        if heuristic_type == "likely_code" and pointer_type == "code":
            base_confidence = min(0.98, base_confidence + 0.10)
        elif heuristic_type == "likely_data" and pointer_type == "data":
            base_confidence = min(0.95, base_confidence + 0.10)
        elif heuristic_type == "likely_stack" and pointer_type == "stack":
            base_confidence = min(0.98, base_confidence + 0.10)

    # Clamp to [0.0, 1.0]
    return max(0.0, min(1.0, base_confidence))


def classify_by_value_heuristic(
    reg_value: int,
) -> Literal["likely_pointer", "likely_constant", "unknown"]:
    """Classify a register value as likely a pointer or constant.

    Heuristics:
    - Very small values (< 256) are rarely pointers, usually constants
    - Very large values in kernel space (> 0xffff800000000000) are special
    - Aligned values (0-3 LSBs zero) are more likely pointers
    - Odd values are unlikely to be pointers (unaligned)

    Args:
        reg_value: Register value

    Returns:
        Classification: likely_pointer, likely_constant, or unknown
    """
    # Small values are likely constants (return codes, sizes, etc.)
    if reg_value < 256:
        return "likely_constant"

    # Check for alignment (most malloc'd pointers are at least 8-byte aligned)
    if (reg_value & 0xFF) != 0:
        # Not even page-aligned; could be offset into structure
        return "unknown"

    # Large aligned value = likely pointer
    if reg_value > 0x100000:  # > 1MB
        return "likely_pointer"

    return "unknown"


def estimate_string_likelihood(
    start_addr: int,
    region_mapping: dict,
    max_length: int = 256,
) -> float:
    """Estimate likelihood that an address points to a string.

    Heuristics:
    - Must be in readable region
    - Preferably in .rodata (read-only data) or heap
    - Estimated length should be reasonable

    Args:
        start_addr: Potential string start address
        region_mapping: Dict of {addr: region_info}
        max_length: Maximum reasonable string length for heuristic validation

    Returns:
        Confidence (0.0-1.0) that address points to a string
    """
    # Check if address is in readable region
    if start_addr not in region_mapping:
        return 0.0

    region = region_mapping[start_addr]

    # Strings typically in:
    # - .rodata (read-only data section)
    # - .data (data section)
    # - heap (dynamic allocation)
    confidence = 0.5

    if "r" not in region.get("perms", ""):
        return 0.0  # Not readable

    # Check region size (heuristic: allocations > max_length are less likely single strings)
    region_size = region.get("size", max_length + 1)
    if region_size > max_length:
        confidence *= 0.8

    if ".rodata" in region.get("name", "") or ".rodata" in region.get("pathname", ""):
        confidence = 0.90
    elif region.get("type") == "heap":
        confidence = 0.70
    elif region.get("type") == "data":
        confidence = 0.75

    return confidence
