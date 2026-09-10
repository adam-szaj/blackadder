"""
Phase 3 static test data and mock fixtures.

Provides realistic mock process state, memory layouts, and register values
for testing Advanced CLI commands and Register Interpreter.
"""

from datetime import datetime

from baldrick.models import MemoryMapping, ProcessSnapshot

# ============================================================================
# Mock Process Data
# ============================================================================


def mock_process_x86_64() -> ProcessSnapshot:
    """Create mock process snapshot for x86-64 architecture."""
    process = ProcessSnapshot(
        id=1,
        pid=12345,
        created_at=datetime.now(),
        description="Mock x86-64 process for testing",
        source_type="maps",
    )
    return process


def mock_process_arm64() -> ProcessSnapshot:
    """Create mock process snapshot for ARM64 architecture."""
    process = ProcessSnapshot(
        id=2,
        pid=12346,
        created_at=datetime.now(),
        description="Mock ARM64 process for testing",
        source_type="maps",
    )
    return process


def mock_process_arm() -> ProcessSnapshot:
    """Create mock process snapshot for ARM 32-bit architecture."""
    process = ProcessSnapshot(
        id=3,
        pid=12347,
        created_at=datetime.now(),
        description="Mock ARM 32-bit process for testing",
        source_type="maps",
    )
    return process


# ============================================================================
# Mock Memory Mappings (x86-64)
# ============================================================================


def mock_memory_mappings_x86_64() -> list[MemoryMapping]:
    """Create realistic memory layout for x86-64 process."""
    return [
        # Code section (.text)
        MemoryMapping(
            id=1,
            process_id=1,
            start_addr=0x400000,
            end_addr=0x401000,
            perms="r-xp",
            offset=0x0,
            pathname="/home/user/myapp",
        ),
        # Data section (.data)
        MemoryMapping(
            id=2,
            process_id=1,
            start_addr=0x600000,
            end_addr=0x601000,
            perms="rw-p",
            offset=0x1000,
            pathname="/home/user/myapp",
        ),
        # Heap (anonymous, writable)
        MemoryMapping(
            id=3,
            process_id=1,
            start_addr=0x10000000,
            end_addr=0x10100000,
            perms="rw-p",
            offset=0x0,
            pathname="[heap]",
        ),
        # libc.so.6 (must come before stack to match first)
        MemoryMapping(
            id=6,
            process_id=1,
            start_addr=0x7FFFF7E00000,
            end_addr=0x7FFFF7E1C000,
            perms="r-xp",
            offset=0x0,
            pathname="/lib/x86_64-linux-gnu/libc.so.6",
        ),
        # Stack (starts above libc_end: 0x7ffff7e1c000, includes test addr 0x7ffffffff0)
        MemoryMapping(
            id=5,
            process_id=1,
            start_addr=0x7FFFF7F00000,
            end_addr=0x7FFFFFFFF000,
            perms="rw-p",
            offset=0x0,
            pathname="[stack]",
        ),
        # VDSO (virtual dynamic shared object)
        MemoryMapping(
            id=4,
            process_id=1,
            start_addr=0x7FFFF7FFD000,
            end_addr=0x7FFFF7FFE000,
            perms="r-xp",
            offset=0x0,
            pathname="[vdso]",
        ),
    ]


# ============================================================================
# Mock Memory Mappings (ARM64)
# ============================================================================


def mock_memory_mappings_arm64() -> list[MemoryMapping]:
    """Create realistic memory layout for ARM64 process."""
    return [
        # Code section
        MemoryMapping(
            id=10,
            process_id=2,
            start_addr=0x400000,
            end_addr=0x401000,
            perms="r-xp",
            offset=0x0,
            pathname="/home/user/myapp_arm64",
        ),
        # Data section
        MemoryMapping(
            id=11,
            process_id=2,
            start_addr=0x600000,
            end_addr=0x601000,
            perms="rw-p",
            offset=0x1000,
            pathname="/home/user/myapp_arm64",
        ),
        # Heap
        MemoryMapping(
            id=12,
            process_id=2,
            start_addr=0x55555555000,
            end_addr=0x55555565000,
            perms="rw-p",
            offset=0x0,
            pathname="[heap]",
        ),
        # VDSO
        MemoryMapping(
            id=13,
            process_id=2,
            start_addr=0xFFFFFFFFB000,
            end_addr=0xFFFFFFFFC000,
            perms="r-xp",
            offset=0x0,
            pathname="[vdso]",
        ),
        # Stack (should not overlap with libc/vdso)
        MemoryMapping(
            id=14,
            process_id=2,
            start_addr=0xFFFFFFFFFC000,
            end_addr=0x10000000000000,
            perms="rw-p",
            offset=0x0,
            pathname="[stack]",
        ),
        # libc
        MemoryMapping(
            id=15,
            process_id=2,
            start_addr=0xFFFF8000000,
            end_addr=0xFFFF8020000,
            perms="r-xp",
            offset=0x0,
            pathname="/lib/aarch64-linux-gnu/libc.so.6",
        ),
    ]


# ============================================================================
# Mock Memory Mappings (ARM 32-bit)
# ============================================================================


def mock_memory_mappings_arm() -> list[MemoryMapping]:
    """Create realistic memory layout for ARM 32-bit process."""
    return [
        # Code section (consistent with x86-64 and ARM64 for testing)
        MemoryMapping(
            id=20,
            process_id=3,
            start_addr=0x400000,
            end_addr=0x401000,
            perms="r-xp",
            offset=0x0,
            pathname="/home/user/myapp_arm",
        ),
        # Data section
        MemoryMapping(
            id=21,
            process_id=3,
            start_addr=0x600000,
            end_addr=0x601000,
            perms="rw-p",
            offset=0x1000,
            pathname="/home/user/myapp_arm",
        ),
        # Heap
        MemoryMapping(
            id=22,
            process_id=3,
            start_addr=0x1000000,
            end_addr=0x1010000,
            perms="rw-p",
            offset=0x0,
            pathname="[heap]",
        ),
        # VDSO
        MemoryMapping(
            id=23,
            process_id=3,
            start_addr=0xB6FFD000,
            end_addr=0xB6FFE000,
            perms="r-xp",
            offset=0x0,
            pathname="[vdso]",
        ),
        # Stack
        MemoryMapping(
            id=24,
            process_id=3,
            start_addr=0xBEF00000,
            end_addr=0xBF000000,
            perms="rw-p",
            offset=0x0,
            pathname="[stack]",
        ),
        # libc
        MemoryMapping(
            id=25,
            process_id=3,
            start_addr=0xB6E00000,
            end_addr=0xB6E1C000,
            perms="r-xp",
            offset=0x0,
            pathname="/lib/arm-linux-gnueabihf/libc.so.6",
        ),
    ]


# ============================================================================
# Mock Register States (x86-64)
# ============================================================================


def mock_register_state_x86_64_code_pointer() -> dict[str, int | None]:
    """x86-64 registers with RIP pointing to main function."""
    return {
        "rax": 0x0,  # Return value
        "rbx": 0x0,  # Saved register
        "rcx": 0x123456789ABC,  # Parameter
        "rdx": 0x0,  # Parameter
        "rsi": 0x0,  # Parameter
        "rdi": 0x0,  # Parameter
        "rbp": 0x7FFFFFFFD000,  # Frame pointer (stack)
        "rsp": 0x7FFFFFFFDF00,  # Stack pointer
        "rip": 0x400A1C,  # CODE POINTER - main function
        "r8": 0x0,
        "r9": 0x0,
        "r10": 0x0,
        "r11": 0x0,
        "r12": 0x0,
        "r13": 0x0,
        "r14": 0x0,
        "r15": 0x0,
        "rflags": 0x202,
    }


def mock_register_state_x86_64_heap_pointer() -> dict[str, int | None]:
    """x86-64 registers with RAX pointing to heap allocation."""
    return {
        "rax": 0x10001000,  # HEAP POINTER - return value from malloc
        "rbx": 0x0,
        "rcx": 0x0,
        "rdx": 0x0,
        "rsi": 0x0,
        "rdi": 0x0,
        "rbp": 0x7FFFFFFFD000,
        "rsp": 0x7FFFFFFFDF00,
        "rip": 0x400A25,
        "r8": 0x0,
        "r9": 0x0,
        "r10": 0x0,
        "r11": 0x0,
        "r12": 0x0,
        "r13": 0x0,
        "r14": 0x0,
        "r15": 0x0,
        "rflags": 0x202,
    }


def mock_register_state_x86_64_stack_pointer() -> dict[str, int | None]:
    """x86-64 registers with RSP/RBP in stack."""
    return {
        "rax": 0x0,
        "rbx": 0x0,
        "rcx": 0x0,
        "rdx": 0x0,
        "rsi": 0x0,
        "rdi": 0x0,
        "rbp": 0x7FFFFFFFDD00,  # STACK POINTER - frame pointer
        "rsp": 0x7FFFFFFFDCC0,  # STACK POINTER - stack pointer
        "rip": 0x400A2C,
        "r8": 0x0,
        "r9": 0x0,
        "r10": 0x0,
        "r11": 0x0,
        "r12": 0x0,
        "r13": 0x0,
        "r14": 0x0,
        "r15": 0x0,
        "rflags": 0x202,
    }


# ============================================================================
# Mock Register States (ARM64)
# ============================================================================


def mock_register_state_arm64_code_pointer() -> dict[str, int | None]:
    """ARM64 registers with PC pointing to main function."""
    return {
        "x0": 0x0,  # Return value
        "x1": 0x0,  # Temporary
        "x2": 0x0,  # Temporary
        "x3": 0x0,  # Temporary
        "x4": 0x0,  # Temporary
        "x5": 0x0,  # Temporary
        "x6": 0x0,  # Temporary
        "x7": 0x0,  # Temporary
        "x8": 0xFFFFFFFFFFD00000,  # Frame pointer (stack)
        "x9": 0x0,  # Saved
        "x10": 0x0,  # Argument
        "x11": 0x0,  # Argument
        "x12": 0x0,  # Argument
        "x13": 0x0,  # Argument
        "x14": 0x0,  # Argument
        "x15": 0x0,  # Argument
        "x16": 0x0,  # Temporary
        "x17": 0x0,  # Temporary
        "x18": 0x0,  # Saved
        "x19": 0x0,  # Saved
        "x20": 0x0,  # Saved
        "x21": 0x0,  # Saved
        "x22": 0x0,  # Saved
        "x23": 0x0,  # Saved
        "x24": 0x0,  # Saved
        "x25": 0x0,  # Saved
        "x26": 0x0,  # Saved
        "x27": 0x0,  # Saved
        "x28": 0x0,  # Temporary
        "x29": 0xFFFFFFFFFFD01000,  # Frame pointer
        "x30": 0x400A1C,  # Link register (CODE POINTER)
        "sp": 0xFFFFFFFFFFFDF00,  # Stack pointer
        "pc": 0x400A20,  # CODE POINTER - instruction pointer
    }


def mock_register_state_arm64_heap_pointer() -> dict[str, int | None]:
    """ARM64 registers with X0 pointing to heap allocation."""
    return {
        "x0": 0x55555555100,  # HEAP POINTER - return value
        "x1": 0x0,
        "x2": 0x0,
        "x3": 0x0,
        "x4": 0x0,
        "x5": 0x0,
        "x6": 0x0,
        "x7": 0x0,
        "x8": 0xFFFFFFFFFFD00000,
        "x9": 0x0,
        "x10": 0x0,
        "x11": 0x0,
        "x12": 0x0,
        "x13": 0x0,
        "x14": 0x0,
        "x15": 0x0,
        "x16": 0x0,
        "x17": 0x0,
        "x18": 0x0,
        "x19": 0x0,
        "x20": 0x0,
        "x21": 0x0,
        "x22": 0x0,
        "x23": 0x0,
        "x24": 0x0,
        "x25": 0x0,
        "x26": 0x0,
        "x27": 0x0,
        "x28": 0x0,
        "x29": 0xFFFFFFFFFFD01000,
        "x30": 0x400A1C,
        "sp": 0xFFFFFFFFFFFDF00,
        "pc": 0x400A25,
    }


# ============================================================================
# Mock Register States (ARM 32-bit)
# ============================================================================


def mock_register_state_arm_code_pointer() -> dict[str, int | None]:
    """ARM 32-bit registers with PC pointing to main function."""
    return {
        "r0": 0x0,  # Return value
        "r1": 0x0,  # Argument
        "r2": 0x0,  # Argument
        "r3": 0x0,  # Argument
        "r4": 0x0,  # Saved
        "r5": 0x0,  # Saved
        "r6": 0x0,  # Saved
        "r7": 0x0,  # Saved
        "r8": 0x0,  # Saved
        "r9": 0x0,  # Saved
        "r10": 0x0,  # Saved
        "r11": 0xBEF00000,  # Frame pointer (stack)
        "r12": 0x0,  # IP (intra-procedure)
        "r13": 0xBEF00F00,  # Stack pointer
        "r14": 0x8A1C,  # Link register (CODE POINTER)
        "r15": 0x8A20,  # CODE POINTER - program counter
    }


def mock_register_state_arm_heap_pointer() -> dict[str, int | None]:
    """ARM 32-bit registers with R0 pointing to heap allocation."""
    return {
        "r0": 0x1000100,  # HEAP POINTER - return value
        "r1": 0x0,
        "r2": 0x0,
        "r3": 0x0,
        "r4": 0x0,
        "r5": 0x0,
        "r6": 0x0,
        "r7": 0x0,
        "r8": 0x0,
        "r9": 0x0,
        "r10": 0x0,
        "r11": 0xBEF00000,
        "r12": 0x0,
        "r13": 0xBEF00F00,
        "r14": 0x8A1C,
        "r15": 0x8A25,
    }


# ============================================================================
# Mock Symbol Information
# ============================================================================


def mock_symbols() -> dict[int, str]:
    """Mock symbol addresses for code pointer resolution."""
    return {
        0x400A1C: "main",
        0x400A25: "process_data",
        0x400A2C: "calculate_sum",
        0x400B00: "malloc_wrapper",
        0x400B1C: "free_wrapper",
        0x7FFFF7E00000: "__libc_start_main",
        0x7FFFF7E1C5C0: "libc_malloc",
        0x7FFFF7E1D0C0: "libc_free",
    }


# ============================================================================
# Export All Fixtures
# ============================================================================


MOCK_PROCESSES = {
    "x86_64": mock_process_x86_64,
    "arm64": mock_process_arm64,
    "arm": mock_process_arm,
}

MOCK_MEMORY_MAPPINGS = {
    "x86_64": mock_memory_mappings_x86_64,
    "arm64": mock_memory_mappings_arm64,
    "arm": mock_memory_mappings_arm,
}

MOCK_REGISTER_STATES = {
    "x86_64": {
        "code_pointer": mock_register_state_x86_64_code_pointer,
        "heap_pointer": mock_register_state_x86_64_heap_pointer,
        "stack_pointer": mock_register_state_x86_64_stack_pointer,
    },
    "arm64": {
        "code_pointer": mock_register_state_arm64_code_pointer,
        "heap_pointer": mock_register_state_arm64_heap_pointer,
    },
    "arm": {
        "code_pointer": mock_register_state_arm_code_pointer,
        "heap_pointer": mock_register_state_arm_heap_pointer,
    },
}
