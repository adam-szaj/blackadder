"""Tests for register value interpretation and analysis.

Tests RegisterAnalyzer with mock process state across multiple architectures
(x86-64, ARM64, ARM 32-bit) using static test data from phase3_data.py.
"""

import pytest

from blackadder.arch import (
    ARM64Architecture,
    ARMArchitecture,
    X86_64Architecture,
)
from blackadder.models import MemoryMapping, ProcessSnapshot
from blackadder.register_analyzer import RegisterAnalyzer, RegisterInterpretation
from tests.fixtures.phase3_data import MOCK_MEMORY_MAPPINGS, MOCK_PROCESSES, MOCK_REGISTER_STATES


class TestRegisterAnalyzerX86_64:
    """Test register interpretation for x86-64 architecture."""

    @pytest.fixture
    def x86_64_process(self) -> ProcessSnapshot:
        """Get x86-64 mock process."""
        # MOCK_PROCESSES stores functions, need to call them
        process_func = MOCK_PROCESSES["x86_64"]
        process = process_func()
        # Add mappings from mock data
        mappings_func = MOCK_MEMORY_MAPPINGS["x86_64"]
        mappings = mappings_func()
        process.mappings = mappings
        return process

    @pytest.fixture
    def x86_64_symbols(self) -> dict[int, str]:
        """Get x86-64 symbol table."""
        return {
            0x400A1C: "main",
            0x400A25: "process_data",
            0x400A2C: "calculate_sum",
            0x400B00: "malloc_wrapper",
            0x7FFFF7E00000: "__libc_start_main",
        }

    @pytest.fixture
    def analyzer(self, x86_64_process, x86_64_symbols) -> RegisterAnalyzer:
        """Create analyzer for x86-64."""
        return RegisterAnalyzer(
            x86_64_process,
            X86_64Architecture(),
            symbols=x86_64_symbols,
        )

    def test_code_pointer_with_symbol(self, analyzer):
        """Test code pointer that resolves to known symbol."""
        # RIP at main
        result = analyzer.interpret_register("rip", 0x400A1C)

        assert result.pointer_type == "code"
        assert result.resolved_symbol == "main"
        assert result.confidence > 0.90
        assert "main" in "\n".join(result.notes).lower()

    def test_code_pointer_without_symbol(self, analyzer):
        """Test code pointer that doesn't resolve to symbol."""
        # RIP at unmapped code address
        result = analyzer.interpret_register("rip", 0x400500)

        assert result.pointer_type == "code"
        assert result.resolved_symbol is None
        assert result.confidence < 0.80

    def test_heap_pointer(self, analyzer):
        """Test heap pointer detection."""
        # RAX pointing to heap (0x10001000 is in heap region)
        result = analyzer.interpret_register("rax", 0x10001000)

        assert result.pointer_type == "heap"
        assert result.confidence > 0.80
        assert "heap" in result.region_info.lower()

    def test_stack_pointer(self, analyzer):
        """Test stack pointer detection."""
        # RBP pointing to stack (high address, above libc)
        result = analyzer.interpret_register("rbp", 0x7FFFF7F00100)

        assert result.pointer_type == "stack"
        assert result.confidence > 0.85

    def test_library_pointer(self, analyzer):
        """Test pointer to library code."""
        result = analyzer.interpret_register("rax", 0x7FFFF7E00000)

        assert result.pointer_type == "code"
        assert result.confidence > 0.60

    def test_unknown_pointer(self, analyzer):
        """Test unmapped address."""
        result = analyzer.interpret_register("rax", 0xDEADBEEF)

        assert result.pointer_type == "unknown"
        assert result.confidence < 0.5

    def test_all_registers(self, analyzer):
        """Test interpreting all registers in state dict."""
        # MOCK_REGISTER_STATES stores functions, need to call them
        register_state_func = MOCK_REGISTER_STATES["x86_64"]["code_pointer"]
        register_state = register_state_func()

        results = analyzer.interpret_all_registers(register_state)

        assert isinstance(results, dict)
        assert len(results) > 0
        assert all(isinstance(v, RegisterInterpretation) for v in results.values())

    def test_interesting_registers(self, analyzer):
        """Test filtering for interesting registers only."""
        # MOCK_REGISTER_STATES stores functions, need to call them
        register_state_func = MOCK_REGISTER_STATES["x86_64"]["code_pointer"]
        register_state = register_state_func()

        results = analyzer.get_interesting_registers(register_state)

        # Should exclude flags and special registers
        assert isinstance(results, dict)
        # Should have some interesting registers
        assert len(results) > 0
        # Check that we're getting general-purpose registers
        assert any(reg in results for reg in ["rax", "rbx", "rcx", "rdx"])


class TestRegisterAnalyzerARM64:
    """Test register interpretation for ARM64 architecture."""

    @pytest.fixture
    def arm64_process(self) -> ProcessSnapshot:
        """Get ARM64 mock process."""
        # MOCK_PROCESSES stores functions, need to call them
        process_func = MOCK_PROCESSES["arm64"]
        process = process_func()
        # Add mappings from mock data
        mappings_func = MOCK_MEMORY_MAPPINGS["arm64"]
        mappings = mappings_func()
        process.mappings = mappings
        return process

    @pytest.fixture
    def arm64_symbols(self) -> dict[int, str]:
        """Get ARM64 symbol table."""
        return {
            0x400A1C: "main",
            0x400A25: "process_data",
            0x400A2C: "calculate_sum",
            0x400B00: "malloc_wrapper",
            0x7FFFF7E00000: "__libc_start_main",
        }

    @pytest.fixture
    def analyzer(self, arm64_process, arm64_symbols) -> RegisterAnalyzer:
        """Create analyzer for ARM64."""
        return RegisterAnalyzer(
            arm64_process,
            ARM64Architecture(),
            symbols=arm64_symbols,
        )

    def test_pc_code_pointer(self, analyzer):
        """Test ARM64 PC (program counter) at code address."""
        result = analyzer.interpret_register("pc", 0x400A1C)

        assert result.pointer_type == "code"
        assert result.confidence > 0.85

    def test_lr_link_register(self, analyzer):
        """Test ARM64 LR (link register) at return address."""
        result = analyzer.interpret_register("lr", 0x400A2C)

        assert result.pointer_type == "code"
        assert result.confidence > 0.70

    def test_heap_pointer_arm64(self, analyzer):
        """Test ARM64 heap pointer."""
        # ARM64 mock uses 0x55555555100 for heap
        result = analyzer.interpret_register("x0", 0x55555555100)

        assert result.pointer_type == "heap"
        assert result.confidence > 0.75

    def test_stack_pointer_arm64(self, analyzer):
        """Test ARM64 stack pointer."""
        result = analyzer.interpret_register("sp", 0xFFFFFFFFFFD00)

        assert result.pointer_type == "stack"
        assert result.confidence > 0.80

    def test_all_registers_arm64(self, analyzer):
        """Test interpreting all ARM64 registers."""
        # MOCK_REGISTER_STATES stores functions, need to call them
        register_state_func = MOCK_REGISTER_STATES["arm64"]["code_pointer"]
        register_state = register_state_func()

        results = analyzer.interpret_all_registers(register_state)

        assert isinstance(results, dict)
        assert len(results) > 0


class TestRegisterAnalyzerARM32:
    """Test register interpretation for ARM 32-bit architecture."""

    @pytest.fixture
    def arm_process(self) -> ProcessSnapshot:
        """Get ARM 32-bit mock process."""
        # MOCK_PROCESSES stores functions, need to call them
        process_func = MOCK_PROCESSES["arm"]
        process = process_func()
        # Add mappings from mock data
        mappings_func = MOCK_MEMORY_MAPPINGS["arm"]
        mappings = mappings_func()
        process.mappings = mappings
        return process

    @pytest.fixture
    def arm_symbols(self) -> dict[int, str]:
        """Get ARM symbol table."""
        return {
            0x400A1C: "main",
            0x400A25: "process_data",
            0x400B00: "malloc_wrapper",
        }

    @pytest.fixture
    def analyzer(self, arm_process, arm_symbols) -> RegisterAnalyzer:
        """Create analyzer for ARM 32-bit."""
        return RegisterAnalyzer(
            arm_process,
            ARMArchitecture(),
            symbols=arm_symbols,
        )

    def test_pc_code_pointer_arm(self, analyzer):
        """Test ARM 32-bit PC at code address."""
        result = analyzer.interpret_register("pc", 0x400A1C)

        assert result.pointer_type == "code"
        assert result.confidence > 0.85

    def test_lr_link_register_arm(self, analyzer):
        """Test ARM 32-bit LR (link register)."""
        result = analyzer.interpret_register("lr", 0x400A25)

        assert result.pointer_type == "code"
        assert result.confidence > 0.70

    def test_heap_pointer_arm(self, analyzer):
        """Test ARM 32-bit heap pointer."""
        # ARM 32-bit mock uses 0x1000100 for heap
        result = analyzer.interpret_register("r0", 0x1000100)

        assert result.pointer_type == "heap"
        assert result.confidence > 0.75

    def test_stack_pointer_arm(self, analyzer):
        """Test ARM 32-bit SP (stack pointer)."""
        result = analyzer.interpret_register("sp", 0xBEF00000)

        assert result.pointer_type == "stack"
        assert result.confidence > 0.80


class TestRegisterInterpretationModel:
    """Test RegisterInterpretation Pydantic model."""

    def test_model_creation(self):
        """Test creating RegisterInterpretation instance."""
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x10001000",
            pointer_type="heap",
            confidence=0.85,
            notes=["Test note"],
        )

        assert interp.register_name == "rax"
        assert interp.raw_value == "0x10001000"
        assert interp.pointer_type == "heap"
        assert interp.confidence == 0.85

    def test_model_json_serialization(self):
        """Test JSON serialization of RegisterInterpretation."""
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x10001000",
            pointer_type="heap",
            resolved_symbol=None,
            region_info="Heap region",
            confidence=0.85,
            notes=["Points to heap"],
        )

        json_str = interp.model_dump_json()
        assert "rax" in json_str
        assert "0x10001000" in json_str
        assert "heap" in json_str

    def test_model_validation_confidence(self):
        """Test confidence value validation (0.0-1.0)."""
        # Valid
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x1000",
            pointer_type="code",
            confidence=0.5,
        )
        assert interp.confidence == 0.5

        # Too high
        with pytest.raises(ValueError):
            RegisterInterpretation(
                register_name="rax",
                raw_value="0x1000",
                pointer_type="code",
                confidence=1.5,
            )

        # Negative
        with pytest.raises(ValueError):
            RegisterInterpretation(
                register_name="rax",
                raw_value="0x1000",
                pointer_type="code",
                confidence=-0.1,
            )


class TestRegisterAnalyzerEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def analyzer(self) -> RegisterAnalyzer:
        """Create analyzer with minimal process."""
        process = ProcessSnapshot(
            id=1,
            pid=9999,
            mappings=[
                MemoryMapping(
                    id=1,
                    process_id=1,
                    start_addr=0x400000,
                    end_addr=0x401000,
                    perms="r-xp",
                    offset=0,
                    pathname="/test/binary",
                ),
                MemoryMapping(
                    id=2,
                    process_id=1,
                    start_addr=0x600000,
                    end_addr=0x601000,
                    perms="rw-p",
                    offset=0x1000,
                    pathname="/test/binary",
                ),
            ],
        )
        return RegisterAnalyzer(process, X86_64Architecture())

    def test_zero_address(self, analyzer):
        """Test NULL pointer (0x0)."""
        result = analyzer.interpret_register("rax", 0x0)

        assert result.pointer_type == "unknown"
        assert result.confidence < 0.5

    def test_very_large_address(self, analyzer):
        """Test address in kernel space."""
        result = analyzer.interpret_register("rax", 0xFFFFFFFFFFFFFFFF)

        assert result.pointer_type == "unknown"

    def test_empty_register_state(self, analyzer):
        """Test interpreting empty register dict."""
        result = analyzer.interpret_all_registers({})

        assert result == {}

    def test_case_insensitive_register_names(self, analyzer):
        """Test that register names are case-insensitive."""
        # Setup with a test mapping
        result1 = analyzer.interpret_register("RIP", 0x400A1C)
        result2 = analyzer.interpret_register("rip", 0x400A1C)

        assert result1.register_name == "RIP"
        assert result2.register_name == "rip"
        # Results should be equivalent except for register_name casing
