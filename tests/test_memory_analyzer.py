"""
Tests for MemoryAnalyzer module (Phase 2.3 - Enhanced Memory Analysis).

Tests region classification, anomaly detection, and corruption detection.
"""

import pytest
from blackadder.memory_analyzer import MemoryAnalyzer
from blackadder.models import MemoryRegionType


class TestClassifyRegion:
    """Test memory region classification."""

    def test_classify_heap_explicit_marker(self):
        """Test classifying heap with explicit [heap] marker."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="[heap]",
            start_addr=0x1000000,
            end_addr=0x2000000,
            perms="rw-p",
            offset=0,
        )

        assert region_type == MemoryRegionType.HEAP
        assert confidence == 0.99

    def test_classify_stack_explicit_marker(self):
        """Test classifying stack with explicit [stack] marker."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="[stack]",
            start_addr=0x7fffff000000,
            end_addr=0x7ffffffff000,
            perms="rw-p",
            offset=0,
        )

        assert region_type == MemoryRegionType.STACK
        assert confidence == 0.99

    def test_classify_vdso(self):
        """Test classifying VDSO region."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="[vdso]",
            start_addr=0x7fff0000,
            end_addr=0x7ffff000,
            perms="r-xp",
            offset=0,
        )

        assert region_type == MemoryRegionType.VDSO
        assert confidence == 0.98

    def test_classify_vsyscall(self):
        """Test classifying vsyscall region."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="[vsyscall]",
            start_addr=0xffffffffff600000,
            end_addr=0xffffffffff601000,
            perms="r-xp",
            offset=0,
        )

        assert region_type == MemoryRegionType.VSYSCALL
        assert confidence == 0.98

    def test_classify_library_executable(self):
        """Test classifying executable library."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="/lib/libc.so.6",
            start_addr=0x7f0000000000,
            end_addr=0x7f0001000000,
            perms="r-xp",
            offset=0,
        )

        assert region_type == MemoryRegionType.MMAP
        assert confidence >= 0.85

    def test_classify_anonymous_writable(self):
        """Test classifying anonymous writable region (likely heap)."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="",
            start_addr=0x1000000,
            end_addr=0x2000000,
            perms="rw-p",
            offset=0,
        )

        assert region_type == MemoryRegionType.ANON
        # Could be classified as HEAP with lower confidence in some cases

    def test_classify_stack_by_register(self):
        """Test stack detection via register state (RSP)."""
        register_state = {
            "rsp": 0x7fffffffde00,
            "rbp": 0x7fffffffde10,
        }

        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="",
            start_addr=0x7fffffe00000,
            end_addr=0x8000000000000,
            perms="rw-p",
            offset=0,
            register_state=register_state,
        )

        assert region_type == MemoryRegionType.STACK
        assert confidence == 0.95

    def test_classify_jit_region(self):
        """Test classifying JIT region (RWX anonymous)."""
        region_type, confidence = MemoryAnalyzer.classify_region(
            pathname="",
            start_addr=0x3000000,
            end_addr=0x4000000,
            perms="rwxp",
            offset=0,
        )

        assert region_type == MemoryRegionType.JIT
        assert confidence == 0.75


class TestDetectAnomalies:
    """Test anomaly detection."""

    def test_executable_heap(self):
        """Test detecting executable heap (code injection)."""
        anomalies = MemoryAnalyzer.detect_anomalies(
            region_type=MemoryRegionType.HEAP,
            perms="rwxp",
            size=0x1000000,
            pathname="[heap]",
        )

        assert "Executable heap" in " ".join(anomalies)

    def test_oversized_region(self):
        """Test detecting oversized region (> 1GB)."""
        large_size = 0x40000000 + 1  # 1GB + 1 byte

        anomalies = MemoryAnalyzer.detect_anomalies(
            region_type=MemoryRegionType.HEAP,
            perms="rw-p",
            size=large_size,
            pathname="[heap]",
        )

        assert any("Oversized" in a for a in anomalies)

    def test_rwx_region(self):
        """Test detecting RWX region (unusual)."""
        anomalies = MemoryAnalyzer.detect_anomalies(
            region_type=MemoryRegionType.MMAP,
            perms="rwxp",
            size=0x1000,
            pathname="/lib/lib.so",
        )

        assert any("RWX" in a for a in anomalies)

    def test_large_stack(self):
        """Test detecting unusually large stack."""
        large_stack = 0x10000000 + 1  # 256MB + 1 byte

        anomalies = MemoryAnalyzer.detect_anomalies(
            region_type=MemoryRegionType.STACK,
            perms="rw-p",
            size=large_stack,
            pathname="[stack]",
        )

        assert any("Large stack" in a for a in anomalies)

    def test_no_anomalies_normal_region(self):
        """Test normal region produces no anomalies."""
        anomalies = MemoryAnalyzer.detect_anomalies(
            region_type=MemoryRegionType.MMAP,
            perms="r-xp",
            size=0x100000,
            pathname="/lib/libc.so.6",
        )

        assert len(anomalies) == 0

    def test_writable_executable_library(self):
        """Test detecting writable executable library."""
        anomalies = MemoryAnalyzer.detect_anomalies(
            region_type=MemoryRegionType.MMAP,
            perms="rwxp",
            size=0x100000,
            pathname="/lib/libc.so.6",
        )

        assert any("Writable executable" in a for a in anomalies)


class TestCheckCorruptionMarkers:
    """Test corruption pattern detection."""

    def test_executable_heap_corruption(self):
        """Test executable heap detected as corruption."""
        is_corrupted = MemoryAnalyzer.check_corruption_markers(
            region_type=MemoryRegionType.HEAP,
            perms="rwxp",
            pathname="[heap]",
        )

        assert is_corrupted is True

    def test_rwx_corruption(self):
        """Test RWX region detected as corruption."""
        is_corrupted = MemoryAnalyzer.check_corruption_markers(
            region_type=MemoryRegionType.MMAP,
            perms="rwxp",
            pathname="/lib/lib.so",
        )

        assert is_corrupted is True

    def test_writable_vdso_corruption(self):
        """Test writable VDSO detected as corruption."""
        is_corrupted = MemoryAnalyzer.check_corruption_markers(
            region_type=MemoryRegionType.VDSO,
            perms="rw-p",
            pathname="[vdso]",
        )

        assert is_corrupted is True

    def test_normal_region_no_corruption(self):
        """Test normal region not flagged as corrupted."""
        is_corrupted = MemoryAnalyzer.check_corruption_markers(
            region_type=MemoryRegionType.MMAP,
            perms="r-xp",
            pathname="/lib/libc.so.6",
        )

        assert is_corrupted is False

    def test_normal_stack_no_corruption(self):
        """Test normal stack not flagged as corrupted."""
        is_corrupted = MemoryAnalyzer.check_corruption_markers(
            region_type=MemoryRegionType.STACK,
            perms="rw-p",
            pathname="[stack]",
        )

        assert is_corrupted is False


class TestAnalyzeMemoryRegion:
    """Test full region analysis."""

    def test_analyze_heap_region(self):
        """Test analyzing a heap region."""
        analysis = MemoryAnalyzer.analyze_memory_region(
            pathname="[heap]",
            start_addr=0x1000000,
            end_addr=0x2000000,
            perms="rw-p",
            offset=0,
        )

        assert analysis["region_type"] == MemoryRegionType.HEAP.value
        assert analysis["confidence"] > 0.95
        assert analysis["is_writable"] is True
        assert analysis["is_executable"] is False
        assert analysis["likely_corrupted"] is False

    def test_analyze_suspicious_heap(self):
        """Test analyzing suspicious heap (executable)."""
        analysis = MemoryAnalyzer.analyze_memory_region(
            pathname="[heap]",
            start_addr=0x1000000,
            end_addr=0x2000000,
            perms="rwxp",
            offset=0,
        )

        assert analysis["region_type"] == MemoryRegionType.HEAP.value
        assert analysis["is_executable"] is True
        assert analysis["likely_corrupted"] is True
        assert len(analysis["anomalies"]) > 0

    def test_analyze_library_region(self):
        """Test analyzing a library region."""
        analysis = MemoryAnalyzer.analyze_memory_region(
            pathname="/lib/libc.so.6",
            start_addr=0x7f0000000000,
            end_addr=0x7f0001000000,
            perms="r-xp",
            offset=0,
        )

        assert analysis["region_type"] == MemoryRegionType.MMAP.value
        assert analysis["is_executable"] is True
        assert analysis["is_writable"] is False
        assert analysis["likely_corrupted"] is False


class TestRegisterDisplay:
    """Test register state formatting."""

    def test_format_register_display(self):
        """Test formatting register display."""
        register_state = {
            "rax": 0x123456789abcdef0,
            "rbx": 0x0,
            "rip": 0x400a1c,
            "rsp": 0x7fffffffde00,
        }

        display = MemoryAnalyzer.format_register_display(register_state)

        assert "rax" in display.lower()
        assert "rip" in display.lower()
        assert "0x123456789abcdef0" in display
        assert "0x0000000000400a1c" in display

    def test_format_handles_missing_registers(self):
        """Test formatting handles missing registers gracefully."""
        register_state = {"rax": 0x123}

        display = MemoryAnalyzer.format_register_display(register_state)

        assert "rax" in display.lower()
        assert "N/A" in display
