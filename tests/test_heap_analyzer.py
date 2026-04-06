"""Tests for heap corruption detection and analysis.

Tests heap analyzer across common corruption patterns.
"""

import pytest
from blackadder.heap_analyzer import (
    HeapAnalyzer,
    HeapAllocation,
    HeapAnomalyType,
)


@pytest.fixture
def analyzer():
    """Create heap analyzer instance."""
    return HeapAnalyzer()


@pytest.fixture
def sample_allocations():
    """Create sample heap allocations."""
    return [
        HeapAllocation(
            address=0x10000000,
            size=256,
            is_free=False,
            in_use=True,
            metadata_valid=True,
        ),
        HeapAllocation(
            address=0x10000100,
            size=512,
            is_free=False,
            in_use=True,
            metadata_valid=True,
        ),
        HeapAllocation(
            address=0x10000300,
            size=1024,
            is_free=True,
            in_use=False,
            metadata_valid=True,
        ),
    ]


class TestHeapAnalyzer:
    """Test basic heap analyzer functionality."""

    def test_analyzer_creation(self, analyzer):
        """Test creating heap analyzer."""
        assert analyzer.min_allocation_size == 8
        assert analyzer.max_allocation_size == 1 << 30

    def test_analyze_without_memory(self, analyzer):
        """Test analysis without memory read function."""
        result = analyzer.analyze(0x10000000, 0x11000000)

        assert result.total_size == 0x01000000
        assert result.free_size == 0x01000000
        assert result.allocated_size == 0
        assert result.fragmentation_ratio == 0.0
        assert len(result.anomalies) == 0


class TestBufferOverflowDetection:
    """Test buffer overflow pattern detection."""

    def test_adjacent_allocations(self, analyzer):
        """Test detection of adjacent allocations."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
            HeapAllocation(
                address=0x10000100,  # Immediately after first
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_buffer_overflow(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == HeapAnomalyType.BUFFER_OVERFLOW
        assert anomalies[0].severity == 0.8

    def test_spaced_allocations(self, analyzer):
        """Test spaced allocations (no overflow risk)."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
            HeapAllocation(
                address=0x10001000,  # Large gap
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_buffer_overflow(allocations)

        assert len(anomalies) == 0

    def test_small_gap_overflow(self, analyzer):
        """Test small gap between allocations."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
            HeapAllocation(
                address=0x10000108,  # 8-byte gap
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_buffer_overflow(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].severity == 0.6


class TestUseAfterFreeDetection:
    """Test use-after-free pattern detection."""

    def test_uaf_detection(self, analyzer):
        """Test detection of use-after-free."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=True,  # Marked as free
                in_use=True,  # But appears in-use
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_use_after_free(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == HeapAnomalyType.USE_AFTER_FREE
        assert anomalies[0].severity == 0.9

    def test_free_allocation_no_uaf(self, analyzer):
        """Test free allocation (no in-use)."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=True,
                in_use=False,  # Not in-use
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_use_after_free(allocations)

        assert len(anomalies) == 0


class TestDoubleFreeDetection:
    """Test double-free pattern detection."""

    def test_double_free_detection(self, analyzer):
        """Test detection of double-free."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=True,
                in_use=False,
                metadata_valid=True,
            ),
            HeapAllocation(
                address=0x10000000,  # Same address
                size=256,
                is_free=True,  # Freed again
                in_use=False,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_double_free(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == HeapAnomalyType.DOUBLE_FREE
        assert anomalies[0].severity == 0.95

    def test_no_double_free_single_alloc(self, analyzer):
        """Test single allocation (no double-free)."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=True,
                in_use=False,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.detect_double_free(allocations)

        assert len(anomalies) == 0


class TestMetadataValidation:
    """Test heap metadata validation."""

    def test_invalid_size_detection(self, analyzer):
        """Test detection of invalid allocation sizes."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=2,  # Less than min_allocation_size (8)
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.check_metadata_validity(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == HeapAnomalyType.INVALID_SIZE

    def test_oversized_allocation(self, analyzer):
        """Test detection of oversized allocations."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=(1 << 31),  # > max_allocation_size
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.check_metadata_validity(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == HeapAnomalyType.INVALID_SIZE

    def test_corrupted_metadata(self, analyzer):
        """Test detection of corrupted metadata."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=False,  # Corrupted
            ),
        ]

        anomalies = analyzer.check_metadata_validity(allocations)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == HeapAnomalyType.METADATA_CORRUPTION

    def test_valid_allocation(self, analyzer):
        """Test valid allocation."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=256,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        anomalies = analyzer.check_metadata_validity(allocations)

        assert len(anomalies) == 0


class TestFragmentationCalculation:
    """Test heap fragmentation calculation."""

    def test_no_fragmentation(self, analyzer):
        """Test heap with no fragmentation."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=512,
                is_free=False,
                in_use=True,
                metadata_valid=True,
            ),
        ]

        frag = analyzer.calculate_fragmentation(allocations, total_size=1024)

        # Single allocation, no free chunks = no fragmentation
        assert frag == 0.0

    def test_complete_fragmentation(self, analyzer):
        """Test completely fragmented heap."""
        allocations = [
            HeapAllocation(
                address=0x10000000,
                size=1,
                is_free=True,
                in_use=False,
                metadata_valid=True,
            ),
            HeapAllocation(
                address=0x10000001,
                size=1,
                is_free=True,
                in_use=False,
                metadata_valid=True,
            ),
            HeapAllocation(
                address=0x10000002,
                size=1,
                is_free=True,
                in_use=False,
                metadata_valid=True,
            ),
        ]

        frag = analyzer.calculate_fragmentation(allocations, total_size=10)

        # Many small free chunks = high fragmentation
        assert frag > 0.5

    def test_empty_heap(self, analyzer):
        """Test empty heap."""
        frag = analyzer.calculate_fragmentation([], total_size=1024)

        assert frag == 0.0

    def test_fragmentation_bounds(self, analyzer):
        """Test that fragmentation is always in [0.0, 1.0]."""
        allocations = [
            HeapAllocation(
                address=0x10000000 + i * 16,
                size=8,
                is_free=(i % 2 == 0),
                in_use=(i % 2 != 0),
                metadata_valid=True,
            )
            for i in range(100)
        ]

        frag = analyzer.calculate_fragmentation(allocations, total_size=2048)

        assert 0.0 <= frag <= 1.0
