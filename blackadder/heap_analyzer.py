"""Heap memory analysis and corruption detection.

Analyzes heap structure to detect:
- Free list corruption
- Buffer overflow patterns
- Use-after-free indicators
- Heap metadata corruption
- Allocation anomalies
"""

from enum import StrEnum

from pydantic import BaseModel, Field


class HeapAnomalyType(StrEnum):
    """Types of heap anomalies detected."""

    FREE_LIST_CORRUPTION = "free_list_corruption"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    INVALID_SIZE = "invalid_size"
    HEAP_CORRUPTION = "heap_corruption"
    METADATA_CORRUPTION = "metadata_corruption"
    UNINITIALIZED_ACCESS = "uninitialized_access"


class HeapAnomaly(BaseModel):
    """Description of a detected heap anomaly."""

    anomaly_type: HeapAnomalyType = Field(description="Type of anomaly detected")
    address: int = Field(description="Address where anomaly detected")
    severity: float = Field(ge=0.0, le=1.0, description="Severity score (0.0-1.0)")
    description: str = Field(description="Human-readable description")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in detection (0.0-1.0)")
    suggested_action: str | None = Field(default=None, description="Suggested remediation")


class HeapAllocation(BaseModel):
    """Description of a heap allocation."""

    address: int = Field(description="Start address of allocation")
    size: int = Field(description="Allocation size in bytes")
    is_free: bool = Field(description="Whether allocation is currently free")
    allocated_by: str | None = Field(default=None, description="Function that allocated (if known)")
    freed_by: str | None = Field(default=None, description="Function that freed")
    in_use: bool = Field(description="Whether allocation appears in-use")
    metadata_valid: bool = Field(description="Whether metadata appears valid")


class HeapSegment(BaseModel):
    """Description of a heap segment."""

    start_addr: int = Field(description="Start address of segment")
    end_addr: int = Field(description="End address of segment")
    size: int = Field(description="Total segment size")
    allocations: int = Field(description="Number of allocations in segment")
    free_chunks: int = Field(description="Number of free chunks")
    fragmentation_ratio: float = Field(ge=0.0, le=1.0, description="Fragmentation ratio (0.0-1.0)")
    anomalies: list[HeapAnomaly] = Field(default_factory=list, description="Detected anomalies")


class HeapAnalysisResult(BaseModel):
    """Result of heap analysis."""

    total_allocations: int = Field(description="Total number of allocations")
    total_size: int = Field(description="Total heap size in bytes")
    free_size: int = Field(description="Total free space in bytes")
    allocated_size: int = Field(description="Total allocated space in bytes")
    fragmentation_ratio: float = Field(ge=0.0, le=1.0, description="Overall fragmentation ratio")
    segments: list[HeapSegment] = Field(default_factory=list, description="Heap segments analyzed")
    anomalies: list[HeapAnomaly] = Field(default_factory=list, description="All detected anomalies")
    high_risk_anomalies: list[HeapAnomaly] = Field(
        default_factory=list, description="High-severity anomalies"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Overall confidence in analysis")
    analysis_notes: list[str] = Field(
        default_factory=list, description="Notes about analysis limitations"
    )


class HeapAnalyzer:
    """Analyze heap memory for corruption and anomalies.

    Detects patterns indicating heap corruption, buffer overflows,
    use-after-free conditions, and other memory safety violations.
    """

    def __init__(self, min_allocation_size: int = 8, max_allocation_size: int = 1 << 30):
        """Initialize heap analyzer.

        Args:
            min_allocation_size: Minimum valid allocation size (default 8 bytes)
            max_allocation_size: Maximum valid allocation size (default 1GB)
        """
        self.min_allocation_size = min_allocation_size
        self.max_allocation_size = max_allocation_size

    def analyze(
        self,
        heap_start: int,
        heap_end: int,
        memory_read_func=None,
    ) -> HeapAnalysisResult:
        """Analyze heap for corruption.

        Args:
            heap_start: Start address of heap
            heap_end: End address of heap
            memory_read_func: Function to read memory (address -> bytes)

        Returns:
            HeapAnalysisResult with detected anomalies and statistics
        """
        if not memory_read_func:
            # Stub: return empty analysis without live memory
            return HeapAnalysisResult(
                total_allocations=0,
                total_size=heap_end - heap_start,
                free_size=heap_end - heap_start,
                allocated_size=0,
                fragmentation_ratio=0.0,
                confidence=0.0,
                analysis_notes=[
                    "No memory read function provided; static analysis not implemented"
                ],
            )

        # For now, return a basic analysis structure
        total_size = heap_end - heap_start

        return HeapAnalysisResult(
            total_allocations=0,
            total_size=total_size,
            free_size=total_size,
            allocated_size=0,
            fragmentation_ratio=0.0,
            confidence=0.5,
            analysis_notes=[
                "Heap analysis requires live memory access or core dump data",
                "This is a stub implementation for Phase 3.3",
            ],
        )

    def detect_buffer_overflow(
        self,
        allocations: list[HeapAllocation],
    ) -> list[HeapAnomaly]:
        """Detect potential buffer overflow patterns.

        Args:
            allocations: List of heap allocations

        Returns:
            List of detected buffer overflow anomalies
        """
        anomalies: list[HeapAnomaly] = []

        # Check for allocations immediately adjacent to each other
        if len(allocations) < 2:
            return anomalies

        sorted_allocs = sorted(allocations, key=lambda a: a.address)

        for i in range(len(sorted_allocs) - 1):
            current = sorted_allocs[i]
            next_alloc = sorted_allocs[i + 1]

            # If adjacent, there's risk of overflow from current into next
            gap = next_alloc.address - (current.address + current.size)

            if gap < 16 and current.in_use:
                # Small gap or no gap = high overflow risk
                anomalies.append(
                    HeapAnomaly(
                        anomaly_type=HeapAnomalyType.BUFFER_OVERFLOW,
                        address=current.address,
                        severity=0.8 if gap == 0 else 0.6,
                        description=f"Allocation at {current.address:#x} is adjacent to next "
                        f"allocation with only {gap} byte gap",
                        confidence=0.75,
                        suggested_action="Review allocation sizes and boundaries",
                    )
                )

        return anomalies

    def detect_use_after_free(
        self,
        allocations: list[HeapAllocation],
    ) -> list[HeapAnomaly]:
        """Detect use-after-free patterns.

        Args:
            allocations: List of heap allocations

        Returns:
            List of detected use-after-free anomalies
        """
        anomalies = []

        for alloc in allocations:
            # If marked as free but appears to be in-use, it's a UAF risk
            if alloc.is_free and alloc.in_use:
                anomalies.append(
                    HeapAnomaly(
                        anomaly_type=HeapAnomalyType.USE_AFTER_FREE,
                        address=alloc.address,
                        severity=0.9,
                        description=f"Allocation at {alloc.address:#x} marked as free "
                        f"but appears in-use",
                        confidence=0.80,
                        suggested_action="Check for dangling pointers and missing nullification",
                    )
                )

        return anomalies

    def detect_double_free(
        self,
        allocations: list[HeapAllocation],
    ) -> list[HeapAnomaly]:
        """Detect double-free patterns.

        Args:
            allocations: List of heap allocations

        Returns:
            List of detected double-free anomalies
        """
        anomalies = []

        # Group by address to find duplicates
        by_address: dict[int, list[HeapAllocation]] = {}
        for alloc in allocations:
            if alloc.address not in by_address:
                by_address[alloc.address] = []
            by_address[alloc.address].append(alloc)

        # Multiple allocations at same address = likely double-free
        for addr, allocs in by_address.items():
            if len(allocs) > 1:
                freed_count = sum(1 for a in allocs if a.is_free)
                if freed_count > 1:
                    anomalies.append(
                        HeapAnomaly(
                            anomaly_type=HeapAnomalyType.DOUBLE_FREE,
                            address=addr,
                            severity=0.95,
                            description=f"Address {addr:#x} freed {freed_count} times",
                            confidence=0.85,
                            suggested_action="Check free() call sites for duplicate calls",
                        )
                    )

        return anomalies

    def check_metadata_validity(
        self,
        allocations: list[HeapAllocation],
    ) -> list[HeapAnomaly]:
        """Check heap metadata for corruption.

        Args:
            allocations: List of heap allocations

        Returns:
            List of detected metadata corruption anomalies
        """
        anomalies = []

        for alloc in allocations:
            # Check for invalid sizes
            if alloc.size < self.min_allocation_size or alloc.size > self.max_allocation_size:
                anomalies.append(
                    HeapAnomaly(
                        anomaly_type=HeapAnomalyType.INVALID_SIZE,
                        address=alloc.address,
                        severity=0.7,
                        description=f"Allocation at {alloc.address:#x} has invalid size: {alloc.size}",
                        confidence=0.70,
                        suggested_action="Verify allocation size is reasonable",
                    )
                )

            # Check metadata validity flag
            if not alloc.metadata_valid:
                anomalies.append(
                    HeapAnomaly(
                        anomaly_type=HeapAnomalyType.METADATA_CORRUPTION,
                        address=alloc.address,
                        severity=0.85,
                        description=f"Allocation at {alloc.address:#x} has corrupted metadata",
                        confidence=0.80,
                        suggested_action="Likely heap corruption; review memory writes",
                    )
                )

        return anomalies

    def calculate_fragmentation(
        self,
        allocations: list[HeapAllocation],
        total_size: int,
    ) -> float:
        """Calculate heap fragmentation ratio.

        Args:
            allocations: List of heap allocations
            total_size: Total heap size

        Returns:
            Fragmentation ratio (0.0 = no fragmentation, 1.0 = completely fragmented)
        """
        if not allocations or total_size == 0:
            return 0.0

        # Calculate free space
        allocated = sum(a.size for a in allocations if not a.is_free)
        free = total_size - allocated

        if free == 0:
            return 0.0

        # Count free chunks
        sorted_free = sorted(
            [a for a in allocations if a.is_free],
            key=lambda a: a.address,
        )

        if not sorted_free:
            return 0.0

        # Fragmentation = number of free chunks / total free space
        # Higher = more fragmented
        num_chunks = len(sorted_free)
        avg_chunk_size = free / num_chunks if num_chunks > 0 else free

        # Normalize: fragmentation = 1 - (avg_chunk_size / max_possible_chunk)
        fragmentation = min(1.0, 1.0 - (avg_chunk_size / free)) if free > 0 else 0.0

        return max(0.0, min(1.0, fragmentation))
