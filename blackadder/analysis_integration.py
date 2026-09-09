"""Analysis integration layer for Phase 3.2.

Integrates ProcessSnapshot data with Register Analyzer, Heap Analyzer,
and Stack Validator to provide live memory analysis capabilities.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlmodel import select

from blackadder.db.base import AsyncDatabaseManager
from blackadder.heap_analyzer import HeapAnalyzer
from blackadder.models import ProcessSnapshot
from blackadder.register_analyzer import RegisterAnalyzer, RegisterInterpretation
from blackadder.stack_validator import StackValidator

logger = logging.getLogger("blackadder.analysis_integration")


class ProcessMemoryReader:
    """Provides memory reading interface from ProcessSnapshot."""

    def __init__(self, process: ProcessSnapshot, session: AsyncSession):
        """Initialize reader.

        Args:
            process: ProcessSnapshot with memory mappings
            session: AsyncSession for database access
        """
        self.process = process
        self.session = session
        self._memory_cache: dict[tuple[int, int], bytes] = {}

    async def read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory from process.

        For offline analysis (core dump), extracts from stored segments.
        For live analysis, would connect to debugger.

        Args:
            address: Start address to read
            size: Number of bytes to read

        Returns:
            Memory contents or None if not available
        """
        if size <= 0:
            return None

        # Check cache first
        cache_key = (address, size)
        if cache_key in self._memory_cache:
            return self._memory_cache[cache_key]

        # For core dumps, memory is stored in mappings
        # This is a placeholder for Phase 3.2+ when core dump data is available
        logger.debug(
            "read_memory_not_available",
            extra={
                "address": hex(address),
                "size": size,
                "source": self.process.source_type or "unknown",
            },
        )
        return None

    def get_mappings(self):
        """Get memory mappings for process.

        Returns:
            List of memory mappings
        """
        return self.process.mappings

    def find_mapping(self, address: int):
        """Find mapping containing address.

        Args:
            address: Address to search for

        Returns:
            MemoryMapping if found, None otherwise
        """
        for mapping in self.process.mappings:
            if mapping.start_addr <= address < mapping.end_addr:
                return mapping
        return None


class AnalysisIntegration:
    """Orchestrates analysis across all analyzer modules."""

    def __init__(
        self,
        manager: AsyncDatabaseManager,
        config,
    ):
        """Initialize integration layer.

        Args:
            manager: AsyncDatabaseManager for database access
            config: BlackadderConfig
        """
        self.manager = manager
        self.config = config

    async def _load_process(self, process: ProcessSnapshot) -> ProcessSnapshot:
        """Return a process whose analyzer relationships are loaded."""
        if process.id is None:
            return process

        async with self.manager.get_session() as session:
            statement = (
                select(ProcessSnapshot)
                .where(ProcessSnapshot.id == process.id)
                .options(
                    selectinload(ProcessSnapshot.mappings),  # type: ignore[arg-type]
                    selectinload(ProcessSnapshot.register_states),  # type: ignore[arg-type]
                )
            )
            result = await session.execute(statement)  # type: ignore
            return result.scalar_one_or_none() or process

    async def analyze_registers(
        self,
        process: ProcessSnapshot | None,
        register_state: dict | None = None,
        interesting_only: bool = False,
    ) -> dict:
        """Analyze register values from process.

        Args:
            process: ProcessSnapshot to analyze (optional)
            register_state: Register values {name: value}
            interesting_only: Filter to non-trivial registers

        Returns:
            Dict with interpreted registers and metadata
        """
        if not process:
            # Return empty result if no process
            from blackadder.arch import get_architecture

            arch = get_architecture("x86_64")
            return {
                "process_id": None,
                "pid": None,
                "architecture": arch.__class__.__name__,
                "register_count": 0,
                "grouped_registers": {},
                "grouped_by_type": {},
            }

        # Default to x86-64 (would detect from process binaries in Phase 3.2+)
        from blackadder.arch import get_architecture

        arch = get_architecture("x86_64")

        process = await self._load_process(process)

        logger.debug(
            "analyzing_registers",
            extra={
                "process_id": process.id,
                "architecture": arch.__class__.__name__,
                "has_registers": register_state is not None,
            },
        )

        analyzer = RegisterAnalyzer(process, arch)

        if not register_state:
            # If no explicit register state, create empty
            register_state = {}

        if interesting_only:
            interpretations = analyzer.get_interesting_registers(register_state)
        else:
            interpretations = analyzer.interpret_all_registers(register_state)

        # Group by pointer type
        grouped: dict[str, list[tuple[str, RegisterInterpretation]]] = {}
        for reg_name, interp in interpretations.items():
            ptr_type = interp.pointer_type
            if ptr_type not in grouped:
                grouped[ptr_type] = []
            grouped[ptr_type].append((reg_name, interp))

        return {
            "process_id": process.id,
            "pid": process.pid,
            "architecture": arch.__class__.__name__,
            "register_count": len(interpretations),
            "grouped_registers": grouped,
            "grouped_by_type": {
                ptype: [
                    {"name": name, "interpretation": interp.model_dump()} for name, interp in regs
                ]
                for ptype, regs in grouped.items()
            },
        }

    async def validate_stack(
        self,
        process: ProcessSnapshot | None,
        frame_pointer: int | None = None,
        return_address: int | None = None,
        max_frames: int = 100,
    ) -> dict:
        """Validate stack frame chain from process.

        Args:
            process: ProcessSnapshot to analyze
            frame_pointer: Initial frame pointer (RBP/R29)
            return_address: Current return address
            max_frames: Max frames to validate

        Returns:
            Dict with validation results
        """
        if not process:
            from blackadder.arch import get_architecture

            arch = get_architecture("x86_64")
            return {
                "process_id": None,
                "pid": None,
                "architecture": arch.__class__.__name__,
                "total_frames": 0,
                "valid_frames": 0,
                "corrupted_frames": 0,
                "chain_integrity": 0.0,
                "confidence": 0.0,
                "issues": [],
                "validation_notes": ["No process provided"],
            }

        # Default to x86-64 (would detect from process binaries in Phase 3.2+)
        from blackadder.arch import get_architecture

        arch = get_architecture("x86_64")

        logger.debug(
            "validating_stack",
            extra={
                "process_id": process.id,
                "frame_pointer": hex(frame_pointer) if frame_pointer else None,
                "architecture": arch.__class__.__name__,
            },
        )

        validator = StackValidator(arch)

        # Validate frame chain (stub returns no data without live memory)
        result = validator.validate_frame_chain(
            frame_pointer or 0,
            return_address or 0,
            memory_read_func=None,  # Phase 3.2: would pass reader.read_memory
            max_frames=max_frames,
        )

        return {
            "process_id": process.id,
            "pid": process.pid,
            "architecture": arch.__class__.__name__,
            "total_frames": result.total_frames,
            "valid_frames": result.valid_frames,
            "corrupted_frames": result.corrupted_frames,
            "chain_integrity": result.chain_integrity,
            "confidence": result.confidence,
            "issues": [issue.model_dump() for issue in result.issues],
            "validation_notes": result.validation_notes,
        }

    async def analyze_heap(
        self,
        process: ProcessSnapshot | None,
        heap_start: int | None = None,
        heap_end: int | None = None,
    ) -> dict:
        """Analyze heap from process.

        Args:
            process: ProcessSnapshot to analyze
            heap_start: Heap start address (auto-detect if None)
            heap_end: Heap end address (auto-detect if None)

        Returns:
            Dict with heap analysis results
        """
        if not process:
            return {
                "process_id": None,
                "pid": None,
                "error": "No process provided",
                "heap_size": 0,
                "anomalies": [],
            }

        logger.debug(
            "analyzing_heap",
            extra={
                "process_id": process.id,
                "heap_start": hex(heap_start) if heap_start else "auto",
                "heap_end": hex(heap_end) if heap_end else "auto",
            },
        )

        process = await self._load_process(process)

        # Auto-detect heap region from mappings
        if heap_start is None or heap_end is None:
            for mapping in process.mappings:
                # Look for anonymous heap
                if "[heap]" in (mapping.pathname or ""):
                    if heap_start is None:
                        heap_start = mapping.start_addr
                    if heap_end is None:
                        heap_end = mapping.end_addr
                    break

        if not heap_start or not heap_end:
            logger.warning(
                "heap_not_found_in_mappings",
                extra={"process_id": process.id},
            )
            return {
                "process_id": process.id,
                "pid": process.pid,
                "error": "Heap region not found in memory mappings",
                "heap_size": 0,
                "anomalies": [],
            }

        analyzer = HeapAnalyzer()

        # Analyze heap (stub: no live memory, return basic structure)
        result = analyzer.analyze(heap_start, heap_end, memory_read_func=None)

        return {
            "process_id": process.id,
            "pid": process.pid,
            "heap_start": hex(heap_start),
            "heap_end": hex(heap_end),
            "heap_size": heap_end - heap_start,
            "allocated_size": result.allocated_size,
            "free_size": result.free_size,
            "fragmentation": result.fragmentation_ratio,
            "total_allocations": result.total_allocations,
            "anomalies": [anomaly.model_dump() for anomaly in result.anomalies],
            "high_risk_anomalies": [anomaly.model_dump() for anomaly in result.high_risk_anomalies],
            "analysis_notes": result.analysis_notes,
        }

    async def get_process_by_id(self, process_id: int) -> ProcessSnapshot | None:
        """Load process from database by ID.

        Args:
            process_id: ProcessSnapshot ID

        Returns:
            ProcessSnapshot or None if not found
        """
        async with self.manager.get_session() as session:
            statement = (
                select(ProcessSnapshot)
                .where(ProcessSnapshot.id == process_id)
                .options(
                    selectinload(ProcessSnapshot.mappings),  # type: ignore[arg-type]
                    selectinload(ProcessSnapshot.register_states),  # type: ignore[arg-type]
                )
            )
            result = await session.execute(statement)  # type: ignore
            return result.scalar_one_or_none()

    async def get_process_by_pid(
        self, pid: int, db_path: str | None = None
    ) -> ProcessSnapshot | None:
        """Load process from database by PID.

        Args:
            pid: Process ID to search for
            db_path: Path to process database (uses default if None)

        Returns:
            ProcessSnapshot or None if not found
        """
        async with self.manager.get_session() as session:
            statement = (
                select(ProcessSnapshot)
                .where(ProcessSnapshot.pid == pid)
                .options(
                    selectinload(ProcessSnapshot.mappings),  # type: ignore[arg-type]
                    selectinload(ProcessSnapshot.register_states),  # type: ignore[arg-type]
                )
            )
            result = await session.execute(statement)  # type: ignore
            return result.scalar_one_or_none()

    async def get_register_state(self, process: ProcessSnapshot) -> dict | None:
        """Extract register state from process.

        For core dumps, extracts from PT_NOTE section.
        For live processes, would connect to debugger.

        Args:
            process: ProcessSnapshot to extract registers from

        Returns:
            Dict of {register_name: register_value} or None
        """
        process = await self._load_process(process)

        # Phase 3.2: Extract from ProcessRegisterState if available
        # For now, return empty dict (requires core dump register extraction)
        if process.register_states:
            # Would reconstruct register dict from ProcessRegisterState model
            logger.debug(
                "register_state_available",
                extra={"process_id": process.id},
            )
            return {}  # Placeholder

        logger.debug(
            "register_state_not_available",
            extra={"process_id": process.id},
        )
        return None
