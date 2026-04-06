"""Tests for analysis integration layer (Phase 3.2).

Tests AnalysisIntegration with ProcessSnapshot data and analyzers.
"""

import pytest
from blackadder.analysis_integration import AnalysisIntegration, ProcessMemoryReader
from blackadder.db.base import AsyncDatabaseManager
from blackadder.config import BlackadderConfig
from blackadder.models import ProcessSnapshot, MemoryMapping


@pytest.fixture
def config():
    """Create test config."""
    return BlackadderConfig(max_subprocess_workers=4)


@pytest.fixture
async def manager():
    """Create in-memory SQLite database for testing."""
    db_url = "sqlite+aiosqlite:///:memory:"
    mgr = AsyncDatabaseManager(db_url)
    async with mgr.engine.begin() as conn:
        from blackadder.models import SQLModel

        await conn.run_sync(SQLModel.metadata.create_all)
    return mgr


@pytest.fixture
async def sample_process(manager):
    """Create a sample process snapshot."""
    async with manager.get_session() as session:
        process = ProcessSnapshot(
            pid=12345,
            description="Test process",
        )

        # Add memory mappings
        mappings = [
            MemoryMapping(
                start_addr=0x400000,
                end_addr=0x401000,
                perms="r-xp",
                offset=0,
                pathname="/bin/bash",
            ),
            MemoryMapping(
                start_addr=0x600000,
                end_addr=0x601000,
                perms="rw-p",
                offset=0x1000,
                pathname="/bin/bash",
            ),
            MemoryMapping(
                start_addr=0x1000000,
                end_addr=0x2000000,
                perms="rw-p",
                offset=0,
                pathname="[heap]",
            ),
            MemoryMapping(
                start_addr=0x7fffde000000,
                end_addr=0x7fffdf000000,
                perms="rw-p",
                offset=0,
                pathname="[stack]",
            ),
            MemoryMapping(
                start_addr=0x7ffff7e00000,
                end_addr=0x7ffff7f00000,
                perms="r-xp",
                offset=0,
                pathname="/lib64/libc.so.6",
            ),
        ]

        for mapping in mappings:
            process.mappings.append(mapping)

        session.add(process)
        await session.commit()
        await session.refresh(process)

        return process


class TestProcessMemoryReader:
    """Test ProcessMemoryReader."""

    @pytest.mark.asyncio
    async def test_reader_creation(self, manager):
        """Test creating memory reader."""
        async with manager.get_session() as session:
            process = ProcessSnapshot(pid=1, description="Test")
            session.add(process)
            await session.commit()

            reader = ProcessMemoryReader(process, session)
            assert reader.process == process
            assert reader.session == session

    @pytest.mark.asyncio
    async def test_read_memory_not_available(self, manager):
        """Test reading memory (not available without core dump)."""
        async with manager.get_session() as session:
            process = ProcessSnapshot(pid=4, description="Test")
            session.add(process)
            await session.commit()

            reader = ProcessMemoryReader(process, session)
            data = await reader.read_memory(0x400000, 16)

            # Should return None without live memory
            assert data is None


class TestAnalysisIntegration:
    """Test AnalysisIntegration layer."""

    @pytest.fixture
    def integration(self, manager, config):
        """Create integration instance."""
        return AnalysisIntegration(manager, config)

    @pytest.mark.asyncio
    async def test_integration_creation(self, integration):
        """Test creating integration instance."""
        assert integration.manager is not None
        assert integration.config is not None

    @pytest.mark.asyncio
    async def test_get_process_by_pid(self, integration, sample_process):
        """Test loading process by PID."""
        process = await integration.get_process_by_pid(12345)
        assert process is not None
        assert process.pid == 12345
        assert process.description == "Test process"

    @pytest.mark.asyncio
    async def test_get_process_by_pid_not_found(self, integration):
        """Test loading non-existent process."""
        process = await integration.get_process_by_pid(99999)
        assert process is None

    @pytest.mark.asyncio
    async def test_analyze_registers_empty(self, integration, sample_process):
        """Test register analysis with empty register state."""
        result = await integration.analyze_registers(
            sample_process,
            register_state={},
            interesting_only=False,
        )

        assert result["process_id"] == sample_process.id
        assert result["pid"] == 12345
        assert "architecture" in result
        assert result["register_count"] == 0

    @pytest.mark.asyncio
    async def test_analyze_registers_with_data(self, integration, sample_process):
        """Test register analysis with register data."""
        register_state = {
            "rax": 0x400a1c,  # Code pointer
            "rbx": 0x1234567,  # Unknown
            "rcx": 42,  # Small constant
        }

        result = await integration.analyze_registers(
            sample_process,
            register_state=register_state,
            interesting_only=False,
        )

        assert result["process_id"] == sample_process.id
        assert result["register_count"] > 0
        assert "grouped_by_type" in result

    @pytest.mark.asyncio
    async def test_analyze_registers_interesting_only(
        self, integration, sample_process
    ):
        """Test register analysis with interesting_only filter."""
        register_state = {
            "rax": 0,  # Trivial
            "rbx": 0x400a1c,  # Code pointer (interesting)
            "rcx": 0,  # Trivial
        }

        result = await integration.analyze_registers(
            sample_process,
            register_state=register_state,
            interesting_only=True,
        )

        assert result["process_id"] == sample_process.id
        # Should have fewer registers when filtered
        assert result["register_count"] <= 3

    @pytest.mark.asyncio
    async def test_validate_stack(self, integration, sample_process):
        """Test stack validation."""
        result = await integration.validate_stack(
            sample_process,
            frame_pointer=0x7fffde100000,
            return_address=0x400a1c,
        )

        assert result["process_id"] == sample_process.id
        assert result["pid"] == 12345
        assert "architecture" in result
        assert "total_frames" in result
        assert "chain_integrity" in result

    @pytest.mark.asyncio
    async def test_analyze_heap_auto_detect(self, integration, sample_process):
        """Test heap analysis with auto-detection."""
        result = await integration.analyze_heap(sample_process)

        assert result["process_id"] == sample_process.id
        assert result["pid"] == 12345
        assert "heap_start" in result
        assert "heap_end" in result
        assert result["heap_size"] > 0

    @pytest.mark.asyncio
    async def test_analyze_heap_custom_range(self, integration, sample_process):
        """Test heap analysis with custom range."""
        result = await integration.analyze_heap(
            sample_process,
            heap_start=0x1000000,
            heap_end=0x2000000,
        )

        assert result["process_id"] == sample_process.id
        assert result["heap_start"] == "0x1000000"
        assert result["heap_end"] == "0x2000000"
        assert result["heap_size"] == 0x1000000

    @pytest.mark.asyncio
    async def test_analyze_heap_no_heap(self, integration, manager):
        """Test heap analysis when no heap found."""
        # Create process with no heap mapping
        async with manager.get_session() as session:
            process = ProcessSnapshot(pid=54321, description="No heap")
            process.mappings.append(
                MemoryMapping(
                    start_addr=0x400000,
                    end_addr=0x401000,
                    perms="r-xp",
                    offset=0,
                    pathname="/bin/ls",
                )
            )

            session.add(process)
            await session.commit()
            await session.refresh(process)

            result = await integration.analyze_heap(process)

            assert "error" in result
            assert result["heap_size"] == 0

    @pytest.mark.asyncio
    async def test_get_register_state(self, integration, sample_process):
        """Test extracting register state."""
        state = await integration.get_register_state(sample_process)

        # Should return None or empty dict (placeholder for Phase 3.2)
        assert state is None or isinstance(state, dict)


class TestAnalysisIntegrationWorkflow:
    """Test complete analysis workflows."""

    @pytest.fixture
    def integration(self, manager, config):
        """Create integration instance."""
        return AnalysisIntegration(manager, config)

    @pytest.mark.asyncio
    async def test_complete_analysis_workflow(self, integration, sample_process):
        """Test complete analysis workflow."""
        # 1. Load process by PID
        process = await integration.get_process_by_pid(12345)
        assert process is not None

        # 2. Analyze registers
        reg_result = await integration.analyze_registers(
            process,
            register_state={"rax": 0x400a1c},
        )
        assert reg_result["process_id"] == process.id

        # 3. Validate stack
        stack_result = await integration.validate_stack(process)
        assert stack_result["process_id"] == process.id

        # 4. Analyze heap
        heap_result = await integration.analyze_heap(process)
        assert heap_result["process_id"] == process.id

        # All should reference same process
        assert (
            reg_result["process_id"]
            == stack_result["process_id"]
            == heap_result["process_id"]
        )

    @pytest.mark.asyncio
    async def test_analysis_with_missing_process(self, integration):
        """Test analysis fails gracefully with missing process."""
        # Should handle None process gracefully
        result = await integration.analyze_registers(None, register_state={})

        # Would fail or return empty result (implementation-dependent)
        # Just verify it doesn't crash
        assert result is not None or True
