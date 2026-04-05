"""
Tests for CoreDumpParser module (Phase 2.2 - Core Dump Parsing).

Tests ELF core dump parsing and memory segment extraction.
"""

import pytest
from blackadder.binutils.coredump import CoreDumpParser


class TestParseElfHeaders:
    """Test parsing ELF header information."""

    def test_parse_elf_headers_64bit(self):
        """Test parsing 64-bit ELF header."""
        readelf_output = """
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                        0
  Type:                              CORE (Core file)
  Machine:                           Advanced Micro Devices X86-64
        """

        headers = CoreDumpParser.parse_elf_headers(readelf_output)

        assert headers.get("class") == "ELF64"
        assert headers.get("endian") == "little"
        assert headers.get("type") == "CORE"

    def test_parse_elf_headers_32bit(self):
        """Test parsing 32-bit ELF header."""
        readelf_output = """
ELF Header:
  Class:                             ELF32
  Data:                              2's complement, big endian
  Type:                              CORE (Core file)
        """

        headers = CoreDumpParser.parse_elf_headers(readelf_output)

        assert headers.get("class") == "ELF32"
        assert headers.get("endian") == "big"

    def test_parse_elf_headers_not_core(self):
        """Test parsing non-core ELF file."""
        readelf_output = """
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
        """

        headers = CoreDumpParser.parse_elf_headers(readelf_output)

        assert headers.get("type") == "EXEC"


class TestParseProgramHeaders:
    """Test parsing program header information."""

    def test_parse_program_headers_basic(self):
        """Test parsing basic program headers."""
        readelf_output = """
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000555555554000 0x0000000000000000
                 0x0000000000001000 0x0000000000001000  R E    0x1000
  LOAD           0x0000000000002000 0x0000555555555000 0x0000000000000000
                 0x0000000000002000 0x0000000000002000  RW     0x1000
  NOTE           0x0000000000000340 0x0000000000000000 0x0000000000000000
                 0x00000000000000f0 0x00000000000000f0         0x1
        """

        headers = CoreDumpParser.parse_program_headers(readelf_output)

        # Should find 3 headers
        assert len(headers) >= 3

        # Check first LOAD segment
        load_headers = [h for h in headers if h["type"] == "LOAD"]
        assert len(load_headers) >= 2

        first_load = load_headers[0]
        assert first_load["vaddr"] == 0x555555554000
        assert first_load["filesz"] == 0x1000
        assert first_load["memsz"] == 0x1000
        assert "R" in first_load["flags"]

    def test_parse_program_headers_with_permissions(self):
        """Test parsing program headers with different permissions."""
        readelf_output = """
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000000200 0x0000000000000200  R E    0x1000
  LOAD           0x0000000000000200 0x0000000000600000 0x0000000000600000
                 0x0000000000000100 0x0000000000000200  RW     0x1000
        """

        headers = CoreDumpParser.parse_program_headers(readelf_output)

        # First should have R E
        first = [h for h in headers if h["vaddr"] == 0x400000][0]
        assert "R" in first["flags"]
        assert "E" in first["flags"]

        # Second should have R W
        second = [h for h in headers if h["vaddr"] == 0x600000][0]
        assert "R" in second["flags"]
        assert "W" in second["flags"]

    def test_parse_program_headers_no_load(self):
        """Test parsing headers with no LOAD segments."""
        readelf_output = """
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
  NOTE           0x0000000000000340 0x0000000000000000 0x0000000000000000
                 0x00000000000000f0 0x00000000000000f0         0x1
        """

        headers = CoreDumpParser.parse_program_headers(readelf_output)

        # Find LOAD segments
        load_headers = [h for h in headers if h["type"] == "LOAD"]

        # Should be empty
        assert len(load_headers) == 0


class TestExtractMemorySegments:
    """Test conversion of PT_LOAD segments to memory mappings."""

    def test_extract_memory_segments_basic(self):
        """Test extracting memory segments from program headers."""
        program_headers = [
            {
                "type": "LOAD",
                "vaddr": 0x400000,
                "memsz": 0x1000,
                "offset": 0x0,
                "filesz": 0x1000,
                "flags": "R E",
            },
            {
                "type": "LOAD",
                "vaddr": 0x600000,
                "memsz": 0x2000,
                "offset": 0x1000,
                "filesz": 0x2000,
                "flags": "RW",
            },
        ]

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        # Should have 2 mappings
        assert len(mappings) == 2

        # Check first mapping
        first = mappings[0]
        assert first["start_addr"] == 0x400000
        assert first["end_addr"] == 0x401000
        assert first["offset"] == 0x0
        assert "r" in first["perms"]
        assert "x" in first["perms"]

    def test_extract_memory_segments_permissions(self):
        """Test permission conversion."""
        program_headers = [
            {
                "type": "LOAD",
                "vaddr": 0x400000,
                "memsz": 0x1000,
                "offset": 0x0,
                "filesz": 0x1000,
                "flags": "R",
            },
            {
                "type": "LOAD",
                "vaddr": 0x500000,
                "memsz": 0x1000,
                "offset": 0x1000,
                "filesz": 0x1000,
                "flags": "RW",
            },
            {
                "type": "LOAD",
                "vaddr": 0x600000,
                "memsz": 0x1000,
                "offset": 0x2000,
                "filesz": 0x1000,
                "flags": "RWE",
            },
        ]

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        # R only
        assert mappings[0]["perms"] == "r--p"

        # RW
        assert mappings[1]["perms"] == "rw-p"

        # RWE
        assert mappings[2]["perms"] == "rwxp"

    def test_extract_memory_segments_skips_non_load(self):
        """Test that non-LOAD segments are skipped."""
        program_headers = [
            {
                "type": "NOTE",
                "vaddr": 0x0,
                "memsz": 0x100,
                "offset": 0x0,
                "filesz": 0x100,
                "flags": "",
            },
            {
                "type": "LOAD",
                "vaddr": 0x400000,
                "memsz": 0x1000,
                "offset": 0x100,
                "filesz": 0x1000,
                "flags": "R",
            },
        ]

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        # Should only have 1 mapping (LOAD)
        assert len(mappings) == 1
        assert mappings[0]["start_addr"] == 0x400000

    def test_extract_memory_segments_address_calculation(self):
        """Test that end address is calculated correctly."""
        program_headers = [
            {
                "type": "LOAD",
                "vaddr": 0x1000,
                "memsz": 0x5000,
                "offset": 0x0,
                "filesz": 0x5000,
                "flags": "R",
            },
        ]

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        mapping = mappings[0]
        assert mapping["start_addr"] == 0x1000
        assert mapping["end_addr"] == 0x6000  # 0x1000 + 0x5000

    def test_extract_memory_segments_empty(self):
        """Test extraction with no LOAD segments."""
        program_headers = []

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        assert len(mappings) == 0


class TestCoreMapConversion:
    """Test conversion to /proc/maps-like format."""

    def test_core_mapping_format(self):
        """Test that extracted mappings have correct format."""
        program_headers = [
            {
                "type": "LOAD",
                "vaddr": 0x400000,
                "memsz": 0x1000,
                "offset": 0x0,
                "filesz": 0x1000,
                "flags": "R E",
            },
        ]

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        mapping = mappings[0]

        # Check all required fields
        assert "start_addr" in mapping
        assert "end_addr" in mapping
        assert "perms" in mapping
        assert "offset" in mapping
        assert "pathname" in mapping

        # Verify types
        assert isinstance(mapping["start_addr"], int)
        assert isinstance(mapping["end_addr"], int)
        assert isinstance(mapping["perms"], str)
        assert isinstance(mapping["offset"], int)
        assert isinstance(mapping["pathname"], str)

    def test_core_mapping_pathname(self):
        """Test that core dump mappings have appropriate pathname."""
        program_headers = [
            {
                "type": "LOAD",
                "vaddr": 0x400000,
                "memsz": 0x1000,
                "offset": 0x0,
                "filesz": 0x1000,
                "flags": "R E",
            },
        ]

        mappings = CoreDumpParser.extract_memory_segments(program_headers)

        # Core dump segments should be labeled as such
        assert "[core dump segment]" in mappings[0]["pathname"]


@pytest.mark.requires_tools
class TestCoreParseIntegration:
    """Integration tests requiring actual binaries and core dumps."""

    async def test_parse_real_core_dump(self, sample_core_dump, config):
        """Test parsing a real core dump file."""
        parser = CoreDumpParser(config)
        result = await parser.parse_core_dump(sample_core_dump)

        # Should have mappings
        assert "mappings" in result
        assert isinstance(result["mappings"], list)
        assert len(result["mappings"]) > 0

        # Each mapping should have required fields
        for mapping in result["mappings"]:
            assert "start_addr" in mapping
            assert "end_addr" in mapping
            assert "perms" in mapping
            assert "offset" in mapping

    async def test_parse_core_dump_invalid_file(self, config, tmpdir):
        """Test parsing an invalid file."""
        parser = CoreDumpParser(config)
        invalid_file = str(tmpdir.join("not_a_core_dump"))

        with open(invalid_file, "w") as f:
            f.write("This is not a core dump file")

        with pytest.raises(ValueError):
            await parser.parse_core_dump(invalid_file)
