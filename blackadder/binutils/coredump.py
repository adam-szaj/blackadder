"""
ELF core dump parsing for offline process analysis (Phase 2.2).

Enables reconstruction of process memory layout from core dump files,
allowing address resolution on offline crashes.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import Optional

from blackadder.binutils.parser import BinToolsParser
from blackadder.exceptions import (
    FileNotFoundError,
    FileAccessError,
    FileTooLargeError,
    FileFormatError,
    ELFCoreDumpError,
    ParseError,
)

logger = logging.getLogger("blackadder.coredump")


class CoreDumpParser:
    """Parse ELF core dump files to reconstruct process state."""

    def __init__(self, config):
        self.config = config
        self.parser = BinToolsParser(config)

    async def parse_core_dump(self, core_path: str) -> dict:
        """
        Parse ELF core dump and extract memory layout.

        Strategy:
        1. Use readelf to parse core dump headers (E_TYPE == ET_CORE)
        2. Extract program headers:
           - PT_LOAD: memory segments (map to MemoryMapping)
           - PT_NOTE: metadata (process state, register values)
        3. Reconstruct /proc/maps-like format from segments
        4. Return {mappings, process_info}

        Args:
            core_path: Path to ELF core dump file

        Returns:
            {
                'mappings': [
                    {'start_addr': 0x..., 'end_addr': 0x..., 'perms': 'r-xp',
                     'offset': 0x..., 'pathname': '/path/to/binary'},
                    ...
                ],
                'pid': PID from core dump (if available),
                'signal': terminating signal (if available),
                'timestamp': core dump creation time,
            }

        Raises:
            FileNotFoundError: If core dump file not found
            FileAccessError: If file not readable
            FileTooLargeError: If file exceeds size limit
            FileFormatError: If file not a valid ELF core dump
            ParseError: If parsing fails
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(core_path, str):
                logger.error(f"Invalid core_path type: {type(core_path)}")
                raise FileFormatError(f"core_path must be string")

            core_file = Path(core_path)

            # Check file exists
            if not core_file.exists():
                logger.error(f"Core dump file not found: {core_path}")
                raise FileNotFoundError(f"Core dump file not found: {core_path}")

            # Check file readable
            if not core_file.is_file():
                logger.error(f"Core dump is not a file: {core_path}")
                raise FileAccessError(f"Core dump is not a file: {core_path}")

            # Check file size
            file_size = core_file.stat().st_size
            if file_size > self.config.max_core_dump_size:
                logger.error(f"Core dump exceeds size limit: {file_size} > {self.config.max_core_dump_size}")
                raise FileTooLargeError(
                    f"Core dump exceeds limit: {file_size / (1024**2):.1f}MB "
                    f"(max {self.config.max_core_dump_size / (1024**2):.1f}MB)"
                )

            logger.debug(f"Parsing core dump: {core_path} ({file_size / (1024**2):.1f}MB)")

            # Step 1: Parse ELF headers
            headers_output = await self._get_readelf_output(core_path, ["-h"])

            if not headers_output:
                logger.error(f"Failed to read ELF headers: {core_path}")
                raise ParseError(f"Failed to parse ELF headers: {core_path}")

            elf_headers = self.parse_elf_headers(headers_output)

            if elf_headers.get("type") != "ET_CORE":
                logger.error(f"File is not a core dump (type={elf_headers.get('type')}): {core_path}")
                raise ELFCoreDumpError(f"File is not a core dump: {core_path}")

            # Step 2: Parse program headers
            prog_output = await self._get_readelf_output(core_path, ["-l"])

            if not prog_output:
                logger.error(f"Failed to read program headers: {core_path}")
                raise ParseError(f"Failed to parse program headers: {core_path}")

            program_headers = self.parse_program_headers(prog_output)

            # Step 3: Extract memory segments
            memory_mappings = self.extract_memory_segments(program_headers)

            # Step 4: Extract metadata from PT_NOTE
            metadata = self._extract_metadata_from_program_headers(program_headers)

            logger.debug(
                f"Core dump parsed: {len(memory_mappings)} segments, "
                f"{len(program_headers)} program headers"
            )

            return {
                "mappings": memory_mappings,
                "elf_headers": elf_headers,
                "pid": metadata.get("pid"),
                "signal": metadata.get("signal"),
                "timestamp": metadata.get("timestamp"),
            }

        except (FileNotFoundError, FileAccessError, FileTooLargeError, ELFCoreDumpError, ParseError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error parsing core dump {core_path}: {e}")
            raise ParseError(f"Core dump parsing failed: {e}")

    async def _get_readelf_output(
        self, core_path: str, args: list[str]
    ) -> Optional[str]:
        """
        Get readelf output for core dump.

        Args:
            core_path: Path to core dump
            args: Additional readelf arguments (e.g., ["-h"], ["-l"])

        Returns:
            readelf output or None on error
        """
        lines = []

        def collect_line(line):
            lines.append(line)

        cmd = [self.config.readelf_path, *args, core_path]

        try:
            await self.parser.run_command_limited(cmd, collect_line)
            return "\n".join(lines)
        except Exception:
            return None

    @staticmethod
    def parse_elf_headers(readelf_output: str) -> dict:
        """
        Parse readelf -h output for ELF header info.

        Extract:
        - Class (32/64-bit)
        - Endianness
        - Type (ET_CORE, ET_EXEC, etc.)

        Args:
            readelf_output: Output from readelf -h

        Returns:
            {class: 'ELF64', endian: 'little', type: 'ET_CORE', ...}

        Raises:
            ParseError: If output is invalid type
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(readelf_output, str):
                logger.warning(f"Invalid readelf output type: {type(readelf_output)}")
                raise ParseError(f"readelf output must be string")

            if not readelf_output.strip():
                logger.warning("Empty readelf output")
                raise ParseError(f"readelf output is empty")

            result = {}

            # Pattern: "Class:                             ELF64"
            class_match = re.search(r"Class:\s+(\S+)", readelf_output)
            if class_match:
                result["class"] = class_match.group(1)

            # Pattern: "Data:                              2's complement, little endian"
            endian_match = re.search(r"Data:.*?(little|big)\s+endian", readelf_output)
            if endian_match:
                result["endian"] = endian_match.group(1)

            # Pattern: "Type:                              CORE (Core file)"
            type_match = re.search(r"Type:\s+(\S+)", readelf_output)
            if type_match:
                result["type"] = type_match.group(1)

            logger.debug(f"Parsed ELF headers: {result}")
            return result

        except ParseError:
            raise
        except Exception as e:
            logger.error(f"Error parsing ELF headers: {e}")
            raise ParseError(f"ELF header parsing failed: {e}")

    @staticmethod
    def parse_program_headers(readelf_output: str) -> list[dict]:
        """
        Parse readelf -l output for program headers.

        Extract for each segment:
        - Type (PT_LOAD, PT_NOTE, etc.)
        - Offset in file
        - Virtual address
        - Physical size
        - File size
        - Permissions

        Args:
            readelf_output: Output from readelf -l

        Returns:
            List of program header dicts

        Raises:
            ParseError: If output is invalid type
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(readelf_output, str):
                logger.warning(f"Invalid readelf output type: {type(readelf_output)}")
                raise ParseError(f"readelf output must be string")

            if not readelf_output.strip():
                logger.warning("Empty readelf output for program headers")
                # Return empty list instead of error - some files may have no PT_LOAD
                return []

            headers = []

            # Pattern: "Type           Offset             VirtAddr           PhysAddr"
            # "LOAD           0x0000000000001000 0x0000555555554000 0x0000000000000000"
            # "         0x0000000000001000 0x0000000000001000  R                0x1000"
            prog_header_pattern = re.compile(
                r"(\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)"
                r"\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+([\w\-]+)",
                re.IGNORECASE
            )

            for match in prog_header_pattern.finditer(readelf_output):
                try:
                    header = {
                        "type": match.group(1),
                        "offset": int(match.group(2), 16),
                        "vaddr": int(match.group(3), 16),
                        "paddr": int(match.group(4), 16),
                        "filesz": int(match.group(5), 16),
                        "memsz": int(match.group(6), 16),
                        "flags": match.group(7),
                    }
                    headers.append(header)
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse program header: {e}")
                    # Continue parsing other headers rather than failing

            logger.debug(f"Parsed {len(headers)} program headers")
            return headers

        except ParseError:
            raise
        except Exception as e:
            logger.error(f"Error parsing program headers: {e}")
            raise ParseError(f"Program header parsing failed: {e}")

    @staticmethod
    def extract_memory_segments(program_headers: list[dict]) -> list[dict]:
        """
        Convert PT_LOAD segments to memory mappings.

        Return MemoryMapping format:
        - start_addr = p_vaddr
        - end_addr = p_vaddr + p_memsz
        - perms = convert p_flags to rwx format
        - offset = p_offset
        - pathname = "[core dump segment]" or detected binary name

        Args:
            program_headers: List of program header dicts from parse_program_headers

        Returns:
            List of memory mapping dicts suitable for MemoryMapping model

        Raises:
            ParseError: If headers are invalid type
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(program_headers, list):
                logger.warning(f"Invalid program_headers type: {type(program_headers)}")
                raise ParseError(f"program_headers must be list")

            mappings = []

            for idx, header in enumerate(program_headers):
                # Only process LOAD segments
                if header.get("type") != "LOAD":
                    continue

                # Validate header structure
                required_keys = ["vaddr", "memsz", "offset"]
                if not all(k in header for k in required_keys):
                    logger.warning(f"Incomplete header at index {idx}: missing keys")
                    continue

                # Validate address values
                vaddr = header["vaddr"]
                memsz = header["memsz"]
                if vaddr < 0 or memsz < 0:
                    logger.warning(f"Negative values in header {idx}: vaddr={vaddr}, memsz={memsz}")
                    continue

                if memsz > 0x40000000:  # 1GB (from config max)
                    logger.warning(f"Oversized segment {idx}: memsz={memsz / (1024**3):.1f}GB")
                    # Continue anyway, but log warning

                # Convert flags to permissions
                flags = header.get("flags", "")
                perms = ""
                perms += "r" if "R" in flags else "-"
                perms += "w" if "W" in flags else "-"
                perms += "x" if "E" in flags else "-"
                perms += "p"  # Private (from core dump)

                # Create mapping
                mapping = {
                    "start_addr": vaddr,
                    "end_addr": vaddr + memsz,
                    "perms": perms,
                    "offset": header.get("offset", 0),
                    "pathname": "[core dump segment]",
                }

                mappings.append(mapping)

            logger.debug(f"Extracted {len(mappings)} memory segments from {len(program_headers)} headers")
            return mappings

        except ParseError:
            raise
        except Exception as e:
            logger.error(f"Error extracting memory segments: {e}")
            raise ParseError(f"Memory segment extraction failed: {e}")

    async def extract_register_state(self, core_path: str) -> dict:
        """
        Extract CPU register state from PT_NOTE sections (Phase 2.3).

        Uses readelf to get note information, then parses NT_PRSTATUS.

        Args:
            core_path: Path to core dump

        Returns:
            {
                'rax': 0x...,
                'rbx': 0x...,
                'rip': 0x...,  # Crash location
                'rsp': 0x...,
                ...
            }

        Raises:
            FileFormatError: If core_path is invalid type
            ParseError: If parsing fails
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(core_path, str):
                logger.warning(f"Invalid core_path type: {type(core_path)}")
                raise FileFormatError(f"core_path must be string")

            if not core_path.strip():
                logger.warning("Empty core_path")
                return {}

            logger.debug(f"Extracting register state from core dump: {core_path}")

            notes_output = await self._get_readelf_output(core_path, ["-n"])

            if not notes_output:
                logger.debug("No notes section in core dump")
                return {}

            # Parse notes to find register information
            # For MVP, extract what we can from readelf output
            registers = {}

            # Look for register values in notes output
            # Readelf -n output contains register values as hex
            # Pattern: "R15:" or similar
            register_pattern = re.compile(r"(?:RAX|RBX|RCX|RDX|RSI|RDI|RBP|RSP|RIP|R\d+):\s+([0-9a-f]+)")

            for match in register_pattern.finditer(notes_output, re.IGNORECASE):
                reg_name = match.group(0).split(":")[0].lower()
                try:
                    reg_value = int(match.group(1), 16)
                    registers[reg_name] = reg_value
                except ValueError:
                    logger.warning(f"Failed to parse register value: {match.group(1)}")

            logger.debug(f"Extracted {len(registers)} registers from core dump")
            return registers

        except FileFormatError:
            raise
        except Exception as e:
            logger.error(f"Error extracting register state: {e}")
            raise ParseError(f"Register state extraction failed: {e}")

    @staticmethod
    def _extract_metadata_from_program_headers(
        program_headers: list[dict],
    ) -> dict:
        """
        Extract process metadata from PT_NOTE sections.

        Note: Full PT_NOTE parsing requires additional parsing.
        For MVP, we extract basic info if available.

        Args:
            program_headers: List of program headers

        Returns:
            {pid: int, signal: int, timestamp: str} (or empty if not found)
        """
        # Note: PT_NOTE parsing is complex and requires binary parsing
        # For MVP, we just track that metadata might be present
        # Full implementation would parse NT_PRPSINFO, NT_PRSTATUS
        return {}
