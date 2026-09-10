"""
ELF core dump parsing for offline process analysis (Phase 2.2).

Enables reconstruction of process memory layout from core dump files,
allowing address resolution on offline crashes.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import logging
import re
from pathlib import Path

from baldrick.binutils.parser import BinToolsParser
from baldrick.exceptions import (
    FileFormatError,
)
from baldrick.results import CoreDumpResult

logger = logging.getLogger("baldrick.coredump")


class CoreDumpParser:
    """Parse ELF core dump files to reconstruct process state."""

    def __init__(self, config):
        self.config = config
        self.parser = BinToolsParser(config)

    async def parse_core_dump(self, core_path: str) -> CoreDumpResult:
        """
        Parse ELF core dump and extract memory layout.

        Strategy:
        1. Use readelf to parse core dump headers (E_TYPE == ET_CORE)
        2. Extract program headers:
           - PT_LOAD: memory segments (map to MemoryMapping)
           - PT_NOTE: metadata (process state, register values)
        3. Reconstruct /proc/maps-like format from segments
        4. Return CoreDumpResult with status and mappings

        Args:
            core_path: Path to ELF core dump file

        Returns:
            CoreDumpResult with status and reason if parsing fails
        """
        # Input validation
        if not isinstance(core_path, str):
            logger.error(
                "invalid_core_path_type",
                extra={
                    "type": type(core_path).__name__,
                },
            )
            raise FileFormatError("core_path must be string")

        core_file = Path(core_path)

        # Check file exists
        if not core_file.exists():
            logger.warning(
                "core_dump_file_not_found",
                extra={
                    "core_path": core_path,
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="file_not_found",
                reason="Core dump file does not exist",
                core_path=core_path,
            )

        # Check file readable
        if not core_file.is_file():
            logger.warning(
                "core_dump_not_a_file",
                extra={
                    "core_path": core_path,
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="permission_denied",
                reason="Path is not a regular file",
                core_path=core_path,
            )

        # Check file size
        file_size = core_file.stat().st_size
        if file_size > self.config.max_core_dump_size:
            logger.warning(
                "core_dump_exceeds_size_limit",
                extra={
                    "core_path": core_path,
                    "file_size_mb": file_size / (1024**2),
                    "limit_mb": self.config.max_core_dump_size / (1024**2),
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="file_too_large",
                reason=f"Core dump size {file_size / (1024**2):.1f}MB exceeds limit",
                core_path=core_path,
            )

        logger.debug(
            "core_dump_parsing_started",
            extra={
                "core_path": core_path,
                "file_size_mb": file_size / (1024**2),
            },
        )

        # Step 1: Parse ELF headers
        headers_output = await self._get_readelf_output(core_path, ["-h"])

        if not headers_output:
            logger.warning(
                "failed_to_read_elf_headers",
                extra={
                    "core_path": core_path,
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="parse_error",
                reason="Failed to read ELF headers",
                core_path=core_path,
            )

        elf_headers = self.parse_elf_headers(headers_output)

        if elf_headers.get("type") not in ("ET_CORE", "CORE"):
            logger.warning(
                "not_a_core_dump",
                extra={
                    "core_path": core_path,
                    "elf_type": elf_headers.get("type"),
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="not_core_dump",
                reason=f"File type is {elf_headers.get('type')!r}, expected CORE or ET_CORE",
                core_path=core_path,
            )

        # Step 2: Parse program headers
        prog_output = await self._get_readelf_output(core_path, ["-l"])

        if not prog_output:
            logger.warning(
                "failed_to_read_program_headers",
                extra={
                    "core_path": core_path,
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="parse_error",
                reason="Failed to read program headers",
                core_path=core_path,
            )

        program_headers = self.parse_program_headers(prog_output)

        # Step 3: Extract memory segments
        memory_mappings = self.extract_memory_segments(program_headers)

        if not memory_mappings:
            logger.warning(
                "no_load_segments_found",
                extra={
                    "core_path": core_path,
                },
            )
            return CoreDumpResult(
                mappings=[],
                status="parse_error",
                reason="No PT_LOAD segments found in core dump",
                core_path=core_path,
            )

        # Step 4: Extract metadata from PT_NOTE
        metadata = self._extract_metadata_from_program_headers(program_headers)

        logger.info(
            "core_dump_parsed",
            extra={
                "core_path": core_path,
                "segment_count": len(memory_mappings),
                "program_header_count": len(program_headers),
                "pid": metadata.get("pid"),
            },
        )

        return CoreDumpResult(
            mappings=memory_mappings,
            elf_headers=elf_headers,
            pid=metadata.get("pid"),
            signal=metadata.get("signal"),
            status="success",
            core_path=core_path,
        )

    async def _get_readelf_output(self, core_path: str, args: list[str]) -> str | None:
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
        """Parse readelf -h output for ELF header info."""
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

        logger.debug("elf_headers_parsed", extra={"headers": result})
        return result

    @staticmethod
    def parse_program_headers(readelf_output: str) -> list[dict]:
        """Parse readelf -l output for program headers."""
        headers = []

        # Pattern: "Type           Offset             VirtAddr           PhysAddr"
        # "LOAD           0x0000000000001000 0x0000555555554000 0x0000000000000000"
        # "         0x0000000000001000 0x0000000000001000  R E                0x1000"
        prog_header_pattern = re.compile(
            r"(\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)"
            r"\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+([\w\-\s]+?)\s+0x",
            re.IGNORECASE,
        )

        failed_count = 0
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
            except (ValueError, IndexError):
                logger.debug("malformed_program_header")
                failed_count += 1
                # Continue parsing other headers rather than failing

        logger.debug(
            "program_headers_parsed",
            extra={
                "header_count": len(headers),
                "failed_count": failed_count,
            },
        )
        return headers

    @staticmethod
    def extract_memory_segments(program_headers: list[dict]) -> list[dict]:
        """Convert PT_LOAD segments to memory mappings."""
        mappings = []
        skipped_count = 0

        for idx, header in enumerate(program_headers):
            # Only process LOAD segments
            if header.get("type") != "LOAD":
                continue

            # Validate header structure
            required_keys = ["vaddr", "memsz", "offset"]
            if not all(k in header for k in required_keys):
                logger.debug("incomplete_segment_header", extra={"index": idx})
                skipped_count += 1
                continue

            # Validate address values
            vaddr = header["vaddr"]
            memsz = header["memsz"]
            if vaddr < 0 or memsz < 0:
                logger.debug(
                    "negative_segment_values",
                    extra={
                        "index": idx,
                        "vaddr": vaddr,
                        "memsz": memsz,
                    },
                )
                skipped_count += 1
                continue

            if memsz > 0x40000000:  # 1GB
                logger.warning(
                    "oversized_segment",
                    extra={
                        "index": idx,
                        "size_gb": memsz / (1024**3),
                    },
                )
                # Continue anyway

            # Convert flags to permissions
            flags = header.get("flags", "")
            perms = ""
            perms += "r" if "R" in flags else "-"
            perms += "w" if "W" in flags else "-"
            perms += "x" if "E" in flags else "-"
            perms += "p"  # Private (from core dump)

            mapping = {
                "start_addr": vaddr,
                "end_addr": vaddr + memsz,
                "perms": perms,
                "offset": header.get("offset", 0),
                "pathname": "[core dump segment]",
            }

            mappings.append(mapping)

        logger.debug(
            "memory_segments_extracted",
            extra={
                "segment_count": len(mappings),
                "total_headers": len(program_headers),
                "skipped_count": skipped_count,
            },
        )
        return mappings

    async def extract_register_state(self, core_path: str) -> dict:
        """Extract CPU register state from PT_NOTE sections (Phase 2.3)."""
        logger.debug("extracting_register_state", extra={"core_path": core_path})

        notes_output = await self._get_readelf_output(core_path, ["-n"])

        if not notes_output:
            logger.debug("no_notes_section")
            return {}

        # Parse notes to find register information
        # For MVP, extract what we can from readelf output
        registers = {}

        # Look for register values in notes output
        # Readelf -n output contains register values as hex
        # Pattern: "R15:" or similar
        register_pattern = re.compile(
            r"(?:RAX|RBX|RCX|RDX|RSI|RDI|RBP|RSP|RIP|R\d+):\s+([0-9a-f]+)"
        )

        failed_count = 0
        for match in register_pattern.finditer(notes_output, re.IGNORECASE):
            reg_name = match.group(0).split(":")[0].lower()
            try:
                reg_value = int(match.group(1), 16)
                registers[reg_name] = reg_value
            except ValueError:
                logger.debug(
                    "malformed_register_value",
                    extra={
                        "value": match.group(1),
                    },
                )
                failed_count += 1

        logger.debug(
            "register_state_extracted",
            extra={
                "register_count": len(registers),
                "failed_count": failed_count,
            },
        )
        return registers

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
