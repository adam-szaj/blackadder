"""
Function fingerprinting for binary version-mismatch matching.

Extracts function boundaries and computes content hashes to enable
matching binaries with different versions but similar code.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import asyncio
import hashlib
import logging
import re
from pathlib import Path

from blackadder.binutils.parser import BinToolsParser
from blackadder.exceptions import (
    FileFormatError,
)
from blackadder.results import FingerprintResult

logger = logging.getLogger("blackadder.hasher")


class FunctionHasher:
    """Extract and hash function boundaries for binary matching."""

    def __init__(self, config):
        self.config = config
        self.parser = BinToolsParser(config)

    async def compute_fingerprints(self, binary_path: str) -> FingerprintResult:
        """
        Extract functions from binary and compute content hashes.

        Strategy:
        1. Parse objdump --syms to find function boundaries (name, start addr, size)
        2. Run objdump -d to get disassembly
        3. Extract function bytes, normalize (remove addresses), hash
        4. Return {func_name: content_hash}

        Args:
            binary_path: Path to ELF binary

        Returns:
            FingerprintResult with status and reason if computation fails

        Raises:
            FileNotFoundError: If binary not found
            FileAccessError: If binary not readable
            FileTooLargeError: If binary exceeds size limit
            FileFormatError: If binary is invalid type
        """
        # Input validation
        if not isinstance(binary_path, str):
            logger.error(
                "invalid_binary_path_type",
                extra={
                    "type": type(binary_path).__name__,
                },
            )
            raise FileFormatError("binary_path must be string")

        binary_file = Path(binary_path)

        # Check file exists
        if not binary_file.exists():
            logger.warning(
                "binary_file_not_found",
                extra={
                    "binary_path": binary_path,
                },
            )
            return FingerprintResult(
                fingerprints={},
                status="file_not_found",
                reason="Binary file does not exist",
                binary_path=binary_path,
            )

        # Check file readable
        if not binary_file.is_file():
            logger.warning(
                "binary_not_a_file",
                extra={
                    "binary_path": binary_path,
                },
            )
            return FingerprintResult(
                fingerprints={},
                status="permission_denied",
                reason="Path is not a regular file",
                binary_path=binary_path,
            )

        # Check file size
        file_size = binary_file.stat().st_size
        if file_size > self.config.max_core_dump_size:
            logger.warning(
                "binary_exceeds_size_limit",
                extra={
                    "binary_path": binary_path,
                    "file_size_mb": file_size / (1024**2),
                    "limit_mb": self.config.max_core_dump_size / (1024**2),
                },
            )
            return FingerprintResult(
                fingerprints={},
                status="file_too_large",
                reason=f"Binary size {file_size / (1024**2):.1f}MB exceeds limit",
                binary_path=binary_path,
            )

        logger.debug(
            "fingerprint_computation_started",
            extra={
                "binary_path": binary_path,
                "file_size_mb": file_size / (1024**2),
            },
        )

        # Step 1: Get function boundaries from symbol table
        function_info = await self._extract_function_info(binary_path)

        if not function_info:
            logger.warning(
                "no_function_symbols",
                extra={
                    "binary_path": binary_path,
                },
            )
            return FingerprintResult(
                fingerprints={},
                status="no_functions",
                reason="Binary has no function symbols",
                binary_path=binary_path,
            )

        # Step 2: Get disassembly
        disassembly = await self._get_disassembly(binary_path)

        if not disassembly:
            logger.warning(
                "no_disassembly_generated",
                extra={
                    "binary_path": binary_path,
                },
            )
            return FingerprintResult(
                fingerprints={},
                status="parse_error",
                reason="Failed to generate disassembly",
                binary_path=binary_path,
            )

        # Step 3: Compute fingerprints for each function
        fingerprints = {}
        failed_funcs = 0

        for func_name, func_data in function_info.items():
            try:
                start_addr = func_data.get("address", 0)
                size = func_data.get("size", 0)
                end_addr = start_addr + size

                # Extract function disassembly bytes
                func_asm = self._extract_function_asm(disassembly, start_addr, end_addr, func_name)

                if func_asm:
                    # Normalize and hash
                    normalized = self.normalize_function_body(func_asm)
                    content_hash = hashlib.sha256(normalized).hexdigest()
                    fingerprints[func_name] = content_hash
            except Exception as e:
                logger.debug(
                    "function_fingerprint_failed",
                    extra={
                        "binary_path": binary_path,
                        "function": func_name,
                        "error": str(e),
                    },
                )
                failed_funcs += 1

        logger.info(
            "fingerprint_computation_completed",
            extra={
                "binary_path": binary_path,
                "fingerprint_count": len(fingerprints),
                "failed_count": failed_funcs,
                "total_functions": len(function_info),
            },
        )

        return FingerprintResult(
            fingerprints=fingerprints,
            status="success",
            binary_path=binary_path,
        )

    async def _extract_function_info(self, binary_path: str) -> dict[str, dict]:
        """
        Extract function metadata from objdump --syms.

        Returns:
            {func_name: {address: int, size: int, section: str}, ...}
        """
        lines = []

        def collect_line(line):
            lines.append(line)

        logger.debug("extracting_function_symbols", extra={"binary_path": binary_path})

        await self.parser.run_command_limited(
            [self.config.objdump_path, "--syms", binary_path], collect_line
        )

        if not lines:
            logger.debug("no_symbol_output", extra={"binary_path": binary_path})
            return {}

        # Parse symbol output in thread pool
        def parse_symbols(all_lines):
            result = {}
            # Pattern: address scope type section size name
            # Example: 0000000000001000 g     F .text  0000000000000042 my_function
            symbol_pattern = re.compile(
                r"^([0-9a-f]+)\s+([lg])\s+([FOO])\s+([.\w]+)\s+([0-9a-f]+)\s+(.+)$"
            )

            for line in all_lines:
                m = symbol_pattern.match(line.strip())
                if m:
                    try:
                        addr = int(m.group(1), 16)
                        sym_type = m.group(3)
                        section = m.group(4)
                        size = int(m.group(5), 16)
                        name = m.group(6).strip()

                        # Only include function symbols
                        if sym_type == "F" and size > 0 and name not in result:
                            result[name] = {
                                "address": addr,
                                "size": size,
                                "section": section,
                            }
                    except (ValueError, IndexError):
                        # Skip malformed symbol line, continue parsing
                        continue

            return result

        function_info = await asyncio.to_thread(parse_symbols, lines)
        logger.debug(
            "function_symbols_extracted",
            extra={
                "binary_path": binary_path,
                "function_count": len(function_info),
            },
        )
        return function_info

    async def _get_disassembly(self, binary_path: str) -> str:
        """Get full disassembly via objdump -d."""
        lines = []

        def collect_line(line):
            lines.append(line)

        logger.debug("generating_disassembly", extra={"binary_path": binary_path})

        await self.parser.run_command_limited(
            [self.config.objdump_path, "-d", binary_path], collect_line
        )

        if not lines:
            logger.debug("no_disassembly_output", extra={"binary_path": binary_path})
            return ""

        result = "\n".join(lines)
        logger.debug(
            "disassembly_generated",
            extra={
                "binary_path": binary_path,
                "line_count": len(lines),
            },
        )
        return result

    def _extract_function_asm(
        self, disassembly: str, start_addr: int, end_addr: int, func_name: str
    ) -> list[str]:
        """Extract disassembly lines for a specific function."""
        func_lines = []
        in_function = False

        for line in disassembly.split("\n"):
            line = line.strip()

            if not line:
                continue

            # Check if this line starts the function (contains function name)
            if f"<{func_name}>:" in line:
                in_function = True
                continue

            if in_function:
                # Stop at next function
                if line and line.endswith(">:") and func_name not in line:
                    break

                # Extract instruction part (skip address and hex bytes)
                # Format: address: hex hex hex ... instruction
                # Example: 1000:	48 89 e5                	mov    %rsp,%rbp
                parts = line.split("\t", 1)
                if len(parts) >= 2:
                    instruction = parts[-1]
                    func_lines.append(instruction)

        logger.debug(
            "function_assembly_extracted",
            extra={
                "function_name": func_name,
                "line_count": len(func_lines),
            },
        )
        return func_lines

    @staticmethod
    def normalize_function_body(asm_lines: list[str]) -> bytes:
        """
        Normalize disassembly for hashing.

        Remove:
        - Absolute addresses (relocation-independent)
        - Specific register names (normalize to patterns)
        - Immediate values that may differ across versions

        Keep: instruction opcodes and operand structure
        """
        if not asm_lines:
            logger.debug("empty_assembly_lines")
            return b""

        normalized_lines = []

        for line in asm_lines:
            # Remove comments
            if "#" in line:
                line = line.split("#")[0]

            line = line.strip()
            if not line:
                continue

            # Normalize absolute addresses (0x... pattern at end of line)
            # These can differ across versions due to ASLR/PIE
            line = re.sub(r"0x[0-9a-f]+", "0xADDR", line)

            # Normalize register names to generic patterns
            # %rax, %eax, %al -> %REG_A
            # %rbx, %ebx, %bl -> %REG_B, etc.
            register_map = {
                r"%r?[0-9]?[a-d][xl]": "%REG_A",
                r"%r?[0-9]?[b][xl]": "%REG_B",
                r"%r?[0-9]?[c][xl]": "%REG_C",
                r"%r?[0-9]?[d][xl]": "%REG_D",
                r"%r?[sd]i": "%REG_IDX",
                r"%r?bp": "%REG_BP",
                r"%r?sp": "%REG_SP",
            }

            for pattern, replacement in register_map.items():
                line = re.sub(pattern, replacement, line)

            # Normalize immediate values (numbers that aren't part of instructions)
            # Keep instruction structure but normalize numeric constants
            line = re.sub(r"\$0x[0-9a-f]+", "$IMM", line)
            line = re.sub(r"\$-?\d+", "$IMM", line)

            normalized_lines.append(line)

        # Join and encode for hashing
        normalized_text = "\n".join(normalized_lines)
        result = normalized_text.encode("utf-8")
        logger.debug(
            "assembly_normalized",
            extra={
                "input_lines": len(asm_lines),
                "output_bytes": len(result),
            },
        )
        return result
