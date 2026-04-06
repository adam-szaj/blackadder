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
from typing import Optional

from blackadder.binutils.parser import BinToolsParser
from blackadder.exceptions import (
    FileNotFoundError,
    FileAccessError,
    FileTooLargeError,
    FileFormatError,
    ParseError,
)

logger = logging.getLogger("blackadder.hasher")


class FunctionHasher:
    """Extract and hash function boundaries for binary matching."""

    def __init__(self, config):
        self.config = config
        self.parser = BinToolsParser(config)

    async def compute_fingerprints(self, binary_path: str) -> dict[str, str]:
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
            Dict mapping function name -> SHA256 hash of normalized body

        Raises:
            FileNotFoundError: If binary not found
            FileAccessError: If binary not readable
            FileTooLargeError: If binary exceeds size limit
            FileFormatError: If binary is invalid type
            ParseError: If parsing fails
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(binary_path, str):
                logger.error(f"Invalid binary_path type: {type(binary_path)}")
                raise FileFormatError(f"binary_path must be string")

            binary_file = Path(binary_path)

            # Check file exists
            if not binary_file.exists():
                logger.error(f"Binary file not found: {binary_path}")
                raise FileNotFoundError(f"Binary file not found: {binary_path}")

            # Check file readable
            if not binary_file.is_file():
                logger.error(f"Binary is not a file: {binary_path}")
                raise FileAccessError(f"Binary is not a file: {binary_path}")

            # Check file size
            file_size = binary_file.stat().st_size
            if file_size > self.config.max_core_dump_size:  # Reuse existing limit
                logger.error(f"Binary exceeds size limit: {file_size} > {self.config.max_core_dump_size}")
                raise FileTooLargeError(
                    f"Binary exceeds limit: {file_size / (1024**2):.1f}MB "
                    f"(max {self.config.max_core_dump_size / (1024**2):.1f}MB)"
                )

            logger.debug(f"Computing fingerprints for: {binary_path} ({file_size / (1024**2):.1f}MB)")

            # Step 1: Get function boundaries from symbol table
            function_info = await self._extract_function_info(binary_path)

            if not function_info:
                logger.debug(f"No function symbols found in {binary_path}")
                return {}

            # Step 2: Get disassembly
            disassembly = await self._get_disassembly(binary_path)

            if not disassembly:
                logger.warning(f"No disassembly generated for {binary_path}")
                return {}

            # Step 3: Compute fingerprints for each function
            fingerprints = {}
            failed_funcs = 0

            for func_name, func_data in function_info.items():
                try:
                    start_addr = func_data.get("address", 0)
                    size = func_data.get("size", 0)
                    end_addr = start_addr + size

                    # Extract function disassembly bytes
                    func_asm = self._extract_function_asm(
                        disassembly, start_addr, end_addr, func_name
                    )

                    if func_asm:
                        # Normalize and hash
                        normalized = self.normalize_function_body(func_asm)
                        content_hash = hashlib.sha256(normalized).hexdigest()
                        fingerprints[func_name] = content_hash
                except Exception as e:
                    logger.warning(f"Failed to fingerprint function {func_name}: {e}")
                    failed_funcs += 1

            logger.debug(f"Computed {len(fingerprints)} fingerprints ({failed_funcs} failed)")
            return fingerprints

        except (FileNotFoundError, FileAccessError, FileTooLargeError, FileFormatError, ParseError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error computing fingerprints: {e}")
            raise ParseError(f"Fingerprint computation failed: {e}")

    async def _extract_function_info(self, binary_path: str) -> dict[str, dict]:
        """
        Extract function metadata from objdump --syms.

        Returns:
            {func_name: {address: int, size: int, section: str}, ...}

        Raises:
            ParseError: If parsing fails
        """
        try:
            function_info = {}
            lines = []

            def collect_line(line):
                lines.append(line)

            logger.debug(f"Extracting function info from: {binary_path}")

            await self.parser.run_command_limited(
                [self.config.objdump_path, "--syms", binary_path], collect_line
            )

            if not lines:
                logger.warning(f"No symbol output from objdump: {binary_path}")
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
                        except (ValueError, IndexError) as e:
                            logger.warning(f"Failed to parse symbol line: {e}")

                return result

            function_info = await asyncio.to_thread(parse_symbols, lines)
            logger.debug(f"Extracted {len(function_info)} functions")
            return function_info

        except Exception as e:
            logger.error(f"Error extracting function info: {e}")
            raise ParseError(f"Function info extraction failed: {e}")

    async def _get_disassembly(self, binary_path: str) -> str:
        """
        Get full disassembly via objdump -d.

        Raises:
            ParseError: If disassembly fails
        """
        try:
            lines = []

            def collect_line(line):
                lines.append(line)

            logger.debug(f"Generating disassembly for: {binary_path}")

            await self.parser.run_command_limited(
                [self.config.objdump_path, "-d", binary_path], collect_line
            )

            if not lines:
                logger.warning(f"No disassembly output for {binary_path}")
                return ""

            result = "\n".join(lines)
            logger.debug(f"Generated {len(lines)} disassembly lines")
            return result

        except Exception as e:
            logger.error(f"Error generating disassembly: {e}")
            raise ParseError(f"Disassembly generation failed: {e}")

    def _extract_function_asm(
        self, disassembly: str, start_addr: int, end_addr: int, func_name: str
    ) -> list[str]:
        """
        Extract disassembly lines for a specific function.

        Returns:
            List of disassembly lines for the function (excluding address/offset info)

        Raises:
            ParseError: If inputs are invalid
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(disassembly, str):
                logger.warning(f"Invalid disassembly type: {type(disassembly)}")
                raise ParseError(f"disassembly must be string")

            if not isinstance(func_name, str):
                logger.warning(f"Invalid func_name type: {type(func_name)}")
                raise ParseError(f"func_name must be string")

            if start_addr < 0 or end_addr < 0:
                logger.warning(f"Invalid addresses: start={start_addr}, end={end_addr}")
                raise ParseError(f"Addresses must be non-negative")

            if start_addr >= end_addr:
                logger.debug(f"Empty address range for {func_name}: {start_addr}-{end_addr}")
                return []

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

            logger.debug(f"Extracted {len(func_lines)} assembly lines for {func_name}")
            return func_lines

        except ParseError:
            raise
        except Exception as e:
            logger.error(f"Error extracting function assembly: {e}")
            raise ParseError(f"Assembly extraction failed: {e}")

    @staticmethod
    def normalize_function_body(asm_lines: list[str]) -> bytes:
        """
        Normalize disassembly for hashing.

        Remove:
        - Absolute addresses (relocation-independent)
        - Specific register names (normalize to patterns)
        - Immediate values that may differ across versions

        Keep: instruction opcodes and operand structure

        Args:
            asm_lines: Disassembly instruction lines

        Returns:
            Normalized bytes suitable for hashing

        Raises:
            ParseError: If inputs are invalid
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(asm_lines, list):
                logger.warning(f"Invalid asm_lines type: {type(asm_lines)}")
                raise ParseError(f"asm_lines must be list")

            if not asm_lines:
                logger.debug("Empty assembly lines for normalization")
                return b""

            normalized_lines = []

            for idx, line in enumerate(asm_lines):
                if not isinstance(line, str):
                    logger.warning(f"Non-string line at index {idx}: {type(line)}")
                    continue

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
            logger.debug(f"Normalized {len(asm_lines)} lines to {len(result)} bytes")
            return result

        except ParseError:
            raise
        except Exception as e:
            logger.error(f"Error normalizing function body: {e}")
            raise ParseError(f"Function normalization failed: {e}")
