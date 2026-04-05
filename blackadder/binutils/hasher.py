"""
Function fingerprinting for binary version-mismatch matching.

Extracts function boundaries and computes content hashes to enable
matching binaries with different versions but similar code.
"""

import asyncio
import hashlib
import re
from typing import Optional

from blackadder.binutils.parser import BinToolsParser


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
        """
        # Step 1: Get function boundaries from symbol table
        symbols = await self.parser.parse_objdump_syms(binary_path)

        if not symbols:
            return {}

        # Extract only function symbols (scope == F)
        # We need to get more info from objdump --syms output
        function_info = await self._extract_function_info(binary_path)

        if not function_info:
            return {}

        # Step 2: Get disassembly
        disassembly = await self._get_disassembly(binary_path)

        if not disassembly:
            return {}

        # Step 3: Compute fingerprints for each function
        fingerprints = {}

        for func_name, func_data in function_info.items():
            start_addr = func_data["address"]
            size = func_data["size"]
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

        return fingerprints

    async def _extract_function_info(self, binary_path: str) -> dict[str, dict]:
        """
        Extract function metadata from objdump --syms.

        Returns:
            {func_name: {address: int, size: int, section: str}, ...}
        """
        function_info = {}
        lines = []

        def collect_line(line):
            lines.append(line)

        await self.parser.run_command_limited(
            [self.config.objdump_path, "--syms", binary_path], collect_line
        )

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
                    addr = int(m.group(1), 16)
                    scope = m.group(2)
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

            return result

        function_info = await asyncio.to_thread(parse_symbols, lines)
        return function_info

    async def _get_disassembly(self, binary_path: str) -> str:
        """Get full disassembly via objdump -d."""
        lines = []

        def collect_line(line):
            lines.append(line)

        await self.parser.run_command_limited(
            [self.config.objdump_path, "-d", binary_path], collect_line
        )

        return "\n".join(lines)

    def _extract_function_asm(
        self, disassembly: str, start_addr: int, end_addr: int, func_name: str
    ) -> list[str]:
        """
        Extract disassembly lines for a specific function.

        Returns:
            List of disassembly lines for the function (excluding address/offset info)
        """
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

        Args:
            asm_lines: Disassembly instruction lines

        Returns:
            Normalized bytes suitable for hashing
        """
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
        return normalized_text.encode("utf-8")
