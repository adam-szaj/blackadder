"""
Memory analysis for process snapshots (Phase 2.3).

Classifies memory regions, detects anomalies, and analyzes potential corruption.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import logging
import re
from typing import Optional

from blackadder.models import MemoryRegionType
from blackadder.exceptions import (
    ValidationError,
    InvalidArgumentError,
    MemoryAnalysisError,
)

logger = logging.getLogger("blackadder.analyzer")


class MemoryAnalyzer:
    """Analyze and classify memory regions."""

    def __init__(self, config):
        self.config = config

    @staticmethod
    def classify_region(
        pathname: str,
        start_addr: int,
        end_addr: int,
        perms: str,
        offset: int,
        register_state: Optional[dict] = None,
    ) -> tuple[MemoryRegionType, float]:
        """
        Classify memory region type and confidence.

        Validates inputs and handles edge cases gracefully.

        Raises:
            ValidationError: If inputs are invalid

        Heuristics:
        - pathname contains "heap" → HEAP
        - near RSP/RBP (register_state provided) → STACK
        - pathname contains "vdso" → VDSO
        - pathname contains "vsyscall" → VSYSCALL
        - pathname contains ".so" → MMAP library
        - permissions contain "x" and size reasonable → may be JIT
        - filename is binary name → TEXT/DATA
        - anonymous mapping "[anon]" → ANON

        Args:
            pathname: Memory region name
            start_addr: Start address
            end_addr: End address
            perms: Permission string (r/w/x)
            offset: File offset
            register_state: Optional CPU register state (for stack detection)

        Returns:
            (MemoryRegionType, confidence: 0.0-1.0)

        Raises:
            ValidationError: If address range is invalid
        """
        # Input validation (Phase 2 hardening)
        if start_addr < 0 or end_addr < 0:
            logger.warning(f"Negative address: {start_addr:#x} to {end_addr:#x}")
            raise ValidationError(f"Negative addresses not allowed")

        if start_addr >= end_addr:
            logger.warning(f"Invalid address range: {start_addr:#x} >= {end_addr:#x}")
            raise ValidationError(f"start_addr must be less than end_addr")

        if len(perms) != 4 or perms[3] not in "ps":
            logger.warning(f"Invalid permissions string: {perms}")
            raise ValidationError(f"Invalid permissions (expected 4 chars like 'rw-p')")

        if not isinstance(pathname, str):
            logger.warning(f"Invalid pathname type: {type(pathname)}")
            raise ValidationError(f"pathname must be string")

        size = end_addr - start_addr

        # Check for stack (near RSP/RBP)
        if register_state:
            rsp = register_state.get("rsp")
            rbp = register_state.get("rbp")

            if rsp and rbp:
                # Stack typically contains RSP and is below it
                if start_addr <= rsp < end_addr or start_addr <= rbp < end_addr:
                    return (MemoryRegionType.STACK, 0.95)

        # Explicit markers in pathname
        if "[heap]" in pathname:
            return (MemoryRegionType.HEAP, 0.99)

        if "[stack]" in pathname:
            return (MemoryRegionType.STACK, 0.99)

        if "vdso" in pathname.lower():
            return (MemoryRegionType.VDSO, 0.98)

        if "vsyscall" in pathname.lower():
            return (MemoryRegionType.VSYSCALL, 0.98)

        if "vvar" in pathname.lower():
            return (MemoryRegionType.VVAR, 0.95)

        if "[anon]" in pathname or pathname == "":
            return (MemoryRegionType.ANON, 0.80)

        # Shared libraries
        if ".so" in pathname:
            # May be executable or not
            if "x" in perms:
                return (MemoryRegionType.MMAP, 0.90)
            else:
                return (MemoryRegionType.MMAP, 0.85)

        # Heap heuristic: anonymous mapping without execute
        if (
            "[anon]" in pathname
            and "x" not in perms
            and "w" in perms
            and size > 0x1000
        ):
            return (MemoryRegionType.HEAP, 0.70)

        # JIT heuristic: executable anonymous memory
        if "[anon]" in pathname and "x" in perms and "w" in perms:
            return (MemoryRegionType.JIT, 0.75)

        # Default
        return (MemoryRegionType.UNKNOWN, 0.5)

    @staticmethod
    def detect_anomalies(
        region_type: MemoryRegionType,
        perms: str,
        size: int,
        pathname: str,
    ) -> list[str]:
        """
        Detect potential memory anomalies.

        Args:
            region_type: Classified region type
            perms: Permission string
            size: Region size in bytes
            pathname: Region name

        Returns:
            List of anomaly descriptions

        Raises:
            ValidationError: If inputs are invalid
        """
        # Validate once at boundary (analyze_memory_region)
        anomalies = []

        # Executable heap (code injection marker)
        if region_type == MemoryRegionType.HEAP and "x" in perms:
            anomalies.append("Executable heap (code injection risk)")

        # Writable code section
        if region_type in [
            MemoryRegionType.TEXT,
            MemoryRegionType.MMAP,
        ] and "x" in perms and "w" in perms:
            anomalies.append("Writable executable region (unusual)")

        # Oversized region (> 1GB)
        if size > 0x40000000:  # 1GB
            anomalies.append(f"Oversized region ({size / (1024**3):.1f}GB)")

        # RWX region (all permissions)
        if "r" in perms and "w" in perms and "x" in perms:
            anomalies.append("RWX region (full permissions - unusual)")

        # Stack writable is normal, but flag if unusual size
        if region_type == MemoryRegionType.STACK and size > 0x10000000:  # 256MB
            anomalies.append(f"Large stack region ({size / (1024**2):.1f}MB)")

        # Suspicious naming
        if re.match(r"^\[.*\]$", pathname) and region_type == MemoryRegionType.UNKNOWN:
            anomalies.append("Unusual bracketed region name")

        return anomalies

    @staticmethod
    def check_corruption_markers(
        region_type: MemoryRegionType,
        perms: str,
        pathname: str,
    ) -> bool:
        """
        Check for common memory corruption patterns.

        Args:
            region_type: Classified region type
            perms: Permission string
            pathname: Region name

        Returns:
            True if potential corruption detected

        Raises:
            ValidationError: If inputs are invalid
        """
        try:
            # Executable heap
            if region_type == MemoryRegionType.HEAP and "x" in perms:
                logger.warning(f"Executable heap detected: {pathname}")
                return True

            # RWX region (highly suspicious)
            if "r" in perms and "w" in perms and "x" in perms:
                logger.warning(f"RWX region detected: {pathname}")
                return True

            # Writable vdso/vsyscall (should be read-only)
            if region_type in [MemoryRegionType.VDSO, MemoryRegionType.VSYSCALL]:
                if "w" in perms:
                    logger.warning(f"Writable {region_type.value} detected: {pathname}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking corruption markers: {e}")
            raise MemoryAnalysisError(f"Corruption check failed: {e}")

    @staticmethod
    def analyze_memory_region(
        pathname: str,
        start_addr: int,
        end_addr: int,
        perms: str,
        offset: int,
        register_state: Optional[dict] = None,
    ) -> dict:
        """
        Perform full analysis on a memory region.

        Args:
            pathname: Region name
            start_addr: Start address
            end_addr: End address
            perms: Permissions string
            offset: File offset
            register_state: Optional register state

        Returns:
            {
                'region_type': MemoryRegionType,
                'confidence': float,
                'is_writable': bool,
                'is_executable': bool,
                'likely_corrupted': bool,
                'anomalies': [str],
            }

        Raises:
            ValidationError: If inputs are invalid
            MemoryAnalysisError: If analysis fails
        """
        try:
            # Input validation
            if start_addr < 0 or end_addr < 0:
                logger.error(f"Negative addresses: {start_addr:#x} to {end_addr:#x}")
                raise ValidationError("Negative addresses not allowed")

            if start_addr >= end_addr:
                logger.error(f"Invalid range: {start_addr:#x} >= {end_addr:#x}")
                raise ValidationError("start_addr must be less than end_addr")

            size = end_addr - start_addr
            is_writable = "w" in perms
            is_executable = "x" in perms

            logger.debug(f"Analyzing region {pathname} ({start_addr:#x}-{end_addr:#x})")

            region_type, confidence = MemoryAnalyzer.classify_region(
                pathname, start_addr, end_addr, perms, offset, register_state
            )

            anomalies = MemoryAnalyzer.detect_anomalies(
                region_type, perms, size, pathname
            )

            likely_corrupted = MemoryAnalyzer.check_corruption_markers(
                region_type, perms, pathname
            )

            result = {
                "region_type": region_type.value,
                "confidence": confidence,
                "is_writable": is_writable,
                "is_executable": is_executable,
                "likely_corrupted": likely_corrupted,
                "anomalies": anomalies,
                "size": size,
                "start_addr": start_addr,
                "end_addr": end_addr,
            }

            logger.debug(
                f"Analysis complete: {region_type.value} "
                f"(confidence={confidence:.2f}, corrupted={likely_corrupted})"
            )

            return result

        except (ValidationError, MemoryAnalysisError):
            raise
        except Exception as e:
            logger.error(f"Error analyzing region {pathname}: {e}")
            raise MemoryAnalysisError(f"Analysis failed for {pathname}: {e}")

    @staticmethod
    def format_register_display(register_state: Optional[dict] = None) -> str:
        """
        Format register state for display.

        Args:
            register_state: Dict of register name → value (or None)

        Returns:
            Formatted string for display

        Raises:
            ValidationError: If register_state is invalid type
        """
        try:
            # Handle missing register state
            if register_state is None:
                logger.debug("No register state available")
                return "No register state available from core dump"

            lines = []

            # Group registers by type
            gp_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"]
            ext_regs = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
            special = ["rip", "eflags"]

            lines.append("General Purpose Registers:")
            for i in range(0, len(gp_regs), 2):
                reg1 = gp_regs[i]
                reg2 = gp_regs[i + 1] if i + 1 < len(gp_regs) else None

                val1 = register_state.get(reg1)
                val1_str = f"{val1:#018x}" if val1 is not None else "N/A"

                if reg2:
                    val2 = register_state.get(reg2)
                    val2_str = f"{val2:#018x}" if val2 is not None else "N/A"
                    lines.append(
                        f"  {reg1:4s} = {val1_str}    {reg2:4s} = {val2_str}"
                    )
                else:
                    lines.append(f"  {reg1:4s} = {val1_str}")

            lines.append("\nExtended Registers:")
            for i in range(0, len(ext_regs), 2):
                reg1 = ext_regs[i]
                reg2 = ext_regs[i + 1] if i + 1 < len(ext_regs) else None

                val1 = register_state.get(reg1)
                val1_str = f"{val1:#018x}" if val1 is not None else "N/A"

                if reg2:
                    val2 = register_state.get(reg2)
                    val2_str = f"{val2:#018x}" if val2 is not None else "N/A"
                    lines.append(
                        f"  {reg1:4s} = {val1_str}    {reg2:4s} = {val2_str}"
                    )
                else:
                    lines.append(f"  {reg1:4s} = {val1_str}")

            lines.append("\nSpecial Registers:")
            for reg in special:
                val = register_state.get(reg)
                val_str = f"{val:#018x}" if val is not None else "N/A"
                lines.append(f"  {reg:4s} = {val_str}")

            logger.debug(f"Formatted {len(register_state)} registers")
            return "\n".join(lines)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Error formatting registers: {e}")
            raise MemoryAnalysisError(f"Register formatting failed: {e}")
