"""Stack frame chain validation and corruption detection.

Validates stack frame integrity to detect:
- Frame pointer corruption
- Stack buffer overflows
- Return address corruption
- Invalid frame chains
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum
from pydantic import BaseModel, Field
from blackadder.arch import Architecture


class FrameCorruptionType(str, Enum):
    """Types of frame chain corruption."""

    INVALID_POINTER = "invalid_pointer"
    CHAIN_LOOP = "chain_loop"
    MISALIGNED_FRAME = "misaligned_frame"
    SUSPICIOUS_RETURN = "suspicious_return"
    STACK_OVERFLOW = "stack_overflow"
    CORRUPTED_SAVED_REGISTERS = "corrupted_saved_registers"


class FrameValidationIssue(BaseModel):
    """Description of a frame validation issue."""

    issue_type: FrameCorruptionType = Field(description="Type of issue detected")
    frame_address: int = Field(description="Address of frame with issue")
    frame_pointer: int = Field(description="Frame pointer value")
    severity: float = Field(
        ge=0.0, le=1.0, description="Severity score (0.0-1.0)"
    )
    description: str = Field(description="Human-readable description")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence in detection (0.0-1.0)"
    )
    suggested_action: Optional[str] = Field(
        default=None, description="Suggested remediation"
    )


class StackFrame(BaseModel):
    """Description of a stack frame."""

    frame_num: int = Field(description="Frame number in chain (0 = top)")
    frame_pointer: int = Field(description="Frame pointer value")
    return_address: Optional[int] = Field(default=None, description="Return address")
    saved_rbp: Optional[int] = Field(default=None, description="Saved RBP value")
    is_valid: bool = Field(description="Whether frame appears valid")
    size: int = Field(description="Estimated frame size")
    issues: List[FrameValidationIssue] = Field(
        default_factory=list, description="Validation issues"
    )


class StackValidationResult(BaseModel):
    """Result of stack validation."""

    total_frames: int = Field(description="Total frames traced")
    valid_frames: int = Field(description="Number of valid frames")
    corrupted_frames: int = Field(description="Number of corrupted frames")
    frame_chain: List[StackFrame] = Field(
        default_factory=list, description="Traced frame chain"
    )
    issues: List[FrameValidationIssue] = Field(
        default_factory=list, description="All detected issues"
    )
    chain_integrity: float = Field(
        ge=0.0, le=1.0, description="Chain integrity score (0.0-1.0)"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Overall confidence in validation"
    )
    validation_notes: List[str] = Field(
        default_factory=list, description="Notes about validation"
    )


class StackValidator:
    """Validate stack frame chain integrity.

    Checks frame pointer chains, return address validity,
    and detects corruption patterns.
    """

    def __init__(self, architecture: Architecture):
        """Initialize validator.

        Args:
            architecture: Architecture instance for register semantics
        """
        self.architecture = architecture

    def validate_frame_chain(
        self,
        initial_frame_pointer: int,
        return_address: int,
        memory_read_func=None,
        max_frames: int = 100,
    ) -> StackValidationResult:
        """Validate stack frame chain starting from given frame pointer.

        Args:
            initial_frame_pointer: Starting RBP/FP value
            return_address: Current instruction pointer/return address
            memory_read_func: Function to read memory (address -> bytes)
            max_frames: Maximum frames to trace (prevent infinite loops)

        Returns:
            StackValidationResult with validation status and issues
        """
        if not memory_read_func:
            # Stub: return empty validation without live memory
            return StackValidationResult(
                total_frames=0,
                valid_frames=0,
                corrupted_frames=0,
                chain_integrity=0.0,
                confidence=0.0,
                validation_notes=[
                    "No memory read function provided; cannot validate live stack",
                    "Stack validation requires core dump or live memory access",
                ],
            )

        result = StackValidationResult(
            total_frames=0,
            valid_frames=0,
            corrupted_frames=0,
            chain_integrity=0.5,
            confidence=0.5,
            validation_notes=[
                "Stack validation stub: live memory support needed for Phase 3.4",
            ],
        )

        return result

    def check_frame_alignment(self, frame_pointer: int) -> bool:
        """Check if frame pointer is properly aligned.

        Args:
            frame_pointer: Frame pointer value to check

        Returns:
            True if properly aligned, False otherwise
        """
        # Most systems require 16-byte or pointer-size alignment
        alignment = 16
        return frame_pointer % alignment == 0

    def check_pointer_validity(
        self,
        frame_pointer: int,
        stack_start: int,
        stack_end: int,
    ) -> bool:
        """Check if frame pointer is within valid stack range.

        Args:
            frame_pointer: Frame pointer value to check
            stack_start: Stack region start address
            stack_end: Stack region end address

        Returns:
            True if pointer is within valid range, False otherwise
        """
        return stack_start <= frame_pointer < stack_end

    def detect_frame_loops(
        self,
        frames: List[StackFrame],
    ) -> List[FrameValidationIssue]:
        """Detect loops in frame pointer chain.

        Args:
            frames: List of frames in chain

        Returns:
            List of detected loop issues
        """
        issues = []

        # Check for duplicate frame pointers (loops)
        seen_fps = set()
        for i, frame in enumerate(frames):
            if frame.frame_pointer in seen_fps:
                issues.append(
                    FrameValidationIssue(
                        issue_type=FrameCorruptionType.CHAIN_LOOP,
                        frame_address=frame.frame_pointer,
                        frame_pointer=frame.frame_pointer,
                        severity=0.95,
                        description=f"Frame pointer loop detected at frame {i}: "
                        f"FP {frame.frame_pointer:#x} seen before",
                        confidence=0.95,
                        suggested_action="Stack corruption; unable to unwind further",
                    )
                )
            seen_fps.add(frame.frame_pointer)

        return issues

    def detect_buffer_overflow(
        self,
        frames: List[StackFrame],
    ) -> List[FrameValidationIssue]:
        """Detect potential stack buffer overflow patterns.

        Args:
            frames: List of frames in chain

        Returns:
            List of detected overflow issues
        """
        issues = []

        # Check for unusually large frame sizes
        for frame in frames:
            if frame.size > 1024 * 1024:  # > 1MB frame
                issues.append(
                    FrameValidationIssue(
                        issue_type=FrameCorruptionType.STACK_OVERFLOW,
                        frame_address=frame.frame_pointer,
                        frame_pointer=frame.frame_pointer,
                        severity=0.70,
                        description=f"Frame {frame.frame_num} has unusually large size: {frame.size} bytes",
                        confidence=0.70,
                        suggested_action="Check for large stack allocations or array overflows",
                    )
                )

        return issues

    def validate_return_addresses(
        self,
        frames: List[StackFrame],
        code_regions: List[Tuple[int, int]],
    ) -> List[FrameValidationIssue]:
        """Validate return addresses point to valid code regions.

        Args:
            frames: List of frames in chain
            code_regions: List of (start, end) tuples for valid code regions

        Returns:
            List of detected invalid return address issues
        """
        issues = []

        for frame in frames:
            if frame.return_address is None:
                continue

            # Check if return address is in any valid code region
            in_valid_code = any(
                start <= frame.return_address < end for start, end in code_regions
            )

            if not in_valid_code:
                issues.append(
                    FrameValidationIssue(
                        issue_type=FrameCorruptionType.SUSPICIOUS_RETURN,
                        frame_address=frame.frame_pointer,
                        frame_pointer=frame.frame_pointer,
                        severity=0.85,
                        description=f"Frame {frame.frame_num} return address {frame.return_address:#x} "
                        f"is outside valid code regions",
                        confidence=0.80,
                        suggested_action="Possible ROP attack or corrupted return address",
                    )
                )

        return issues
