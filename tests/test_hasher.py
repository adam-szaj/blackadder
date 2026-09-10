"""
Tests for FunctionHasher module (Phase 2.1 - Binary Matching).

Tests fingerprint extraction, normalization, and content hashing.
"""

from unittest.mock import AsyncMock

import pytest

from baldrick.arch.x86 import X86_64Architecture
from baldrick.binutils.hasher import FunctionHasher


@pytest.fixture
def hasher(config):
    """Fixture for FunctionHasher instance."""
    return FunctionHasher(config, X86_64Architecture())


@pytest.fixture
def sample_binary(tmp_path):
    """Create a readable file; command output is mocked by each test."""
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"ELF")
    return str(binary)


class TestNormalizeFunctionBody:
    """Test function body normalization for hashing."""

    def test_normalize_removes_addresses(self, hasher):
        """Test that addresses are replaced with generic pattern."""
        asm_lines = [
            "mov    0x400000(%rip),%rax",
            "call   0x401000 <function>",
            "jmp    0x401234",
        ]

        normalized = hasher.normalize_function_body(asm_lines)
        normalized_text = normalized.decode("utf-8")

        # Addresses should be normalized
        assert "0x400000" not in normalized_text
        assert "0x401000" not in normalized_text
        assert "0x401234" not in normalized_text
        assert "0xADDR" in normalized_text

    def test_normalize_removes_comments(self, hasher):
        """Test that comments are stripped."""
        asm_lines = [
            "mov    %rax,%rbx  # copy value",
            "add    $1,%rcx    # increment counter",
        ]

        normalized = hasher.normalize_function_body(asm_lines)
        normalized_text = normalized.decode("utf-8")

        # Comments should be removed
        assert "# copy" not in normalized_text
        assert "# increment" not in normalized_text

    def test_normalize_handles_immediate_values(self, hasher):
        """Test that immediate values are normalized."""
        asm_lines = [
            "mov    $0x1000,%rax",
            "add    $-42,%rbx",
            "sub    $256,%rcx",
        ]

        normalized = hasher.normalize_function_body(asm_lines)
        normalized_text = normalized.decode("utf-8")

        # Immediates should be normalized
        assert "0x1000" not in normalized_text
        assert "-42" not in normalized_text
        assert "256" not in normalized_text
        assert normalized_text.count("$IMM") >= 3

    def test_normalize_identical_inputs_same_hash(self, hasher):
        """Test that identical code normalizes to same bytes."""
        asm_lines_1 = [
            "mov    %rsi,%rdi",
            "call   0x401234 <strlen>",
            "cmp    %rax,%rbx",
            "je     0x401500",
        ]

        asm_lines_2 = [
            "mov    %rsi,%rdi",
            "call   0x405678 <strlen>",  # Different address
            "cmp    %rax,%rbx",
            "je     0x401600",  # Different address
        ]

        norm1 = hasher.normalize_function_body(asm_lines_1)
        norm2 = hasher.normalize_function_body(asm_lines_2)

        # Should normalize to same value (addresses don't matter)
        assert norm1 == norm2

    def test_normalize_different_registers_same_pattern(self, hasher):
        """Test that different registers are normalized to patterns."""
        asm_lines_1 = [
            "mov    %rax,%rbx",
            "add    %rcx,%rdx",
        ]

        asm_lines_2 = [
            "mov    %rbx,%rax",  # Swapped
            "add    %rdx,%rcx",  # Swapped
        ]

        norm1 = hasher.normalize_function_body(asm_lines_1)
        norm2 = hasher.normalize_function_body(asm_lines_2)

        # Different register usage should NOT normalize to same
        # (this is intentional - register differences matter)
        assert norm1 != norm2
        # But specific register names should be replaced
        assert "%rax" not in norm1.decode("utf-8")
        assert "%rbx" not in norm1.decode("utf-8")

    def test_normalize_empty_lines_ignored(self, hasher):
        """Test that empty lines are ignored."""
        asm_lines = [
            "mov    %rax,%rbx",
            "",  # Empty
            "add    $1,%rcx",
            "   ",  # Whitespace
        ]

        normalized = hasher.normalize_function_body(asm_lines)
        normalized_text = normalized.decode("utf-8")

        # Should have only 2 instructions
        lines = [line for line in normalized_text.split("\n") if line.strip()]
        assert len(lines) == 2


class TestExtractFunctionAssembly:
    """Test function assembly extraction from disassembly."""

    def test_extract_function_asm_basic(self, hasher):
        """Test extracting a simple function."""
        disassembly = """
0000000000001000 <main>:
    1000: 55                    push   %rbp
    1001: 48 89 e5              mov    %rsp,%rbp
    1004: 8b 05 00 00 00 00     mov    0x0(%rip),%eax
    100a: 5d                    pop    %rbp
    100b: c3                    ret

0000000000001010 <other_func>:
    1010: 55                    push   %rbp
        """

        asm_lines = hasher._extract_function_asm(disassembly, 0x1000, 0x100C, "main")

        # Should extract the push/mov/mov/pop/ret instructions
        assert len(asm_lines) > 0
        assert any("push" in line for line in asm_lines)
        assert any("ret" in line for line in asm_lines)

    def test_extract_function_stops_at_next_function(self, hasher):
        """Test that extraction stops at next function."""
        disassembly = """
0000000000001000 <func_a>:
    1000: 55                    push   %rbp
    1001: 48 89 e5              mov    %rsp,%rbp
    1004: c3                    ret

0000000000001005 <func_b>:
    1005: 55                    push   %rbp
    1006: 48 89 e5              mov    %rsp,%rbp
        """

        asm_lines = hasher._extract_function_asm(disassembly, 0x1000, 0x1005, "func_a")

        # Should not include func_b instructions
        assert not any("1005" in line for line in asm_lines)

    def test_extract_function_with_no_content(self, hasher):
        """Test extraction when function not found."""
        disassembly = "no function content"

        asm_lines = hasher._extract_function_asm(disassembly, 0x1000, 0x2000, "nonexistent")

        # Should return empty list
        assert len(asm_lines) == 0


class TestComputeFingerprints:
    """Test fingerprint computation (requires actual binary access)."""

    @pytest.mark.requires_tools
    async def test_compute_fingerprints_returns_dict(self, hasher, sample_binary):
        """Test that compute_fingerprints returns function fingerprints."""
        hasher._extract_function_info = AsyncMock(
            return_value={"main": {"address": 0x1000, "size": 2}}
        )
        hasher._get_disassembly = AsyncMock(return_value="1000 <main>:\n1000: 90 nop\n1001: c3 ret")
        result = await hasher.compute_fingerprints(sample_binary)

        assert result.status == "success"
        assert isinstance(result.fingerprints, dict)

    @pytest.mark.requires_tools
    async def test_compute_fingerprints_hashes_consistent(self, hasher, sample_binary):
        """Test that fingerprints are consistent for same binary."""
        hasher._extract_function_info = AsyncMock(
            return_value={"main": {"address": 0x1000, "size": 2}}
        )
        hasher._get_disassembly = AsyncMock(return_value="1000 <main>:\n1000: 90 nop\n1001: c3 ret")
        fps1 = await hasher.compute_fingerprints(sample_binary)
        fps2 = await hasher.compute_fingerprints(sample_binary)

        # Should produce identical fingerprints on second run
        assert fps1 == fps2

    @pytest.mark.requires_tools
    async def test_compute_fingerprints_handles_missing_file(self, hasher):
        """Test that missing file returns empty dict gracefully."""
        result = await hasher.compute_fingerprints("/nonexistent/binary")

        assert result.status == "file_not_found"
        assert result.fingerprints == {}


class TestFingerprintMatching:
    """Test matching fingerprints between binaries."""

    def test_identical_fingerprints_match_perfectly(self):
        """Test that identical fingerprints score 1.0."""
        from baldrick.binutils.matcher import BinaryMatcher

        target = {"main": "hash1", "foo": "hash2", "bar": "hash3"}
        candidate = {"main": "hash1", "foo": "hash2", "bar": "hash3"}

        score = BinaryMatcher.score_match(target, candidate)
        assert score == 1.0

    def test_no_common_functions_score_zero(self):
        """Test that no matching functions score 0.0."""
        from baldrick.binutils.matcher import BinaryMatcher

        target = {"main": "hash1", "foo": "hash2"}
        candidate = {"other": "hash3", "baz": "hash4"}

        score = BinaryMatcher.score_match(target, candidate)
        assert score == 0.0

    def test_partial_match_scores_correctly(self):
        """Test partial matches score between 0 and 1."""
        from baldrick.binutils.matcher import BinaryMatcher

        target = {"main": "hash1", "foo": "hash2", "bar": "hash3"}
        candidate = {"main": "hash1", "foo": "hash2", "other": "hash4"}

        # 2 matching functions out of max(3, 3)
        score = BinaryMatcher.score_match(target, candidate)
        assert score == pytest.approx(2.0 / 3.0)

    def test_empty_fingerprints_score_zero(self):
        """Test that empty fingerprints score 0.0."""
        from baldrick.binutils.matcher import BinaryMatcher

        target = {}
        candidate = {"main": "hash1"}

        score = BinaryMatcher.score_match(target, candidate)
        assert score == 0.0

    def test_score_matches_both_empty_zero(self):
        """Test that both empty fingerprints score 0.0."""
        from baldrick.binutils.matcher import BinaryMatcher

        target = {}
        candidate = {}

        score = BinaryMatcher.score_match(target, candidate)
        assert score == 0.0

    def test_function_reordering_doesnt_affect_score(self):
        """Test that function order doesn't matter."""
        from baldrick.binutils.matcher import BinaryMatcher

        target = {"main": "hash1", "foo": "hash2", "bar": "hash3"}
        candidate = {"bar": "hash3", "main": "hash1", "foo": "hash2"}

        score = BinaryMatcher.score_match(target, candidate)
        assert score == 1.0

    def test_score_handles_subset_correctly(self):
        """Test scoring when one set is subset of other."""
        from baldrick.binutils.matcher import BinaryMatcher

        # Target has more functions
        target = {"main": "hash1", "foo": "hash2", "bar": "hash3", "extra": "hash4"}
        # Candidate has subset
        candidate = {"main": "hash1", "foo": "hash2"}

        # 2 matching out of max(4, 2) = 4
        score = BinaryMatcher.score_match(target, candidate)
        assert score == pytest.approx(2.0 / 4.0)
