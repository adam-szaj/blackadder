"""Tests for CLI output formatters.

Tests plain text and JSON formatting for analysis results.
"""

import json
import pytest
from blackadder.cli.formatters import (
    PlainTextFormatter,
    JSONFormatter,
    OutputFormatter,
)
from blackadder.register_analyzer import RegisterInterpretation


@pytest.fixture
def sample_interpretations():
    """Create sample register interpretations for testing."""
    return {
        "rax": RegisterInterpretation(
            register_name="rax",
            raw_value="0x10001000",
            pointer_type="heap",
            confidence=0.85,
            region_info="Heap allocation (0x10000000-0x10100000)",
            notes=["Points to heap region"],
        ),
        "rbx": RegisterInterpretation(
            register_name="rbx",
            raw_value="0x400a1c",
            pointer_type="code",
            resolved_symbol="main",
            confidence=0.95,
            notes=["Resolved to symbol: main"],
        ),
        "rsp": RegisterInterpretation(
            register_name="rsp",
            raw_value="0x7ffff0000",
            pointer_type="stack",
            confidence=0.90,
            region_info="Stack region: 0x7ffff0000-0x7ffffffff000",
            notes=["Points to stack region"],
        ),
        "r10": RegisterInterpretation(
            register_name="r10",
            raw_value="0x0",
            pointer_type="unknown",
            confidence=0.1,
            notes=["Address not found in process memory map"],
        ),
    }


class TestPlainTextFormatter:
    """Test plain text output formatting."""

    def test_format_single_interpretation(self):
        """Test formatting a single register interpretation."""
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x10001000",
            pointer_type="heap",
            confidence=0.85,
            region_info="Heap allocation",
            notes=["Test note"],
        )

        result = PlainTextFormatter.format_register_interpretation(interp)

        assert "rax" in result.lower()
        assert "0x10001000" in result
        assert "heap" in result
        assert "85" in result  # Confidence percentage
        assert "Heap allocation" in result
        assert "Test note" in result

    def test_format_all_registers(self, sample_interpretations):
        """Test formatting all register interpretations."""
        result = PlainTextFormatter.format_all_registers(sample_interpretations)

        assert "Register Analysis Results" in result
        assert "CODE Pointers:" in result or "code" in result.lower()
        assert "HEAP Pointers:" in result or "heap" in result.lower()
        assert "STACK Pointers:" in result or "stack" in result.lower()
        assert "main" in result

    def test_format_all_registers_empty(self):
        """Test formatting empty register dict."""
        result = PlainTextFormatter.format_all_registers({})
        assert "No registers" in result

    def test_format_interesting_registers(self, sample_interpretations):
        """Test filtering and formatting interesting registers."""
        result = PlainTextFormatter.format_interesting_registers(
            sample_interpretations
        )

        assert "Interesting Registers" in result
        # Should include heap, code, stack but not the unknown r10 (confidence 0.1)
        assert "rax" in result
        assert "rbx" in result
        assert "rsp" in result


class TestJSONFormatter:
    """Test JSON output formatting."""

    def test_format_single_interpretation(self):
        """Test formatting a single interpretation as JSON."""
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x1000",
            pointer_type="heap",
            confidence=0.85,
        )

        result = JSONFormatter.format_register_interpretation(interp)
        data = json.loads(result)

        assert data["register_name"] == "rax"
        assert data["raw_value"] == "0x1000"
        assert data["pointer_type"] == "heap"
        assert data["confidence"] == 0.85

    def test_format_all_registers(self, sample_interpretations):
        """Test formatting all registers as JSON."""
        result = JSONFormatter.format_all_registers(sample_interpretations)
        data = json.loads(result)

        assert "registers" in data
        assert "summary" in data
        assert data["summary"]["total"] == 4
        assert "by_type" in data["summary"]
        assert data["summary"]["by_type"]["heap"] == 1
        assert data["summary"]["by_type"]["code"] == 1
        assert data["summary"]["by_type"]["stack"] == 1

    def test_format_all_registers_empty(self):
        """Test formatting empty registers as JSON."""
        result = JSONFormatter.format_all_registers({})
        data = json.loads(result)

        assert data["registers"] == {}
        assert data["summary"]["total"] == 0

    def test_format_interesting_registers(self, sample_interpretations):
        """Test formatting interesting registers as JSON."""
        result = JSONFormatter.format_interesting_registers(sample_interpretations)
        data = json.loads(result)

        # Should have 3 interesting registers (heap, code, stack)
        assert data["summary"]["interesting_count"] == 3
        assert "rax" in data["registers"]
        assert "rbx" in data["registers"]
        assert "rsp" in data["registers"]
        # r10 should not be included (confidence too low)
        assert "r10" not in data["registers"]


class TestOutputFormatter:
    """Test unified output formatter."""

    def test_plain_text_mode(self, sample_interpretations):
        """Test formatter in plain text mode."""
        formatter = OutputFormatter(json_output=False)
        result = formatter.format_all_registers(sample_interpretations)

        # Should be plain text, not JSON
        assert not result.strip().startswith("{")
        assert "Register Analysis Results" in result

    def test_json_mode(self, sample_interpretations):
        """Test formatter in JSON mode."""
        formatter = OutputFormatter(json_output=True)
        result = formatter.format_all_registers(sample_interpretations)

        # Should be valid JSON
        data = json.loads(result)
        assert "registers" in data
        assert "summary" in data

    def test_format_single_plain_text(self):
        """Test formatting single interpretation in plain text."""
        formatter = OutputFormatter(json_output=False)
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x1000",
            pointer_type="code",
            resolved_symbol="main",
            confidence=0.95,
        )

        result = formatter.format_register_interpretation(interp)

        assert "rax" in result.lower()
        assert "0x1000" in result
        assert "main" in result

    def test_format_single_json(self):
        """Test formatting single interpretation in JSON."""
        formatter = OutputFormatter(json_output=True)
        interp = RegisterInterpretation(
            register_name="rax",
            raw_value="0x1000",
            pointer_type="code",
            confidence=0.95,
        )

        result = formatter.format_register_interpretation(interp)
        data = json.loads(result)

        assert data["register_name"] == "rax"
        assert data["pointer_type"] == "code"

    def test_format_interesting_plain_text(self, sample_interpretations):
        """Test formatting interesting registers in plain text."""
        formatter = OutputFormatter(json_output=False)
        result = formatter.format_interesting_registers(sample_interpretations)

        assert "Interesting Registers" in result
        assert not result.strip().startswith("{")

    def test_format_interesting_json(self, sample_interpretations):
        """Test formatting interesting registers in JSON."""
        formatter = OutputFormatter(json_output=True)
        result = formatter.format_interesting_registers(sample_interpretations)

        data = json.loads(result)
        assert "registers" in data
        assert "summary" in data
