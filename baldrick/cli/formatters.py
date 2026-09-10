"""Output formatters for advanced CLI commands.

Provides plain text and JSON formatting for analysis results.
Supports structured output for register analysis, memory analysis, and more.
"""

import json

from baldrick.register_analyzer import RegisterInterpretation


class PlainTextFormatter:
    """Format analysis results as human-readable plain text."""

    @staticmethod
    def format_register_interpretation(interp: RegisterInterpretation) -> str:
        """Format a single register interpretation."""
        lines = [
            f"  Register: {interp.register_name.upper()}",
            f"  Value:    {interp.raw_value}",
            f"  Type:     {interp.pointer_type}",
            f"  Confidence: {interp.confidence:.1%}",
        ]

        if interp.resolved_symbol:
            lines.append(f"  Symbol:   {interp.resolved_symbol}")

        if interp.region_info:
            lines.append(f"  Region:   {interp.region_info}")

        if interp.notes:
            lines.append("  Notes:")
            for note in interp.notes:
                lines.append(f"    - {note}")

        return "\n".join(lines)

    @staticmethod
    def format_all_registers(
        interpretations: dict[str, RegisterInterpretation],
    ) -> str:
        """Format all register interpretations."""
        if not interpretations:
            return "No registers to display."

        lines = ["Register Analysis Results", "=" * 50]

        # Group by pointer type for better readability
        by_type: dict[str, list[str]] = {}
        for reg_name, interp in sorted(interpretations.items()):
            ptr_type = interp.pointer_type
            if ptr_type not in by_type:
                by_type[ptr_type] = []
            by_type[ptr_type].append(
                f"{reg_name:6} -> {interp.raw_value:18} "
                f"[{interp.confidence:.0%}] {interp.resolved_symbol or interp.region_info or '(unknown)'}"
            )

        # Output by type
        type_order: list[str] = ["code", "heap", "stack", "data", "unknown"]
        for output_type in type_order:
            if output_type in by_type:
                lines.append(f"\n{output_type.upper()} Pointers:")
                lines.extend(by_type[output_type])

        return "\n".join(lines)

    @staticmethod
    def format_interesting_registers(
        interpretations: dict[str, RegisterInterpretation],
    ) -> str:
        """Format interesting registers only (excluding zeros and unknowns)."""
        if not interpretations:
            return "No interesting registers found."

        # Filter: exclude unknown pointers with low confidence
        interesting = {
            reg: interp
            for reg, interp in interpretations.items()
            if interp.pointer_type != "unknown" or interp.confidence > 0.5
        }

        if not interesting:
            return "No interesting registers found."

        lines = ["Interesting Registers", "=" * 50]
        for reg_name, interp in sorted(interesting.items()):
            symbol = (
                interp.resolved_symbol
                if interp.resolved_symbol
                else interp.region_info or "(value)"
            )
            lines.append(f"{reg_name:6} = {interp.raw_value:18} ({interp.pointer_type:6}) {symbol}")

        return "\n".join(lines)


class JSONFormatter:
    """Format analysis results as JSON."""

    @staticmethod
    def format_register_interpretation(interp: RegisterInterpretation) -> str:
        """Format a single register interpretation as JSON."""
        data = interp.model_dump()
        return json.dumps(data, indent=2)

    @staticmethod
    def format_all_registers(
        interpretations: dict[str, RegisterInterpretation],
    ) -> str:
        """Format all register interpretations as JSON."""
        data = {
            "registers": {
                reg_name: interp.model_dump() for reg_name, interp in interpretations.items()
            },
            "summary": {
                "total": len(interpretations),
                "by_type": _count_by_type(interpretations),
            },
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def format_interesting_registers(
        interpretations: dict[str, RegisterInterpretation],
    ) -> str:
        """Format interesting registers as JSON."""
        interesting = {
            reg: interp
            for reg, interp in interpretations.items()
            if interp.pointer_type != "unknown" or interp.confidence > 0.5
        }

        data = {
            "registers": {
                reg_name: interp.model_dump() for reg_name, interp in interesting.items()
            },
            "summary": {
                "interesting_count": len(interesting),
                "by_type": _count_by_type(interesting),
            },
        }
        return json.dumps(data, indent=2)


def _count_by_type(interpretations: dict[str, RegisterInterpretation]) -> dict[str, int]:
    """Count registers by pointer type."""
    counts: dict[str, int] = {}
    for interp in interpretations.values():
        ptr_type = interp.pointer_type
        counts[ptr_type] = counts.get(ptr_type, 0) + 1
    return counts


class OutputFormatter:
    """Unified output formatter supporting both plain text and JSON."""

    def __init__(self, json_output: bool = False):
        """Initialize formatter.

        Args:
            json_output: If True, output JSON; if False, plain text
        """
        self.json_output = json_output
        self.plain_formatter = PlainTextFormatter()
        self.json_formatter = JSONFormatter()

    def format_register_interpretation(self, interp: RegisterInterpretation) -> str:
        """Format a single register interpretation."""
        if self.json_output:
            return self.json_formatter.format_register_interpretation(interp)
        return self.plain_formatter.format_register_interpretation(interp)

    def format_all_registers(self, interpretations: dict[str, RegisterInterpretation]) -> str:
        """Format all register interpretations."""
        if self.json_output:
            return self.json_formatter.format_all_registers(interpretations)
        return self.plain_formatter.format_all_registers(interpretations)

    def format_interesting_registers(
        self, interpretations: dict[str, RegisterInterpretation]
    ) -> str:
        """Format interesting registers."""
        if self.json_output:
            return self.json_formatter.format_interesting_registers(interpretations)
        return self.plain_formatter.format_interesting_registers(interpretations)
