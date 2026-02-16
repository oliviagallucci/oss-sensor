"""Report generators: Triage, ReverseContext, VulnHypotheses, FuzzPlan, Telemetry (rules + optional LLM)."""

from oss_sensor.reports.generator import (
    generate_triage_report,
    generate_reverse_context_report,
    generate_vuln_hypotheses,
    generate_fuzz_plan,
    generate_telemetry_recommendations,
)

__all__ = [
    "generate_triage_report",
    "generate_reverse_context_report",
    "generate_vuln_hypotheses",
    "generate_fuzz_plan",
    "generate_telemetry_recommendations",
]
