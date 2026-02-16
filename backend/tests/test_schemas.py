"""Schema validation tests: TriageReport, FuzzPlan, VulnHypotheses, etc."""

import pytest
from datetime import datetime
from oss_sensor.models import (
    TriageReport,
    ReverseContextReport,
    VulnHypothesis,
    VulnHypotheses,
    FuzzPlan,
    TelemetryRecommendation,
    TelemetryRecommendations,
    EvidenceRef,
)


def test_triage_report_schema() -> None:
    r = TriageReport(
        diff_id="1",
        summary="Score 3.0 from 1 reason.",
        score_explanation="alloc_math in parser.c",
        citations=[EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id="h1")],
    )
    assert r.diff_id == "1"
    assert r.generated_at is not None
    r.model_dump()  # no validation error


def test_fuzz_plan_schema() -> None:
    p = FuzzPlan(
        diff_id="1",
        target_surface="Parser",
        harness_sketch="Feed stdin.",
        input_model="Count + payload.",
        seed_strategy="Strings from binary.",
        success_metrics=["crash", "coverage"],
        evidence_refs=[EvidenceRef(ref_type="string", artifact_id="a1", stable_id="s1")],
    )
    assert p.diff_id == "1"
    p.model_dump()


def test_vuln_hypotheses_schema() -> None:
    h = VulnHypotheses(
        diff_id="1",
        hypotheses=[
            VulnHypothesis(
                statement="Size from input influences allocation.",
                evidence_refs=[EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id="h1")],
                test_approach="Fuzz count.",
            )
        ],
    )
    assert len(h.hypotheses) == 1
    assert h.hypotheses[0].statement.startswith("Size")
    h.model_dump()


def test_telemetry_recommendations_schema() -> None:
    t = TelemetryRecommendations(
        diff_id="1",
        recommendations=[
            TelemetryRecommendation(
                recommendation="Monitor template X",
                subsystem_category="default/default",
                correlation="Correlate with entitlements.",
                evidence_refs=[],
            )
        ],
    )
    assert len(t.recommendations) == 1
    t.model_dump()


def test_reverse_context_report_schema() -> None:
    r = ReverseContextReport(
        diff_id="1",
        anchor_strings=["malloc", "parse_buffer"],
        probable_entry_points=["_main"],
        oss_context_snippets=[{"file": "parser.c", "lines": (1, 10), "snippet": "code"}],
        call_path_hints=[],
        evidence_refs=[],
    )
    r.model_dump()
