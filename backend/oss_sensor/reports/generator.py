"""Generate all report types from evidence; rules-only by default, optional LLM when configured."""

from datetime import datetime
from typing import Any

from oss_sensor.config import Settings
from oss_sensor.models import (
    EvidenceBundle,
    EvidenceRef,
    ScoreResult,
    TriageReport,
    ReverseContextReport,
    VulnHypothesis,
    VulnHypotheses,
    FuzzPlan,
    TelemetryRecommendation,
    TelemetryRecommendations,
)


def _evidence_refs_from_bundle(bundle: EvidenceBundle) -> list[EvidenceRef]:
    refs: list[EvidenceRef] = []
    for h in bundle.diff_hunks:
        refs.append(EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id=h.hunk_id))
    for s in bundle.binary_features_from + bundle.binary_features_to:
        if isinstance(s.value, str):
            refs.append(EvidenceRef(ref_type="string", artifact_id=None, stable_id=s.value[:64]))
    for t in bundle.log_templates:
        refs.append(EvidenceRef(ref_type="log_template", artifact_id=None, stable_id=t.template_id))
    return refs


def generate_triage_report(
    diff_id: str,
    score_result: ScoreResult,
    evidence_bundle: EvidenceBundle,
    settings: Settings | None = None,
) -> TriageReport:
    """Explain score with citations to evidence IDs only (no free-text speculation)."""
    settings = settings or Settings()
    citations: list[EvidenceRef] = []
    for r in score_result.reasons:
        citations.extend(r.evidence_refs)
    summary = f"Score {score_result.total_score} from {len(score_result.reasons)} reasons."
    score_explanation = " ".join(
        f"[{i+1}] {reasons.reason} (evidence: {[e.stable_id for e in reasons.evidence_refs]})"
        for i, reasons in enumerate(score_result.reasons)
    )
    return TriageReport(
        diff_id=diff_id,
        summary=summary,
        score_explanation=score_explanation,
        citations=citations,
    )


def generate_reverse_context_report(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    settings: Settings | None = None,
) -> ReverseContextReport:
    """Map binary evidence to source chunks; anchor strings and entry points from evidence."""
    settings = settings or Settings()
    anchor_strings: list[str] = []
    for b in evidence_bundle.binary_features_from + evidence_bundle.binary_features_to:
        if b.feature_type == "strings" and isinstance(b.value, str) and len(b.value) > 8:
            anchor_strings.append(b.value[:80])
    probable_entry_points = [
        s.value for s in evidence_bundle.binary_features_to
        if s.feature_type == "symbols" and isinstance(s.value, str)
    ][:10]
    oss_snippets: list[dict[str, Any]] = []
    for h in evidence_bundle.diff_hunks:
        oss_snippets.append({
            "file": h.file_path,
            "lines": (h.old_start, h.old_start + h.old_count),
            "snippet": "\n".join(h.lines[:15]),
        })
    refs = _evidence_refs_from_bundle(evidence_bundle)
    return ReverseContextReport(
        diff_id=diff_id,
        anchor_strings=anchor_strings[:20],
        probable_entry_points=probable_entry_points,
        oss_context_snippets=oss_snippets,
        call_path_hints=[],
        evidence_refs=refs[:30],
    )


def generate_vuln_hypotheses(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    score_result: ScoreResult | None = None,
    settings: Settings | None = None,
) -> VulnHypotheses:
    """Produce testable hypotheses from features (no exploit chains)."""
    settings = settings or Settings()
    hypotheses: list[VulnHypothesis] = []
    for sf in evidence_bundle.source_features:
        if sf.feature_type == "alloc_math":
            hypotheses.append(
                VulnHypothesis(
                    statement="Size derived from external input may influence allocation; check for integer overflow.",
                    evidence_refs=[EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id=sf.hunk_id)],
                    test_approach="Trace allocation size from input; fuzz with large/small counts.",
                )
            )
        elif sf.feature_type == "bounds_check":
            hypotheses.append(
                VulnHypothesis(
                    statement="Bounds check added or removed; prior OOB read/write possible.",
                    evidence_refs=[EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id=sf.hunk_id)],
                    test_approach="Compare with/without check; fuzz boundary values.",
                )
            )
        elif sf.feature_type == "parsing":
            hypotheses.append(
                VulnHypothesis(
                    statement="Parsing/deserialization change; malformed input may reach new code paths.",
                    evidence_refs=[EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id=sf.hunk_id)],
                    test_approach="Structure-aware fuzzing; capture valid messages as seeds.",
                )
            )
        elif sf.feature_type == "privilege_check":
            hypotheses.append(
                VulnHypothesis(
                    statement="Privilege/entitlement gate moved or added; check for TOCTOU or bypass.",
                    evidence_refs=[EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id=sf.hunk_id)],
                    test_approach="Trace entitlement checks; test with reduced privileges.",
                )
            )
    return VulnHypotheses(
        diff_id=diff_id,
        hypotheses=hypotheses,
    )


def generate_fuzz_plan(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    settings: Settings | None = None,
) -> FuzzPlan:
    """Output fuzz plan: target surface, harness sketch, seed strategy, success metrics."""
    settings = settings or Settings()
    target = "Parser/syscall path implied by diff"
    if evidence_bundle.source_features:
        types = {f.feature_type for f in evidence_bundle.source_features}
        if "parsing" in types:
            target = "Parsing/deserialization path"
        elif "alloc_math" in types:
            target = "Allocation/count path"
    harness = "Minimal harness: feed input from stdin or file; link against target binary or library."
    input_model = "Fields/messages that affect size, length, or parsed structure (from diff context)."
    seed_strategy = "Seeds: strings from binary; log-derived parameter examples; captured message templates."
    success_metrics = [
        "Crash bucketing by signature",
        "Sanitizer signals (ASan, UBSan) where applicable",
        "Coverage deltas on changed functions",
    ]
    refs = _evidence_refs_from_bundle(evidence_bundle)[:15]
    return FuzzPlan(
        diff_id=diff_id,
        target_surface=target,
        harness_sketch=harness,
        input_model=input_model,
        seed_strategy=seed_strategy,
        success_metrics=success_metrics,
        evidence_refs=refs,
    )


def generate_telemetry_recommendations(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    settings: Settings | None = None,
) -> TelemetryRecommendations:
    """What to log/alert on and correlations."""
    settings = settings or Settings()
    recs: list[TelemetryRecommendation] = []
    for t in evidence_bundle.log_templates:
        recs.append(
            TelemetryRecommendation(
                recommendation=f"Monitor for log template: {t.format_string[:80]}",
                subsystem_category=f"{t.subsystem}/{t.category}",
                correlation="Correlate with process ancestry and entitlements when this template appears.",
                evidence_refs=[EvidenceRef(ref_type="log_template", artifact_id=None, stable_id=t.template_id)],
            )
        )
    if evidence_bundle.log_to_binary_matches:
        recs.append(
            TelemetryRecommendation(
                recommendation="Alert when XPC/service path for correlated log template is invoked unusually.",
                subsystem_category="xpc",
                correlation="Log–binary correlation suggests entry point; enrich with entitlements.",
                evidence_refs=[
                    EvidenceRef(ref_type="log_template", artifact_id=None, stable_id=tpl_id)
                    for tpl_id, _ in evidence_bundle.log_to_binary_matches[:5]
                ],
            )
        )
    return TelemetryRecommendations(
        diff_id=diff_id,
        recommendations=recs,
    )
