"""Scoring engine: total score + reasons with evidence_refs (deterministic, reproducible)."""

from oss_sensor.models import (
    EvidenceBundle,
    EvidenceRef,
    Reason,
    ScoreResult,
)


# Weights per feature type (rules-only; reproducible)
WEIGHTS = {
    "alloc_math": 3.0,
    "bounds_check": 2.5,
    "parsing": 2.0,
    "privilege_check": 2.5,
    "binary_strings_added": 0.5,
    "binary_symbols_changed": 1.0,
    "log_template_new": 0.8,
    "log_binary_correlation": 1.2,
}


def score_diff(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
) -> ScoreResult:
    """
    Compute total score and reasons from evidence bundle.
    Every reason cites evidence_refs (artifact IDs / stable IDs).
    Deterministic and reproducible.
    """
    total = 0.0
    reasons: list[Reason] = []

    # Source features
    for sf in evidence_bundle.source_features:
        w = WEIGHTS.get(sf.feature_type, 1.0)
        total += w
        reasons.append(
            Reason(
                reason=f"Source feature: {sf.feature_type} in {sf.file_path}",
                score_contribution=w,
                evidence_refs=[
                    EvidenceRef(ref_type="diff_hunk", artifact_id=None, stable_id=sf.hunk_id)
                ],
            )
        )

    # Binary diff pairs (symbol/function changes)
    for bd in evidence_bundle.binary_diff_pairs:
        w = WEIGHTS.get("binary_symbols_changed", 1.0)
        total += w
        reasons.append(
            Reason(
                reason=f"Binary symbol change: {bd.from_function} -> {bd.to_function}",
                score_contribution=w,
                evidence_refs=[
                    EvidenceRef(
                        ref_type="binary_function",
                        artifact_id=None,
                        stable_id=bd.to_function or bd.from_function,
                    )
                ],
            )
        )

    # Log–binary correlation
    for tpl_id, _ in evidence_bundle.log_to_binary_matches:
        w = WEIGHTS.get("log_binary_correlation", 1.2)
        total += w
        reasons.append(
            Reason(
                reason=f"Log template correlated to binary: {tpl_id}",
                score_contribution=w,
                evidence_refs=[
                    EvidenceRef(ref_type="log_template", artifact_id=None, stable_id=tpl_id)
                ],
            )
        )

    return ScoreResult(
        total_score=round(total, 2),
        reasons=reasons,
        diff_id=diff_id,
    )
