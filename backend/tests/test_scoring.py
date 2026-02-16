"""Unit tests for scoring engine: deterministic, evidence_refs present."""

import pytest
from oss_sensor.models import EvidenceBundle, DiffHunk, SourceFeature, EvidenceRef
from oss_sensor.scoring import score_diff, WEIGHTS


def test_score_empty_bundle() -> None:
    bundle = EvidenceBundle()
    result = score_diff("1", bundle)
    assert result.diff_id == "1"
    assert result.total_score == 0.0
    assert result.reasons == []


def test_score_source_feature_alloc_math() -> None:
    hunk = DiffHunk(
        file_path="parser.c",
        old_start=1,
        old_count=5,
        new_start=1,
        new_count=8,
        lines=["+ if (count > 0 && (count * sizeof(struct entry)) / sizeof(struct entry) != count)"],
        hunk_id="abc123",
    )
    sf = SourceFeature(
        feature_type="alloc_math",
        description="Pattern match: alloc_math",
        hunk_id="abc123",
        file_path="parser.c",
        line_range=(1, 6),
        snippet="malloc(count * sizeof",
    )
    bundle = EvidenceBundle(diff_hunks=[hunk], source_features=[sf])
    result = score_diff("2", bundle)
    assert result.total_score == WEIGHTS["alloc_math"]
    assert len(result.reasons) == 1
    assert result.reasons[0].evidence_refs[0].stable_id == "abc123"
    assert result.reasons[0].evidence_refs[0].ref_type == "diff_hunk"


def test_score_multiple_reasons() -> None:
    sf1 = SourceFeature(
        feature_type="bounds_check",
        description="bounds",
        hunk_id="h1",
        file_path="a.c",
        line_range=(1, 2),
        snippet="if (x >= 0)",
    )
    sf2 = SourceFeature(
        feature_type="parsing",
        description="parse",
        hunk_id="h2",
        file_path="b.c",
        line_range=(1, 2),
        snippet="parse_buffer",
    )
    bundle = EvidenceBundle(source_features=[sf1, sf2])
    result = score_diff("3", bundle)
    assert result.total_score == WEIGHTS["bounds_check"] + WEIGHTS["parsing"]
    assert len(result.reasons) == 2
    ids = {r.evidence_refs[0].stable_id for r in result.reasons}
    assert ids == {"h1", "h2"}


def test_score_reproducible() -> None:
    bundle = EvidenceBundle(
        source_features=[
            SourceFeature(
                feature_type="alloc_math",
                description="desc",
                hunk_id="h1",
                file_path="f",
                line_range=(1, 2),
                snippet="snippet",
            ),
        ]
    )
    r1 = score_diff("1", bundle)
    r2 = score_diff("1", bundle)
    assert r1.total_score == r2.total_score
    assert len(r1.reasons) == len(r2.reasons)
    assert r1.reasons[0].reason == r2.reasons[0].reason
