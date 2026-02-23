"""Tests for LLM provider selection and enrichment helpers (no live API calls)."""

import pytest
from oss_sensor.config import Settings
from oss_sensor.llm import get_llm_provider, NoOpLLM
from oss_sensor.models import (
    EvidenceBundle,
    TriageReport,
    ScoreResult,
    Reason,
    EvidenceRef,
)


def test_get_llm_provider_returns_noop_when_provider_empty() -> None:
    s = Settings(llm_provider="", llm_api_key="")
    p = get_llm_provider(s)
    assert isinstance(p, NoOpLLM)


def test_get_llm_provider_returns_noop_when_key_empty() -> None:
    s = Settings(llm_provider="openai", llm_api_key="")
    # Without OPENAI_API_KEY or LLM_API_KEY, should get NoOp
    s.openai_api_key = ""
    p = get_llm_provider(s)
    assert isinstance(p, NoOpLLM)


def test_noop_llm_returns_base_triage_unchanged() -> None:
    base = TriageReport(
        diff_id="1",
        summary="Score 5.0 from 2 reasons.",
        score_explanation="[1] alloc_math (evidence: [h1])",
        citations=[],
    )
    result = NoOpLLM().enrich_triage(
        "1",
        ScoreResult(total_score=5.0, reasons=[Reason(reason="alloc_math", score_contribution=3.0, evidence_refs=[])], diff_id="1"),
        EvidenceBundle(),
        base,
    )
    assert result.summary == base.summary
    assert result.diff_id == "1"


def test_noop_llm_returns_base_fuzz_plan_unchanged() -> None:
    from oss_sensor.models import FuzzPlan

    base = FuzzPlan(
        diff_id="1",
        target_surface="Parser",
        harness_sketch="Minimal harness",
        input_model="Fields",
        seed_strategy="Seeds from binary",
    )
    result = NoOpLLM().enrich_fuzz_plan("1", EvidenceBundle(), base)
    assert result.target_surface == base.target_surface
    assert result.diff_id == "1"


def test_valid_evidence_refs_from_bundle() -> None:
    from oss_sensor.llm_impl import _valid_evidence_refs, _refs_to_instruction

    bundle = EvidenceBundle(
        diff_hunks=[],
        source_features=[],
    )
    refs = _valid_evidence_refs(bundle)
    assert refs == []
    instr = _refs_to_instruction(refs)
    assert "no evidence refs" in instr.lower() or "only these refs" in instr.lower() or "do not invent" in instr.lower()

    from oss_sensor.models import DiffHunk

    hunk = DiffHunk(
        file_path="a.c",
        old_start=1,
        old_count=1,
        new_start=1,
        new_count=1,
        lines=["+ line"],
        hunk_id="h1",
    )
    bundle2 = EvidenceBundle(diff_hunks=[hunk])
    refs2 = _valid_evidence_refs(bundle2)
    assert len(refs2) == 1
    assert refs2[0]["ref_type"] == "diff_hunk"
    assert refs2[0]["stable_id"] == "h1"


def test_parse_triage_uses_base_on_invalid_json() -> None:
    from oss_sensor.llm_impl import _parse_triage

    base = TriageReport(diff_id="1", summary="Base", score_explanation="Base explanation", citations=[])
    # Valid dict
    data = {
        "diff_id": "1",
        "summary": "Enriched summary",
        "score_explanation": "Enriched explanation",
        "citations": [{"ref_type": "diff_hunk", "stable_id": "h1"}],
    }
    out = _parse_triage(data, base)
    assert out.summary == "Enriched summary"
    assert len(out.citations) == 1
    assert out.citations[0].stable_id == "h1"
