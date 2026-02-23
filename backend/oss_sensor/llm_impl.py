"""LLM provider implementations: OpenAI and Anthropic. Enrich reports using only allowed evidence_refs."""

import json
import logging
from datetime import datetime
from typing import Any

from oss_sensor.config import Settings
from oss_sensor.models import (
    EvidenceBundle,
    EvidenceRef,
    ScoreResult,
    TriageReport,
    ReverseContextReport,
    VulnHypotheses,
    VulnHypothesis,
    FuzzPlan,
    TelemetryRecommendations,
    TelemetryRecommendation,
)

logger = logging.getLogger(__name__)

# --- Evidence refs: collect all citable refs from bundle for prompt ---


def _valid_evidence_refs(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    """List of allowed evidence refs (ref_type, stable_id, artifact_id?) for inclusion in LLM prompts."""
    refs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for h in bundle.diff_hunks:
        key = ("diff_hunk", h.hunk_id)
        if key not in seen:
            seen.add(key)
            refs.append({"ref_type": "diff_hunk", "stable_id": h.hunk_id, "artifact_id": None})
    for b in bundle.binary_features_from + bundle.binary_features_to:
        if isinstance(b.value, str):
            sid = b.value[:64]
            key = ("string", sid)
            if key not in seen:
                seen.add(key)
                refs.append({"ref_type": "string", "stable_id": sid, "artifact_id": None})
        elif isinstance(b.value, list):
            for v in b.value[:5]:
                if isinstance(v, str):
                    key = ("symbol", v)
                    if key not in seen:
                        seen.add(key)
                        refs.append({"ref_type": "symbol", "stable_id": v, "artifact_id": None})
    for t in bundle.log_templates:
        key = ("log_template", t.template_id)
        if key not in seen:
            seen.add(key)
            refs.append({"ref_type": "log_template", "stable_id": t.template_id, "artifact_id": None})
    for bd in bundle.binary_diff_pairs:
        for name in (bd.from_function, bd.to_function):
            if name and ("binary_function", name) not in seen:
                seen.add(("binary_function", name))
                refs.append({"ref_type": "binary_function", "stable_id": name, "artifact_id": None})
    return refs


def _refs_to_instruction(refs: list[dict[str, Any]]) -> str:
    """Format allowed refs for the system prompt."""
    if not refs:
        return "There are no evidence refs to cite; you may still improve the narrative but do not invent IDs."
    lines = ["When citing evidence, use ONLY these refs (ref_type and stable_id):"]
    for r in refs[:80]:
        lines.append(f"  - ref_type={r['ref_type']!r}, stable_id={r['stable_id']!r}")
    return "\n".join(lines)


def _parse_evidence_refs(obj: list[Any]) -> list[EvidenceRef]:
    """Parse list of dicts into EvidenceRef list; invalid entries skipped."""
    out: list[EvidenceRef] = []
    for x in obj:
        if isinstance(x, dict) and isinstance(x.get("stable_id"), str) and isinstance(x.get("ref_type"), str):
            out.append(
                EvidenceRef(
                    ref_type=str(x["ref_type"]),
                    artifact_id=x.get("artifact_id") if x.get("artifact_id") else None,
                    stable_id=str(x["stable_id"]),
                )
            )
    return out


# --- Prompt builders (system + user) per report type ---


def _prompt_triage(
    diff_id: str,
    score_result: ScoreResult,
    evidence_bundle: EvidenceBundle,
    base_report: TriageReport,
    refs_instruction: str,
) -> tuple[str, str]:
    system = (
        "You are a security triage assistant. Enrich the triage report: clearer summary and score explanation. "
        "Do not invent evidence. " + refs_instruction
    )
    user = (
        f"Diff id: {diff_id}. Score: {score_result.total_score}. "
        f"Reasons: {json.dumps([{'reason': r.reason, 'score_contribution': r.score_contribution} for r in score_result.reasons], indent=2)}\n\n"
        f"Base triage report:\n{base_report.model_dump_json(indent=2)}\n\n"
        "Return a single JSON object with keys: diff_id (string), summary (string), score_explanation (string), "
        "citations (array of objects with ref_type, stable_id, and optional artifact_id). "
        "Improve summary and score_explanation for a human analyst; keep citations only from the allowed list."
    )
    return system, user


def _prompt_reverse_context(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    base_report: ReverseContextReport,
    refs_instruction: str,
) -> tuple[str, str]:
    system = (
        "You are a reverse-engineering assistant. Enrich the reverse context report: "
        "better anchor strings, entry points, and call path hints from the evidence. "
        "Do not invent evidence. " + refs_instruction
    )
    # Truncate snippets for token budget
    dump = base_report.model_dump()
    for s in dump.get("oss_context_snippets", [])[:15]:
        if isinstance(s.get("snippet"), str) and len(s["snippet"]) > 500:
            s["snippet"] = s["snippet"][:500] + "..."
    user = (
        f"Diff id: {diff_id}.\n\n"
        f"Base reverse context report:\n{json.dumps(dump, indent=2)}\n\n"
        "Return a single JSON object with keys: diff_id, anchor_strings (array of strings), "
        "probable_entry_points (array of strings), oss_context_snippets (array of {file, lines, snippet}), "
        "call_path_hints (array of strings), evidence_refs (array of {ref_type, stable_id}). "
        "Only use evidence_refs from the allowed list."
    )
    return system, user


def _prompt_hypotheses(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    base: VulnHypotheses,
    refs_instruction: str,
) -> tuple[str, str]:
    system = (
        "You are a vulnerability research assistant. Enrich the list of testable hypotheses: "
        "sharper statements and test_approach. Do not suggest exploit chains. Do not invent evidence. "
        + refs_instruction
    )
    user = (
        f"Diff id: {diff_id}.\n\n"
        f"Base hypotheses:\n{base.model_dump_json(indent=2)}\n\n"
        "Return a single JSON object with keys: diff_id, hypotheses (array of objects with "
        "statement, evidence_refs (array of {ref_type, stable_id}), test_approach). "
        "Only use evidence_refs from the allowed list. Add or refine hypotheses based on the evidence."
    )
    return system, user


def _prompt_fuzz_plan(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    base_plan: FuzzPlan,
    refs_instruction: str,
) -> tuple[str, str]:
    system = (
        "You are a fuzzing advisor. Enrich the fuzz plan: concrete target_surface, harness_sketch, "
        "input_model, seed_strategy, success_metrics. Do not invent evidence. " + refs_instruction
    )
    user = (
        f"Diff id: {diff_id}.\n\n"
        f"Base fuzz plan:\n{base_plan.model_dump_json(indent=2)}\n\n"
        "Return a single JSON object with keys: diff_id, target_surface, harness_sketch, input_model, "
        "seed_strategy, success_metrics (array of strings), evidence_refs (array of {ref_type, stable_id}). "
        "Make the plan specific to this diff; only cite refs from the allowed list."
    )
    return system, user


def _prompt_telemetry(
    diff_id: str,
    evidence_bundle: EvidenceBundle,
    base: TelemetryRecommendations,
    refs_instruction: str,
) -> tuple[str, str]:
    system = (
        "You are a telemetry advisor. Enrich the telemetry recommendations: "
        "what to log/alert on and correlations. Do not invent evidence. " + refs_instruction
    )
    user = (
        f"Diff id: {diff_id}.\n\n"
        f"Base telemetry recommendations:\n{base.model_dump_json(indent=2)}\n\n"
        "Return a single JSON object with keys: diff_id, recommendations (array of objects with "
        "recommendation, subsystem_category, correlation, evidence_refs). Only use evidence_refs from the allowed list."
    )
    return system, user


# --- Safe parse: fill generated_at and validate ---


def _parse_triage(data: dict[str, Any], base: TriageReport) -> TriageReport:
    citations = _parse_evidence_refs(data.get("citations") or [])
    return TriageReport(
        diff_id=str(data.get("diff_id", base.diff_id)),
        summary=str(data.get("summary", base.summary))[:2000],
        score_explanation=str(data.get("score_explanation", base.score_explanation))[:8000],
        citations=citations,
    )


def _parse_reverse_context(data: dict[str, Any], base: ReverseContextReport) -> ReverseContextReport:
    refs = _parse_evidence_refs(data.get("evidence_refs") or [])
    snippets = data.get("oss_context_snippets")
    if not isinstance(snippets, list):
        snippets = base.oss_context_snippets
    return ReverseContextReport(
        diff_id=str(data.get("diff_id", base.diff_id)),
        anchor_strings=[str(x) for x in (data.get("anchor_strings") or base.anchor_strings)][:50],
        probable_entry_points=[str(x) for x in (data.get("probable_entry_points") or base.probable_entry_points)][:20],
        oss_context_snippets=[x for x in snippets if isinstance(x, dict)][:30],
        call_path_hints=[str(x) for x in (data.get("call_path_hints") or base.call_path_hints)][:20],
        evidence_refs=refs[:50],
    )


def _parse_hypotheses(data: dict[str, Any], base: VulnHypotheses) -> VulnHypotheses:
    raw = data.get("hypotheses") or []
    hypotheses: list[VulnHypothesis] = []
    for h in raw[:20]:
        if isinstance(h, dict) and isinstance(h.get("statement"), str):
            hypotheses.append(
                VulnHypothesis(
                    statement=str(h["statement"])[:1000],
                    evidence_refs=_parse_evidence_refs(h.get("evidence_refs") or []),
                    test_approach=str(h.get("test_approach", ""))[:500],
                )
            )
    return VulnHypotheses(diff_id=str(data.get("diff_id", base.diff_id)), hypotheses=hypotheses)


def _parse_fuzz_plan(data: dict[str, Any], base: FuzzPlan) -> FuzzPlan:
    metrics = data.get("success_metrics")
    if not isinstance(metrics, list):
        metrics = base.success_metrics
    return FuzzPlan(
        diff_id=str(data.get("diff_id", base.diff_id)),
        target_surface=str(data.get("target_surface", base.target_surface))[:500],
        harness_sketch=str(data.get("harness_sketch", base.harness_sketch))[:3000],
        input_model=str(data.get("input_model", base.input_model))[:1500],
        seed_strategy=str(data.get("seed_strategy", base.seed_strategy))[:1000],
        success_metrics=[str(m) for m in metrics][:15],
        evidence_refs=_parse_evidence_refs(data.get("evidence_refs") or []),
    )


def _parse_telemetry(data: dict[str, Any], base: TelemetryRecommendations) -> TelemetryRecommendations:
    raw = data.get("recommendations") or []
    recs: list[TelemetryRecommendation] = []
    for r in raw[:25]:
        if isinstance(r, dict) and isinstance(r.get("recommendation"), str):
            recs.append(
                TelemetryRecommendation(
                    recommendation=str(r["recommendation"])[:500],
                    subsystem_category=str(r.get("subsystem_category", ""))[:100],
                    correlation=str(r.get("correlation", ""))[:300],
                    evidence_refs=_parse_evidence_refs(r.get("evidence_refs") or []),
                )
            )
    return TelemetryRecommendations(diff_id=str(data.get("diff_id", base.diff_id)), recommendations=recs)


# --- Base class for API-calling providers ---


class _BaseLLMImpl:
    """Shared logic: call API, parse JSON, return enriched or base on failure."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.timeout = getattr(settings, "llm_timeout_seconds", 60.0) or 60.0

    def _call(self, system: str, user: str) -> str | None:
        """Return JSON string from LLM, or None on failure. Override in subclass."""
        return None

    def _enrich(self, system: str, user: str, parse_fn: Any, base: Any) -> Any:
        try:
            raw = self._call(system, user)
            if not raw or not raw.strip():
                return base
            # Strip markdown code block if present
            text = raw.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                text = "\n".join(lines)
            data = json.loads(text)
            if isinstance(data, dict):
                return parse_fn(data, base)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            logger.warning("LLM response parse failed, using base report: %s", e)
        return base


# --- OpenAI ---


def _create_openai_provider(settings: Settings) -> "OpenAIProvider | None":
    try:
        from openai import OpenAI
    except ImportError:
        logger.warning("openai package not installed; install with pip install 'oss-sensor[llm]'")
        return None
    key = settings.get_llm_api_key() or getattr(settings, "openai_api_key", "")
    if not key:
        logger.warning("OpenAI API key not set (LLM_API_KEY or OPENAI_API_KEY)")
        return None
    model = (settings.llm_model or "").strip() or "gpt-4o-mini"
    client = OpenAI(api_key=key)
    return OpenAIProvider(settings=settings, client=client, model=model)


class OpenAIProvider(_BaseLLMImpl):
    """Enrich reports using OpenAI Chat Completions (JSON mode)."""

    def __init__(self, settings: Settings, client: Any, model: str):
        super().__init__(settings)
        self.client = client
        self.model = model

    def _call(self, system: str, user: str) -> str | None:
        try:
            r = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                timeout=self.timeout,
            )
            if r.choices and r.choices[0].message.content:
                return r.choices[0].message.content
        except Exception as e:
            logger.warning("OpenAI API call failed: %s", e)
        return None


# --- Anthropic ---


def _create_anthropic_provider(settings: Settings) -> "AnthropicProvider | None":
    try:
        from anthropic import Anthropic
    except ImportError:
        logger.warning("anthropic package not installed; install with pip install 'oss-sensor[llm]'")
        return None
    key = settings.get_llm_api_key() or getattr(settings, "anthropic_api_key", "")
    if not key:
        logger.warning("Anthropic API key not set (LLM_API_KEY or ANTHROPIC_API_KEY)")
        return None
    model = (settings.llm_model or "").strip() or "claude-3-5-sonnet-20241022"
    timeout = getattr(settings, "llm_timeout_seconds", 60.0) or 60.0
    client = Anthropic(api_key=key, timeout=timeout)
    return AnthropicProvider(settings=settings, client=client, model=model)


class AnthropicProvider(_BaseLLMImpl):
    """Enrich reports using Anthropic Messages API (JSON in content)."""

    def __init__(self, settings: Settings, client: Any, model: str):
        super().__init__(settings)
        self.client = client
        self.model = model

    def _call(self, system: str, user: str) -> str | None:
        try:
            r = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            for b in r.content:
                if getattr(b, "type", None) == "text" and getattr(b, "text", None):
                    return b.text
        except Exception as e:
            logger.warning("Anthropic API call failed: %s", e)
        return None


# --- Implement LLMProvider interface for OpenAI ---


class OpenAIEnrichment(OpenAIProvider):
    """OpenAI provider implementing full LLMProvider interface."""

    def enrich_triage(
        self,
        diff_id: str,
        score_result: ScoreResult,
        evidence_bundle: EvidenceBundle,
        base_report: TriageReport,
    ) -> TriageReport:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_triage(diff_id, score_result, evidence_bundle, base_report, refs_instruction)
        return self._enrich(system, user, _parse_triage, base_report)

    def enrich_fuzz_plan(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_plan: FuzzPlan,
    ) -> FuzzPlan:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_fuzz_plan(diff_id, evidence_bundle, base_plan, refs_instruction)
        return self._enrich(system, user, _parse_fuzz_plan, base_plan)

    def enrich_reverse_context(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_report: ReverseContextReport,
    ) -> ReverseContextReport:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_reverse_context(diff_id, evidence_bundle, base_report, refs_instruction)
        return self._enrich(system, user, _parse_reverse_context, base_report)

    def enrich_hypotheses(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base: VulnHypotheses,
    ) -> VulnHypotheses:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_hypotheses(diff_id, evidence_bundle, base, refs_instruction)
        return self._enrich(system, user, _parse_hypotheses, base)

    def enrich_telemetry(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base: TelemetryRecommendations,
    ) -> TelemetryRecommendations:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_telemetry(diff_id, evidence_bundle, base, refs_instruction)
        return self._enrich(system, user, _parse_telemetry, base)


# --- Implement LLMProvider interface for Anthropic ---


class AnthropicEnrichment(AnthropicProvider):
    """Anthropic provider implementing full LLMProvider interface."""

    def enrich_triage(
        self,
        diff_id: str,
        score_result: ScoreResult,
        evidence_bundle: EvidenceBundle,
        base_report: TriageReport,
    ) -> TriageReport:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_triage(diff_id, score_result, evidence_bundle, base_report, refs_instruction)
        return self._enrich(system, user, _parse_triage, base_report)

    def enrich_fuzz_plan(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_plan: FuzzPlan,
    ) -> FuzzPlan:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_fuzz_plan(diff_id, evidence_bundle, base_plan, refs_instruction)
        return self._enrich(system, user, _parse_fuzz_plan, base_plan)

    def enrich_reverse_context(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_report: ReverseContextReport,
    ) -> ReverseContextReport:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_reverse_context(diff_id, evidence_bundle, base_report, refs_instruction)
        return self._enrich(system, user, _parse_reverse_context, base_report)

    def enrich_hypotheses(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base: VulnHypotheses,
    ) -> VulnHypotheses:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_hypotheses(diff_id, evidence_bundle, base, refs_instruction)
        return self._enrich(system, user, _parse_hypotheses, base)

    def enrich_telemetry(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base: TelemetryRecommendations,
    ) -> TelemetryRecommendations:
        refs_instruction = _refs_to_instruction(_valid_evidence_refs(evidence_bundle))
        system, user = _prompt_telemetry(diff_id, evidence_bundle, base, refs_instruction)
        return self._enrich(system, user, _parse_telemetry, base)


def create_openai_enrichment(settings: Settings) -> OpenAIEnrichment | None:
    """Build OpenAI provider if key and package available."""
    p = _create_openai_provider(settings)
    return OpenAIEnrichment(settings=p.settings, client=p.client, model=p.model) if p else None


def create_anthropic_enrichment(settings: Settings) -> AnthropicEnrichment | None:
    """Build Anthropic provider if key and package available."""
    p = _create_anthropic_provider(settings)
    return AnthropicEnrichment(settings=p.settings, client=p.client, model=p.model) if p else None
