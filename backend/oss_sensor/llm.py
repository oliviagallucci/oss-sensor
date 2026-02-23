"""Optional LLM provider: pluggable; when unset, pipeline runs rules-only."""

from abc import ABC, abstractmethod
from typing import Any

from oss_sensor.config import Settings
from oss_sensor.models import (
    EvidenceBundle,
    ScoreResult,
    TriageReport,
    ReverseContextReport,
    VulnHypotheses,
    FuzzPlan,
    TelemetryRecommendations,
)


class LLMProvider(ABC):
    """Abstract LLM provider; implement for OpenAI, Anthropic, etc."""

    @abstractmethod
    def enrich_triage(
        self,
        diff_id: str,
        score_result: ScoreResult,
        evidence_bundle: EvidenceBundle,
        base_report: TriageReport,
    ) -> TriageReport:
        """Enrich triage report with LLM; must only cite evidence_refs from bundle."""
        ...

    @abstractmethod
    def enrich_fuzz_plan(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_plan: FuzzPlan,
    ) -> FuzzPlan:
        """Enrich fuzz plan; must cite only existing evidence_refs."""
        ...
    
    def enrich_reverse_context(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_report: ReverseContextReport,
    ) -> ReverseContextReport:
        """Optional: enrich reverse context. Default returns base."""
        return base_report

    def enrich_hypotheses(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base: VulnHypotheses,
    ) -> VulnHypotheses:
        """Optional: add hypotheses. Default returns base."""
        return base

    def enrich_telemetry(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base: TelemetryRecommendations,
    ) -> TelemetryRecommendations:
        """Optional: add recommendations. Default returns base."""
        return base


class NoOpLLM(LLMProvider):
    """No LLM: return base reports unchanged (rules-only)."""

    def enrich_triage(
        self,
        diff_id: str,
        score_result: ScoreResult,
        evidence_bundle: EvidenceBundle,
        base_report: TriageReport,
    ) -> TriageReport:
        return base_report

    def enrich_fuzz_plan(
        self,
        diff_id: str,
        evidence_bundle: EvidenceBundle,
        base_plan: FuzzPlan,
    ) -> FuzzPlan:
        return base_plan


def get_llm_provider(settings: Settings | None = None) -> LLMProvider:
    """Return configured LLM provider or NoOp (rules-only)."""
    s = settings or Settings()
    provider = (s.llm_provider or "").strip().lower()
    if not provider:
        return NoOpLLM()
    # Prefer provider-specific key if set
    key = s.get_llm_api_key()
    if not key:
        return NoOpLLM()
    if provider == "openai":
        from oss_sensor.llm_impl import create_openai_enrichment
        impl = create_openai_enrichment(s)
        return impl if impl else NoOpLLM()
    if provider == "anthropic":
        from oss_sensor.llm_impl import create_anthropic_enrichment
        impl = create_anthropic_enrichment(s)
        return impl if impl else NoOpLLM()
    return NoOpLLM()
