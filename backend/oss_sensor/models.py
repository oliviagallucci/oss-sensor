"""Data models for builds, artifacts, diffs, evidence, and queue."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --- Build & artifact identity ---


class ArtifactKind(str, Enum):
    SOURCE = "source"
    BINARY = "binary"
    LOG = "log"


class ArtifactMeta(BaseModel):
    """Metadata for an ingested artifact; stored with artifact_id reference."""

    artifact_id: str
    build_id: str
    component: str
    kind: ArtifactKind
    path: str
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    storage_mode: str = "derived_features_only"


# --- Source diff & features ---


class DiffHunk(BaseModel):
    """A single hunk from source diff with file and line range."""

    file_path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str]
    hunk_id: str = ""


class SourceFeature(BaseModel):
    """Deterministic feature extracted from source (alloc math, bounds, parsing, privilege)."""

    feature_type: str  # e.g. "alloc_math", "bounds_check", "parsing", "privilege_check"
    description: str
    hunk_id: str
    file_path: str
    line_range: tuple[int, int]
    snippet: str = ""


# --- Binary features ---


class BinaryFeature(BaseModel):
    """Extracted binary evidence: strings, imports, symbols, ObjC metadata."""

    feature_type: str  # "strings", "imports", "symbols", "objc_metadata"
    value: str | list[str]
    address: str | None = None
    source_file: str | None = None  # when matched to source


class BinaryDiffStub(BaseModel):
    """Stub for binary diff: match by name/address; interface for future Diaphora."""

    from_function: str
    to_function: str
    from_address: str | None = None
    to_address: str | None = None
    similarity_note: str = ""


# --- Log correlation ---


class LogTemplate(BaseModel):
    """Extracted log message template (subsystem/category + format)."""

    template_id: str
    subsystem: str
    category: str
    format_string: str
    sample_messages: list[str] = Field(default_factory=list)


# --- Evidence bundle (all refs use artifact IDs or stable IDs) ---


class EvidenceRef(BaseModel):
    """Reference to a stored artifact or evidence piece; all reports cite these."""

    ref_type: str  # "diff_hunk", "string", "symbol", "log_template", "binary_function"
    artifact_id: str | None = None
    stable_id: str  # e.g. hunk_id, string_hash, symbol_name, template_id


class EvidenceBundle(BaseModel):
    """Bundle of evidence for a diff item; all IDs are stable and citable."""

    diff_hunks: list[DiffHunk] = Field(default_factory=list)
    source_features: list[SourceFeature] = Field(default_factory=list)
    binary_features_from: list[BinaryFeature] = Field(default_factory=list)
    binary_features_to: list[BinaryFeature] = Field(default_factory=list)
    binary_diff_pairs: list[BinaryDiffStub] = Field(default_factory=list)
    log_templates: list[LogTemplate] = Field(default_factory=list)
    log_to_binary_matches: list[tuple[str, str]] = Field(default_factory=list)  # template_id, string_id


# --- Scoring ---


class Reason(BaseModel):
    """One reason contributing to score; must cite evidence."""

    reason: str
    score_contribution: float
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class ScoreResult(BaseModel):
    """Output of scoring engine: total score + reasons with evidence refs."""

    total_score: float
    reasons: list[Reason] = Field(default_factory=list)
    diff_id: str


# --- Queue & triage ---


class TriageState(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DENIED = "denied"
    IN_PROGRESS = "in_progress"


# --- Reports (schemas for agent / rules output) ---


class TriageReport(BaseModel):
    """Explain score with citations to evidence IDs only."""

    diff_id: str
    summary: str
    score_explanation: str
    citations: list[EvidenceRef] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class ReverseContextReport(BaseModel):
    """Map binary evidence to source chunks when possible."""

    diff_id: str
    anchor_strings: list[str] = Field(default_factory=list)
    probable_entry_points: list[str] = Field(default_factory=list)
    oss_context_snippets: list[dict[str, Any]] = Field(default_factory=list)  # file, lines, snippet
    call_path_hints: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class VulnHypothesis(BaseModel):
    """Single testable hypothesis (no exploit chains)."""

    statement: str
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    test_approach: str = ""


class VulnHypotheses(BaseModel):
    """List of testable hypotheses for a diff."""

    diff_id: str
    hypotheses: list[VulnHypothesis] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class FuzzPlan(BaseModel):
    """Fuzz plan: target surface + harness sketch + seeds + success metrics."""

    diff_id: str
    target_surface: str  # e.g. syscall handler, XPC service, parser
    harness_sketch: str
    input_model: str  # what fields/messages matter
    seed_strategy: str  # strings-derived, log-derived, etc.
    success_metrics: list[str] = Field(default_factory=list)  # crash buckets, sanitizer, coverage
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class TelemetryRecommendation(BaseModel):
    """Single recommendation: what to log/alert on + correlations."""

    recommendation: str
    subsystem_category: str = ""
    correlation: str = ""
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class TelemetryRecommendations(BaseModel):
    """Telemetry recommendations for a diff."""

    diff_id: str
    recommendations: list[TelemetryRecommendation] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# --- API DTOs ---


class QueueItem(BaseModel):
    """Ranked queue item for API/UI."""

    id: str
    diff_id: str
    build_from: str
    build_to: str
    component: str
    score: float
    state: TriageState
    notes: str = ""
    created_at: datetime | None = None


class DiffDetail(BaseModel):
    """Full diff detail for API/UI."""

    id: str
    build_from: str
    build_to: str
    component: str
    evidence_bundle: EvidenceBundle
    score_result: ScoreResult | None = None
    state: TriageState = TriageState.PENDING
    notes: str = ""
