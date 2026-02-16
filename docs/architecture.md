# OSS-Sensor Architecture

## Overview

OSS-Sensor is a local-first platform that operationalizes **Apple partial open source**, **binaries**, and **unified logs** into a **prioritized vulnerability research queue**. The mental model is: **diff → hypothesis → harness** with tight evidence provenance and minimal hallucination risk.

## Components

### 1. CLI

- **ingest-source** — Ingest OSS for a build/component (tarball or repo path). Stores path and file list; features are extracted at diff time.
- **ingest-binary** — Ingest Mach-O(s); runs deterministic extraction (strings, imports, symbols, ObjC metadata stub).
- **ingest-logs** — Ingest logarchive/crash dir; extracts message templates (subsystem/category + format).
- **diff** — Compute diff between two builds for a component: source hunks + features, binary diff stub, log correlation. Persists an **evidence bundle** and creates a queue item (diff record).
- **score** — Run the scoring engine on a diff; store total score and reasons (each with `evidence_refs`).
- **report** — Generate all report types (triage, reverse context, vuln hypotheses, fuzz plan, telemetry); optionally enrich with LLM when configured.

### 2. Deterministic analyzers

- **Source diff** — Unified diff hunks between two source trees; feature extraction (alloc math, bounds checks, parsing, privilege checks) from hunk content. All outputs have stable IDs (e.g. `hunk_id`).
- **Binary features** — Strings, imports, symbols, ObjC metadata (stub). Stored per artifact.
- **Binary diff** — Stub: match by symbol/function name (and address if present). Interface designed for future Diaphora integration.
- **Log correlation** — Extract log templates; match template/sample strings to binary string table. Produces `(template_id, string)` pairs for evidence.

### 3. Scoring engine

- Input: `EvidenceBundle` (hunks, source features, binary features/pairs, log templates, log–binary matches).
- Output: **ScoreResult** — `total_score`, `reasons[]`, each reason with `evidence_refs[]` pointing to diff hunks, strings, symbols, or log template IDs.
- Deterministic and reproducible; no LLM required.

### 4. Report schemas (agent output)

All reports **cite artifact IDs / stable IDs** only; no free-text speculation without evidence refs.

- **TriageReport** — Explains score with citations.
- **ReverseContextReport** — Anchor strings, probable entry points, OSS context snippets, call path hints; all with `evidence_refs`.
- **VulnHypotheses** — Testable hypotheses (e.g. “size from input influences allocation”); no exploit chains.
- **FuzzPlan** — Target surface, harness sketch, input model, seed strategy, success metrics; `evidence_refs` for traceability.
- **TelemetryRecommendations** — What to log/alert on; correlations; `evidence_refs`.

### 5. API (FastAPI)

- **GET /queue** — Ranked queue; optional filters: component, state, min_score, build_from, build_to.
- **GET /diff/{id}** — Full diff detail: evidence bundle, score result, state, notes.
- **POST /diff/{id}/triage** — Update state and notes.
- **GET /artifacts/{id}** — Artifact metadata (and optional content path when `full_source_internal`).
- **GET /reports/{diff_id}** — All reports for a diff.

### 6. UI (React)

- **Queue view** — Table of queue items; filter by component, score, build range, state; link to diff detail.
- **Diff detail view** — Evidence bundle (hunks, reasons with evidence_refs), reports (triage, hypotheses, fuzz plan, telemetry), triage state/notes.

### 7. License-aware storage

- **derived_features_only** — Only store extracted features (hunks, strings, symbols, templates); no raw source or binary content.
- **full_source_internal** — Store full source/code when allowed (internal use only). Controlled by `STORAGE_MODE` env.

### 8. LLM (optional, pluggable)

- When `LLM_PROVIDER` and credentials are not set, the pipeline runs **rules-only** (no LLM).
- When set, a provider can enrich triage, fuzz plan, reverse context, hypotheses, telemetry. Enrichment must only cite existing `evidence_refs`; no inventing artifact IDs.

## Data model

- **Build** — Identifier (e.g. B1, B2).
- **Artifact** — Stored per (build_id, component, kind). Kinds: source, binary, log. Holds path and `features_json` (and optionally `content_path` in full_source_internal).
- **Diff** — (build_from, build_to, component). Holds `evidence_bundle_json`, `score_result_json`, state, notes.
- **Report** — Stored per (diff_id, report_type). Payload is the report schema JSON.
- **Evidence refs** — Always `ref_type` + `artifact_id?` + `stable_id` (e.g. hunk_id, symbol name, template_id).

## Demo

Synthetic fixtures under `demo/fixtures/`:

- **source_b1 / source_b2** — Two C files: B1 has allocation without overflow check; B2 adds a bounds check. Used to demonstrate source diff + alloc_math/bounds_check features.
- **binary_b1 / binary_b2** — Fake Mach-O (magic + strings). B2 includes a string that appears in logs.
- **logs_b1 / logs_b2** — Text logs; B2 includes a line matching the binary string so log–binary correlation fires.

End-to-end: run `make demo` (ingest both builds, diff, score, report), then open the UI and inspect the ranked queue and diff detail with evidence and reports.

## 10-minute quickstart

See [README](../README.md): install backend + frontend deps, run `make demo`, then `make serve-api` and `make serve-frontend` (or use Docker Compose). Open http://localhost:3000 for the queue and diff views.
