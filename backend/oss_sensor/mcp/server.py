"""MCP server implementation: tools for queue, diff, reports, pipeline, r2, Frida."""

import asyncio
import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from oss_sensor.config import Settings
from oss_sensor.storage import Storage
from oss_sensor.models import (
    ArtifactKind,
    EvidenceBundle,
    ScoreResult,
    TriageState,
    LogTemplate,
)
from oss_sensor.analyzers import (
    extract_source_diff,
    extract_binary_features,
    compute_binary_diff_stub,
    extract_log_templates,
    correlate_log_to_binary,
)
from oss_sensor.analyzers.binary_features import features_to_list
from oss_sensor.scoring import score_diff
from oss_sensor.reports import (
    generate_triage_report,
    generate_reverse_context_report,
    generate_vuln_hypotheses,
    generate_fuzz_plan,
    generate_telemetry_recommendations,
)
from oss_sensor.llm import get_llm_provider

mcp = FastMCP(
    "OSS-Sensor RE",
    instructions="Tools for the OSS-Sensor reverse-engineering pipeline: queue, diffs, reports, pipeline steps, radare2 analysis, and Frida tracing.",
)


def _run_async(coro):
    return asyncio.run(coro)


# --- Queue, diff, reports ---


@mcp.tool()
def get_queue(
    component: str | None = None,
    state: str | None = None,
    min_score: float | None = None,
    build_from: str | None = None,
    build_to: str | None = None,
) -> str:
    """Return the ranked vulnerability research queue. Optional filters: component, state (pending|accepted|denied|in_progress), min_score, build_from, build_to."""
    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        triage = TriageState(state) if state else None
        return await storage.get_queue(
            component=component,
            state=triage,
            min_score=min_score,
            build_from=build_from,
            build_to=build_to,
        )
    result = _run_async(_do())
    return json.dumps(result, indent=2)


@mcp.tool()
def get_diff(diff_id: int) -> str:
    """Return full diff detail by diff_id: evidence bundle, score result, state, notes."""
    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        row = await storage.get_diff(diff_id)
        if not row:
            return None
        evidence = (
            EvidenceBundle.model_validate_json(row.evidence_bundle_json)
            if row.evidence_bundle_json
            else EvidenceBundle()
        )
        score_result = (
            ScoreResult.model_validate_json(row.score_result_json)
            if row.score_result_json
            else None
        )
        return {
            "id": str(row.id),
            "build_from": row.build_from,
            "build_to": row.build_to,
            "component": row.component,
            "evidence_bundle": evidence.model_dump(),
            "score_result": score_result.model_dump() if score_result else None,
            "state": row.state or TriageState.PENDING.value,
            "notes": row.notes or "",
        }
    result = _run_async(_do())
    if result is None:
        return json.dumps({"error": "Diff not found", "diff_id": diff_id})
    return json.dumps(result, indent=2)


@mcp.tool()
def get_reports(diff_id: int) -> str:
    """Return all reports for a diff_id: triage, reverse_context, vuln_hypotheses, fuzz_plan, telemetry."""
    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        row = await storage.get_diff(diff_id)
        if not row:
            return None
        return await storage.get_reports(diff_id)
    result = _run_async(_do())
    if result is None:
        return json.dumps({"error": "Diff not found", "diff_id": diff_id})
    return json.dumps(result, indent=2)


# --- Pipeline step ---


@mcp.tool()
def run_pipeline_step(
    step: str,
    build_id: str | None = None,
    component: str | None = None,
    path: str | None = None,
    from_build: str | None = None,
    to_build: str | None = None,
    diff_id: int | None = None,
    with_llm: bool = False,
) -> str:
    """Run one pipeline step. step: ingest_source | ingest_binary | ingest_logs | diff | score | report. For ingest_*: build_id, component, path. For diff: from_build, to_build, component. For score/report: diff_id. with_llm: only for report."""
    async def _ingest_source():
        if not build_id or not component or not path:
            return {"error": "ingest_source requires build_id, component, path"}
        path_obj = Path(path)
        if not path_obj.exists():
            return {"error": f"Path not found: {path}"}
        features = {"path": str(path_obj.resolve()), "files": []}
        if path_obj.is_dir():
            features["files"] = [str(p.relative_to(path_obj)) for p in path_obj.rglob("*") if p.is_file()][:5000]
        storage = Storage(Settings())
        await storage.init_db()
        aid = await storage.store_artifact(
            build_id=build_id,
            component=component,
            kind=ArtifactKind.SOURCE,
            path=str(path_obj.resolve()),
            features_json=features,
        )
        return {"step": "ingest_source", "artifact_id": aid}

    async def _ingest_binary():
        if not build_id or not component or not path:
            return {"error": "ingest_binary requires build_id, component, path"}
        path_obj = Path(path)
        if not path_obj.exists():
            return {"error": f"Path not found: {path}"}
        features = extract_binary_features(path_obj)
        storage = Storage(Settings())
        await storage.init_db()
        aid = await storage.store_artifact(
            build_id=build_id,
            component=component,
            kind=ArtifactKind.BINARY,
            path=str(path_obj.resolve()),
            features_json=features,
        )
        return {"step": "ingest_binary", "artifact_id": aid}

    async def _ingest_logs():
        if not build_id or not path:
            return {"error": "ingest_logs requires build_id, path"}
        path_obj = Path(path)
        if not path_obj.exists():
            return {"error": f"Path not found: {path}"}
        templates = extract_log_templates(path_obj)
        features = [t.model_dump() for t in templates]
        storage = Storage(Settings())
        await storage.init_db()
        aid = await storage.store_artifact(
            build_id=build_id,
            component="logs",
            kind=ArtifactKind.LOG,
            path=str(path_obj.resolve()),
            features_json=features,
        )
        return {"step": "ingest_logs", "artifact_id": aid}

    async def _diff():
        if not from_build or not to_build or not component:
            return {"error": "diff requires from_build, to_build, component"}
        storage = Storage(Settings())
        await storage.init_db()
        from_src = await storage.list_artifacts(build_id=from_build, component=component, kind=ArtifactKind.SOURCE)
        to_src = await storage.list_artifacts(build_id=to_build, component=component, kind=ArtifactKind.SOURCE)
        from_path = Path(from_src[0].path) if from_src else None
        to_path = Path(to_src[0].path) if to_src else None
        hunks, source_features = [], []
        if from_path and to_path and from_path.exists() and to_path.exists():
            hunks, source_features = extract_source_diff(from_path, to_path, component)
        from_bin = await storage.list_artifacts(build_id=from_build, component=component, kind=ArtifactKind.BINARY)
        to_bin = await storage.list_artifacts(build_id=to_build, component=component, kind=ArtifactKind.BINARY)
        bin_features_from, bin_features_to = [], []
        if from_bin:
            feats = await storage.get_artifact_features(from_bin[0].artifact_id)
            if feats and isinstance(feats, dict):
                bin_features_from = features_to_list(feats, from_bin[0].artifact_id)
        if to_bin:
            feats = await storage.get_artifact_features(to_bin[0].artifact_id)
            if feats and isinstance(feats, dict):
                bin_features_to = features_to_list(feats, to_bin[0].artifact_id)
        binary_diff_pairs = compute_binary_diff_stub(bin_features_from, bin_features_to)
        from_logs = await storage.list_artifacts(build_id=from_build, component="logs", kind=ArtifactKind.LOG)
        to_logs = await storage.list_artifacts(build_id=to_build, component="logs", kind=ArtifactKind.LOG)
        log_templates, log_to_binary_matches = [], []
        if to_logs:
            tpl_feats = await storage.get_artifact_features(to_logs[0].artifact_id)
            if tpl_feats and isinstance(tpl_feats, list):
                log_templates = [LogTemplate(**x) for x in tpl_feats if isinstance(x, dict)]
            binary_strings = [f.value for f in bin_features_to if f.feature_type == "strings" and isinstance(f.value, str)]
            log_to_binary_matches = correlate_log_to_binary(log_templates, binary_strings)
        bundle = EvidenceBundle(
            diff_hunks=hunks,
            source_features=source_features,
            binary_features_from=bin_features_from,
            binary_features_to=bin_features_to,
            binary_diff_pairs=binary_diff_pairs,
            log_templates=log_templates,
            log_to_binary_matches=log_to_binary_matches,
        )
        did = await storage.create_diff(from_build, to_build, component, bundle)
        return {"step": "diff", "diff_id": did}

    async def _score():
        if diff_id is None:
            return {"error": "score requires diff_id"}
        storage = Storage(Settings())
        await storage.init_db()
        row = await storage.get_diff(diff_id)
        if not row or not row.evidence_bundle_json:
            return {"error": "Diff not found or no evidence bundle"}
        bundle = EvidenceBundle.model_validate_json(row.evidence_bundle_json)
        result = score_diff(str(diff_id), bundle)
        await storage.set_diff_score(diff_id, result)
        return {"step": "score", "diff_id": diff_id, "total_score": result.total_score, "reasons_count": len(result.reasons)}

    async def _report():
        if diff_id is None:
            return {"error": "report requires diff_id"}
        storage = Storage(Settings())
        await storage.init_db()
        row = await storage.get_diff(diff_id)
        if not row:
            return {"error": "Diff not found"}
        bundle = (
            EvidenceBundle.model_validate_json(row.evidence_bundle_json)
            if row.evidence_bundle_json
            else EvidenceBundle()
        )
        score_result = (
            ScoreResult.model_validate_json(row.score_result_json)
            if row.score_result_json
            else ScoreResult(total_score=0, reasons=[], diff_id=str(diff_id))
        )
        settings = Settings()
        llm = get_llm_provider(settings) if with_llm else get_llm_provider(Settings())
        triage = generate_triage_report(str(diff_id), score_result, bundle, settings)
        triage = llm.enrich_triage(str(diff_id), score_result, bundle, triage)
        await storage.store_report(diff_id, "triage", triage)
        rev = generate_reverse_context_report(str(diff_id), bundle, settings)
        rev = llm.enrich_reverse_context(str(diff_id), bundle, rev)
        await storage.store_report(diff_id, "reverse_context", rev)
        hyp = generate_vuln_hypotheses(str(diff_id), bundle, score_result, settings)
        hyp = llm.enrich_hypotheses(str(diff_id), bundle, hyp)
        await storage.store_report(diff_id, "vuln_hypotheses", hyp)
        fuzz = generate_fuzz_plan(str(diff_id), bundle, settings)
        fuzz = llm.enrich_fuzz_plan(str(diff_id), bundle, fuzz)
        await storage.store_report(diff_id, "fuzz_plan", fuzz)
        tele = generate_telemetry_recommendations(str(diff_id), bundle, settings)
        tele = llm.enrich_telemetry(str(diff_id), bundle, tele)
        await storage.store_report(diff_id, "telemetry", tele)
        return {"step": "report", "diff_id": diff_id}

    steps = {
        "ingest_source": _ingest_source,
        "ingest_binary": _ingest_binary,
        "ingest_logs": _ingest_logs,
        "diff": _diff,
        "score": _score,
        "report": _report,
    }
    if step not in steps:
        return json.dumps({"error": f"Unknown step: {step}. Use one of: {list(steps.keys())}"})
    try:
        result = _run_async(steps[step]())
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "step": step})


# --- radare2 ---


@mcp.tool()
def r2_analyze(
    binary_path: str,
    action: str,
    target: str | None = None,
) -> str:
    """Run radare2 analysis on a binary. action: symbols | imports | function_list | disasm_at | function_summary. For disasm_at and function_summary pass target (address or symbol name). Returns JSON or error string."""
    try:
        from oss_sensor.analyzers.r2_analysis import r2_analyze as _r2_analyze
        out = _r2_analyze(binary_path, action, target)
        if isinstance(out, dict):
            return json.dumps(out, indent=2)
        return out
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def r2_extract_features(binary_path: str) -> str:
    """Extract binary features (symbols, imports, strings) via radare2. Returns dict compatible with EvidenceBundle binary features."""
    try:
        from oss_sensor.analyzers.r2_analysis import r2_extract_features as _extract
        out = _extract(binary_path)
        return json.dumps(out, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Frida ---


@mcp.tool()
def frida_run_script(
    script_content: str,
    target: str,
    script_path: str | None = None,
    timeout_seconds: int = 30,
    spawn: bool = False,
) -> str:
    """Run a Frida script against target (process name or PID). script_path: optional path to script file. spawn: spawn process by name instead of attach. Requires target to be running (or use spawn=True)."""
    try:
        from oss_sensor.reverse.frida_runner import frida_run_script as _run
        out = _run(script_content, target, script_path=script_path, timeout_seconds=timeout_seconds, spawn=spawn)
        return json.dumps(out, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "output": "", "error": str(e)})


@mcp.tool()
def frida_trace_export(
    target: str,
    symbols: str,
    module_name: str | None = None,
    timeout_seconds: int = 15,
    dry_run: bool = False,
    spawn: bool = False,
) -> str:
    """Generate and optionally run a Frida trace for given symbols (e.g. from ReverseContextReport probable_entry_points). symbols: JSON array of symbol names. dry_run: only return generated script. Target must be running unless spawn=True."""
    try:
        import json as _json
        sym_list = _json.loads(symbols) if isinstance(symbols, str) else list(symbols)
        from oss_sensor.reverse.frida_runner import frida_run_trace
        out = frida_run_trace(
            target,
            sym_list,
            module_name=module_name,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
            spawn=spawn,
        )
        return json.dumps(out, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "output": "", "error": str(e)})


def run() -> None:
    """Run the MCP server (stdio transport for Cursor)."""
    mcp.run(transport="stdio")
