"""CLI: ingest-source, ingest-binary, ingest-logs, diff, score, report."""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from oss_sensor.config import Settings
from oss_sensor.storage import Storage
from oss_sensor.models import ArtifactKind, EvidenceBundle, ScoreResult
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

app = typer.Typer(help="OSS-Sensor: Apple OSS + binaries + logs → prioritized vulnerability research queue")
console = Console()


def _run(coro):
    return asyncio.run(coro)


@app.command()
def ingest_source(
    build_id: str = typer.Option(..., "--build-id"),
    component: str = typer.Option(..., "--component"),
    path: str = typer.Argument(..., help="Path to tarball or repo directory"),
) -> None:
    """Ingest OSS source for a build/component."""
    path_obj = Path(path)
    if not path_obj.exists():
        console.print(f"[red]Path not found: {path}[/red]")
        raise typer.Exit(1)
    features = {"path": str(path_obj.resolve()), "files": []}
    if path_obj.is_dir():
        features["files"] = [str(p.relative_to(path_obj)) for p in path_obj.rglob("*") if p.is_file()][:5000]

    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        aid = await storage.store_artifact(
            build_id=build_id,
            component=component,
            kind=ArtifactKind.SOURCE,
            path=str(path_obj.resolve()),
            features_json=features,
        )
        return aid

    aid = _run(_do())
    console.print(f"[green]Ingested source: build={build_id} component={component} artifact_id={aid}[/green]")


@app.command()
def ingest_binary(
    build_id: str = typer.Option(..., "--build-id"),
    component: str = typer.Option(..., "--component"),
    path: str = typer.Argument(..., help="Path to Mach-O file or directory"),
) -> None:
    """Ingest binary (Mach-O) for a build/component."""
    path_obj = Path(path)
    if not path_obj.exists():
        console.print(f"[red]Path not found: {path}[/red]")
        raise typer.Exit(1)
    features = extract_binary_features(path_obj)

    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        aid = await storage.store_artifact(
            build_id=build_id,
            component=component,
            kind=ArtifactKind.BINARY,
            path=str(path_obj.resolve()),
            features_json=features,
        )
        return aid

    aid = _run(_do())
    console.print(f"[green]Ingested binary: build={build_id} component={component} artifact_id={aid}[/green]")


@app.command()
def ingest_logs(
    build_id: str = typer.Option(..., "--build-id"),
    path: str = typer.Argument(..., help="Path to logarchive or crash dir"),
) -> None:
    """Ingest logs for a build."""
    path_obj = Path(path)
    if not path_obj.exists():
        console.print(f"[red]Path not found: {path}[/red]")
        raise typer.Exit(1)
    templates = extract_log_templates(path_obj)
    features = [t.model_dump() for t in templates]

    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        aid = await storage.store_artifact(
            build_id=build_id,
            component="logs",
            kind=ArtifactKind.LOG,
            path=str(path_obj.resolve()),
            features_json=features,
        )
        return aid

    aid = _run(_do())
    console.print(f"[green]Ingested logs: build={build_id} artifact_id={aid}[/green]")


@app.command()
def diff(
    from_build: str = typer.Option(..., "--from"),
    to_build: str = typer.Option(..., "--to"),
    component: str = typer.Option(..., "--component"),
) -> None:
    """Compute diff between two builds for a component."""
    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()

        # Source artifacts (paths)
        from_src = await storage.list_artifacts(build_id=from_build, component=component, kind=ArtifactKind.SOURCE)
        to_src = await storage.list_artifacts(build_id=to_build, component=component, kind=ArtifactKind.SOURCE)
        from_path = Path(from_src[0].path) if from_src else None
        to_path = Path(to_src[0].path) if to_src else None

        hunks: list = []
        source_features: list = []
        if from_path and to_path and from_path.exists() and to_path.exists():
            hunks, source_features = extract_source_diff(from_path, to_path, component)

        # Binary features
        from_bin = await storage.list_artifacts(build_id=from_build, component=component, kind=ArtifactKind.BINARY)
        to_bin = await storage.list_artifacts(build_id=to_build, component=component, kind=ArtifactKind.BINARY)
        bin_features_from: list = []
        bin_features_to: list = []
        if from_bin:
            feats = await storage.get_artifact_features(from_bin[0].artifact_id)
            if feats and isinstance(feats, dict):
                bin_features_from = features_to_list(feats, from_bin[0].artifact_id)
        if to_bin:
            feats = await storage.get_artifact_features(to_bin[0].artifact_id)
            if feats and isinstance(feats, dict):
                bin_features_to = features_to_list(feats, to_bin[0].artifact_id)

        binary_diff_pairs = compute_binary_diff_stub(bin_features_from, bin_features_to)

        # Log templates and correlation
        from_logs = await storage.list_artifacts(build_id=from_build, component="logs", kind=ArtifactKind.LOG)
        to_logs = await storage.list_artifacts(build_id=to_build, component="logs", kind=ArtifactKind.LOG)
        log_templates: list = []
        log_to_binary_matches: list = []
        if to_logs:
            tpl_feats = await storage.get_artifact_features(to_logs[0].artifact_id)
            if tpl_feats and isinstance(tpl_feats, list):
                from oss_sensor.models import LogTemplate
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
        diff_id = await storage.create_diff(from_build, to_build, component, bundle)
        return diff_id

    diff_id = _run(_do())
    console.print(f"[green]Created diff: id={diff_id} from={from_build} to={to_build} component={component}[/green]")


@app.command()
def score(
    diff_id: int = typer.Option(..., "--diff-id"),
) -> None:
    """Score a diff and store result."""
    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        row = await storage.get_diff(diff_id)
        if not row or not row.evidence_bundle_json:
            return None
        from oss_sensor.models import EvidenceBundle
        bundle = EvidenceBundle.model_validate_json(row.evidence_bundle_json)
        result = score_diff(str(diff_id), bundle)
        await storage.set_diff_score(diff_id, result)
        return result

    result = _run(_do())
    if result is None:
        console.print("[red]Diff not found or no evidence bundle.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Score: {result.total_score} (reasons: {len(result.reasons)})[/green]")


@app.command()
def report(
    diff_id: int = typer.Option(..., "--diff-id"),
    with_llm: bool = typer.Option(False, "--with-llm"),
) -> None:
    """Generate reports for a diff (optionally with LLM enrichment)."""
    async def _do():
        settings = Settings()
        storage = Storage(settings)
        await storage.init_db()
        row = await storage.get_diff(diff_id)
        if not row:
            return False
        bundle = (
            __import__("oss_sensor.models", fromlist=["EvidenceBundle"])
            .EvidenceBundle.model_validate_json(row.evidence_bundle_json)
            if row.evidence_bundle_json
            else EvidenceBundle()
        )
        score_result = (
            ScoreResult.model_validate_json(row.score_result_json)
            if row.score_result_json
            else None
        )
        llm = get_llm_provider(settings) if with_llm else get_llm_provider(Settings())

        score_result = score_result or ScoreResult(total_score=0, reasons=[], diff_id=str(diff_id))
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

        return True

    ok = _run(_do())
    if not ok:
        console.print("[red]Diff not found.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Reports generated for diff_id={diff_id}[/green]")


if __name__ == "__main__":
    app()
