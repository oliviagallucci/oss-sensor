"""FastAPI app: queue, diff, triage, artifacts, reports."""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from oss_sensor.config import Settings
from oss_sensor.storage import Storage
from oss_sensor.models import TriageState, EvidenceBundle, ScoreResult


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.settings = Settings()
    app.state.storage = Storage(app.state.settings)
    await app.state.storage.init_db()
    yield
    # shutdown if needed
    pass


app = FastAPI(
    title="OSS-Sensor",
    description="Apple OSS + binaries + logs → prioritized vulnerability research queue",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/queue")
async def get_queue(
    component: str | None = None,
    state: str | None = None,
    min_score: float | None = None,
    build_from: str | None = None,
    build_to: str | None = None,
) -> list[dict[str, Any]]:
    """Ranked queue with optional filters."""
    storage: Storage = app.state.storage
    triage_state = TriageState(state) if state else None
    return await storage.get_queue(
        component=component,
        state=triage_state,
        min_score=min_score,
        build_from=build_from,
        build_to=build_to,
    )


@app.get("/diff/{diff_id}")
async def get_diff(diff_id: int) -> dict[str, Any]:
    """Full diff detail: evidence bundle, score, state, notes."""
    storage: Storage = app.state.storage
    row = await storage.get_diff(diff_id)
    if not row:
        raise HTTPException(status_code=404, detail="Diff not found")
    evidence = EvidenceBundle.model_validate_json(row.evidence_bundle_json) if row.evidence_bundle_json else EvidenceBundle()
    score_result = ScoreResult.model_validate_json(row.score_result_json) if row.score_result_json else None
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


@app.post("/diff/{diff_id}/triage")
async def update_triage(
    diff_id: int,
    state: str,
    notes: str = "",
) -> dict[str, str]:
    """Update triage state and notes."""
    storage: Storage = app.state.storage
    try:
        triage_state = TriageState(state)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid state: {state}")
    ok = await storage.update_diff_triage(diff_id, triage_state, notes)
    if not ok:
        raise HTTPException(status_code=404, detail="Diff not found")
    return {"status": "updated", "diff_id": str(diff_id)}


@app.get("/artifacts/{artifact_id}")
async def get_artifact(artifact_id: str) -> dict[str, Any]:
    """Artifact metadata (and optional content path when full_source_internal)."""
    storage: Storage = app.state.storage
    meta = await storage.get_artifact(artifact_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return meta.model_dump()


@app.get("/reports/{diff_id}")
async def get_reports(diff_id: int) -> dict[str, Any]:
    """All reports for a diff: triage, reverse_context, vuln_hypotheses, fuzz_plan, telemetry."""
    storage: Storage = app.state.storage
    row = await storage.get_diff(diff_id)
    if not row:
        raise HTTPException(status_code=404, detail="Diff not found")
    return await storage.get_reports(diff_id)
