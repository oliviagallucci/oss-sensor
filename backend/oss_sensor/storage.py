"""License-aware storage: artifacts, diffs, evidence, queue, reports."""

from datetime import datetime
from pathlib import Path
from typing import Any
import json
import uuid

from sqlalchemy import Column, String, Float, DateTime, Text, Integer
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

from oss_sensor.config import Settings, StorageMode
from oss_sensor.models import (
    ArtifactKind,
    ArtifactMeta,
    EvidenceBundle,
    ScoreResult,
    TriageState,
    TriageReport,
    ReverseContextReport,
    VulnHypotheses,
    FuzzPlan,
    TelemetryRecommendations,
)

Base = declarative_base()


def _json_serial(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


# --- Tables ---


class BuildRow(Base):
    __tablename__ = "builds"
    id = Column(String(64), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ArtifactRow(Base):
    __tablename__ = "artifacts"
    id = Column(String(64), primary_key=True)
    build_id = Column(String(64), nullable=False, index=True)
    component = Column(String(128), nullable=False, index=True)
    kind = Column(String(32), nullable=False)  # source, binary, log
    path = Column(Text, nullable=False)
    ingested_at = Column(DateTime, default=datetime.utcnow)
    # Derived features only (always stored); full content only when storage_mode allows
    features_json = Column(Text, nullable=True)  # JSON of extracted features
    content_path = Column(Text, nullable=True)  # optional path to full content in full_source_internal


class DiffRow(Base):
    __tablename__ = "diffs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    build_from = Column(String(64), nullable=False, index=True)
    build_to = Column(String(64), nullable=False, index=True)
    component = Column(String(128), nullable=False, index=True)
    evidence_bundle_json = Column(Text, nullable=True)
    score_result_json = Column(Text, nullable=True)
    state = Column(String(32), default=TriageState.PENDING.value)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class ReportRow(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    diff_id = Column(Integer, nullable=False, index=True)
    report_type = Column(String(64), nullable=False)  # triage, reverse_context, vuln_hypotheses, fuzz_plan, telemetry
    payload_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# --- Storage service ---


class Storage:
    """License-aware storage; respects storage_mode for what we persist."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self._engine = create_async_engine(
            self.settings.database_url,
            echo=False,
        )
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )
        self._init_done = False

    async def init_db(self) -> None:
        if self._init_done:
            return
        # Ensure data dir exists before SQLite tries to open (path is relative to CWD).
        if "sqlite" in self.settings.database_url:
            data_path = Path("./data")
            data_path.mkdir(parents=True, exist_ok=True)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self._init_done = True

    def _session(self) -> AsyncSession:
        return self._session_factory()

    # --- Builds ---

    async def ensure_build(self, build_id: str) -> None:
        async with self._session() as session:
            from sqlalchemy import select
            r = await session.execute(select(BuildRow).where(BuildRow.id == build_id))
            if r.scalar_one_or_none() is None:
                session.add(BuildRow(id=build_id))
                await session.commit()

    # --- Artifacts ---

    async def store_artifact(
        self,
        build_id: str,
        component: str,
        kind: ArtifactKind,
        path: str,
        features_json: dict | list,
        content_path: str | None = None,
    ) -> str:
        artifact_id = str(uuid.uuid4())
        async with self._session() as session:
            await self.ensure_build(build_id)
            store_content = (
                self.settings.storage_mode == StorageMode.FULL_SOURCE_INTERNAL
                and content_path is not None
            )
            row = ArtifactRow(
                id=artifact_id,
                build_id=build_id,
                component=component,
                kind=kind.value,
                path=path,
                features_json=json.dumps(features_json, default=_json_serial),
                content_path=content_path if store_content else None,
            )
            session.add(row)
            await session.commit()
        return artifact_id

    async def get_artifact(self, artifact_id: str) -> ArtifactMeta | None:
        async with self._session() as session:
            from sqlalchemy import select
            r = await session.execute(select(ArtifactRow).where(ArtifactRow.id == artifact_id))
            row = r.scalar_one_or_none()
        if not row:
            return None
        return ArtifactMeta(
            artifact_id=row.id,
            build_id=row.build_id,
            component=row.component,
            kind=ArtifactKind(row.kind),
            path=row.path,
            ingested_at=row.ingested_at or datetime.utcnow(),
            storage_mode=self.settings.storage_mode.value,
        )

    async def get_artifact_features(self, artifact_id: str) -> dict | list | None:
        """Return stored features JSON for an artifact."""
        async with self._session() as session:
            from sqlalchemy import select
            r = await session.execute(select(ArtifactRow).where(ArtifactRow.id == artifact_id))
            row = r.scalar_one_or_none()
        if not row or not row.features_json:
            return None
        return json.loads(row.features_json)

    async def list_artifacts(
        self,
        build_id: str | None = None,
        component: str | None = None,
        kind: ArtifactKind | None = None,
    ) -> list[ArtifactMeta]:
        async with self._session() as session:
            from sqlalchemy import select
            q = select(ArtifactRow)
            if build_id:
                q = q.where(ArtifactRow.build_id == build_id)
            if component:
                q = q.where(ArtifactRow.component == component)
            if kind:
                q = q.where(ArtifactRow.kind == kind.value)
            r = await session.execute(q)
            rows = r.scalars().all()
        return [
            ArtifactMeta(
                artifact_id=row.id,
                build_id=row.build_id,
                component=row.component,
                kind=ArtifactKind(row.kind),
                path=row.path,
                ingested_at=row.ingested_at or datetime.utcnow(),
                storage_mode=self.settings.storage_mode.value,
            )
            for row in rows
        ]

    # --- Diffs ---

    async def create_diff(
        self,
        build_from: str,
        build_to: str,
        component: str,
        evidence_bundle: EvidenceBundle,
        score_result: ScoreResult | None = None,
    ) -> int:
        async with self._session() as session:
            row = DiffRow(
                build_from=build_from,
                build_to=build_to,
                component=component,
                evidence_bundle_json=evidence_bundle.model_dump_json(),
                score_result_json=score_result.model_dump_json() if score_result else None,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return int(row.id)

    async def get_diff(self, diff_id: int) -> DiffRow | None:
        async with self._session() as session:
            from sqlalchemy import select
            r = await session.execute(select(DiffRow).where(DiffRow.id == diff_id))
            return r.scalar_one_or_none()

    async def update_diff_triage(self, diff_id: int, state: TriageState, notes: str = "") -> bool:
        async with self._session() as session:
            from sqlalchemy import select, update
            r = await session.execute(select(DiffRow).where(DiffRow.id == diff_id))
            row = r.scalar_one_or_none()
            if not row:
                return False
            await session.execute(
                update(DiffRow).where(DiffRow.id == diff_id).values(state=state.value, notes=notes)
            )
            await session.commit()
            return True

    async def set_diff_score(self, diff_id: int, score_result: ScoreResult) -> bool:
        async with self._session() as session:
            from sqlalchemy import update
            await session.execute(
                update(DiffRow)
                .where(DiffRow.id == diff_id)
                .values(score_result_json=score_result.model_dump_json())
            )
            await session.commit()
            return True

    async def list_diffs(
        self,
        build_from: str | None = None,
        build_to: str | None = None,
        component: str | None = None,
        state: TriageState | None = None,
    ) -> list[DiffRow]:
        async with self._session() as session:
            from sqlalchemy import select
            q = select(DiffRow)
            if build_from:
                q = q.where(DiffRow.build_from == build_from)
            if build_to:
                q = q.where(DiffRow.build_to == build_to)
            if component:
                q = q.where(DiffRow.component == component)
            if state:
                q = q.where(DiffRow.state == state.value)
            q = q.order_by(DiffRow.id.desc())
            r = await session.execute(q)
            return list(r.scalars().all())

    # --- Queue (ranked) ---

    async def get_queue(
        self,
        component: str | None = None,
        state: TriageState | None = None,
        min_score: float | None = None,
        build_from: str | None = None,
        build_to: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = await self.list_diffs(
            build_from=build_from,
            build_to=build_to,
            component=component,
            state=state,
        )
        out: list[dict[str, Any]] = []
        for row in rows:
            score = 0.0
            if row.score_result_json:
                sr = ScoreResult.model_validate_json(row.score_result_json)
                score = sr.total_score
            if min_score is not None and score < min_score:
                continue
            out.append({
                "id": str(row.id),
                "diff_id": str(row.id),
                "build_from": row.build_from,
                "build_to": row.build_to,
                "component": row.component,
                "score": score,
                "state": row.state or TriageState.PENDING.value,
                "notes": row.notes or "",
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })
        out.sort(key=lambda x: (-x["score"], x["diff_id"]))
        return out

    # --- Reports ---

    async def store_report(
        self,
        diff_id: int,
        report_type: str,
        payload: TriageReport
        | ReverseContextReport
        | VulnHypotheses
        | FuzzPlan
        | TelemetryRecommendations,
    ) -> int:
        async with self._session() as session:
            row = ReportRow(
                diff_id=diff_id,
                report_type=report_type,
                payload_json=payload.model_dump_json(),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return int(row.id)

    async def get_reports(self, diff_id: int) -> dict[str, Any]:
        async with self._session() as session:
            from sqlalchemy import select
            r = await session.execute(
                select(ReportRow).where(ReportRow.diff_id == diff_id).order_by(ReportRow.id)
            )
            rows = list(r.scalars().all())
        result: dict[str, Any] = {}
        for row in rows:
            result[row.report_type] = json.loads(row.payload_json)
        return result
