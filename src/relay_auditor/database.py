import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


def isoformat_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def duration_ms(started_at: datetime, completed_at: datetime | None) -> int | None:
    if completed_at is None:
        return None
    return max(0, round((completed_at - started_at).total_seconds() * 1000))


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    detector: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_base_url: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "detector": self.detector,
            "status": self.status,
            "verdict": self.verdict,
            "target_base_url": self.target_base_url,
            "model": self.model,
            "started_at": isoformat_utc(self.started_at),
            "completed_at": isoformat_utc(self.completed_at),
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "error_message": self.error_message,
        }


class ManagedEndpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(100), index=True)
    base_url: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(255), index=True)
    protocol: Mapped[str] = mapped_column(String(32), default="openai_chat")
    api_key_env: Mapped[str | None] = mapped_column(String(100), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "protocol": self.protocol,
            "api_key_env": self.api_key_env,
            "enabled": self.enabled,
            "created_at": isoformat_utc(self.created_at),
            "updated_at": isoformat_utc(self.updated_at),
        }


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), index=True)
    detector: Mapped[str] = mapped_column(String(32), index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True, default="active")
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "endpoint_id": self.endpoint_id,
            "detector": self.detector,
            "artifact_id": self.artifact_id,
            "status": self.status,
            "valid_from": isoformat_utc(self.valid_from),
            "expires_at": isoformat_utc(self.expires_at),
            "metadata": self.metadata_json,
            "created_at": isoformat_utc(self.created_at),
        }


class ComparisonBatch(Base):
    __tablename__ = "comparison_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), index=True, default="running")
    total_items: Mapped[int] = mapped_column(Integer)
    completed_items: Mapped[int] = mapped_column(Integer, default=0)
    cells: Mapped[int] = mapped_column(Integer)
    samples: Mapped[int] = mapped_column(Integer)
    concurrency: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "total_items": self.total_items,
            "completed_items": self.completed_items,
            "cells": self.cells,
            "samples": self.samples,
            "concurrency": self.concurrency,
            "created_at": isoformat_utc(self.created_at),
            "completed_at": isoformat_utc(self.completed_at),
        }


class ComparisonRecord(Base):
    __tablename__ = "comparison_records"

    audit_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("comparison_batches.id"), index=True)
    station_name: Mapped[str] = mapped_column(String(80), index=True)
    reference_artifact_id: Mapped[str] = mapped_column(String(36), index=True)
    reference_name: Mapped[str] = mapped_column(String(100))
    reference_model: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "audit_id": self.audit_id,
            "batch_id": self.batch_id,
            "station_name": self.station_name,
            "reference_artifact_id": self.reference_artifact_id,
            "reference_name": self.reference_name,
            "reference_model": self.reference_model,
            "created_at": isoformat_utc(self.created_at),
            "finished_at": isoformat_utc(self.finished_at),
        }


class ComparisonTaskProgress(Base):
    __tablename__ = "comparison_task_progress"

    audit_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), primary_key=True)
    stage: Mapped[str] = mapped_column(String(32), index=True, default="queued")
    done: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def as_dict(self) -> dict[str, object]:
        return {
            "audit_id": self.audit_id,
            "stage": self.stage,
            "done": self.done,
            "total": self.total,
            "errors": self.errors,
            "detail": self.detail,
            "updated_at": isoformat_utc(self.updated_at),
        }


class ComparisonTaskOptions(Base):
    __tablename__ = "comparison_task_options"

    audit_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), primary_key=True)
    priority: Mapped[int] = mapped_column(Integer, default=50, index=True)
    concurrency_mode: Mapped[str] = mapped_column(String(16), default="auto")
    max_concurrency: Mapped[int] = mapped_column(Integer, default=4)
    effective_concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)
    concurrency_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "audit_id": self.audit_id,
            "priority": self.priority,
            "concurrency_mode": self.concurrency_mode,
            "max_concurrency": self.max_concurrency,
            "effective_concurrency": self.effective_concurrency,
            "concurrency_reason": self.concurrency_reason,
        }


class Database:
    def __init__(self, url: str) -> None:
        if url.startswith("sqlite:///") and not url.endswith(":memory:"):
            database_path = Path(url.removeprefix("sqlite:///"))
            database_path.parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def session(self) -> Iterator[Session]:
        with self.sessions() as session:
            yield session

    def create_run(
        self,
        *,
        audit_id: str,
        detector: str,
        target_base_url: str,
        model: str,
        status: str = "running",
    ) -> AuditRun:
        run = AuditRun(
            id=audit_id,
            detector=detector,
            status=status,
            target_base_url=target_base_url,
            model=model,
            started_at=datetime.now(UTC),
        )
        with self.sessions() as session:
            session.add(run)
            session.commit()
        return run

    def update_run_status(
        self,
        audit_id: str,
        *,
        status: str,
        error_message: str | None = None,
        reset_started_at: bool = True,
    ) -> AuditRun:
        with self.sessions() as session:
            run = session.get(AuditRun, audit_id)
            if run is None:
                raise LookupError(f"audit run not found: {audit_id}")
            previous_status = run.status
            run.status = status
            run.error_message = error_message
            if reset_started_at and status == "running" and previous_status in {"queued", "paused"}:
                run.started_at = datetime.now(UTC)
            if status in {"queued", "running", "paused", "canceling"}:
                run.completed_at = None
            session.commit()
            session.refresh(run)
            return run

    def update_run_artifact(
        self,
        audit_id: str,
        *,
        artifact_path: str,
        artifact_sha256: str,
    ) -> AuditRun:
        """Attach partial evidence without changing the task lifecycle state."""

        with self.sessions() as session:
            run = session.get(AuditRun, audit_id)
            if run is None:
                raise LookupError(f"audit run not found: {audit_id}")
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            session.commit()
            session.refresh(run)
            return run

    def finish_run(
        self,
        audit_id: str,
        *,
        status: str,
        verdict: str | None = None,
        artifact_path: str | None = None,
        artifact_sha256: str | None = None,
        error_message: str | None = None,
    ) -> AuditRun:
        with self.sessions() as session:
            run = session.get(AuditRun, audit_id)
            if run is None:
                raise LookupError(f"audit run not found: {audit_id}")
            run.status = status
            run.verdict = verdict
            run.completed_at = datetime.now(UTC)
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            run.error_message = error_message
            session.commit()
            session.refresh(run)
            return run

    def list_runs(self, limit: int = 50) -> list[AuditRun]:
        with self.sessions() as session:
            statement = select(AuditRun).order_by(AuditRun.started_at.desc()).limit(limit)
            return list(session.scalars(statement))

    def get_run(self, audit_id: str) -> AuditRun | None:
        with self.sessions() as session:
            return session.get(AuditRun, audit_id)

    def create_comparison_record(
        self,
        *,
        audit_id: str,
        batch_id: str,
        total_items: int,
        station_name: str,
        reference_artifact_id: str,
        reference_name: str,
        reference_model: str,
        cells: int,
        samples: int,
        concurrency: int,
        priority: int = 50,
        concurrency_mode: str = "fixed",
    ) -> ComparisonRecord:
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(ComparisonBatch, batch_id)
            if batch is None:
                batch = ComparisonBatch(
                    id=batch_id,
                    status="running",
                    total_items=total_items,
                    completed_items=0,
                    cells=cells,
                    samples=samples,
                    concurrency=concurrency,
                    created_at=now,
                )
                session.add(batch)
            record = ComparisonRecord(
                audit_id=audit_id,
                batch_id=batch_id,
                station_name=station_name,
                reference_artifact_id=reference_artifact_id,
                reference_name=reference_name,
                reference_model=reference_model,
                created_at=now,
            )
            session.add(record)
            run = session.get(AuditRun, audit_id)
            session.add(
                ComparisonTaskProgress(
                    audit_id=audit_id,
                    stage="queued" if run and run.status == "queued" else "starting",
                    done=0,
                    total=cells * samples,
                    errors=0,
                    updated_at=now,
                )
            )
            session.add(
                ComparisonTaskOptions(
                    audit_id=audit_id,
                    priority=priority,
                    concurrency_mode=concurrency_mode,
                    max_concurrency=concurrency,
                )
            )
            session.commit()
            session.refresh(record)
            return record

    def create_comparison_batch_queue(
        self,
        *,
        batch_id: str,
        items: list[dict[str, Any]],
        cells: int,
        samples: int,
        concurrency: int,
        concurrency_mode: str,
    ) -> ComparisonBatch:
        """Persist a complete queued comparison batch in one transaction."""

        if not items:
            raise ValueError("comparison batch must contain at least one item")
        now = datetime.now(UTC)
        batch = ComparisonBatch(
            id=batch_id,
            status="running",
            total_items=len(items),
            completed_items=0,
            cells=cells,
            samples=samples,
            concurrency=concurrency,
            created_at=now,
        )
        with self.sessions() as session:
            session.add(batch)
            for item in items:
                audit_id = str(item["audit_id"])
                priority = int(item.get("priority", 50))
                session.add(
                    AuditRun(
                        id=audit_id,
                        detector="one_token_verify",
                        status="queued",
                        target_base_url=str(item["target_base_url"]),
                        model=str(item["model"]),
                        started_at=now,
                    )
                )
                session.add(
                    ComparisonRecord(
                        audit_id=audit_id,
                        batch_id=batch_id,
                        station_name=str(item["station_name"]),
                        reference_artifact_id=str(item["reference_artifact_id"]),
                        reference_name=str(item["reference_name"]),
                        reference_model=str(item["reference_model"]),
                        created_at=now,
                    )
                )
                session.add(
                    ComparisonTaskProgress(
                        audit_id=audit_id,
                        stage="queued",
                        done=0,
                        total=cells * samples,
                        errors=0,
                        detail=f"已进入队列 · 优先级 {priority}",
                        updated_at=now,
                    )
                )
                session.add(
                    ComparisonTaskOptions(
                        audit_id=audit_id,
                        priority=priority,
                        concurrency_mode=concurrency_mode,
                        max_concurrency=concurrency,
                    )
                )
            session.commit()
            session.refresh(batch)
            return batch

    def finish_comparison_record(self, audit_id: str) -> None:
        finished_at = datetime.now(UTC)
        with self.sessions() as session:
            record = session.get(ComparisonRecord, audit_id)
            if record is None:
                return
            result = session.execute(
                update(ComparisonRecord)
                .where(
                    ComparisonRecord.audit_id == audit_id,
                    ComparisonRecord.finished_at.is_(None),
                )
                .values(finished_at=finished_at)
            )
            if result.rowcount != 1:
                session.rollback()
                return
            batch = session.get(ComparisonBatch, record.batch_id)
            if batch is not None:
                completed_items = session.scalar(
                    select(func.count())
                    .select_from(ComparisonRecord)
                    .where(
                        ComparisonRecord.batch_id == record.batch_id,
                        ComparisonRecord.finished_at.is_not(None),
                    )
                )
                batch.completed_items = min(batch.total_items, int(completed_items or 0))
                if batch.completed_items >= batch.total_items and batch.status not in {
                    "canceling",
                    "canceled",
                    "failed",
                    "interrupted",
                }:
                    batch.status = "completed"
                    batch.completed_at = finished_at
            progress = session.get(ComparisonTaskProgress, audit_id)
            run = session.get(AuditRun, audit_id)
            if progress is not None and run is not None:
                progress.stage = run.status
                progress.updated_at = finished_at
            session.commit()

    def update_task_progress(
        self,
        audit_id: str,
        *,
        stage: str,
        done: int | None = None,
        total: int | None = None,
        errors: int | None = None,
        detail: str | None = None,
    ) -> ComparisonTaskProgress | None:
        with self.sessions() as session:
            progress = session.get(ComparisonTaskProgress, audit_id)
            if progress is None:
                return None
            progress.stage = stage
            if done is not None:
                progress.done = done
            if total is not None:
                progress.total = total
            if errors is not None:
                progress.errors = errors
            progress.detail = detail
            progress.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(progress)
            return progress

    def get_task_progress(self, audit_id: str) -> ComparisonTaskProgress | None:
        with self.sessions() as session:
            return session.get(ComparisonTaskProgress, audit_id)

    def get_task_options(self, audit_id: str) -> ComparisonTaskOptions | None:
        with self.sessions() as session:
            return session.get(ComparisonTaskOptions, audit_id)

    def update_task_priority(self, audit_id: str, priority: int) -> ComparisonTaskOptions:
        with self.sessions() as session:
            options = session.get(ComparisonTaskOptions, audit_id)
            if options is None:
                raise LookupError(f"comparison task options not found: {audit_id}")
            options.priority = max(0, min(100, priority))
            session.commit()
            session.refresh(options)
            return options

    def set_task_concurrency(
        self,
        audit_id: str,
        *,
        effective_concurrency: int,
        reason: str,
    ) -> ComparisonTaskOptions:
        with self.sessions() as session:
            options = session.get(ComparisonTaskOptions, audit_id)
            if options is None:
                raise LookupError(f"comparison task options not found: {audit_id}")
            options.effective_concurrency = effective_concurrency
            options.concurrency_reason = reason
            session.commit()
            session.refresh(options)
            return options

    def list_concurrency_observations(
        self,
        target_base_url: str,
        *,
        model: str,
        station_name: str,
        limit: int = 50,
    ) -> list[tuple[AuditRun, ComparisonTaskOptions, ComparisonBatch]]:
        with self.sessions() as session:
            statement = (
                select(AuditRun, ComparisonTaskOptions, ComparisonBatch)
                .join(
                    ComparisonTaskOptions,
                    ComparisonTaskOptions.audit_id == AuditRun.id,
                )
                .join(ComparisonRecord, ComparisonRecord.audit_id == AuditRun.id)
                .join(ComparisonBatch, ComparisonBatch.id == ComparisonRecord.batch_id)
                .where(
                    AuditRun.detector == "one_token_verify",
                    AuditRun.target_base_url == target_base_url,
                    AuditRun.model == model,
                    ComparisonRecord.station_name == station_name,
                    AuditRun.status.in_({"completed", "failed"}),
                    ComparisonTaskOptions.effective_concurrency.is_not(None),
                )
                .order_by(AuditRun.started_at.desc())
                .limit(limit)
            )
            return list(session.execute(statement).all())

    def set_batch_status(self, batch_id: str, status: str) -> ComparisonBatch:
        with self.sessions() as session:
            batch = session.get(ComparisonBatch, batch_id)
            if batch is None:
                raise LookupError(f"comparison batch not found: {batch_id}")
            batch.status = status
            if status in {"completed", "canceled", "failed", "interrupted"}:
                batch.completed_at = datetime.now(UTC)
            elif status in {"running", "pausing", "paused", "canceling"}:
                batch.completed_at = None
            session.commit()
            session.refresh(batch)
            return batch

    def get_comparison_batch(self, batch_id: str) -> ComparisonBatch | None:
        with self.sessions() as session:
            return session.get(ComparisonBatch, batch_id)

    def latest_active_comparison_batch(self) -> ComparisonBatch | None:
        with self.sessions() as session:
            statement = (
                select(ComparisonBatch)
                .where(ComparisonBatch.status.in_({"running", "pausing", "paused", "canceling"}))
                .order_by(ComparisonBatch.created_at.desc())
                .limit(1)
            )
            return session.scalar(statement)

    def interrupt_orphaned_comparison_batches(self) -> int:
        """Mark batches left active across a service restart as non-resumable."""
        now = datetime.now(UTC)
        with self.sessions() as session:
            batches = list(
                session.scalars(
                    select(ComparisonBatch).where(
                        ComparisonBatch.status.in_({"running", "pausing", "paused", "canceling"})
                    )
                )
            )
            for batch in batches:
                batch.status = "interrupted"
                batch.completed_at = now
                records = list(
                    session.scalars(
                        select(ComparisonRecord).where(ComparisonRecord.batch_id == batch.id)
                    )
                )
                for record in records:
                    run = session.get(AuditRun, record.audit_id)
                    if run is not None and run.status in {
                        "queued",
                        "running",
                        "paused",
                        "canceling",
                    }:
                        run.status = "interrupted"
                        run.verdict = "error"
                        run.completed_at = now
                        run.error_message = "本地服务曾重启，临时 API Key 已清除；请重新提交该模型"
                    progress = session.get(ComparisonTaskProgress, record.audit_id)
                    if progress is not None and progress.stage not in {
                        "completed",
                        "failed",
                        "canceled",
                    }:
                        progress.stage = "interrupted"
                        progress.detail = "服务重启后无法恢复临时凭据"
                        progress.updated_at = now
            orphan_runs = list(
                session.scalars(
                    select(AuditRun)
                    .outerjoin(
                        ComparisonRecord,
                        ComparisonRecord.audit_id == AuditRun.id,
                    )
                    .where(
                        AuditRun.detector == "one_token_verify",
                        AuditRun.status.in_({"queued", "running", "paused", "canceling"}),
                        ComparisonRecord.audit_id.is_(None),
                    )
                )
            )
            for run in orphan_runs:
                run.status = "interrupted"
                run.verdict = "error"
                run.completed_at = now
                run.error_message = "任务登记未完整提交；服务已按失败关闭原则中断该孤立任务"
                progress = session.get(ComparisonTaskProgress, run.id)
                if progress is not None:
                    progress.stage = "interrupted"
                    progress.detail = "任务登记不完整，服务重启后已中断"
                    progress.updated_at = now
            session.commit()
            return len(batches) + len(orphan_runs)

    def get_batch_comparison_rows(
        self,
        batch_id: str,
    ) -> list[tuple[AuditRun, ComparisonRecord, ComparisonBatch]]:
        with self.sessions() as session:
            statement = (
                select(AuditRun, ComparisonRecord, ComparisonBatch)
                .join(ComparisonRecord, ComparisonRecord.audit_id == AuditRun.id)
                .join(ComparisonBatch, ComparisonBatch.id == ComparisonRecord.batch_id)
                .outerjoin(
                    ComparisonTaskOptions,
                    ComparisonTaskOptions.audit_id == AuditRun.id,
                )
                .where(ComparisonRecord.batch_id == batch_id)
                .order_by(
                    ComparisonTaskOptions.priority.desc(),
                    ComparisonRecord.created_at.asc(),
                )
            )
            return list(session.execute(statement).all())

    def list_comparison_rows(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        station: str | None = None,
        model: str | None = None,
        verdict: str | None = None,
    ) -> tuple[list[tuple[AuditRun, ComparisonRecord | None, ComparisonBatch | None]], int]:
        with self.sessions() as session:
            lifecycle_statuses = {
                "queued",
                "running",
                "paused",
                "canceling",
                "canceled",
                "interrupted",
            }
            needs_operational_filter = bool(verdict and verdict not in lifecycle_statuses)
            statement = (
                select(AuditRun, ComparisonRecord, ComparisonBatch)
                .outerjoin(ComparisonRecord, ComparisonRecord.audit_id == AuditRun.id)
                .outerjoin(ComparisonBatch, ComparisonBatch.id == ComparisonRecord.batch_id)
                .where(AuditRun.detector == "one_token_verify")
            )
            if station:
                statement = statement.where(
                    or_(
                        ComparisonRecord.station_name.ilike(f"%{station}%"),
                        AuditRun.target_base_url.ilike(f"%{station}%"),
                    )
                )
            if model:
                statement = statement.where(AuditRun.model.ilike(f"%{model}%"))
            if verdict and verdict in lifecycle_statuses:
                statement = statement.where(AuditRun.status == verdict)
            rows = list(session.execute(statement.order_by(AuditRun.started_at.desc())).all())
            total = len(rows)
            # Operational verdicts can only be reconstructed from the evidence
            # artifact. Return every SQL candidate so the API layer can normalize,
            # filter, and paginate without mixing legacy and operational semantics.
            if needs_operational_filter:
                return rows, total
            return rows[offset : offset + limit], total

    def latest_comparison_rows(
        self,
    ) -> list[tuple[AuditRun, ComparisonRecord | None, ComparisonBatch | None]]:
        with self.sessions() as session:
            batch = session.scalar(
                select(ComparisonBatch).order_by(ComparisonBatch.created_at.desc()).limit(1)
            )
            if batch is not None:
                statement = (
                    select(AuditRun, ComparisonRecord, ComparisonBatch)
                    .join(ComparisonRecord, ComparisonRecord.audit_id == AuditRun.id)
                    .join(ComparisonBatch, ComparisonBatch.id == ComparisonRecord.batch_id)
                    .where(ComparisonRecord.batch_id == batch.id)
                    .order_by(AuditRun.started_at.desc())
                )
                return list(session.execute(statement).all())
            statement = (
                select(AuditRun, ComparisonRecord, ComparisonBatch)
                .outerjoin(ComparisonRecord, ComparisonRecord.audit_id == AuditRun.id)
                .outerjoin(ComparisonBatch, ComparisonBatch.id == ComparisonRecord.batch_id)
                .where(
                    AuditRun.detector == "one_token_verify",
                    AuditRun.status == "completed",
                )
                .order_by(AuditRun.started_at.desc())
                .limit(1)
            )
            return list(session.execute(statement).all())

    def create_endpoint(
        self,
        *,
        endpoint_id: str,
        name: str,
        provider: str,
        base_url: str,
        model: str,
        protocol: str,
        api_key_env: str | None,
    ) -> ManagedEndpoint:
        now = datetime.now(UTC)
        endpoint = ManagedEndpoint(
            id=endpoint_id,
            name=name,
            provider=provider,
            base_url=base_url,
            model=model,
            protocol=protocol,
            api_key_env=api_key_env,
            created_at=now,
            updated_at=now,
        )
        with self.sessions() as session:
            session.add(endpoint)
            session.commit()
        return endpoint

    def get_endpoint(self, endpoint_id: str) -> ManagedEndpoint | None:
        with self.sessions() as session:
            return session.get(ManagedEndpoint, endpoint_id)

    def upsert_endpoint(
        self,
        *,
        endpoint_id: str,
        name: str,
        provider: str,
        base_url: str,
        model: str,
        protocol: str,
    ) -> ManagedEndpoint:
        now = datetime.now(UTC)
        with self.sessions() as session:
            endpoint = self.upsert_endpoint_in_session(
                session,
                endpoint_id=endpoint_id,
                name=name,
                provider=provider,
                base_url=base_url,
                model=model,
                protocol=protocol,
                now=now,
            )
            session.commit()
            session.refresh(endpoint)
            return endpoint

    @staticmethod
    def upsert_endpoint_in_session(
        session: Session,
        *,
        endpoint_id: str,
        name: str,
        provider: str,
        base_url: str,
        model: str,
        protocol: str,
        now: datetime,
        reuse_by_connection_identity: bool = True,
    ) -> ManagedEndpoint:
        """Reuse an exact identity without rewriting a name collision's provenance."""

        identity_filters = (
            ManagedEndpoint.provider == provider,
            ManagedEndpoint.base_url == base_url,
            ManagedEndpoint.model == model,
            ManagedEndpoint.protocol == protocol,
        )
        endpoint = (
            session.scalar(select(ManagedEndpoint).where(*identity_filters))
            if reuse_by_connection_identity
            else session.get(ManagedEndpoint, endpoint_id)
        )
        if endpoint is not None:
            if not reuse_by_connection_identity and (
                endpoint.provider != provider
                or endpoint.base_url != base_url
                or endpoint.model != model
                or endpoint.protocol != protocol
            ):
                endpoint = None
            else:
                endpoint.enabled = True
                endpoint.updated_at = now
                return endpoint

        identity_parts = (provider, base_url, model, protocol)
        if not reuse_by_connection_identity:
            identity_parts = (endpoint_id, name, *identity_parts)
        identity = "|".join(identity_parts)
        digest = hashlib.sha256(identity.encode()).hexdigest()
        candidate_name = name
        existing_name = session.scalar(
            select(ManagedEndpoint).where(ManagedEndpoint.name == candidate_name)
        )
        if existing_name is not None:
            for width in (8, 12, 16, 24, 32, 64):
                suffix = f"-{digest[:width]}"
                candidate_name = f"{name[: 100 - len(suffix)]}{suffix}"
                conflict = session.scalar(
                    select(ManagedEndpoint).where(ManagedEndpoint.name == candidate_name)
                )
                if conflict is None:
                    break
            else:  # pragma: no cover - a SHA-256 name collision is not practical
                raise ValueError("cannot allocate a unique endpoint name")

        if session.get(ManagedEndpoint, endpoint_id) is not None:
            endpoint_id = str(uuid5(NAMESPACE_URL, f"relay-auditor:endpoint:{identity}"))
            if session.get(ManagedEndpoint, endpoint_id) is not None:
                raise ValueError("endpoint identity conflicts with an existing endpoint id")

        endpoint = ManagedEndpoint(
            id=endpoint_id,
            name=candidate_name,
            provider=provider,
            base_url=base_url,
            model=model,
            protocol=protocol,
            api_key_env=None,
            enabled=True,
            created_at=now,
            updated_at=now,
        )
        session.add(endpoint)
        return endpoint

    def list_endpoints(self) -> list[ManagedEndpoint]:
        with self.sessions() as session:
            statement = select(ManagedEndpoint).order_by(ManagedEndpoint.created_at.desc())
            return list(session.scalars(statement))

    def create_baseline(
        self,
        *,
        baseline_id: str,
        endpoint_id: str,
        detector: str,
        artifact_id: str,
        valid_from: datetime,
        expires_at: datetime,
        metadata: dict[str, Any],
    ) -> Baseline:
        baseline = Baseline(
            id=baseline_id,
            endpoint_id=endpoint_id,
            detector=detector,
            artifact_id=artifact_id,
            status="active",
            valid_from=valid_from,
            expires_at=expires_at,
            metadata_json=metadata,
            created_at=datetime.now(UTC),
        )
        with self.sessions() as session:
            session.execute(
                update(Baseline)
                .where(
                    Baseline.endpoint_id == endpoint_id,
                    Baseline.detector == detector,
                    Baseline.status == "active",
                )
                .values(status="superseded")
            )
            session.add(baseline)
            session.commit()
        return baseline

    def list_baselines(self, endpoint_id: str | None = None) -> list[Baseline]:
        with self.sessions() as session:
            session.execute(
                update(Baseline)
                .where(Baseline.status == "active", Baseline.expires_at < datetime.now(UTC))
                .values(status="expired")
            )
            session.commit()
            statement = select(Baseline)
            if endpoint_id:
                statement = statement.where(Baseline.endpoint_id == endpoint_id)
            statement = statement.order_by(Baseline.created_at.desc())
            return list(session.scalars(statement))

    def delete_reference(self, baseline_id: str) -> Baseline | None:
        """Remove a reference from the active catalog without deleting evidence."""
        with self.sessions() as session:
            baseline = session.get(Baseline, baseline_id)
            if baseline is None or baseline.detector != "one_token":
                return None
            if baseline.status != "deleted":
                baseline.status = "deleted"
                session.commit()
                session.refresh(baseline)
            return baseline

    def list_reference_catalog(self, *, active_only: bool = True) -> list[dict[str, object]]:
        with self.sessions() as session:
            session.execute(
                update(Baseline)
                .where(Baseline.status == "active", Baseline.expires_at < datetime.now(UTC))
                .values(status="expired")
            )
            session.commit()
            statement = (
                select(Baseline, ManagedEndpoint, AuditRun)
                .join(ManagedEndpoint, Baseline.endpoint_id == ManagedEndpoint.id)
                .join(AuditRun, Baseline.artifact_id == AuditRun.id)
                .where(Baseline.detector == "one_token")
            )
            if active_only:
                statement = statement.where(Baseline.status == "active")
            statement = statement.order_by(Baseline.created_at.desc())
            rows = session.execute(statement).all()
            return [
                {
                    "baseline": baseline.as_dict(),
                    "endpoint": endpoint.as_dict(),
                    "artifact_sha256": run.artifact_sha256,
                    "collected_at": isoformat_utc(run.completed_at),
                    "duration_ms": duration_ms(run.started_at, run.completed_at),
                }
                for baseline, endpoint, run in rows
            ]

    def get_reference_metadata(self, artifact_id: str) -> dict[str, Any] | None:
        """Return decision provenance for the newest baseline using an artifact."""

        with self.sessions() as session:
            session.execute(
                update(Baseline)
                .where(Baseline.status == "active", Baseline.expires_at < datetime.now(UTC))
                .values(status="expired")
            )
            session.commit()
            statement = (
                select(Baseline)
                .where(
                    Baseline.detector == "one_token",
                    Baseline.artifact_id == artifact_id,
                )
                .order_by(Baseline.created_at.desc())
                .limit(1)
            )
            baseline = session.scalar(statement)
            if baseline is None:
                return None
            return {
                **dict(baseline.metadata_json or {}),
                "baseline_id": baseline.id,
                "baseline_status": baseline.status,
                "valid_from": isoformat_utc(baseline.valid_from),
                "expires_at": isoformat_utc(baseline.expires_at),
            }
