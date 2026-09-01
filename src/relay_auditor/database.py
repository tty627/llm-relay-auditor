import hashlib
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class ActiveBatchConflict(ValueError):
    def __init__(self, batch_id: str, message: str) -> None:
        self.batch_id = batch_id
        super().__init__(message)


ACTIVE_BATCH_STATUSES = {"running", "pausing", "paused", "canceling"}

ONE_MODEL_BATCH_TERMINAL_STATUSES = {"completed", "failed", "canceled", "interrupted"}
ONE_MODEL_BATCH_ACTIVE_STATUSES = {
    "running",
    "pausing",
    "paused",
    "canceling",
    "finalizing",
}
ONE_MODEL_ITEM_TERMINAL_STATUSES = {"completed", "failed", "canceled", "interrupted"}
ONE_MODEL_ITEM_ACTIVE_STATUSES = {"queued", "running", "paused", "canceling"}
_SAFE_ROW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REASON_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ONE_MODEL_QUALITY_FIELDS = {
    "valid_samples",
    "invalid_samples",
    "refusal_samples",
    "empty_samples",
    "error_samples",
    "coverage_cells",
    "total_cells",
    "directness",
    "split_half_mean_jsd",
}


def _validate_lower_sha256(value: str, label: str) -> None:
    if _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _validate_safe_quality(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) - _ONE_MODEL_QUALITY_FIELDS:
        raise ValueError("quality contains unsupported persistence fields")
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "directness":
            if value is not None and (not isinstance(value, str) or len(value) > 64):
                raise ValueError("quality.directness must be a bounded string")
        elif key == "split_half_mean_jsd":
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 <= float(value) <= 1
            ):
                raise ValueError("quality.split_half_mean_jsd must be between 0 and 1")
        elif value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError(f"quality.{key} must be a non-negative integer")
        result[key] = value
    return result


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


class ReferenceCollectionBatch(Base):
    __tablename__ = "reference_collection_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), index=True, default="running")
    reference_name: Mapped[str] = mapped_column(String(60))
    provider: Mapped[str] = mapped_column(String(100))
    base_url: Mapped[str] = mapped_column(Text)
    method_profile_id: Mapped[str] = mapped_column(String(64), index=True)
    total_items: Mapped[int] = mapped_column(Integer)
    completed_items: Mapped[int] = mapped_column(Integer, default=0)
    cells: Mapped[int] = mapped_column(Integer)
    samples: Mapped[int] = mapped_column(Integer)
    max_concurrency: Mapped[int] = mapped_column(Integer)
    concurrency_mode: Mapped[str] = mapped_column(String(16))
    request_timeout_seconds: Mapped[float] = mapped_column(Float)
    model_timeout_seconds: Mapped[float] = mapped_column(Float)
    valid_days: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "reference_name": self.reference_name,
            "provider": self.provider,
            "base_url": self.base_url,
            "method_profile_id": self.method_profile_id,
            "total_items": self.total_items,
            "completed_items": self.completed_items,
            "cells": self.cells,
            "samples": self.samples,
            "max_concurrency": self.max_concurrency,
            "concurrency_mode": self.concurrency_mode,
            "request_timeout_seconds": self.request_timeout_seconds,
            "model_timeout_seconds": self.model_timeout_seconds,
            "valid_days": self.valid_days,
            "created_at": isoformat_utc(self.created_at),
            "completed_at": isoformat_utc(self.completed_at),
        }


class ReferenceCollectionItem(Base):
    __tablename__ = "reference_collection_items"

    audit_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("reference_collection_batches.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    model: Mapped[str] = mapped_column(String(255), index=True)
    stage: Mapped[str] = mapped_column(String(32), index=True, default="queued")
    done: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    effective_concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)
    concurrency_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    baseline_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "audit_id": self.audit_id,
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "model": self.model,
            "stage": self.stage,
            "done": self.done,
            "total": self.total,
            "errors": self.errors,
            "retry_count": self.retry_count,
            "detail": self.detail,
            "effective_concurrency": self.effective_concurrency,
            "concurrency_reason": self.concurrency_reason,
            "baseline_id": self.baseline_id,
            "created_at": isoformat_utc(self.created_at),
            "updated_at": isoformat_utc(self.updated_at),
            "finished_at": isoformat_utc(self.finished_at),
        }


class ReferenceSet(Base):
    """An immutable three-epoch reference identity and its derived statistics."""

    __tablename__ = "reference_sets"
    __table_args__ = (
        CheckConstraint("cell_count = 40", name="ck_reference_set_cell_count"),
        CheckConstraint("samples_per_cell = 30", name="ck_reference_set_samples_per_cell"),
        CheckConstraint("expected_members = 3", name="ck_reference_set_member_count"),
        CheckConstraint(
            "source_type IN ('official_api', 'trusted_relay')",
            name="ck_reference_set_source_type",
        ),
        CheckConstraint(
            "status IN ('collecting', 'pausing', 'paused', 'canceling', "
            "'validating', 'ready', 'failed', 'canceled', 'interrupted')",
            name="ck_reference_set_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), index=True, default="collecting")
    reference_name: Mapped[str] = mapped_column(String(60))
    source_type: Mapped[str] = mapped_column(String(24), index=True)
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    transport_profile_id: Mapped[str] = mapped_column(String(64), index=True)
    logical_model: Mapped[str] = mapped_column(String(255), index=True)
    actual_model: Mapped[str] = mapped_column(String(255), index=True)
    normalized_base_url: Mapped[str] = mapped_column(Text)
    cell_count: Mapped[int] = mapped_column(Integer, default=40)
    samples_per_cell: Mapped[int] = mapped_column(Integer, default=30)
    expected_members: Mapped[int] = mapped_column(Integer, default=3)
    immutable_manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    immutable_manifest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    pairwise_statistics_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reference_envelope: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "reference_name": self.reference_name,
            "source_type": self.source_type,
            "protocol": self.protocol,
            "transport_profile_id": self.transport_profile_id,
            "logical_model": self.logical_model,
            "actual_model": self.actual_model,
            "normalized_base_url": self.normalized_base_url,
            "cell_count": self.cell_count,
            "samples_per_cell": self.samples_per_cell,
            "expected_members": self.expected_members,
            "immutable_manifest": self.immutable_manifest_json,
            "immutable_manifest_sha256": self.immutable_manifest_sha256,
            "pairwise_statistics": self.pairwise_statistics_json,
            "reference_envelope": self.reference_envelope,
            "decision_eligible": False,
            "operational_verdict": "unverifiable",
            "created_at": isoformat_utc(self.created_at),
            "completed_at": isoformat_utc(self.completed_at),
        }


class ReferenceSetMember(Base):
    __tablename__ = "reference_set_members"
    __table_args__ = (
        UniqueConstraint("reference_set_id", "ordinal", name="uq_reference_set_member_ordinal"),
        CheckConstraint("ordinal BETWEEN 1 AND 3", name="ck_reference_set_member_ordinal"),
        CheckConstraint(
            "status IN ('queued', 'running', 'paused', 'completed', 'failed', "
            "'canceled', 'interrupted')",
            name="ck_reference_set_member_status",
        ),
        CheckConstraint(
            "progress_done >= 0 AND progress_total = 1200 AND progress_done <= progress_total",
            name="ck_reference_set_member_progress",
        ),
        CheckConstraint(
            "error_count >= 0 AND request_attempts >= 0 AND retry_count >= 0 "
            "AND retry_budget_used >= retry_count",
            name="ck_reference_set_member_counters",
        ),
    )

    audit_id: Mapped[str] = mapped_column(ForeignKey("audit_runs.id"), primary_key=True)
    reference_set_id: Mapped[str] = mapped_column(ForeignKey("reference_sets.id"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), index=True, default="queued")
    stage: Mapped[str] = mapped_column(String(32), default="queued")
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=1200)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    request_attempts: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    retry_budget_used: Mapped[int] = mapped_column(Integer, default=0)
    scheduler_seed: Mapped[str] = mapped_column(String(255))
    artifact_id: Mapped[str | None] = mapped_column(String(36), unique=True, nullable=True)
    artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reference_manifest_sha256: Mapped[str] = mapped_column(String(64))
    fingerprint_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    quality_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    failure_reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "audit_id": self.audit_id,
            "reference_set_id": self.reference_set_id,
            "ordinal": self.ordinal,
            "status": self.status,
            "stage": self.stage,
            "progress_done": self.progress_done,
            "progress_total": self.progress_total,
            "error_count": self.error_count,
            "request_attempts": self.request_attempts,
            "retry_count": self.retry_count,
            "retry_budget_used": self.retry_budget_used,
            "scheduler_seed": self.scheduler_seed,
            "artifact_id": self.artifact_id,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "reference_manifest_sha256": self.reference_manifest_sha256,
            "fingerprint_manifest_sha256": self.fingerprint_manifest_sha256,
            "quality": self.quality_json,
            "failure_reason_code": self.failure_reason_code,
            "created_at": isoformat_utc(self.created_at),
            "completed_at": isoformat_utc(self.completed_at),
        }


class OneModelBatch(Base):
    __tablename__ = "one_model_batches"
    __table_args__ = (
        CheckConstraint("total_items BETWEEN 1 AND 20", name="ck_one_model_batch_items"),
        CheckConstraint(
            "completed_items >= 0 AND completed_items <= total_items",
            name="ck_one_model_batch_completed_items",
        ),
        CheckConstraint(
            "failed_items >= 0 AND failed_items <= total_items",
            name="ck_one_model_batch_failed_items",
        ),
        CheckConstraint(
            "progress_done >= 0 AND progress_total >= 0 AND progress_done <= progress_total",
            name="ck_one_model_batch_progress",
        ),
        CheckConstraint(
            "max_parallel_stations BETWEEN 1 AND 8",
            name="ck_one_model_batch_station_workers",
        ),
        CheckConstraint(
            "per_station_concurrency BETWEEN 1 AND 4",
            name="ck_one_model_batch_station_concurrency",
        ),
        CheckConstraint(
            "global_request_concurrency BETWEEN 1 AND 16",
            name="ck_one_model_batch_global_concurrency",
        ),
        CheckConstraint(
            "status IN ('running', 'pausing', 'paused', 'canceling', 'finalizing', "
            "'completed', 'failed', 'canceled', 'interrupted')",
            name="ck_one_model_batch_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    reference_set_id: Mapped[str] = mapped_column(ForeignKey("reference_sets.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    transport_profile_id: Mapped[str] = mapped_column(String(64), index=True)
    default_model: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), index=True, default="running")
    total_items: Mapped[int] = mapped_column(Integer)
    completed_items: Mapped[int] = mapped_column(Integer, default=0)
    failed_items: Mapped[int] = mapped_column(Integer, default=0)
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer)
    max_parallel_stations: Mapped[int] = mapped_column(Integer)
    per_station_concurrency: Mapped[int] = mapped_column(Integer)
    global_request_concurrency: Mapped[int] = mapped_column(Integer)
    request_timeout_seconds: Mapped[float] = mapped_column(Float)
    station_timeout_seconds: Mapped[float] = mapped_column(Float)
    batch_timeout_seconds: Mapped[float] = mapped_column(Float)
    retry_budget: Mapped[int] = mapped_column(Integer)
    report_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "reference_set_id": self.reference_set_id,
            "protocol": self.protocol,
            "transport_profile_id": self.transport_profile_id,
            "default_model": self.default_model,
            "status": self.status,
            "total_items": self.total_items,
            "completed_items": self.completed_items,
            "failed_items": self.failed_items,
            "progress_done": self.progress_done,
            "progress_total": self.progress_total,
            "max_parallel_stations": self.max_parallel_stations,
            "per_station_concurrency": self.per_station_concurrency,
            "global_request_concurrency": self.global_request_concurrency,
            "request_timeout_seconds": self.request_timeout_seconds,
            "station_timeout_seconds": self.station_timeout_seconds,
            "batch_timeout_seconds": self.batch_timeout_seconds,
            "retry_budget": self.retry_budget,
            "report_path": self.report_path,
            "report_sha256": self.report_sha256,
            "created_at": isoformat_utc(self.created_at),
            "started_at": isoformat_utc(self.started_at),
            "updated_at": isoformat_utc(self.updated_at),
            "completed_at": isoformat_utc(self.completed_at),
        }


class OneModelBatchItem(Base):
    __tablename__ = "one_model_batch_items"
    __table_args__ = (
        UniqueConstraint("batch_id", "row_id", name="uq_one_model_batch_row"),
        UniqueConstraint("batch_id", "sequence", name="uq_one_model_batch_sequence"),
        CheckConstraint("sequence >= 0", name="ck_one_model_item_sequence"),
        CheckConstraint(
            "status IN ('queued', 'running', 'paused', 'canceling', 'completed', "
            "'failed', 'canceled', 'interrupted')",
            name="ck_one_model_item_status",
        ),
        CheckConstraint(
            "progress_done >= 0 AND progress_total = 1200 AND progress_done <= progress_total",
            name="ck_one_model_item_progress",
        ),
        CheckConstraint(
            "error_count >= 0 AND request_attempts >= 0 AND retry_count >= 0 "
            "AND retry_budget_used >= retry_count",
            name="ck_one_model_item_counters",
        ),
        CheckConstraint(
            "latency_p50_ms IS NULL OR latency_p50_ms >= 0",
            name="ck_one_model_item_latency_p50",
        ),
        CheckConstraint(
            "latency_p95_ms IS NULL OR latency_p95_ms >= 0",
            name="ck_one_model_item_latency_p95",
        ),
        CheckConstraint(
            "error_http_status IS NULL OR error_http_status BETWEEN 100 AND 599",
            name="ck_one_model_item_http_status",
        ),
        CheckConstraint("decision_eligible = 0", name="ck_one_model_item_non_decision"),
        CheckConstraint(
            "operational_verdict = 'unverifiable'",
            name="ck_one_model_item_unverifiable",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("one_model_batches.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    row_id: Mapped[str] = mapped_column(String(128), index=True)
    station_name: Mapped[str] = mapped_column(String(80))
    canonical_base_url: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(255))
    reported_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(24), index=True, default="queued")
    stage: Mapped[str] = mapped_column(String(32), default="queued")
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=1200)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    request_attempts: Mapped[int] = mapped_column(Integer, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    retry_budget_used: Mapped[int] = mapped_column(Integer, default=0)
    safe_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_p50_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_p95_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    quality_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    exploratory_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_eligible: Mapped[bool] = mapped_column(Boolean, default=False)
    operational_verdict: Mapped[str] = mapped_column(String(32), default="unverifiable")
    comparison_json_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    comparison_json_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    partial_artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "row_id": self.row_id,
            "station_name": self.station_name,
            "canonical_base_url": self.canonical_base_url,
            "model": self.model,
            "reported_model": self.reported_model,
            "status": self.status,
            "stage": self.stage,
            "progress_done": self.progress_done,
            "progress_total": self.progress_total,
            "error_count": self.error_count,
            "request_attempts": self.request_attempts,
            "retry_count": self.retry_count,
            "retry_budget_used": self.retry_budget_used,
            "safe_error_code": self.safe_error_code,
            "error_http_status": self.error_http_status,
            "latency_p50_ms": self.latency_p50_ms,
            "latency_p95_ms": self.latency_p95_ms,
            "quality": self.quality_json,
            "exploratory_status": self.exploratory_status,
            "decision_eligible": self.decision_eligible,
            "operational_verdict": self.operational_verdict,
            "comparison_json_path": self.comparison_json_path,
            "comparison_json_sha256": self.comparison_json_sha256,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "partial_artifact_sha256": self.partial_artifact_sha256,
            "created_at": isoformat_utc(self.created_at),
            "updated_at": isoformat_utc(self.updated_at),
            "completed_at": isoformat_utc(self.completed_at),
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
        """Persist a complete queued comparison batch in one transaction.

        A batch is only schedulable after every lifecycle row exists.  Keeping
        the batch, audit runs, comparison records, progress rows, and task
        options in one transaction prevents a partially-created queue from
        being mistaken for recoverable work after a validation or database
        failure.
        """

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
            active = session.scalar(
                select(ComparisonBatch)
                .where(ComparisonBatch.status.in_(ACTIVE_BATCH_STATUSES))
                .order_by(ComparisonBatch.created_at.desc())
                .limit(1)
            )
            if active is not None:
                raise ActiveBatchConflict(
                    active.id,
                    "another comparison batch is already active",
                )
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
        retrying: bool = False,
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
            # An eight-character suffix is stable and normally sufficient. If
            # it collides with another identity, deterministically lengthen it.
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

    def create_reference_collection_batch_queue(
        self,
        *,
        batch_id: str,
        audit_ids: list[str],
        reference_name: str,
        provider: str,
        base_url: str,
        models: list[str],
        method_profile_id: str,
        cells: int,
        samples: int,
        max_concurrency: int,
        concurrency_mode: str,
        request_timeout_seconds: float,
        model_timeout_seconds: float,
        valid_days: int,
    ) -> ReferenceCollectionBatch:
        if not models or len(models) != len(audit_ids):
            raise ValueError("reference collection models and audit ids must be non-empty")
        now = datetime.now(UTC)
        batch = ReferenceCollectionBatch(
            id=batch_id,
            status="running",
            reference_name=reference_name,
            provider=provider,
            base_url=base_url,
            method_profile_id=method_profile_id,
            total_items=len(models),
            completed_items=0,
            cells=cells,
            samples=samples,
            max_concurrency=max_concurrency,
            concurrency_mode=concurrency_mode,
            request_timeout_seconds=request_timeout_seconds,
            model_timeout_seconds=model_timeout_seconds,
            valid_days=valid_days,
            created_at=now,
        )
        with self.sessions() as session:
            active = session.scalar(
                select(ReferenceCollectionBatch)
                .where(ReferenceCollectionBatch.status.in_(ACTIVE_BATCH_STATUSES))
                .order_by(ReferenceCollectionBatch.created_at.desc())
                .limit(1)
            )
            if active is not None:
                raise ActiveBatchConflict(
                    active.id,
                    "another reference collection batch is already active",
                )
            session.add(batch)
            total = cells * samples
            for sequence, (audit_id, model) in enumerate(zip(audit_ids, models, strict=True)):
                session.add(
                    AuditRun(
                        id=audit_id,
                        detector="one_token_collect",
                        status="queued",
                        target_base_url=base_url,
                        model=model,
                        started_at=now,
                    )
                )
                session.add(
                    ReferenceCollectionItem(
                        audit_id=audit_id,
                        batch_id=batch_id,
                        sequence=sequence,
                        model=model,
                        stage="queued",
                        done=0,
                        total=total,
                        errors=0,
                        detail="已进入参考采集队列",
                        created_at=now,
                        updated_at=now,
                    )
                )
            session.commit()
            session.refresh(batch)
            return batch

    def get_reference_collection_batch(
        self,
        batch_id: str,
    ) -> ReferenceCollectionBatch | None:
        with self.sessions() as session:
            return session.get(ReferenceCollectionBatch, batch_id)

    def latest_active_reference_collection_batch(
        self,
    ) -> ReferenceCollectionBatch | None:
        with self.sessions() as session:
            return session.scalar(
                select(ReferenceCollectionBatch)
                .where(ReferenceCollectionBatch.status.in_(ACTIVE_BATCH_STATUSES))
                .order_by(ReferenceCollectionBatch.created_at.desc())
                .limit(1)
            )

    def get_reference_collection_rows(
        self,
        batch_id: str,
    ) -> list[tuple[AuditRun, ReferenceCollectionItem]]:
        with self.sessions() as session:
            statement = (
                select(AuditRun, ReferenceCollectionItem)
                .join(
                    ReferenceCollectionItem,
                    ReferenceCollectionItem.audit_id == AuditRun.id,
                )
                .where(ReferenceCollectionItem.batch_id == batch_id)
                .order_by(ReferenceCollectionItem.sequence.asc())
            )
            return list(session.execute(statement).all())

    def set_reference_collection_batch_status(
        self,
        batch_id: str,
        status: str,
    ) -> ReferenceCollectionBatch:
        with self.sessions() as session:
            batch = session.get(ReferenceCollectionBatch, batch_id)
            if batch is None:
                raise LookupError(f"reference collection batch not found: {batch_id}")
            batch.status = status
            batch.completed_at = (
                datetime.now(UTC)
                if status in {"completed", "failed", "canceled", "interrupted"}
                else None
            )
            session.commit()
            session.refresh(batch)
            return batch

    def update_reference_collection_progress(
        self,
        audit_id: str,
        *,
        stage: str,
        done: int | None = None,
        total: int | None = None,
        errors: int | None = None,
        retrying: bool = False,
        detail: str | None = None,
    ) -> ReferenceCollectionItem:
        with self.sessions() as session:
            item = session.get(ReferenceCollectionItem, audit_id)
            if item is None:
                raise LookupError(f"reference collection item not found: {audit_id}")
            item.stage = stage
            if done is not None:
                item.done = max(0, done)
            if total is not None:
                item.total = max(0, total)
            if errors is not None:
                item.errors = max(0, errors)
            if retrying:
                item.retry_count += 1
            item.detail = detail
            item.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(item)
            return item

    def set_reference_collection_concurrency(
        self,
        audit_id: str,
        *,
        effective_concurrency: int,
        reason: str,
    ) -> ReferenceCollectionItem:
        with self.sessions() as session:
            item = session.get(ReferenceCollectionItem, audit_id)
            if item is None:
                raise LookupError(f"reference collection item not found: {audit_id}")
            item.effective_concurrency = effective_concurrency
            item.concurrency_reason = reason
            item.updated_at = datetime.now(UTC)
            session.commit()
            session.refresh(item)
            return item

    @staticmethod
    def _refresh_reference_batch_completion(
        session: Session,
        batch_id: str,
        now: datetime,
    ) -> None:
        batch = session.get(ReferenceCollectionBatch, batch_id)
        if batch is None:
            return
        finished = session.scalar(
            select(func.count())
            .select_from(ReferenceCollectionItem)
            .where(
                ReferenceCollectionItem.batch_id == batch_id,
                ReferenceCollectionItem.finished_at.is_not(None),
            )
        )
        batch.completed_items = min(batch.total_items, int(finished or 0))
        if batch.completed_items >= batch.total_items and batch.status not in {
            "canceled",
            "failed",
            "interrupted",
        }:
            batch.status = "completed"
            batch.completed_at = now

    def complete_reference_collection_item(
        self,
        audit_id: str,
        *,
        artifact_path: str,
        artifact_sha256: str,
        endpoint_id: str,
        endpoint_name: str,
        baseline_id: str,
        metadata: dict[str, Any],
    ) -> Baseline:
        now = datetime.now(UTC)
        with self.sessions() as session:
            item = session.get(ReferenceCollectionItem, audit_id)
            run = session.get(AuditRun, audit_id)
            if item is None or run is None:
                raise LookupError(f"reference collection item not found: {audit_id}")
            batch = session.get(ReferenceCollectionBatch, item.batch_id)
            if batch is None:
                raise LookupError(f"reference collection batch not found: {item.batch_id}")
            endpoint = self.upsert_endpoint_in_session(
                session,
                endpoint_id=endpoint_id,
                name=endpoint_name,
                provider=batch.provider,
                base_url=batch.base_url,
                model=item.model,
                protocol="openai_chat",
                now=now,
            )
            session.flush()
            session.execute(
                update(Baseline)
                .where(
                    Baseline.endpoint_id == endpoint.id,
                    Baseline.detector == "one_token",
                    Baseline.status == "active",
                )
                .values(status="superseded")
            )
            baseline = Baseline(
                id=baseline_id,
                endpoint_id=endpoint.id,
                detector="one_token",
                artifact_id=audit_id,
                status="active",
                valid_from=now,
                expires_at=now + timedelta(days=batch.valid_days),
                metadata_json=metadata,
                created_at=now,
            )
            session.add(baseline)
            run.status = "completed"
            run.verdict = "recorded"
            run.completed_at = now
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            run.error_message = None
            item.stage = "completed"
            item.done = item.total
            item.detail = "参考指纹采集完成"
            item.baseline_id = baseline.id
            item.updated_at = now
            item.finished_at = now
            self._refresh_reference_batch_completion(session, item.batch_id, now)
            session.commit()
            session.refresh(baseline)
            return baseline

    def finish_reference_collection_item(
        self,
        audit_id: str,
        *,
        status: str,
        verdict: str,
        detail: str,
        artifact_path: str | None = None,
        artifact_sha256: str | None = None,
    ) -> ReferenceCollectionItem:
        now = datetime.now(UTC)
        with self.sessions() as session:
            item = session.get(ReferenceCollectionItem, audit_id)
            run = session.get(AuditRun, audit_id)
            if item is None or run is None:
                raise LookupError(f"reference collection item not found: {audit_id}")
            run.status = status
            run.verdict = verdict
            run.completed_at = now
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            run.error_message = detail
            item.stage = status
            item.detail = detail
            item.updated_at = now
            item.finished_at = now
            self._refresh_reference_batch_completion(session, item.batch_id, now)
            session.commit()
            session.refresh(item)
            return item

    def interrupt_orphaned_reference_collections(self) -> int:
        now = datetime.now(UTC)
        interrupted = 0
        with self.sessions() as session:
            batches = list(
                session.scalars(
                    select(ReferenceCollectionBatch).where(
                        ReferenceCollectionBatch.status.in_(ACTIVE_BATCH_STATUSES)
                    )
                )
            )
            for batch in batches:
                items = list(
                    session.scalars(
                        select(ReferenceCollectionItem).where(
                            ReferenceCollectionItem.batch_id == batch.id,
                            ReferenceCollectionItem.finished_at.is_(None),
                        )
                    )
                )
                for item in items:
                    run = session.get(AuditRun, item.audit_id)
                    if run is not None:
                        run.status = "interrupted"
                        run.verdict = "interrupted"
                        run.completed_at = now
                        run.error_message = "服务重启，内存中的 API key 已清除"
                    item.stage = "interrupted"
                    item.detail = "服务重启，凭证已清除；请重新创建参考采集批次"
                    item.updated_at = now
                    item.finished_at = now
                    interrupted += 1
                batch.status = "interrupted"
                batch.completed_items = batch.total_items
                batch.completed_at = now
            session.commit()
        return interrupted

    def create_reference_set_queue(
        self,
        *,
        reference_set_id: str,
        audit_ids: list[str],
        scheduler_seeds: list[str],
        reference_name: str,
        source_type: str,
        immutable_manifest: dict[str, Any],
    ) -> ReferenceSet:
        """Create one immutable ReferenceSet and exactly three queued members."""

        from relay_auditor.reference_sets import (
            REFERENCE_SET_MEMBER_COUNT,
            load_reference_set_manifest,
            reference_manifest_sha256,
        )

        if len(audit_ids) != REFERENCE_SET_MEMBER_COUNT or len(set(audit_ids)) != len(audit_ids):
            raise ValueError("a ReferenceSet requires exactly three unique audit ids")
        if len(scheduler_seeds) != REFERENCE_SET_MEMBER_COUNT or len(set(scheduler_seeds)) != len(
            scheduler_seeds
        ):
            raise ValueError("a ReferenceSet requires exactly three unique scheduler seeds")
        if source_type not in {"official_api", "trusted_relay"}:
            raise ValueError("unsupported ReferenceSet source_type")

        manifest = load_reference_set_manifest(immutable_manifest)
        manifest_payload = manifest.as_dict()
        manifest_sha256 = reference_manifest_sha256(manifest_payload)
        now = datetime.now(UTC)
        reference_set = ReferenceSet(
            id=reference_set_id,
            status="collecting",
            reference_name=reference_name,
            source_type=source_type,
            protocol=manifest.protocol,
            transport_profile_id=manifest.transport_profile_id,
            logical_model=manifest.logical_model,
            actual_model=manifest.actual_model,
            normalized_base_url=manifest.normalized_base_url,
            cell_count=manifest.cell_count,
            samples_per_cell=manifest.samples_per_cell,
            expected_members=manifest.member_count,
            immutable_manifest_json=manifest_payload,
            immutable_manifest_sha256=manifest_sha256,
            created_at=now,
        )
        with self.sessions() as session:
            session.add(reference_set)
            for ordinal, (audit_id, scheduler_seed) in enumerate(
                zip(audit_ids, scheduler_seeds, strict=True),
                start=1,
            ):
                session.add(
                    AuditRun(
                        id=audit_id,
                        detector="one_token_reference_member",
                        status="queued",
                        target_base_url=manifest.normalized_base_url,
                        model=manifest.actual_model,
                        started_at=now,
                    )
                )
                session.add(
                    ReferenceSetMember(
                        audit_id=audit_id,
                        reference_set_id=reference_set_id,
                        ordinal=ordinal,
                        status="queued",
                        stage="queued",
                        progress_done=0,
                        progress_total=1200,
                        error_count=0,
                        request_attempts=0,
                        retry_count=0,
                        retry_budget_used=0,
                        scheduler_seed=scheduler_seed,
                        reference_manifest_sha256=manifest_sha256,
                        created_at=now,
                    )
                )
            session.commit()
            session.refresh(reference_set)
            return reference_set

    def get_reference_set(self, reference_set_id: str) -> ReferenceSet | None:
        with self.sessions() as session:
            return session.get(ReferenceSet, reference_set_id)

    def set_reference_set_status(self, reference_set_id: str, status: str) -> ReferenceSet:
        """Apply only reversible control-plane states; terminal states have dedicated methods."""

        allowed = {"collecting", "pausing", "paused", "canceling"}
        if status not in allowed:
            raise ValueError("unsupported reversible ReferenceSet status")
        transitions = {
            "collecting": {"collecting", "pausing", "canceling"},
            "pausing": {"pausing", "paused", "canceling"},
            "paused": {"paused", "collecting", "canceling"},
            "canceling": {"canceling"},
        }
        with self.sessions() as session:
            reference_set = session.get(ReferenceSet, reference_set_id)
            if reference_set is None:
                raise LookupError(f"ReferenceSet not found: {reference_set_id}")
            if status not in transitions.get(reference_set.status, set()):
                raise ValueError("invalid or terminal ReferenceSet status transition")
            reference_set.status = status
            reference_set.completed_at = None
            session.commit()
            session.refresh(reference_set)
            return reference_set

    def set_reference_set_member_running(self, audit_id: str) -> ReferenceSetMember:
        now = datetime.now(UTC)
        with self.sessions() as session:
            member = session.get(ReferenceSetMember, audit_id)
            run = session.get(AuditRun, audit_id)
            if member is None or run is None:
                raise LookupError(f"ReferenceSet member not found: {audit_id}")
            reference_set = session.get(ReferenceSet, member.reference_set_id)
            if reference_set is None:
                raise LookupError(f"ReferenceSet not found: {member.reference_set_id}")
            if reference_set.status != "collecting" or member.status not in {"queued", "paused"}:
                raise ValueError("ReferenceSet member cannot enter running state")
            was_paused = member.status == "paused"
            member.status = "running"
            member.stage = "starting"
            if was_paused:
                # A paused collector is restarted from its immutable seed.  Its
                # previous partial samples are not part of the eventual member,
                # so expose the restarted progress honestly while preserving the
                # cumulative retry budget.
                member.progress_done = 0
                member.error_count = 0
            run.status = "running"
            if run.started_at is None:
                run.started_at = now
            run.completed_at = None
            run.error_message = None
            session.commit()
            session.refresh(member)
            return member

    def update_reference_set_member_progress(
        self,
        audit_id: str,
        *,
        stage: str,
        done: int,
        errors: int,
        retrying: bool = False,
        request_attempts: int | None = None,
        retry_count: int | None = None,
        retry_budget_used: int | None = None,
    ) -> ReferenceSetMember:
        if not stage or len(stage) > 32 or re.fullmatch(r"[a-z0-9_:-]+", stage) is None:
            raise ValueError("ReferenceSet progress stage must be a safe machine code")
        if done < 0 or done > 1200 or errors < 0:
            raise ValueError("ReferenceSet progress counters are out of bounds")
        if request_attempts is not None and request_attempts < 0:
            raise ValueError("ReferenceSet request attempts are out of bounds")
        if retry_count is not None and retry_count < 0:
            raise ValueError("ReferenceSet retry count is out of bounds")
        if retry_budget_used is not None and not 0 <= retry_budget_used <= 240:
            raise ValueError("ReferenceSet retry budget is out of bounds")
        if retrying and any(
            value is not None for value in (request_attempts, retry_count, retry_budget_used)
        ):
            raise ValueError("use either retrying or absolute request counters")
        with self.sessions() as session:
            member = session.get(ReferenceSetMember, audit_id)
            if member is None:
                raise LookupError(f"ReferenceSet member not found: {audit_id}")
            if member.status != "running":
                raise ValueError("only a running ReferenceSet member can report progress")
            if done < member.progress_done or errors < member.error_count:
                raise ValueError("ReferenceSet progress counters must be monotonic")
            if request_attempts is not None and request_attempts < member.request_attempts:
                raise ValueError("ReferenceSet request attempts must be monotonic")
            if retry_count is not None and retry_count < member.retry_count:
                raise ValueError("ReferenceSet retry count must be monotonic")
            if (
                retry_budget_used is not None
                and retry_budget_used < member.retry_budget_used
            ):
                raise ValueError("ReferenceSet retry budget must be monotonic")
            effective_attempts = (
                request_attempts if request_attempts is not None else member.request_attempts
            )
            effective_retries = retry_count if retry_count is not None else member.retry_count
            effective_budget = (
                retry_budget_used
                if retry_budget_used is not None
                else member.retry_budget_used
            )
            if effective_retries > effective_attempts or effective_retries > effective_budget:
                raise ValueError("ReferenceSet request counters are inconsistent")
            member.stage = stage
            member.progress_done = done
            member.error_count = errors
            if request_attempts is not None:
                member.request_attempts = request_attempts
            if retry_count is not None:
                member.retry_count = retry_count
            if retry_budget_used is not None:
                member.retry_budget_used = retry_budget_used
            if retrying:
                if member.retry_budget_used >= 240:
                    raise ValueError("ReferenceSet retry count is out of bounds")
                member.request_attempts += 1
                member.retry_count += 1
                member.retry_budget_used += 1
            session.commit()
            session.refresh(member)
            return member

    def pause_reference_set_member(self, audit_id: str) -> ReferenceSetMember:
        with self.sessions() as session:
            member = session.get(ReferenceSetMember, audit_id)
            run = session.get(AuditRun, audit_id)
            if member is None or run is None:
                raise LookupError(f"ReferenceSet member not found: {audit_id}")
            if member.status not in {"queued", "running"}:
                raise ValueError("ReferenceSet member cannot be paused")
            member.status = "paused"
            member.stage = "paused"
            run.status = "paused"
            session.commit()
            session.refresh(member)
            return member

    def list_reference_sets(self, *, ready_only: bool = False) -> list[ReferenceSet]:
        """List only formal ReferenceSets; legacy Baseline rows are never promoted."""

        with self.sessions() as session:
            statement = select(ReferenceSet)
            if ready_only:
                statement = statement.where(ReferenceSet.status == "ready")
            return list(session.scalars(statement.order_by(ReferenceSet.created_at.desc())))

    def get_reference_set_rows(
        self,
        reference_set_id: str,
    ) -> list[tuple[AuditRun, ReferenceSetMember]]:
        with self.sessions() as session:
            statement = (
                select(AuditRun, ReferenceSetMember)
                .join(ReferenceSetMember, ReferenceSetMember.audit_id == AuditRun.id)
                .where(ReferenceSetMember.reference_set_id == reference_set_id)
                .order_by(ReferenceSetMember.ordinal.asc())
            )
            return list(session.execute(statement).all())

    def complete_reference_set_member(
        self,
        audit_id: str,
        *,
        artifact_id: str,
        artifact_path: str,
        artifact_sha256: str,
        raw_evidence_sha256: str,
        reference_manifest_sha256: str,
        fingerprint_manifest_sha256: str,
        quality: dict[str, Any],
    ) -> ReferenceSetMember:
        """Seal a member once; final readiness still requires ensemble validation."""

        digests = {
            "artifact_sha256": artifact_sha256,
            "raw_evidence_sha256": raw_evidence_sha256,
            "reference_manifest_sha256": reference_manifest_sha256,
            "fingerprint_manifest_sha256": fingerprint_manifest_sha256,
        }
        for label, digest in digests.items():
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")

        now = datetime.now(UTC)
        with self.sessions() as session:
            member = session.get(ReferenceSetMember, audit_id)
            run = session.get(AuditRun, audit_id)
            if member is None or run is None:
                raise LookupError(f"ReferenceSet member not found: {audit_id}")
            reference_set = session.get(ReferenceSet, member.reference_set_id)
            if reference_set is None:
                raise LookupError(f"ReferenceSet not found: {member.reference_set_id}")
            if reference_set.status in {"ready", "failed", "canceled", "interrupted"}:
                raise ValueError("terminal ReferenceSet members are immutable")
            if member.status == "completed":
                raise ValueError("completed ReferenceSet members are immutable")
            if reference_manifest_sha256 != reference_set.immutable_manifest_sha256:
                raise ValueError("member ReferenceSet manifest digest mismatch")

            member.status = "completed"
            member.stage = "completed"
            member.progress_done = member.progress_total
            member.artifact_id = artifact_id
            member.artifact_path = artifact_path
            member.artifact_sha256 = artifact_sha256
            member.raw_evidence_sha256 = raw_evidence_sha256
            member.fingerprint_manifest_sha256 = fingerprint_manifest_sha256
            member.quality_json = dict(quality)
            member.failure_reason_code = None
            member.completed_at = now
            run.status = "completed"
            run.verdict = "recorded"
            run.completed_at = now
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            run.error_message = None

            completed = session.scalar(
                select(func.count())
                .select_from(ReferenceSetMember)
                .where(
                    ReferenceSetMember.reference_set_id == reference_set.id,
                    ReferenceSetMember.status == "completed",
                )
            )
            if int(completed or 0) >= reference_set.expected_members:
                reference_set.status = "validating"
            session.commit()
            session.refresh(member)
            return member

    def fail_reference_set_member(
        self,
        audit_id: str,
        *,
        status: str = "failed",
        reason_code: str,
        artifact_path: str | None = None,
        artifact_sha256: str | None = None,
    ) -> ReferenceSetMember:
        if status not in {"failed", "canceled", "interrupted"}:
            raise ValueError("unsupported ReferenceSet member failure status")
        if not reason_code or len(reason_code) > 64:
            raise ValueError("ReferenceSet failure requires a bounded reason code")
        now = datetime.now(UTC)
        with self.sessions() as session:
            member = session.get(ReferenceSetMember, audit_id)
            run = session.get(AuditRun, audit_id)
            if member is None or run is None:
                raise LookupError(f"ReferenceSet member not found: {audit_id}")
            reference_set = session.get(ReferenceSet, member.reference_set_id)
            if reference_set is None:
                raise LookupError(f"ReferenceSet not found: {member.reference_set_id}")
            if member.status == "completed" or reference_set.status == "ready":
                raise ValueError("completed ReferenceSet evidence is immutable")
            member.status = status
            member.stage = status
            member.failure_reason_code = reason_code
            member.artifact_path = artifact_path
            member.artifact_sha256 = artifact_sha256
            member.completed_at = now
            run.status = status
            run.verdict = "unverifiable"
            run.completed_at = now
            run.artifact_path = artifact_path
            run.artifact_sha256 = artifact_sha256
            run.error_message = reason_code
            reference_set.status = status
            reference_set.completed_at = now
            session.commit()
            session.refresh(member)
            return member

    def finalize_reference_set(
        self,
        reference_set_id: str,
        *,
        statistics: dict[str, Any],
    ) -> ReferenceSet:
        from relay_auditor.reference_sets import validate_reference_statistics_payload

        validated = validate_reference_statistics_payload(statistics)
        now = datetime.now(UTC)
        with self.sessions() as session:
            reference_set = session.get(ReferenceSet, reference_set_id)
            if reference_set is None:
                raise LookupError(f"ReferenceSet not found: {reference_set_id}")
            if reference_set.status == "ready":
                raise ValueError("ready ReferenceSets are immutable")
            if reference_set.status != "validating":
                raise ValueError("ReferenceSet is not ready for ensemble validation")
            if (
                validated.get("referenceManifestSha256")
                != reference_set.immutable_manifest_sha256
            ):
                raise ValueError("reference statistics manifest digest mismatch")
            members = list(
                session.scalars(
                    select(ReferenceSetMember)
                    .where(ReferenceSetMember.reference_set_id == reference_set_id)
                    .order_by(ReferenceSetMember.ordinal.asc())
                )
            )
            if len(members) != reference_set.expected_members or any(
                member.status != "completed"
                or member.reference_manifest_sha256 != reference_set.immutable_manifest_sha256
                or member.artifact_id is None
                or member.artifact_sha256 is None
                or member.raw_evidence_sha256 is None
                or member.fingerprint_manifest_sha256 is None
                for member in members
            ):
                raise ValueError("ReferenceSet members are incomplete or incompatible")
            expected_fingerprint_manifest = reference_set.immutable_manifest_json.get(
                "batteryManifestSha256"
            )
            if any(
                member.fingerprint_manifest_sha256 != expected_fingerprint_manifest
                for member in members
            ):
                raise ValueError("ReferenceSet member fingerprint manifest digest mismatch")
            reference_set.pairwise_statistics_json = validated
            reference_set.reference_envelope = float(validated["referenceEnvelope"])
            reference_set.status = "ready"
            reference_set.completed_at = now
            session.commit()
            session.refresh(reference_set)
            return reference_set

    def interrupt_orphaned_reference_sets(self) -> int:
        """Fail closed after restart because all member credentials were memory-only."""

        now = datetime.now(UTC)
        interrupted = 0
        with self.sessions() as session:
            reference_sets = list(
                session.scalars(
                    select(ReferenceSet).where(
                        ReferenceSet.status.in_({"collecting", "pausing", "paused", "validating"})
                    )
                )
            )
            for reference_set in reference_sets:
                unfinished = list(
                    session.scalars(
                        select(ReferenceSetMember).where(
                            ReferenceSetMember.reference_set_id == reference_set.id,
                            ReferenceSetMember.status.in_({"queued", "running", "paused"}),
                        )
                    )
                )
                for member in unfinished:
                    member.status = "interrupted"
                    member.stage = "interrupted"
                    member.failure_reason_code = "credential_lost_after_restart"
                    member.completed_at = now
                    run = session.get(AuditRun, member.audit_id)
                    if run is not None:
                        run.status = "interrupted"
                        run.verdict = "unverifiable"
                        run.completed_at = now
                        run.error_message = "credential_lost_after_restart"
                    interrupted += 1
                reference_set.status = "interrupted"
                reference_set.completed_at = now
            session.commit()
        return interrupted

    def create_one_model_batch_queue(
        self,
        *,
        batch_id: str,
        reference_set_id: str,
        protocol: str,
        transport_profile_id: str,
        default_model: str,
        items: list[dict[str, Any]],
        max_parallel_stations: int = 4,
        per_station_concurrency: int = 3,
        global_request_concurrency: int = 12,
        request_timeout_seconds: float = 30,
        station_timeout_seconds: float = 7200,
        batch_timeout_seconds: float = 43200,
        retry_budget: int = 240,
    ) -> OneModelBatch:
        """Atomically persist the complete secret-free input ledger for one model."""

        from relay_auditor.network_safety import canonical_endpoint_url

        if not 1 <= len(items) <= 20:
            raise ValueError("one-model batch requires 1 to 20 input rows")
        if not 1 <= max_parallel_stations <= 8:
            raise ValueError("max_parallel_stations must be between 1 and 8")
        if not 1 <= per_station_concurrency <= 4:
            raise ValueError("per_station_concurrency must be between 1 and 4")
        if not 1 <= global_request_concurrency <= 16:
            raise ValueError("global_request_concurrency must be between 1 and 16")
        if global_request_concurrency > max_parallel_stations * per_station_concurrency:
            raise ValueError("global concurrency exceeds the station worker capacity")
        if not 3 <= request_timeout_seconds <= 120:
            raise ValueError("request timeout is out of bounds")
        if not 60 <= station_timeout_seconds <= 7200:
            raise ValueError("station timeout is out of bounds")
        if not 60 <= batch_timeout_seconds <= 43200:
            raise ValueError("batch timeout is out of bounds")
        if not 0 <= retry_budget <= 240:
            raise ValueError("retry budget is out of bounds")
        if not default_model.strip() or len(default_model) > 255:
            raise ValueError("default_model must contain 1 to 255 characters")
        profile_by_protocol = {
            "openai_chat": "openai-chat-onetoken-v1",
            "anthropic_messages": "anthropic-messages-opus5-onetoken-v1",
        }
        if profile_by_protocol.get(protocol) != transport_profile_id:
            raise ValueError("protocol and transport profile do not match")

        allowed_item_fields = {
            "item_id",
            "row_id",
            "station_name",
            "canonical_base_url",
            "model",
        }
        prepared: list[dict[str, str]] = []
        item_ids: set[str] = set()
        row_ids: set[str] = set()
        endpoint_models: set[tuple[str, str]] = set()
        for raw in items:
            if set(raw) != allowed_item_fields:
                raise ValueError("one-model batch item has unsupported persistence fields")
            item_id = raw.get("item_id")
            row_id = raw.get("row_id")
            station_name = raw.get("station_name")
            base_url = raw.get("canonical_base_url")
            model = raw.get("model")
            if (
                not isinstance(item_id, str)
                or len(item_id) != 36
                or any(character not in "0123456789abcdef-" for character in item_id)
            ):
                raise ValueError("one-model item_id must be a lowercase UUID")
            if not isinstance(row_id, str) or _SAFE_ROW_ID.fullmatch(row_id) is None:
                raise ValueError("one-model row_id is not a safe identifier")
            if (
                not isinstance(station_name, str)
                or not station_name.strip()
                or len(station_name) > 80
            ):
                raise ValueError("one-model station_name must contain 1 to 80 characters")
            if not isinstance(base_url, str):
                raise ValueError("one-model canonical_base_url must be a string")
            canonical_base_url = canonical_endpoint_url(base_url, protocol)[0]
            if base_url != canonical_base_url:
                raise ValueError("one-model canonical_base_url is not canonical")
            if not isinstance(model, str) or not model.strip() or len(model) > 255:
                raise ValueError("one-model item model must contain 1 to 255 characters")
            if item_id in item_ids or row_id in row_ids:
                raise ValueError("one-model batch contains duplicate item_id or row_id")
            identity = (canonical_base_url, model)
            if identity in endpoint_models:
                raise ValueError("one-model batch contains a duplicate endpoint and model")
            item_ids.add(item_id)
            row_ids.add(row_id)
            endpoint_models.add(identity)
            prepared.append(
                {
                    "item_id": item_id,
                    "row_id": row_id,
                    "station_name": station_name.strip(),
                    "canonical_base_url": canonical_base_url,
                    "model": model,
                }
            )

        now = datetime.now(UTC)
        batch = OneModelBatch(
            id=batch_id,
            reference_set_id=reference_set_id,
            protocol=protocol,
            transport_profile_id=transport_profile_id,
            default_model=default_model,
            status="running",
            total_items=len(prepared),
            completed_items=0,
            failed_items=0,
            progress_done=0,
            progress_total=len(prepared) * 1200,
            max_parallel_stations=max_parallel_stations,
            per_station_concurrency=per_station_concurrency,
            global_request_concurrency=global_request_concurrency,
            request_timeout_seconds=request_timeout_seconds,
            station_timeout_seconds=station_timeout_seconds,
            batch_timeout_seconds=batch_timeout_seconds,
            retry_budget=retry_budget,
            created_at=now,
            started_at=now,
            updated_at=now,
        )
        with self.sessions() as session:
            reference_set = session.get(ReferenceSet, reference_set_id)
            if reference_set is None or reference_set.status != "ready":
                raise ValueError("one-model batch requires a ready ReferenceSet")
            if (
                reference_set.protocol != protocol
                or reference_set.transport_profile_id != transport_profile_id
            ):
                raise ValueError("one-model batch does not match its ReferenceSet protocol")
            session.add(batch)
            for sequence, item in enumerate(prepared):
                session.add(
                    OneModelBatchItem(
                        id=item["item_id"],
                        batch_id=batch_id,
                        sequence=sequence,
                        row_id=item["row_id"],
                        station_name=item["station_name"],
                        canonical_base_url=item["canonical_base_url"],
                        model=item["model"],
                        status="queued",
                        stage="queued",
                        progress_done=0,
                        progress_total=1200,
                        error_count=0,
                        request_attempts=0,
                        retry_count=0,
                        retry_budget_used=0,
                        quality_json={},
                        decision_eligible=False,
                        operational_verdict="unverifiable",
                        created_at=now,
                        updated_at=now,
                    )
                )
            session.commit()
            session.refresh(batch)
            return batch

    def get_one_model_batch(self, batch_id: str) -> OneModelBatch | None:
        with self.sessions() as session:
            return session.get(OneModelBatch, batch_id)

    def get_one_model_batch_item(self, item_id: str) -> OneModelBatchItem | None:
        with self.sessions() as session:
            return session.get(OneModelBatchItem, item_id)

    def list_one_model_batch_items(self, batch_id: str) -> list[OneModelBatchItem]:
        with self.sessions() as session:
            return list(
                session.scalars(
                    select(OneModelBatchItem)
                    .where(OneModelBatchItem.batch_id == batch_id)
                    .order_by(OneModelBatchItem.sequence.asc())
                )
            )

    def list_active_one_model_batches(self) -> list[OneModelBatch]:
        with self.sessions() as session:
            return list(
                session.scalars(
                    select(OneModelBatch)
                    .where(OneModelBatch.status.in_(ONE_MODEL_BATCH_ACTIVE_STATUSES))
                    .order_by(OneModelBatch.created_at.asc())
                )
            )

    def list_one_model_batches_without_reports(self) -> list[OneModelBatch]:
        """Return terminal ledgers that still need their immutable report."""

        with self.sessions() as session:
            return list(
                session.scalars(
                    select(OneModelBatch)
                    .where(
                        OneModelBatch.status.in_(ONE_MODEL_BATCH_TERMINAL_STATUSES),
                        OneModelBatch.report_path.is_(None),
                        OneModelBatch.report_sha256.is_(None),
                    )
                    .order_by(OneModelBatch.created_at.asc())
                )
            )

    @staticmethod
    def _refresh_one_model_batch_progress(
        session: Session,
        batch: OneModelBatch,
        now: datetime,
    ) -> None:
        items = list(
            session.scalars(
                select(OneModelBatchItem).where(OneModelBatchItem.batch_id == batch.id)
            )
        )
        batch.progress_done = min(batch.progress_total, sum(item.progress_done for item in items))
        batch.completed_items = sum(
            item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES for item in items
        )
        batch.failed_items = sum(item.status in {"failed", "interrupted"} for item in items)
        batch.updated_at = now
        if batch.completed_items == batch.total_items and batch.status not in {
            "canceled",
            "failed",
            "interrupted",
        }:
            batch.status = "finalizing"

    def update_one_model_batch_item_progress(
        self,
        item_id: str,
        *,
        status: str,
        stage: str,
        done: int,
        errors: int,
        request_attempts: int,
        retry_count: int,
        retry_budget_used: int,
    ) -> OneModelBatchItem:
        if status not in {"queued", "running"}:
            raise ValueError("unsupported active one-model item status")
        if not stage or len(stage) > 32 or re.fullmatch(r"[a-z0-9_:-]+", stage) is None:
            raise ValueError("one-model progress stage must be a safe machine code")
        if not 0 <= done <= 1200 or min(
            errors,
            request_attempts,
            retry_count,
            retry_budget_used,
        ) < 0:
            raise ValueError("one-model progress counters are out of bounds")
        if retry_count > request_attempts or retry_count > retry_budget_used:
            raise ValueError("one-model request counters are inconsistent")
        now = datetime.now(UTC)
        with self.sessions() as session:
            item = session.get(OneModelBatchItem, item_id)
            if item is None:
                raise LookupError(f"one-model batch item not found: {item_id}")
            batch = session.get(OneModelBatch, item.batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {item.batch_id}")
            if batch.status != "running" or item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
                raise ValueError("one-model item cannot report progress in its current state")
            if retry_budget_used > batch.retry_budget:
                raise ValueError("one-model retry budget is exhausted")
            if (
                done < item.progress_done
                or errors < item.error_count
                or request_attempts < item.request_attempts
                or retry_count < item.retry_count
                or retry_budget_used < item.retry_budget_used
            ):
                raise ValueError("one-model progress counters must be monotonic")
            item.status = status
            item.stage = stage
            item.progress_done = done
            item.error_count = errors
            item.request_attempts = request_attempts
            item.retry_count = retry_count
            item.retry_budget_used = retry_budget_used
            item.updated_at = now
            self._refresh_one_model_batch_progress(session, batch, now)
            session.commit()
            session.refresh(item)
            return item

    def finish_one_model_batch_item(
        self,
        item_id: str,
        *,
        status: str,
        exploratory_status: str | None = None,
        safe_error_code: str | None = None,
        error_http_status: int | None = None,
        latency_p50_ms: float | None = None,
        latency_p95_ms: float | None = None,
        reported_model: str | None = None,
        quality: dict[str, Any] | None = None,
        comparison_json_path: str | None = None,
        comparison_json_sha256: str | None = None,
        artifact_id: str | None = None,
        artifact_sha256: str | None = None,
        raw_evidence_sha256: str | None = None,
        partial_artifact_sha256: str | None = None,
    ) -> OneModelBatchItem:
        if status not in ONE_MODEL_ITEM_TERMINAL_STATUSES:
            raise ValueError("one-model item requires a terminal status")
        if safe_error_code is not None and _SAFE_REASON_CODE.fullmatch(safe_error_code) is None:
            raise ValueError("one-model item error must be a safe reason code")
        if exploratory_status is not None and _SAFE_REASON_CODE.fullmatch(
            exploratory_status
        ) is None:
            raise ValueError("one-model exploratory status must be a safe reason code")
        if error_http_status is not None and not 100 <= error_http_status <= 599:
            raise ValueError("one-model HTTP status is out of bounds")
        for label, value in (
            ("latency_p50_ms", latency_p50_ms),
            ("latency_p95_ms", latency_p95_ms),
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0
            ):
                raise ValueError(f"{label} must be a non-negative number")
        if (
            latency_p50_ms is not None
            and latency_p95_ms is not None
            and latency_p95_ms < latency_p50_ms
        ):
            raise ValueError("latency p95 cannot be lower than p50")
        if reported_model is not None and (
            not reported_model.strip() or len(reported_model) > 255
        ):
            raise ValueError("reported_model must contain 1 to 255 characters")
        if (comparison_json_path is None) != (comparison_json_sha256 is None):
            raise ValueError("comparison JSON path and digest must be supplied together")
        if status == "completed" and comparison_json_path is None:
            raise ValueError("completed one-model item requires a comparison JSON artifact")
        if comparison_json_path is not None:
            if not Path(comparison_json_path).is_absolute():
                raise ValueError("comparison JSON path must be absolute")
            _validate_lower_sha256(comparison_json_sha256 or "", "comparison_json_sha256")
        for label, digest in (
            ("artifact_sha256", artifact_sha256),
            ("raw_evidence_sha256", raw_evidence_sha256),
            ("partial_artifact_sha256", partial_artifact_sha256),
        ):
            if digest is not None:
                _validate_lower_sha256(digest, label)
        if artifact_id is not None and _SAFE_ROW_ID.fullmatch(artifact_id) is None:
            raise ValueError("artifact_id is not a safe identifier")
        safe_quality = _validate_safe_quality(quality or {})

        now = datetime.now(UTC)
        with self.sessions() as session:
            item = session.get(OneModelBatchItem, item_id)
            if item is None:
                raise LookupError(f"one-model batch item not found: {item_id}")
            batch = session.get(OneModelBatch, item.batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {item.batch_id}")
            if item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
                raise ValueError("terminal one-model items are immutable")
            item.status = status
            item.stage = status
            if status == "completed":
                item.progress_done = item.progress_total
            item.safe_error_code = safe_error_code
            item.error_http_status = error_http_status
            item.latency_p50_ms = float(latency_p50_ms) if latency_p50_ms is not None else None
            item.latency_p95_ms = float(latency_p95_ms) if latency_p95_ms is not None else None
            item.reported_model = reported_model.strip() if reported_model is not None else None
            item.quality_json = safe_quality
            item.exploratory_status = exploratory_status
            item.decision_eligible = False
            item.operational_verdict = "unverifiable"
            item.comparison_json_path = comparison_json_path
            item.comparison_json_sha256 = comparison_json_sha256
            item.artifact_id = artifact_id
            item.artifact_sha256 = artifact_sha256
            item.raw_evidence_sha256 = raw_evidence_sha256
            item.partial_artifact_sha256 = partial_artifact_sha256
            item.updated_at = now
            item.completed_at = now
            self._refresh_one_model_batch_progress(session, batch, now)
            session.commit()
            session.refresh(item)
            return item

    def pause_one_model_batch(self, batch_id: str) -> OneModelBatch:
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(OneModelBatch, batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            if batch.status == "paused":
                return batch
            if batch.status not in {"running", "pausing"}:
                raise ValueError("one-model batch cannot be paused")
            items = list(
                session.scalars(
                    select(OneModelBatchItem).where(
                        OneModelBatchItem.batch_id == batch_id,
                        OneModelBatchItem.status.in_({"queued", "running"}),
                    )
                )
            )
            for item in items:
                item.status = "paused"
                item.stage = "paused"
                item.updated_at = now
            batch.status = "paused"
            batch.updated_at = now
            session.commit()
            session.refresh(batch)
            return batch

    def resume_one_model_batch(self, batch_id: str) -> OneModelBatch:
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(OneModelBatch, batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            if batch.status != "paused":
                raise ValueError("only a paused one-model batch can be resumed")
            paused_items = list(
                session.scalars(
                    select(OneModelBatchItem).where(
                        OneModelBatchItem.batch_id == batch_id,
                        OneModelBatchItem.status == "paused",
                    )
                )
            )
            for item in paused_items:
                item.status = "queued"
                item.stage = "queued"
                # A station collection is deterministic in schedule but is not
                # resumable at the sample-file level.  Restart its visible
                # logical progress while retaining cumulative physical attempts
                # and retries for the hard budget and terminal report.
                item.progress_done = 0
                item.error_count = 0
                item.updated_at = now
            batch.status = "running"
            batch.updated_at = now
            batch.completed_at = None
            self._refresh_one_model_batch_progress(session, batch, now)
            session.commit()
            session.refresh(batch)
            return batch

    def request_one_model_batch_cancel(self, batch_id: str) -> OneModelBatch:
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(OneModelBatch, batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            if batch.status in ONE_MODEL_BATCH_TERMINAL_STATUSES:
                return batch
            if batch.status == "finalizing":
                raise ValueError("a finalizing one-model batch cannot be canceled")
            batch.status = "canceling"
            batch.updated_at = now
            session.execute(
                update(OneModelBatchItem)
                .where(
                    OneModelBatchItem.batch_id == batch_id,
                    OneModelBatchItem.status.in_({"queued", "running", "paused"}),
                )
                .values(status="canceling", stage="canceling", updated_at=now)
            )
            session.commit()
            session.refresh(batch)
            return batch

    def cancel_one_model_batch(self, batch_id: str) -> OneModelBatch:
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(OneModelBatch, batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            if batch.status == "canceled":
                return batch
            if batch.status in {"completed", "failed", "interrupted", "finalizing"}:
                raise ValueError("terminal or finalizing one-model batch cannot be canceled")
            unfinished = list(
                session.scalars(
                    select(OneModelBatchItem).where(
                        OneModelBatchItem.batch_id == batch_id,
                        OneModelBatchItem.status.not_in(ONE_MODEL_ITEM_TERMINAL_STATUSES),
                    )
                )
            )
            for item in unfinished:
                item.status = "canceled"
                item.stage = "canceled"
                item.safe_error_code = "batch_canceled"
                item.decision_eligible = False
                item.operational_verdict = "unverifiable"
                item.updated_at = now
                item.completed_at = now
            batch.status = "canceled"
            batch.completed_items = batch.total_items
            batch.failed_items = sum(
                item.status in {"failed", "interrupted"}
                for item in self.list_one_model_batch_items_in_session(session, batch_id)
            )
            batch.progress_done = min(
                batch.progress_total,
                sum(
                    item.progress_done
                    for item in self.list_one_model_batch_items_in_session(session, batch_id)
                ),
            )
            batch.updated_at = now
            batch.completed_at = now
            session.commit()
            session.refresh(batch)
            return batch

    @staticmethod
    def list_one_model_batch_items_in_session(
        session: Session,
        batch_id: str,
    ) -> list[OneModelBatchItem]:
        return list(
            session.scalars(
                select(OneModelBatchItem)
                .where(OneModelBatchItem.batch_id == batch_id)
                .order_by(OneModelBatchItem.sequence.asc())
            )
        )

    def attach_one_model_batch_report(
        self,
        batch_id: str,
        *,
        status: str,
        report_path: str,
        report_sha256: str,
        expected_status: str,
        expected_updated_at: datetime,
    ) -> OneModelBatch:
        if status not in ONE_MODEL_BATCH_TERMINAL_STATUSES:
            raise ValueError("one-model report requires a terminal batch status")
        if expected_status not in {"finalizing", *ONE_MODEL_BATCH_TERMINAL_STATUSES}:
            raise ValueError("one-model report requires a finalization lease")
        if not isinstance(expected_updated_at, datetime):
            raise ValueError("one-model report requires a finalization timestamp")
        if not Path(report_path).is_absolute():
            raise ValueError("one-model report path must be absolute")
        _validate_lower_sha256(report_sha256, "report_sha256")
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(OneModelBatch, batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            items = self.list_one_model_batch_items_in_session(session, batch_id)
            if len(items) != batch.total_items or any(
                item.status not in ONE_MODEL_ITEM_TERMINAL_STATUSES for item in items
            ):
                raise ValueError("one-model report requires every input row to be terminal")
            if batch.report_path is not None or batch.report_sha256 is not None:
                raise ValueError("one-model batch report is immutable")
            result = session.execute(
                update(OneModelBatch)
                .where(
                    OneModelBatch.id == batch_id,
                    OneModelBatch.status == expected_status,
                    OneModelBatch.updated_at == expected_updated_at,
                    OneModelBatch.report_path.is_(None),
                    OneModelBatch.report_sha256.is_(None),
                )
                .values(
                    status=status,
                    completed_items=batch.total_items,
                    report_path=report_path,
                    report_sha256=report_sha256,
                    updated_at=now,
                    completed_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                session.rollback()
                raise ValueError("one-model report finalization lease expired")
            session.commit()
            session.refresh(batch)
            return batch

    def fail_one_model_batch_finalization(
        self,
        batch_id: str,
        *,
        expected_status: str,
        expected_updated_at: datetime,
    ) -> OneModelBatch:
        """Fail closed when a terminal batch report cannot be published.

        Sampling counters and immutable item results are deliberately left
        untouched: this transition records a report-finalization failure, not
        a new sampling result.
        """

        if expected_status not in {"finalizing", *ONE_MODEL_BATCH_TERMINAL_STATUSES}:
            raise ValueError("one-model batch is not awaiting report finalization")
        if not isinstance(expected_updated_at, datetime):
            raise ValueError("one-model report requires a finalization timestamp")
        now = datetime.now(UTC)
        with self.sessions() as session:
            batch = session.get(OneModelBatch, batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            if batch.report_path is not None or batch.report_sha256 is not None:
                raise ValueError("published one-model batch reports are immutable")
            items = self.list_one_model_batch_items_in_session(session, batch_id)
            if len(items) != batch.total_items or any(
                item.status not in ONE_MODEL_ITEM_TERMINAL_STATUSES for item in items
            ):
                raise ValueError(
                    "one-model report finalization can fail only after every input row is terminal"
                )
            result = session.execute(
                update(OneModelBatch)
                .where(
                    OneModelBatch.id == batch_id,
                    OneModelBatch.status == expected_status,
                    OneModelBatch.updated_at == expected_updated_at,
                    OneModelBatch.report_path.is_(None),
                    OneModelBatch.report_sha256.is_(None),
                )
                .values(
                    status="failed",
                    updated_at=now,
                    completed_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                session.rollback()
                current = session.get(OneModelBatch, batch_id)
                if (
                    current is not None
                    and current.status == "failed"
                    and current.report_path is None
                    and current.report_sha256 is None
                ):
                    return current
                raise ValueError("one-model report finalization lease expired")
            session.commit()
            session.refresh(batch)
            return batch

    def interrupt_orphaned_one_model_batches(self) -> int:
        """Terminalize every input row after restart without attempting credential reuse."""

        now = datetime.now(UTC)
        interrupted_batches = 0
        with self.sessions() as session:
            batches = list(
                session.scalars(
                    select(OneModelBatch).where(
                        OneModelBatch.status.in_(ONE_MODEL_BATCH_ACTIVE_STATUSES)
                    )
                )
            )
            for batch in batches:
                items = self.list_one_model_batch_items_in_session(session, batch.id)
                for item in items:
                    if item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
                        continue
                    item.status = "interrupted"
                    item.stage = "interrupted"
                    item.safe_error_code = "credential_lost_after_restart"
                    item.decision_eligible = False
                    item.operational_verdict = "unverifiable"
                    item.updated_at = now
                    item.completed_at = now
                batch.status = "interrupted"
                batch.completed_items = batch.total_items
                batch.failed_items = sum(
                    item.status in {"failed", "interrupted"} for item in items
                )
                batch.progress_done = min(
                    batch.progress_total,
                    sum(item.progress_done for item in items),
                )
                batch.updated_at = now
                batch.completed_at = now
                interrupted_batches += 1
            session.commit()
        return interrupted_batches
