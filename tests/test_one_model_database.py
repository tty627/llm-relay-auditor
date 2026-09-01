from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from relay_auditor.database import (
    Database,
    OneModelBatch,
    OneModelBatchItem,
    ReferenceSet,
    ReferenceSetMember,
)
from relay_auditor.reference_sets import build_reference_set_manifest, reference_manifest_sha256

BATCH_ID = "60000000-0000-0000-0000-000000000001"
REFERENCE_SET_ID = "40000000-0000-0000-0000-000000000001"
ITEM_IDS = (
    "70000000-0000-0000-0000-000000000001",
    "70000000-0000-0000-0000-000000000002",
)


def _database(tmp_path: Path) -> Database:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    return database


def _reference_manifest() -> dict[str, object]:
    return build_reference_set_manifest(
        protocol="anthropic_messages",
        transport_profile_id="anthropic-messages-opus5-onetoken-v1",
        logical_model="opus-5",
        actual_model="claude-opus-5",
        base_url="https://official.example/v1",
        cell_ids=[f"cell-{index:02d}" for index in range(40)],
        battery_manifest={"id": "canonical40", "transportProfileId": "anthropic"},
    )


def _ready_reference(database: Database) -> None:
    manifest = _reference_manifest()
    now = datetime.now(UTC)
    with database.sessions() as session:
        session.add(
            ReferenceSet(
                id=REFERENCE_SET_ID,
                status="ready",
                reference_name="Official Opus",
                source_type="official_api",
                protocol="anthropic_messages",
                transport_profile_id="anthropic-messages-opus5-onetoken-v1",
                logical_model="opus-5",
                actual_model="claude-opus-5",
                normalized_base_url="https://official.example/v1",
                cell_count=40,
                samples_per_cell=30,
                expected_members=3,
                immutable_manifest_json=manifest,
                immutable_manifest_sha256=reference_manifest_sha256(manifest),
                pairwise_statistics_json={"referenceEnvelope": 0.1},
                reference_envelope=0.1,
                created_at=now,
                completed_at=now,
            )
        )
        session.commit()


def _items() -> list[dict[str, str]]:
    return [
        {
            "item_id": ITEM_IDS[0],
            "row_id": "relay-a",
            "station_name": "Relay A",
            "canonical_base_url": "https://relay-a.example/v1",
            "model": "opus-alias-a",
        },
        {
            "item_id": ITEM_IDS[1],
            "row_id": "relay-b",
            "station_name": "Relay B",
            "canonical_base_url": "https://relay-b.example/v1",
            "model": "opus-alias-b",
        },
    ]


def _create_batch(database: Database) -> OneModelBatch:
    return database.create_one_model_batch_queue(
        batch_id=BATCH_ID,
        reference_set_id=REFERENCE_SET_ID,
        protocol="anthropic_messages",
        transport_profile_id="anthropic-messages-opus5-onetoken-v1",
        default_model="claude-opus-5",
        items=_items(),
    )


def _finish_completed(database: Database, item_id: str, tmp_path: Path) -> None:
    database.finish_one_model_batch_item(
        item_id,
        status="completed",
        exploratory_status="exploratory_reference_like",
        latency_p50_ms=100,
        latency_p95_ms=180,
        quality={
            "valid_samples": 1200,
            "invalid_samples": 0,
            "error_samples": 0,
            "coverage_cells": 40,
            "total_cells": 40,
            "directness": "verified",
            "split_half_mean_jsd": 0.01,
        },
        comparison_json_path=str((tmp_path / f"{item_id}.json").resolve()),
        comparison_json_sha256="a" * 64,
        artifact_id=item_id,
        artifact_sha256="b" * 64,
        raw_evidence_sha256="c" * 64,
    )


def test_models_have_constraints_and_no_credential_persistence_columns() -> None:
    forbidden = {
        "credential_ref",
        "credential",
        "api_key",
        "api_key_env",
        "env_name",
        "key_hash",
        "upstream_body",
        "error_body",
    }
    batch_columns = {column.name for column in OneModelBatch.__table__.columns}
    item_columns = {column.name for column in OneModelBatchItem.__table__.columns}

    assert forbidden.isdisjoint(batch_columns)
    assert forbidden.isdisjoint(item_columns)
    assert {"reference_set_id", "protocol", "transport_profile_id"} <= batch_columns
    assert {"row_id", "canonical_base_url", "comparison_json_sha256"} <= item_columns
    assert len(OneModelBatchItem.__table__.foreign_keys) == 1
    assert len(OneModelBatch.__table__.foreign_keys) == 1


def test_atomic_batch_creation_persists_exactly_one_item_per_input_row(tmp_path: Path) -> None:
    database = _database(tmp_path)
    _ready_reference(database)
    batch = _create_batch(database)

    assert batch.status == "running"
    assert batch.total_items == 2
    assert batch.progress_total == 2400
    rows = database.list_one_model_batch_items(BATCH_ID)
    assert [row.row_id for row in rows] == ["relay-a", "relay-b"]
    assert all(row.progress_total == 1200 for row in rows)
    assert all(row.decision_eligible is False for row in rows)
    assert all(row.operational_verdict == "unverifiable" for row in rows)

    with database.sessions() as session:
        duplicate = OneModelBatchItem(
            id="70000000-0000-0000-0000-000000000009",
            batch_id=BATCH_ID,
            sequence=9,
            row_id="relay-a",
            station_name="Duplicate",
            canonical_base_url="https://duplicate.example/v1",
            model="model",
            status="queued",
            stage="queued",
            progress_done=0,
            progress_total=1200,
            error_count=0,
            request_attempts=0,
            retry_count=0,
            decision_eligible=False,
            operational_verdict="unverifiable",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        session.add(duplicate)
        with pytest.raises(IntegrityError):
            session.commit()


def test_creation_rejects_credential_fields_without_writing_secret(tmp_path: Path) -> None:
    database = _database(tmp_path)
    _ready_reference(database)
    canary = "sk-secret-must-never-be-persisted"
    items = _items()
    items[0]["credential_ref"] = canary

    with pytest.raises(ValueError, match="unsupported persistence fields"):
        database.create_one_model_batch_queue(
            batch_id=BATCH_ID,
            reference_set_id=REFERENCE_SET_ID,
            protocol="anthropic_messages",
            transport_profile_id="anthropic-messages-opus5-onetoken-v1",
            default_model="claude-opus-5",
            items=items,
        )

    with database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(OneModelBatch)) == 0
        assert session.scalar(select(func.count()).select_from(OneModelBatchItem)) == 0
    assert canary.encode() not in (tmp_path / "auditor.db").read_bytes()


def test_progress_results_and_terminal_report_are_immutable(tmp_path: Path) -> None:
    database = _database(tmp_path)
    _ready_reference(database)
    _create_batch(database)
    item = database.update_one_model_batch_item_progress(
        ITEM_IDS[0],
        status="running",
        stage="sampling",
        done=120,
        errors=1,
        request_attempts=121,
        retry_count=1,
        retry_budget_used=1,
    )
    assert item.progress_done == 120
    assert database.get_one_model_batch(BATCH_ID).progress_done == 120  # type: ignore[union-attr]

    _finish_completed(database, ITEM_IDS[0], tmp_path)
    failed = database.finish_one_model_batch_item(
        ITEM_IDS[1],
        status="failed",
        exploratory_status="request_failed",
        safe_error_code="upstream_auth_failed",
        error_http_status=401,
        quality={},
    )
    assert failed.safe_error_code == "upstream_auth_failed"
    finalizing = database.get_one_model_batch(BATCH_ID)
    assert finalizing is not None
    assert finalizing.status == "finalizing"
    assert finalizing.completed_items == 2

    report = database.attach_one_model_batch_report(
        BATCH_ID,
        status="completed",
        report_path=str((tmp_path / "report.json").resolve()),
        report_sha256="d" * 64,
        expected_status=finalizing.status,
        expected_updated_at=finalizing.updated_at,
    )
    assert report.status == "completed"
    assert report.report_sha256 == "d" * 64
    with pytest.raises(ValueError, match="immutable"):
        database.attach_one_model_batch_report(
            BATCH_ID,
            status="completed",
            report_path=str((tmp_path / "replacement.json").resolve()),
            report_sha256="e" * 64,
            expected_status=report.status,
            expected_updated_at=report.updated_at,
        )
    with pytest.raises(ValueError, match="immutable"):
        database.finish_one_model_batch_item(
            ITEM_IDS[0],
            status="failed",
            safe_error_code="replacement",
        )


def test_report_finalization_failure_is_terminal_without_recounting_items(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    _ready_reference(database)
    _create_batch(database)
    _finish_completed(database, ITEM_IDS[0], tmp_path)
    database.finish_one_model_batch_item(
        ITEM_IDS[1],
        status="failed",
        exploratory_status="request_failed",
        safe_error_code="network_failed",
        quality={},
    )
    before = database.get_one_model_batch(BATCH_ID)
    assert before is not None and before.status == "finalizing"
    counters = (
        before.completed_items,
        before.failed_items,
        before.progress_done,
        before.progress_total,
    )

    failed = database.fail_one_model_batch_finalization(
        BATCH_ID,
        expected_status=before.status,
        expected_updated_at=before.updated_at,
    )

    assert failed.status == "failed"
    assert failed.report_path is None
    assert failed.report_sha256 is None
    assert failed.completed_at is not None
    assert (
        failed.completed_items,
        failed.failed_items,
        failed.progress_done,
        failed.progress_total,
    ) == counters
    with pytest.raises(ValueError, match="lease expired"):
        database.attach_one_model_batch_report(
            BATCH_ID,
            status="completed",
            report_path=str((tmp_path / "late-report.json").resolve()),
            report_sha256="e" * 64,
            expected_status=before.status,
            expected_updated_at=before.updated_at,
        )


def test_pause_resume_and_cancel_terminalize_every_input_row(tmp_path: Path) -> None:
    database = _database(tmp_path)
    _ready_reference(database)
    _create_batch(database)

    assert database.pause_one_model_batch(BATCH_ID).status == "paused"
    assert {item.status for item in database.list_one_model_batch_items(BATCH_ID)} == {"paused"}
    assert database.resume_one_model_batch(BATCH_ID).status == "running"
    assert {item.status for item in database.list_one_model_batch_items(BATCH_ID)} == {"queued"}
    assert database.request_one_model_batch_cancel(BATCH_ID).status == "canceling"
    canceled = database.cancel_one_model_batch(BATCH_ID)

    assert canceled.status == "canceled"
    assert canceled.completed_items == canceled.total_items
    rows = database.list_one_model_batch_items(BATCH_ID)
    assert len(rows) == 2
    assert all(item.status == "canceled" for item in rows)
    assert all(item.safe_error_code == "batch_canceled" for item in rows)


def test_restart_preserves_finished_rows_and_interrupts_every_unfinished_row(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    _ready_reference(database)
    _create_batch(database)
    _finish_completed(database, ITEM_IDS[0], tmp_path)
    database.update_one_model_batch_item_progress(
        ITEM_IDS[1],
        status="running",
        stage="sampling",
        done=20,
        errors=0,
        request_attempts=20,
        retry_count=0,
        retry_budget_used=0,
    )

    assert database.interrupt_orphaned_one_model_batches() == 1
    batch = database.get_one_model_batch(BATCH_ID)
    rows = database.list_one_model_batch_items(BATCH_ID)
    assert batch is not None
    assert batch.status == "interrupted"
    assert batch.completed_items == batch.total_items
    assert [item.status for item in rows] == ["completed", "interrupted"]
    assert rows[1].safe_error_code == "credential_lost_after_restart"


def test_reference_set_control_status_and_progress_have_no_free_text_detail(tmp_path: Path) -> None:
    database = _database(tmp_path)
    audit_ids = [f"50000000-0000-0000-0000-00000000000{index}" for index in range(1, 4)]
    reference_set = database.create_reference_set_queue(
        reference_set_id=REFERENCE_SET_ID,
        audit_ids=audit_ids,
        scheduler_seeds=["epoch-1", "epoch-2", "epoch-3"],
        reference_name="Official Opus",
        source_type="official_api",
        immutable_manifest=_reference_manifest(),
    )
    assert reference_set.status == "collecting"
    running = database.set_reference_set_member_running(audit_ids[0])
    assert running.status == "running"
    progress = database.update_reference_set_member_progress(
        audit_ids[0],
        stage="sampling",
        done=100,
        errors=1,
        retrying=True,
    )
    assert progress.retry_count == 1
    assert "detail" not in ReferenceSetMember.__table__.columns

    assert database.set_reference_set_status(REFERENCE_SET_ID, "pausing").status == "pausing"
    assert database.pause_reference_set_member(audit_ids[0]).status == "paused"
    assert database.set_reference_set_status(REFERENCE_SET_ID, "paused").status == "paused"
    assert database.set_reference_set_status(REFERENCE_SET_ID, "collecting").status == "collecting"
    assert database.set_reference_set_member_running(audit_ids[0]).status == "running"
