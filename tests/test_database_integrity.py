import asyncio
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from relay_auditor.batches import ComparisonBatchManager
from relay_auditor.database import (
    AuditRun,
    ComparisonBatch,
    ComparisonRecord,
    ComparisonTaskOptions,
    ComparisonTaskProgress,
    Database,
)
from relay_auditor.detectors.fingerprint import FingerprintRunner
from relay_auditor.evidence import EvidenceStore
from relay_auditor.schemas import ConsoleComparisonBatchRequest


def _database(tmp_path: Path) -> Database:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    return database


def _queued_item(audit_id: str) -> dict[str, object]:
    return {
        "audit_id": audit_id,
        "target_base_url": "https://relay.example/v1",
        "model": f"model-{audit_id[-1]}",
        "station_name": "Relay Test",
        "reference_artifact_id": "11111111-1111-1111-1111-111111111111",
        "reference_name": "Reference",
        "reference_model": "reference-model",
        "priority": 50,
    }


def test_comparison_batch_queue_is_committed_as_one_transaction(tmp_path: Path) -> None:
    database = _database(tmp_path)
    database.create_comparison_batch_queue(
        batch_id="22222222-2222-2222-2222-222222222222",
        items=[
            _queued_item("33333333-3333-3333-3333-333333333331"),
            _queued_item("33333333-3333-3333-3333-333333333332"),
        ],
        cells=4,
        samples=15,
        concurrency=3,
        concurrency_mode="fixed",
    )

    with database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(ComparisonBatch)) == 1
        assert session.scalar(select(func.count()).select_from(AuditRun)) == 2
        assert session.scalar(select(func.count()).select_from(ComparisonRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ComparisonTaskProgress)) == 2
        assert session.scalar(select(func.count()).select_from(ComparisonTaskOptions)) == 2


def test_comparison_batch_queue_rolls_back_every_row_on_failure(tmp_path: Path) -> None:
    database = _database(tmp_path)
    duplicate_id = "33333333-3333-3333-3333-333333333333"

    with pytest.raises(IntegrityError):
        database.create_comparison_batch_queue(
            batch_id="22222222-2222-2222-2222-222222222222",
            items=[_queued_item(duplicate_id), _queued_item(duplicate_id)],
            cells=4,
            samples=15,
            concurrency=3,
            concurrency_mode="fixed",
        )

    with database.sessions() as session:
        for table in (
            ComparisonBatch,
            AuditRun,
            ComparisonRecord,
            ComparisonTaskProgress,
            ComparisonTaskOptions,
        ):
            assert session.scalar(select(func.count()).select_from(table)) == 0


def test_startup_interrupts_nonterminal_verify_run_without_comparison_record(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    audit_id = "33333333-3333-3333-3333-333333333339"
    database.create_run(
        audit_id=audit_id,
        detector="one_token_verify",
        target_base_url="https://relay.example/v1",
        model="target-model",
        status="queued",
    )

    assert database.interrupt_orphaned_comparison_batches() == 1
    run = database.get_run(audit_id)
    assert run is not None
    assert run.status == "interrupted"
    assert run.verdict == "error"
    assert "登记未完整提交" in (run.error_message or "")


def test_endpoint_upsert_preserves_identity_and_credential_provenance(tmp_path: Path) -> None:
    database = _database(tmp_path)
    original = database.create_endpoint(
        endpoint_id="44444444-4444-4444-4444-444444444441",
        name="Official",
        provider="provider-a",
        base_url="https://official.example/v1",
        model="model-a",
        protocol="openai_chat",
        api_key_env="OFFICIAL_API_KEY",
    )

    exact = database.upsert_endpoint(
        endpoint_id="44444444-4444-4444-4444-444444444442",
        name="Renamed by caller",
        provider="provider-a",
        base_url="https://official.example/v1",
        model="model-a",
        protocol="openai_chat",
    )
    conflict = database.upsert_endpoint(
        endpoint_id="44444444-4444-4444-4444-444444444443",
        name="Official",
        provider="provider-b",
        base_url="https://relay.example/v1",
        model="model-b",
        protocol="openai_chat",
    )

    assert exact.id == original.id
    assert exact.name == "Official"
    assert exact.api_key_env == "OFFICIAL_API_KEY"
    assert conflict.id != original.id
    assert conflict.name.startswith("Official-")
    persisted_original = database.get_endpoint(original.id)
    assert persisted_original is not None
    assert persisted_original.provider == "provider-a"
    assert persisted_original.base_url == "https://official.example/v1"
    assert persisted_original.model == "model-a"
    assert persisted_original.api_key_env == "OFFICIAL_API_KEY"


def test_batch_reference_requires_canonical_path_and_persisted_digest(tmp_path: Path) -> None:
    database = _database(tmp_path)
    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    artifact_id = "11111111-1111-1111-1111-111111111111"
    artifact = evidence.write_json("fingerprints", artifact_id, {"protocol": "one-token/v1"})
    database.create_run(
        audit_id=artifact_id,
        detector="one_token_collect",
        target_base_url="https://official.example/v1",
        model="reference-model",
    )
    database.finish_run(
        artifact_id,
        status="completed",
        verdict="recorded",
        artifact_path=str(artifact.path),
        artifact_sha256=artifact.sha256,
    )
    manager = ComparisonBatchManager(
        database,
        evidence,
        FingerprintRunner(tmp_path / "unused-cli.js"),
    )

    assert manager._verified_reference_path(artifact_id) == artifact.path.resolve()
    artifact.path.write_text('{"protocol":"tampered"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        manager._verified_reference_path(artifact_id)

    restored = evidence.write_json("fingerprints", artifact_id, {"protocol": "one-token/v1"})
    database.finish_run(
        artifact_id,
        status="completed",
        verdict="recorded",
        artifact_path=str(tmp_path / "alternate.json"),
        artifact_sha256=restored.sha256,
    )
    with pytest.raises(ValueError, match="path does not match"):
        manager._verified_reference_path(artifact_id)

    missing_record_id = "11111111-1111-1111-1111-111111111112"
    evidence.write_json("fingerprints", missing_record_id, {"protocol": "one-token/v1"})
    with pytest.raises(ValueError, match="audit record not found"):
        manager._verified_reference_path(missing_record_id)


def test_batch_runtime_is_not_published_when_atomic_insert_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path)
    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    artifact_id = "11111111-1111-1111-1111-111111111111"
    artifact = evidence.write_json("fingerprints", artifact_id, {"protocol": "one-token/v1"})
    database.create_run(
        audit_id=artifact_id,
        detector="one_token_collect",
        target_base_url="https://official.example/v1",
        model="reference-model",
    )
    database.finish_run(
        artifact_id,
        status="completed",
        verdict="recorded",
        artifact_path=str(artifact.path),
        artifact_sha256=artifact.sha256,
    )
    manager = ComparisonBatchManager(
        database,
        evidence,
        FingerprintRunner(tmp_path / "unused-cli.js"),
    )
    request = ConsoleComparisonBatchRequest.model_validate(
        {
            "items": [
                {
                    "endpoint": {
                        "base_url": "https://relay.example/v1",
                        "model": "target-model",
                    },
                    "reference_artifact_id": artifact_id,
                    "station_name": "Relay Test",
                    "reference_name": "Reference",
                    "reference_model": "reference-model",
                }
            ]
        }
    )

    def fail_insert(**kwargs):
        raise RuntimeError("injected transaction failure")

    monkeypatch.setattr(database, "create_comparison_batch_queue", fail_insert)

    async def exercise() -> None:
        with pytest.raises(RuntimeError, match="injected transaction failure"):
            manager.start(request)
        assert manager._runtimes == {}

    asyncio.run(exercise())
