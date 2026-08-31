from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import relay_auditor.one_model_batches as batch_module
from relay_auditor.batch_reports import (
    empty_secret_scanner_for_tests,
    load_verified_batch_report,
)
from relay_auditor.credentials import RuntimeCredentialStore
from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import (
    FingerprintPausedError,
    paper_manifest_for_transport,
    paper_profile_cell_ids,
)
from relay_auditor.evidence import EvidenceStore
from relay_auditor.one_model_batches import (
    OneModelBatchManager,
    ResolvedCredential,
)
from relay_auditor.one_model_schemas import OneModelBatchCreateRequest
from relay_auditor.reference_sets import (
    build_reference_set_manifest,
    build_reference_statistics,
    fingerprint_manifest_sha256,
    reference_manifest_sha256,
)
from relay_auditor.strict_preflight import StrictPreflightError

SECRET_PREFIX = "sk-one-model-batch-canary-"
TRANSPORT_PROFILE = "openai-chat-onetoken-v1"


async def _resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return ("8.8.8.8",)


async def _preflight(_resolution, *, model: str, **_kwargs: object) -> dict[str, object]:
    return {
        "statusCode": 200,
        "latencyMs": 2.5,
        "reportedModel": model,
        "protocol": "openai_chat",
    }


def _fingerprint(
    model: str,
    scheduler_seed: str,
    raw_sha256: str,
    *,
    answer: str = "7",
    role: str = "audit",
) -> dict[str, Any]:
    cell_ids = paper_profile_cell_ids()
    cells = {
        cell_id: {
            "cellId": cell_id,
            "counts": {answer: 30},
            "validCount": 30,
            "invalidCount": 0,
            "refusalCount": 0,
            "emptyCount": 0,
            "errorCount": 0,
            "totalCount": 30,
            "entropyBits": 0,
            "normalizedEntropy": 0,
            "medianLatencyMs": 3,
            "meanCompletionTokens": 1,
            "meanReasoningTokens": 0,
        }
        for cell_id in cell_ids
    }
    return {
        "formatVersion": 2,
        "protocol": "bruckner-2026-canonical40/v1",
        "model": model,
        "collectedAt": "2026-08-31T00:00:00.000Z",
        "samplesPerCell": 30,
        "postReasoning": False,
        "cells": cells,
        "manifest": paper_manifest_for_transport(TRANSPORT_PROFILE),
        "plan": {
            "planVersion": 1,
            "role": role,
            "cellIds": list(cell_ids),
            "samplesPerCell": 30,
            "expectedSamples": 1200,
            "schedulerSeed": scheduler_seed,
            "schedulerPolicy": "bruckner-seeded-shuffle-mulberry32-v1",
        },
        "quality": {
            "qualityVersion": 1,
            "complete": True,
            "completedSamples": 1200,
            "expectedSamples": 1200,
            "validSamples": 1200,
            "invalidSamples": 0,
            "refusalSamples": 0,
            "emptySamples": 0,
            "errorSamples": 0,
            "directness": "verified",
            "reasoningTraceCount": 0,
            "reasoningTokenCount": 0,
            "reasoningUsageObservedSamples": 1200,
            "rawEvidenceSha256": raw_sha256,
            "attemptCount": 1200,
            "retryCount": 0,
        },
        "completedSamples": 1200,
        "expectedSamples": 1200,
        "errorCount": 0,
    }


def _ready_reference(database: Database, evidence: EvidenceStore) -> str:
    reference_set_id = str(uuid4())
    audit_ids = [str(uuid4()) for _ in range(3)]
    seeds = [f"reference-member-{ordinal}" for ordinal in range(1, 4)]
    manifest = build_reference_set_manifest(
        protocol="openai_chat",
        transport_profile_id=TRANSPORT_PROFILE,
        logical_model="opus-5",
        actual_model="opus-5-reference",
        base_url="https://reference.example/v1",
        cell_ids=paper_profile_cell_ids(),
        battery_manifest=paper_manifest_for_transport(TRANSPORT_PROFILE),
    )
    database.create_reference_set_queue(
        reference_set_id=reference_set_id,
        audit_ids=audit_ids,
        scheduler_seeds=seeds,
        reference_name="Trusted reference snapshot",
        source_type="trusted_relay",
        immutable_manifest=manifest,
    )
    fingerprints: list[dict[str, Any]] = []
    for audit_id, seed in zip(audit_ids, seeds, strict=True):
        raw_path = evidence.fingerprint_samples_path(audit_id)
        raw_path.write_text('{"sample":1}\n', encoding="utf-8")
        raw_sha256 = evidence.digest_file(raw_path)
        fingerprint = _fingerprint(
            "opus-5-reference",
            seed,
            raw_sha256,
            role="enrollment",
        )
        artifact = evidence.write_json("fingerprints", audit_id, fingerprint)
        database.complete_reference_set_member(
            audit_id,
            artifact_id=audit_id,
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
            raw_evidence_sha256=raw_sha256,
            reference_manifest_sha256=reference_manifest_sha256(manifest),
            fingerprint_manifest_sha256=fingerprint_manifest_sha256(fingerprint),
            quality={**fingerprint["quality"], "splitHalfMeanJsd": 0.0},
        )
        fingerprints.append(fingerprint)
    statistics = build_reference_statistics(
        fingerprints,
        manifest,
        bootstrap_iterations=1,
        seed_material="test-reference",
    )
    # Point-mass fixtures have the same interval for every bootstrap count; mark
    # the sealed fixture with the formal 2,000-iteration production contract.
    for comparison in statistics["pairwiseComparisons"]:
        comparison["confidenceInterval95"]["iterations"] = 2_000
    database.finalize_reference_set(reference_set_id, statistics=statistics)
    return reference_set_id


def _comparison() -> dict[str, Any]:
    return {
        "status": "exploratory_reference_like",
        "reasonCodes": ["within_reference_envelope"],
        "distances": [
            {
                "referenceMemberOrdinal": ordinal,
                "meanJsdBase2": 0.0,
                "confidenceInterval95": {
                    "lower": 0.0,
                    "upper": 0.0,
                    "iterations": 2000,
                    "seed": ordinal,
                    "method": "within-cell-nonparametric-bootstrap/v1",
                },
            }
            for ordinal in range(1, 4)
        ],
        "medianMeanJsdBase2": 0.0,
        "madMeanJsdBase2": 0.0,
        "minimumMeanJsdBase2": 0.0,
        "maximumMeanJsdBase2": 0.0,
        "decisionEligible": False,
        "operationalVerdict": "unverifiable",
    }


class FakeFingerprint:
    def __init__(
        self,
        *,
        delay: float = 0.01,
        block_first: bool = False,
        progress_before_block: bool = False,
    ) -> None:
        self.delay = delay
        self.block_first = block_first
        self.progress_before_block = progress_before_block
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.concurrencies: list[int] = []
        self.retry_budgets: list[int] = []
        self.models: list[str] = []
        self.started = asyncio.Event()
        self._lock = asyncio.Lock()

    async def collect_paper_profile(self, endpoint, **kwargs):
        async with self._lock:
            self.calls += 1
            call_number = self.calls
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.concurrencies.append(kwargs["concurrency"])
            self.retry_budgets.append(kwargs["retry_budget"])
            self.models.append(endpoint.model)
            self.started.set()
        try:
            if self.block_first and call_number == 1:
                if self.progress_before_block:
                    kwargs["progress_callback"](
                        {
                            "stage": "sampling",
                            "done": 137,
                            "errors": 0,
                            "retrying": False,
                            "attemptCount": 139,
                            "retryCount": 2,
                            "retryBudgetUsed": 2,
                        }
                    )
                await kwargs["cancel_event"].wait()
                raise FingerprintPausedError("test control interrupt")
            await asyncio.sleep(self.delay)
            rows = [
                json.dumps(
                    {
                        "sample": index,
                        "latencyMs": float(1 + index % 10),
                        "reportedModel": endpoint.model,
                    }
                )
                for index in range(1200)
            ]
            raw = "\n".join(rows) + "\n"
            kwargs["samples_output_path"].write_text(raw, encoding="utf-8")
            raw_sha256 = hashlib.sha256(raw.encode()).hexdigest()
            fingerprint = _fingerprint(
                endpoint.model,
                kwargs["scheduler_seed"],
                raw_sha256,
            )
            kwargs["output_path"].write_text(json.dumps(fingerprint), encoding="utf-8")
            kwargs["progress_callback"](
                {
                    "stage": "sampling",
                    "done": 1200,
                    "errors": 0,
                    "retrying": False,
                    "attemptCount": 1200,
                    "retryCount": 0,
                    "retryBudgetUsed": 0,
                }
            )
            return {
                "fingerprint": fingerprint,
                "collection": {
                    "splitHalfMeanJsd": 0.0,
                    "attemptCount": 1200,
                    "retryCount": 0,
                },
            }
        finally:
            async with self._lock:
                self.active -= 1


def _request(
    reference_set_id: str,
    count: int,
    *,
    same_origin: bool = False,
    max_parallel_stations: int = 4,
) -> tuple[OneModelBatchCreateRequest, dict[str, ResolvedCredential]]:
    targets: list[dict[str, Any]] = []
    credentials: dict[str, ResolvedCredential] = {}
    for index in range(count):
        row_id = f"row-{index + 1}"
        if same_origin:
            base_url = f"https://shared.example/relay-{index + 1}/v1"
        else:
            base_url = f"https://station-{index + 1}.example/v1"
        secret = f"{SECRET_PREFIX}{index + 1:02d}-Zeta"
        targets.append(
            {
                "row_id": row_id,
                "station_name": f"Relay {index + 1}",
                "base_url": base_url,
                "credential": {"mode": "ephemeral", "api_key": secret},
                "model_id": f"opus-5-relay-{index + 1}",
            }
        )
        credentials[row_id] = ResolvedCredential(secret=secret, source="ephemeral")
    request = OneModelBatchCreateRequest.model_validate(
        {
            "reference_set_id": reference_set_id,
            "default_model_id": "opus-5-default",
            "targets": targets,
            "max_parallel_stations": max_parallel_stations,
            "per_station_concurrency": 3,
            "global_request_concurrency": max_parallel_stations * 3,
            "request_timeout_seconds": 3,
            "station_timeout_seconds": 60,
            "batch_timeout_seconds": 60,
            "retry_budget": 2,
        }
    )
    return request, credentials


def _manager(
    tmp_path: Path,
    fingerprint: FakeFingerprint,
    *,
    preflight_runner=_preflight,
    report_finalization_timeout_seconds: float = 600.0,
) -> tuple[Database, EvidenceStore, RuntimeCredentialStore, OneModelBatchManager, str]:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    reference_set_id = _ready_reference(database, evidence)
    credentials = RuntimeCredentialStore()
    manager = OneModelBatchManager(
        database,
        evidence,
        fingerprint,  # type: ignore[arg-type]
        credentials,
        resolver=_resolver,
        preflight_runner=preflight_runner,
        git_sha="1683796",
        report_finalization_timeout_seconds=report_finalization_timeout_seconds,
    )
    return database, evidence, credentials, manager, reference_set_id


async def _wait_terminal(database: Database, batch_id: str) -> Any:
    for _ in range(1000):
        batch = database.get_one_model_batch(batch_id)
        if batch is not None and batch.status in {
            "completed",
            "failed",
            "canceled",
            "interrupted",
        }:
            return batch
        await asyncio.sleep(0.01)
    raise AssertionError("one-model batch did not reach a terminal state")


@pytest.fixture(autouse=True)
def _fast_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        batch_module,
        "compare_target_to_reference",
        lambda *_args, **_kwargs: _comparison(),
    )


async def test_completed_batch_has_verified_json_and_csv_and_no_credentials(
    tmp_path: Path,
) -> None:
    fingerprint = FakeFingerprint()
    database, evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    request, resolved = _request(reference_set_id, 3)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    batch = await _wait_terminal(database, batch_id)

    assert batch.status == "completed"
    assert batch.completed_items == 3
    assert batch.failed_items == 0
    assert batch.report_path == str(evidence.batch_report_path(batch_id))
    assert evidence.batch_csv_path(batch_id).is_file()
    verified = load_verified_batch_report(
        batch.report_path,
        batch.report_sha256,
        secret_scanner=empty_secret_scanner_for_tests(),
    )
    assert verified.payload["batch"]["input_row_count"] == 3
    assert len(verified.payload["targets"]) == 3
    assert all(target["status"] == "completed" for target in verified.payload["targets"])
    assert all(target["decision_eligible"] is False for target in verified.payload["targets"])
    assert all(
        target["operational_verdict"] == "unverifiable" for target in verified.payload["targets"]
    )
    csv_rows = list(
        csv.DictReader(io.StringIO(evidence.batch_csv_path(batch_id).read_text(encoding="utf-8")))
    )
    assert [row["row_id"] for row in csv_rows] == ["row-1", "row-2", "row-3"]
    assert len(credential_store) == 0

    forbidden = [credential.secret.encode() for credential in resolved.values()]
    persisted = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    assert all(secret not in persisted for secret in forbidden)
    checkpoint = evidence.read_json(evidence.path_for("batch_checkpoints", batch_id))
    assert "credential" not in json.dumps(checkpoint).casefold()


async def test_report_finalization_exception_fails_closed_and_cleans_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = FakeFingerprint()
    database, evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )

    def failed_finalization(*_args: object, **kwargs: object) -> None:
        report_path = kwargs["report_path"]
        csv_path = kwargs["csv_path"]
        assert isinstance(report_path, Path)
        assert isinstance(csv_path, Path)
        report_path.write_text("orphan", encoding="utf-8")
        csv_path.write_text("orphan", encoding="utf-8")
        raise RuntimeError("synthetic report failure")

    monkeypatch.setattr(manager, "_prepare_persisted_report", failed_finalization)
    request, resolved = _request(reference_set_id, 1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    worker = manager._runtimes[batch_id].worker
    assert worker is not None
    await asyncio.wait_for(asyncio.shield(worker), timeout=2)

    batch = database.get_one_model_batch(batch_id)
    assert batch is not None
    assert batch.status == "failed"
    assert batch.completed_items == 1
    assert batch.failed_items == 0
    assert batch.report_path is None
    assert batch.report_sha256 is None
    assert not evidence.batch_report_path(batch_id).exists()
    assert not evidence.batch_csv_path(batch_id).exists()
    assert batch_id not in manager._runtimes
    assert len(credential_store) == 0


async def test_report_cleanup_failure_cannot_prevent_failed_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = FakeFingerprint()
    database, _evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )

    def failed_finalization(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic report failure")

    def failed_cleanup(_batch_id: str) -> None:
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(manager, "_prepare_persisted_report", failed_finalization)
    monkeypatch.setattr(manager, "_discard_unregistered_report_artifacts", failed_cleanup)
    request, resolved = _request(reference_set_id, 1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    worker = manager._runtimes[batch_id].worker
    assert worker is not None
    await asyncio.wait_for(asyncio.shield(worker), timeout=2)

    batch = database.get_one_model_batch(batch_id)
    assert batch is not None and batch.status == "failed"
    assert batch.report_path is None
    assert batch_id not in manager._runtimes
    assert len(credential_store) == 0


async def test_recovery_replaces_unregistered_canonical_orphans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = FakeFingerprint()
    database, evidence, _credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    original_prepare = manager._prepare_persisted_report

    def failed_finalization(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic first finalization failure")

    monkeypatch.setattr(manager, "_prepare_persisted_report", failed_finalization)
    request, resolved = _request(reference_set_id, 1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    batch = await _wait_terminal(database, batch_id)
    assert batch.status == "failed" and batch.report_path is None

    report_path = evidence.batch_report_path(batch_id)
    csv_path = evidence.batch_csv_path(batch_id)
    report_path.write_text("unregistered report orphan", encoding="utf-8")
    csv_path.write_text("unregistered csv orphan", encoding="utf-8")
    monkeypatch.setattr(manager, "_prepare_persisted_report", original_prepare)

    assert await manager.recover_interrupted_reports() == {"generated": 1, "failed": 0}
    recovered = database.get_one_model_batch(batch_id)
    assert recovered is not None and recovered.status == "failed"
    assert recovered.report_path == str(report_path)
    assert recovered.report_sha256 is not None
    assert report_path.read_text(encoding="utf-8") != "unregistered report orphan"
    assert csv_path.read_text(encoding="utf-8") != "unregistered csv orphan"


async def test_hanging_report_finalization_is_bounded_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = FakeFingerprint()
    database, evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
        report_finalization_timeout_seconds=0.02,
    )
    started = threading.Event()
    release = threading.Event()
    original_writer = batch_module.write_terminal_batch_report

    def blocking_report_writer(*args: object, **kwargs: object):
        started.set()
        if not release.wait(timeout=2):
            raise TimeoutError("test report writer was not released")
        return original_writer(*args, **kwargs)

    monkeypatch.setattr(batch_module, "write_terminal_batch_report", blocking_report_writer)
    request, resolved = _request(reference_set_id, 1)
    tick_count = 0
    stop_ticker = asyncio.Event()

    async def ticker() -> None:
        nonlocal tick_count
        while not stop_ticker.is_set():
            tick_count += 1
            await asyncio.sleep(0.002)

    ticker_task = asyncio.create_task(ticker())
    batch_id = await manager.start(request, resolved_credentials=resolved)
    worker = manager._runtimes[batch_id].worker
    assert worker is not None
    assert await asyncio.to_thread(started.wait, 1)
    await asyncio.wait_for(asyncio.shield(worker), timeout=1)
    stop_ticker.set()
    await ticker_task

    batch = database.get_one_model_batch(batch_id)
    assert batch is not None
    assert batch.status == "failed"
    assert batch.completed_items == 1
    assert batch.failed_items == 0
    assert batch.report_path is None
    assert batch.report_sha256 is None
    assert tick_count >= 2
    assert not evidence.batch_report_path(batch_id).exists()
    assert not evidence.batch_csv_path(batch_id).exists()
    assert batch_id not in manager._runtimes
    assert len(credential_store) == 0

    release.set()
    for _ in range(100):
        if not manager._report_finalizers:
            break
        await asyncio.sleep(0.01)
    assert not manager._report_finalizers
    late_batch = database.get_one_model_batch(batch_id)
    assert late_batch is not None and late_batch.status == "failed"
    assert late_batch.report_path is None
    assert not evidence.batch_report_path(batch_id).exists()
    assert not evidence.batch_csv_path(batch_id).exists()
    report_parent = evidence.batch_report_path(batch_id).parent
    csv_parent = evidence.batch_csv_path(batch_id).parent
    assert not list(report_parent.glob(f".{batch_id}.json.*.staging"))
    assert not list(csv_parent.glob(f".{batch_id}.csv.*.staging"))


async def test_cancelled_report_finalization_fails_closed_and_cleans_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = FakeFingerprint()
    database, evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    started = threading.Event()
    release = threading.Event()
    original_writer = batch_module.write_terminal_batch_report

    def blocking_report_writer(*args: object, **kwargs: object):
        started.set()
        if not release.wait(timeout=2):
            raise TimeoutError("test report writer was not released")
        return original_writer(*args, **kwargs)

    monkeypatch.setattr(batch_module, "write_terminal_batch_report", blocking_report_writer)
    request, resolved = _request(reference_set_id, 1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    worker = manager._runtimes[batch_id].worker
    assert worker is not None
    assert await asyncio.to_thread(started.wait, 1)

    worker.cancel()
    with pytest.raises(asyncio.CancelledError):
        await worker

    batch = database.get_one_model_batch(batch_id)
    assert batch is not None and batch.status == "failed"
    assert batch.report_path is None
    assert batch_id not in manager._runtimes
    assert len(credential_store) == 0

    release.set()
    for _ in range(100):
        if not manager._report_finalizers:
            break
        await asyncio.sleep(0.01)
    assert not manager._report_finalizers
    assert not evidence.batch_report_path(batch_id).exists()
    assert not evidence.batch_csv_path(batch_id).exists()


async def test_twenty_inputs_produce_twenty_terminal_rows_with_four_by_three_cap(
    tmp_path: Path,
) -> None:
    fingerprint = FakeFingerprint(delay=0.025)
    database, evidence, _credentials, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    request, resolved = _request(reference_set_id, 20)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    batch = await _wait_terminal(database, batch_id)

    items = database.list_one_model_batch_items(batch_id)
    report = load_verified_batch_report(
        batch.report_path,
        batch.report_sha256,
        secret_scanner=empty_secret_scanner_for_tests(),
    ).payload
    assert len(items) == 20
    assert len(report["targets"]) == 20
    assert [item.row_id for item in items] == [f"row-{index}" for index in range(1, 21)]
    assert all(item.status == "completed" for item in items)
    assert fingerprint.max_active == 4
    assert set(fingerprint.concurrencies) == {3}
    assert fingerprint.max_active * max(fingerprint.concurrencies) <= 12
    assert evidence.batch_csv_path(batch_id).is_file()


async def test_same_origin_targets_are_serialized(tmp_path: Path) -> None:
    fingerprint = FakeFingerprint(delay=0.025)
    database, _evidence, _credentials, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    request, resolved = _request(reference_set_id, 4, same_origin=True)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    await _wait_terminal(database, batch_id)

    assert fingerprint.calls == 4
    assert fingerprint.max_active == 1


async def test_one_station_429_cooldown_does_not_block_another_origin(
    tmp_path: Path,
) -> None:
    first_station_attempts = 0

    async def preflight(_resolution, *, model: str, **_kwargs: object):
        nonlocal first_station_attempts
        if model.endswith("-1"):
            first_station_attempts += 1
            if first_station_attempts == 1:
                raise StrictPreflightError(
                    "upstream_unavailable",
                    status_code=429,
                    transient=True,
                    retry_after_seconds=0.25,
                )
        return {
            "statusCode": 200,
            "latencyMs": 2.5,
            "reportedModel": model,
            "protocol": "openai_chat",
        }

    fingerprint = FakeFingerprint(delay=0.01)
    database, _evidence, _credentials, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
        preflight_runner=preflight,
    )
    request, resolved = _request(reference_set_id, 2, max_parallel_stations=2)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    await asyncio.wait_for(fingerprint.started.wait(), timeout=1)

    assert fingerprint.models[0] == "opus-5-relay-2"
    batch = await _wait_terminal(database, batch_id)
    assert batch.status == "completed"
    assert set(fingerprint.models) == {"opus-5-relay-1", "opus-5-relay-2"}
    assert first_station_attempts == 2


async def test_pause_then_resume_restarts_only_unfinished_work(tmp_path: Path) -> None:
    fingerprint = FakeFingerprint(block_first=True)
    database, _evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    request, resolved = _request(reference_set_id, 2, max_parallel_stations=1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    await asyncio.wait_for(fingerprint.started.wait(), timeout=2)
    await manager.pause(batch_id)

    paused = database.get_one_model_batch(batch_id)
    assert paused is not None and paused.status == "paused"
    assert {item.status for item in database.list_one_model_batch_items(batch_id)} == {"paused"}
    assert len(credential_store) == 2

    await manager.resume(batch_id)
    completed = await _wait_terminal(database, batch_id)
    assert completed.status == "completed"
    assert all(item.status == "completed" for item in database.list_one_model_batch_items(batch_id))
    assert fingerprint.calls == 3
    assert len(credential_store) == 0


async def test_pause_after_progress_preserves_physical_cost_and_retry_budget(
    tmp_path: Path,
) -> None:
    fingerprint = FakeFingerprint(block_first=True, progress_before_block=True)
    database, _evidence, _credentials, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    request, resolved = _request(reference_set_id, 1, max_parallel_stations=1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    runtime = manager._runtimes[batch_id]
    target_runtime = runtime.targets[0]
    await asyncio.wait_for(fingerprint.started.wait(), timeout=2)
    await manager.pause(batch_id)

    paused_item = database.list_one_model_batch_items(batch_id)[0]
    assert paused_item.progress_done == 137
    assert paused_item.request_attempts == 140
    assert paused_item.retry_count == 2
    assert paused_item.retry_budget_used == 2
    remaining_after_pause = target_runtime.remaining_timeout_seconds
    assert 0 < remaining_after_pause < request.station_timeout_seconds

    await manager.resume(batch_id)
    batch = await _wait_terminal(database, batch_id)
    item = database.list_one_model_batch_items(batch_id)[0]
    report = load_verified_batch_report(
        batch.report_path,
        batch.report_sha256,
        secret_scanner=empty_secret_scanner_for_tests(),
    ).payload

    assert batch.status == "completed"
    assert item.request_attempts == 1341
    assert item.retry_count == 2
    assert item.retry_budget_used == 2
    assert fingerprint.retry_budgets == [2, 0]
    assert target_runtime.remaining_timeout_seconds < remaining_after_pause
    assert report["targets"][0]["requests"] == {
        "logical_samples": 1200,
        "attempts": 1341,
        "retries": 2,
        "retry_budget_used": 2,
        "discarded_attempts": 138,
    }


async def test_cancel_interrupts_collection_and_reports_every_input_row(tmp_path: Path) -> None:
    fingerprint = FakeFingerprint(block_first=True)
    database, _evidence, credential_store, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
    )
    request, resolved = _request(reference_set_id, 3, max_parallel_stations=1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    await asyncio.wait_for(fingerprint.started.wait(), timeout=2)
    await manager.cancel(batch_id)
    batch = await _wait_terminal(database, batch_id)

    assert batch.status == "canceled"
    assert len(database.list_one_model_batch_items(batch_id)) == 3
    assert all(item.status == "canceled" for item in database.list_one_model_batch_items(batch_id))
    report = load_verified_batch_report(
        batch.report_path,
        batch.report_sha256,
        secret_scanner=empty_secret_scanner_for_tests(),
    ).payload
    assert len(report["targets"]) == 3
    assert all(target["status"] == "canceled" for target in report["targets"])
    assert len(credential_store) == 0


@pytest.mark.parametrize(
    ("code", "http_status", "exploratory_status"),
    [
        ("authentication_failed", 401, "request_failed"),
        ("unsupported_protocol", 400, "unsupported_protocol"),
    ],
)
async def test_preflight_failure_is_safely_classified_without_body_or_key(
    tmp_path: Path,
    code: str,
    http_status: int,
    exploratory_status: str,
) -> None:
    async def failed_preflight(*_args, **_kwargs):
        raise StrictPreflightError(
            code,
            status_code=http_status,
            transient=False,
        )

    fingerprint = FakeFingerprint()
    database, _evidence, _credentials, manager, reference_set_id = _manager(
        tmp_path,
        fingerprint,
        preflight_runner=failed_preflight,
    )
    request, resolved = _request(reference_set_id, 1)
    batch_id = await manager.start(request, resolved_credentials=resolved)
    batch = await _wait_terminal(database, batch_id)
    item = database.list_one_model_batch_items(batch_id)[0]
    report = load_verified_batch_report(
        batch.report_path,
        batch.report_sha256,
        secret_scanner=empty_secret_scanner_for_tests(),
    ).payload

    assert batch.status == "completed"
    assert item.status == "failed"
    assert item.exploratory_status == exploratory_status
    assert item.safe_error_code == code
    assert item.error_http_status == http_status
    assert item.request_attempts == 1
    assert fingerprint.calls == 0
    assert report["targets"][0]["error"] == {
        "code": code,
        "http_status": http_status,
    }
    encoded_report = Path(batch.report_path).read_bytes()
    assert resolved["row-1"].secret.encode() not in encoded_report
    assert b"response_body" not in encoded_report
