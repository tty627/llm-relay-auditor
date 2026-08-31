import asyncio
import copy
import hashlib
import json
from pathlib import Path

import pytest

from relay_auditor.credentials import RuntimeCredentialStore
from relay_auditor.database import Database, ReferenceSet
from relay_auditor.detectors.fingerprint import FingerprintPausedError
from relay_auditor.evidence import EvidenceIntegrityError, EvidenceStore
from relay_auditor.reference_set_batches import (
    ReferenceSetManager,
    load_verified_reference_bundle,
)
from relay_auditor.schemas import ReferenceSetCreateRequest


def _request() -> ReferenceSetCreateRequest:
    return ReferenceSetCreateRequest.model_validate(
        {
            "reference_name": "Official snapshot",
            "source_type": "official_api",
            "protocol": "openai_chat",
            "transport_profile_id": "openai-chat-onetoken-v1",
            "logical_model": "opus-5",
            "actual_model": "opus-5-actual",
            "base_url": "https://reference.example/v1",
            "credential": {"mode": "ephemeral", "api_key": "sk-reference-canary"},
            "concurrency": 3,
            "request_timeout_seconds": 3,
            "member_timeout_seconds": 60,
        }
    )


async def _resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return ("8.8.8.8",)


async def _preflight(*_args, **_kwargs):
    return {"statusCode": 200, "latencyMs": 1, "reportedModel": "opus-5-actual"}


def _strict_fingerprint(model: str, seed: str, raw_sha: str) -> dict:
    from relay_auditor.detectors.fingerprint import (
        paper_manifest_for_transport,
        paper_profile_cell_ids,
    )

    cell_ids = paper_profile_cell_ids()
    cells = {
        cell_id: {
            "cellId": cell_id,
            "counts": {"7": 30},
            "validCount": 30,
            "invalidCount": 0,
            "refusalCount": 0,
            "emptyCount": 0,
            "errorCount": 0,
            "totalCount": 30,
            "entropyBits": 0,
            "normalizedEntropy": 0,
            "medianLatencyMs": 1,
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
        "manifest": paper_manifest_for_transport("openai-chat-onetoken-v1"),
        "plan": {
            "planVersion": 1,
            "role": "enrollment",
            "cellIds": list(cell_ids),
            "samplesPerCell": 30,
            "expectedSamples": 1200,
            "schedulerSeed": seed,
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
            "rawEvidenceSha256": raw_sha,
            "attemptCount": 1200,
            "retryCount": 0,
        },
        "completedSamples": 1200,
        "expectedSamples": 1200,
        "errorCount": 0,
    }


class FakeFingerprint:
    def __init__(self, *, block_first: bool = False) -> None:
        self.calls: list[str] = []
        self.block_first = block_first
        self.started = asyncio.Event()
        self.retry_budgets: list[int] = []

    async def collect_paper_profile(self, endpoint, **kwargs):
        self.calls.append(kwargs["scheduler_seed"])
        self.retry_budgets.append(kwargs["retry_budget"])
        self.started.set()
        if self.block_first and len(self.calls) == 1:
            kwargs["progress_callback"](
                {
                    "stage": "sampling",
                    "done": 123,
                    "errors": 0,
                    "attemptCount": 125,
                    "retryCount": 2,
                    "retryBudgetUsed": 2,
                }
            )
            await kwargs["cancel_event"].wait()
            raise FingerprintPausedError("test control interrupt")
        samples_path = kwargs["samples_output_path"]
        raw = "".join(f'{{"sample":{index}}}\n' for index in range(1200))
        samples_path.write_text(raw, encoding="utf-8")
        raw_sha = hashlib.sha256(raw.encode()).hexdigest()
        fingerprint = _strict_fingerprint(endpoint.model, kwargs["scheduler_seed"], raw_sha)
        kwargs["output_path"].write_text(json.dumps(fingerprint), encoding="utf-8")
        kwargs["progress_callback"](
            {
                "stage": "sampling",
                "done": 1200,
                "errors": 0,
                "attemptCount": 1200,
                "retryCount": 0,
                "retryBudgetUsed": 0,
            }
        )
        return {
            "fingerprint": fingerprint,
            "collection": {
                "splitHalfMeanJsd": 0,
                "attemptCount": 1200,
                "retryCount": 0,
            },
        }


async def _wait_ready(database: Database, reference_set_id: str) -> None:
    for _ in range(200):
        reference_set = database.get_reference_set(reference_set_id)
        if reference_set is not None and reference_set.status in {
            "ready",
            "failed",
            "interrupted",
        }:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("ReferenceSet did not reach a terminal state")


async def test_reference_set_manager_collects_three_members_and_seals_hashes(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    credentials = RuntimeCredentialStore()
    fingerprint = FakeFingerprint()
    manager = ReferenceSetManager(
        database,
        evidence,
        fingerprint,  # type: ignore[arg-type]
        credentials,
        resolver=_resolver,
        preflight_runner=_preflight,
    )
    reference_set_id = await manager.start(
        _request(),
        credential_secret="sk-reference-canary",
        credential_source="ephemeral",
    )
    await _wait_ready(database, reference_set_id)

    reference_set, members = load_verified_reference_bundle(
        database,
        evidence,
        reference_set_id,
    )
    assert reference_set.status == "ready"
    assert len(members) == 3
    assert len(set(fingerprint.calls)) == 3
    assert reference_set.reference_envelope is not None
    assert len(credentials) == 0
    for _, member, _ in members:
        assert member.request_attempts == 1201
        assert member.retry_count == 0
        assert member.retry_budget_used == 0
        assert member.quality_json["attemptCount"] == 1201
        assert member.quality_json["retryCount"] == 0
        assert member.quality_json["retryBudgetUsed"] == 0
        assert member.quality_json["discardedAttemptCount"] == 0

    with database.sessions() as session:
        stored = session.get(ReferenceSet, reference_set_id)
        assert stored is not None
        tampered_statistics = copy.deepcopy(stored.pairwise_statistics_json)
        tampered_statistics["pairwiseComparisons"][0]["confidenceInterval95"][
            "iterations"
        ] = 1_999
        stored.pairwise_statistics_json = tampered_statistics
        session.commit()
    with pytest.raises(ValueError, match="exactly 2000"):
        load_verified_reference_bundle(database, evidence, reference_set_id)


async def test_ready_reference_becomes_unselectable_when_member_is_tampered(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    manager = ReferenceSetManager(
        database,
        evidence,
        FakeFingerprint(),  # type: ignore[arg-type]
        RuntimeCredentialStore(),
        resolver=_resolver,
        preflight_runner=_preflight,
    )
    reference_set_id = await manager.start(
        _request(),
        credential_secret="sk-reference-canary",
        credential_source="ephemeral",
    )
    await _wait_ready(database, reference_set_id)
    first = database.get_reference_set_rows(reference_set_id)[0][1]
    evidence.fingerprint_path(first.audit_id).write_bytes(b"tampered")

    try:
        load_verified_reference_bundle(database, evidence, reference_set_id)
    except EvidenceIntegrityError:
        pass
    else:
        raise AssertionError("tampered ReferenceSet was still selectable")


async def test_reference_pause_resume_preserves_retry_and_timeout_budgets(
    tmp_path: Path,
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    fingerprint = FakeFingerprint(block_first=True)
    manager = ReferenceSetManager(
        database,
        evidence,
        fingerprint,  # type: ignore[arg-type]
        RuntimeCredentialStore(),
        resolver=_resolver,
        preflight_runner=_preflight,
    )
    reference_set_id = await manager.start(
        _request(),
        credential_secret="sk-reference-canary",
        credential_source="ephemeral",
    )
    runtime = manager._runtimes[reference_set_id]
    first_audit_id = runtime.audit_ids[0]
    await asyncio.wait_for(fingerprint.started.wait(), timeout=2)
    await manager.pause(reference_set_id)

    paused_member = database.get_reference_set_rows(reference_set_id)[0][1]
    assert paused_member.status == "paused"
    assert paused_member.progress_done == 123
    assert paused_member.request_attempts == 126
    assert paused_member.retry_count == 2
    assert paused_member.retry_budget_used == 2
    remaining_after_pause = runtime.member_remaining_seconds[first_audit_id]
    assert 0 < remaining_after_pause < _request().member_timeout_seconds

    await manager.resume(reference_set_id)
    await _wait_ready(database, reference_set_id)
    reference_set, rows = load_verified_reference_bundle(
        database,
        evidence,
        reference_set_id,
    )

    assert reference_set.status == "ready"
    assert fingerprint.calls[0] == fingerprint.calls[1]
    assert len(fingerprint.calls) == 4
    assert fingerprint.retry_budgets == [240, 238, 240, 240]
    assert rows[0][1].request_attempts == 1327
    assert rows[0][1].retry_count == 2
    assert rows[0][1].retry_budget_used == 2
    assert rows[0][1].quality_json["attemptCount"] == 1327
    assert rows[0][1].quality_json["retryCount"] == 2
    assert rows[0][1].quality_json["retryBudgetUsed"] == 2
    assert rows[0][1].quality_json["discardedAttemptCount"] == 124
    assert runtime.member_remaining_seconds[first_audit_id] < remaining_after_pause
