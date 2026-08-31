import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from relay_auditor.database import Database
from relay_auditor.reference_sets import (
    DECISION_ELIGIBLE,
    OPERATIONAL_VERDICT,
    assess_fingerprint_quality,
    build_reference_set_manifest,
    build_reference_statistics,
    canonical_sha256,
    compare_fingerprints,
    compare_target_to_reference,
    load_reference_set_manifest,
    reference_manifest_sha256,
    validate_member_fingerprint,
)
from relay_auditor.schemas import ReferenceSetCreateRequest

CELL_IDS = tuple(f"canonical-task-{index:02d}" for index in range(40))
BATTERY_MANIFEST = {
    "manifestVersion": 1,
    "battery": {
        "id": "canonical40",
        "version": "1.0.0",
        "digest": "sha256:" + "a" * 64,
    },
    "sampling": {
        "temperature": 1,
        "maxTokens": 16,
        "answerConstraint": "single-word-or-number",
    },
}


def _manifest(*, protocol: str = "anthropic_messages") -> dict[str, object]:
    profile = (
        "anthropic-messages-opus5-onetoken-v1"
        if protocol == "anthropic_messages"
        else "openai-chat-onetoken-v1"
    )
    return build_reference_set_manifest(
        protocol=protocol,  # type: ignore[arg-type]
        transport_profile_id=profile,  # type: ignore[arg-type]
        logical_model="opus-5",
        actual_model="claude-opus-5",
        base_url="https://API.Example:443/v1/",
        cell_ids=CELL_IDS,
        battery_manifest=BATTERY_MANIFEST,
    )


def _fingerprint(
    answer: str,
    *,
    model: str = "claude-opus-5",
    valid: int = 30,
    complete: bool = True,
    raw_sha256: str = "b" * 64,
) -> dict[str, object]:
    cells = {
        cell_id: {
            "cellId": cell_id,
            "counts": {answer: valid},
            "validCount": valid,
            "invalidCount": 30 - valid,
            "refusalCount": 0,
            "emptyCount": 0,
            "errorCount": 0,
            "totalCount": 30,
        }
        for cell_id in CELL_IDS
    }
    return {
        "formatVersion": 2,
        "protocol": "bruckner-2026-canonical40/v1",
        "apiProtocol": "anthropic_messages",
        "transportProfileId": "anthropic-messages-opus5-onetoken-v1",
        "model": model,
        "samplesPerCell": 30,
        "postReasoning": False,
        "partial": not complete,
        "cells": cells,
        "manifest": copy.deepcopy(BATTERY_MANIFEST),
        "plan": {
            "role": "enrollment",
            "cellIds": list(CELL_IDS),
            "samplesPerCell": 30,
            "expectedSamples": 1200,
        },
        "quality": {
            "complete": complete,
            "completedSamples": 1200 if complete else 1199,
            "expectedSamples": 1200,
            "validSamples": valid * 40,
            "invalidSamples": (30 - valid) * 40,
            "refusalSamples": 0,
            "emptySamples": 0,
            "errorSamples": 0,
            "directness": "verified",
            "rawEvidenceSha256": raw_sha256,
        },
    }


def _database(tmp_path: Path) -> Database:
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    database.initialize()
    return database


def test_reference_manifest_is_canonical_strict_and_hash_bound() -> None:
    manifest = _manifest()
    loaded = load_reference_set_manifest(manifest)

    assert loaded.normalized_base_url == "https://api.example/v1"
    assert loaded.cell_count == 40
    assert loaded.samples_per_cell == 30
    assert loaded.member_count == 3
    assert reference_manifest_sha256(manifest) == reference_manifest_sha256(
        dict(reversed(list(manifest.items())))
    )

    tampered = copy.deepcopy(manifest)
    tampered["batteryManifest"]["sampling"]["maxTokens"] = 17  # type: ignore[index]
    with pytest.raises(ValueError, match="digest mismatch"):
        load_reference_set_manifest(tampered)

    wrong_size = copy.deepcopy(manifest)
    wrong_size["samplesPerCell"] = 29
    with pytest.raises(ValueError, match="must be 30"):
        load_reference_set_manifest(wrong_size)


def test_reference_set_database_requires_three_members_and_never_promotes_baseline(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    endpoint = database.create_endpoint(
        endpoint_id="10000000-0000-0000-0000-000000000001",
        name="Legacy",
        provider="legacy",
        base_url="https://legacy.example/v1",
        model="legacy-model",
        protocol="openai_chat",
        api_key_env=None,
    )
    database.create_baseline(
        baseline_id="20000000-0000-0000-0000-000000000001",
        endpoint_id=endpoint.id,
        detector="one_token",
        artifact_id="30000000-0000-0000-0000-000000000001",
        valid_from=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
        metadata={},
    )
    assert database.list_reference_sets() == []

    with pytest.raises(ValueError, match="exactly three"):
        database.create_reference_set_queue(
            reference_set_id="40000000-0000-0000-0000-000000000001",
            audit_ids=["50000000-0000-0000-0000-000000000001"],
            scheduler_seeds=["seed-1"],
            reference_name="Official Opus",
            source_type="official_api",
            immutable_manifest=_manifest(),
        )


def test_reference_set_database_seals_members_then_finalizes_once(tmp_path: Path) -> None:
    database = _database(tmp_path)
    reference_set_id = "40000000-0000-0000-0000-000000000001"
    audit_ids = [f"50000000-0000-0000-0000-00000000000{index}" for index in range(1, 4)]
    manifest = _manifest()
    manifest_sha256 = reference_manifest_sha256(manifest)
    fingerprint_manifest_digest = canonical_sha256(BATTERY_MANIFEST)
    created = database.create_reference_set_queue(
        reference_set_id=reference_set_id,
        audit_ids=audit_ids,
        scheduler_seeds=["epoch-one", "epoch-two", "epoch-three"],
        reference_name="Official Opus",
        source_type="official_api",
        immutable_manifest=manifest,
    )

    assert created.status == "collecting"
    assert created.expected_members == 3
    assert [member.ordinal for _, member in database.get_reference_set_rows(reference_set_id)] == [
        1,
        2,
        3,
    ]

    with pytest.raises(ValueError, match="manifest digest mismatch"):
        database.complete_reference_set_member(
            audit_ids[0],
            artifact_id=audit_ids[0],
            artifact_path="/evidence/member-1.json",
            artifact_sha256="1" * 64,
            raw_evidence_sha256="a" * 64,
            reference_manifest_sha256="0" * 64,
            fingerprint_manifest_sha256=fingerprint_manifest_digest,
            quality={"complete": True},
        )

    for index, audit_id in enumerate(audit_ids, start=1):
        member = database.complete_reference_set_member(
            audit_id,
            artifact_id=audit_id,
            artifact_path=f"/evidence/member-{index}.json",
            artifact_sha256=str(index) * 64,
            raw_evidence_sha256=chr(96 + index) * 64,
            reference_manifest_sha256=manifest_sha256,
            fingerprint_manifest_sha256=fingerprint_manifest_digest,
            quality={"complete": True, "validSamples": 1200},
        )
        assert member.status == "completed"

    pending = database.get_reference_set(reference_set_id)
    assert pending is not None
    assert pending.status == "validating"
    fingerprints = [_fingerprint("red", raw_sha256=chr(96 + index) * 64) for index in range(1, 4)]
    statistics = build_reference_statistics(
        fingerprints,
        manifest,
        bootstrap_iterations=16,
        seed_material=reference_set_id,
    )
    ready = database.finalize_reference_set(reference_set_id, statistics=statistics)
    assert ready.status == "ready"
    assert ready.reference_envelope == 0
    assert ready.as_dict()["decision_eligible"] is False
    assert database.list_reference_sets(ready_only=True)[0].id == reference_set_id

    with pytest.raises(ValueError, match="immutable"):
        database.finalize_reference_set(reference_set_id, statistics=statistics)
    with pytest.raises(ValueError, match="immutable"):
        database.complete_reference_set_member(
            audit_ids[0],
            artifact_id=audit_ids[0],
            artifact_path="/evidence/replaced.json",
            artifact_sha256="f" * 64,
            raw_evidence_sha256="e" * 64,
            reference_manifest_sha256=manifest_sha256,
            fingerprint_manifest_sha256=fingerprint_manifest_digest,
            quality={"complete": True},
        )


def test_pairwise_jsd_and_bootstrap_are_deterministic() -> None:
    left = _fingerprint("red")
    right = _fingerprint("blue")
    first = compare_fingerprints(
        left,
        right,
        cell_ids=CELL_IDS,
        bootstrap_iterations=32,
        bootstrap_seed="stable-seed",
    )
    second = compare_fingerprints(
        left,
        right,
        cell_ids=CELL_IDS,
        bootstrap_iterations=32,
        bootstrap_seed="stable-seed",
    )

    assert first == second
    assert first["meanJsdBase2"] == pytest.approx(1.0)
    assert first["confidenceInterval95"]["lower"] == pytest.approx(1.0)
    assert first["confidenceInterval95"]["upper"] == pytest.approx(1.0)
    assert first["comparableCellCount"] == 40


def test_target_comparison_uses_envelope_and_fixed_non_decision_semantics() -> None:
    manifest = _manifest()
    members = [_fingerprint("red") for _ in range(3)]
    statistics = build_reference_statistics(
        members,
        manifest,
        bootstrap_iterations=16,
        seed_material="reference",
    )

    like = compare_target_to_reference(
        _fingerprint("red", model="relay-alias"),
        members,
        manifest,
        statistics,
        target_protocol="anthropic_messages",
        target_transport_profile_id="anthropic-messages-opus5-onetoken-v1",
        bootstrap_iterations=16,
    )
    deviation = compare_target_to_reference(
        _fingerprint("blue", model="relay-alias"),
        members,
        manifest,
        statistics,
        target_protocol="anthropic_messages",
        target_transport_profile_id="anthropic-messages-opus5-onetoken-v1",
        bootstrap_iterations=16,
    )

    assert like["status"] == "exploratory_reference_like"
    assert deviation["status"] == "exploratory_reference_deviation"
    for result in (like, deviation):
        assert result["decisionEligible"] is DECISION_ELIGIBLE
        assert result["operationalVerdict"] == OPERATIONAL_VERDICT
        assert len(result["distances"]) == 3
        assert result["medianMeanJsdBase2"] >= 0
        assert result["madMeanJsdBase2"] >= 0


def test_target_quality_and_protocol_failures_take_priority() -> None:
    manifest = _manifest()
    members = [_fingerprint("red") for _ in range(3)]
    statistics = build_reference_statistics(
        members,
        manifest,
        bootstrap_iterations=8,
    )
    low_quality = _fingerprint("red", model="relay-alias", valid=23)

    quality = assess_fingerprint_quality(low_quality, cell_ids=CELL_IDS)
    assert quality["sufficient"] is False
    assert quality["minimumValidPerCellObserved"] == 23
    insufficient = compare_target_to_reference(
        low_quality,
        members,
        manifest,
        statistics,
        bootstrap_iterations=8,
    )
    unsupported = compare_target_to_reference(
        low_quality,
        members,
        manifest,
        statistics,
        failure_status="unsupported_protocol",
        bootstrap_iterations=8,
    )
    cross_protocol = compare_target_to_reference(
        _fingerprint("red", model="relay-alias"),
        members,
        manifest,
        statistics,
        target_protocol="openai_chat",
        bootstrap_iterations=8,
    )
    request_failed = compare_target_to_reference(
        None,
        members,
        manifest,
        statistics,
        failure_status="request_failed",
        bootstrap_iterations=8,
    )

    assert insufficient["status"] == "insufficient_quality"
    assert unsupported["status"] == "unsupported_protocol"
    assert cross_protocol["status"] == "unsupported_protocol"
    assert request_failed["status"] == "request_failed"
    for result in (insufficient, unsupported, cross_protocol, request_failed):
        assert result["decisionEligible"] is False
        assert result["operationalVerdict"] == "unverifiable"


def test_member_integrity_and_reference_request_schema_are_strict() -> None:
    manifest = _manifest()
    fingerprint = _fingerprint("red")
    validate_member_fingerprint(
        fingerprint,
        manifest,
        expected_model="claude-opus-5",
        expected_raw_evidence_sha256="b" * 64,
    )
    tampered = copy.deepcopy(fingerprint)
    tampered["plan"]["samplesPerCell"] = 29  # type: ignore[index]
    with pytest.raises(ValueError, match="plan samples"):
        validate_member_fingerprint(tampered, manifest, expected_model="claude-opus-5")

    request = ReferenceSetCreateRequest.model_validate(
        {
            "reference_name": "Official Opus",
            "source_type": "official_api",
            "protocol": "anthropic_messages",
            "transport_profile_id": "anthropic-messages-opus5-onetoken-v1",
            "logical_model": "opus-5",
            "actual_model": "claude-opus-5",
            "base_url": "https://api.example/v1",
            "credential": {"mode": "ephemeral", "api_key": "secret"},
        }
    )
    assert request.member_count == 3
    assert request.samples_per_cell == 30
    assert request.cell_count == 40
    assert request.credential.reveal_api_key() == "secret"

    invalid = request.model_dump(mode="json")
    invalid["transport_profile_id"] = "openai-chat-onetoken-v1"
    with pytest.raises(ValidationError, match="must match"):
        ReferenceSetCreateRequest.model_validate(invalid)
