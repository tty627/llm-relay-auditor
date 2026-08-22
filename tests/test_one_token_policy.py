import copy
import hashlib
import json
import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from relay_auditor.evidence import EvidenceStore
from relay_auditor.one_token_decision import build_safe_decision as _build_safe_decision
from relay_auditor.one_token_policy import (
    POLICY_FORMAT_VERSION,
    ComparisonScope,
    ThresholdPolicy,
    canonical_policy_json,
    load_threshold_policy,
    policy_envelope,
    policy_sha256,
    read_threshold_policy,
    write_threshold_policy,
)

POLICY_ID = "00000000-0000-0000-0000-000000000101"
TRAINING_ID = "00000000-0000-0000-0000-000000000102"
HOLDOUT_ID = "00000000-0000-0000-0000-000000000103"
TRAINING_ID_2 = "00000000-0000-0000-0000-000000000104"
HOLDOUT_ID_2 = "00000000-0000-0000-0000-000000000105"
PROTOCOL_MANIFEST = {
    "manifestVersion": 1,
    "protocolId": "one-token/v2",
    "battery": {"id": "test-battery", "version": "1", "digest": f"sha256:{'1' * 64}"},
    "prompts": {
        "systemPromptDigest": f"sha256:{'2' * 64}",
        "templateDigest": f"sha256:{'3' * 64}",
    },
    "normalization": {
        "id": "test-normalizer",
        "version": "1",
        "digest": f"sha256:{'4' * 64}",
    },
    "sampling": {
        "temperature": 1,
        "topP": None,
        "maxTokens": 16,
        "answerConstraint": "single",
        "reasoningPolicy": "disabled-required",
    },
}
PROFILE_SHA = hashlib.sha256(
    json.dumps(
        PROTOCOL_MANIFEST,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
).hexdigest()
ELIGIBLE_REFERENCE = {
    "ground_truth": "official_first_party",
    "decision_eligible": True,
    "baseline_status": "active",
}


def valid_policy_payload(*, status: str = "validated") -> dict[str, object]:
    result: dict[str, object] = {
        "formatVersion": POLICY_FORMAT_VERSION,
        "id": POLICY_ID,
        "status": status,
        "methodProfileSha256": PROFILE_SHA,
        "modelScope": {
            "environment": "real",
            "providerScope": "provider-a",
            "model": "model-a",
            "protocol": "one-token/v2",
        },
        "cellSelection": ["animal-random:en", "coin-flip:en"],
        "referenceSamplesPerCell": 30,
        "targetSamplesPerCell": 30,
        "minComparableCells": 2,
        "matchMax": 0.2,
        "mismatchMin": 0.4,
        "qualityGates": {
            "requireProtocolMatch": True,
            "requireNoPostReasoning": True,
            "requireZeroReasoningTokens": True,
            "requireDirectnessVerified": True,
            "requireRawEvidence": True,
            "minValidSamplesPerCell": 10,
        },
        "genuineCount": 100,
        "impostorCount": 100,
        "holdoutGenuineCount": 40,
        "holdoutImpostorCount": 40,
        "far": 0.025,
        "frr": 0.05,
        "farConfidenceInterval": {
            "lower": 0.005,
            "upper": 0.08,
            "confidenceLevel": 0.95,
        },
        "frrConfidenceInterval": {
            "lower": 0.015,
            "upper": 0.12,
            "confidenceLevel": 0.95,
        },
        "sourceArtifactIds": {
            "training": [TRAINING_ID_2, TRAINING_ID],
            "holdout": [HOLDOUT_ID_2, HOLDOUT_ID],
        },
    }
    if status == "draft":
        for field in (
            "matchMax",
            "mismatchMin",
            "genuineCount",
            "impostorCount",
            "holdoutGenuineCount",
            "holdoutImpostorCount",
            "far",
            "frr",
            "farConfidenceInterval",
            "frrConfidenceInterval",
            "sourceArtifactIds",
        ):
            result.pop(field)
    return result


def valid_policy() -> ThresholdPolicy:
    return load_threshold_policy(valid_policy_payload())


ELIGIBLE_REFERENCE.update(
    {
        "calibration_policy_id": POLICY_ID,
        "calibration_policy_sha256": policy_sha256(valid_policy()),
    }
)


def build_safe_decision(*args, **kwargs):
    if args and isinstance(args[0], PolicyComparisonPayload):
        kwargs.setdefault("raw_evidence_jsonl", args[0].raw_evidence_jsonl)
    return _build_safe_decision(*args, **kwargs)


def scope_payload() -> dict[str, object]:
    return {
        "methodProfileSha256": PROFILE_SHA,
        "modelScope": {
            "environment": "real",
            "providerScope": "provider-a",
            "model": "model-a",
            "protocol": "one-token/v2",
        },
        "cellSelection": ["animal-random:en", "coin-flip:en"],
        "referenceSamplesPerCell": 30,
        "targetSamplesPerCell": 30,
        "comparableCells": 2,
        "qualityGates": {
            "requireProtocolMatch": True,
            "requireNoPostReasoning": True,
            "requireZeroReasoningTokens": True,
            "requireDirectnessVerified": True,
            "requireRawEvidence": True,
            "minValidSamplesPerCell": 10,
        },
        "qualityPassed": True,
    }


class PolicyComparisonPayload(dict):
    raw_evidence_jsonl: dict[str, bytes]


def _policy_raw_sidecar(fingerprint: dict[str, object], *, role: str) -> bytes:
    cells = fingerprint["cells"]
    assert isinstance(cells, dict)
    samples: list[dict[str, object]] = []
    for cell_id in sorted(cells):
        cell = cells[cell_id]
        assert isinstance(cell, dict)
        counts = cell["counts"]
        assert isinstance(counts, dict)
        planned = [
            normalized for normalized, count in sorted(counts.items()) for _ in range(int(count))
        ]
        for repetition, normalized in enumerate(planned):
            samples.append(
                {
                    "evidenceVersion": 1,
                    "protocolId": fingerprint["protocol"],
                    "role": role,
                    "requestedModel": fingerprint["model"],
                    "jobId": hashlib.sha256(f"{cell_id}\0{repetition}".encode()).hexdigest(),
                    "cellId": cell_id,
                    "repetitionIndex": repetition,
                    "category": "valid",
                    "normalized": normalized,
                    "normalizationCandidate": normalized,
                    "normalizationCategory": "valid",
                    "excludedFromDistribution": False,
                    "exclusionReason": None,
                    "reasoningTraceFields": [],
                    "reasoningTraceCharacterCount": 0,
                    "usage": {"reasoningTokens": 0},
                    "errorKind": None,
                }
            )
    return "".join(
        f"{json.dumps(sample, sort_keys=True, separators=(',', ':'))}\n" for sample in samples
    ).encode()


def comparison_payload() -> PolicyComparisonPayload:
    cell_ids = ["animal-random:en", "coin-flip:en"]
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
            "meanReasoningTokens": 0,
        }
        for cell_id in cell_ids
    }

    def fingerprint(role: str, digest: str) -> dict[str, object]:
        return {
            "formatVersion": 2,
            "protocol": "one-token/v2",
            "model": "model-a",
            "samplesPerCell": 30,
            "postReasoning": False,
            "cells": copy.deepcopy(cells),
            "manifest": copy.deepcopy(PROTOCOL_MANIFEST),
            "plan": {
                "role": role,
                "cellIds": cell_ids,
                "samplesPerCell": 30,
                "expectedSamples": 60,
            },
            "quality": {
                "complete": True,
                "completedSamples": 60,
                "expectedSamples": 60,
                "validSamples": 60,
                "invalidSamples": 0,
                "refusalSamples": 0,
                "emptySamples": 0,
                "errorSamples": 0,
                "directness": "verified",
                "reasoningTraceCount": 0,
                "reasoningTokenCount": 0,
                "reasoningUsageObservedSamples": 60,
                "rawEvidenceSha256": digest,
            },
        }

    result: dict[str, object] = {
        "verdict": "match",
        "comparison": {
            "meanJsd": 0.0,
            "verdict": "match",
            "protocolMismatch": False,
            "compatibility": {
                "compatible": True,
                "status": "compatible",
                "manifestMatch": True,
            },
            "cells": [
                {"cellId": cell_id, "jsd": 0.0, "validA": 30, "validB": 30} for cell_id in cell_ids
            ],
            "comparableCellCount": 2,
        },
        "target": {"fingerprint": fingerprint("audit", "a" * 64)},
        "reference": fingerprint("enrollment", "b" * 64),
    }
    target = result["target"]
    assert isinstance(target, dict)
    target_fingerprint = target["fingerprint"]
    reference_fingerprint = result["reference"]
    assert isinstance(target_fingerprint, dict)
    assert isinstance(reference_fingerprint, dict)
    raw = {
        "target": _policy_raw_sidecar(target_fingerprint, role="audit"),
        "reference": _policy_raw_sidecar(reference_fingerprint, role="enrollment"),
    }
    target_quality = target_fingerprint["quality"]
    reference_quality = reference_fingerprint["quality"]
    assert isinstance(target_quality, dict)
    assert isinstance(reference_quality, dict)
    target_quality["rawEvidenceSha256"] = hashlib.sha256(raw["target"]).hexdigest()
    reference_quality["rawEvidenceSha256"] = hashlib.sha256(raw["reference"]).hexdigest()
    attached = PolicyComparisonPayload(result)
    attached.raw_evidence_jsonl = raw
    return attached


def test_canonical_json_and_sha256_are_stable() -> None:
    policy = valid_policy()
    canonical = canonical_policy_json(policy)
    reordered_payload = valid_policy_payload()
    reordered_payload["cellSelection"] = ["coin-flip:en", "animal-random:en"]
    source_ids = reordered_payload["sourceArtifactIds"]
    assert isinstance(source_ids, dict)
    source_ids["training"] = [TRAINING_ID, TRAINING_ID_2]
    source_ids["holdout"] = [HOLDOUT_ID, HOLDOUT_ID_2]
    reordered = json.dumps(reordered_payload, indent=4, sort_keys=False)

    loaded = load_threshold_policy(reordered, expected_sha256=policy_sha256(policy))

    assert canonical_policy_json(loaded) == canonical
    assert policy_sha256(loaded) == policy_sha256(policy)
    assert loaded.cellSelection == ("animal-random:en", "coin-flip:en")
    assert loaded.sourceArtifactIds is not None
    assert loaded.sourceArtifactIds.training == (TRAINING_ID, TRAINING_ID_2)
    assert loaded.sourceArtifactIds.holdout == (HOLDOUT_ID, HOLDOUT_ID_2)
    assert "\n" not in canonical
    assert " " not in canonical


def test_hash_bound_envelope_detects_tampering() -> None:
    envelope = policy_envelope(valid_policy())
    policy_payload = envelope["policy"]
    assert isinstance(policy_payload, dict)
    policy_payload["matchMax"] = 0.19

    with pytest.raises(ValueError, match="does not match canonical policy content"):
        load_threshold_policy(envelope)


def test_expected_outer_hash_detects_substitution() -> None:
    with pytest.raises(ValueError, match="expected_sha256 does not match"):
        load_threshold_policy(valid_policy_payload(), expected_sha256="b" * 64)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.update({"referenceSamplesPerCell": True}),
        lambda value: value.update({"methodProfileSha256": "A" * 64}),
        lambda value: value.update({"matchMax": math.nan}),
        lambda value: value.update({"matchMax": 0.4, "mismatchMin": 0.4}),
        lambda value: value.update({"minComparableCells": 3}),
        lambda value: value.update({"genuineCount": 0}),
        lambda value: value.update({"far": 0.5}),
    ],
)
def test_malformed_or_invalid_policy_is_rejected(mutation: object) -> None:
    payload = valid_policy_payload()
    mutation(payload)  # type: ignore[operator]

    with pytest.raises((ValidationError, ValueError)):
        load_threshold_policy(payload)


def test_unknown_nested_field_is_rejected() -> None:
    payload = valid_policy_payload()
    scope = payload["modelScope"]
    assert isinstance(scope, dict)
    scope["provider"] = "unexpected"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        load_threshold_policy(payload)


def test_nonfinite_json_and_duplicate_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-finite JSON number"):
        load_threshold_policy('{"far": NaN}')
    duplicate = '{"formatVersion":"one-token-threshold-policy/v1","id":"a","id":"b"}'
    with pytest.raises(ValueError, match="duplicate JSON key: id"):
        load_threshold_policy(duplicate)


def test_training_and_holdout_artifacts_must_be_independent() -> None:
    payload = valid_policy_payload()
    sources = payload["sourceArtifactIds"]
    assert isinstance(sources, dict)
    sources["holdout"] = [TRAINING_ID]

    with pytest.raises(ValidationError, match="training and holdout must be disjoint"):
        load_threshold_policy(payload)


def test_validated_policy_requires_positive_independent_holdout_statistics() -> None:
    payload = valid_policy_payload()
    payload.pop("holdoutImpostorCount")

    with pytest.raises(ValidationError, match="missing complete calibration fields"):
        load_threshold_policy(payload)


@pytest.mark.parametrize("status", ["validated", "retired"])
@pytest.mark.parametrize("gate", ["requireDirectnessVerified", "requireRawEvidence"])
def test_complete_policy_requires_directness_and_raw_evidence_gates(
    status: str,
    gate: str,
) -> None:
    payload = valid_policy_payload(status=status)
    quality_gates = payload["qualityGates"]
    assert isinstance(quality_gates, dict)
    quality_gates[gate] = False

    with pytest.raises(ValidationError, match="requires all safety quality gates"):
        load_threshold_policy(payload)


def test_confidence_interval_must_be_ordered_and_contain_rate() -> None:
    payload = valid_policy_payload()
    payload["farConfidenceInterval"] = {
        "lower": 0.08,
        "upper": 0.01,
        "confidenceLevel": 0.95,
    }
    with pytest.raises(ValidationError, match="lower must not exceed upper"):
        load_threshold_policy(payload)

    payload = valid_policy_payload()
    payload["far"] = 0.5
    with pytest.raises(ValidationError, match="far must fall within"):
        load_threshold_policy(payload)


def test_draft_can_omit_statistics_but_is_not_decision_eligible() -> None:
    draft = load_threshold_policy(valid_policy_payload(status="draft"))

    assert draft.status == "draft"
    assert draft.matchMax is None
    assert draft.decision_eligible is False


def test_decision_gate_revalidates_constructed_policy_instances() -> None:
    bypassed = ThresholdPolicy.model_construct(
        formatVersion=POLICY_FORMAT_VERSION,
        id=POLICY_ID,
        status="validated",
    )

    with pytest.raises(ValidationError):
        build_safe_decision(comparison_payload(), threshold_policy=bypassed)


def test_policy_storage_is_hash_bound_but_not_activated(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    store.initialize()
    policy = valid_policy()

    stored = write_threshold_policy(store, policy)
    loaded = read_threshold_policy(
        store,
        policy.id,
        expected_sha256=stored.policy_sha256,
    )

    assert stored.artifact.path.parent.name == "calibrations"
    assert loaded == policy
    assert policy_sha256(loaded) == stored.policy_sha256


@pytest.mark.parametrize(
    ("change", "expected_reason"),
    [
        ({"methodProfileSha256": "b" * 64}, "method_profile_mismatch"),
        ({"cellSelection": ["animal-random:en"]}, "cell_selection_mismatch"),
        ({"referenceSamplesPerCell": 29}, "reference_samples_per_cell_mismatch"),
        ({"targetSamplesPerCell": 29}, "target_samples_per_cell_mismatch"),
        ({"comparableCells": 1}, "comparable_cells_below_policy_minimum"),
    ],
)
def test_exact_comparison_profile_cell_and_sample_scope_is_required(
    change: dict[str, object],
    expected_reason: str,
) -> None:
    raw_scope = scope_payload()
    raw_scope.update(change)
    scope = ComparisonScope.model_validate(raw_scope)

    result = build_safe_decision(
        comparison_payload(),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=valid_policy(),
        comparison_scope=scope,
    )

    assert result["operationalVerdict"] == "unverifiable"
    assert expected_reason in result["reasons"]
    assert result["decisionEligible"] is False


def test_mock_scope_cannot_use_real_policy() -> None:
    raw_scope = scope_payload()
    raw_scope["modelScope"] = {
        "environment": "mock",
        "providerScope": "provider-a",
        "model": "model-a",
        "protocol": "one-token/v2",
    }
    scope = ComparisonScope.model_validate(raw_scope)

    result = build_safe_decision(
        comparison_payload(),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=valid_policy(),
        comparison_scope=scope,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == ["model_scope_mismatch"]
    assert result["decisionEligible"] is False


def test_same_real_model_from_different_provider_scope_is_rejected() -> None:
    raw_scope = scope_payload()
    model_scope = copy.deepcopy(raw_scope["modelScope"])
    assert isinstance(model_scope, dict)
    model_scope["providerScope"] = "provider-b"
    raw_scope["modelScope"] = model_scope
    scope = ComparisonScope.model_validate(raw_scope)

    result = build_safe_decision(
        comparison_payload(),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=valid_policy(),
        comparison_scope=scope,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == ["model_scope_mismatch"]
    assert result["decisionEligible"] is False


def test_quality_configuration_and_observation_are_both_bound() -> None:
    raw_scope = scope_payload()
    gates = copy.deepcopy(raw_scope["qualityGates"])
    assert isinstance(gates, dict)
    gates["minValidSamplesPerCell"] = 9
    raw_scope["qualityGates"] = gates
    raw_scope["qualityPassed"] = False
    scope = ComparisonScope.model_validate(raw_scope)

    result = build_safe_decision(
        comparison_payload(),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=valid_policy(),
        comparison_scope=scope,
    )

    assert result["reasons"] == [
        "quality_gates_mismatch",
        "comparison_quality_gates_failed",
    ]
