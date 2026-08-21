import copy
import hashlib
import json
import math

import pytest

from relay_auditor.one_token_decision import (
    _RawEvidenceValidationError,
    _rebuild_raw_evidence,
)
from relay_auditor.one_token_decision import (
    build_safe_decision as _build_safe_decision,
)
from relay_auditor.one_token_policy import (
    ComparisonScope,
    load_threshold_policy,
    policy_sha256,
)

QUALITY_GATES = {
    "requireProtocolMatch": True,
    "requireNoPostReasoning": True,
    "requireZeroReasoningTokens": True,
    "requireDirectnessVerified": True,
    "requireRawEvidence": True,
    "minValidSamplesPerCell": 10,
}
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


def distribution_jsd(other_count: int) -> float:
    left_probability = 1.0
    right_primary = (10 - other_count) / 10
    right_other = other_count / 10
    midpoint_primary = (left_probability + right_primary) / 2
    result = 0.5 * left_probability * math.log2(left_probability / midpoint_primary)
    if right_primary > 0:
        result += 0.5 * right_primary * math.log2(right_primary / midpoint_primary)
    if right_other > 0:
        result += 0.5 * right_other * math.log2(right_other / (right_other / 2))
    return result


JSD_BY_OTHER_COUNT = {count: distribution_jsd(count) for count in range(11)}
DEFAULT_JSD = JSD_BY_OTHER_COUNT[2]
VALIDATED_POLICY_PAYLOAD = {
    "formatVersion": "one-token-threshold-policy/v1",
    "id": "00000000-0000-0000-0000-000000000001",
    "status": "validated",
    "methodProfileSha256": PROFILE_SHA,
    "modelScope": {
        "environment": "real",
        "providerScope": "provider-a",
        "model": "model-a",
        "protocol": "one-token/v2",
    },
    "cellSelection": ["random-number-1-100:en"],
    "referenceSamplesPerCell": 10,
    "targetSamplesPerCell": 10,
    "minComparableCells": 1,
    "matchMax": 0.2,
    "mismatchMin": 0.4,
    "qualityGates": QUALITY_GATES,
    "genuineCount": 20,
    "impostorCount": 20,
    "holdoutGenuineCount": 10,
    "holdoutImpostorCount": 10,
    "far": 0.01,
    "frr": 0.02,
    "farConfidenceInterval": {"lower": 0.0, "upper": 0.03, "confidenceLevel": 0.95},
    "frrConfidenceInterval": {"lower": 0.0, "upper": 0.04, "confidenceLevel": 0.95},
    "sourceArtifactIds": {
        "training": ["00000000-0000-0000-0000-000000000010"],
        "holdout": ["00000000-0000-0000-0000-000000000011"],
    },
}
VALIDATED_POLICY = load_threshold_policy(VALIDATED_POLICY_PAYLOAD)
ELIGIBLE_REFERENCE.update(
    {
        "calibration_policy_id": VALIDATED_POLICY.id,
        "calibration_policy_sha256": policy_sha256(VALIDATED_POLICY),
    }
)


def build_safe_decision(*args, **kwargs):
    if args and isinstance(args[0], DecisionPayload):
        kwargs.setdefault("raw_evidence_jsonl", args[0].raw_evidence_jsonl)
    return _build_safe_decision(*args, **kwargs)


VALID_SCOPE = ComparisonScope.model_validate(
    {
        "methodProfileSha256": PROFILE_SHA,
        "modelScope": {
            "environment": "real",
            "providerScope": "provider-a",
            "model": "model-a",
            "protocol": "one-token/v2",
        },
        "cellSelection": ["random-number-1-100:en"],
        "referenceSamplesPerCell": 10,
        "targetSamplesPerCell": 10,
        "comparableCells": 1,
        "qualityGates": QUALITY_GATES,
        "qualityPassed": True,
    }
)


class DecisionPayload(dict):
    raw_evidence_jsonl: dict[str, bytes]


def _raw_sidecar(fingerprint: dict[str, object], *, role: str) -> bytes:
    samples: list[dict[str, object]] = []
    cells = fingerprint["cells"]
    assert isinstance(cells, dict)
    for cell_id in sorted(cells):
        cell = cells[cell_id]
        assert isinstance(cell, dict)
        planned: list[tuple[str, str | None]] = []
        counts = cell["counts"]
        assert isinstance(counts, dict)
        for normalized, count in sorted(counts.items()):
            planned.extend([("valid", str(normalized))] * int(count))
        planned.extend([("invalid", "out-of-range")] * int(cell["invalidCount"]))
        for category in ("refusal", "empty", "error"):
            planned.extend([(category, None)] * int(cell[f"{category}Count"]))
        for repetition, (category, normalized) in enumerate(planned):
            is_error = category == "error"
            samples.append(
                {
                    "evidenceVersion": 1,
                    "protocolId": fingerprint["protocol"],
                    "role": role,
                    "requestedModel": fingerprint["model"],
                    "jobId": hashlib.sha256(f"{cell_id}\0{repetition}".encode()).hexdigest(),
                    "cellId": cell_id,
                    "repetitionIndex": repetition,
                    "category": category,
                    "normalized": normalized,
                    "normalizationCandidate": normalized,
                    "normalizationCategory": None if is_error else category,
                    "excludedFromDistribution": is_error,
                    "exclusionReason": None,
                    "reasoningTraceFields": [],
                    "reasoningTraceCharacterCount": 0,
                    "usage": None if is_error else {"reasoningTokens": 0},
                    "errorKind": "request_failed" if is_error else None,
                }
            )
    return "".join(
        f"{json.dumps(sample, sort_keys=True, separators=(',', ':'))}\n" for sample in samples
    ).encode()


def _attach_raw_sidecars(result: dict[str, object]) -> DecisionPayload:
    target = result["target"]
    assert isinstance(target, dict)
    target_fingerprint = target["fingerprint"]
    reference_fingerprint = result["reference"]
    assert isinstance(target_fingerprint, dict)
    assert isinstance(reference_fingerprint, dict)
    raw = {
        "target": _raw_sidecar(target_fingerprint, role="audit"),
        "reference": _raw_sidecar(reference_fingerprint, role="enrollment"),
    }
    target_quality = target_fingerprint["quality"]
    reference_quality = reference_fingerprint["quality"]
    assert isinstance(target_quality, dict)
    assert isinstance(reference_quality, dict)
    target_quality["rawEvidenceSha256"] = hashlib.sha256(raw["target"]).hexdigest()
    reference_quality["rawEvidenceSha256"] = hashlib.sha256(raw["reference"]).hexdigest()
    attached = DecisionPayload(result)
    attached.raw_evidence_jsonl = raw
    return attached


def payload(
    mean_jsd: float | None = DEFAULT_JSD,
    *,
    verdict: str = "match",
    protocol_mismatch: bool = False,
) -> dict[str, object]:
    cell_id = "random-number-1-100:en"
    other_count = next(
        (
            count
            for count, expected_jsd in JSD_BY_OTHER_COUNT.items()
            if isinstance(mean_jsd, (int, float))
            and not isinstance(mean_jsd, bool)
            and math.isfinite(mean_jsd)
            and abs(float(mean_jsd) - expected_jsd) <= 1e-12
        ),
        2,
    )

    def fingerprint(role: str, raw_sha: str, *, target: bool) -> dict[str, object]:
        counts = {"7": 10}
        if target and other_count:
            counts = {"7": 10 - other_count, "8": other_count}
            if counts["7"] == 0:
                counts.pop("7")
        cell = {
            "cellId": cell_id,
            "counts": counts,
            "validCount": 10,
            "invalidCount": 0,
            "refusalCount": 0,
            "emptyCount": 0,
            "errorCount": 0,
            "totalCount": 10,
            "meanReasoningTokens": 0,
        }
        return {
            "formatVersion": 2,
            "protocol": "one-token/v2",
            "model": "model-a",
            "samplesPerCell": 10,
            "postReasoning": False,
            "cells": {cell_id: dict(cell)},
            "manifest": copy.deepcopy(PROTOCOL_MANIFEST),
            "plan": {
                "role": role,
                "cellIds": [cell_id],
                "samplesPerCell": 10,
                "expectedSamples": 10,
            },
            "quality": {
                "complete": True,
                "completedSamples": 10,
                "expectedSamples": 10,
                "validSamples": 10,
                "invalidSamples": 0,
                "refusalSamples": 0,
                "emptySamples": 0,
                "errorSamples": 0,
                "directness": "verified",
                "reasoningTraceCount": 0,
                "reasoningTokenCount": 0,
                "reasoningUsageObservedSamples": 10,
                "rawEvidenceSha256": raw_sha,
            },
        }

    cell_jsd = JSD_BY_OTHER_COUNT[other_count]
    result: dict[str, object] = {
        "verdict": verdict,
        "comparison": {
            "meanJsd": mean_jsd,
            "verdict": verdict,
            "protocolMismatch": protocol_mismatch,
            "compatibility": {
                "compatible": not protocol_mismatch,
                "status": "compatible" if not protocol_mismatch else "incompatible",
                "manifestMatch": not protocol_mismatch,
            },
            "cells": [
                {
                    "cellId": cell_id,
                    "jsd": cell_jsd,
                    "validA": 10,
                    "validB": 10,
                }
            ],
            "comparableCellCount": 1,
        },
        "target": {"fingerprint": fingerprint("audit", "a" * 64, target=True)},
        "reference": fingerprint("enrollment", "b" * 64, target=False),
    }
    return _attach_raw_sidecars(result)


@pytest.mark.parametrize(
    ("mean_jsd", "expected"),
    [
        (JSD_BY_OTHER_COUNT[0], "match"),
        (JSD_BY_OTHER_COUNT[3], "match"),
        (JSD_BY_OTHER_COUNT[4], "uncertain"),
        (JSD_BY_OTHER_COUNT[6], "uncertain"),
        (JSD_BY_OTHER_COUNT[7], "mismatch"),
        (JSD_BY_OTHER_COUNT[10], "mismatch"),
    ],
)
def test_validated_policy_produces_operational_verdict(
    mean_jsd: float,
    expected: str,
) -> None:
    result = build_safe_decision(
        payload(mean_jsd),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result == {
        "operationalVerdict": expected,
        "status": "calibrated",
        "reasons": [],
        "legacyVerdict": "match",
        "rawMeanJsd": mean_jsd,
        "decisionEligible": True,
        "thresholdPolicyId": VALIDATED_POLICY.id,
        "thresholdPolicySha256": policy_sha256(VALIDATED_POLICY),
    }


def test_validated_policy_accepts_online_verify_target_as_comparison_a() -> None:
    policy_data = copy.deepcopy(VALIDATED_POLICY_PAYLOAD)
    policy_data["qualityGates"]["minValidSamplesPerCell"] = 9
    policy = load_threshold_policy(policy_data)
    scope_data = VALID_SCOPE.model_dump(mode="json")
    scope_data["qualityGates"]["minValidSamplesPerCell"] = 9
    scope = ComparisonScope.model_validate(scope_data)
    sample = payload(JSD_BY_OTHER_COUNT[0])
    target = sample["target"]["fingerprint"]  # type: ignore[index]
    target_cell = target["cells"]["random-number-1-100:en"]  # type: ignore[index]
    target_cell["counts"] = {"7": 9}
    target_cell["validCount"] = 9
    target_cell["invalidCount"] = 1
    target["quality"]["validSamples"] = 9  # type: ignore[index]
    target["quality"]["invalidSamples"] = 1  # type: ignore[index]
    # Node verify calls compare(target, reference), so A is the target here.
    sample["comparison"]["cells"][0].update({"validA": 9, "validB": 10})  # type: ignore[index]
    sample = _attach_raw_sidecars(dict(sample))

    result = build_safe_decision(
        sample,
        reference_metadata={
            **ELIGIBLE_REFERENCE,
            "calibration_policy_sha256": policy_sha256(policy),
        },
        threshold_policy=policy,
        comparison_scope=scope,
    )

    assert result["status"] == "calibrated"
    assert result["operationalVerdict"] == "match"


def test_explicit_legacy_verdict_overrides_payload() -> None:
    mismatch_jsd = JSD_BY_OTHER_COUNT[7]
    result = build_safe_decision(
        payload(mismatch_jsd, verdict="match"),
        legacy_verdict="mismatch",
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["legacyVerdict"] == "mismatch"
    assert result["operationalVerdict"] == "mismatch"


@pytest.mark.parametrize(
    ("mean_jsd", "legacy_verdict", "expected_reasons"),
    [
        (None, "match", ["mean_jsd_missing"]),
        (0.1, "insufficient", ["legacy_verdict_insufficient"]),
        (
            None,
            "insufficient",
            ["mean_jsd_missing", "legacy_verdict_insufficient"],
        ),
    ],
)
def test_missing_score_or_legacy_insufficient_fails_closed(
    mean_jsd: float | None,
    legacy_verdict: str,
    expected_reasons: list[str],
) -> None:
    result = build_safe_decision(
        payload(mean_jsd, verdict=legacy_verdict),
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["operationalVerdict"] == "unverifiable"
    assert result["status"] == "insufficient"
    assert result["reasons"] == expected_reasons
    assert result["decisionEligible"] is False


def test_protocol_mismatch_is_incompatible_even_for_identical_score() -> None:
    result = build_safe_decision(
        payload(0.0, protocol_mismatch=True),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["operationalVerdict"] == "unverifiable"
    assert result["status"] == "incompatible"
    assert result["reasons"] == ["protocol_mismatch", "v2_compatibility_not_verified"]
    assert result["decisionEligible"] is False


@pytest.mark.parametrize("side", ["target", "reference"])
def test_post_reasoning_is_incompatible(side: str) -> None:
    sample = payload()
    if side == "target":
        sample[side]["fingerprint"]["postReasoning"] = True  # type: ignore[index]
    else:
        sample[side]["postReasoning"] = True  # type: ignore[index]

    result = build_safe_decision(
        sample,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == [f"{side}_post_reasoning"]
    assert result["decisionEligible"] is False


@pytest.mark.parametrize("side", ["target", "reference"])
def test_positive_cell_reasoning_tokens_are_incompatible(side: str) -> None:
    sample = payload()
    fingerprint = sample[side]  # type: ignore[index]
    if side == "target":
        fingerprint = fingerprint["fingerprint"]
    fingerprint["cells"]["random-number-1-100:en"]["meanReasoningTokens"] = 1  # type: ignore[index]

    result = build_safe_decision(
        sample,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == [f"{side}_reasoning_tokens_positive"]


def test_all_incompatibility_reasons_are_preserved() -> None:
    sample = payload(protocol_mismatch=True)
    sample["target"]["fingerprint"]["postReasoning"] = True  # type: ignore[index]
    sample["reference"]["cells"]["random-number-1-100:en"][  # type: ignore[index]
        "meanReasoningTokens"
    ] = 2

    result = build_safe_decision(
        sample,
        reference_metadata={
            **ELIGIBLE_REFERENCE,
            "ground_truth": "relay_snapshot_not_official",
        },
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == [
        "protocol_mismatch",
        "target_post_reasoning",
        "reference_reasoning_tokens_positive",
        "reference_ground_truth_not_eligible",
        "v2_compatibility_not_verified",
    ]


@pytest.mark.parametrize(
    "ground_truth",
    ["official_first_party", "attested_cross_provider"],
)
def test_eligible_ground_truth_can_receive_calibrated_decision(ground_truth: str) -> None:
    result = build_safe_decision(
        payload(),
        reference_metadata={
            **ELIGIBLE_REFERENCE,
            "ground_truth": ground_truth,
        },
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "calibrated"
    assert result["decisionEligible"] is True


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        (lambda value: value.pop("target"), "target_fingerprint_missing"),
        (
            lambda value: value["target"]["fingerprint"]["quality"].update(  # type: ignore[index]
                {"rawEvidenceSha256": None}
            ),
            "target_raw_evidence_hash_missing",
        ),
        (
            lambda value: value["target"]["fingerprint"]["quality"].update(  # type: ignore[index]
                {"directness": "unknown"}
            ),
            "target_directness_not_verified",
        ),
        (
            lambda value: value["target"]["fingerprint"]["manifest"][  # type: ignore[index]
                "prompts"
            ].update({"templateDigest": f"sha256:{'f' * 64}"}),
            "target_method_profile_hash_mismatch",
        ),
        (
            lambda value: value["reference"]["plan"].update({"role": "audit"}),  # type: ignore[index]
            "reference_collection_role_mismatch",
        ),
        (
            lambda value: value["comparison"].update({"cells": []}),  # type: ignore[index]
            "comparison_cell_selection_mismatch",
        ),
        (
            lambda value: value["comparison"]["cells"][0].update({"jsd": 0.2}),  # type: ignore[index]
            "comparison_cell_jsd_evidence_mismatch",
        ),
        (
            lambda value: value["comparison"].update({"meanJsd": 0.2}),  # type: ignore[index]
            "mean_jsd_evidence_mismatch",
        ),
    ],
)
def test_validated_policy_reconstructs_actual_v2_evidence(
    mutation,
    expected_reason: str,
) -> None:
    sample = payload()
    mutation(sample)

    result = build_safe_decision(
        sample,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["operationalVerdict"] == "unverifiable"
    assert result["status"] == "incompatible"
    assert expected_reason in result["reasons"]
    assert result["decisionEligible"] is False


@pytest.mark.parametrize(
    "metadata",
    [
        {"ground_truth": "official_first_party", "baseline_status": "active"},
        {"ground_truth": "official_first_party", "decision_eligible": True},
    ],
)
def test_validated_policy_requires_explicitly_eligible_active_reference(metadata) -> None:
    metadata.update(
        {
            "calibration_policy_id": VALIDATED_POLICY.id,
            "calibration_policy_sha256": policy_sha256(VALIDATED_POLICY),
        }
    )
    result = build_safe_decision(
        payload(),
        reference_metadata=metadata,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert result["decisionEligible"] is False


def test_validated_policy_requires_reference_ground_truth() -> None:
    result = build_safe_decision(
        payload(),
        reference_metadata={
            "reference_name": "Official A",
            "decision_eligible": True,
            "baseline_status": "active",
            "calibration_policy_id": VALIDATED_POLICY.id,
            "calibration_policy_sha256": policy_sha256(VALIDATED_POLICY),
        },
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == ["reference_ground_truth_missing"]


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        (
            "calibration_policy_id",
            "00000000-0000-0000-0000-000000000099",
            "reference_calibration_policy_id_mismatch",
        ),
        (
            "calibration_policy_sha256",
            "f" * 64,
            "reference_calibration_policy_sha256_mismatch",
        ),
    ],
)
def test_validated_policy_requires_exact_reference_policy_binding(
    field: str,
    value: str,
    expected_reason: str,
) -> None:
    metadata = {**ELIGIBLE_REFERENCE, field: value}

    result = build_safe_decision(
        payload(),
        reference_metadata=metadata,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert expected_reason in result["reasons"]
    assert result["decisionEligible"] is False


def _decision_with_target_raw(
    sample: DecisionPayload,
    raw_target: bytes,
    *,
    bind_hash: bool,
) -> dict[str, object]:
    if bind_hash:
        target = sample["target"]
        assert isinstance(target, dict)
        fingerprint = target["fingerprint"]
        assert isinstance(fingerprint, dict)
        quality = fingerprint["quality"]
        assert isinstance(quality, dict)
        quality["rawEvidenceSha256"] = hashlib.sha256(raw_target).hexdigest()
    raw = {**sample.raw_evidence_jsonl, "target": raw_target}
    return _build_safe_decision(
        sample,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
        raw_evidence_jsonl=raw,
    )


def _replace_first_raw_sample(raw_jsonl: bytes, **changes: object) -> bytes:
    lines = raw_jsonl.splitlines()
    first = json.loads(lines[0])
    first.update(changes)
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
    return b"\n".join(lines) + b"\n"


def test_validated_policy_requires_actual_hash_bound_raw_sidecar_bytes() -> None:
    sample = payload()
    missing = _build_safe_decision(
        sample,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )
    assert "reference_raw_evidence_missing" in missing["reasons"]
    assert "target_raw_evidence_missing" in missing["reasons"]

    tampered = _decision_with_target_raw(
        sample,
        sample.raw_evidence_jsonl["target"] + b" ",
        bind_hash=False,
    )
    assert "target_raw_evidence_hash_mismatch" in tampered["reasons"]
    assert tampered["decisionEligible"] is False


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        (
            lambda lines: [b"\xff" + lines[0][1:], *lines[1:]],
            "target_raw_evidence_invalid_utf8",
        ),
        (
            lambda lines: [b"!" + lines[0][1:], *lines[1:]],
            "target_raw_evidence_invalid_json",
        ),
        (
            lambda lines: [
                lines[0].replace(
                    b'"category":"valid"',
                    b'"category":"valid","category":"valid"',
                ),
                *lines[1:],
            ],
            "target_raw_evidence_duplicate_json_key",
        ),
        (
            lambda lines: [lines[0], lines[0], *lines[2:]],
            "target_raw_evidence_duplicate_job",
        ),
        (
            lambda lines: lines[:-1],
            "target_raw_evidence_plan_mismatch",
        ),
    ],
)
def test_validated_policy_rejects_malformed_or_incomplete_raw_sidecars(
    mutation,
    expected_reason: str,
) -> None:
    sample = payload()
    lines = sample.raw_evidence_jsonl["target"].splitlines()
    mutated = b"\n".join(mutation(lines)) + b"\n"

    result = _decision_with_target_raw(sample, mutated, bind_hash=True)

    assert expected_reason in result["reasons"]
    assert result["decisionEligible"] is False


def test_validated_policy_rebuilds_sample_state_and_aggregates_from_raw_sidecar() -> None:
    invalid_state = payload()
    lines = invalid_state.raw_evidence_jsonl["target"].splitlines()
    first = json.loads(lines[0])
    first["excludedFromDistribution"] = True
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
    invalid_result = _decision_with_target_raw(
        invalid_state,
        b"\n".join(lines) + b"\n",
        bind_hash=True,
    )
    assert "target_raw_evidence_sample_state_invalid" in invalid_result["reasons"]

    forged_cell = payload()
    target = forged_cell["target"]
    assert isinstance(target, dict)
    fingerprint = target["fingerprint"]
    assert isinstance(fingerprint, dict)
    cells = fingerprint["cells"]
    assert isinstance(cells, dict)
    cell = cells["random-number-1-100:en"]
    assert isinstance(cell, dict)
    cell["counts"] = {"forged": 10}
    forged_cell_result = build_safe_decision(
        forged_cell,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )
    assert "target_raw_evidence_cell_aggregate_mismatch" in forged_cell_result["reasons"]

    forged_quality = payload()
    target = forged_quality["target"]
    assert isinstance(target, dict)
    fingerprint = target["fingerprint"]
    assert isinstance(fingerprint, dict)
    quality = fingerprint["quality"]
    assert isinstance(quality, dict)
    quality["validSamples"] = 9
    quality["invalidSamples"] = 1
    forged_quality_result = build_safe_decision(
        forged_quality,
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )
    assert "target_raw_evidence_quality_aggregate_mismatch" in forged_quality_result["reasons"]


def test_raw_rebuilder_accepts_canonical_reasoning_invalid_and_contaminated_error() -> None:
    sample = payload()
    target = sample["target"]
    assert isinstance(target, dict)
    fingerprint = target["fingerprint"]
    assert isinstance(fingerprint, dict)
    ordinary = json.loads(sample.raw_evidence_jsonl["target"].splitlines()[0])

    reasoning_invalid = _replace_first_raw_sample(
        sample.raw_evidence_jsonl["target"],
        category="invalid",
        normalized=None,
        normalizationCandidate=ordinary["normalized"],
        normalizationCategory="valid",
        excludedFromDistribution=True,
        exclusionReason="reasoning_contamination",
        reasoningTraceFields=["reasoning"],
        reasoningTraceCharacterCount=4,
        usage={"reasoningTokens": 1},
        errorKind=None,
    )
    rebuilt = _rebuild_raw_evidence(
        reasoning_invalid,
        fingerprint=fingerprint,
        expected_role="audit",
        selected_cells={"random-number-1-100:en"},
        samples_per_cell=10,
    )
    assert rebuilt["invalid"] == 1
    assert rebuilt["reasoningTraceCount"] == 1

    contaminated_error = _replace_first_raw_sample(
        sample.raw_evidence_jsonl["target"],
        category="error",
        normalized=None,
        normalizationCandidate=None,
        normalizationCategory=None,
        excludedFromDistribution=True,
        exclusionReason="provider_error",
        reasoningTraceFields=["reasoning"],
        reasoningTraceCharacterCount=4,
        usage={"reasoningTokens": 1},
        errorKind="provider_error",
    )
    rebuilt = _rebuild_raw_evidence(
        contaminated_error,
        fingerprint=fingerprint,
        expected_role="audit",
        selected_cells={"random-number-1-100:en"},
        samples_per_cell=10,
    )
    assert rebuilt["error"] == 1
    assert rebuilt["directness"] == "violated"


@pytest.mark.parametrize("category", ["valid", "refusal", "empty"])
def test_raw_rebuilder_rejects_contaminated_noninvalid_success_states(category: str) -> None:
    sample = payload()
    target = sample["target"]
    assert isinstance(target, dict)
    fingerprint = target["fingerprint"]
    assert isinstance(fingerprint, dict)
    normalized = "7" if category == "valid" else None
    contaminated = _replace_first_raw_sample(
        sample.raw_evidence_jsonl["target"],
        category=category,
        normalized=normalized,
        normalizationCandidate=normalized,
        normalizationCategory=category,
        excludedFromDistribution=False,
        exclusionReason=None,
        reasoningTraceFields=["reasoning"],
        reasoningTraceCharacterCount=4,
        usage={"reasoningTokens": 1},
        errorKind=None,
    )

    with pytest.raises(_RawEvidenceValidationError, match="sample_state_invalid"):
        _rebuild_raw_evidence(
            contaminated,
            fingerprint=fingerprint,
            expected_role="audit",
            selected_cells={"random-number-1-100:en"},
            samples_per_cell=10,
        )


def test_noneligible_ground_truth_is_incompatible() -> None:
    result = build_safe_decision(
        payload(),
        reference_metadata={
            **ELIGIBLE_REFERENCE,
            "ground_truth": "relay_snapshot_not_official",
        },
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == ["reference_ground_truth_not_eligible"]


def test_explicitly_ineligible_reference_is_incompatible() -> None:
    result = build_safe_decision(
        payload(),
        reference_metadata={
            **ELIGIBLE_REFERENCE,
            "decision_eligible": False,
        },
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["operationalVerdict"] == "unverifiable"
    assert result["status"] == "incompatible"
    assert result["reasons"] == ["reference_decision_ineligible"]
    assert result["decisionEligible"] is False


@pytest.mark.parametrize("baseline_status", ["expired", "superseded", "deleted"])
def test_nonactive_reference_baseline_is_incompatible(baseline_status: str) -> None:
    result = build_safe_decision(
        payload(),
        reference_metadata={
            **ELIGIBLE_REFERENCE,
            "baseline_status": baseline_status,
        },
        threshold_policy=VALIDATED_POLICY,
        comparison_scope=VALID_SCOPE,
    )

    assert result["operationalVerdict"] == "unverifiable"
    assert result["status"] == "incompatible"
    assert result["reasons"] == ["reference_baseline_not_active"]
    assert result["decisionEligible"] is False


def test_missing_validated_policy_is_uncalibrated() -> None:
    result = build_safe_decision(payload())

    assert result == {
        "operationalVerdict": "unverifiable",
        "status": "uncalibrated",
        "reasons": ["validated_threshold_policy_missing"],
        "legacyVerdict": "match",
        "rawMeanJsd": DEFAULT_JSD,
        "decisionEligible": False,
    }


@pytest.mark.parametrize("status", ["draft", "retired"])
def test_nonvalidated_policy_is_uncalibrated(status: str) -> None:
    policy_payload = dict(VALIDATED_POLICY_PAYLOAD)
    policy_payload["status"] = status
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
            policy_payload.pop(field)
    policy = load_threshold_policy(policy_payload)

    result = build_safe_decision(payload(), threshold_policy=policy)

    assert result["status"] == "uncalibrated"
    assert result["reasons"] == ["threshold_policy_not_validated"]


@pytest.mark.parametrize("policy", [[], {}, {"status": "validated"}])
def test_decision_gate_rejects_unvalidated_policy_objects(policy: object) -> None:
    with pytest.raises(TypeError, match="validated ThresholdPolicy instance"):
        build_safe_decision(payload(), threshold_policy=policy)  # type: ignore[arg-type]


def test_validated_policy_without_exact_scope_fails_closed() -> None:
    result = build_safe_decision(
        payload(),
        reference_metadata=ELIGIBLE_REFERENCE,
        threshold_policy=VALIDATED_POLICY,
    )

    assert result["status"] == "incompatible"
    assert result["reasons"] == ["comparison_scope_missing"]
    assert result["decisionEligible"] is False
    assert result["thresholdPolicyId"] == VALIDATED_POLICY.id
    assert result["thresholdPolicySha256"] == policy_sha256(VALIDATED_POLICY)


@pytest.mark.parametrize("mean_jsd", [True, -0.1, 1.1, math.nan, math.inf])
def test_mean_jsd_must_be_a_finite_unit_interval(mean_jsd: object) -> None:
    with pytest.raises(ValueError, match="meanJsd must be a finite number"):
        build_safe_decision(payload(mean_jsd))  # type: ignore[arg-type]


@pytest.mark.parametrize("tokens", [True, -1, math.nan, math.inf, "1"])
def test_reasoning_token_metric_is_strictly_validated(tokens: object) -> None:
    sample = payload()
    sample["reference"]["cells"]["random-number-1-100:en"][  # type: ignore[index]
        "meanReasoningTokens"
    ] = tokens

    with pytest.raises(ValueError, match="meanReasoningTokens must be"):
        build_safe_decision(
            sample,
            threshold_policy=VALIDATED_POLICY,
            comparison_scope=VALID_SCOPE,
        )


def test_payload_and_reference_metadata_must_be_mappings() -> None:
    with pytest.raises(TypeError, match="payload must be a mapping"):
        build_safe_decision([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="reference_metadata must be a mapping"):
        build_safe_decision(payload(), reference_metadata=[])  # type: ignore[arg-type]


def test_legacy_verdict_is_strictly_validated() -> None:
    with pytest.raises(ValueError, match="legacy_verdict must be one of"):
        build_safe_decision(payload(), legacy_verdict="MATCH")
