"""Safe operational decision gate for One Token comparison results.

The upstream detector can always provide an exploratory JSD score, but that
score is not an operational model-identity verdict unless protocol, reasoning
channel, reference provenance, and calibration requirements all pass.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from math import isfinite, log2
from typing import Any

from relay_auditor.one_token_policy import ComparisonScope, ThresholdPolicy, policy_sha256

_LEGACY_VERDICTS = {"match", "uncertain", "mismatch", "insufficient"}
_ELIGIBLE_GROUND_TRUTH = {"official_first_party", "attested_cross_provider"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    return value


def _finite_unit_interval(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite number between 0 and 1")
    number = float(value)
    if not isfinite(number) or not 0 <= number <= 1:
        raise ValueError(f"{label} must be a finite number between 0 and 1")
    return number


def _optional_boolean(container: Mapping[str, Any], key: str, label: str) -> bool:
    if key not in container or container[key] is None:
        return False
    value = container[key]
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _comparison(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    value = payload.get("comparison")
    if value is None:
        return payload
    return _require_mapping(value, "payload.comparison")


def _fingerprint(payload: Mapping[str, Any], side: str) -> Mapping[str, Any]:
    value = payload.get(side)
    if value is None:
        return {}
    side_payload = _require_mapping(value, f"payload.{side}")
    nested = side_payload.get("fingerprint")
    if nested is None:
        return side_payload
    return _require_mapping(nested, f"payload.{side}.fingerprint")


def _legacy_verdict(payload: Mapping[str, Any], explicit: str | None) -> str | None:
    value: object = explicit
    if value is None:
        value = payload.get("verdict")
    if value is None:
        value = _comparison(payload).get("verdict")
    if value is None:
        return None
    if not isinstance(value, str) or value not in _LEGACY_VERDICTS:
        raise ValueError("legacy_verdict must be one of match, uncertain, mismatch, insufficient")
    return value


def _mean_jsd(payload: Mapping[str, Any]) -> float | None:
    comparison = _comparison(payload)
    value = comparison["meanJsd"] if "meanJsd" in comparison else payload.get("meanJsd")
    if value is None:
        return None
    return _finite_unit_interval(value, "meanJsd")


def _has_reasoning_tokens(fingerprint: Mapping[str, Any], side: str) -> bool:
    cells = fingerprint.get("cells")
    if cells is None:
        return False
    cell_map = _require_mapping(cells, f"payload.{side}.cells")
    found = False
    for cell_id, value in cell_map.items():
        cell = _require_mapping(value, f"payload.{side}.cells[{cell_id!r}]")
        tokens = cell.get("meanReasoningTokens")
        if tokens is None:
            continue
        if isinstance(tokens, bool) or not isinstance(tokens, (int, float)):
            raise ValueError(
                f"payload.{side}.cells[{cell_id!r}].meanReasoningTokens "
                "must be a finite non-negative number or null"
            )
        number = float(tokens)
        if not isfinite(number) or number < 0:
            raise ValueError(
                f"payload.{side}.cells[{cell_id!r}].meanReasoningTokens "
                "must be a finite non-negative number or null"
            )
        found = found or number > 0
    return found


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _non_negative_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _canonical_manifest_sha256(manifest: Mapping[str, Any]) -> str | None:
    """Hash a manifest using the same recursively key-sorted JSON shape as Node."""

    try:
        encoded = json.dumps(
            manifest,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def _jsd_from_counts(left: Mapping[str, int], right: Mapping[str, int]) -> float | None:
    left_total = sum(left.values())
    right_total = sum(right.values())
    if left_total <= 0 or right_total <= 0:
        return None
    divergence = 0.0
    for answer in set(left).union(right):
        probability_left = left.get(answer, 0) / left_total
        probability_right = right.get(answer, 0) / right_total
        midpoint = (probability_left + probability_right) / 2
        if probability_left > 0:
            divergence += 0.5 * probability_left * log2(probability_left / midpoint)
        if probability_right > 0:
            divergence += 0.5 * probability_right * log2(probability_right / midpoint)
    return divergence


class _RawEvidenceValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _rebuild_raw_evidence(
    raw_jsonl: bytes,
    *,
    fingerprint: Mapping[str, Any],
    expected_role: str,
    selected_cells: set[str],
    samples_per_cell: int,
) -> dict[str, Any]:
    """Parse untrusted JSONL bytes and independently rebuild decision inputs."""

    try:
        text = raw_jsonl.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _RawEvidenceValidationError("invalid_utf8") from error
    if not text or not text.endswith("\n"):
        raise _RawEvidenceValidationError("invalid_jsonl")
    lines = text.splitlines()
    expected_samples = len(selected_cells) * samples_per_cell
    if len(lines) != expected_samples or any(not line for line in lines):
        raise _RawEvidenceValidationError("plan_mismatch")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise _RawEvidenceValidationError("duplicate_json_key")
            parsed[key] = value
        return parsed

    def reject_nonfinite_number(value: str) -> None:
        raise _RawEvidenceValidationError("invalid_json")

    categories = ("valid", "invalid", "refusal", "empty", "error")
    summary: dict[str, Any] = {
        **{category: 0 for category in categories},
        "reasoningTraceCount": 0,
        "reasoningTokenCount": 0,
        "reasoningUsageObservedSamples": 0,
        "observableResponseSamples": 0,
        "cells": {
            cell_id: {
                **{category: 0 for category in categories},
                "total": 0,
                "counts": {},
            }
            for cell_id in selected_cells
        },
    }
    observed_jobs: set[tuple[str, int]] = set()
    observed_job_ids: set[str] = set()
    required_fields = {
        "evidenceVersion",
        "protocolId",
        "role",
        "requestedModel",
        "jobId",
        "cellId",
        "repetitionIndex",
        "category",
        "normalized",
        "normalizationCandidate",
        "normalizationCategory",
        "excludedFromDistribution",
        "exclusionReason",
        "reasoningTraceFields",
        "reasoningTraceCharacterCount",
        "usage",
        "errorKind",
    }

    for line in lines:
        try:
            sample = json.loads(
                line,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonfinite_number,
            )
        except _RawEvidenceValidationError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise _RawEvidenceValidationError("invalid_json") from error
        if not isinstance(sample, Mapping) or not required_fields.issubset(sample):
            raise _RawEvidenceValidationError("invalid_shape")
        if (
            sample.get("evidenceVersion") != 1
            or sample.get("protocolId") != fingerprint.get("protocol")
            or sample.get("role") != expected_role
            or sample.get("requestedModel") != fingerprint.get("model")
        ):
            raise _RawEvidenceValidationError("metadata_mismatch")

        cell_id = sample.get("cellId")
        repetition = sample.get("repetitionIndex")
        job_id = sample.get("jobId")
        if (
            not isinstance(cell_id, str)
            or cell_id not in selected_cells
            or _non_negative_integer(repetition) is None
            or repetition >= samples_per_cell
            or not isinstance(job_id, str)
            or not job_id
            or len(job_id) > 256
        ):
            raise _RawEvidenceValidationError("job_invalid")
        job = (cell_id, repetition)
        if job in observed_jobs or job_id in observed_job_ids:
            raise _RawEvidenceValidationError("duplicate_job")
        observed_jobs.add(job)
        observed_job_ids.add(job_id)

        category = sample.get("category")
        normalized = sample.get("normalized")
        normalization_candidate = sample.get("normalizationCandidate")
        normalization_category = sample.get("normalizationCategory")
        excluded = sample.get("excludedFromDistribution")
        exclusion_reason = sample.get("exclusionReason")
        error_kind = sample.get("errorKind")
        if category not in categories or not isinstance(excluded, bool):
            raise _RawEvidenceValidationError("sample_state_invalid")

        trace_fields = sample.get("reasoningTraceFields")
        trace_characters = _non_negative_integer(sample.get("reasoningTraceCharacterCount"))
        if (
            not isinstance(trace_fields, list)
            or any(not isinstance(field, str) for field in trace_fields)
            or len(trace_fields) != len(set(trace_fields))
            or trace_characters is None
            or bool(trace_fields) != (trace_characters > 0)
        ):
            raise _RawEvidenceValidationError("reasoning_state_invalid")

        usage = sample.get("usage")
        reasoning_tokens: int | None = None
        if usage is not None:
            if not isinstance(usage, Mapping) or "reasoningTokens" not in usage:
                raise _RawEvidenceValidationError("usage_invalid")
            raw_reasoning_tokens = usage.get("reasoningTokens")
            if raw_reasoning_tokens is not None:
                reasoning_tokens = _non_negative_integer(raw_reasoning_tokens)
                if reasoning_tokens is None:
                    raise _RawEvidenceValidationError("usage_invalid")
        contaminated = bool(trace_fields) or (reasoning_tokens is not None and reasoning_tokens > 0)
        if category == "valid":
            valid_state = (
                isinstance(normalized, str)
                and normalization_candidate == normalized
                and normalization_category == "valid"
                and not excluded
                and exclusion_reason is None
                and error_kind is None
                and not contaminated
            )
        elif category == "invalid":
            if contaminated:
                candidate_state = (
                    isinstance(normalization_candidate, str)
                    if normalization_category in {"valid", "invalid"}
                    else normalization_candidate is None
                )
                valid_state = (
                    normalized is None
                    and normalization_category in {"valid", "invalid", "refusal", "empty"}
                    and candidate_state
                    and excluded
                    and exclusion_reason == "reasoning_contamination"
                    and error_kind is None
                )
            else:
                valid_state = (
                    isinstance(normalized, str)
                    and normalization_candidate == normalized
                    and normalization_category == "invalid"
                    and not excluded
                    and exclusion_reason is None
                    and error_kind is None
                )
        elif category in {"refusal", "empty"}:
            valid_state = (
                normalized is None
                and normalization_candidate is None
                and normalization_category == category
                and not excluded
                and exclusion_reason is None
                and error_kind is None
                and not contaminated
            )
        else:
            # Provider/malformed/credential errors win over reasoning contamination
            # in the collector's category selection and remain canonical errors.
            expected_exclusion = None if error_kind == "request_failed" else error_kind
            valid_state = (
                normalized is None
                and normalization_candidate is None
                and normalization_category is None
                and excluded
                and isinstance(error_kind, str)
                and exclusion_reason == expected_exclusion
                and (not contaminated or error_kind != "request_failed")
            )
        if not valid_state:
            raise _RawEvidenceValidationError("sample_state_invalid")

        summary[category] += 1
        cell_summary = summary["cells"][cell_id]
        cell_summary[category] += 1
        cell_summary["total"] += 1
        if category == "valid":
            counts = cell_summary["counts"]
            counts[normalized] = counts.get(normalized, 0) + 1
        if trace_fields:
            summary["reasoningTraceCount"] += 1
        if reasoning_tokens is not None:
            summary["reasoningTokenCount"] += reasoning_tokens
        if error_kind is None:
            summary["observableResponseSamples"] += 1
            if reasoning_tokens is not None:
                summary["reasoningUsageObservedSamples"] += 1

    expected_jobs = {
        (cell_id, repetition)
        for cell_id in selected_cells
        for repetition in range(samples_per_cell)
    }
    if observed_jobs != expected_jobs:
        raise _RawEvidenceValidationError("plan_mismatch")

    summary["directness"] = (
        "violated"
        if summary["reasoningTraceCount"] > 0 or summary["reasoningTokenCount"] > 0
        else "unknown"
        if summary["error"] > 0
        or summary["reasoningUsageObservedSamples"] != summary["observableResponseSamples"]
        else "verified"
    )
    return summary


def _raw_evidence_reasons(
    side: str,
    raw_jsonl: object,
    *,
    fingerprint: Mapping[str, Any],
    quality: Mapping[str, Any],
    expected_role: str,
    selected_cells: set[str],
    samples_per_cell: int,
) -> list[str]:
    if not isinstance(raw_jsonl, bytes):
        return [f"{side}_raw_evidence_missing"]
    expected_sha = quality.get("rawEvidenceSha256")
    if not isinstance(expected_sha, str) or not _SHA256_RE.fullmatch(expected_sha):
        return []
    if hashlib.sha256(raw_jsonl).hexdigest() != expected_sha:
        return [f"{side}_raw_evidence_hash_mismatch"]
    try:
        rebuilt = _rebuild_raw_evidence(
            raw_jsonl,
            fingerprint=fingerprint,
            expected_role=expected_role,
            selected_cells=selected_cells,
            samples_per_cell=samples_per_cell,
        )
    except _RawEvidenceValidationError as error:
        return [f"{side}_raw_evidence_{error.reason}"]

    category_names = ("valid", "invalid", "refusal", "empty", "error")
    quality_fields = {
        "valid": "validSamples",
        "invalid": "invalidSamples",
        "refusal": "refusalSamples",
        "empty": "emptySamples",
        "error": "errorSamples",
    }
    if (
        quality.get("complete") is not True
        or quality.get("completedSamples") != len(selected_cells) * samples_per_cell
        or quality.get("expectedSamples") != len(selected_cells) * samples_per_cell
        or any(
            quality.get(field) != rebuilt[category] for category, field in quality_fields.items()
        )
        or quality.get("directness") != rebuilt["directness"]
        or quality.get("reasoningTraceCount") != rebuilt["reasoningTraceCount"]
        or quality.get("reasoningTokenCount") != rebuilt["reasoningTokenCount"]
        or quality.get("reasoningUsageObservedSamples") != rebuilt["reasoningUsageObservedSamples"]
    ):
        return [f"{side}_raw_evidence_quality_aggregate_mismatch"]

    cells = fingerprint.get("cells")
    if not isinstance(cells, Mapping):
        return [f"{side}_raw_evidence_cell_aggregate_mismatch"]
    for cell_id in selected_cells:
        cell = cells.get(cell_id)
        rebuilt_cell = rebuilt["cells"][cell_id]
        if not isinstance(cell, Mapping):
            return [f"{side}_raw_evidence_cell_aggregate_mismatch"]
        if (
            any(
                cell.get(f"{category}Count") != rebuilt_cell[category]
                for category in category_names
            )
            or cell.get("totalCount") != rebuilt_cell["total"]
        ):
            return [f"{side}_raw_evidence_cell_aggregate_mismatch"]
        counts = cell.get("counts")
        if not isinstance(counts, Mapping) or dict(counts) != rebuilt_cell["counts"]:
            return [f"{side}_raw_evidence_cell_aggregate_mismatch"]
    return []


def _validated_v2_evidence_reasons(
    payload: Mapping[str, Any],
    policy: ThresholdPolicy,
    scope: ComparisonScope,
    raw_evidence_jsonl: Mapping[str, Any] | None,
) -> list[str]:
    """Verify operational inputs from the actual V2 evidence, not scope claims.

    ``ComparisonScope`` still binds execution-only facts such as provider and
    environment. Every fact observable in the artifacts is independently
    reconstructed here before a calibrated verdict is allowed.
    """

    reasons: list[str] = []
    selected_cells = set(policy.cellSelection)
    minimum_valid = policy.qualityGates.minValidSamplesPerCell
    side_valid_counts: dict[str, dict[str, int]] = {}
    side_distributions: dict[str, dict[str, dict[str, int]]] = {}

    for side, expected_role, expected_samples in (
        ("reference", "enrollment", policy.referenceSamplesPerCell),
        ("target", "audit", policy.targetSamplesPerCell),
    ):
        fingerprint = _fingerprint(payload, side)
        if not fingerprint:
            _append_reason(reasons, f"{side}_fingerprint_missing")
            continue
        if fingerprint.get("formatVersion") != 2:
            _append_reason(reasons, f"{side}_fingerprint_not_v2")
            continue
        if fingerprint.get("partial") is True:
            _append_reason(reasons, f"{side}_fingerprint_partial")
        post_reasoning = fingerprint.get("postReasoning")
        if post_reasoning is not False and post_reasoning is not True:
            _append_reason(reasons, f"{side}_post_reasoning_not_explicitly_false")
        if fingerprint.get("protocol") != scope.modelScope.protocol:
            _append_reason(reasons, f"{side}_protocol_scope_mismatch")
        if fingerprint.get("model") != scope.modelScope.model:
            _append_reason(reasons, f"{side}_model_scope_mismatch")
        if _non_negative_integer(fingerprint.get("samplesPerCell")) != expected_samples:
            _append_reason(reasons, f"{side}_samples_per_cell_evidence_mismatch")

        manifest = fingerprint.get("manifest")
        if not isinstance(manifest, Mapping):
            _append_reason(reasons, f"{side}_manifest_missing")
        else:
            if manifest.get("protocolId") != fingerprint.get("protocol"):
                _append_reason(reasons, f"{side}_manifest_protocol_mismatch")
            manifest_sha = _canonical_manifest_sha256(manifest)
            if manifest_sha != scope.methodProfileSha256:
                _append_reason(reasons, f"{side}_method_profile_hash_mismatch")

        plan = fingerprint.get("plan")
        plan_expected_samples = len(selected_cells) * expected_samples
        if not isinstance(plan, Mapping):
            _append_reason(reasons, f"{side}_collection_plan_missing")
        else:
            if plan.get("role") != expected_role:
                _append_reason(reasons, f"{side}_collection_role_mismatch")
            plan_cells = plan.get("cellIds")
            if (
                not isinstance(plan_cells, list)
                or any(not isinstance(cell_id, str) for cell_id in plan_cells)
                or len(plan_cells) != len(set(plan_cells))
                or set(plan_cells) != selected_cells
            ):
                _append_reason(reasons, f"{side}_collection_cells_mismatch")
            if _non_negative_integer(plan.get("samplesPerCell")) != expected_samples:
                _append_reason(reasons, f"{side}_plan_samples_per_cell_mismatch")
            if _non_negative_integer(plan.get("expectedSamples")) != plan_expected_samples:
                _append_reason(reasons, f"{side}_plan_expected_samples_mismatch")

        cells = fingerprint.get("cells")
        parsed_valid_counts: dict[str, int] = {}
        parsed_distributions: dict[str, dict[str, int]] = {}
        aggregate = {
            "valid": 0,
            "invalid": 0,
            "refusal": 0,
            "empty": 0,
            "error": 0,
            "total": 0,
        }
        if not isinstance(cells, Mapping) or set(cells) != selected_cells:
            _append_reason(reasons, f"{side}_cell_evidence_mismatch")
        else:
            for cell_id in policy.cellSelection:
                cell = cells.get(cell_id)
                if not isinstance(cell, Mapping):
                    _append_reason(reasons, f"{side}_cell_evidence_invalid")
                    continue
                parsed: dict[str, int] = {}
                for category in aggregate:
                    count = _non_negative_integer(cell.get(f"{category}Count"))
                    if count is None:
                        _append_reason(reasons, f"{side}_cell_evidence_invalid")
                        break
                    parsed[category] = count
                if len(parsed) != len(aggregate):
                    continue
                if (
                    sum(parsed[name] for name in ("valid", "invalid", "refusal", "empty", "error"))
                    != parsed["total"]
                ):
                    _append_reason(reasons, f"{side}_cell_category_counts_mismatch")
                if parsed["total"] != expected_samples:
                    _append_reason(reasons, f"{side}_cell_total_samples_mismatch")
                counts = cell.get("counts")
                if not isinstance(counts, Mapping):
                    _append_reason(reasons, f"{side}_cell_distribution_missing")
                else:
                    distribution_total = 0
                    valid_distribution = True
                    parsed_distribution: dict[str, int] = {}
                    for answer, count_value in counts.items():
                        count = _non_negative_integer(count_value)
                        if not isinstance(answer, str) or count is None:
                            valid_distribution = False
                            break
                        distribution_total += count
                        parsed_distribution[answer] = count
                    if not valid_distribution or distribution_total != parsed["valid"]:
                        _append_reason(reasons, f"{side}_cell_distribution_mismatch")
                    else:
                        parsed_distributions[cell_id] = parsed_distribution
                if parsed["valid"] < minimum_valid:
                    _append_reason(reasons, f"{side}_valid_samples_below_quality_minimum")
                parsed_valid_counts[cell_id] = parsed["valid"]
                for category in aggregate:
                    aggregate[category] += parsed[category]
        side_valid_counts[side] = parsed_valid_counts
        side_distributions[side] = parsed_distributions

        quality = fingerprint.get("quality")
        if not isinstance(quality, Mapping):
            _append_reason(reasons, f"{side}_quality_missing")
            continue
        if quality.get("complete") is not True:
            _append_reason(reasons, f"{side}_quality_incomplete")
        if _non_negative_integer(quality.get("expectedSamples")) != plan_expected_samples:
            _append_reason(reasons, f"{side}_quality_expected_samples_mismatch")
        if _non_negative_integer(quality.get("completedSamples")) != plan_expected_samples:
            _append_reason(reasons, f"{side}_quality_completed_samples_mismatch")
        quality_names = ("valid", "invalid", "refusal", "empty", "error")
        quality_counts: dict[str, int] = {}
        for category in quality_names:
            value = _non_negative_integer(quality.get(f"{category}Samples"))
            if value is None:
                _append_reason(reasons, f"{side}_quality_counts_invalid")
                break
            quality_counts[category] = value
        if len(quality_counts) == len(quality_names):
            if sum(quality_counts.values()) != plan_expected_samples:
                _append_reason(reasons, f"{side}_quality_category_counts_mismatch")
            if any(quality_counts[name] != aggregate[name] for name in quality_names):
                _append_reason(reasons, f"{side}_quality_cell_counts_mismatch")
            if quality_counts["error"] != 0:
                _append_reason(reasons, f"{side}_quality_request_errors")
        if quality.get("directness") != "verified":
            _append_reason(reasons, f"{side}_directness_not_verified")
        if _non_negative_integer(quality.get("reasoningTraceCount")) != 0:
            _append_reason(reasons, f"{side}_reasoning_trace_present_or_unknown")
        if _non_negative_integer(quality.get("reasoningTokenCount")) != 0:
            _append_reason(reasons, f"{side}_reasoning_tokens_present_or_unknown")
        if (
            _non_negative_integer(quality.get("reasoningUsageObservedSamples"))
            != plan_expected_samples
        ):
            _append_reason(reasons, f"{side}_reasoning_usage_not_fully_observed")
        raw_sha = quality.get("rawEvidenceSha256")
        if not isinstance(raw_sha, str) or not _SHA256_RE.fullmatch(raw_sha):
            _append_reason(reasons, f"{side}_raw_evidence_hash_missing")
        if policy.qualityGates.requireRawEvidence:
            for reason in _raw_evidence_reasons(
                side,
                None if raw_evidence_jsonl is None else raw_evidence_jsonl.get(side),
                fingerprint=fingerprint,
                quality=quality,
                expected_role=expected_role,
                selected_cells=selected_cells,
                samples_per_cell=expected_samples,
            ):
                _append_reason(reasons, reason)

    comparison = _comparison(payload)
    compatibility = comparison.get("compatibility")
    if (
        not isinstance(compatibility, Mapping)
        or compatibility.get("compatible") is not True
        or compatibility.get("status") != "compatible"
        or compatibility.get("manifestMatch") is not True
    ):
        _append_reason(reasons, "v2_compatibility_not_verified")

    cell_results = comparison.get("cells")
    parsed_jsds: list[float] = []
    observed_cell_ids: set[str] = set()
    # The online Node verify path compares target=A/reference=B, while the
    # Python offline recovery path invokes compare(reference, target). Accept
    # either ordering, but require one ordering to hold consistently for the
    # complete comparison rather than choosing independently per cell.
    reference_is_a = True
    target_is_a = True
    if not isinstance(cell_results, list):
        _append_reason(reasons, "comparison_cells_missing")
    else:
        for result in cell_results:
            if not isinstance(result, Mapping):
                _append_reason(reasons, "comparison_cells_invalid")
                continue
            cell_id = result.get("cellId")
            if (
                not isinstance(cell_id, str)
                or cell_id not in selected_cells
                or cell_id in observed_cell_ids
            ):
                _append_reason(reasons, "comparison_cells_invalid")
                continue
            observed_cell_ids.add(cell_id)
            jsd = result.get("jsd")
            if (
                isinstance(jsd, bool)
                or not isinstance(jsd, (int, float))
                or not isfinite(jsd)
                or not 0 <= float(jsd) <= 1
            ):
                _append_reason(reasons, "comparison_cell_jsd_invalid")
                continue
            valid_a = _non_negative_integer(result.get("validA"))
            valid_b = _non_negative_integer(result.get("validB"))
            reference_valid = side_valid_counts.get("reference", {}).get(cell_id)
            target_valid = side_valid_counts.get("target", {}).get(cell_id)
            if (
                valid_a is None
                or valid_b is None
                or valid_a < minimum_valid
                or valid_b < minimum_valid
            ):
                reference_is_a = False
                target_is_a = False
            else:
                reference_is_a = reference_is_a and (
                    valid_a == reference_valid and valid_b == target_valid
                )
                target_is_a = target_is_a and (
                    valid_a == target_valid and valid_b == reference_valid
                )
            recomputed_jsd = _jsd_from_counts(
                side_distributions.get("reference", {}).get(cell_id, {}),
                side_distributions.get("target", {}).get(cell_id, {}),
            )
            if recomputed_jsd is None or abs(float(jsd) - recomputed_jsd) > 1e-12:
                _append_reason(reasons, "comparison_cell_jsd_evidence_mismatch")
            parsed_jsds.append(float(jsd))

    comparable_count = _non_negative_integer(comparison.get("comparableCellCount"))
    if observed_cell_ids != selected_cells:
        _append_reason(reasons, "comparison_cell_selection_mismatch")
    if not reference_is_a and not target_is_a:
        _append_reason(reasons, "comparison_cell_valid_counts_mismatch")
    if comparable_count != len(parsed_jsds) or scope.comparableCells != len(parsed_jsds):
        _append_reason(reasons, "comparable_cell_count_evidence_mismatch")
    if len(parsed_jsds) < policy.minComparableCells:
        _append_reason(reasons, "comparable_cells_below_policy_minimum")
    mean_jsd = comparison.get("meanJsd")
    if parsed_jsds:
        recomputed_mean = sum(parsed_jsds) / len(parsed_jsds)
        if (
            isinstance(mean_jsd, bool)
            or not isinstance(mean_jsd, (int, float))
            or not isfinite(mean_jsd)
            or abs(float(mean_jsd) - recomputed_mean) > 1e-12
        ):
            _append_reason(reasons, "mean_jsd_evidence_mismatch")
    return reasons


def _decision(
    *,
    operational_verdict: str,
    status: str,
    reasons: list[str],
    legacy_verdict: str | None,
    raw_mean_jsd: float | None,
    decision_eligible: bool,
    threshold_policy: ThresholdPolicy | None,
) -> dict[str, Any]:
    result = {
        "operationalVerdict": operational_verdict,
        "status": status,
        "reasons": reasons,
        "legacyVerdict": legacy_verdict,
        "rawMeanJsd": raw_mean_jsd,
        "decisionEligible": decision_eligible,
    }
    if threshold_policy is not None:
        result["thresholdPolicyId"] = threshold_policy.id
        result["thresholdPolicySha256"] = policy_sha256(threshold_policy)
    return result


def build_safe_decision(
    payload: Mapping[str, Any],
    legacy_verdict: str | None = None,
    reference_metadata: Mapping[str, Any] | None = None,
    threshold_policy: ThresholdPolicy | None = None,
    comparison_scope: ComparisonScope | None = None,
    raw_evidence_jsonl: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Build a fail-closed operational decision from a One Token result payload.

    A validated threshold policy is necessary but not sufficient: incompatible
    protocols, post-reasoning samples, reasoning-token contamination, and
    explicitly untrusted reference provenance all make the result unverifiable.
    The original detector verdict and raw JSD remain available for diagnostics.
    """

    result = _require_mapping(payload, "payload")
    metadata = (
        None
        if reference_metadata is None
        else _require_mapping(reference_metadata, "reference_metadata")
    )
    raw_evidence = (
        None
        if raw_evidence_jsonl is None
        else _require_mapping(
            raw_evidence_jsonl,
            "raw_evidence_jsonl",
        )
    )
    if threshold_policy is not None and not isinstance(threshold_policy, ThresholdPolicy):
        raise TypeError("threshold_policy must be a validated ThresholdPolicy instance")
    if comparison_scope is not None and not isinstance(comparison_scope, ComparisonScope):
        raise TypeError("comparison_scope must be a validated ComparisonScope instance")
    if threshold_policy is not None:
        threshold_policy = ThresholdPolicy.model_validate(threshold_policy)
    if comparison_scope is not None:
        comparison_scope = ComparisonScope.model_validate(comparison_scope)
    policy_status = None if threshold_policy is None else threshold_policy.status
    raw_mean_jsd = _mean_jsd(result)
    legacy = _legacy_verdict(result, legacy_verdict)

    insufficient_reasons: list[str] = []
    if raw_mean_jsd is None:
        insufficient_reasons.append("mean_jsd_missing")
    if legacy == "insufficient":
        insufficient_reasons.append("legacy_verdict_insufficient")
    if insufficient_reasons:
        return _decision(
            operational_verdict="unverifiable",
            status="insufficient",
            reasons=insufficient_reasons,
            legacy_verdict=legacy,
            raw_mean_jsd=raw_mean_jsd,
            decision_eligible=False,
            threshold_policy=threshold_policy,
        )

    comparison = _comparison(result)
    incompatible_reasons: list[str] = []
    if _optional_boolean(comparison, "protocolMismatch", "protocolMismatch"):
        incompatible_reasons.append("protocol_mismatch")

    for side in ("target", "reference"):
        fingerprint = _fingerprint(result, side)
        if _optional_boolean(
            fingerprint,
            "postReasoning",
            f"payload.{side}.postReasoning",
        ):
            incompatible_reasons.append(f"{side}_post_reasoning")
        if _has_reasoning_tokens(fingerprint, side):
            incompatible_reasons.append(f"{side}_reasoning_tokens_positive")

    if metadata is None or "ground_truth" not in metadata:
        if policy_status == "validated":
            incompatible_reasons.append("reference_ground_truth_missing")
    else:
        ground_truth = metadata["ground_truth"]
        if ground_truth not in _ELIGIBLE_GROUND_TRUTH:
            incompatible_reasons.append("reference_ground_truth_not_eligible")
        decision_eligible = metadata.get("decision_eligible")
        decision_ineligible = (
            decision_eligible is not True
            if policy_status == "validated"
            else decision_eligible is False
        )
        if decision_ineligible:
            incompatible_reasons.append("reference_decision_ineligible")
        baseline_status = metadata.get("baseline_status")
        baseline_inactive = (
            baseline_status != "active"
            if policy_status == "validated"
            else baseline_status is not None and baseline_status != "active"
        )
        if baseline_inactive:
            incompatible_reasons.append("reference_baseline_not_active")

    if policy_status == "validated":
        assert threshold_policy is not None
        expected_policy_sha256 = policy_sha256(threshold_policy)
        if metadata is None or metadata.get("calibration_policy_id") != threshold_policy.id:
            incompatible_reasons.append("reference_calibration_policy_id_mismatch")
        if metadata is None or metadata.get("calibration_policy_sha256") != expected_policy_sha256:
            incompatible_reasons.append("reference_calibration_policy_sha256_mismatch")
        if comparison_scope is None:
            incompatible_reasons.append("comparison_scope_missing")
        else:
            incompatible_reasons.extend(comparison_scope.mismatch_reasons(threshold_policy))
            incompatible_reasons.extend(
                reason
                for reason in _validated_v2_evidence_reasons(
                    result,
                    threshold_policy,
                    comparison_scope,
                    raw_evidence,
                )
                if reason not in incompatible_reasons
            )

    if incompatible_reasons:
        return _decision(
            operational_verdict="unverifiable",
            status="incompatible",
            reasons=incompatible_reasons,
            legacy_verdict=legacy,
            raw_mean_jsd=raw_mean_jsd,
            decision_eligible=False,
            threshold_policy=threshold_policy,
        )

    if policy_status != "validated":
        reason = (
            "validated_threshold_policy_missing"
            if policy_status is None
            else "threshold_policy_not_validated"
        )
        return _decision(
            operational_verdict="unverifiable",
            status="uncalibrated",
            reasons=[reason],
            legacy_verdict=legacy,
            raw_mean_jsd=raw_mean_jsd,
            decision_eligible=False,
            threshold_policy=threshold_policy,
        )

    assert threshold_policy is not None
    assert threshold_policy.matchMax is not None
    assert threshold_policy.mismatchMin is not None
    if raw_mean_jsd <= threshold_policy.matchMax:
        operational_verdict = "match"
    elif raw_mean_jsd >= threshold_policy.mismatchMin:
        operational_verdict = "mismatch"
    else:
        operational_verdict = "uncertain"
    return _decision(
        operational_verdict=operational_verdict,
        status="calibrated",
        reasons=[],
        legacy_verdict=legacy,
        raw_mean_jsd=raw_mean_jsd,
        decision_eligible=True,
        threshold_policy=threshold_policy,
    )
