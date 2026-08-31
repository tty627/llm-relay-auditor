"""Immutable ReferenceSet contracts and deterministic relative fingerprint statistics."""

from __future__ import annotations

import bisect
import copy
import hashlib
import json
import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from statistics import median
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

REFERENCE_SET_FORMAT_VERSION = "one-token-reference-set-manifest/v1"
REFERENCE_STATISTICS_FORMAT_VERSION = "one-token-reference-statistics/v1"
REFERENCE_SET_MEMBER_COUNT = 3
REFERENCE_CELL_COUNT = 40
REFERENCE_SAMPLES_PER_CELL = 30
MINIMUM_VALID_SAMPLES_PER_CELL = 24
DEFAULT_BOOTSTRAP_ITERATIONS = 2_000
DECISION_ELIGIBLE = False
OPERATIONAL_VERDICT = "unverifiable"

Protocol = Literal["anthropic_messages", "openai_chat"]
TransportProfileId = Literal[
    "openai-chat-onetoken-v1",
    "anthropic-messages-opus5-onetoken-v1",
]
ExploratoryStatus = Literal[
    "exploratory_reference_like",
    "exploratory_reference_deviation",
    "inconclusive",
    "insufficient_quality",
    "unsupported_protocol",
    "request_failed",
]

TRANSPORT_PROFILE_BY_PROTOCOL: dict[Protocol, TransportProfileId] = {
    "openai_chat": "openai-chat-onetoken-v1",
    "anthropic_messages": "anthropic-messages-opus5-onetoken-v1",
}


class ReferenceCompatibilityError(ValueError):
    """Evidence does not belong to the frozen ReferenceSet contract."""


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def normalize_reference_base_url(value: str) -> str:
    """Canonicalize a credential-free HTTPS base URL without changing its path."""

    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("ReferenceSet base URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("ReferenceSet base URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("ReferenceSet base URL must not contain query or fragment")
    if parsed.hostname is None:
        raise ValueError("ReferenceSet base URL requires a hostname")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("ReferenceSet base URL contains an invalid port") from error
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    authority = hostname if port in {None, 443} else f"{hostname}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit(("https", authority, path, "", ""))


@dataclass(frozen=True)
class ReferenceSetManifest:
    protocol: Protocol
    transport_profile_id: TransportProfileId
    logical_model: str
    actual_model: str
    normalized_base_url: str
    cell_ids: tuple[str, ...]
    battery_manifest: dict[str, Any]
    battery_manifest_sha256: str
    samples_per_cell: int = REFERENCE_SAMPLES_PER_CELL
    member_count: int = REFERENCE_SET_MEMBER_COUNT

    @property
    def cell_count(self) -> int:
        return len(self.cell_ids)

    def as_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": REFERENCE_SET_FORMAT_VERSION,
            "protocol": self.protocol,
            "transportProfileId": self.transport_profile_id,
            "logicalModel": self.logical_model,
            "actualModel": self.actual_model,
            "normalizedBaseUrl": self.normalized_base_url,
            "cellIds": list(self.cell_ids),
            "cellCount": self.cell_count,
            "samplesPerCell": self.samples_per_cell,
            "memberCount": self.member_count,
            "batteryManifest": copy.deepcopy(self.battery_manifest),
            "batteryManifestSha256": self.battery_manifest_sha256,
        }


def build_reference_set_manifest(
    *,
    protocol: Protocol,
    transport_profile_id: TransportProfileId,
    logical_model: str,
    actual_model: str,
    base_url: str,
    cell_ids: Sequence[str],
    battery_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    payload = {
        "formatVersion": REFERENCE_SET_FORMAT_VERSION,
        "protocol": protocol,
        "transportProfileId": transport_profile_id,
        "logicalModel": logical_model,
        "actualModel": actual_model,
        "normalizedBaseUrl": normalize_reference_base_url(base_url),
        "cellIds": list(cell_ids),
        "cellCount": len(cell_ids),
        "samplesPerCell": REFERENCE_SAMPLES_PER_CELL,
        "memberCount": REFERENCE_SET_MEMBER_COUNT,
        "batteryManifest": copy.deepcopy(dict(battery_manifest)),
        "batteryManifestSha256": canonical_sha256(battery_manifest),
    }
    return load_reference_set_manifest(payload).as_dict()


def load_reference_set_manifest(payload: Mapping[str, Any]) -> ReferenceSetManifest:
    expected_keys = {
        "formatVersion",
        "protocol",
        "transportProfileId",
        "logicalModel",
        "actualModel",
        "normalizedBaseUrl",
        "cellIds",
        "cellCount",
        "samplesPerCell",
        "memberCount",
        "batteryManifest",
        "batteryManifestSha256",
    }
    if set(payload) != expected_keys:
        raise ValueError("ReferenceSet manifest has an unsupported shape")
    if payload.get("formatVersion") != REFERENCE_SET_FORMAT_VERSION:
        raise ValueError("unsupported ReferenceSet manifest formatVersion")
    protocol = payload.get("protocol")
    profile = payload.get("transportProfileId")
    if protocol not in TRANSPORT_PROFILE_BY_PROTOCOL:
        raise ValueError("unsupported ReferenceSet protocol")
    if profile != TRANSPORT_PROFILE_BY_PROTOCOL[protocol]:
        raise ValueError("ReferenceSet protocol and transport profile do not match")
    logical_model = payload.get("logicalModel")
    actual_model = payload.get("actualModel")
    if not isinstance(logical_model, str) or not logical_model.strip() or len(logical_model) > 255:
        raise ValueError("ReferenceSet logicalModel must contain 1 to 255 characters")
    if not isinstance(actual_model, str) or not actual_model.strip() or len(actual_model) > 255:
        raise ValueError("ReferenceSet actualModel must contain 1 to 255 characters")
    normalized_base_url = payload.get("normalizedBaseUrl")
    if not isinstance(normalized_base_url, str):
        raise ValueError("ReferenceSet normalizedBaseUrl must be a string")
    if normalize_reference_base_url(normalized_base_url) != normalized_base_url:
        raise ValueError("ReferenceSet normalizedBaseUrl is not canonical")
    cell_ids_value = payload.get("cellIds")
    if not isinstance(cell_ids_value, list) or any(
        not isinstance(cell_id, str) or not cell_id for cell_id in cell_ids_value
    ):
        raise ValueError("ReferenceSet cellIds must be non-empty strings")
    cell_ids = tuple(cell_ids_value)
    if len(cell_ids) != REFERENCE_CELL_COUNT or len(set(cell_ids)) != len(cell_ids):
        raise ValueError("ReferenceSet requires exactly 40 unique cells")
    if payload.get("cellCount") != REFERENCE_CELL_COUNT:
        raise ValueError("ReferenceSet cellCount must be 40")
    if payload.get("samplesPerCell") != REFERENCE_SAMPLES_PER_CELL:
        raise ValueError("ReferenceSet samplesPerCell must be 30")
    if payload.get("memberCount") != REFERENCE_SET_MEMBER_COUNT:
        raise ValueError("ReferenceSet memberCount must be 3")
    battery_manifest = payload.get("batteryManifest")
    if not isinstance(battery_manifest, dict) or not battery_manifest:
        raise ValueError("ReferenceSet batteryManifest must be a non-empty object")
    battery_manifest_sha256 = payload.get("batteryManifestSha256")
    if not _is_sha256(battery_manifest_sha256):
        raise ValueError("ReferenceSet batteryManifestSha256 is invalid")
    if canonical_sha256(battery_manifest) != battery_manifest_sha256:
        raise ValueError("ReferenceSet battery manifest digest mismatch")
    return ReferenceSetManifest(
        protocol=protocol,
        transport_profile_id=profile,
        logical_model=logical_model,
        actual_model=actual_model,
        normalized_base_url=normalized_base_url,
        cell_ids=cell_ids,
        battery_manifest=copy.deepcopy(battery_manifest),
        battery_manifest_sha256=battery_manifest_sha256,
    )


def reference_manifest_sha256(payload: Mapping[str, Any]) -> str:
    return canonical_sha256(load_reference_set_manifest(payload).as_dict())


def fingerprint_manifest_sha256(fingerprint: Mapping[str, Any]) -> str:
    manifest = fingerprint.get("manifest")
    if not isinstance(manifest, dict) or not manifest:
        raise ReferenceCompatibilityError("fingerprint manifest is missing")
    return canonical_sha256(manifest)


def validate_member_fingerprint(
    fingerprint: Mapping[str, Any],
    manifest: ReferenceSetManifest | Mapping[str, Any],
    *,
    expected_model: str | None = None,
    expected_raw_evidence_sha256: str | None = None,
    require_complete: bool = True,
    protocol: str | None = None,
    transport_profile_id: str | None = None,
) -> None:
    contract = (
        manifest
        if isinstance(manifest, ReferenceSetManifest)
        else load_reference_set_manifest(manifest)
    )
    if protocol is not None and protocol != contract.protocol:
        raise ReferenceCompatibilityError("fingerprint API protocol does not match ReferenceSet")
    if transport_profile_id is not None and transport_profile_id != contract.transport_profile_id:
        raise ReferenceCompatibilityError(
            "fingerprint transport profile does not match ReferenceSet"
        )
    declared_api_protocol = fingerprint.get("apiProtocol")
    if declared_api_protocol is not None and declared_api_protocol != contract.protocol:
        raise ReferenceCompatibilityError("fingerprint declared a different API protocol")
    declared_profile = fingerprint.get("transportProfileId")
    if declared_profile is not None and declared_profile != contract.transport_profile_id:
        raise ReferenceCompatibilityError("fingerprint declared a different transport profile")
    if fingerprint.get("formatVersion") != 2:
        raise ReferenceCompatibilityError("ReferenceSet requires formatVersion 2 fingerprints")
    if fingerprint.get("postReasoning") is not False:
        raise ReferenceCompatibilityError("ReferenceSet fingerprints must disable post-reasoning")
    if expected_model is not None and fingerprint.get("model") != expected_model:
        raise ReferenceCompatibilityError("reference member model does not match actualModel")
    if fingerprint.get("samplesPerCell") != contract.samples_per_cell:
        raise ReferenceCompatibilityError("fingerprint samplesPerCell does not match ReferenceSet")
    cells = fingerprint.get("cells")
    if not isinstance(cells, dict) or set(cells) != set(contract.cell_ids):
        raise ReferenceCompatibilityError("fingerprint does not contain the frozen 40 cells")
    plan = fingerprint.get("plan")
    if not isinstance(plan, dict):
        raise ReferenceCompatibilityError("fingerprint collection plan is missing")
    if plan.get("cellIds") != list(contract.cell_ids):
        raise ReferenceCompatibilityError("fingerprint cell order does not match ReferenceSet")
    if plan.get("samplesPerCell") != contract.samples_per_cell:
        raise ReferenceCompatibilityError("fingerprint plan samples do not match ReferenceSet")
    if plan.get("expectedSamples") != contract.cell_count * contract.samples_per_cell:
        raise ReferenceCompatibilityError("fingerprint expected sample count does not match")
    if fingerprint_manifest_sha256(fingerprint) != contract.battery_manifest_sha256:
        raise ReferenceCompatibilityError("fingerprint battery manifest digest does not match")
    quality = fingerprint.get("quality")
    if not isinstance(quality, dict):
        raise ReferenceCompatibilityError("fingerprint quality is missing")
    raw_sha256 = quality.get("rawEvidenceSha256")
    if not _is_sha256(raw_sha256):
        raise ReferenceCompatibilityError("fingerprint raw evidence digest is invalid")
    if expected_raw_evidence_sha256 is not None and raw_sha256 != expected_raw_evidence_sha256:
        raise ReferenceCompatibilityError("fingerprint raw evidence digest does not match")
    if require_complete and (
        fingerprint.get("partial") is True
        or quality.get("complete") is not True
        or quality.get("completedSamples") != contract.cell_count * contract.samples_per_cell
        or quality.get("expectedSamples") != contract.cell_count * contract.samples_per_cell
    ):
        raise ReferenceCompatibilityError("reference member fingerprint is incomplete")


def _validated_counts(cell: Mapping[str, Any], *, cell_id: str) -> dict[str, int]:
    counts = cell.get("counts")
    if not isinstance(counts, dict) or not counts:
        raise ValueError(f"fingerprint cell {cell_id} has no valid answer distribution")
    validated: dict[str, int] = {}
    for answer, count in counts.items():
        if not isinstance(answer, str) or not answer:
            raise ValueError(f"fingerprint cell {cell_id} has an invalid answer")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"fingerprint cell {cell_id} has an invalid answer count")
        if count:
            validated[answer] = count
    if not validated:
        raise ValueError(f"fingerprint cell {cell_id} has no positive answer counts")
    return validated


def jensen_shannon_divergence_base2(
    left_counts: Mapping[str, int],
    right_counts: Mapping[str, int],
) -> float:
    categories = sorted(set(left_counts) | set(right_counts))
    left_total = sum(left_counts.values())
    right_total = sum(right_counts.values())
    if left_total <= 0 or right_total <= 0:
        raise ValueError("JSD requires two non-empty distributions")
    divergence = 0.0
    for category in categories:
        left = left_counts.get(category, 0) / left_total
        right = right_counts.get(category, 0) / right_total
        midpoint = (left + right) / 2
        if left:
            divergence += 0.5 * left * math.log2(left / midpoint)
        if right:
            divergence += 0.5 * right * math.log2(right / midpoint)
    return min(1.0, max(0.0, divergence))


def _array_jsd(left: Sequence[int], right: Sequence[int]) -> float:
    left_total = sum(left)
    right_total = sum(right)
    divergence = 0.0
    for left_count, right_count in zip(left, right, strict=True):
        left_probability = left_count / left_total
        right_probability = right_count / right_total
        midpoint = (left_probability + right_probability) / 2
        if left_probability:
            divergence += 0.5 * left_probability * math.log2(left_probability / midpoint)
        if right_probability:
            divergence += 0.5 * right_probability * math.log2(right_probability / midpoint)
    return min(1.0, max(0.0, divergence))


def _seed_integer(seed: int | str) -> int:
    if isinstance(seed, int):
        return seed
    return int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big")


def _multinomial_draw(
    probabilities: Sequence[float],
    sample_count: int,
    rng: random.Random,
) -> list[int]:
    cumulative: list[float] = []
    running = 0.0
    for probability in probabilities:
        running += probability
        cumulative.append(running)
    cumulative[-1] = 1.0
    result = [0] * len(probabilities)
    for _ in range(sample_count):
        index = bisect.bisect_left(cumulative, rng.random())
        result[min(index, len(result) - 1)] += 1
    return result


def _quantile(sorted_values: Sequence[float], probability: float) -> float:
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def compare_fingerprints(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    cell_ids: Sequence[str],
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    bootstrap_seed: int | str = "reference-set-bootstrap/v1",
) -> dict[str, Any]:
    """Mean base-2 JSD with deterministic within-cell stratified bootstrap."""

    if bootstrap_iterations < 1:
        raise ValueError("bootstrap_iterations must be positive")
    left_cells = left.get("cells")
    right_cells = right.get("cells")
    if not isinstance(left_cells, dict) or not isinstance(right_cells, dict):
        raise ValueError("fingerprints must contain cell mappings")
    if set(left_cells) != set(cell_ids) or set(right_cells) != set(cell_ids):
        raise ValueError("fingerprints must contain exactly the requested cells")

    prepared: list[tuple[list[float], int, list[float], int]] = []
    cell_distances: list[dict[str, Any]] = []
    for cell_id in cell_ids:
        left_cell = left_cells[cell_id]
        right_cell = right_cells[cell_id]
        if not isinstance(left_cell, dict) or not isinstance(right_cell, dict):
            raise ValueError(f"fingerprint cell {cell_id} must be an object")
        left_counts = _validated_counts(left_cell, cell_id=cell_id)
        right_counts = _validated_counts(right_cell, cell_id=cell_id)
        categories = sorted(set(left_counts) | set(right_counts))
        left_total = sum(left_counts.values())
        right_total = sum(right_counts.values())
        left_probabilities = [left_counts.get(category, 0) / left_total for category in categories]
        right_probabilities = [
            right_counts.get(category, 0) / right_total for category in categories
        ]
        prepared.append((left_probabilities, left_total, right_probabilities, right_total))
        cell_distances.append(
            {
                "cellId": cell_id,
                "jsdBase2": jensen_shannon_divergence_base2(left_counts, right_counts),
                "validLeft": left_total,
                "validRight": right_total,
            }
        )

    point_estimate = sum(item["jsdBase2"] for item in cell_distances) / len(cell_distances)
    seed_integer = _seed_integer(bootstrap_seed)
    rng = random.Random(seed_integer)
    replicates: list[float] = []
    for _ in range(bootstrap_iterations):
        total = 0.0
        for left_probabilities, left_total, right_probabilities, right_total in prepared:
            left_draw = _multinomial_draw(left_probabilities, left_total, rng)
            right_draw = _multinomial_draw(right_probabilities, right_total, rng)
            total += _array_jsd(left_draw, right_draw)
        replicates.append(total / len(prepared))
    replicates.sort()
    return {
        "meanJsdBase2": point_estimate,
        "comparableCellCount": len(cell_distances),
        "confidenceInterval95": {
            "lower": _quantile(replicates, 0.025),
            "upper": _quantile(replicates, 0.975),
            "iterations": bootstrap_iterations,
            "seed": seed_integer,
            "method": "within-cell-nonparametric-bootstrap/v1",
        },
        "cells": cell_distances,
    }


def build_reference_statistics(
    members: Sequence[Mapping[str, Any]],
    manifest: ReferenceSetManifest | Mapping[str, Any],
    *,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed_material: str = "reference-set/v1",
) -> dict[str, Any]:
    contract = (
        manifest
        if isinstance(manifest, ReferenceSetManifest)
        else load_reference_set_manifest(manifest)
    )
    if len(members) != REFERENCE_SET_MEMBER_COUNT:
        raise ValueError("reference statistics require exactly three members")
    for member in members:
        validate_member_fingerprint(member, contract, expected_model=contract.actual_model)
        quality = assess_fingerprint_quality(member, cell_ids=contract.cell_ids)
        if quality["sufficient"] is not True:
            raise ReferenceCompatibilityError("reference member has insufficient sample quality")
    pairwise: list[dict[str, Any]] = []
    for left_index, right_index in ((0, 1), (0, 2), (1, 2)):
        comparison = compare_fingerprints(
            members[left_index],
            members[right_index],
            cell_ids=contract.cell_ids,
            bootstrap_iterations=bootstrap_iterations,
            bootstrap_seed=f"{seed_material}:{left_index + 1}:{right_index + 1}",
        )
        pairwise.append(
            {
                "leftMemberOrdinal": left_index + 1,
                "rightMemberOrdinal": right_index + 1,
                **comparison,
            }
        )
    envelope = max(item["confidenceInterval95"]["upper"] for item in pairwise)
    payload = {
        "formatVersion": REFERENCE_STATISTICS_FORMAT_VERSION,
        "referenceManifestSha256": reference_manifest_sha256(contract.as_dict()),
        "pairwiseComparisons": pairwise,
        "referenceEnvelope": envelope,
        "decisionEligible": DECISION_ELIGIBLE,
        "operationalVerdict": OPERATIONAL_VERDICT,
    }
    return validate_reference_statistics_payload(payload)


def validate_reference_statistics_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("formatVersion") != REFERENCE_STATISTICS_FORMAT_VERSION:
        raise ValueError("unsupported reference statistics formatVersion")
    if payload.get("decisionEligible") is not False:
        raise ValueError("reference statistics must remain decision-ineligible")
    if payload.get("operationalVerdict") != OPERATIONAL_VERDICT:
        raise ValueError("reference statistics operational verdict must be unverifiable")
    if not _is_sha256(payload.get("referenceManifestSha256")):
        raise ValueError("reference statistics manifest digest is invalid")
    comparisons = payload.get("pairwiseComparisons")
    if not isinstance(comparisons, list) or len(comparisons) != 3:
        raise ValueError("reference statistics require three pairwise comparisons")
    expected_pairs = {(1, 2), (1, 3), (2, 3)}
    observed_pairs: set[tuple[int, int]] = set()
    upper_bounds: list[float] = []
    for comparison in comparisons:
        if not isinstance(comparison, dict):
            raise ValueError("reference pairwise comparison must be an object")
        pair = (comparison.get("leftMemberOrdinal"), comparison.get("rightMemberOrdinal"))
        if pair not in expected_pairs:
            raise ValueError("reference pairwise comparison has invalid member ordinals")
        observed_pairs.add(pair)
        mean_jsd = comparison.get("meanJsdBase2")
        interval = comparison.get("confidenceInterval95")
        if not isinstance(mean_jsd, (int, float)) or isinstance(mean_jsd, bool):
            raise ValueError("reference pairwise mean JSD is invalid")
        if not 0 <= float(mean_jsd) <= 1 or not isinstance(interval, dict):
            raise ValueError("reference pairwise comparison is outside JSD bounds")
        if comparison.get("comparableCellCount") != REFERENCE_CELL_COUNT:
            raise ValueError("reference pairwise comparison must cover all 40 cells")
        cells = comparison.get("cells")
        if not isinstance(cells, list) or len(cells) != REFERENCE_CELL_COUNT:
            raise ValueError("reference pairwise comparison cell statistics are incomplete")
        cell_ids: set[str] = set()
        cell_values: list[float] = []
        for cell in cells:
            if not isinstance(cell, dict) or not isinstance(cell.get("cellId"), str):
                raise ValueError("reference pairwise cell statistic is invalid")
            cell_ids.add(cell["cellId"])
            cell_jsd = cell.get("jsdBase2")
            if (
                not isinstance(cell_jsd, (int, float))
                or isinstance(cell_jsd, bool)
                or not 0 <= cell_jsd <= 1
            ):
                raise ValueError("reference pairwise cell JSD is invalid")
            if not all(
                isinstance(cell.get(field), int)
                and not isinstance(cell.get(field), bool)
                and cell[field] > 0
                for field in ("validLeft", "validRight")
            ):
                raise ValueError("reference pairwise cell sample count is invalid")
            cell_values.append(float(cell_jsd))
        if len(cell_ids) != REFERENCE_CELL_COUNT:
            raise ValueError("reference pairwise cells are not unique")
        if not math.isclose(
            float(mean_jsd),
            sum(cell_values) / REFERENCE_CELL_COUNT,
            rel_tol=0,
            abs_tol=1e-15,
        ):
            raise ValueError("reference pairwise mean JSD is not derived from its cells")
        lower = interval.get("lower")
        upper = interval.get("upper")
        if not isinstance(lower, (int, float)) or not isinstance(upper, (int, float)):
            raise ValueError("reference pairwise confidence interval is invalid")
        if isinstance(lower, bool) or isinstance(upper, bool) or not 0 <= lower <= upper <= 1:
            raise ValueError("reference pairwise confidence interval is outside JSD bounds")
        if (
            interval.get("method") != "within-cell-nonparametric-bootstrap/v1"
            or not isinstance(interval.get("iterations"), int)
            or isinstance(interval.get("iterations"), bool)
            or interval["iterations"] < 1
            or not isinstance(interval.get("seed"), int)
            or isinstance(interval.get("seed"), bool)
        ):
            raise ValueError("reference pairwise bootstrap metadata is invalid")
        upper_bounds.append(float(upper))
    if observed_pairs != expected_pairs:
        raise ValueError("reference statistics do not cover all member pairs")
    envelope = payload.get("referenceEnvelope")
    if not isinstance(envelope, (int, float)) or isinstance(envelope, bool):
        raise ValueError("reference envelope is invalid")
    if not math.isclose(float(envelope), max(upper_bounds), rel_tol=0, abs_tol=1e-15):
        raise ValueError("reference envelope is not derived from pairwise upper bounds")
    return copy.deepcopy(dict(payload))


def assess_fingerprint_quality(
    fingerprint: Mapping[str, Any],
    *,
    cell_ids: Sequence[str],
    minimum_valid_per_cell: int = MINIMUM_VALID_SAMPLES_PER_CELL,
) -> dict[str, Any]:
    reasons: list[str] = []
    quality = fingerprint.get("quality")
    if not isinstance(quality, dict) or quality.get("complete") is not True:
        reasons.append("fingerprint_incomplete")
    if fingerprint.get("partial") is True:
        reasons.append("partial_fingerprint")
    cells = fingerprint.get("cells")
    sufficient_cells = 0
    minimum_observed: int | None = None
    totals = {key: 0 for key in ("valid", "invalid", "refusal", "empty", "error")}
    if not isinstance(cells, dict) or set(cells) != set(cell_ids):
        reasons.append("cell_coverage_mismatch")
        cells = {}
    for cell_id in cell_ids:
        cell = cells.get(cell_id)
        if not isinstance(cell, dict):
            continue
        counts = cell.get("counts")
        valid = cell.get("validCount")
        if not isinstance(valid, int) or isinstance(valid, bool) or valid < 0:
            valid = sum(counts.values()) if isinstance(counts, dict) else 0
        if not isinstance(counts, dict) or any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in counts.values()
        ):
            reasons.append("cell_answer_counts_invalid")
        elif sum(counts.values()) != valid:
            reasons.append("cell_valid_count_mismatch")
        if cell.get("totalCount") != REFERENCE_SAMPLES_PER_CELL:
            reasons.append("cell_total_count_mismatch")
        minimum_observed = valid if minimum_observed is None else min(minimum_observed, valid)
        if valid >= minimum_valid_per_cell:
            sufficient_cells += 1
        totals["valid"] += valid
        for field, total_key in (
            ("invalidCount", "invalid"),
            ("refusalCount", "refusal"),
            ("emptyCount", "empty"),
            ("errorCount", "error"),
        ):
            value = cell.get(field)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                totals[total_key] += value
    if sufficient_cells != len(cell_ids):
        reasons.append("minimum_valid_samples_per_cell_not_met")
    return {
        "sufficient": not reasons,
        "reasonCodes": list(dict.fromkeys(reasons)),
        "cellCoverage": len(cells) / len(cell_ids),
        "sufficientCellCount": sufficient_cells,
        "cellCount": len(cell_ids),
        "minimumValidPerCellRequired": minimum_valid_per_cell,
        "minimumValidPerCellObserved": minimum_observed,
        "validSamples": totals["valid"],
        "invalidSamples": totals["invalid"],
        "refusalSamples": totals["refusal"],
        "emptySamples": totals["empty"],
        "errorSamples": totals["error"],
        "directness": quality.get("directness") if isinstance(quality, dict) else None,
    }


def _status_result(status: ExploratoryStatus, reasons: Sequence[str]) -> dict[str, Any]:
    return {
        "status": status,
        "reasonCodes": list(reasons),
        "decisionEligible": DECISION_ELIGIBLE,
        "operationalVerdict": OPERATIONAL_VERDICT,
    }


def compare_target_to_reference(
    target: Mapping[str, Any] | None,
    members: Sequence[Mapping[str, Any]],
    manifest: ReferenceSetManifest | Mapping[str, Any],
    reference_statistics: Mapping[str, Any],
    *,
    failure_status: Literal["unsupported_protocol", "request_failed"] | None = None,
    target_protocol: str | None = None,
    target_transport_profile_id: str | None = None,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed_material: str = "reference-target/v1",
) -> dict[str, Any]:
    """Compare one target against all members while preserving quality-first semantics."""

    if failure_status is not None:
        return _status_result(failure_status, [failure_status])
    if target is None:
        return _status_result("request_failed", ["target_fingerprint_missing"])
    contract = (
        manifest
        if isinstance(manifest, ReferenceSetManifest)
        else load_reference_set_manifest(manifest)
    )
    statistics = validate_reference_statistics_payload(reference_statistics)
    if statistics["referenceManifestSha256"] != reference_manifest_sha256(contract.as_dict()):
        raise ValueError("reference statistics do not belong to this ReferenceSet manifest")
    if len(members) != REFERENCE_SET_MEMBER_COUNT:
        raise ValueError("target comparison requires exactly three reference members")
    try:
        for member in members:
            validate_member_fingerprint(member, contract, expected_model=contract.actual_model)
        validate_member_fingerprint(
            target,
            contract,
            require_complete=False,
            protocol=target_protocol,
            transport_profile_id=target_transport_profile_id,
        )
    except ReferenceCompatibilityError as error:
        return _status_result("unsupported_protocol", [str(error)])

    quality = assess_fingerprint_quality(target, cell_ids=contract.cell_ids)
    if quality["sufficient"] is not True:
        return {
            **_status_result("insufficient_quality", quality["reasonCodes"]),
            "quality": quality,
        }

    distances: list[dict[str, Any]] = []
    for index, member in enumerate(members, start=1):
        comparison = compare_fingerprints(
            member,
            target,
            cell_ids=contract.cell_ids,
            bootstrap_iterations=bootstrap_iterations,
            bootstrap_seed=f"{seed_material}:{index}",
        )
        distances.append({"referenceMemberOrdinal": index, **comparison})
    means = [float(item["meanJsdBase2"]) for item in distances]
    middle = median(means)
    mad = median(abs(value - middle) for value in means)
    envelope = float(statistics["referenceEnvelope"])
    maximum_upper = max(item["confidenceInterval95"]["upper"] for item in distances)
    minimum_lower = min(item["confidenceInterval95"]["lower"] for item in distances)
    if maximum_upper <= envelope:
        status: ExploratoryStatus = "exploratory_reference_like"
        reasons = ["all_target_upper_bounds_within_reference_envelope"]
    elif minimum_lower > envelope:
        status = "exploratory_reference_deviation"
        reasons = ["all_target_lower_bounds_above_reference_envelope"]
    else:
        status = "inconclusive"
        reasons = ["target_intervals_overlap_reference_envelope"]
    return {
        **_status_result(status, reasons),
        "quality": quality,
        "distances": distances,
        "medianMeanJsdBase2": middle,
        "madMeanJsdBase2": mad,
        "minimumMeanJsdBase2": min(means),
        "maximumMeanJsdBase2": max(means),
        "maximumUpperBound95": maximum_upper,
        "minimumLowerBound95": minimum_lower,
        "referenceEnvelope": envelope,
    }
