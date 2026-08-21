"""Strict, content-addressed calibration policy for One Token decisions.

This module intentionally contains no policy discovery or activation logic.
Persisting a policy is not the same as enrolling it for operational use: a
caller must explicitly load a fully validated :class:`ThresholdPolicy` and
provide an exact :class:`ComparisonScope` to the decision gate.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from relay_auditor.evidence import Artifact, EvidenceStore

POLICY_FORMAT_VERSION = "one-token-threshold-policy/v1"
POLICY_ENVELOPE_FORMAT_VERSION = "one-token-threshold-policy-envelope/v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        revalidate_instances="always",
        strict=True,
    )


def _validate_nonempty_exact(value: str, label: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string without surrounding whitespace")
    return value


def _validate_sha256(value: str, label: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _validate_artifact_id(value: str, label: str) -> str:
    if not _UUID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase UUID")
    return value


class ModelScope(_StrictModel):
    """Exact environment/model/protocol population covered by a policy."""

    environment: Literal["real", "mock"]
    providerScope: str = Field(min_length=1, max_length=255)
    model: str = Field(min_length=1, max_length=255)
    protocol: str = Field(min_length=1, max_length=100)

    @field_validator("providerScope", "model", "protocol")
    @classmethod
    def validate_exact_strings(cls, value: str, info: Any) -> str:
        return _validate_nonempty_exact(value, f"modelScope.{info.field_name}")


class QualityGates(_StrictModel):
    """Collection-quality requirements used while calibrating and comparing."""

    requireProtocolMatch: bool
    requireNoPostReasoning: bool
    requireZeroReasoningTokens: bool
    requireDirectnessVerified: bool
    requireRawEvidence: bool
    minValidSamplesPerCell: int = Field(ge=1)

    def is_safe_for_operational_use(self) -> bool:
        return (
            self.requireProtocolMatch
            and self.requireNoPostReasoning
            and self.requireZeroReasoningTokens
            and self.requireDirectnessVerified
            and self.requireRawEvidence
        )


class ConfidenceInterval(_StrictModel):
    lower: float = Field(ge=0, le=1, allow_inf_nan=False)
    upper: float = Field(ge=0, le=1, allow_inf_nan=False)
    confidenceLevel: float = Field(gt=0, lt=1, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_bounds(self) -> ConfidenceInterval:
        if self.lower > self.upper:
            raise ValueError("confidence interval lower must not exceed upper")
        return self


class SourceArtifactIds(_StrictModel):
    """Disjoint calibration-training and independent holdout evidence."""

    training: tuple[str, ...] = Field(min_length=1)
    holdout: tuple[str, ...] = Field(min_length=1)

    @field_validator("training", "holdout", mode="before")
    @classmethod
    def accept_json_arrays(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("training", "holdout")
    @classmethod
    def validate_ids(cls, values: tuple[str, ...], info: Any) -> tuple[str, ...]:
        for value in values:
            _validate_artifact_id(value, f"sourceArtifactIds.{info.field_name} item")
        if len(set(values)) != len(values):
            raise ValueError(f"sourceArtifactIds.{info.field_name} must not contain duplicates")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def validate_disjoint_sets(self) -> SourceArtifactIds:
        overlap = set(self.training).intersection(self.holdout)
        if overlap:
            raise ValueError("sourceArtifactIds training and holdout must be disjoint")
        return self


class ThresholdPolicy(_StrictModel):
    """Complete schema for a calibrated One Token threshold policy.

    Draft policies may omit the statistical fields. Validated and retired
    policies represent complete historical calibration records; only the
    ``validated`` status is decision eligible.
    """

    formatVersion: Literal[POLICY_FORMAT_VERSION]
    id: str
    status: Literal["draft", "validated", "retired"]
    methodProfileSha256: str = Field(
        description=(
            "SHA-256 of the UTF-8 protocol manifest serialized as compact JSON "
            "with object keys recursively sorted and array order preserved"
        )
    )
    modelScope: ModelScope
    cellSelection: tuple[str, ...] = Field(min_length=1)
    referenceSamplesPerCell: int = Field(ge=1)
    targetSamplesPerCell: int = Field(ge=1)
    minComparableCells: int = Field(ge=1)
    matchMax: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    mismatchMin: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    qualityGates: QualityGates
    genuineCount: int | None = Field(default=None, ge=0)
    impostorCount: int | None = Field(default=None, ge=0)
    holdoutGenuineCount: int | None = Field(default=None, ge=0)
    holdoutImpostorCount: int | None = Field(default=None, ge=0)
    far: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    frr: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    farConfidenceInterval: ConfidenceInterval | None = None
    frrConfidenceInterval: ConfidenceInterval | None = None
    sourceArtifactIds: SourceArtifactIds | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _validate_artifact_id(value, "id")

    @field_validator("methodProfileSha256")
    @classmethod
    def validate_profile_sha256(cls, value: str) -> str:
        return _validate_sha256(value, "methodProfileSha256")

    @field_validator("cellSelection", mode="before")
    @classmethod
    def accept_json_cell_array(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("cellSelection")
    @classmethod
    def validate_cells(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("cellSelection must not contain duplicates")
        for value in values:
            _validate_nonempty_exact(value, "cellSelection item")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def validate_invariants(self) -> ThresholdPolicy:
        if self.minComparableCells > len(self.cellSelection):
            raise ValueError("minComparableCells must not exceed selected cell count")
        minimum = self.qualityGates.minValidSamplesPerCell
        if minimum > self.referenceSamplesPerCell or minimum > self.targetSamplesPerCell:
            raise ValueError(
                "qualityGates.minValidSamplesPerCell must not exceed requested samples per cell"
            )

        complete_fields: dict[str, object | None] = {
            "matchMax": self.matchMax,
            "mismatchMin": self.mismatchMin,
            "genuineCount": self.genuineCount,
            "impostorCount": self.impostorCount,
            "holdoutGenuineCount": self.holdoutGenuineCount,
            "holdoutImpostorCount": self.holdoutImpostorCount,
            "far": self.far,
            "frr": self.frr,
            "farConfidenceInterval": self.farConfidenceInterval,
            "frrConfidenceInterval": self.frrConfidenceInterval,
            "sourceArtifactIds": self.sourceArtifactIds,
        }
        present = {key for key, value in complete_fields.items() if value is not None}
        if self.status == "draft":
            threshold_fields = {"matchMax", "mismatchMin"}
            if present.intersection(threshold_fields) not in (set(), threshold_fields):
                raise ValueError("draft matchMax and mismatchMin must be provided together")
            return self

        missing = set(complete_fields).difference(present)
        if missing:
            fields = ", ".join(sorted(missing))
            raise ValueError(
                f"{self.status} policy is missing complete calibration fields: {fields}"
            )

        assert self.matchMax is not None
        assert self.mismatchMin is not None
        if self.matchMax >= self.mismatchMin:
            raise ValueError("matchMax must be strictly less than mismatchMin")
        if not self.qualityGates.is_safe_for_operational_use():
            raise ValueError(f"{self.status} policy requires all safety quality gates")

        for field_name in (
            "genuineCount",
            "impostorCount",
            "holdoutGenuineCount",
            "holdoutImpostorCount",
        ):
            if cast(int, getattr(self, field_name)) <= 0:
                raise ValueError(f"{field_name} must be positive for {self.status} policy")

        assert self.far is not None
        assert self.frr is not None
        assert self.farConfidenceInterval is not None
        assert self.frrConfidenceInterval is not None
        if not self.farConfidenceInterval.lower <= self.far <= self.farConfidenceInterval.upper:
            raise ValueError("far must fall within farConfidenceInterval")
        if not self.frrConfidenceInterval.lower <= self.frr <= self.frrConfidenceInterval.upper:
            raise ValueError("frr must fall within frrConfidenceInterval")
        return self

    @property
    def decision_eligible(self) -> bool:
        return self.status == "validated"

    def canonical_json(self) -> str:
        return canonical_policy_json(self)

    def sha256(self) -> str:
        return policy_sha256(self)


class ComparisonScope(_StrictModel):
    """Exact observed/configured comparison scope bound to a policy."""

    methodProfileSha256: str = Field(
        description=(
            "SHA-256 of the UTF-8 protocol manifest serialized as compact JSON "
            "with object keys recursively sorted and array order preserved"
        )
    )
    modelScope: ModelScope
    cellSelection: tuple[str, ...] = Field(min_length=1)
    referenceSamplesPerCell: int = Field(ge=1)
    targetSamplesPerCell: int = Field(ge=1)
    comparableCells: int = Field(ge=0)
    qualityGates: QualityGates
    qualityPassed: bool

    @field_validator("methodProfileSha256")
    @classmethod
    def validate_profile_sha256(cls, value: str) -> str:
        return _validate_sha256(value, "methodProfileSha256")

    @field_validator("cellSelection", mode="before")
    @classmethod
    def accept_json_cell_array(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("cellSelection")
    @classmethod
    def validate_cells(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("cellSelection must not contain duplicates")
        for value in values:
            _validate_nonempty_exact(value, "cellSelection item")
        return tuple(sorted(values))

    def mismatch_reasons(self, policy: ThresholdPolicy) -> list[str]:
        reasons: list[str] = []
        if self.methodProfileSha256 != policy.methodProfileSha256:
            reasons.append("method_profile_mismatch")
        if self.modelScope != policy.modelScope:
            reasons.append("model_scope_mismatch")
        if self.cellSelection != policy.cellSelection:
            reasons.append("cell_selection_mismatch")
        if self.referenceSamplesPerCell != policy.referenceSamplesPerCell:
            reasons.append("reference_samples_per_cell_mismatch")
        if self.targetSamplesPerCell != policy.targetSamplesPerCell:
            reasons.append("target_samples_per_cell_mismatch")
        if self.comparableCells < policy.minComparableCells:
            reasons.append("comparable_cells_below_policy_minimum")
        if self.qualityGates != policy.qualityGates:
            reasons.append("quality_gates_mismatch")
        if not self.qualityPassed:
            reasons.append("comparison_quality_gates_failed")
        return reasons


def canonical_policy_json(policy: ThresholdPolicy) -> str:
    """Return the sole canonical serialization used for policy identity."""

    if not isinstance(policy, ThresholdPolicy):
        raise TypeError("policy must be a validated ThresholdPolicy instance")
    payload = policy.model_dump(mode="json", by_alias=True)
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def policy_sha256(policy: ThresholdPolicy) -> str:
    return hashlib.sha256(canonical_policy_json(policy).encode("utf-8")).hexdigest()


def policy_envelope(policy: ThresholdPolicy) -> dict[str, object]:
    return {
        "formatVersion": POLICY_ENVELOPE_FORMAT_VERSION,
        "policy": policy.model_dump(mode="json", by_alias=True),
        "policySha256": policy_sha256(policy),
    }


def _reject_duplicate_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _decode_payload(payload: Mapping[str, object] | str | bytes) -> Mapping[str, object]:
    if isinstance(payload, Mapping):
        return payload
    if not isinstance(payload, (str, bytes)):
        raise TypeError("policy payload must be a mapping, JSON string, or JSON bytes")
    decoded = json.loads(
        payload,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite_json,
    )
    if not isinstance(decoded, Mapping):
        raise ValueError("policy JSON must contain an object")
    return decoded


def load_threshold_policy(
    payload: Mapping[str, object] | str | bytes,
    *,
    expected_sha256: str | None = None,
) -> ThresholdPolicy:
    """Strictly validate a bare policy or a hash-bound policy envelope."""

    outer = _decode_payload(payload)
    bound_sha256: str | None = None
    if "policy" in outer:
        allowed = {"formatVersion", "policy", "policySha256"}
        unknown = set(outer).difference(allowed)
        if unknown:
            raise ValueError(f"policy envelope contains unknown fields: {sorted(unknown)}")
        if outer.get("formatVersion") != POLICY_ENVELOPE_FORMAT_VERSION:
            raise ValueError("unsupported policy envelope formatVersion")
        nested = outer["policy"]
        if not isinstance(nested, Mapping):
            raise ValueError("policy envelope policy must be an object")
        policy_payload = nested
        if "policySha256" in outer:
            value = outer["policySha256"]
            if not isinstance(value, str):
                raise ValueError("policySha256 must be a lowercase SHA-256 hex digest")
            bound_sha256 = _validate_sha256(value, "policySha256")
    else:
        policy_payload = outer

    policy = ThresholdPolicy.model_validate(policy_payload)
    actual_sha256 = policy_sha256(policy)
    if bound_sha256 is not None and bound_sha256 != actual_sha256:
        raise ValueError("policySha256 does not match canonical policy content")
    if expected_sha256 is not None:
        _validate_sha256(expected_sha256, "expected_sha256")
        if expected_sha256 != actual_sha256:
            raise ValueError("expected_sha256 does not match canonical policy content")
    return policy


@dataclass(frozen=True)
class StoredThresholdPolicy:
    artifact: Artifact
    policy_sha256: str


def write_threshold_policy(
    store: EvidenceStore,
    policy: ThresholdPolicy,
) -> StoredThresholdPolicy:
    """Persist a policy as inert calibration evidence; it is not activated."""

    if not isinstance(policy, ThresholdPolicy):
        raise TypeError("policy must be a validated ThresholdPolicy instance")
    artifact = store.write_json("calibrations", policy.id, policy_envelope(policy))
    return StoredThresholdPolicy(artifact=artifact, policy_sha256=policy_sha256(policy))


def read_threshold_policy(
    store: EvidenceStore,
    policy_id: str,
    *,
    expected_sha256: str | None = None,
) -> ThresholdPolicy:
    """Read and verify inert calibration evidence from the local store."""

    _validate_artifact_id(policy_id, "policy_id")
    path = store.path_for("calibrations", policy_id)
    if not path.is_file():
        raise FileNotFoundError(f"threshold policy not found: {policy_id}")
    return load_threshold_policy(path.read_bytes(), expected_sha256=expected_sha256)


def read_threshold_policy_file(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> ThresholdPolicy:
    """Read a policy file without enrolling it into any application route."""

    return load_threshold_policy(path.read_bytes(), expected_sha256=expected_sha256)
