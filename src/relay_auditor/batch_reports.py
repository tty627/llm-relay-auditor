"""Canonical, secret-safe terminal reports for one-model audit batches.

The JSON artifact is the source of truth. CSV is deliberately accepted only
from a JSON artifact whose digest and canonical representation were verified.
This module does not know how credentials are stored; callers provide active
credential/canary values to :class:`SecretCanaryScanner` immediately before
publishing an artifact.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

REPORT_SCHEMA_VERSION = "relay-auditor.one-model-batch-report.v1"
REPORT_KIND = "one_model_batch_terminal_report"

TERMINAL_BATCH_STATUSES = frozenset({"completed", "failed", "canceled", "interrupted"})
TERMINAL_TARGET_STATUSES = frozenset({"completed", "failed", "canceled", "interrupted"})
NON_TERMINAL_TARGET_STATUSES = frozenset(
    {"queued", "running", "paused", "canceling", "pending"}
)
EXPLORATORY_STATUSES = frozenset(
    {
        "exploratory_reference_like",
        "exploratory_reference_deviation",
        "inconclusive",
        "insufficient_quality",
        "unsupported_protocol",
        "request_failed",
        "canceled",
        "interrupted",
        "failed",
    }
)
PROTOCOLS = frozenset({"openai_chat", "anthropic_messages"})
SOURCE_TYPES = frozenset({"official_api", "trusted_relay"})
DIRECTNESS_VALUES = frozenset({"verified", "claimed", "violated", "unknown"})
TRANSPORT_PROFILE_BY_PROTOCOL = {
    "openai_chat": "openai-chat-onetoken-v1",
    "anthropic_messages": "anthropic-messages-opus5-onetoken-v1",
}
REFERENCE_CELL_COUNT = 40
SAMPLES_PER_CELL = 30
LOGICAL_SAMPLE_COUNT = REFERENCE_CELL_COUNT * SAMPLES_PER_CELL
MINIMUM_VALID_PER_CELL = 24

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_DANGEROUS_CSV_PREFIXES = frozenset("=+-@")
_UNICODE_DIGIT_TRANSLATION = str.maketrans(
    "０１２３４５６７８９٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹",
    "012345678901234567890123456789",
)
_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "apikey",
        "apikeyenv",
        "authorization",
        "credential",
        "credentialhash",
        "credentialref",
        "envname",
        "errorbody",
        "keyenv",
        "keyhash",
        "rawerrorbody",
        "requestbody",
        "responsebody",
        "secret",
        "upstreambody",
        "xapikey",
    }
)

CSV_COLUMNS = (
    "schema_version",
    "batch_id",
    "batch_status",
    "reference_set_id",
    "reference_set_name",
    "reference_source_type",
    "protocol",
    "transport_profile",
    "logical_model",
    "row_id",
    "station_name",
    "base_url",
    "requested_model",
    "reported_model",
    "status",
    "exploratory_status",
    "operational_verdict",
    "decision_eligible",
    "reason_codes",
    "preflight_status",
    "preflight_http_status",
    "preflight_attempts",
    "preflight_latency_ms",
    "preflight_reason_code",
    "valid_samples",
    "invalid_samples",
    "error_samples",
    "coverage_cells",
    "total_cells",
    "directness",
    "split_half_mean_jsd",
    "reference_member_1_id",
    "reference_member_1_mean_jsd",
    "reference_member_1_ci_lower",
    "reference_member_1_ci_upper",
    "reference_member_2_id",
    "reference_member_2_mean_jsd",
    "reference_member_2_ci_lower",
    "reference_member_2_ci_upper",
    "reference_member_3_id",
    "reference_member_3_mean_jsd",
    "reference_member_3_ci_lower",
    "reference_member_3_ci_upper",
    "median_mean_jsd",
    "mad_mean_jsd",
    "min_mean_jsd",
    "max_mean_jsd",
    "latency_p50_ms",
    "latency_p95_ms",
    "logical_samples",
    "request_attempts",
    "retries",
    "retry_budget_used",
    "discarded_attempts",
    "artifact_id",
    "artifact_sha256",
    "raw_evidence_sha256",
    "comparison_artifact_sha256",
    "partial_artifact_sha256",
    "error_code",
    "error_http_status",
)


class BatchReportValidationError(ValueError):
    """The requested report cannot satisfy the versioned report contract."""


class BatchReportIntegrityError(ValueError):
    """A stored report is missing, modified, or not canonical JSON."""


class SecretCanaryDetected(RuntimeError):
    """A report candidate contains a credential or one of its transforms."""


@dataclass(frozen=True)
class ReportArtifact:
    path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class VerifiedBatchReport:
    """Opaque proof that a canonical report was loaded through the verifier."""

    path: Path
    sha256: str
    payload: dict[str, Any]
    encoded: bytes


def _legacy_normalize(value: str) -> str:
    canonical = unicodedata.normalize("NFC", value).casefold().strip()
    cleaned = "".join(
        character
        for character in canonical
        if character.isalnum() or character.isspace()
    )
    return "".join(cleaned.translate(_UNICODE_DIGIT_TRANSLATION).split())


class SecretCanaryScanner:
    """Independently detect exact and historically normalized secret echoes."""

    __slots__ = ("_exact", "_normalized", "_legacy")

    def __init__(self, canaries: Iterable[str] = ()) -> None:
        exact: set[str] = set()
        normalized: set[str] = set()
        legacy: set[str] = set()
        for raw in canaries:
            if not isinstance(raw, str):
                raise TypeError("secret canaries must be strings")
            if not raw:
                continue
            exact.add(raw)
            normalized_value = unicodedata.normalize("NFC", raw).casefold()
            if normalized_value:
                normalized.add(normalized_value)
            legacy_value = _legacy_normalize(raw)
            if legacy_value:
                legacy.add(legacy_value)
        self._exact = tuple(sorted(exact, key=len, reverse=True))
        self._normalized = tuple(sorted(normalized, key=len, reverse=True))
        self._legacy = tuple(sorted(legacy, key=len, reverse=True))

    def __repr__(self) -> str:
        return f"SecretCanaryScanner(canary_count={len(self._exact)})"

    @property
    def configured(self) -> bool:
        return bool(self._exact)

    def _string_contains_canary(self, candidate: str) -> bool:
        if any(secret in candidate for secret in self._exact):
            return True
        normalized = unicodedata.normalize("NFC", candidate).casefold()
        if any(secret in normalized for secret in self._normalized):
            return True
        legacy = _legacy_normalize(candidate)
        return any(secret in legacy for secret in self._legacy)

    def contains(self, value: Any) -> bool:
        if not self.configured:
            return False
        if isinstance(value, str):
            return self._string_contains_canary(value)
        if isinstance(value, bytes):
            if any(secret.encode("utf-8") in value for secret in self._exact):
                return True
            return self._string_contains_canary(value.decode("utf-8", errors="ignore"))
        if isinstance(value, Mapping):
            return any(
                self._string_contains_canary(str(key)) or self.contains(child)
                for key, child in value.items()
            )
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(self.contains(child) for child in value)
        return False

    def reject(
        self,
        value: Any,
        *,
        delete_paths: Iterable[Path] = (),
    ) -> None:
        if not self.contains(value):
            return
        for path in delete_paths:
            Path(path).unlink(missing_ok=True)
        raise SecretCanaryDetected("report output contained a possible credential echo")


def empty_secret_scanner_for_tests() -> SecretCanaryScanner:
    """Return an explicitly empty scanner for isolated, synthetic tests only.

    Production report entry points intentionally require callers to pass a
    scanner.  This helper keeps tests concise without allowing an omitted
    scanner to silently disable the publishing gate.
    """

    return SecretCanaryScanner()


def _require_secret_scanner(value: Any) -> SecretCanaryScanner:
    if not isinstance(value, SecretCanaryScanner):
        raise TypeError(
            "an explicit SecretCanaryScanner is required; "
            "use empty_secret_scanner_for_tests() only for synthetic tests"
        )
    return value


def reject_secret_canaries(
    value: Any,
    canaries: Iterable[str],
    *,
    delete_paths: Iterable[Path] = (),
) -> None:
    """Standalone security gate usable by HTTP, log, DB, and artifact scans."""

    SecretCanaryScanner(canaries).reject(value, delete_paths=delete_paths)


def _pick(payload: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in payload:
            return payload[name]
    return default


def _required_text(value: Any, label: str, *, max_length: int = 500) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BatchReportValidationError(f"{label} must be a non-empty string")
    clean = value.strip()
    if len(clean) > max_length:
        raise BatchReportValidationError(f"{label} exceeds {max_length} characters")
    return clean


def _optional_text(value: Any, label: str, *, max_length: int = 500) -> str | None:
    if value is None:
        return None
    return _required_text(value, label, max_length=max_length)


def _identifier(value: Any, label: str) -> str:
    clean = _required_text(value, label, max_length=128)
    if not _IDENTIFIER_RE.fullmatch(clean):
        raise BatchReportValidationError(f"{label} is not a safe identifier")
    return clean


def _sha256(value: Any, label: str, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    clean = _required_text(value, label, max_length=64).lower()
    if not _SHA256_RE.fullmatch(clean):
        raise BatchReportValidationError(f"{label} must be a SHA-256 hex digest")
    return clean


def _reason_code(value: Any, label: str) -> str:
    clean = _required_text(value, label, max_length=128).lower()
    if not _REASON_CODE_RE.fullmatch(clean):
        raise BatchReportValidationError(f"{label} must be a machine-readable reason code")
    return clean


def _reason_codes(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise BatchReportValidationError(f"{label} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        code = _reason_code(item, f"{label}[{index}]")
        if code not in result:
            result.append(code)
    return result


def _optional_int(value: Any, label: str, *, minimum: int = 0) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BatchReportValidationError(f"{label} must be an integer >= {minimum}")
    return value


def _git_sha(value: Any, label: str = "tool.git_sha") -> str:
    clean = _required_text(value, label, max_length=64).lower()
    if clean == "unknown" or not _GIT_SHA_RE.fullmatch(clean):
        raise BatchReportValidationError(f"{label} must be a 7 to 64 character hex SHA")
    return clean


def _optional_float(
    value: Any,
    label: str,
    *,
    minimum: float = 0.0,
    maximum: float | None = None,
) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BatchReportValidationError(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise BatchReportValidationError(f"{label} must be a finite number >= {minimum}")
    if maximum is not None and result > maximum:
        raise BatchReportValidationError(f"{label} must be <= {maximum}")
    return result


def _public_url(value: Any, label: str) -> str:
    raw = _required_text(value, label, max_length=2048)
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as error:
        raise BatchReportValidationError(f"{label} is not a valid URL") from error
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BatchReportValidationError(f"{label} must be an HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise BatchReportValidationError(f"{label} must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise BatchReportValidationError(f"{label} must not contain query or fragment data")
    hostname = parsed.hostname.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = hostname if port in {None, default_port} else f"{hostname}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _enum(value: Any, label: str, allowed: frozenset[str]) -> str:
    clean = _required_text(value, label, max_length=128)
    if clean not in allowed:
        raise BatchReportValidationError(f"{label} has unsupported value: {clean}")
    return clean


def _quality(payload: Any, label: str) -> dict[str, Any]:
    source = payload if isinstance(payload, Mapping) else {}
    return {
        "valid_samples": _optional_int(
            _pick(source, "valid_samples", "validSamples"), f"{label}.valid_samples"
        ),
        "invalid_samples": _optional_int(
            _pick(source, "invalid_samples", "invalidSamples"), f"{label}.invalid_samples"
        ),
        "error_samples": _optional_int(
            _pick(source, "error_samples", "errorSamples"), f"{label}.error_samples"
        ),
        "coverage_cells": _optional_int(
            _pick(source, "coverage_cells", "coverageCells"), f"{label}.coverage_cells"
        ),
        "total_cells": _optional_int(
            _pick(source, "total_cells", "totalCells", "cellCount"), f"{label}.total_cells"
        ),
        "directness": _optional_text(
            _pick(source, "directness"), f"{label}.directness", max_length=64
        ),
        "split_half_mean_jsd": _optional_float(
            _pick(source, "split_half_mean_jsd", "splitHalfMeanJsd"),
            f"{label}.split_half_mean_jsd",
            maximum=1.0,
        ),
    }


def _reference_member(payload: Mapping[str, Any], index: int) -> dict[str, Any]:
    label = f"reference_set.members[{index}]"
    return {
        "member_id": _identifier(
            _pick(payload, "member_id", "memberId", "id"), f"{label}.member_id"
        ),
        "ordinal": _optional_int(
            _pick(payload, "ordinal", default=index + 1), f"{label}.ordinal", minimum=1
        ),
        "seed_id": _optional_text(
            _pick(payload, "seed_id", "seedId"), f"{label}.seed_id", max_length=128
        ),
        "artifact_id": _identifier(
            _pick(payload, "artifact_id", "artifactId"), f"{label}.artifact_id"
        ),
        "artifact_sha256": _sha256(
            _pick(payload, "artifact_sha256", "artifactSha256"),
            f"{label}.artifact_sha256",
            optional=False,
        ),
        "raw_evidence_sha256": _sha256(
            _pick(payload, "raw_evidence_sha256", "rawEvidenceSha256"),
            f"{label}.raw_evidence_sha256",
            optional=False,
        ),
        "created_at": _optional_text(
            _pick(payload, "created_at", "createdAt"), f"{label}.created_at", max_length=64
        ),
        "quality": _quality(_pick(payload, "quality", "metrics"), f"{label}.quality"),
    }


def _pairwise_distance(payload: Mapping[str, Any], index: int) -> dict[str, Any]:
    label = f"reference_set.pairwise_distances[{index}]"
    lower = _optional_float(
        _pick(payload, "ci_lower", "ciLower"), f"{label}.ci_lower", maximum=1.0
    )
    upper = _optional_float(
        _pick(payload, "ci_upper", "ciUpper"), f"{label}.ci_upper", maximum=1.0
    )
    if lower is not None and upper is not None and lower > upper:
        raise BatchReportValidationError(f"{label} confidence interval is reversed")
    return {
        "left_member_id": _identifier(
            _pick(payload, "left_member_id", "leftMemberId"), f"{label}.left_member_id"
        ),
        "right_member_id": _identifier(
            _pick(payload, "right_member_id", "rightMemberId"), f"{label}.right_member_id"
        ),
        "mean_jsd": _optional_float(
            _pick(payload, "mean_jsd", "meanJsd"), f"{label}.mean_jsd", maximum=1.0
        ),
        "ci_lower": lower,
        "ci_upper": upper,
    }


def _sanitize_reference_set(payload: Mapping[str, Any]) -> dict[str, Any]:
    raw_members = _pick(payload, "members", default=[])
    if not isinstance(raw_members, Sequence) or isinstance(raw_members, (str, bytes)):
        raise BatchReportValidationError("reference_set.members must be a list")
    if len(raw_members) != 3:
        raise BatchReportValidationError("reference_set must contain exactly three members")
    if not all(isinstance(member, Mapping) for member in raw_members):
        raise BatchReportValidationError("reference_set members must be objects")
    members = [_reference_member(member, index) for index, member in enumerate(raw_members)]
    member_ids = [member["member_id"] for member in members]
    if len(set(member_ids)) != 3:
        raise BatchReportValidationError("reference_set member IDs must be unique")
    ordinals = [member["ordinal"] for member in members]
    if set(ordinals) != {1, 2, 3}:
        raise BatchReportValidationError("reference_set member ordinals must be 1, 2, and 3")
    members.sort(key=lambda member: int(member["ordinal"]))

    raw_pairwise = _pick(payload, "pairwise_distances", "pairwiseDistances", default=[])
    if not isinstance(raw_pairwise, Sequence) or isinstance(raw_pairwise, (str, bytes)):
        raise BatchReportValidationError("reference_set.pairwise_distances must be a list")
    if len(raw_pairwise) != 3 or not all(isinstance(item, Mapping) for item in raw_pairwise):
        raise BatchReportValidationError("reference_set requires all three pairwise distances")
    pairwise = [_pairwise_distance(item, index) for index, item in enumerate(raw_pairwise)]
    expected_pairs = {
        frozenset((member_ids[0], member_ids[1])),
        frozenset((member_ids[0], member_ids[2])),
        frozenset((member_ids[1], member_ids[2])),
    }
    actual_pairs = {
        frozenset((item["left_member_id"], item["right_member_id"])) for item in pairwise
    }
    if actual_pairs != expected_pairs or any(len(pair) != 2 for pair in actual_pairs):
        raise BatchReportValidationError("reference_set pairwise distances do not cover members")
    pairwise.sort(key=lambda item: (item["left_member_id"], item["right_member_id"]))

    for index, item in enumerate(pairwise):
        if any(item[field] is None for field in ("mean_jsd", "ci_lower", "ci_upper")):
            raise BatchReportValidationError(
                f"reference_set.pairwise_distances[{index}] requires mean and bootstrap interval"
            )

    protocol = _enum(_pick(payload, "protocol"), "reference_set.protocol", PROTOCOLS)
    transport_profile = _identifier(
        _pick(payload, "transport_profile", "transportProfile"),
        "reference_set.transport_profile",
    )
    if transport_profile != TRANSPORT_PROFILE_BY_PROTOCOL[protocol]:
        raise BatchReportValidationError(
            "reference_set protocol and transport_profile do not match"
        )
    raw_envelope = _pick(payload, "envelope", default={})
    raw_envelope = raw_envelope if isinstance(raw_envelope, Mapping) else {}
    envelope = _optional_float(
        _pick(
            raw_envelope,
            "max_upper_jsd",
            "maxUpperJsd",
            default=_pick(payload, "envelope_upper_jsd", "envelopeUpperJsd"),
        ),
        "reference_set.envelope.max_upper_jsd",
        maximum=1.0,
    )
    expected_envelope = max(float(item["ci_upper"]) for item in pairwise)
    if envelope is None or not math.isclose(
        envelope, expected_envelope, rel_tol=0.0, abs_tol=1e-15
    ):
        raise BatchReportValidationError(
            "reference_set envelope is not the maximum pairwise bootstrap upper bound"
        )
    samples_per_cell = _optional_int(
        _pick(payload, "samples_per_cell", "samplesPerCell"),
        "reference_set.samples_per_cell",
        minimum=1,
    )
    if samples_per_cell != SAMPLES_PER_CELL:
        raise BatchReportValidationError(
            f"reference_set.samples_per_cell must be {SAMPLES_PER_CELL}"
        )

    for index, member in enumerate(members):
        quality = member["quality"]
        values = {
            field: quality[field]
            for field in (
                "valid_samples",
                "invalid_samples",
                "error_samples",
                "coverage_cells",
                "total_cells",
            )
        }
        if any(value is None for value in values.values()):
            raise BatchReportValidationError(
                f"reference_set.members[{index}].quality must be complete"
            )
        if quality["directness"] not in DIRECTNESS_VALUES:
            raise BatchReportValidationError(
                f"reference_set.members[{index}].quality.directness is unsupported"
            )
        if quality["split_half_mean_jsd"] is None:
            raise BatchReportValidationError(
                f"reference_set.members[{index}].quality.split_half_mean_jsd is required"
            )
        if quality["total_cells"] != REFERENCE_CELL_COUNT:
            raise BatchReportValidationError(
                f"reference_set.members[{index}].quality.total_cells must be "
                f"{REFERENCE_CELL_COUNT}"
            )
        if not 0 <= quality["coverage_cells"] <= quality["total_cells"]:
            raise BatchReportValidationError(
                f"reference_set.members[{index}].quality coverage is out of range"
            )
        observed_samples = (
            quality["valid_samples"]
            + quality["invalid_samples"]
            + quality["error_samples"]
        )
        if observed_samples != LOGICAL_SAMPLE_COUNT:
            raise BatchReportValidationError(
                f"reference_set.members[{index}].quality sample totals must equal "
                f"{LOGICAL_SAMPLE_COUNT}"
            )
        if (
            quality["coverage_cells"] != REFERENCE_CELL_COUNT
            or quality["valid_samples"]
            < REFERENCE_CELL_COUNT * MINIMUM_VALID_PER_CELL
        ):
            raise BatchReportValidationError(
                f"reference_set.members[{index}] is not a complete selectable reference"
            )
    return {
        "reference_set_id": _identifier(
            _pick(payload, "reference_set_id", "referenceSetId", "id"),
            "reference_set.reference_set_id",
        ),
        "name": _required_text(_pick(payload, "name"), "reference_set.name", max_length=120),
        "source_type": _enum(
            _pick(payload, "source_type", "sourceType"),
            "reference_set.source_type",
            SOURCE_TYPES,
        ),
        "protocol": protocol,
        "transport_profile": transport_profile,
        "logical_model": _required_text(
            _pick(payload, "logical_model", "logicalModel"),
            "reference_set.logical_model",
            max_length=255,
        ),
        "model_id": _required_text(
            _pick(payload, "model_id", "modelId"),
            "reference_set.model_id",
            max_length=255,
        ),
        "base_url": _public_url(
            _pick(payload, "base_url", "baseUrl"), "reference_set.base_url"
        ),
        "battery_sha256": _sha256(
            _pick(payload, "battery_sha256", "batterySha256"),
            "reference_set.battery_sha256",
            optional=False,
        ),
        "samples_per_cell": samples_per_cell,
        "created_at": _optional_text(
            _pick(payload, "created_at", "createdAt"),
            "reference_set.created_at",
            max_length=64,
        ),
        "members": members,
        "pairwise_distances": pairwise,
        "envelope": {
            "method": "max_reference_pairwise_bootstrap_upper",
            "max_upper_jsd": envelope,
        },
    }


def _distance_member(payload: Mapping[str, Any], index: int) -> dict[str, Any]:
    label = f"target.distances.members[{index}]"
    lower = _optional_float(
        _pick(payload, "ci_lower", "ciLower"), f"{label}.ci_lower", maximum=1.0
    )
    upper = _optional_float(
        _pick(payload, "ci_upper", "ciUpper"), f"{label}.ci_upper", maximum=1.0
    )
    if lower is not None and upper is not None and lower > upper:
        raise BatchReportValidationError(f"{label} confidence interval is reversed")
    return {
        "member_id": _identifier(
            _pick(payload, "member_id", "memberId"), f"{label}.member_id"
        ),
        "mean_jsd": _optional_float(
            _pick(payload, "mean_jsd", "meanJsd"), f"{label}.mean_jsd", maximum=1.0
        ),
        "ci_lower": lower,
        "ci_upper": upper,
    }


def _evidence_json_sha256(payload: Mapping[str, Any]) -> str:
    """Match ``EvidenceStore.write_json`` for a parsed comparison artifact."""

    try:
        serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    except (TypeError, ValueError) as error:
        raise BatchReportValidationError(
            "target comparison evidence is not JSON serializable"
        ) from error
    return hashlib.sha256(f"{serialized}\n".encode()).hexdigest()


def _validate_target_semantics(
    target: Mapping[str, Any],
    *,
    reference_member_ids: Sequence[str],
    reference_envelope: float,
) -> None:
    row_id = target["row_id"]
    status = target["status"]
    exploratory_status = target["exploratory_status"]
    metrics = target["metrics"]
    distances = target["distances"]
    latency = target["latency"]
    requests = target["requests"]
    preflight = target["preflight"]
    evidence = target["evidence"]

    http_status = preflight["http_status"]
    if http_status is not None and http_status > 599:
        raise BatchReportValidationError(
            f"target[{row_id}].preflight.http_status must be <= 599"
        )
    error_http_status = target["error"]["http_status"]
    if error_http_status is not None and error_http_status > 599:
        raise BatchReportValidationError(
            f"target[{row_id}].error.http_status must be <= 599"
        )

    coverage = metrics["coverage_cells"]
    total_cells = metrics["total_cells"]
    if coverage is not None and total_cells is not None and coverage > total_cells:
        raise BatchReportValidationError(
            f"target[{row_id}] coverage_cells exceeds total_cells"
        )
    p50 = latency["p50_ms"]
    p95 = latency["p95_ms"]
    if p50 is not None and p95 is not None and p95 < p50:
        raise BatchReportValidationError(f"target[{row_id}] latency p95 is below p50")
    logical_samples = requests["logical_samples"]
    attempts = requests["attempts"]
    retries = requests["retries"]
    retry_budget_used = requests["retry_budget_used"]
    if retry_budget_used is None:
        raise BatchReportValidationError(
            f"target[{row_id}].requests.retry_budget_used must be a non-negative integer"
        )
    if retries is not None and retry_budget_used < retries:
        raise BatchReportValidationError(
            f"target[{row_id}] retry_budget_used cannot be below physical retries"
        )
    discarded_attempts = requests["discarded_attempts"]
    if discarded_attempts is None:
        raise BatchReportValidationError(
            f"target[{row_id}].requests.discarded_attempts must be a non-negative integer"
        )
    if logical_samples is not None and logical_samples > LOGICAL_SAMPLE_COUNT:
        raise BatchReportValidationError(
            f"target[{row_id}].requests.logical_samples exceeds {LOGICAL_SAMPLE_COUNT}"
        )
    if attempts is not None and retries is not None and retries > attempts:
        raise BatchReportValidationError(f"target[{row_id}] retries exceed attempts")
    if attempts is not None and discarded_attempts > attempts:
        raise BatchReportValidationError(
            f"target[{row_id}] discarded attempts exceed all request attempts"
        )
    if (
        attempts is not None
        and preflight["attempts"] is not None
        and preflight["attempts"] > attempts
    ):
        raise BatchReportValidationError(
            f"target[{row_id}] preflight attempts exceed all request attempts"
        )

    expected_exploratory_by_terminal = {
        "canceled": "canceled",
        "interrupted": "interrupted",
    }
    expected_terminal_exploratory = expected_exploratory_by_terminal.get(status)
    if (
        expected_terminal_exploratory is not None
        and exploratory_status != expected_terminal_exploratory
    ):
        raise BatchReportValidationError(
            f"target[{row_id}] terminal and exploratory statuses conflict"
        )
    if status == "failed" and exploratory_status not in {
        "request_failed",
        "unsupported_protocol",
        "failed",
    }:
        raise BatchReportValidationError(
            f"target[{row_id}] failed status has a contradictory exploratory status"
        )
    if status != "completed":
        return

    if exploratory_status not in {
        "exploratory_reference_like",
        "exploratory_reference_deviation",
        "inconclusive",
        "insufficient_quality",
    }:
        raise BatchReportValidationError(
            f"target[{row_id}] completed status has a contradictory exploratory status"
        )
    for field in (
        "artifact_id",
        "artifact_sha256",
        "raw_evidence_sha256",
        "comparison_artifact_sha256",
    ):
        if evidence[field] is None:
            raise BatchReportValidationError(
                f"target[{row_id}] completed result requires {field} evidence"
            )
    if logical_samples != LOGICAL_SAMPLE_COUNT:
        raise BatchReportValidationError(
            f"target[{row_id}] completed result must contain {LOGICAL_SAMPLE_COUNT} "
            "logical samples"
        )
    required_counts = (
        metrics["valid_samples"],
        metrics["invalid_samples"],
        metrics["error_samples"],
    )
    if any(value is None for value in required_counts):
        raise BatchReportValidationError(
            f"target[{row_id}] completed result requires all quality sample counts"
        )
    if sum(required_counts) != LOGICAL_SAMPLE_COUNT:
        raise BatchReportValidationError(
            f"target[{row_id}] quality sample totals do not equal logical_samples"
        )
    if total_cells != REFERENCE_CELL_COUNT or coverage is None:
        raise BatchReportValidationError(
            f"target[{row_id}] completed result requires 40-cell coverage metrics"
        )
    if metrics["directness"] not in DIRECTNESS_VALUES:
        raise BatchReportValidationError(
            f"target[{row_id}].metrics.directness is unsupported"
        )
    if metrics["split_half_mean_jsd"] is None:
        raise BatchReportValidationError(
            f"target[{row_id}] completed result requires split-half stability"
        )
    if attempts is None or retries is None:
        raise BatchReportValidationError(
            f"target[{row_id}] completed result requires request attempts and retries"
        )
    # There are 1,200 retained sampling requests plus exactly one eventual
    # successful preflight. Sampling/preflight retries remain in ``retries``;
    # attempts abandoned by a pause/resume cycle are separately auditable.
    if attempts != logical_samples + retries + 1 + discarded_attempts:
        raise BatchReportValidationError(
            f"target[{row_id}] request attempts are inconsistent with logical samples "
            "retries, and discarded attempts"
        )
    if (
        preflight["status"] != "passed"
        or http_status is None
        or not 200 <= http_status <= 299
        or preflight["attempts"] is None
        or preflight["attempts"] < 1
        or preflight["latency_ms"] is None
    ):
        raise BatchReportValidationError(
            f"target[{row_id}] completed result requires a successful strict preflight"
        )
    if p50 is None or p95 is None:
        raise BatchReportValidationError(
            f"target[{row_id}] completed result requires p50 and p95 latency"
        )

    quality_insufficient = (
        coverage < REFERENCE_CELL_COUNT
        or metrics["valid_samples"]
        < REFERENCE_CELL_COUNT * MINIMUM_VALID_PER_CELL
    )
    if quality_insufficient:
        if exploratory_status != "insufficient_quality":
            raise BatchReportValidationError(
                f"target[{row_id}] insufficient quality must take classification priority"
            )
        if distances["members"] or any(
            distances[field] is not None
            for field in (
                "median_mean_jsd",
                "mad_mean_jsd",
                "min_mean_jsd",
                "max_mean_jsd",
            )
        ):
            raise BatchReportValidationError(
                f"target[{row_id}] insufficient quality cannot publish comparison distances"
            )
        return
    if exploratory_status == "insufficient_quality":
        raise BatchReportValidationError(
            f"target[{row_id}] sufficient quality contradicts insufficient_quality"
        )

    distance_members = distances["members"]
    if len(distance_members) != 3 or {
        item["member_id"] for item in distance_members
    } != set(reference_member_ids):
        raise BatchReportValidationError(
            f"target[{row_id}] requires exactly three reference-member distances"
        )
    for index, item in enumerate(distance_members):
        if any(item[field] is None for field in ("mean_jsd", "ci_lower", "ci_upper")):
            raise BatchReportValidationError(
                f"target[{row_id}].distances.members[{index}] is incomplete"
            )
    means = [float(item["mean_jsd"]) for item in distance_members]
    middle = sorted(means)[1]
    derived = {
        "median_mean_jsd": middle,
        "mad_mean_jsd": sorted(abs(value - middle) for value in means)[1],
        "min_mean_jsd": min(means),
        "max_mean_jsd": max(means),
    }
    for field, expected in derived.items():
        observed = distances[field]
        if observed is None or not math.isclose(
            observed, expected, rel_tol=0.0, abs_tol=1e-15
        ):
            raise BatchReportValidationError(
                f"target[{row_id}].distances.{field} is not derived from member means"
            )
    maximum_upper = max(float(item["ci_upper"]) for item in distance_members)
    minimum_lower = min(float(item["ci_lower"]) for item in distance_members)
    if maximum_upper <= reference_envelope:
        expected_exploratory = "exploratory_reference_like"
    elif minimum_lower > reference_envelope:
        expected_exploratory = "exploratory_reference_deviation"
    else:
        expected_exploratory = "inconclusive"
    if exploratory_status != expected_exploratory:
        raise BatchReportValidationError(
            f"target[{row_id}] exploratory classification contradicts confidence intervals "
            "and reference envelope"
        )


def _sanitize_target(
    row: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    reference_member_ids: Sequence[str],
    reference_envelope: float,
    fallback_status: str | None = None,
) -> dict[str, Any]:
    row_id = _identifier(_pick(row, "row_id", "rowId", "id"), "input_rows.row_id")
    raw_status = fallback_status or _pick(result, "status")
    status = _enum(raw_status, f"target[{row_id}].status", TERMINAL_TARGET_STATUSES)
    default_exploratory = {
        "failed": "request_failed",
        "canceled": "canceled",
        "interrupted": "interrupted",
    }.get(status, "inconclusive")
    exploratory_status = _enum(
        _pick(result, "exploratory_status", "exploratoryStatus", default=default_exploratory),
        f"target[{row_id}].exploratory_status",
        EXPLORATORY_STATUSES,
    )
    reasons = _reason_codes(
        _pick(result, "reason_codes", "reasonCodes", "reasons"),
        f"target[{row_id}].reason_codes",
    )
    if fallback_status is not None:
        fallback_reason = f"batch_{fallback_status}_before_target_terminal"
        if fallback_reason not in reasons:
            reasons.append(fallback_reason)

    raw_distances = _pick(result, "distances", default={})
    raw_distances = raw_distances if isinstance(raw_distances, Mapping) else {}
    raw_distance_members = _pick(raw_distances, "members", default=[])
    if not isinstance(raw_distance_members, Sequence) or isinstance(
        raw_distance_members, (str, bytes)
    ):
        raise BatchReportValidationError(f"target[{row_id}].distances.members must be a list")
    if not all(isinstance(item, Mapping) for item in raw_distance_members):
        raise BatchReportValidationError(f"target[{row_id}] distance members must be objects")
    distance_members = [
        _distance_member(item, index) for index, item in enumerate(raw_distance_members)
    ]
    distance_members.sort(
        key=lambda item: (
            reference_member_ids.index(item["member_id"])
            if item["member_id"] in reference_member_ids
            else 99
        )
    )
    distance_ids = [item["member_id"] for item in distance_members]
    if len(distance_ids) != len(set(distance_ids)) or any(
        member_id not in reference_member_ids for member_id in distance_ids
    ):
        raise BatchReportValidationError(f"target[{row_id}] has invalid reference member distances")
    if exploratory_status in {
        "exploratory_reference_like",
        "exploratory_reference_deviation",
        "inconclusive",
    } and set(distance_ids) != set(reference_member_ids):
        raise BatchReportValidationError(
            f"target[{row_id}] requires distances to all three reference members"
        )

    preflight_raw = _pick(result, "preflight", default={})
    preflight_raw = preflight_raw if isinstance(preflight_raw, Mapping) else {}
    latency_raw = _pick(result, "latency", default={})
    latency_raw = latency_raw if isinstance(latency_raw, Mapping) else {}
    request_raw = _pick(result, "requests", "request_counts", default={})
    request_raw = request_raw if isinstance(request_raw, Mapping) else {}
    evidence_raw = _pick(result, "evidence", default={})
    evidence_raw = evidence_raw if isinstance(evidence_raw, Mapping) else {}
    error_raw = _pick(result, "error", default={})
    error_raw = error_raw if isinstance(error_raw, Mapping) else {}
    error_code_value = _pick(error_raw, "code", default=_pick(result, "error_code"))
    retry_count = _optional_int(
        _pick(request_raw, "retries", "retry_count", "retryCount"),
        f"target[{row_id}].requests.retries",
    )
    comparison_default = (
        _evidence_json_sha256(result) if fallback_status is None else None
    )

    sanitized = {
        "row_id": row_id,
        "station_name": _required_text(
            _pick(row, "station_name", "stationName", "name"),
            f"target[{row_id}].station_name",
            max_length=120,
        ),
        "base_url": _public_url(
            _pick(row, "base_url", "baseUrl"), f"target[{row_id}].base_url"
        ),
        "requested_model": _required_text(
            _pick(
                row,
                "model_id",
                "modelId",
                "model",
                default=_pick(result, "requested_model", "requestedModel"),
            ),
            f"target[{row_id}].requested_model",
            max_length=255,
        ),
        "reported_model": _optional_text(
            _pick(result, "reported_model", "reportedModel"),
            f"target[{row_id}].reported_model",
            max_length=255,
        ),
        "status": status,
        "exploratory_status": exploratory_status,
        "operational_verdict": "unverifiable",
        "decision_eligible": False,
        "reason_codes": reasons,
        "preflight": {
            "status": _optional_text(
                _pick(preflight_raw, "status"),
                f"target[{row_id}].preflight.status",
                max_length=64,
            ),
            "http_status": _optional_int(
                _pick(preflight_raw, "http_status", "httpStatus"),
                f"target[{row_id}].preflight.http_status",
                minimum=100,
            ),
            "attempts": _optional_int(
                _pick(preflight_raw, "attempts"),
                f"target[{row_id}].preflight.attempts",
                minimum=0,
            ),
            "latency_ms": _optional_float(
                _pick(preflight_raw, "latency_ms", "latencyMs"),
                f"target[{row_id}].preflight.latency_ms",
            ),
            "reason_code": (
                _reason_code(
                    _pick(preflight_raw, "reason_code", "reasonCode"),
                    f"target[{row_id}].preflight.reason_code",
                )
                if _pick(preflight_raw, "reason_code", "reasonCode") is not None
                else None
            ),
        },
        "metrics": _quality(
            _pick(result, "metrics", "quality"), f"target[{row_id}].metrics"
        ),
        "distances": {
            "members": distance_members,
            "median_mean_jsd": _optional_float(
                _pick(raw_distances, "median_mean_jsd", "medianMeanJsd"),
                f"target[{row_id}].distances.median_mean_jsd",
                maximum=1.0,
            ),
            "mad_mean_jsd": _optional_float(
                _pick(raw_distances, "mad_mean_jsd", "madMeanJsd"),
                f"target[{row_id}].distances.mad_mean_jsd",
                maximum=1.0,
            ),
            "min_mean_jsd": _optional_float(
                _pick(raw_distances, "min_mean_jsd", "minMeanJsd"),
                f"target[{row_id}].distances.min_mean_jsd",
                maximum=1.0,
            ),
            "max_mean_jsd": _optional_float(
                _pick(raw_distances, "max_mean_jsd", "maxMeanJsd"),
                f"target[{row_id}].distances.max_mean_jsd",
                maximum=1.0,
            ),
        },
        "latency": {
            "p50_ms": _optional_float(
                _pick(latency_raw, "p50_ms", "p50Ms"),
                f"target[{row_id}].latency.p50_ms",
            ),
            "p95_ms": _optional_float(
                _pick(latency_raw, "p95_ms", "p95Ms"),
                f"target[{row_id}].latency.p95_ms",
            ),
        },
        "requests": {
            "logical_samples": _optional_int(
                _pick(request_raw, "logical_samples", "logicalSamples"),
                f"target[{row_id}].requests.logical_samples",
            ),
            "attempts": _optional_int(
                _pick(request_raw, "attempts"), f"target[{row_id}].requests.attempts"
            ),
            "retries": retry_count,
            "retry_budget_used": _optional_int(
                _pick(
                    request_raw,
                    "retry_budget_used",
                    "retryBudgetUsed",
                    default=retry_count if retry_count is not None else 0,
                ),
                f"target[{row_id}].requests.retry_budget_used",
            ),
            "discarded_attempts": _optional_int(
                _pick(
                    request_raw,
                    "discarded_attempts",
                    "discardedAttempts",
                    default=0,
                ),
                f"target[{row_id}].requests.discarded_attempts",
            ),
        },
        "evidence": {
            "artifact_id": (
                _identifier(
                    _pick(evidence_raw, "artifact_id", "artifactId"),
                    f"target[{row_id}].evidence.artifact_id",
                )
                if _pick(evidence_raw, "artifact_id", "artifactId") is not None
                else None
            ),
            "artifact_sha256": _sha256(
                _pick(evidence_raw, "artifact_sha256", "artifactSha256"),
                f"target[{row_id}].evidence.artifact_sha256",
            ),
            "raw_evidence_sha256": _sha256(
                _pick(evidence_raw, "raw_evidence_sha256", "rawEvidenceSha256"),
                f"target[{row_id}].evidence.raw_evidence_sha256",
            ),
            "comparison_artifact_sha256": _sha256(
                _pick(
                    evidence_raw,
                    "comparison_artifact_sha256",
                    "comparisonArtifactSha256",
                    default=comparison_default,
                ),
                f"target[{row_id}].evidence.comparison_artifact_sha256",
                optional=status != "completed",
            ),
            "partial_artifact_sha256": _sha256(
                _pick(evidence_raw, "partial_artifact_sha256", "partialArtifactSha256"),
                f"target[{row_id}].evidence.partial_artifact_sha256",
            ),
        },
        "error": {
            "code": (
                _reason_code(error_code_value, f"target[{row_id}].error.code")
                if error_code_value is not None
                else None
            ),
            "http_status": _optional_int(
                _pick(error_raw, "http_status", "httpStatus"),
                f"target[{row_id}].error.http_status",
                minimum=100,
            ),
        },
    }
    _validate_target_semantics(
        sanitized,
        reference_member_ids=reference_member_ids,
        reference_envelope=reference_envelope,
    )
    return sanitized


def build_terminal_batch_report(
    *,
    batch: Mapping[str, Any],
    reference_set: Mapping[str, Any],
    input_rows: Sequence[Mapping[str, Any]],
    target_results: Sequence[Mapping[str, Any]],
    tool: Mapping[str, Any],
    generated_at: str | None = None,
    secret_scanner: SecretCanaryScanner | None = None,
) -> dict[str, Any]:
    """Build a terminal report while preserving input order and row completeness."""

    if not isinstance(batch, Mapping) or not isinstance(reference_set, Mapping):
        raise BatchReportValidationError("batch and reference_set must be objects")
    if not isinstance(tool, Mapping):
        raise BatchReportValidationError("tool must be an object")
    scanner = _require_secret_scanner(secret_scanner)
    if not input_rows or len(input_rows) > 20:
        raise BatchReportValidationError("input_rows must contain between 1 and 20 rows")
    if not all(isinstance(row, Mapping) for row in input_rows):
        raise BatchReportValidationError("input_rows must contain objects")
    if not all(isinstance(result, Mapping) for result in target_results):
        raise BatchReportValidationError("target_results must contain objects")

    batch_status = _enum(
        _pick(batch, "status"), "batch.status", TERMINAL_BATCH_STATUSES
    )
    sanitized_reference = _sanitize_reference_set(reference_set)
    batch_protocol = _enum(
        _pick(batch, "protocol", default=sanitized_reference["protocol"]),
        "batch.protocol",
        PROTOCOLS,
    )
    if batch_protocol != sanitized_reference["protocol"]:
        raise BatchReportValidationError("batch and reference_set protocols differ")
    batch_transport_profile = _identifier(
        _pick(
            batch,
            "transport_profile",
            "transportProfile",
            default=sanitized_reference["transport_profile"],
        ),
        "batch.transport_profile",
    )
    if (
        batch_transport_profile != sanitized_reference["transport_profile"]
        or batch_transport_profile != TRANSPORT_PROFILE_BY_PROTOCOL[batch_protocol]
    ):
        raise BatchReportValidationError(
            "batch protocol and transport_profile do not match reference_set"
        )
    batch_logical_model = _required_text(
        _pick(batch, "logical_model", "logicalModel", default=sanitized_reference["logical_model"]),
        "batch.logical_model",
        max_length=255,
    )
    if batch_logical_model != sanitized_reference["logical_model"]:
        raise BatchReportValidationError("batch and reference_set logical models differ")

    row_ids = [
        _identifier(_pick(row, "row_id", "rowId", "id"), f"input_rows[{index}].row_id")
        for index, row in enumerate(input_rows)
    ]
    if len(row_ids) != len(set(row_ids)):
        raise BatchReportValidationError("input row IDs must be unique")
    results_by_id: dict[str, Mapping[str, Any]] = {}
    for index, result in enumerate(target_results):
        row_id = _identifier(
            _pick(result, "row_id", "rowId", "id"), f"target_results[{index}].row_id"
        )
        if row_id in results_by_id:
            raise BatchReportValidationError("target result row IDs must be unique")
        if row_id not in set(row_ids):
            raise BatchReportValidationError(f"target result has unknown row ID: {row_id}")
        results_by_id[row_id] = result

    reference_member_ids = [
        str(member["member_id"]) for member in sanitized_reference["members"]
    ]
    targets: list[dict[str, Any]] = []
    for row, row_id in zip(input_rows, row_ids, strict=True):
        result = results_by_id.get(row_id)
        fallback_status: str | None = None
        if result is None:
            if batch_status == "completed":
                raise BatchReportValidationError(
                    f"completed batch is missing terminal result for row: {row_id}"
                )
            result = {"row_id": row_id}
            fallback_status = batch_status
        else:
            raw_status = _pick(result, "status")
            if raw_status in NON_TERMINAL_TARGET_STATUSES or raw_status is None:
                if batch_status == "completed":
                    raise BatchReportValidationError(
                        f"completed batch has non-terminal row: {row_id}"
                    )
                fallback_status = batch_status
        targets.append(
            _sanitize_target(
                row,
                result,
                reference_member_ids=reference_member_ids,
                reference_envelope=sanitized_reference["envelope"]["max_upper_jsd"],
                fallback_status=fallback_status,
            )
        )

    generated = generated_at or datetime.now(UTC).isoformat()
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND,
        "generated_at": _required_text(generated, "generated_at", max_length=64),
        "tool": {
            "name": _required_text(_pick(tool, "name"), "tool.name", max_length=100),
            "version": _required_text(
                _pick(tool, "version"), "tool.version", max_length=100
            ),
            "git_sha": _git_sha(_pick(tool, "git_sha", "gitSha")),
        },
        "batch": {
            "batch_id": _identifier(
                _pick(batch, "batch_id", "batchId", "id"), "batch.batch_id"
            ),
            "status": batch_status,
            "protocol": batch_protocol,
            "transport_profile": batch_transport_profile,
            "logical_model": batch_logical_model,
            "default_model_id": _required_text(
                _pick(batch, "default_model_id", "defaultModelId"),
                "batch.default_model_id",
                max_length=255,
            ),
            "reference_set_id": sanitized_reference["reference_set_id"],
            "created_at": _optional_text(
                _pick(batch, "created_at", "createdAt"), "batch.created_at", max_length=64
            ),
            "completed_at": _optional_text(
                _pick(batch, "completed_at", "completedAt"),
                "batch.completed_at",
                max_length=64,
            ),
            "input_row_count": len(input_rows),
            "decision_eligible": False,
            "operational_verdict": "unverifiable",
        },
        "reference_set": sanitized_reference,
        "targets": targets,
    }
    validate_batch_report(report)
    scanner.reject(report)
    return report


def _normalized_field_name(value: Any) -> str:
    return "".join(character for character in str(value).casefold() if character.isalnum())


def _assert_no_forbidden_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _normalized_field_name(key) in _FORBIDDEN_FIELD_NAMES:
                raise BatchReportValidationError("report contains a forbidden sensitive field")
            _assert_no_forbidden_fields(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_forbidden_fields(child)


def _assert_exact_keys(payload: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(payload)
    if actual != expected:
        raise BatchReportValidationError(f"{label} does not match schema {REPORT_SCHEMA_VERSION}")


def validate_batch_report(report: Mapping[str, Any]) -> None:
    """Validate the exact v1 wire shape, row completeness, and safe decisions."""

    if not isinstance(report, Mapping):
        raise BatchReportValidationError("report must be an object")
    _assert_no_forbidden_fields(report)
    _assert_exact_keys(
        report,
        {
            "schema_version",
            "report_kind",
            "generated_at",
            "tool",
            "batch",
            "reference_set",
            "targets",
        },
        "report",
    )
    if (
        report.get("schema_version") != REPORT_SCHEMA_VERSION
        or report.get("report_kind") != REPORT_KIND
    ):
        raise BatchReportValidationError("unsupported batch report schema")
    _required_text(report.get("generated_at"), "generated_at", max_length=64)
    tool = report.get("tool")
    batch = report.get("batch")
    reference = report.get("reference_set")
    targets = report.get("targets")
    if not isinstance(tool, Mapping) or not isinstance(batch, Mapping):
        raise BatchReportValidationError("tool and batch must be objects")
    if not isinstance(reference, Mapping) or not isinstance(targets, list):
        raise BatchReportValidationError("reference_set must be an object and targets a list")
    _assert_exact_keys(tool, {"name", "version", "git_sha"}, "tool")
    _required_text(tool.get("name"), "tool.name", max_length=100)
    _required_text(tool.get("version"), "tool.version", max_length=100)
    _git_sha(tool.get("git_sha"))
    _assert_exact_keys(
        batch,
        {
            "batch_id",
            "status",
            "protocol",
            "transport_profile",
            "logical_model",
            "default_model_id",
            "reference_set_id",
            "created_at",
            "completed_at",
            "input_row_count",
            "decision_eligible",
            "operational_verdict",
        },
        "batch",
    )
    if batch.get("status") not in TERMINAL_BATCH_STATUSES:
        raise BatchReportValidationError("batch report is not terminal")
    _identifier(batch.get("batch_id"), "batch.batch_id")
    _enum(batch.get("protocol"), "batch.protocol", PROTOCOLS)
    _identifier(batch.get("transport_profile"), "batch.transport_profile")
    if batch.get("transport_profile") != TRANSPORT_PROFILE_BY_PROTOCOL[batch["protocol"]]:
        raise BatchReportValidationError(
            "batch protocol and transport_profile do not match"
        )
    _required_text(batch.get("logical_model"), "batch.logical_model", max_length=255)
    _required_text(batch.get("default_model_id"), "batch.default_model_id", max_length=255)
    _identifier(batch.get("reference_set_id"), "batch.reference_set_id")
    _optional_text(batch.get("created_at"), "batch.created_at", max_length=64)
    _optional_text(batch.get("completed_at"), "batch.completed_at", max_length=64)
    _optional_int(batch.get("input_row_count"), "batch.input_row_count", minimum=1)
    if (
        batch.get("decision_eligible") is not False
        or batch.get("operational_verdict") != "unverifiable"
    ):
        raise BatchReportValidationError("batch report must remain operationally unverifiable")
    if batch.get("reference_set_id") != reference.get("reference_set_id"):
        raise BatchReportValidationError("batch reference_set_id does not match reference_set")
    if batch.get("protocol") != reference.get("protocol"):
        raise BatchReportValidationError("batch protocol does not match reference_set")
    if batch.get("transport_profile") != reference.get("transport_profile"):
        raise BatchReportValidationError(
            "batch transport_profile does not match reference_set"
        )
    if batch.get("logical_model") != reference.get("logical_model"):
        raise BatchReportValidationError("batch logical_model does not match reference_set")
    if batch.get("input_row_count") != len(targets) or not targets:
        raise BatchReportValidationError("terminal report does not contain every input row")

    _assert_exact_keys(
        reference,
        {
            "reference_set_id",
            "name",
            "source_type",
            "protocol",
            "transport_profile",
            "logical_model",
            "model_id",
            "base_url",
            "battery_sha256",
            "samples_per_cell",
            "created_at",
            "members",
            "pairwise_distances",
            "envelope",
        },
        "reference_set",
    )
    if dict(reference) != _sanitize_reference_set(reference):
        raise BatchReportValidationError(
            f"reference_set does not match schema {REPORT_SCHEMA_VERSION}"
        )
    members = reference.get("members")
    pairwise = reference.get("pairwise_distances")
    if not isinstance(members, list) or len(members) != 3:
        raise BatchReportValidationError("reference_set must contain exactly three members")
    if not isinstance(pairwise, list) or len(pairwise) != 3:
        raise BatchReportValidationError("reference_set must contain three pairwise distances")
    member_ids: list[str] = []
    for member in members:
        if not isinstance(member, Mapping):
            raise BatchReportValidationError("reference member must be an object")
        _assert_exact_keys(
            member,
            {
                "member_id",
                "ordinal",
                "seed_id",
                "artifact_id",
                "artifact_sha256",
                "raw_evidence_sha256",
                "created_at",
                "quality",
            },
            "reference member",
        )
        member_ids.append(_identifier(member.get("member_id"), "reference member ID"))
        _sha256(member.get("artifact_sha256"), "reference artifact SHA-256", optional=False)
        _sha256(
            member.get("raw_evidence_sha256"),
            "reference raw evidence SHA-256",
            optional=False,
        )
    if len(set(member_ids)) != 3:
        raise BatchReportValidationError("reference member IDs must be unique")

    row_ids: list[str] = []
    for target in targets:
        if not isinstance(target, Mapping):
            raise BatchReportValidationError("target must be an object")
        _assert_exact_keys(
            target,
            {
                "row_id",
                "station_name",
                "base_url",
                "requested_model",
                "reported_model",
                "status",
                "exploratory_status",
                "operational_verdict",
                "decision_eligible",
                "reason_codes",
                "preflight",
                "metrics",
                "distances",
                "latency",
                "requests",
                "evidence",
                "error",
            },
            "target",
        )
        row_ids.append(_identifier(target.get("row_id"), "target.row_id"))
        if target.get("status") not in TERMINAL_TARGET_STATUSES:
            raise BatchReportValidationError("target row is not terminal")
        if target.get("exploratory_status") not in EXPLORATORY_STATUSES:
            raise BatchReportValidationError("target exploratory status is unsupported")
        if (
            target.get("decision_eligible") is not False
            or target.get("operational_verdict") != "unverifiable"
        ):
            raise BatchReportValidationError("target must remain operationally unverifiable")
        distances = target.get("distances")
        if not isinstance(distances, Mapping):
            raise BatchReportValidationError("target distances must be an object")
        distance_members = distances.get("members")
        if not isinstance(distance_members, list):
            raise BatchReportValidationError("target distance members must be a list")
        if any(
            not isinstance(item, Mapping) or item.get("member_id") not in member_ids
            for item in distance_members
        ):
            raise BatchReportValidationError("target distance references an unknown member")
        if dict(target) != _sanitize_target(
            target,
            target,
            reference_member_ids=member_ids,
            reference_envelope=reference["envelope"]["max_upper_jsd"],
        ):
            raise BatchReportValidationError(
                f"target does not match schema {REPORT_SCHEMA_VERSION}"
            )
    if len(row_ids) != len(set(row_ids)):
        raise BatchReportValidationError("target row IDs must be unique")


def canonical_report_bytes(report: Mapping[str, Any]) -> bytes:
    validate_batch_report(report)
    try:
        serialized = json.dumps(
            report,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise BatchReportValidationError("report is not canonical JSON data") from error
    return f"{serialized}\n".encode()


def _atomic_write_bytes(
    path: Path,
    encoded: bytes,
    *,
    secret_scanner: SecretCanaryScanner,
) -> ReportArtifact:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{uuid4().hex}.tmp"
    secret_scanner.reject(encoded)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        secret_scanner.reject(temporary.read_bytes(), delete_paths=(temporary,))
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    digest = hashlib.sha256(encoded).hexdigest()
    return ReportArtifact(path=destination, sha256=digest, size_bytes=len(encoded))


def write_terminal_batch_report(
    path: Path,
    report: Mapping[str, Any],
    *,
    secret_scanner: SecretCanaryScanner | None = None,
) -> ReportArtifact:
    scanner = _require_secret_scanner(secret_scanner)
    scanner.reject(report)
    encoded = canonical_report_bytes(report)
    return _atomic_write_bytes(Path(path), encoded, secret_scanner=scanner)


def load_verified_batch_report(
    path: Path,
    expected_sha256: str,
    *,
    secret_scanner: SecretCanaryScanner | None = None,
) -> VerifiedBatchReport:
    scanner = _require_secret_scanner(secret_scanner)
    expected = _sha256(expected_sha256, "expected_sha256", optional=False)
    artifact_path = Path(path)
    try:
        encoded = artifact_path.read_bytes()
    except FileNotFoundError:
        raise BatchReportIntegrityError("batch report artifact is missing") from None
    actual = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(actual, str(expected)):
        raise BatchReportIntegrityError("batch report SHA-256 does not match")
    try:
        payload = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BatchReportIntegrityError("batch report is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise BatchReportIntegrityError("batch report root is not an object")
    try:
        canonical = canonical_report_bytes(payload)
    except BatchReportValidationError as error:
        raise BatchReportIntegrityError(str(error)) from error
    if canonical != encoded:
        raise BatchReportIntegrityError("batch report is not canonical JSON")
    scanner.reject(payload)
    return VerifiedBatchReport(
        path=artifact_path,
        sha256=actual,
        payload=payload,
        encoded=encoded,
    )


def _csv_safe(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        value = "|".join(str(item) for item in value)
    text = str(value)
    if not text:
        return text
    first_category = unicodedata.category(text[0])
    index = 0
    while index < len(text) and (
        text[index].isspace() or unicodedata.category(text[index]) in {"Cc", "Cf"}
    ):
        index += 1
    dangerous_after_prefix = index < len(text) and text[index] in _DANGEROUS_CSV_PREFIXES
    control_prefix = first_category in {"Cc", "Cf"}
    if text[0] in _DANGEROUS_CSV_PREFIXES or dangerous_after_prefix or control_prefix:
        return f"'{text}"
    return text


def _csv_row(report: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, str]:
    batch = report["batch"]
    reference = report["reference_set"]
    preflight = target["preflight"]
    metrics = target["metrics"]
    distances = target["distances"]
    latency = target["latency"]
    requests = target["requests"]
    evidence = target["evidence"]
    error = target["error"]
    members_by_id = {item["member_id"]: item for item in distances["members"]}
    ordered_members = reference["members"]
    flat: dict[str, Any] = {
        "schema_version": report["schema_version"],
        "batch_id": batch["batch_id"],
        "batch_status": batch["status"],
        "reference_set_id": reference["reference_set_id"],
        "reference_set_name": reference["name"],
        "reference_source_type": reference["source_type"],
        "protocol": batch["protocol"],
        "transport_profile": batch["transport_profile"],
        "logical_model": batch["logical_model"],
        "row_id": target["row_id"],
        "station_name": target["station_name"],
        "base_url": target["base_url"],
        "requested_model": target["requested_model"],
        "reported_model": target["reported_model"],
        "status": target["status"],
        "exploratory_status": target["exploratory_status"],
        "operational_verdict": target["operational_verdict"],
        "decision_eligible": target["decision_eligible"],
        "reason_codes": target["reason_codes"],
        "preflight_status": preflight["status"],
        "preflight_http_status": preflight["http_status"],
        "preflight_attempts": preflight["attempts"],
        "preflight_latency_ms": preflight["latency_ms"],
        "preflight_reason_code": preflight["reason_code"],
        "valid_samples": metrics["valid_samples"],
        "invalid_samples": metrics["invalid_samples"],
        "error_samples": metrics["error_samples"],
        "coverage_cells": metrics["coverage_cells"],
        "total_cells": metrics["total_cells"],
        "directness": metrics["directness"],
        "split_half_mean_jsd": metrics["split_half_mean_jsd"],
        "median_mean_jsd": distances["median_mean_jsd"],
        "mad_mean_jsd": distances["mad_mean_jsd"],
        "min_mean_jsd": distances["min_mean_jsd"],
        "max_mean_jsd": distances["max_mean_jsd"],
        "latency_p50_ms": latency["p50_ms"],
        "latency_p95_ms": latency["p95_ms"],
        "logical_samples": requests["logical_samples"],
        "request_attempts": requests["attempts"],
        "retries": requests["retries"],
        "retry_budget_used": requests["retry_budget_used"],
        "discarded_attempts": requests["discarded_attempts"],
        "artifact_id": evidence["artifact_id"],
        "artifact_sha256": evidence["artifact_sha256"],
        "raw_evidence_sha256": evidence["raw_evidence_sha256"],
        "comparison_artifact_sha256": evidence["comparison_artifact_sha256"],
        "partial_artifact_sha256": evidence["partial_artifact_sha256"],
        "error_code": error["code"],
        "error_http_status": error["http_status"],
    }
    for index, reference_member in enumerate(ordered_members, start=1):
        member_id = reference_member["member_id"]
        distance = members_by_id.get(member_id, {})
        flat[f"reference_member_{index}_id"] = member_id
        flat[f"reference_member_{index}_mean_jsd"] = distance.get("mean_jsd")
        flat[f"reference_member_{index}_ci_lower"] = distance.get("ci_lower")
        flat[f"reference_member_{index}_ci_upper"] = distance.get("ci_upper")
    return {column: _csv_safe(flat.get(column)) for column in CSV_COLUMNS}


def csv_bytes_from_verified_report(verified: VerifiedBatchReport) -> bytes:
    """Render CSV only from the opaque output of ``load_verified_batch_report``."""

    if not isinstance(verified, VerifiedBatchReport):
        raise TypeError("CSV requires a VerifiedBatchReport")
    validate_batch_report(verified.payload)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=list(CSV_COLUMNS),
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for target in verified.payload["targets"]:
        writer.writerow(_csv_row(verified.payload, target))
    return output.getvalue().encode("utf-8")


def write_verified_batch_csv(
    csv_path: Path,
    *,
    json_path: Path,
    expected_json_sha256: str,
    secret_scanner: SecretCanaryScanner | None = None,
) -> ReportArtifact:
    scanner = _require_secret_scanner(secret_scanner)
    verified = load_verified_batch_report(
        json_path,
        expected_json_sha256,
        secret_scanner=scanner,
    )
    encoded = csv_bytes_from_verified_report(verified)
    return _atomic_write_bytes(Path(csv_path), encoded, secret_scanner=scanner)
