import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select, update

from relay_auditor.database import AuditRun, Baseline, Database
from relay_auditor.evidence import EvidenceStore

IMPORT_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "https://relay-model-auditor.local/reference-import/v1",
)


@dataclass(frozen=True)
class ImportedReference:
    source_label: str
    model: str
    artifact_id: str
    endpoint_id: str
    baseline_id: str
    status: str

    def as_dict(self) -> dict[str, str]:
        return {
            "source_label": self.source_label,
            "model": self.model,
            "artifact_id": self.artifact_id,
            "endpoint_id": self.endpoint_id,
            "baseline_id": self.baseline_id,
            "status": self.status,
        }


def _parse_collected_at(value: object, path: Path) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"fingerprint collectedAt is missing: {path}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"fingerprint collectedAt is invalid: {path}") from error
    if parsed.tzinfo is None:
        raise ValueError(f"fingerprint collectedAt must include a timezone: {path}")
    return parsed.astimezone(UTC)


def _load_fingerprint(path: Path) -> tuple[dict[str, Any], datetime]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read fingerprint JSON: {path}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"fingerprint must contain a JSON object: {path}")
    if payload.get("formatVersion") != 1:
        raise ValueError(f"unsupported fingerprint formatVersion: {path}")
    if payload.get("protocol") != "one-token/v1":
        raise ValueError(f"unsupported fingerprint protocol: {path}")

    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ValueError(f"fingerprint model is missing: {path}")
    expected_model = path.name.removesuffix(".fingerprint.json")
    if expected_model != model:
        raise ValueError(
            f"fingerprint filename/model mismatch ({expected_model!r} != {model!r}): {path}"
        )

    samples = payload.get("samplesPerCell")
    cells = payload.get("cells")
    if not isinstance(samples, int) or samples < 1:
        raise ValueError(f"fingerprint samplesPerCell is invalid: {path}")
    if not isinstance(cells, dict) or not cells:
        raise ValueError(f"fingerprint cells are missing: {path}")
    for cell_id, cell in cells.items():
        if not isinstance(cell_id, str) or not isinstance(cell, dict):
            raise ValueError(f"fingerprint cell is invalid: {path}")
        if cell.get("cellId") != cell_id or not isinstance(cell.get("counts"), dict):
            raise ValueError(f"fingerprint cell payload is invalid ({cell_id}): {path}")

    return payload, _parse_collected_at(payload.get("collectedAt"), path)


def _bounded_endpoint_name(prefix: str, source_label: str, model: str) -> str:
    raw_name = f"{prefix} {source_label} · {model}"
    if len(raw_name) <= 100:
        return raw_name
    suffix = hashlib.sha256(raw_name.encode()).hexdigest()[:8]
    return f"{raw_name[:89]}-{suffix}"


def _sample_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    cells = payload["cells"]
    assert isinstance(cells, dict)
    fields = (
        "validCount",
        "invalidCount",
        "refusalCount",
        "emptyCount",
        "errorCount",
        "totalCount",
    )
    totals = {field: 0 for field in fields}
    thin_cells: list[str] = []
    for cell_id, cell in cells.items():
        assert isinstance(cell, dict)
        for field in fields:
            value = cell.get(field)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"fingerprint {field} is invalid ({cell_id})")
            totals[field] += value
        if cell["validCount"] < 10:
            thin_cells.append(str(cell_id))

    flags: list[str] = []
    if totals["errorCount"]:
        flags.append("request_errors")
    if totals["invalidCount"]:
        flags.append("invalid_answers")
    if totals["refusalCount"]:
        flags.append("refusals")
    if totals["emptyCount"]:
        flags.append("empty_answers")
    if payload.get("postReasoning") is True:
        flags.append("post_reasoning")
    if thin_cells:
        flags.append("thin_cells")

    return {
        "valid_samples": totals["validCount"],
        "invalid_samples": totals["invalidCount"],
        "refusal_samples": totals["refusalCount"],
        "empty_samples": totals["emptyCount"],
        "error_samples": totals["errorCount"],
        "total_samples": totals["totalCount"],
        "thin_cells": thin_cells,
        "quality_flags": flags,
    }


def import_reference_directory(
    source_dir: Path,
    *,
    database: Database,
    evidence: EvidenceStore,
    base_url: str,
    provider: str,
    reference_prefix: str,
    valid_days: int = 14,
    extra_metadata: Mapping[str, Any] | None = None,
    per_reference_metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[ImportedReference]:
    """Import tracked One Token snapshots into the local reference catalog.

    IDs are deterministic, so importing the same files repeatedly is safe. A changed
    snapshot creates a new artifact/baseline and supersedes the older baseline for the
    same source label and model.
    """

    if not 1 <= valid_days <= 90:
        raise ValueError("valid_days must be between 1 and 90")
    normalized_base_url = base_url.rstrip("/")
    if not normalized_base_url:
        raise ValueError("base_url is required")
    if not provider.strip() or not reference_prefix.strip():
        raise ValueError("provider and reference_prefix are required")

    root = source_dir.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"reference source directory not found: {root}")
    paths = sorted(root.glob("*/*.fingerprint.json"))
    if not paths:
        raise FileNotFoundError(f"no fingerprint files found under: {root}")

    database.initialize()
    evidence.initialize()
    imported: list[ImportedReference] = []
    metadata_overlay = dict(extra_metadata or {})
    item_metadata = dict(per_reference_metadata or {})

    for path in paths:
        relative = path.relative_to(root)
        source_label = relative.parts[0]
        payload, collected_at = _load_fingerprint(path)
        model = str(payload["model"])
        source_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        identity = "|".join(
            (
                normalized_base_url,
                source_label,
                model,
                collected_at.isoformat(),
                source_sha256,
            )
        )
        endpoint_identity = "|".join((normalized_base_url, source_label, model))
        artifact_id = str(uuid5(IMPORT_NAMESPACE, f"artifact|{identity}"))
        endpoint_id = str(uuid5(IMPORT_NAMESPACE, f"endpoint|{endpoint_identity}"))
        baseline_id = str(uuid5(IMPORT_NAMESPACE, f"baseline|{identity}"))
        artifact = evidence.write_json("fingerprints", artifact_id, payload)
        endpoint_name = _bounded_endpoint_name(reference_prefix, source_label, model)
        expires_at = collected_at + timedelta(days=valid_days)
        now = datetime.now(UTC)
        relative_name = relative.as_posix()
        per_item_overlay = dict(item_metadata.get(relative_name, {}))
        sample_metadata = _sample_metadata(payload)
        extra_flags = per_item_overlay.pop("quality_flags", [])
        if not isinstance(extra_flags, list) or not all(
            isinstance(flag, str) for flag in extra_flags
        ):
            raise ValueError(f"quality_flags metadata must be a list of strings: {relative_name}")
        sample_metadata["quality_flags"] = list(
            dict.fromkeys([*sample_metadata["quality_flags"], *extra_flags])
        )
        metadata = {
            "source": "tracked_reference_snapshot",
            "reference_name": f"{reference_prefix} {source_label}",
            "source_label": source_label,
            "source_file": relative_name,
            "source_sha256": source_sha256,
            "ground_truth": "relay_snapshot_not_official",
            "method_profile_id": "legacy-one-token/v1",
            "decision_eligible": False,
            "calibration_policy_id": None,
            "cells": len(payload["cells"]),
            "samples": payload["samplesPerCell"],
            "protocol": payload["protocol"],
            "collected_at": collected_at.isoformat(),
            "duration_known": False,
            **sample_metadata,
            **metadata_overlay,
            **per_item_overlay,
        }

        with database.sessions() as session:
            endpoint = database.upsert_endpoint_in_session(
                session,
                endpoint_id=endpoint_id,
                name=endpoint_name,
                provider=provider,
                base_url=normalized_base_url,
                model=model,
                protocol="openai_chat",
                now=now,
                reuse_by_connection_identity=False,
            )
            session.flush()
            endpoint_id = endpoint.id

            run = session.get(AuditRun, artifact_id)
            if run is None:
                run = AuditRun(
                    id=artifact_id,
                    detector="one_token_collect",
                    status="completed",
                    verdict="recorded",
                    target_base_url=normalized_base_url,
                    model=model,
                    started_at=collected_at,
                    completed_at=collected_at,
                    artifact_path=str(artifact.path),
                    artifact_sha256=artifact.sha256,
                    error_message=None,
                )
                session.add(run)
            else:
                run.detector = "one_token_collect"
                run.status = "completed"
                run.verdict = "recorded"
                run.target_base_url = normalized_base_url
                run.model = model
                run.started_at = collected_at
                run.completed_at = collected_at
                run.artifact_path = str(artifact.path)
                run.artifact_sha256 = artifact.sha256
                run.error_message = None

            # Expiry and snapshot chronology, rather than import order,
            # determine which baseline is active. Re-importing an older file
            # must never roll the catalog back from a newer snapshot.
            session.execute(
                update(Baseline)
                .where(
                    Baseline.endpoint_id == endpoint_id,
                    Baseline.detector == "one_token",
                    Baseline.status == "active",
                    Baseline.expires_at < now,
                )
                .values(status="expired")
            )
            active_baseline = session.scalar(
                select(Baseline)
                .where(
                    Baseline.endpoint_id == endpoint_id,
                    Baseline.detector == "one_token",
                    Baseline.status == "active",
                )
                .order_by(Baseline.valid_from.desc(), Baseline.created_at.desc())
                .limit(1)
            )
            baseline = session.get(Baseline, baseline_id)
            if expires_at < now:
                desired_status = "expired"
            elif baseline is not None and baseline.status == "deleted":
                desired_status = "deleted"
            elif active_baseline is None or active_baseline.id == baseline_id:
                desired_status = "active"
            elif collected_at > (
                active_baseline.valid_from
                if active_baseline.valid_from.tzinfo is not None
                else active_baseline.valid_from.replace(tzinfo=UTC)
            ):
                active_baseline.status = "superseded"
                desired_status = "active"
            else:
                desired_status = "superseded"

            if baseline is None:
                baseline = Baseline(
                    id=baseline_id,
                    endpoint_id=endpoint_id,
                    detector="one_token",
                    artifact_id=artifact_id,
                    status=desired_status,
                    valid_from=collected_at,
                    expires_at=expires_at,
                    metadata_json=metadata,
                    created_at=now,
                )
                session.add(baseline)
            else:
                baseline.endpoint_id = endpoint_id
                baseline.detector = "one_token"
                baseline.artifact_id = artifact_id
                baseline.status = desired_status
                baseline.valid_from = collected_at
                baseline.expires_at = expires_at
                baseline.metadata_json = metadata

            session.commit()

        imported.append(
            ImportedReference(
                source_label=source_label,
                model=model,
                artifact_id=artifact_id,
                endpoint_id=endpoint_id,
                baseline_id=baseline_id,
                status=desired_status,
            )
        )

    return imported
