from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from relay_auditor.config import Settings
from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import (
    FingerprintRunner,
    safeguard_verification_result,
)
from relay_auditor.evidence import EvidenceStore


async def recover_failed_verification(
    *,
    failed_audit_id: str,
    reference_artifact_id: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Create a new, offline-only audit from a failed run's saved fingerprint.

    The original failed audit remains unchanged. The recovered audit links both source
    artifacts in its evidence so the repair is explicit and reproducible.
    """

    configured = settings or Settings()
    database = Database(configured.database_url)
    evidence = EvidenceStore(configured.evidence_dir)
    runner = FingerprintRunner(configured.fingerprint_cli_path)
    database.initialize()
    evidence.initialize()

    failed_run = database.get_run(failed_audit_id)
    if failed_run is None:
        raise LookupError(f"failed audit not found: {failed_audit_id}")
    if failed_run.detector != "one_token_verify" or failed_run.status != "failed":
        raise ValueError("source audit must be a failed one_token_verify run")

    target_path = evidence.verify_registered_path(
        failed_run.artifact_path,
        failed_run.artifact_sha256,
        expected_path=evidence.fingerprint_path(failed_audit_id),
    )
    reference_run = database.get_run(reference_artifact_id)
    if (
        reference_run is None
        or reference_run.status != "completed"
        or reference_run.detector != "one_token_collect"
    ):
        raise LookupError(f"completed reference audit not found: {reference_artifact_id}")
    reference_path = evidence.verify_registered_path(
        reference_run.artifact_path,
        reference_run.artifact_sha256,
        expected_path=evidence.fingerprint_path(reference_artifact_id),
    )
    reference_metadata = database.get_reference_metadata(reference_artifact_id)
    verdict, payload = await runner.recover_verify(
        reference_path=reference_path,
        target_path=target_path,
    )
    verdict, payload = safeguard_verification_result(
        verdict,
        payload,
        reference_metadata=reference_metadata,
    )
    recovery = payload.setdefault("recovery", {})
    recovery.update(
        {
            "source_failed_audit_id": failed_audit_id,
            "reference_artifact_id": reference_artifact_id,
            "source_target_sha256": evidence.digest_file(target_path),
            "source_reference_sha256": evidence.digest_file(reference_path),
            "recovered_at": datetime.now(UTC).isoformat(),
        }
    )

    recovered_audit_id = str(uuid4())
    artifact = evidence.write_json("verification", recovered_audit_id, payload)
    database.create_run(
        audit_id=recovered_audit_id,
        detector="one_token_recovered",
        target_base_url=failed_run.target_base_url,
        model=failed_run.model,
    )
    database.finish_run(
        recovered_audit_id,
        status="completed",
        verdict=verdict,
        artifact_path=str(artifact.path),
        artifact_sha256=artifact.sha256,
    )
    return {
        "audit_id": recovered_audit_id,
        "source_failed_audit_id": failed_audit_id,
        "reference_artifact_id": reference_artifact_id,
        "model": failed_run.model,
        "verdict": verdict,
        "legacy_verdict": payload.get("legacyVerdict"),
        "decision": payload.get("decision"),
        "mean_jsd": payload.get("meanJsd"),
        "artifact_path": str(artifact.path),
        "artifact_sha256": artifact.sha256,
        "network_requests": 0,
    }


def resolve_existing_path(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved
