import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from relay_auditor.schemas import (
    LEGACY_ONE_TOKEN_PROFILE,
    PAPER_ONE_TOKEN_PROFILE,
    OneTokenMethodProfileId,
)

_EVIDENCE_EXTENSIONS = {
    "smoke": ".json",
    "fingerprints": ".json",
    "fingerprint_samples": ".jsonl",
    "verification": ".json",
    "tokenizers": ".json",
    "tokenizer_verification": ".json",
    "calibrations": ".json",
    "target_comparisons": ".json",
    "batch_reports": ".json",
    "batch_csv": ".csv",
    "batch_checkpoints": ".json",
}


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str


class EvidenceIntegrityError(ValueError):
    """Stored evidence no longer matches its registered path or digest."""


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def initialize(self) -> None:
        for category in _EVIDENCE_EXTENSIONS:
            (self.root / category).mkdir(parents=True, exist_ok=True)

    def path_for(self, category: str, artifact_id: str) -> Path:
        if category not in _EVIDENCE_EXTENSIONS:
            raise ValueError(f"unsupported evidence category: {category}")
        if not artifact_id or any(char not in "0123456789abcdef-" for char in artifact_id):
            raise ValueError("artifact_id must be a lowercase UUID")
        extension = _EVIDENCE_EXTENSIONS[category]
        path = (self.root / category / f"{artifact_id}{extension}").resolve()
        if self.root not in path.parents:
            raise ValueError("artifact path escapes evidence root")
        return path

    def write_json(self, category: str, artifact_id: str, payload: Any) -> Artifact:
        if _EVIDENCE_EXTENSIONS.get(category) != ".json":
            raise ValueError(f"evidence category is not a JSON artifact: {category}")
        path = self.path_for(category, artifact_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        encoded = f"{serialized}\n".encode()
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(encoded)
        temporary.replace(path)
        return Artifact(path=path, sha256=hashlib.sha256(encoded).hexdigest())

    def fingerprint_path(self, artifact_id: str, *, must_exist: bool = False) -> Path:
        path = self.path_for("fingerprints", artifact_id)
        if must_exist and not path.is_file():
            raise FileNotFoundError(f"fingerprint artifact not found: {artifact_id}")
        return path

    def fingerprint_samples_path(
        self,
        artifact_id: str,
        *,
        must_exist: bool = False,
    ) -> Path:
        path = self.path_for("fingerprint_samples", artifact_id)
        if must_exist and not path.is_file():
            raise FileNotFoundError(f"fingerprint sample evidence not found: {artifact_id}")
        return path

    def tokenizer_path(self, artifact_id: str, *, must_exist: bool = False) -> Path:
        path = self.path_for("tokenizers", artifact_id)
        if must_exist and not path.is_file():
            raise FileNotFoundError(f"tokenizer artifact not found: {artifact_id}")
        return path

    def target_comparison_path(self, artifact_id: str, *, must_exist: bool = False) -> Path:
        path = self.path_for("target_comparisons", artifact_id)
        if must_exist and not path.is_file():
            raise FileNotFoundError(f"target comparison artifact not found: {artifact_id}")
        return path

    def batch_report_path(self, batch_id: str, *, must_exist: bool = False) -> Path:
        path = self.path_for("batch_reports", batch_id)
        if must_exist and not path.is_file():
            raise FileNotFoundError(f"batch report artifact not found: {batch_id}")
        return path

    def batch_csv_path(self, batch_id: str, *, must_exist: bool = False) -> Path:
        path = self.path_for("batch_csv", batch_id)
        if must_exist and not path.is_file():
            raise FileNotFoundError(f"batch CSV artifact not found: {batch_id}")
        return path

    def read_json(self, path: Path) -> dict[str, Any]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"evidence must contain a JSON object: {path}")
        return payload

    def read_verified_bytes(
        self,
        registered_path: str | Path | None,
        registered_sha256: str | None,
        *,
        expected_path: Path | None = None,
    ) -> tuple[Path, bytes]:
        """Read once, then validate the registered location and digest."""

        if not registered_path:
            raise EvidenceIntegrityError("evidence path is not registered")
        if not registered_sha256:
            raise EvidenceIntegrityError("evidence SHA-256 is not registered")
        artifact_path = Path(registered_path).resolve()
        if self.root not in artifact_path.parents:
            raise EvidenceIntegrityError("evidence path escapes the evidence root")
        if expected_path is not None and artifact_path != expected_path.resolve():
            raise EvidenceIntegrityError("evidence path does not match its canonical artifact path")
        try:
            encoded = artifact_path.read_bytes()
        except FileNotFoundError:
            raise FileNotFoundError(f"evidence file is missing: {artifact_path}") from None
        actual_sha256 = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(actual_sha256, registered_sha256.lower()):
            raise EvidenceIntegrityError("evidence SHA-256 does not match the registered digest")
        return artifact_path, encoded

    def read_verified_json(
        self,
        registered_path: str | Path | None,
        registered_sha256: str | None,
        *,
        expected_path: Path | None = None,
    ) -> dict[str, Any]:
        artifact_path, encoded = self.read_verified_bytes(
            registered_path,
            registered_sha256,
            expected_path=expected_path,
        )
        try:
            payload = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceIntegrityError(
                f"evidence is not valid UTF-8 JSON: {artifact_path}"
            ) from error
        if not isinstance(payload, dict):
            raise EvidenceIntegrityError(
                f"evidence must contain a JSON object: {artifact_path}"
            )
        return payload

    def verify_registered_path(
        self,
        registered_path: str | Path | None,
        registered_sha256: str | None,
        *,
        expected_path: Path | None = None,
    ) -> Path:
        if not registered_path:
            raise EvidenceIntegrityError("evidence path is not registered")
        if not registered_sha256:
            raise EvidenceIntegrityError("evidence SHA-256 is not registered")
        artifact_path = Path(registered_path).resolve()
        if self.root not in artifact_path.parents:
            raise EvidenceIntegrityError("evidence path escapes the evidence root")
        if expected_path is not None and artifact_path != expected_path.resolve():
            raise EvidenceIntegrityError("evidence path does not match its canonical artifact path")
        try:
            actual_sha256 = self.digest_file(artifact_path)
        except FileNotFoundError:
            raise FileNotFoundError(f"evidence file is missing: {artifact_path}") from None
        if not hmac.compare_digest(actual_sha256, registered_sha256.lower()):
            raise EvidenceIntegrityError("evidence SHA-256 does not match the registered digest")
        return artifact_path

    def fingerprint_method_profile(
        self,
        artifact_id: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> OneTokenMethodProfileId:
        """Resolve a reference profile from evidence, with legacy-history fallback.

        Baseline metadata is useful for presentation but cannot override the
        immutable fingerprint artifact. Old baselines predate method_profile_id,
        so any non-V2 historical fingerprint remains legacy-compatible.
        """

        fingerprint = self.read_json(self.fingerprint_path(artifact_id, must_exist=True))
        protocol = fingerprint.get("protocol")
        format_version = fingerprint.get("formatVersion")
        if format_version == 2 or protocol == PAPER_ONE_TOKEN_PROFILE:
            if format_version != 2 or protocol != PAPER_ONE_TOKEN_PROFILE:
                raise ValueError(
                    "paper fingerprint evidence has an inconsistent formatVersion/protocol"
                )
            detected: OneTokenMethodProfileId = PAPER_ONE_TOKEN_PROFILE
        else:
            detected = LEGACY_ONE_TOKEN_PROFILE

        declared = (metadata or {}).get("method_profile_id")
        if declared is not None and declared not in {
            LEGACY_ONE_TOKEN_PROFILE,
            PAPER_ONE_TOKEN_PROFILE,
        }:
            raise ValueError(f"unsupported reference method_profile_id: {declared}")
        if declared is not None and declared != detected:
            raise ValueError("reference method_profile_id does not match its fingerprint evidence")
        return detected

    @staticmethod
    def digest_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
