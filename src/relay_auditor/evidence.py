import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_EVIDENCE_EXTENSIONS = {
    "smoke": ".json",
    "fingerprints": ".json",
    "fingerprint_samples": ".jsonl",
    "verification": ".json",
    "tokenizers": ".json",
    "tokenizer_verification": ".json",
    "calibrations": ".json",
}


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str


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

    def read_json(self, path: Path) -> dict[str, Any]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"evidence must contain a JSON object: {path}")
        return payload

    @staticmethod
    def digest_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
