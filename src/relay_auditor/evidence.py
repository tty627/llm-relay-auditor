import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def initialize(self) -> None:
        for category in ("smoke", "fingerprints", "verification"):
            (self.root / category).mkdir(parents=True, exist_ok=True)

    def path_for(self, category: str, artifact_id: str) -> Path:
        if category not in {"smoke", "fingerprints", "verification"}:
            raise ValueError(f"unsupported evidence category: {category}")
        if not artifact_id or any(char not in "0123456789abcdef-" for char in artifact_id):
            raise ValueError("artifact_id must be a lowercase UUID")
        path = (self.root / category / f"{artifact_id}.json").resolve()
        if self.root not in path.parents:
            raise ValueError("artifact path escapes evidence root")
        return path

    def write_json(self, category: str, artifact_id: str, payload: Any) -> Artifact:
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

    @staticmethod
    def digest_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
