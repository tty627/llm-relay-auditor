import hashlib
from pathlib import Path

from relay_auditor.evidence import EvidenceStore


def test_evidence_is_atomic_and_hashed(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    store.initialize()
    artifact_id = "00000000-0000-0000-0000-000000000001"
    artifact = store.write_json("smoke", artifact_id, {"verdict": "pass"})

    assert artifact.path.is_file()
    assert artifact.sha256 == hashlib.sha256(artifact.path.read_bytes()).hexdigest()
    assert not artifact.path.with_suffix(".tmp").exists()


def test_artifact_id_cannot_escape_root(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    store.initialize()

    try:
        store.path_for("smoke", "../../etc/passwd")
    except ValueError as error:
        assert "lowercase UUID" in str(error)
    else:
        raise AssertionError("path traversal was accepted")
