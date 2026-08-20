from pathlib import Path

from fastapi.testclient import TestClient

from relay_auditor.config import Settings
from relay_auditor.main import create_app


def test_health_and_mock(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    with TestClient(create_app(settings)) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        models = client.get("/mock/v1/models")
        assert models.status_code == 200
        assert {item["id"] for item in models.json()["data"]} == {
            "reference-model",
            "substitute-model",
        }

        completion = client.post(
            "/mock/v1/chat/completions",
            json={
                "model": "reference-model",
                "messages": [{"role": "user", "content": "Name a random color."}],
            },
        )
        assert completion.status_code == 200
        assert completion.json()["choices"][0]["message"]["content"] in {
            "blue",
            "green",
            "purple",
        }


def test_missing_fingerprint_reference_returns_404(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/fingerprints/verify",
            json={
                "endpoint": {
                    "base_url": "http://127.0.0.1:8000/mock/v1",
                    "model": "reference-model",
                },
                "reference_artifact_id": "00000000-0000-0000-0000-000000000000",
            },
        )
        assert response.status_code == 404


def test_sqlite_parent_directory_is_created(tmp_path: Path) -> None:
    database_path = tmp_path / "nested" / "auditor.db"
    settings = Settings(
        database_url=f"sqlite:///{database_path}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )

    with TestClient(create_app(settings)) as client:
        assert client.get("/health").status_code == 200

    assert database_path.is_file()
