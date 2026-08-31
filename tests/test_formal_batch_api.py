from pathlib import Path

from fastapi.testclient import TestClient

from relay_auditor.config import Settings
from relay_auditor.main import create_app


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'formal-api.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )


def _reference_payload(secret: str) -> dict[str, object]:
    return {
        "reference_name": "trusted reference",
        "source_type": "trusted_relay",
        "protocol": "openai_chat",
        "transport_profile_id": "openai-chat-onetoken-v1",
        "logical_model": "opus-5",
        "actual_model": "actual-opus-5",
        "base_url": "https://reference.example/v1",
        "credential": {"mode": "ephemeral", "api_key": secret},
    }


def test_formal_batch_routes_are_registered_and_no_store(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        reference_sets = client.get("/api/v1/console/reference-sets")
        assert reference_sets.status_code == 200
        assert reference_sets.json() == {"items": []}
        assert reference_sets.headers["cache-control"] == "no-store"

        missing_reference = client.get(
            "/api/v1/console/reference-sets/00000000-0000-0000-0000-000000000001"
        )
        assert missing_reference.status_code == 404
        assert missing_reference.headers["cache-control"] == "no-store"

        missing_batch = client.get(
            "/api/v1/console/one-model-batches/00000000-0000-0000-0000-000000000002"
        )
        assert missing_batch.status_code == 404
        assert missing_batch.headers["cache-control"] == "no-store"

        paths = {
            path
            for route in app.routes
            if isinstance(path := getattr(route, "path", None), str)
        }
        assert {
            "/api/v1/console/reference-sets",
            "/api/v1/console/reference-sets/{reference_set_id}",
            "/api/v1/console/reference-sets/{reference_set_id}/pause",
            "/api/v1/console/reference-sets/{reference_set_id}/resume",
            "/api/v1/console/reference-sets/{reference_set_id}/cancel",
            "/api/v1/console/one-model-batches",
            "/api/v1/console/one-model-batches/{batch_id}",
            "/api/v1/console/one-model-batches/{batch_id}/pause",
            "/api/v1/console/one-model-batches/{batch_id}/resume",
            "/api/v1/console/one-model-batches/{batch_id}/cancel",
            "/api/v1/console/one-model-batches/{batch_id}/report.json",
            "/api/v1/console/one-model-batches/{batch_id}/report.csv",
        } <= paths


def test_lifespan_recovers_interrupted_batch_reports(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    calls = 0

    async def recover() -> dict[str, int]:
        nonlocal calls
        calls += 1
        return {"generated": 0, "failed": 0}

    app.state.one_model_batches.recover_interrupted_reports = recover
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200

    assert calls == 1


def test_reference_creation_failure_never_reflects_transformed_key(
    tmp_path: Path,
) -> None:
    secret = "Sk-Canary-Api-Key-90817"
    app = create_app(_settings(tmp_path))

    async def fail_start(*_args, **_kwargs):
        raise ValueError(f"unsafe upstream echoed {secret.casefold()}")

    app.state.reference_sets.start = fail_start
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/console/reference-sets",
            json=_reference_payload(secret),
        )

    assert response.status_code == 400
    serialized = response.text.casefold()
    assert secret.casefold() not in serialized
    assert "credential safety policy" in serialized
    assert response.headers["cache-control"] == "no-store"


def test_reference_validation_error_redacts_whole_credential_input(
    tmp_path: Path,
) -> None:
    secret = "sk-validation-canary-441"
    payload = _reference_payload(secret)
    payload["protocol"] = "invalid-protocol"
    app = create_app(_settings(tmp_path))

    with TestClient(app) as client:
        response = client.post("/api/v1/console/reference-sets", json=payload)

    assert response.status_code == 422
    assert secret not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_batch_creation_rejects_missing_reference_without_reflecting_key(
    tmp_path: Path,
) -> None:
    secret = "sk-target-canary-773"
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/console/one-model-batches",
            json={
                "reference_set_id": "00000000-0000-0000-0000-000000000003",
                "default_model_id": "opus-5",
                "targets": [
                    {
                        "row_id": "relay-1",
                        "station_name": "Relay 1",
                        "base_url": "https://relay.example/v1",
                        "credential": {"mode": "ephemeral", "api_key": secret},
                    }
                ],
            },
        )

    assert response.status_code == 404
    assert secret not in response.text
    assert response.headers["cache-control"] == "no-store"
