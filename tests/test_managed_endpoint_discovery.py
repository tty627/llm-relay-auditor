import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from relay_auditor.config import Settings
from relay_auditor.detectors.fingerprint import FingerprintRunner
from relay_auditor.detectors.models import discover_models
from relay_auditor.detectors.preflight import run_fingerprint_preflight
from relay_auditor.detectors.tokenizer import collect_tokenizer_fingerprint
from relay_auditor.main import create_app
from relay_auditor.schemas import EndpointSpec, EphemeralConnectionSpec

MANAGEMENT_TOKEN = "test-management-token-at-least-32-characters"
MANAGEMENT_HEADERS = {"X-Relay-Auditor-Token": MANAGEMENT_TOKEN}


@pytest.mark.parametrize(
    "base_url",
    ["https://relay.example/v1?tenant=other", "https://relay.example/v1#fragment"],
)
def test_endpoint_base_url_rejects_query_and_fragment(base_url: str) -> None:
    with pytest.raises(ValueError, match="query parameters or fragments"):
        EndpointSpec(base_url=base_url, model="model-a")


def test_model_discovery_normalizes_base_url_and_retries_429() -> None:
    secret = "sk-discovery-retry-secret"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["authorization"] == f"Bearer {secret}"
        if len(requests) == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "model-b"},
                    {"id": "model-a", "owned_by": "vendor"},
                    {"id": "model-a", "owned_by": "duplicate"},
                    {"id": " model-a ", "owned_by": "whitespace duplicate"},
                ]
            },
        )

    result = asyncio.run(
        discover_models(
            EphemeralConnectionSpec(base_url="https://relay.example", api_key=secret),
            timeout_seconds=3,
            transport=httpx.MockTransport(handler),
        )
    )

    assert [str(request.url) for request in requests] == [
        "https://relay.example/v1/models",
        "https://relay.example/v1/models",
    ]
    assert result["attempts"] == 2
    assert result["retries"] == 1
    assert [item["id"] for item in result["models"]] == ["model-a", "model-b"]
    assert secret not in json.dumps(result)


def test_model_discovery_rejects_credential_echo() -> None:
    secret = "sk-echoed-model-secret"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": secret}]})

    with pytest.raises(RuntimeError, match="credential"):
        asyncio.run(
            discover_models(
                EphemeralConnectionSpec(
                    base_url="https://relay.example/v1",
                    api_key=secret,
                ),
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )


def test_model_discovery_does_not_follow_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"location": "https://attacker.example/v1/models"},
            json={"data": [{"id": "fake-model"}]},
        )

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(
            discover_models(
                EphemeralConnectionSpec(base_url="https://relay.example/v1"),
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )
    assert len(requests) == 1


def test_model_discovery_uses_bounded_backoff_for_invalid_retry_after(
    monkeypatch,
) -> None:
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "NaN"})

    monkeypatch.setattr("relay_auditor.detectors.models.asyncio.sleep", fake_sleep)
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(
            discover_models(
                EphemeralConnectionSpec(base_url="https://relay.example/v1"),
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
                max_retries=1,
            )
        )
    assert delays == [0.25]


def test_preflight_rejects_credential_echo() -> None:
    secret = "sk-echoed-preflight-secret"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"x-request-id": secret},
            json={"choices": [{"message": {"content": "42"}}]},
        )

    with pytest.raises(RuntimeError, match="credential"):
        asyncio.run(
            run_fingerprint_preflight(
                EndpointSpec(base_url="https://relay.example", model="model-a"),
                api_key=secret,
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )


@pytest.mark.asyncio
async def test_tokenizer_uses_normalized_base_url() -> None:
    urls: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        urls.add(str(request.url))
        return httpx.Response(200, json={"usage": {"prompt_tokens": 12}})

    result = await collect_tokenizer_fingerprint(
        EndpointSpec(base_url="https://relay.example", model="model-a"),
        timeout_seconds=3,
        samples_per_point=1,
        concurrency=4,
        transport=httpx.MockTransport(handler),
    )
    assert urls == {"https://relay.example/v1/chat/completions"}
    assert result["base_url"] == "https://relay.example/v1"


def test_managed_endpoint_discovery_and_collection_use_allowlisted_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-managed-endpoint-secret"
    monkeypatch.setenv("RELAY_AUDIT_KEY", secret)
    database_path = tmp_path / "test.db"
    evidence_dir = tmp_path / "evidence"
    configured = Settings(
        database_url=f"sqlite:///{database_path}",
        evidence_dir=evidence_dir,
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
        allowed_api_key_envs="RELAY_AUDIT_KEY",
        api_key_base_url_bindings=json.dumps(
            {"RELAY_AUDIT_KEY": ["https://relay.example/v1"]}
        ),
        management_token=MANAGEMENT_TOKEN,
    )

    async def fake_discover(endpoint, *, timeout_seconds, api_key):
        assert endpoint.reveal_api_key() is None
        assert str(endpoint.base_url).rstrip("/") == "https://relay.example/v1"
        assert timeout_seconds > 0
        assert api_key == secret
        return {
            "base_url": "https://relay.example/v1",
            "models_url": "https://relay.example/v1/models",
            "count": 2,
            "models": [{"id": "model-a"}, {"id": "model-b"}],
            "attempts": 1,
            "retries": 0,
        }

    async def fake_collect(self, endpoint, *, output_path, api_key, **kwargs):
        assert endpoint.api_key_env == "RELAY_AUDIT_KEY"
        assert api_key == secret
        fingerprint = {
            "formatVersion": 1,
            "protocol": "one-token/v1",
            "model": endpoint.model,
            "cells": {},
        }
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return {"fingerprint": fingerprint}

    monkeypatch.setattr("relay_auditor.main.discover_models", fake_discover)
    monkeypatch.setattr(FingerprintRunner, "collect", fake_collect)
    app = create_app(configured)
    with TestClient(app) as client:
        openapi = client.get("/openapi.json").json()
        scheme = openapi["components"]["securitySchemes"]["ManagedCredentialToken"]
        assert scheme == {
            "type": "apiKey",
            "description": "Local management token required when api_key_env is used.",
            "in": "header",
            "name": "X-Relay-Auditor-Token",
        }
        assert {"ManagedCredentialToken": []} in openapi["paths"][
            "/api/v1/endpoints"
        ]["post"]["security"]

        created = client.post(
            "/api/v1/endpoints",
            json={
                "name": "managed relay model-a",
                "provider": "relay",
                "base_url": "https://relay.example",
                "model": "model-a",
                "api_key_env": "RELAY_AUDIT_KEY",
            },
        )
        assert created.status_code == 401
        created = client.post(
            "/api/v1/endpoints",
            headers=MANAGEMENT_HEADERS,
            json={
                "name": "managed relay model-a",
                "provider": "relay",
                "base_url": "https://relay.example",
                "model": "model-a",
                "api_key_env": "RELAY_AUDIT_KEY",
            },
        )
        assert created.status_code == 201
        assert created.json()["base_url"] == "https://relay.example/v1"
        endpoint_id = created.json()["id"]

        discovered = client.post(
            f"/api/v1/endpoints/{endpoint_id}/models",
            headers=MANAGEMENT_HEADERS,
        )
        assert discovered.status_code == 200
        assert discovered.json()["credential_source"] == "env_ref"
        assert [item["id"] for item in discovered.json()["models"]] == [
            "model-a",
            "model-b",
        ]
        assert discovered.headers["cache-control"] == "no-store"
        assert secret not in discovered.text

        unauthorized = client.post(
            "/api/v1/fingerprints/collect",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "model-a",
                    "api_key_env": "RELAY_AUDIT_KEY",
                }
            },
        )
        assert unauthorized.status_code == 401

        collected = client.post(
            "/api/v1/fingerprints/collect",
            headers=MANAGEMENT_HEADERS,
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "model-a",
                    "api_key_env": "RELAY_AUDIT_KEY",
                },
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
            },
        )
        assert collected.status_code == 200
        assert collected.json()["status"] == "completed"
        assert secret not in collected.text

        baseline = client.post(
            "/api/v1/baselines",
            json={
                "endpoint_id": endpoint_id,
                "detector": "one_token",
                "artifact_id": collected.json()["artifact_id"],
                "valid_days": 7,
            },
        )
        assert baseline.status_code == 201

    assert secret.encode() not in database_path.read_bytes()
    assert all(
        secret.encode() not in path.read_bytes()
        for path in evidence_dir.rglob("*")
        if path.is_file()
    )


def test_managed_credentials_require_allowlist_binding_and_value(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_path = tmp_path / "test.db"
    configured = Settings(
        database_url=f"sqlite:///{database_path}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
        allowed_api_key_envs="RELAY_AUDIT_KEY",
        api_key_base_url_bindings=json.dumps(
            {"RELAY_AUDIT_KEY": ["https://relay.example/v1"]}
        ),
        management_token=MANAGEMENT_TOKEN,
    )
    monkeypatch.delenv("RELAY_AUDIT_KEY", raising=False)
    app = create_app(configured)
    with TestClient(app) as client:
        rejected = client.post(
            "/api/v1/endpoints",
            headers=MANAGEMENT_HEADERS,
            json={
                "name": "unapproved",
                "provider": "relay",
                "base_url": "https://relay.example/v1",
                "model": "model-a",
                "api_key_env": "OTHER_SECRET",
            },
        )
        assert rejected.status_code == 400

        created = client.post(
            "/api/v1/endpoints",
            headers=MANAGEMENT_HEADERS,
            json={
                "name": "approved",
                "provider": "relay",
                "base_url": "https://relay.example/v1",
                "model": "model-a",
                "api_key_env": "RELAY_AUDIT_KEY",
            },
        )
        assert created.status_code == 201
        endpoint_id = created.json()["id"]
        missing = client.post(
            f"/api/v1/endpoints/{endpoint_id}/models",
            headers=MANAGEMENT_HEADERS,
        )
        assert missing.status_code == 400
        assert "not set" in missing.text

        monkeypatch.setenv("RELAY_AUDIT_KEY", "sk-bound-secret")
        unbound = client.post(
            "/api/v1/fingerprints/collect",
            headers=MANAGEMENT_HEADERS,
            json={
                "endpoint": {
                    "base_url": "https://attacker.example/v1",
                    "model": "model-a",
                    "api_key_env": "RELAY_AUDIT_KEY",
                }
            },
        )
        assert unbound.status_code == 400
        assert "not bound" in unbound.text
        assert client.get("/api/v1/audits").json()["items"] == []

        self_registered = client.post(
            "/api/v1/endpoints",
            headers=MANAGEMENT_HEADERS,
            json={
                "name": "attacker registration",
                "provider": "relay",
                "base_url": "https://attacker.example/v1",
                "model": "model-a",
                "api_key_env": "RELAY_AUDIT_KEY",
            },
        )
        assert self_registered.status_code == 400
        assert "not bound" in self_registered.text


def test_managed_fingerprint_echo_never_reaches_response_database_or_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-managed-artifact-echo-secret"
    monkeypatch.setenv("RELAY_AUDIT_KEY", secret)
    database_path = tmp_path / "test.db"
    evidence_dir = tmp_path / "evidence"
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    app = create_app(
        Settings(
            database_url=f"sqlite:///{database_path}",
            evidence_dir=evidence_dir,
            fingerprint_cli_path=cli_path,
            allowed_api_key_envs="RELAY_AUDIT_KEY",
            api_key_base_url_bindings=json.dumps(
                {"RELAY_AUDIT_KEY": ["https://relay.example/v1"]}
            ),
            management_token=MANAGEMENT_TOKEN,
        )
    )

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        assert all(secret not in argument for argument in arguments)
        assert secret in environment.values()
        output_path = Path(arguments[arguments.index("--out") + 1])
        output_path.write_text(json.dumps({"echo": secret}), encoding="utf-8")
        raise RuntimeError("simulated CLI failure")

    monkeypatch.setattr(app.state.fingerprint, "_execute", fake_execute)
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/endpoints",
            headers=MANAGEMENT_HEADERS,
            json={
                "name": "echo test",
                "provider": "relay",
                "base_url": "https://relay.example/v1",
                "model": "model-a",
                "api_key_env": "RELAY_AUDIT_KEY",
            },
        )
        assert created.status_code == 201
        response = client.post(
            "/api/v1/fingerprints/collect",
            headers=MANAGEMENT_HEADERS,
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "model-a",
                    "api_key_env": "RELAY_AUDIT_KEY",
                }
            },
        )
        assert response.status_code == 502
        assert response.json()["detail"] == "credential_echo_detected"
        assert secret not in response.text

    assert secret.encode() not in database_path.read_bytes()
    assert all(
        secret.encode() not in path.read_bytes()
        for path in evidence_dir.rglob("*")
        if path.is_file()
    )


def test_managed_credential_configuration_is_validated_at_startup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("RELAY_AUDIT_KEY", "  sk-trimmed-secret  ")
    common = {
        "database_url": f"sqlite:///{tmp_path / 'test.db'}",
        "evidence_dir": tmp_path / "evidence",
        "fingerprint_cli_path": Path("llm-fingerprint-detector/dist/cli.js"),
        "allowed_api_key_envs": "RELAY_AUDIT_KEY",
        "management_token": MANAGEMENT_TOKEN,
    }

    remote_http = Settings(
        **common,
        api_key_base_url_bindings=json.dumps(
            {"RELAY_AUDIT_KEY": ["http://relay.example/v1"]}
        ),
    )
    with pytest.raises(ValueError, match="HTTPS"):
        create_app(remote_http)

    missing_binding = Settings(**common, api_key_base_url_bindings="{}")
    with pytest.raises(ValueError, match="needs a Base URL binding"):
        create_app(missing_binding)

    invalid_token = Settings(
        **{**common, "management_token": "密" * 24},
        api_key_base_url_bindings=json.dumps(
            {"RELAY_AUDIT_KEY": ["https://relay.example/v1"]}
        ),
    )
    with pytest.raises(ValueError, match="URL-safe ASCII"):
        create_app(invalid_token)

    valid = Settings(
        **common,
        api_key_base_url_bindings=json.dumps(
            {"RELAY_AUDIT_KEY": ["https://relay.example/v1"]}
        ),
    )
    valid.validate_managed_credential_configuration()
    assert valid.resolve_api_key("RELAY_AUDIT_KEY") == "sk-trimmed-secret"


@pytest.mark.parametrize(
    ("configured_url", "requested_url"),
    [
        ("https://Relay.Example/v1", "https://relay.example/v1"),
        ("https://relay.example:443/v1", "https://relay.example/v1"),
        ("https://例子.测试/v1", "https://xn--fsqu00a.xn--0zwm56d/v1"),
    ],
)
def test_managed_base_url_bindings_use_canonical_authority(
    configured_url: str,
    requested_url: str,
) -> None:
    configured = Settings(
        allowed_api_key_envs="RELAY_AUDIT_KEY",
        api_key_base_url_bindings=json.dumps({"RELAY_AUDIT_KEY": [configured_url]}),
        management_token=MANAGEMENT_TOKEN,
    )
    configured.validate_managed_credential_configuration()
    configured.require_api_key_base_url_binding("RELAY_AUDIT_KEY", requested_url)


async def test_fingerprint_runner_never_inherits_ambient_provider_keys(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    captured: dict[str, object] = {}
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ambient-openai")
    monkeypatch.setenv("LLM_FINGERPRINT_API_KEY", "sk-ambient-fingerprint")
    monkeypatch.setenv("LC_VENDOR_API_KEY", "sk-ambient-locale")
    monkeypatch.setenv("LC_ALL", "sk-source-locale")
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/tmp/test-ca.pem")

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        captured["arguments"] = arguments
        captured["environment"] = environment
        return {"fingerprint": {}}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    await runner.collect(
        EndpointSpec(
            base_url="https://public.example/v1",
            model="model-a",
            api_key_env="LC_ALL",
        ),
        output_path=tmp_path / "fingerprint.json",
        cells=4,
        samples=15,
        concurrency=2,
        api_key="sk-explicit-task-key",
    )

    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert "OPENAI_API_KEY" not in environment
    assert "LLM_FINGERPRINT_API_KEY" not in environment
    assert "LC_VENDOR_API_KEY" not in environment
    assert "LC_ALL" not in environment
    assert environment["NODE_EXTRA_CA_CERTS"] == "/tmp/test-ca.pem"
    assert all("sk-explicit-task-key" not in argument for argument in captured["arguments"])


async def test_fingerprint_runner_deletes_failed_artifact_that_echoes_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-failed-artifact-secret"
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    output_path = tmp_path / "fingerprint.json"
    runner = FingerprintRunner(cli_path)

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        output_path.write_text(json.dumps({"echo": secret}), encoding="utf-8")
        raise RuntimeError("CLI failed")

    monkeypatch.setattr(runner, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="output was rejected"):
        await runner.collect(
            EndpointSpec(base_url="https://relay.example/v1", model="model-a"),
            output_path=output_path,
            cells=4,
            samples=15,
            concurrency=2,
            api_key=secret,
        )
    assert not output_path.exists()
