import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

import relay_auditor.main as main_module
from relay_auditor.config import Settings
from relay_auditor.detectors.fingerprint import FingerprintRunner
from relay_auditor.detectors.tokenizer import PROBE_UNITS
from relay_auditor.main import create_app


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=tmp_path / "unused-cli.js",
        **overrides,
    )


def _register_reference(app, artifact_id: str, *, category: str, detector: str, payload: dict):
    artifact = app.state.evidence.write_json(category, artifact_id, payload)
    app.state.database.create_run(
        audit_id=artifact_id,
        detector=detector,
        target_base_url="https://official.example/v1",
        model=str(payload.get("model") or "reference-model"),
    )
    app.state.database.finish_run(
        artifact_id,
        status="completed",
        verdict="recorded",
        artifact_path=str(artifact.path),
        artifact_sha256=artifact.sha256,
    )
    return artifact


def test_tampered_comparison_is_not_trusted_or_downloaded(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    audit_id = "11111111-1111-1111-1111-111111111111"
    batch_id = "22222222-2222-2222-2222-222222222222"
    reference_id = "33333333-3333-3333-3333-333333333333"

    with TestClient(app) as client:
        app.state.database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url="https://relay.example/v1",
            model="target-model",
        )
        app.state.database.create_comparison_record(
            audit_id=audit_id,
            batch_id=batch_id,
            total_items=1,
            station_name="Relay Test",
            reference_artifact_id=reference_id,
            reference_name="Reference",
            reference_model="reference-model",
            cells=4,
            samples=15,
            concurrency=2,
        )
        artifact = app.state.evidence.write_json(
            "verification",
            audit_id,
            {
                "decision": {
                    "operationalVerdict": "unverifiable",
                    "status": "uncalibrated",
                    "reasons": ["validated_threshold_policy_missing"],
                    "decisionEligible": False,
                },
                "comparison": {"verdict": "match", "meanJsd": 0.01},
            },
        )
        app.state.database.finish_run(
            audit_id,
            status="completed",
            verdict="unverifiable",
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
        )
        app.state.database.finish_comparison_record(audit_id)

        artifact.path.write_text(
            json.dumps(
                {
                    "decision": {
                        "operationalVerdict": "match",
                        "status": "calibrated",
                        "reasons": [],
                        "decisionEligible": True,
                    },
                    "comparison": {"verdict": "match", "meanJsd": 0.01},
                }
            ),
            encoding="utf-8",
        )

        item = client.get("/api/v1/console/comparisons").json()["items"][0]
        assert item["verdict"] == "unverifiable"
        assert item["decision_status"] == "legacy_unmigrated"
        assert item["evidence_available"] is False
        assert item["evidence_state"] == "corrupt"
        assert item["evidence_integrity"] == "corrupt"

        download = client.get(f"/api/v1/console/evidence/{audit_id}")
        assert download.status_code == 409
        assert "SHA-256" in download.json()["detail"]

        audit = next(
            value
            for value in client.get("/api/v1/audits").json()["items"]
            if value["id"] == audit_id
        )
        assert audit["verdict"] == "unverifiable"
        assert audit["evidence_integrity"] == "corrupt"


def test_registered_digest_cannot_rebind_evidence_to_another_artifact_path(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    audit_id = "11111111-1111-1111-1111-111111111121"
    other_id = "11111111-1111-1111-1111-111111111122"

    with TestClient(app) as client:
        artifact = app.state.evidence.write_json(
            "verification",
            other_id,
            {"decision": {"operationalVerdict": "match", "status": "calibrated"}},
        )
        app.state.database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url="https://relay.example/v1",
            model="target-model",
        )
        app.state.database.finish_run(
            audit_id,
            status="completed",
            verdict="match",
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
        )

        audit = next(
            item
            for item in client.get("/api/v1/audits").json()["items"]
            if item["id"] == audit_id
        )
        assert audit["verdict"] == "unverifiable"
        assert audit["evidence_integrity"] == "corrupt"
        download = client.get(f"/api/v1/console/evidence/{audit_id}")
        assert download.status_code == 409
        assert "canonical artifact path" in download.json()["detail"]


def test_legacy_audit_endpoint_downgrades_unmigrated_match(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    audit_id = "11111111-1111-1111-1111-111111111119"

    with TestClient(app) as client:
        app.state.database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url="https://relay.example/v1",
            model="target-model",
        )
        artifact = app.state.evidence.write_json(
            "verification",
            audit_id,
            {"verdict": "match", "comparison": {"verdict": "match", "meanJsd": 0.01}},
        )
        app.state.database.finish_run(
            audit_id,
            status="completed",
            verdict="match",
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
        )
        failed_id = "11111111-1111-1111-1111-111111111118"
        app.state.database.create_run(
            audit_id=failed_id,
            detector="one_token_verify",
            target_base_url="https://relay.example/v1",
            model="target-model",
        )
        app.state.database.finish_run(
            failed_id,
            status="failed",
            verdict="error",
            error_message="safe test failure",
        )
        tokenizer_id = "11111111-1111-1111-1111-111111111117"
        app.state.database.create_run(
            audit_id=tokenizer_id,
            detector="tokenizer_verify",
            target_base_url="https://relay.example/v1",
            model="target-model",
        )
        tokenizer_artifact = app.state.evidence.write_json(
            "tokenizer_verification",
            tokenizer_id,
            {
                "comparison": {"verdict": "match", "normalized_l1": 0.0},
                "decision": {
                    "operationalVerdict": "match",
                    "status": "calibrated",
                    "decisionEligible": True,
                },
            },
        )
        app.state.database.finish_run(
            tokenizer_id,
            status="completed",
            verdict="match",
            artifact_path=str(tokenizer_artifact.path),
            artifact_sha256=tokenizer_artifact.sha256,
        )

        audits = client.get("/api/v1/audits").json()["items"]
        audit = next(item for item in audits if item["id"] == audit_id)
        assert audit["verdict"] == "unverifiable"
        assert audit["legacy_verdict"] == "match"
        assert audit["verdict_semantics"] == "legacy-unmigrated"
        assert audit["decision"]["decisionEligible"] is False
        failed = next(item for item in audits if item["id"] == failed_id)
        assert failed["status"] == "failed"
        assert failed["verdict"] == "error"
        tokenizer = next(item for item in audits if item["id"] == tokenizer_id)
        assert tokenizer["verdict"] == "unverifiable"
        assert tokenizer["legacy_verdict"] == "match"
        assert tokenizer["verdict_semantics"] == "legacy-uncalibrated"
        assert tokenizer["decision"]["exploratoryVerdict"] == "match"


def test_tampered_reference_fails_before_sampling(
    tmp_path: Path,
    monkeypatch,
) -> None:
    app = create_app(_settings(tmp_path))
    reference_id = "33333333-3333-3333-3333-333333333339"
    reference = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": "reference-model",
        "cells": {},
    }

    async def must_not_sample(*args, **kwargs):
        raise AssertionError("sampling must not start for corrupt reference evidence")

    monkeypatch.setattr(FingerprintRunner, "verify", must_not_sample)
    with TestClient(app) as client:
        artifact = _register_reference(
            app,
            reference_id,
            category="fingerprints",
            detector="one_token_collect",
            payload=reference,
        )
        artifact.path.write_text('{"tampered":true}\n', encoding="utf-8")

        response = client.post(
            "/api/v1/console/fingerprints/verify",
            json={
                "endpoint": {"base_url": "https://relay.example/v1", "model": "target-model"},
                "reference_artifact_id": reference_id,
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "evidence_integrity_failed"

        batch = client.post(
            "/api/v1/console/comparison-batches",
            json={
                "items": [
                    {
                        "endpoint": {
                            "base_url": "https://relay.example/v1",
                            "model": "target-model",
                        },
                        "reference_artifact_id": reference_id,
                        "station_name": "Relay Test",
                        "reference_name": "Reference",
                        "reference_model": "reference-model",
                    }
                ]
            },
        )
        assert batch.status_code == 409
        assert client.get("/api/v1/console/comparison-batches/active").json()["batch"] is None


def test_console_api_rejects_nonlocal_host_and_cross_origin(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        nonlocal_request = client.get(
            "/api/v1/console/references",
            headers={"host": "relay.example"},
        )
        assert nonlocal_request.status_code == 403
        rebinding_request = client.get(
            "/api/v1/audits",
            headers={"host": "relay.example"},
        )
        assert rebinding_request.status_code == 403

        cross_origin = client.post(
            "/api/v1/console/models",
            headers={"origin": "https://evil.example"},
            json={"endpoint": {"base_url": "https://relay.example/v1"}},
        )
        assert cross_origin.status_code == 403

        malformed_origin = client.get(
            "/api/v1/console/references",
            headers={"origin": "http://testserver:bad"},
        )
        assert malformed_origin.status_code == 403


def test_nonlocal_client_requires_configured_access_token(tmp_path: Path) -> None:
    token = "local-random-access-token"
    app = create_app(_settings(tmp_path, access_token=token))
    credentials = base64.b64encode(f"auditor:{token}".encode()).decode()
    with TestClient(app, client=("203.0.113.9", 41234)) as client:
        denied = client.get("/api/v1/console/references")
        assert denied.status_code == 401
        assert denied.headers["www-authenticate"].startswith("Basic")

        allowed = client.get(
            "/api/v1/console/references",
            headers={"authorization": f"Basic {credentials}"},
        )
        assert allowed.status_code == 200


def test_validation_errors_do_not_echo_api_keys_or_url_credentials(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    api_key_marker = "OVERSIZED-API-KEY-MARKER"
    url_password_marker = "URL-PASSWORD-MARKER"
    camelcase_marker = "CAMELCASE-SECRET-MARKER"
    camelcase_url_marker = "CAMELCASE-URL-SECRET-MARKER"
    unknown_field_marker = "UNKNOWN-CREDENTIAL-FIELD-MARKER"
    query_marker = "QUERY-SECRET-MARKER"

    with TestClient(app) as client:
        oversized_key = client.post(
            "/api/v1/console/models",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "api_key": api_key_marker + ("x" * 4096),
                }
            },
        )
        assert oversized_key.status_code == 422
        assert api_key_marker not in oversized_key.text
        assert oversized_key.json()["detail"][0]["input"] == "[REDACTED]"

        url_userinfo = client.post(
            "/api/v1/audits/smoke",
            json={
                "target": {
                    "base_url": (
                        f"https://auditor:{url_password_marker}@relay.example/v1"
                    ),
                    "model": "target-model",
                }
            },
        )
        assert url_userinfo.status_code == 422
        assert url_password_marker not in url_userinfo.text
        assert url_userinfo.json()["detail"][0]["input"] == "[REDACTED]"

        camelcase_extra = client.post(
            "/api/v1/console/fingerprints/verify",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "target-model",
                },
                "reference_artifact_id": "11111111-1111-1111-1111-111111111111",
                "apiKey": camelcase_marker,
                "baseUrl": f"https://user:{camelcase_url_marker}@relay.example/v1",
                "credential": unknown_field_marker,
            },
        )
        assert camelcase_extra.status_code == 422
        assert camelcase_marker not in camelcase_extra.text
        assert camelcase_url_marker not in camelcase_extra.text
        assert unknown_field_marker not in camelcase_extra.text

        query_secret = client.post(
            "/api/v1/audits/smoke",
            json={
                "target": {
                    "base_url": f"https://relay.example/v1?api_key={query_marker}",
                    "model": "target-model",
                }
            },
        )
        assert query_secret.status_code == 422
        assert query_marker not in query_secret.text


def test_managed_api_key_requires_explicit_allowlist_and_is_not_persisted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-explicit-test-only"
    access_token = "managed-credential-access-token"
    authorization = {
        "authorization": (
            "Basic "
            + base64.b64encode(f"auditor:{access_token}".encode()).decode()
        )
    }
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    calls: list[str | None] = []

    async def fake_smoke(endpoint, prompt, *, timeout_seconds, api_key, **kwargs):
        calls.append(api_key)
        return {"verdict": "pass", "request": {"model": endpoint.model}}

    monkeypatch.setattr(main_module, "run_smoke", fake_smoke)
    blocked_app = create_app(
        _settings(tmp_path / "blocked", access_token=access_token)
    )
    with TestClient(blocked_app) as client:
        response = client.post(
            "/api/v1/audits/smoke",
            headers=authorization,
            json={
                "target": {
                    "base_url": "https://relay.example/v1",
                    "model": "target-model",
                    "api_key_env": "OPENAI_API_KEY",
                }
            },
        )
        assert response.status_code == 400
        assert calls == []

    monkeypatch.setenv("RELAY_AUDIT_KEY", secret)
    allowed_path = tmp_path / "allowed"
    allowed_app = create_app(
        _settings(
            allowed_path,
            allowed_api_key_envs="RELAY_AUDIT_KEY",
            api_key_base_url_bindings=json.dumps(
                {"RELAY_AUDIT_KEY": ["https://relay.example/v1"]}
            ),
            access_token=access_token,
        )
    )
    with TestClient(allowed_app) as client:
        endpoint_payload = {
            "name": "approved-relay",
            "provider": "test",
            "base_url": "https://relay.example/v1",
            "model": "target-model",
            "api_key_env": "RELAY_AUDIT_KEY",
        }
        denied_registration = client.post(
            "/api/v1/endpoints",
            json=endpoint_payload,
        )
        assert denied_registration.status_code == 401
        registered = client.post(
            "/api/v1/endpoints",
            headers=authorization,
            json=endpoint_payload,
        )
        assert registered.status_code == 201

        redacted_endpoint = client.get("/api/v1/endpoints").json()["items"][0]
        assert redacted_endpoint["credential_configured"] is True
        assert redacted_endpoint["api_key_env"] is None
        authenticated_endpoint = client.get(
            "/api/v1/endpoints",
            headers=authorization,
        ).json()["items"][0]
        assert authenticated_endpoint["api_key_env"] == "RELAY_AUDIT_KEY"

        reference_id = "33333333-3333-3333-3333-333333333337"
        _register_reference(
            allowed_app,
            reference_id,
            category="fingerprints",
            detector="one_token_collect",
            payload={"model": "target-model"},
        )
        now = datetime.now(UTC)
        allowed_app.state.database.create_baseline(
            baseline_id="44444444-4444-4444-4444-444444444447",
            endpoint_id=registered.json()["id"],
            detector="one_token",
            artifact_id=reference_id,
            valid_from=now,
            expires_at=now + timedelta(days=1),
            metadata={},
        )
        redacted_reference = client.get("/api/v1/console/references").json()["items"][0]
        assert redacted_reference["endpoint"]["credential_configured"] is True
        assert redacted_reference["endpoint"]["api_key_env"] is None
        authenticated_reference = client.get(
            "/api/v1/console/references",
            headers=authorization,
        ).json()["items"][0]
        assert authenticated_reference["endpoint"]["api_key_env"] == "RELAY_AUDIT_KEY"

        audit_payload = {
            "target": {
                "base_url": "https://relay.example/v1",
                "model": "target-model",
                "api_key_env": "RELAY_AUDIT_KEY",
            }
        }
        denied_use = client.post(
            "/api/v1/audits/smoke",
            json=audit_payload,
        )
        assert denied_use.status_code == 401
        assert calls == []
        response = client.post(
            "/api/v1/audits/smoke",
            headers=authorization,
            json=audit_payload,
        )
        assert response.status_code == 200
        assert calls == [secret]
        assert secret not in response.text
        wrong_target = client.post(
            "/api/v1/audits/smoke",
            headers=authorization,
            json={
                "target": {
                    "base_url": "https://attacker.example/v1",
                    "model": "target-model",
                    "api_key_env": "RELAY_AUDIT_KEY",
                }
            },
        )
        assert wrong_target.status_code == 400
        assert calls == [secret]

    disabled_app = create_app(
        _settings(
            tmp_path / "disabled",
            allowed_api_key_envs="RELAY_AUDIT_KEY",
        )
    )
    with TestClient(disabled_app) as client:
        disabled = client.post("/api/v1/endpoints", json=endpoint_payload)
        assert disabled.status_code == 403
        assert calls == [secret]
    assert secret.encode() not in (allowed_path / "test.db").read_bytes()
    assert all(
        secret not in path.read_text()
        for path in (allowed_path / "evidence").rglob("*.json")
    )


def test_tokenizer_api_keeps_uncalibrated_result_exploratory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    app = create_app(_settings(tmp_path))
    reference_id = "33333333-3333-3333-3333-333333333338"
    fingerprint = {
        "protocol": "tokenizer-slope/v1",
        "model": "reference-model",
        "slope_vector": {probe_id: 1.0 for probe_id in PROBE_UNITS},
        "unstable_probes": [],
    }

    async def fake_collect(endpoint, **kwargs):
        assert kwargs["api_key"] is None
        return {**fingerprint, "model": endpoint.model}

    monkeypatch.setattr(main_module, "collect_tokenizer_fingerprint", fake_collect)
    with TestClient(app) as client:
        _register_reference(
            app,
            reference_id,
            category="tokenizers",
            detector="tokenizer_collect",
            payload=fingerprint,
        )
        response = client.post(
            "/api/v1/tokenizers/verify",
            json={
                "endpoint": {"base_url": "https://relay.example/v1", "model": "target-model"},
                "reference_artifact_id": reference_id,
                "samples_per_point": 2,
                "concurrency": 2,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["verdict"] == "unverifiable"
        assert body["result"]["comparison"]["verdict"] == "match"
        assert body["result"]["exploratoryVerdict"] == "match"
        assert body["result"]["decision"]["decisionEligible"] is False
        assert body["result"]["decision"]["status"] == "uncalibrated"
        run = app.state.database.get_run(body["audit_id"])
        assert run is not None and run.verdict == "unverifiable"
