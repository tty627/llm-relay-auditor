import asyncio
import hashlib
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from relay_auditor.config import Settings
from relay_auditor.detectors.fingerprint import FingerprintPausedError, FingerprintRunner
from relay_auditor.detectors.preflight import (
    FingerprintPreflightError,
    run_fingerprint_preflight,
)
from relay_auditor.main import create_app
from relay_auditor.schemas import EndpointSpec


def _install_fast_batch_preflight(app, *, latency_ms: float = 1) -> None:
    async def fake_preflight(endpoint, *, api_key, timeout_seconds):
        assert timeout_seconds > 0
        return {
            "statusCode": 200,
            "latencyMs": latency_ms,
            "hasContent": True,
            "requestId": "req-local-preflight",
            "normalizedBaseUrl": str(endpoint.base_url).rstrip("/"),
            "retries": 0,
        }

    app.state.batches.preflight = fake_preflight


def _register_reference(app, artifact_id: str, payload: dict[str, object]) -> Path:
    """Write test evidence with the same persisted provenance required in production."""

    path = app.state.evidence.fingerprint_path(artifact_id)
    path.write_text(json.dumps(payload), encoding="utf-8")
    if app.state.database.get_run(artifact_id) is None:
        app.state.database.create_run(
            audit_id=artifact_id,
            detector="one_token_collect",
            target_base_url="https://official.example/v1",
            model=str(payload.get("model") or "reference-model"),
        )
    app.state.database.finish_run(
        artifact_id,
        status="completed",
        verdict="recorded",
        artifact_path=str(path),
        artifact_sha256=app.state.evidence.digest_file(path),
    )
    return path


def _write_test_paper_collection(
    output_path: Path,
    samples_output_path: Path,
    *,
    model: str,
    role: str,
    samples: int,
) -> dict[str, object]:
    raw_evidence = f'{{"model":"{model}","role":"{role}"}}\n'
    samples_output_path.write_text(raw_evidence, encoding="utf-8")
    raw_sha256 = hashlib.sha256(raw_evidence.encode()).hexdigest()
    fingerprint = {
        "formatVersion": 2,
        "protocol": "bruckner-2026-canonical40/v1",
        "model": model,
        "samplesPerCell": samples,
        "postReasoning": False,
        "cells": {},
        "plan": {"role": role},
        "quality": {
            "complete": True,
            "reasoningTokenCount": 0,
            "rawEvidenceSha256": raw_sha256,
        },
    }
    output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
    return {
        "fingerprint": fingerprint,
        "collection": {
            "artifactKind": "paper-profile-collection-v2",
            "interpretation": "uncalibrated-non-decision-evidence",
            "decisionEligible": False,
            "protocol": "bruckner-2026-canonical40/v1",
            "model": model,
            "role": role,
            "cellCount": 40,
            "samplesPerCell": samples,
            "expectedSamples": 40 * samples,
            "validSamples": 40 * samples,
            "invalidSamples": 0,
            "errorSamples": 0,
            "directness": "verified",
            "splitHalfMeanJsd": 0.01,
            "splitHalfComparableCells": 40,
            "rawEvidenceSha256": raw_sha256,
        },
    }


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
        model_ids = {item["id"] for item in models.json()["data"]}
        assert {"reference-model", "substitute-model", "mixed-10", "mixed-20"} <= model_ids

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


def test_fingerprint_preflight_matches_cli_url_and_uses_bare_compatibility_fallback() -> None:
    secret = "sk-local-preflight-only"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["authorization"] == f"Bearer {secret}"
        body = json.loads(request.content)
        if len(requests) == 1:
            assert body["reasoning"] == {"enabled": False}
            return httpx.Response(400, json={"error": {"message": "unknown reasoning"}})
        assert "reasoning" not in body
        return httpx.Response(
            200,
            headers={"x-request-id": "req-preflight"},
            json={"choices": [{"message": {"content": "42"}}]},
        )

    result = asyncio.run(
        run_fingerprint_preflight(
            EndpointSpec(base_url="https://relay.example", model="model-a"),
            api_key=secret,
            timeout_seconds=3,
            transport=httpx.MockTransport(handler),
        )
    )

    assert [str(request.url) for request in requests] == [
        "https://relay.example/v1/chat/completions",
        "https://relay.example/v1/chat/completions",
    ]
    assert result["statusCode"] == 200
    assert result["attempts"] == 2
    assert result["strategy"] == "none"
    assert secret not in json.dumps(result)


def test_fingerprint_preflight_classifies_503_and_retry_after_as_transient() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            503,
            headers={"retry-after": "17"},
            json={"error": {"message": "upstream unavailable"}},
        )

    try:
        asyncio.run(
            run_fingerprint_preflight(
                EndpointSpec(base_url="https://relay.example/v1", model="model-a"),
                api_key=None,
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )
    except FingerprintPreflightError as error:
        assert "HTTP 503" in str(error)
        assert error.transient is True
        assert error.status_code == 503
        assert error.retry_after_seconds == 17
        assert error.error_kind == "http"
    else:
        raise AssertionError("503 preflight unexpectedly passed")
    assert calls == 1


@pytest.mark.parametrize(
    ("status_code", "expected_transient"),
    [(408, True), (425, True), (500, True), (501, False), (505, False)],
)
def test_fingerprint_preflight_classifies_additional_http_failures(
    status_code: int,
    expected_transient: bool,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"error": {"message": "safe failure"}})

    with pytest.raises(FingerprintPreflightError) as caught:
        asyncio.run(
            run_fingerprint_preflight(
                EndpointSpec(base_url="https://relay.example/v1", model="model-a"),
                api_key=None,
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )

    assert caught.value.status_code == status_code
    assert caught.value.transient is expected_transient


def test_fingerprint_preflight_classifies_410_as_permanent_retired_route() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            410,
            json={
                "error": {
                    "message": "old upstream retired; use a different host instead",
                }
            },
        )

    try:
        asyncio.run(
            run_fingerprint_preflight(
                EndpointSpec(base_url="https://relay.example/v1", model="model-a"),
                api_key=None,
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )
    except FingerprintPreflightError as error:
        assert "HTTP 410" in str(error)
        assert "上游路由或服务已停用" in str(error)
        assert error.transient is False
        assert error.status_code == 410
    else:
        raise AssertionError("410 preflight unexpectedly passed")


def test_browser_console_is_served_with_security_headers(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "One Token 行为指纹与证据工作台" in response.text
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

        script = client.get("/assets/app.js")
        assert script.status_code == 200
        assert "/api/v1/console/reference-collections" in script.text
        assert "/api/v1/console/references/${reference.baselineId}" in script.text
        assert "/api/v1/console/models" in script.text
        assert "创建后刷新页面也会继续执行" in script.text
        assert "刷新页面会自动恢复此任务" in script.text
        assert "/api/v1/console/comparison-batches" in script.text
        assert "pauseOrResumeActiveBatch" in script.text
        assert "cancelActiveBatch" in script.text
        assert "prioritizeComparisonTask" in script.text
        assert "concurrency_mode" in script.text
        assert "候选排名表示与本地参考指纹的距离" in script.text
        assert "秒没有收到新进度" in script.text
        assert "pauseOrResumeReferenceCollection" in script.text
        assert "cancelReferenceCollection" in script.text
        assert "relay-auditor.workspace.v1" in script.text
        assert "/api/v1/console/comparisons/latest" in script.text
        assert "request_timeout_seconds" in script.text

        history = client.get("/history")
        assert history.status_code == 200
        assert "本机对比记录与证据索引" in history.text
        history_script = client.get("/assets/history.js")
        assert history_script.status_code == 200
        assert "/api/v1/console/comparisons" in history_script.text
        assert "载入配置" in history_script.text
        assert "实际并发" in history_script.text
        assert 'value="canceled"' in history.text
        assert 'value="unverifiable"' in history.text


def test_console_direct_verify_rejects_client_comparison_context(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/console/fingerprints/verify",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "model-a",
                },
                "reference_artifact_id": "00000000-0000-0000-0000-000000000099",
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
                "comparison_context": {
                    "batch_id": "00000000-0000-0000-0000-000000000088",
                    "total_items": 500,
                    "station_name": "Relay A",
                    "reference_name": "Official A",
                    "reference_model": "model-a",
                },
            },
        )
        assert response.status_code == 422
        assert any(
            error["loc"][-1] == "comparison_context" and error["type"] == "extra_forbidden"
            for error in response.json()["detail"]
        )
        assert client.get("/api/v1/console/comparison-batches/active").json()["batch"] is None
        assert app.state.database.list_runs() == []


def test_legacy_one_token_history_is_read_only_downgraded_to_unverifiable(
    tmp_path: Path,
) -> None:
    audit_id = "00000000-0000-0000-0000-000000000066"
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    legacy_result = {
        "verdict": "match",
        "comparison": {
            "verdict": "match",
            "meanJsd": 0.015,
            "comparableCellCount": 4,
        },
        "target": {"durationMs": 123, "errorCount": 0},
        "reference": {"model": "reference-model"},
    }

    with TestClient(app) as client:
        app.state.database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url="https://legacy.example/v1",
            model="legacy-model",
        )
        artifact = app.state.evidence.write_json("verification", audit_id, legacy_result)
        app.state.database.finish_run(
            audit_id,
            status="completed",
            verdict="match",
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
        )
        artifact_before = artifact.path.read_bytes()

        history = client.get("/api/v1/console/comparisons").json()
        item = history["items"][0]
        assert item["verdict"] == "unverifiable"
        assert item["operational_verdict"] == "unverifiable"
        assert item["legacy_verdict"] == "match"
        assert item["decision_status"] == "legacy_unmigrated"
        assert item["reasons"] == ["legacy_result_without_safe_decision"]
        assert item["verdict_semantics"] == "legacy-unmigrated"
        assert item["decision"] == {
            "operationalVerdict": "unverifiable",
            "status": "legacy_unmigrated",
            "reasons": ["legacy_result_without_safe_decision"],
            "legacyVerdict": "match",
            "rawMeanJsd": 0.015,
            "decisionEligible": False,
        }

        legacy_match_filter = client.get(
            "/api/v1/console/comparisons",
            params={"verdict": "match"},
        ).json()
        assert legacy_match_filter["total"] == 0
        assert legacy_match_filter["items"] == []

        operational_filter = client.get(
            "/api/v1/console/comparisons",
            params={"verdict": "unverifiable"},
        ).json()
        assert operational_filter["total"] == 1
        assert operational_filter["items"][0]["audit_id"] == audit_id

        latest = client.get("/api/v1/console/comparisons/latest").json()
        response = latest["items"][0]["response"]
        assert response["verdict"] == "unverifiable"
        assert response["result"]["comparison"]["verdict"] == "match"
        assert response["result"]["decision"]["status"] == "legacy_unmigrated"
        assert artifact.path.read_bytes() == artifact_before


def test_comparison_batch_is_precreated_and_survives_browser_reload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-background-batch-secret"
    reference_id = "00000000-0000-0000-0000-000000000077"
    release = threading.Event()
    target_fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": "model-a",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        kwargs["progress_callback"](
            {
                "stage": "sampling",
                "done": 1,
                "total": 60,
                "errors": 0,
                "detail": "正在采样 1/60",
            }
        )
        while not release.is_set():
            if kwargs["cancel_event"].is_set():
                raise FingerprintPausedError("comparison paused")
            await asyncio.sleep(0.01)
        output_path.write_text(json.dumps(target_fingerprint), encoding="utf-8")
        return "match", {
            "verdict": "match",
            "meanJsd": 0.02,
            "reference": {"model": endpoint.model},
            "target": {
                "durationMs": 20,
                "errorCount": 0,
                "splitHalfJsd": 0.01,
                "warnings": [],
            },
            "comparison": {
                "verdict": "match",
                "meanJsd": 0.02,
                "comparableCellCount": 4,
                "cells": [],
            },
            "warnings": [],
        }

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    database_path = tmp_path / "test.db"
    evidence_dir = tmp_path / "evidence"
    settings = Settings(
        database_url=f"sqlite:///{database_path}",
        evidence_dir=evidence_dir,
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, target_fingerprint)
        response = client.post(
            "/api/v1/console/comparison-batches",
            json={
                "items": [
                    {
                        "endpoint": {
                            "base_url": "https://relay.example/v1",
                            "model": model,
                            "api_key": secret,
                        },
                        "reference_artifact_id": reference_id,
                        "station_name": "Relay A",
                        "reference_name": "Official A",
                        "reference_model": model,
                    }
                    for model in ("model-a", "model-b")
                ],
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
                "request_timeout_seconds": 3,
                "model_timeout_seconds": 30,
            },
        )
        assert response.status_code == 202
        body = response.json()
        batch_id = body["batch"]["id"]
        assert len(body["items"]) == 2
        assert {item["status"] for item in body["items"]} <= {"queued", "running"}
        assert secret not in response.text

        deadline = time.monotonic() + 2
        restored = None
        while time.monotonic() < deadline:
            restored = client.get("/api/v1/console/comparison-batches/active").json()
            if any(
                item["progress"] and item["progress"]["stage"] == "sampling"
                for item in restored["items"]
            ):
                break
            time.sleep(0.01)
        assert restored is not None
        assert restored["batch"]["id"] == batch_id
        assert len(restored["items"]) == 2
        assert any(item["status"] == "queued" for item in restored["items"])

        # A page reload only reissues this GET; the server-owned worker keeps running.
        reloaded = client.get(f"/api/v1/console/comparison-batches/{batch_id}")
        assert reloaded.status_code == 200
        assert len(reloaded.json()["items"]) == 2

        release.set()
        deadline = time.monotonic() + 2
        completed = None
        while time.monotonic() < deadline:
            completed = client.get(f"/api/v1/console/comparison-batches/{batch_id}").json()
            if completed["batch"]["status"] == "completed":
                break
            time.sleep(0.01)
        assert completed is not None
        assert completed["batch"]["status"] == "completed"
        assert completed["batch"]["completed_items"] == 2
        assert all(item["status"] == "completed" for item in completed["items"])
        assert secret not in json.dumps(completed)

    assert secret.encode() not in database_path.read_bytes()
    assert all(
        secret not in path.read_text(encoding="utf-8") for path in evidence_dir.rglob("*.json")
    )


def test_comparison_batch_can_pause_and_resume_current_model(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000066"
    attempts = 0
    target_fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": "model-a",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        nonlocal attempts
        attempts += 1
        kwargs["progress_callback"](
            {
                "stage": "adapter",
                "done": 0,
                "total": 60,
                "errors": 0,
                "detail": "none",
            }
        )
        if attempts == 1:
            while not kwargs["cancel_event"].is_set():
                await asyncio.sleep(0.01)
            raise FingerprintPausedError("comparison paused")
        output_path.write_text(json.dumps(target_fingerprint), encoding="utf-8")
        return "match", {
            "verdict": "match",
            "meanJsd": 0.01,
            "reference": {"model": endpoint.model},
            "target": {
                "durationMs": 10,
                "errorCount": 0,
                "splitHalfJsd": 0.01,
                "warnings": [],
            },
            "comparison": {
                "verdict": "match",
                "meanJsd": 0.01,
                "comparableCellCount": 4,
                "cells": [],
            },
            "warnings": [],
        }

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, target_fingerprint)
        response = client.post(
            "/api/v1/console/comparison-batches",
            json={
                "items": [
                    {
                        "endpoint": {
                            "base_url": "https://relay.example/v1",
                            "model": "model-a",
                        },
                        "reference_artifact_id": reference_id,
                        "station_name": "Relay A",
                        "reference_name": "Official A",
                        "reference_model": "model-a",
                    }
                ],
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
                "request_timeout_seconds": 3,
                "model_timeout_seconds": 30,
            },
        )
        batch_id = response.json()["batch"]["id"]

        deadline = time.monotonic() + 2
        current = None
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/console/comparison-batches/{batch_id}").json()
            if current["items"][0]["progress"]["stage"] == "adapter":
                break
            time.sleep(0.01)
        assert current is not None
        assert "每次网络尝试最多 3 秒" in current["items"][0]["progress"]["detail"]
        assert "连续无进度最多 30 秒" in current["items"][0]["progress"]["detail"]

        paused = client.post(f"/api/v1/console/comparison-batches/{batch_id}/pause")
        assert paused.status_code == 200
        assert paused.json()["batch"]["status"] == "paused"
        assert paused.json()["items"][0]["status"] == "paused"
        assert paused.json()["items"][0]["progress"]["stage"] == "paused"

        restored = client.get("/api/v1/console/comparison-batches/active").json()
        assert restored["batch"]["id"] == batch_id
        assert restored["batch"]["status"] == "paused"

        resumed = client.post(f"/api/v1/console/comparison-batches/{batch_id}/resume")
        assert resumed.status_code == 200
        deadline = time.monotonic() + 2
        completed = None
        while time.monotonic() < deadline:
            completed = client.get(f"/api/v1/console/comparison-batches/{batch_id}").json()
            if completed["batch"]["status"] == "completed":
                break
            time.sleep(0.01)
        assert completed is not None
        assert completed["batch"]["status"] == "completed"
        assert completed["items"][0]["status"] == "completed"
        assert attempts == 2


def test_console_discovers_models_without_returning_key(tmp_path: Path, monkeypatch) -> None:
    secret = "sk-discovery-secret"

    async def fake_discover(endpoint, *, timeout_seconds):
        assert endpoint.reveal_api_key() == secret
        assert timeout_seconds > 0
        return {
            "base_url": str(endpoint.base_url),
            "models_url": f"{str(endpoint.base_url).rstrip('/')}/models",
            "count": 2,
            "models": [
                {"id": "model-a", "owned_by": "vendor"},
                {"id": "model-b", "owned_by": None},
            ],
        }

    monkeypatch.setattr("relay_auditor.main.discover_models", fake_discover)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/console/models",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "api_key": secret,
                }
            },
        )
        assert response.status_code == 200
        assert [item["id"] for item in response.json()["models"]] == ["model-a", "model-b"]
        assert secret not in response.text


def test_console_reference_is_persisted_and_downloadable(tmp_path: Path, monkeypatch) -> None:
    secret = "sk-reference-secret"

    async def fake_collect(self, endpoint, *, output_path, **kwargs):
        assert kwargs["api_key"] == secret
        fingerprint = {
            "formatVersion": 1,
            "protocol": "one-token/v1",
            "model": endpoint.model,
            "cells": {},
        }
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return {
            "fingerprint": fingerprint,
            "run": {
                "adapter": {"strategy": "none", "postReasoning": False},
                "errorCount": 0,
                "splitHalfJsd": None,
                "durationMs": 1,
                "warnings": [],
            },
        }

    monkeypatch.setattr(FingerprintRunner, "collect", fake_collect)
    database_path = tmp_path / "test.db"
    evidence_dir = tmp_path / "evidence"
    settings = Settings(
        database_url=f"sqlite:///{database_path}",
        evidence_dir=evidence_dir,
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/console/references/collect",
            json={
                "reference_name": "Official A",
                "provider": "user_reference",
                "endpoint": {
                    "base_url": "https://official.example/v1",
                    "model": "model-a",
                    "api_key": secret,
                },
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
            },
        )
        assert response.status_code == 200
        body = response.json()
        artifact_id = body["artifact_id"]
        assert body["saved_reference"]["model"] == "model-a"
        assert secret not in response.text

        catalog = client.get("/api/v1/console/references").json()["items"]
        assert len(catalog) == 1
        assert catalog[0]["endpoint"]["model"] == "model-a"
        assert catalog[0]["baseline"]["metadata"]["reference_name"] == "Official A"
        assert catalog[0]["baseline"]["metadata"]["concurrency"] == 2
        assert isinstance(catalog[0]["duration_ms"], int)
        assert catalog[0]["evidence_available"] is True

        download = client.get(f"/api/v1/console/evidence/{artifact_id}")
        assert download.status_code == 200
        assert download.headers["x-evidence-sha256"] == body["artifact_sha256"]
        assert download.json()["model"] == "model-a"
        assert secret not in download.text

    with TestClient(create_app(settings)) as client:
        persisted = client.get("/api/v1/console/references").json()["items"]
        assert len(persisted) == 1
        assert persisted[0]["baseline"]["artifact_id"] == artifact_id
        baseline_id = persisted[0]["baseline"]["id"]

        deleted = client.delete(f"/api/v1/console/references/{baseline_id}")
        assert deleted.status_code == 200
        assert deleted.json() == {
            "baseline_id": baseline_id,
            "artifact_id": artifact_id,
            "status": "deleted",
            "evidence_preserved": True,
        }
        assert client.get("/api/v1/console/references").json()["items"] == []
        inactive = client.get(
            "/api/v1/console/references",
            params={"include_inactive": True},
        ).json()["items"]
        assert inactive[0]["baseline"]["status"] == "deleted"
        assert client.get(f"/api/v1/console/evidence/{artifact_id}").status_code == 200

        repeated = client.delete(f"/api/v1/console/references/{baseline_id}")
        assert repeated.status_code == 200
        assert repeated.json()["evidence_preserved"] is True

        missing = client.delete("/api/v1/console/references/missing")
        assert missing.status_code == 404

    assert secret.encode() not in database_path.read_bytes()
    assert all(
        secret not in path.read_text(encoding="utf-8") for path in evidence_dir.rglob("*.json")
    )


def test_paper_reference_drives_v2_batch_and_keeps_result_exploratory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    roles: list[str] = []

    async def fake_collect_paper(
        self,
        endpoint,
        *,
        role,
        output_path,
        samples_output_path,
        samples,
        **kwargs,
    ):
        roles.append(role)
        return _write_test_paper_collection(
            output_path,
            samples_output_path,
            model=endpoint.model,
            role=role,
            samples=samples,
        )

    async def fake_compare_paper(self, *, enrollment_path, audit_path):
        assert json.loads(enrollment_path.read_text())["plan"]["role"] == "enrollment"
        assert json.loads(audit_path.read_text())["plan"]["role"] == "audit"
        return {
            "verdict": "match",
            "meanJsd": 0.05,
            "protocolMismatch": False,
            "comparableCellCount": 40,
            "cells": [],
            "interpretation": "uncalibrated-non-decision-evidence",
            "decisionEligible": False,
        }

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    monkeypatch.setattr(FingerprintRunner, "compare_paper_fingerprints", fake_compare_paper)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        invalid_legacy = client.post(
            "/api/v1/console/references/collect",
            json={
                "reference_name": "Invalid legacy reference",
                "endpoint": {
                    "base_url": "https://official.example/v1",
                    "model": "model-a",
                },
                "cells": 40,
                "samples": 10,
                "concurrency": 2,
            },
        )
        assert invalid_legacy.status_code == 422

        reference = client.post(
            "/api/v1/console/references/collect",
            json={
                "reference_name": "Paper reference",
                "provider": "user_reference",
                "method_profile_id": "bruckner-2026-canonical40/v1",
                "endpoint": {
                    "base_url": "https://official.example/v1",
                    "model": "model-a",
                },
                "cells": 40,
                "samples": 10,
                "concurrency": 2,
            },
        )
        assert reference.status_code == 200
        saved = reference.json()["saved_reference"]
        artifact_id = saved["artifact_id"]
        assert saved["method_profile_id"] == "bruckner-2026-canonical40/v1"
        assert saved["samples_evidence_available"] is True
        catalog_item = client.get("/api/v1/console/references").json()["items"][0]
        assert catalog_item["method_profile_id"] == "bruckner-2026-canonical40/v1"
        assert catalog_item["baseline"]["metadata"]["cells"] == 40
        assert catalog_item["samples_evidence_available"] is True

        samples_download = client.get(f"/api/v1/console/evidence/{artifact_id}/samples")
        assert samples_download.status_code == 200
        assert samples_download.headers["content-type"].startswith("application/x-ndjson")
        assert samples_download.headers["x-evidence-sha256"] == saved["raw_evidence_sha256"]

        _install_fast_batch_preflight(app)
        batch_payload = _comparison_batch_payload(
            artifact_id,
            ("model-a",),
            concurrency=2,
        )
        batch_payload.update({"cells": 40, "samples": 10})
        batch_response = client.post(
            "/api/v1/console/comparison-batches",
            json=batch_payload,
        )
        assert batch_response.status_code == 202
        completed = _wait_for_comparison_batch(
            client,
            batch_response.json()["batch"]["id"],
        )
        assert completed["batch"]["cells"] == 40
        item = completed["items"][0]
        assert item["method_profile_id"] == "bruckner-2026-canonical40/v1"
        assert item["verdict"] == "unverifiable"
        assert item["response"]["result"]["decision"]["decisionEligible"] is False
        assert item["response"]["result"]["interpretation"] == (
            "uncalibrated-non-decision-evidence"
        )
        target_samples = client.get(f"/api/v1/console/evidence/{item['audit_id']}/samples")
        assert target_samples.status_code == 200
        assert item["samples_evidence_available"] is True
        assert item["raw_evidence_sha256"] == target_samples.headers["x-evidence-sha256"]

    assert roles == ["enrollment", "audit"]


def test_comparison_batch_rejects_mixed_legacy_and_paper_references(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def fake_collect_paper(
        self,
        endpoint,
        *,
        role,
        output_path,
        samples_output_path,
        samples,
        **kwargs,
    ):
        return _write_test_paper_collection(
            output_path,
            samples_output_path,
            model=endpoint.model,
            role=role,
            samples=samples,
        )

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        paper = client.post(
            "/api/v1/console/references/collect",
            json={
                "reference_name": "Paper reference",
                "method_profile_id": "bruckner-2026-canonical40/v1",
                "endpoint": {
                    "base_url": "https://official.example/v1",
                    "model": "model-a",
                },
                "cells": 40,
                "samples": 10,
                "concurrency": 2,
            },
        ).json()["artifact_id"]
        legacy = "00000000-0000-0000-0000-000000000079"
        _register_reference(
            app,
            legacy,
            {
                "formatVersion": 1,
                "protocol": "one-token/v1",
                "model": "model-a",
                "cells": {},
            },
        )
        legacy_oversized = _comparison_batch_payload(legacy, ("legacy-target",))
        legacy_oversized["cells"] = 40
        legacy_response = client.post(
            "/api/v1/console/comparison-batches",
            json=legacy_oversized,
        )
        assert legacy_response.status_code == 409
        assert "supports at most 16 cells" in legacy_response.json()["detail"]

        payload = _comparison_batch_payload(paper, ("paper-target",))
        legacy_item = _comparison_batch_payload(legacy, ("legacy-target",))["items"][0]
        payload["items"].append(legacy_item)
        response = client.post("/api/v1/console/comparison-batches", json=payload)
        assert response.status_code == 409
        assert "cannot mix One Token method profiles" in response.json()["detail"]


def test_paper_batch_pause_interrupts_and_resume_restarts_current_audit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    audit_attempts = 0

    async def fake_collect_paper(
        self,
        endpoint,
        *,
        role,
        output_path,
        samples_output_path,
        samples,
        progress_callback=None,
        cancel_event=None,
        idle_timeout_seconds=None,
        **kwargs,
    ):
        nonlocal audit_attempts
        if role == "audit":
            audit_attempts += 1
            assert callable(progress_callback)
            assert cancel_event is not None
            assert idle_timeout_seconds == 30
            if audit_attempts == 1:
                progress_callback(
                    {
                        "stage": "sampling",
                        "done": 1,
                        "total": 400,
                        "errors": 0,
                        "detail": "paper sample 1/400",
                    }
                )
                await cancel_event.wait()
                raise FingerprintPausedError("paper batch paused")
        return _write_test_paper_collection(
            output_path,
            samples_output_path,
            model=endpoint.model,
            role=role,
            samples=samples,
        )

    async def fake_compare_paper(self, *, enrollment_path, audit_path):
        return {
            "verdict": "match",
            "meanJsd": 0.05,
            "protocolMismatch": False,
            "comparableCellCount": 40,
            "cells": [],
        }

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    monkeypatch.setattr(FingerprintRunner, "compare_paper_fingerprints", fake_compare_paper)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        reference_id = client.post(
            "/api/v1/console/references/collect",
            json={
                "reference_name": "Paper reference",
                "method_profile_id": "bruckner-2026-canonical40/v1",
                "endpoint": {
                    "base_url": "https://official.example/v1",
                    "model": "model-a",
                },
                "cells": 40,
                "samples": 10,
                "concurrency": 2,
            },
        ).json()["artifact_id"]
        payload = _comparison_batch_payload(reference_id, ("model-a",), concurrency=2)
        payload.update({"cells": 40, "samples": 10})
        started = client.post("/api/v1/console/comparison-batches", json=payload)
        assert started.status_code == 202
        batch_id = started.json()["batch"]["id"]

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/console/comparison-batches/{batch_id}").json()
            progress = current["items"][0].get("progress") or {}
            if progress.get("stage") == "sampling":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("paper audit did not enter sampling")

        paused = client.post(f"/api/v1/console/comparison-batches/{batch_id}/pause")
        assert paused.status_code == 200
        assert paused.json()["batch"]["status"] == "paused"
        assert paused.json()["items"][0]["status"] == "paused"

        resumed = client.post(f"/api/v1/console/comparison-batches/{batch_id}/resume")
        assert resumed.status_code == 200
        completed = _wait_for_comparison_batch(client, batch_id)
        assert completed["items"][0]["status"] == "completed"
        assert completed["items"][0]["verdict"] == "unverifiable"

    assert audit_attempts == 2


async def test_fingerprint_runner_passes_ephemeral_key_only_in_child_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    captured: dict[str, object] = {}

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        captured["arguments"] = arguments
        captured["environment"] = environment
        captured["accepted_exit_codes"] = accepted_exit_codes
        return {"fingerprint": {}}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    secret = "sk-test-must-never-be-persisted"
    await runner.collect(
        EndpointSpec(base_url="https://official.example/v1", model="model-a"),
        output_path=tmp_path / "fingerprint.json",
        cells=4,
        samples=15,
        concurrency=2,
        api_key=secret,
    )

    arguments = captured["arguments"]
    environment = captured["environment"]
    assert isinstance(arguments, list)
    assert isinstance(environment, dict)
    assert secret not in arguments
    assert secret in environment.values()
    env_index = arguments.index("--api-key-env") + 1
    assert environment[arguments[env_index]] == secret


def test_console_key_is_redacted_from_errors_and_audit_records(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-console-secret-value"

    async def fail_collect(self, endpoint, **kwargs):
        assert kwargs["api_key"] == secret
        raise RuntimeError(f"provider rejected bearer {secret}")

    monkeypatch.setattr(FingerprintRunner, "collect", fail_collect)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/console/fingerprints/collect",
            json={
                "endpoint": {
                    "base_url": "https://official.example/v1",
                    "model": "model-a",
                    "api_key": secret,
                },
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
            },
        )
        assert response.status_code == 502
        assert secret not in response.text
        assert response.json()["detail"] == "credential_echo_detected"

        audits = client.get("/api/v1/audits").json()["items"]
        assert len(audits) == 1
        assert secret not in str(audits[0])
        assert "credential_echo_detected" in str(audits[0])


def test_console_verify_preserves_target_fingerprint_after_processing_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": "model-a",
        "samplesPerCell": 15,
        "postReasoning": False,
        "cells": {},
    }

    async def fail_after_write(self, endpoint, *, output_path, **kwargs):
        output_path.write_text(json.dumps(target), encoding="utf-8")
        raise RuntimeError("simulated post-sampling parse failure")

    monkeypatch.setattr(FingerprintRunner, "verify", fail_after_write)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    reference_id = "00000000-0000-0000-0000-000000000099"
    with TestClient(app) as client:
        _register_reference(app, reference_id, target)
        response = client.post(
            "/api/v1/console/fingerprints/verify",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "model-a",
                },
                "reference_artifact_id": reference_id,
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
            },
        )
        assert response.status_code == 502
        audit = client.get("/api/v1/audits").json()["items"][0]
        assert audit["status"] == "failed"
        assert audit["artifact_sha256"]
        preserved = client.get(f"/api/v1/console/evidence/{audit['id']}")
        assert preserved.status_code == 200
        assert preserved.json()["model"] == "model-a"


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


def test_direct_verify_persists_operational_verdict_and_raw_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000081"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "model-a",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", {
            "verdict": "match",
            "meanJsd": 0.12,
            "reference": fingerprint,
            "target": {"fingerprint": fingerprint},
            "comparison": {
                "verdict": "match",
                "meanJsd": 0.12,
                "comparableCellCount": 4,
                "protocolMismatch": False,
                "cells": [],
            },
            "warnings": [],
        }

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        response = client.post(
            "/api/v1/fingerprints/verify",
            json={
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": "model-a",
                },
                "reference_artifact_id": reference_id,
                "cells": 4,
                "samples": 15,
                "concurrency": 2,
            },
        )

        assert response.status_code == 200
        body = response.json()
        result = body["result"]
        assert body["verdict"] == "unverifiable"
        assert result["verdict"] == "unverifiable"
        assert result["verdictSemantics"] == "operational-v1"
        assert result["legacyVerdict"] == "match"
        assert result["comparison"]["verdict"] == "match"
        assert result["decision"]["operationalVerdict"] == "unverifiable"
        assert result["decision"]["status"] == "uncalibrated"

        run = app.state.database.get_run(body["audit_id"])
        assert run is not None
        assert run.verdict == "unverifiable"
        artifact = app.state.evidence.read_json(Path(run.artifact_path))
        assert artifact["verdict"] == "unverifiable"
        assert artifact["verdictSemantics"] == "operational-v1"
        assert artifact["legacyVerdict"] == "match"
        assert artifact["comparison"]["verdict"] == "match"


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


def test_endpoint_and_baseline_registry(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        endpoint_response = client.post(
            "/api/v1/endpoints",
            json={
                "name": "mock-official",
                "provider": "local",
                "base_url": "http://127.0.0.1:8000/mock/v1",
                "model": "reference-model",
            },
        )
        assert endpoint_response.status_code == 201
        endpoint_id = endpoint_response.json()["id"]

        duplicate = client.post(
            "/api/v1/endpoints",
            json={
                "name": "mock-official",
                "provider": "local",
                "base_url": "http://127.0.0.1:8000/mock/v1",
                "model": "reference-model",
            },
        )
        assert duplicate.status_code == 409

        artifact_id = "00000000-0000-0000-0000-000000000010"
        artifact = app.state.evidence.write_json("tokenizers", artifact_id, {})
        app.state.database.create_run(
            audit_id=artifact_id,
            detector="tokenizer_collect",
            target_base_url="http://127.0.0.1:8000/mock/v1",
            model="reference-model",
        )
        app.state.database.finish_run(
            artifact_id,
            status="completed",
            verdict="recorded",
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
        )
        baseline_response = client.post(
            "/api/v1/baselines",
            json={
                "endpoint_id": endpoint_id,
                "detector": "tokenizer",
                "artifact_id": artifact_id,
                "valid_days": 14,
                "metadata": {"temperature": 0},
            },
        )
        assert baseline_response.status_code == 201
        assert baseline_response.json()["artifact_id"] == artifact_id

        baselines = client.get("/api/v1/baselines", params={"endpoint_id": endpoint_id})
        assert baselines.status_code == 200
        assert len(baselines.json()["items"]) == 1

        second_artifact_id = "00000000-0000-0000-0000-000000000011"
        second_artifact = app.state.evidence.write_json("tokenizers", second_artifact_id, {})
        app.state.database.create_run(
            audit_id=second_artifact_id,
            detector="tokenizer_collect",
            target_base_url="http://127.0.0.1:8000/mock/v1",
            model="reference-model",
        )
        app.state.database.finish_run(
            second_artifact_id,
            status="completed",
            verdict="recorded",
            artifact_path=str(second_artifact.path),
            artifact_sha256=second_artifact.sha256,
        )
        replacement = client.post(
            "/api/v1/baselines",
            json={
                "endpoint_id": endpoint_id,
                "detector": "tokenizer",
                "artifact_id": second_artifact_id,
            },
        )
        assert replacement.status_code == 201

        statuses = {
            item["artifact_id"]: item["status"]
            for item in client.get(
                "/api/v1/baselines",
                params={"endpoint_id": endpoint_id},
            ).json()["items"]
        }
        assert statuses[artifact_id] == "superseded"
        assert statuses[second_artifact_id] == "active"


def _comparison_result(model: str, *, verdict: str = "match") -> dict[str, object]:
    mean_jsd = {"match": 0.01, "uncertain": 0.15, "mismatch": 0.4}[verdict]
    return {
        "verdict": verdict,
        "meanJsd": mean_jsd,
        "reference": {"model": "official-reference"},
        "target": {
            "model": model,
            "durationMs": 100,
            "errorCount": 0,
            "splitHalfJsd": 0.01,
            "warnings": [],
        },
        "comparison": {
            "verdict": verdict,
            "meanJsd": mean_jsd,
            "comparableCellCount": 4,
            "cells": [],
        },
        "warnings": [],
    }


def _wait_for_comparison_batch(
    client: TestClient,
    batch_id: str,
    *terminal_statuses: str,
    timeout_seconds: float = 3,
) -> dict[str, object]:
    expected = set(terminal_statuses or ("completed",))
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, object] | None = None
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/console/comparison-batches/{batch_id}")
        assert response.status_code == 200
        latest = response.json()
        if latest["batch"]["status"] in expected:
            return latest
        time.sleep(0.01)
    raise AssertionError(f"batch did not reach {expected}: {latest}")


def _comparison_batch_payload(
    reference_id: str,
    models: tuple[str, ...],
    *,
    concurrency: int = 4,
    concurrency_mode: str = "fixed",
    station_name: str = "Relay Test",
) -> dict[str, object]:
    return {
        "items": [
            {
                "endpoint": {
                    "base_url": "https://relay.example/v1",
                    "model": model,
                },
                "reference_artifact_id": reference_id,
                "station_name": station_name,
                "reference_name": "Official Test",
                "reference_model": "official-reference",
            }
            for model in models
        ],
        "cells": 4,
        "samples": 15,
        "concurrency": concurrency,
        "concurrency_mode": concurrency_mode,
        "request_timeout_seconds": 3,
        "model_timeout_seconds": 30,
    }


def test_batch_preflight_failure_skips_sampling_and_continues(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000251"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }
    verification_calls: list[str] = []

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        verification_calls.append(endpoint.model)
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    async def fake_preflight(endpoint, *, api_key, timeout_seconds):
        if endpoint.model == "unavailable":
            raise FingerprintPreflightError(
                "预检失败：HTTP 410，上游路由或服务已停用；未开始正式采样",
                status_code=410,
                error_kind="http",
            )
        return {
            "statusCode": 200,
            "latencyMs": 1,
            "hasContent": True,
            "requestId": None,
            "normalizedBaseUrl": str(endpoint.base_url).rstrip("/"),
            "retries": 0,
        }

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    app.state.batches.preflight = fake_preflight
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("unavailable", "healthy")),
        )
        completed = _wait_for_comparison_batch(client, created.json()["batch"]["id"], "completed")

    items = {item["target_model"]: item for item in completed["items"]}
    assert verification_calls == ["healthy"]
    assert items["unavailable"]["status"] == "failed"
    assert "HTTP 410" in items["unavailable"]["progress"]["detail"]
    assert items["healthy"]["status"] == "completed"
    healthy = items["healthy"]
    assert healthy["verdict"] == "unverifiable"
    assert healthy["response"]["verdict"] == "unverifiable"
    result = healthy["response"]["result"]
    assert result["verdict"] == "unverifiable"
    assert result["verdictSemantics"] == "operational-v1"
    assert result["legacyVerdict"] == "match"
    assert result["comparison"]["verdict"] == "match"
    assert result["decision"]["operationalVerdict"] == "unverifiable"

    run = app.state.database.get_run(healthy["audit_id"])
    assert run is not None
    assert run.verdict == "unverifiable"
    artifact = app.state.evidence.read_json(Path(run.artifact_path))
    assert artifact["verdict"] == "unverifiable"
    assert artifact["verdictSemantics"] == "operational-v1"
    assert artifact["legacyVerdict"] == "match"
    assert artifact["comparison"]["verdict"] == "match"


def test_transient_preflight_is_cooled_down_and_requeued_behind_other_station(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000258"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }
    preflight_calls: list[str] = []
    verification_calls: list[str] = []
    healthy_started = threading.Event()
    release_healthy = threading.Event()

    async def fake_preflight(endpoint, *, api_key, timeout_seconds):
        preflight_calls.append(endpoint.model)
        if endpoint.model == "limited" and preflight_calls.count("limited") == 1:
            raise FingerprintPreflightError(
                "预检失败：HTTP 429，中转站限流；未开始正式采样",
                transient=True,
                status_code=429,
                retry_after_seconds=0.05,
                error_kind="http",
            )
        return {
            "statusCode": 200,
            "latencyMs": 1,
            "hasContent": True,
            "requestId": None,
            "normalizedBaseUrl": str(endpoint.base_url).rstrip("/"),
            "retries": 0,
        }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        verification_calls.append(endpoint.model)
        if endpoint.model == "healthy":
            healthy_started.set()
            while not release_healthy.is_set():
                await asyncio.sleep(0.005)
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    app.state.batches.preflight = fake_preflight
    app.state.batches.preflight_retry_base_seconds = 0.01
    app.state.batches.preflight_retry_cap_seconds = 0.01
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        payload = _comparison_batch_payload(
            reference_id,
            ("limited", "same-station", "healthy"),
        )
        payload["items"][0]["station_name"] = "Relay A"
        payload["items"][1]["station_name"] = "Relay A"
        payload["items"][2]["station_name"] = "Relay B"
        created = client.post("/api/v1/console/comparison-batches", json=payload)
        batch_id = created.json()["batch"]["id"]

        started = healthy_started.wait(2)
        if not started:
            release_healthy.set()
        assert started
        current = client.get(f"/api/v1/console/comparison-batches/{batch_id}").json()
        items = {item["target_model"]: item for item in current["items"]}
        waiting = items["limited"]
        shared_waiting = items["same-station"]
        release_healthy.set()
        assert waiting["status"] == "queued"
        assert waiting["progress"]["stage"] == "waiting_retry"
        assert "冷却 0.05 秒后自动重试" in waiting["progress"]["detail"]
        assert "Retry-After 0.05 秒" in waiting["progress"]["detail"]
        assert shared_waiting["progress"]["stage"] == "waiting_retry"
        assert "共享冷却" in shared_waiting["progress"]["detail"]
        assert preflight_calls == ["limited", "healthy"]

        completed = _wait_for_comparison_batch(client, batch_id, "completed")

    assert preflight_calls == ["limited", "healthy", "limited", "same-station"]
    assert verification_calls == ["healthy", "limited", "same-station"]
    limited = next(item for item in completed["items"] if item["target_model"] == "limited")
    preflight_result = limited["response"]["result"]["execution"]["preflight"]
    assert preflight_result["schedulerAttempts"] == 2
    assert preflight_result["cooldownSeconds"] == 0.05
    assert preflight_result["transientFailures"][0]["statusCode"] == 429


def test_preflight_cooldown_is_interruptible_by_batch_cancel(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000259"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }

    async def always_limited(endpoint, *, api_key, timeout_seconds):
        raise FingerprintPreflightError(
            "预检失败：HTTP 429，中转站限流；未开始正式采样",
            transient=True,
            status_code=429,
            retry_after_seconds=20,
            error_kind="http",
        )

    async def unexpected_verify(self, endpoint, **kwargs):
        raise AssertionError("sampling must not start during preflight cooldown")

    monkeypatch.setattr(FingerprintRunner, "verify", unexpected_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    app.state.batches.preflight = always_limited
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("limited",)),
        )
        batch_id = created.json()["batch"]["id"]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/console/comparison-batches/{batch_id}").json()
            if current["items"][0]["progress"]["stage"] == "waiting_retry":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("task never entered preflight cooldown")

        started = time.monotonic()
        canceled = client.post(f"/api/v1/console/comparison-batches/{batch_id}/cancel")
        assert canceled.status_code == 200
        completed = _wait_for_comparison_batch(client, batch_id, "canceled")
        assert time.monotonic() - started < 1

    assert completed["items"][0]["status"] == "canceled"


def test_transient_preflight_stops_only_after_bounded_retry_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000260"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }
    preflight_calls = 0

    async def always_unavailable(endpoint, *, api_key, timeout_seconds):
        nonlocal preflight_calls
        preflight_calls += 1
        raise FingerprintPreflightError(
            "预检失败：HTTP 503，中转站上游服务暂不可用；未开始正式采样",
            transient=True,
            status_code=503,
            error_kind="http",
        )

    async def unexpected_verify(self, endpoint, **kwargs):
        raise AssertionError("sampling must not start when every preflight fails")

    monkeypatch.setattr(FingerprintRunner, "verify", unexpected_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    app.state.batches.preflight = always_unavailable
    app.state.batches.preflight_max_attempts = 3
    app.state.batches.preflight_retry_base_seconds = 0
    app.state.batches.preflight_retry_cap_seconds = 0
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("unavailable",)),
        )
        completed = _wait_for_comparison_batch(
            client,
            created.json()["batch"]["id"],
            "completed",
        )

    assert preflight_calls == 3
    item = completed["items"][0]
    assert item["status"] == "failed"
    assert "已达到 3 次预检上限" in item["progress"]["detail"]


def test_batch_slow_plan_continues_while_progress_watchdog_is_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000252"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "slow-model",
        "cells": {},
    }
    verification_calls: list[str] = []

    async def fake_verify(self, endpoint, **kwargs):
        verification_calls.append(endpoint.model)
        assert kwargs["idle_timeout_seconds"] == 30
        kwargs["progress_callback"](
            {
                "stage": "sampling",
                "done": 1,
                "total": 60,
                "errors": 0,
                "detail": None,
                "lastErrorKind": None,
                "lastHttpStatus": 200,
                "retrying": False,
            }
        )
        kwargs["output_path"].write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app, latency_ms=5000)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("slow-model",), concurrency=2),
        )
        completed = _wait_for_comparison_batch(client, created.json()["batch"]["id"], "completed")

    assert verification_calls == ["slow-model"]
    item = completed["items"][0]
    assert item["status"] == "completed"


def test_sampling_retry_diagnostics_are_persisted_in_chinese(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000256"
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "retry-model",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        kwargs["progress_callback"](
            {
                "stage": "sampling",
                "done": 2,
                "total": 60,
                "errors": 0,
                "detail": "retry 1/2 in 5000ms",
                "lastErrorKind": "http",
                "lastHttpStatus": 503,
                "retrying": True,
            }
        )
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("retry-model",)),
        )
        completed = _wait_for_comparison_batch(client, created.json()["batch"]["id"], "completed")

    detail = completed["items"][0]["progress"]["detail"]
    assert detail == "正在重试 1/2 · HTTP 503 · 等待 5000ms"


def test_same_priority_tasks_round_robin_between_stations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000253"
    calls: list[str] = []
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        calls.append(endpoint.model)
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        items = []
        for station, model in (
            ("Relay A", "a-1"),
            ("Relay A", "a-2"),
            ("Relay B", "b-1"),
            ("Relay B", "b-2"),
        ):
            item = _comparison_batch_payload(reference_id, (model,))["items"][0]
            item["station_name"] = station
            items.append(item)
        payload = _comparison_batch_payload(reference_id, ("placeholder",))
        payload["items"] = items
        created = client.post("/api/v1/console/comparison-batches", json=payload)
        _wait_for_comparison_batch(client, created.json()["batch"]["id"], "completed")

    assert calls == ["a-1", "b-1", "a-2", "b-2"]


def test_cancel_running_item_then_prioritized_queued_item_runs_next(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000201"
    calls: list[str] = []
    first_started = threading.Event()
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        calls.append(endpoint.model)
        if endpoint.model == "first":
            first_started.set()
            while not kwargs["cancel_event"].is_set():
                await asyncio.sleep(0.01)
            raise FingerprintPausedError("canceled by test")
        output_path.write_text(
            json.dumps({**fingerprint, "model": endpoint.model}),
            encoding="utf-8",
        )
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("first", "second", "third")),
        )
        assert created.status_code == 202
        batch_id = created.json()["batch"]["id"]
        items = {item["target_model"]: item for item in created.json()["items"]}
        assert first_started.wait(2)

        prioritized = client.post(
            f"/api/v1/console/comparison-batches/{batch_id}/items/"
            f"{items['third']['audit_id']}/prioritize"
        )
        assert prioritized.status_code == 200
        prioritized_items = {item["target_model"]: item for item in prioritized.json()["items"]}
        assert prioritized_items["third"]["priority"] > prioritized_items["second"]["priority"]

        canceled = client.post(
            f"/api/v1/console/comparison-batches/{batch_id}/items/"
            f"{items['first']['audit_id']}/cancel"
        )
        assert canceled.status_code == 200
        completed = _wait_for_comparison_batch(client, batch_id, "completed")

        assert calls == ["first", "third", "second"]
        final_items = {item["target_model"]: item for item in completed["items"]}
        assert final_items["first"]["status"] == "canceled"
        assert final_items["first"]["verdict"] == "canceled"
        assert final_items["third"]["status"] == "completed"
        assert final_items["second"]["status"] == "completed"
        assert all(item["status"] != "failed" for item in completed["items"])


def test_cancel_batch_marks_running_and_queued_items_canceled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000202"
    calls: list[str] = []
    first_started = threading.Event()
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }

    async def fake_verify(self, endpoint, **kwargs):
        calls.append(endpoint.model)
        first_started.set()
        while not kwargs["cancel_event"].is_set():
            await asyncio.sleep(0.01)
        raise FingerprintPausedError("batch canceled by test")

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("first", "second", "third")),
        )
        assert created.status_code == 202
        batch_id = created.json()["batch"]["id"]
        assert first_started.wait(2)

        canceled = client.post(f"/api/v1/console/comparison-batches/{batch_id}/cancel")
        assert canceled.status_code == 200
        finished = _wait_for_comparison_batch(client, batch_id, "canceled")

        assert calls == ["first"]
        assert finished["batch"]["completed_items"] == 3
        assert {item["status"] for item in finished["items"]} == {"canceled"}
        assert {item["verdict"] for item in finished["items"]} == {"canceled"}


def test_cancel_running_item_preserves_partial_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000254"
    started = threading.Event()
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "partial-model",
        "partial": True,
        "completedSamples": 3,
        "expectedSamples": 60,
        "errorCount": 1,
        "incompleteReason": "canceled",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        started.set()
        while not kwargs["cancel_event"].is_set():
            await asyncio.sleep(0.01)
        raise FingerprintPausedError("canceled by test")

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("partial-model",)),
        )
        batch_id = created.json()["batch"]["id"]
        audit_id = created.json()["items"][0]["audit_id"]
        assert started.wait(2)
        canceled = client.post(
            f"/api/v1/console/comparison-batches/{batch_id}/items/{audit_id}/cancel"
        )
        assert canceled.status_code == 200
        finished = _wait_for_comparison_batch(client, batch_id, "canceled")

    item = finished["items"][0]
    run = app.state.database.get_run(audit_id)
    assert item["status"] == "canceled"
    assert item["evidence_available"] is True
    assert item["evidence_state"] == "partial"
    assert item["partial_evidence"] is True
    assert item["partial_sample_count"] == 3
    assert item["partial_expected_samples"] == 60
    assert item["partial_error_count"] == 1
    assert run is not None and run.artifact_path
    assert run.artifact_sha256 == app.state.evidence.digest_file(Path(run.artifact_path))


def test_queued_task_duration_starts_when_sampling_really_begins(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000255"
    first_started = threading.Event()
    release_first = threading.Event()
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        if endpoint.model == "first":
            first_started.set()
            while not release_first.is_set():
                await asyncio.sleep(0.01)
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        created = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(reference_id, ("first", "second")),
        )
        batch_id = created.json()["batch"]["id"]
        second_id = next(
            item["audit_id"] for item in created.json()["items"] if item["target_model"] == "second"
        )
        assert first_started.wait(2)
        queued_started_at = app.state.database.get_run(second_id).started_at
        time.sleep(0.08)
        release_first.set()
        _wait_for_comparison_batch(client, batch_id, "completed")

    second = app.state.database.get_run(second_id)
    assert second is not None and second.completed_at is not None
    assert (second.started_at - queued_started_at).total_seconds() >= 0.05
    assert (second.completed_at - second.started_at).total_seconds() < 0.2


def test_auto_concurrency_ignores_tampered_history_then_trials_four(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000203"
    selected: list[int] = []
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "adaptive-model",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        selected.append(kwargs["concurrency"])
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        effective: list[int] = []
        reasons: list[str] = []
        first_artifact: Path | None = None
        first_artifact_bytes: bytes | None = None
        for _ in range(3):
            created = client.post(
                "/api/v1/console/comparison-batches",
                json=_comparison_batch_payload(
                    reference_id,
                    ("adaptive-model",),
                    concurrency=8,
                    concurrency_mode="auto",
                ),
            )
            assert created.status_code == 202
            batch_id = created.json()["batch"]["id"]
            completed = _wait_for_comparison_batch(client, batch_id, "completed")
            options = completed["items"][0]["task_options"]
            effective.append(options["effective_concurrency"])
            reasons.append(options["concurrency_reason"])
            if first_artifact is None:
                run = app.state.database.get_run(completed["items"][0]["audit_id"])
                assert run is not None and run.artifact_path
                first_artifact = Path(run.artifact_path)
                first_artifact_bytes = first_artifact.read_bytes()

        assert first_artifact is not None and first_artifact_bytes is not None
        first_artifact.write_text(
            json.dumps({"target": {"errorCount": 0, "durationMs": 1}}),
            encoding="utf-8",
        )
        corrupted = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(
                reference_id,
                ("adaptive-model",),
                concurrency=8,
                concurrency_mode="auto",
            ),
        )
        corrupted_completed = _wait_for_comparison_batch(
            client,
            corrupted.json()["batch"]["id"],
            "completed",
        )
        corrupted_options = corrupted_completed["items"][0]["task_options"]
        effective.append(corrupted_options["effective_concurrency"])
        reasons.append(corrupted_options["concurrency_reason"])

        first_artifact.write_bytes(first_artifact_bytes)
        restored = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(
                reference_id,
                ("adaptive-model",),
                concurrency=8,
                concurrency_mode="auto",
            ),
        )
        restored_completed = _wait_for_comparison_batch(
            client,
            restored.json()["batch"]["id"],
            "completed",
        )
        restored_options = restored_completed["items"][0]["task_options"]
        effective.append(restored_options["effective_concurrency"])
        reasons.append(restored_options["concurrency_reason"])

        assert selected == [2, 2, 2, 1, 4]
        assert effective == selected
        assert "试探" in reasons[-1]

        other_station = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(
                reference_id,
                ("adaptive-model",),
                concurrency=8,
                concurrency_mode="auto",
                station_name="Relay Other",
            ),
        )
        other_completed = _wait_for_comparison_batch(
            client, other_station.json()["batch"]["id"], "completed"
        )
        assert selected[-1] == 2
        assert other_completed["items"][0]["task_options"]["effective_concurrency"] == 2
        assert other_completed["items"][0]["task_options"]["concurrency_reason"].startswith(
            "暂无该中转站"
        )


def test_auto_concurrency_treats_tampered_history_as_failed_observation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "00000000-0000-0000-0000-000000000215"
    selected: list[int] = []
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "adaptive-model",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        selected.append(kwargs["concurrency"])
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return "match", _comparison_result(endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, reference_id, fingerprint)
        first = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(
                reference_id,
                ("adaptive-model",),
                concurrency=8,
                concurrency_mode="auto",
            ),
        )
        completed = _wait_for_comparison_batch(client, first.json()["batch"]["id"])
        prior = app.state.database.get_run(completed["items"][0]["audit_id"])
        assert prior is not None and prior.artifact_path
        prior_path = Path(prior.artifact_path)
        prior_path.write_bytes(prior_path.read_bytes() + b"\n")

        second = client.post(
            "/api/v1/console/comparison-batches",
            json=_comparison_batch_payload(
                reference_id,
                ("adaptive-model",),
                concurrency=8,
                concurrency_mode="auto",
            ),
        )
        second_completed = _wait_for_comparison_batch(
            client,
            second.json()["batch"]["id"],
        )

    assert selected == [2, 1]
    assert "失败" in second_completed["items"][0]["task_options"]["concurrency_reason"]


def test_uncertain_and_mismatch_identify_models_from_local_references_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    original_reference_id = "00000000-0000-0000-0000-000000000204"
    trigger_verdicts = ["uncertain", "mismatch"]
    verification_calls: list[str] = []
    comparison_calls: list[str] = []
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "postReasoning": False,
        "model": "target-model",
        "cells": {},
    }

    async def fake_verify(self, endpoint, *, output_path, **kwargs):
        verdict = trigger_verdicts[len(verification_calls)]
        verification_calls.append(verdict)
        output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
        return verdict, _comparison_result(endpoint.model, verdict=verdict)

    async def fake_compare(self, *, reference_path, target_path):
        assert target_path.is_file()
        reference = json.loads(reference_path.read_text(encoding="utf-8"))
        comparison_calls.append(reference["model"])
        mean_jsd = reference["testMeanJsd"]
        return {
            "verdict": "match" if mean_jsd < 0.1 else "mismatch",
            "meanJsd": mean_jsd,
            "comparableCellCount": 4,
            "cells": [],
        }

    monkeypatch.setattr(FingerprintRunner, "verify", fake_verify)
    monkeypatch.setattr(FingerprintRunner, "compare_fingerprints", fake_compare)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )
    app = create_app(settings)
    _install_fast_batch_preflight(app)
    with TestClient(app) as client:
        _register_reference(app, original_reference_id, fingerprint)
        now = datetime.now(UTC)
        references = (
            ("00000000-0000-0000-0000-000000000211", "candidate-model", 0.01),
            ("00000000-0000-0000-0000-000000000212", "candidate-model", 0.03),
            ("00000000-0000-0000-0000-000000000213", "distant-model", 0.3),
        )
        for index, (artifact_id, model, mean_jsd) in enumerate(references, start=1):
            base_url = f"https://official-{index}.example/v1"
            reference_path = app.state.evidence.fingerprint_path(artifact_id)
            reference_path.write_text(
                json.dumps({**fingerprint, "model": model, "testMeanJsd": mean_jsd}),
                encoding="utf-8",
            )
            app.state.database.create_run(
                audit_id=artifact_id,
                detector="one_token_collect",
                target_base_url=base_url,
                model=model,
            )
            app.state.database.finish_run(
                artifact_id,
                status="completed",
                verdict="recorded",
                artifact_path=str(reference_path),
                artifact_sha256=app.state.evidence.digest_file(reference_path),
            )
            endpoint_id = f"00000000-0000-0000-0000-00000000022{index}"
            app.state.database.create_endpoint(
                endpoint_id=endpoint_id,
                name=f"Local reference {index}",
                provider="local_test",
                base_url=base_url,
                model=model,
                protocol="openai_chat",
                api_key_env=None,
            )
            app.state.database.create_baseline(
                baseline_id=f"00000000-0000-0000-0000-00000000023{index}",
                endpoint_id=endpoint_id,
                detector="one_token",
                artifact_id=artifact_id,
                valid_from=now,
                expires_at=now + timedelta(days=1),
                metadata={"reference_name": f"Local reference {index}"},
            )

        for expected_verdict in trigger_verdicts:
            created = client.post(
                "/api/v1/console/comparison-batches",
                json=_comparison_batch_payload(
                    original_reference_id,
                    ("target-model",),
                    concurrency=2,
                ),
            )
            assert created.status_code == 202
            batch_id = created.json()["batch"]["id"]
            completed = _wait_for_comparison_batch(client, batch_id, "completed")
            item = completed["items"][0]
            identification = item["identification"]

            assert item["verdict"] == "unverifiable"
            assert item["response"]["result"]["verdict"] == "unverifiable"
            assert item["response"]["result"]["legacyVerdict"] == expected_verdict
            assert item["response"]["result"]["decision"]["status"] == "uncalibrated"
            assert identification["triggerVerdict"] == expected_verdict
            assert identification["decisionBasis"] == "legacy_exploratory"
            assert identification["networkRequests"] == 0
            assert identification["candidateCount"] == 2
            assert identification["closestCandidate"]["referenceModel"] == "candidate-model"
            assert identification["closestCandidate"]["supportCount"] == 2
            assert abs(identification["closestCandidate"]["medianMeanJsd"] - 0.02) < 1e-9

        assert verification_calls == trigger_verdicts
        assert len(comparison_calls) == 6
        assert comparison_calls.count("candidate-model") == 4
        assert comparison_calls.count("distant-model") == 2
