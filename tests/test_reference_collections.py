import asyncio
import hashlib
import json
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from relay_auditor.config import Settings
from relay_auditor.detectors.fingerprint import FingerprintPausedError, FingerprintRunner
from relay_auditor.main import create_app


def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        evidence_dir=tmp_path / "evidence",
        fingerprint_cli_path=Path("llm-fingerprint-detector/dist/cli.js"),
    )


def request_payload(
    models: list[str],
    *,
    method_profile_id: str = "legacy-one-token/v1",
    cells: int = 4,
    concurrency: int = 4,
    concurrency_mode: str = "auto",
    api_key: str | None = None,
) -> dict[str, object]:
    endpoint: dict[str, object] = {"base_url": "https://official.example/v1"}
    if api_key:
        endpoint["api_key"] = api_key
    return {
        "reference_name": "Trusted API",
        "provider": "user_reference",
        "endpoint": endpoint,
        "models": models,
        "method_profile_id": method_profile_id,
        "cells": cells,
        "samples": 10,
        "concurrency": concurrency,
        "concurrency_mode": concurrency_mode,
        "request_timeout_seconds": 3,
        "model_timeout_seconds": 30,
        "valid_days": 14,
    }


def wait_for_batch(
    client: TestClient,
    batch_id: str,
    *statuses: str,
    timeout: float = 3,
) -> dict[str, object]:
    expected = set(statuses or ("completed",))
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/console/reference-collections/{batch_id}")
        assert response.status_code == 200
        latest = response.json()
        if latest["batch"]["status"] in expected:
            return latest
        time.sleep(0.01)
    raise AssertionError(f"reference collection did not reach {expected}: {latest}")


def write_legacy(path: Path, model: str) -> dict[str, object]:
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": model,
        "postReasoning": False,
        "cells": {},
    }
    path.write_text(json.dumps(fingerprint), encoding="utf-8")
    return {"fingerprint": fingerprint, "run": {"errorCount": 0}}


def write_paper(
    output_path: Path,
    samples_path: Path,
    model: str,
    *,
    partial: bool,
) -> dict[str, object]:
    raw = f'{{"model":"{model}","partial":{str(partial).lower()}}}\n'
    samples_path.write_text(raw, encoding="utf-8")
    raw_sha = hashlib.sha256(raw.encode()).hexdigest()
    fingerprint = {
        "formatVersion": 2,
        "protocol": "bruckner-2026-canonical40/v1",
        "model": model,
        "samplesPerCell": 10,
        "postReasoning": False,
        "partial": partial,
        "completedSamples": 1 if partial else 400,
        "expectedSamples": 400,
        "cells": {},
        "quality": {
            "complete": not partial,
            "reasoningTokenCount": 0,
            "rawEvidenceSha256": raw_sha,
        },
    }
    output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
    return {
        "fingerprint": fingerprint,
        "collection": {
            "rawEvidenceSha256": raw_sha,
            "errorSamples": 0,
        },
    }


def test_reference_collection_runs_in_background_and_auto_uses_retry_history(
    tmp_path: Path,
    monkeypatch,
) -> None:
    release = threading.Event()
    calls: list[tuple[str, int]] = []
    secret = "sk-background-reference-secret"

    async def fake_collect(
        self,
        endpoint,
        *,
        output_path,
        concurrency,
        api_key,
        progress_callback,
        **kwargs,
    ):
        assert api_key == secret
        calls.append((endpoint.model, concurrency))
        if endpoint.model == "model-a":
            progress_callback(
                {
                    "stage": "sampling",
                    "done": 1,
                    "total": 40,
                    "errors": 0,
                    "retrying": True,
                    "detail": "retry 1/4",
                }
            )
            await asyncio.to_thread(release.wait, 2)
        return write_legacy(output_path, endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "collect", fake_collect)
    configured = settings(tmp_path)
    app = create_app(configured)
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(["model-a", "model-b"], api_key=secret),
        )
        assert created.status_code == 202
        batch_id = created.json()["batch"]["id"]
        active = client.get("/api/v1/console/reference-collections/active")
        assert active.status_code == 200
        assert active.json()["batch"]["id"] == batch_id

        conflict = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(["model-c"], api_key=secret),
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["batch_id"] == batch_id

        release.set()
        completed = wait_for_batch(client, batch_id)
        assert [item["effective_concurrency"] for item in completed["items"]] == [2, 1]
        assert completed["items"][0]["retry_count"] == 1
        assert "重试活动" in completed["items"][1]["concurrency_reason"]
        assert len(client.get("/api/v1/console/references").json()["items"]) == 2

    assert calls == [("model-a", 2), ("model-b", 1)]
    assert secret.encode() not in (tmp_path / "test.db").read_bytes()
    for evidence_file in (tmp_path / "evidence").rglob("*"):
        if evidence_file.is_file():
            assert secret.encode() not in evidence_file.read_bytes()


def test_failed_reference_model_does_not_block_later_models(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[str] = []

    async def fake_collect(self, endpoint, *, output_path, **kwargs):
        calls.append(endpoint.model)
        if endpoint.model == "model-a":
            raise RuntimeError("temporary upstream failure")
        return write_legacy(output_path, endpoint.model)

    monkeypatch.setattr(FingerprintRunner, "collect", fake_collect)
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(["model-a", "model-b"]),
        )
        completed = wait_for_batch(client, created.json()["batch"]["id"])
        assert completed["batch"]["status"] == "completed"
        assert [item["status"] for item in completed["items"]] == [
            "failed",
            "completed",
        ]
        assert [item["effective_concurrency"] for item in completed["items"]] == [2, 1]
        assert completed["items"][0]["baseline_id"] is None
        assert completed["items"][1]["baseline_id"]
        assert len(client.get("/api/v1/console/references").json()["items"]) == 1

    assert calls == ["model-a", "model-b"]


def test_paused_paper_reference_keeps_partial_samples_without_baseline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    attempts = 0

    async def fake_collect_paper(
        self,
        endpoint,
        *,
        output_path,
        samples_output_path,
        progress_callback,
        cancel_event,
        **kwargs,
    ):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            write_paper(
                output_path,
                samples_output_path,
                endpoint.model,
                partial=True,
            )
            progress_callback(
                {
                    "stage": "sampling",
                    "done": 1,
                    "total": 400,
                    "errors": 0,
                    "detail": "sample 1/400",
                }
            )
            await cancel_event.wait()
            raise FingerprintPausedError("paused")
        return write_paper(
            output_path,
            samples_output_path,
            endpoint.model,
            partial=False,
        )

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        payload = request_payload(
            ["model-a"],
            method_profile_id="bruckner-2026-canonical40/v1",
            cells=40,
        )
        created = client.post("/api/v1/console/reference-collections", json=payload)
        batch_id = created.json()["batch"]["id"]
        deadline = time.monotonic() + 2
        current = None
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/console/reference-collections/{batch_id}").json()
            if current["items"][0]["progress"]["stage"] == "sampling":
                break
            time.sleep(0.01)
        assert current is not None

        paused = client.post(f"/api/v1/console/reference-collections/{batch_id}/pause")
        assert paused.status_code == 200
        item = paused.json()["items"][0]
        assert item["status"] == "paused"
        assert item["baseline_id"] is None
        assert item["partial_evidence"] is True
        assert client.get("/api/v1/console/references").json()["items"] == []
        samples = client.get(f"/api/v1/console/evidence/{item['audit_id']}/samples")
        assert samples.status_code == 200

        resumed = client.post(f"/api/v1/console/reference-collections/{batch_id}/resume")
        assert resumed.status_code == 200
        completed = wait_for_batch(client, batch_id)
        assert completed["items"][0]["baseline_id"]
        assert len(client.get("/api/v1/console/references").json()["items"]) == 1

    assert attempts == 2


def test_cancel_paused_reference_preserves_partial_without_baseline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def fake_collect_paper(
        self,
        endpoint,
        *,
        output_path,
        samples_output_path,
        progress_callback,
        cancel_event,
        **kwargs,
    ):
        write_paper(output_path, samples_output_path, endpoint.model, partial=True)
        progress_callback(
            {
                "stage": "sampling",
                "done": 1,
                "total": 400,
                "errors": 0,
                "detail": "sample 1/400",
            }
        )
        await cancel_event.wait()
        raise FingerprintPausedError("stopped")

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(
                ["model-a"],
                method_profile_id="bruckner-2026-canonical40/v1",
                cells=40,
            ),
        )
        batch_id = created.json()["batch"]["id"]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/console/reference-collections/{batch_id}").json()
            if current["items"][0]["progress"]["stage"] == "sampling":
                break
            time.sleep(0.01)
        client.post(f"/api/v1/console/reference-collections/{batch_id}/pause")
        canceled = client.post(f"/api/v1/console/reference-collections/{batch_id}/cancel")
        assert canceled.status_code == 200
        item = canceled.json()["items"][0]
        assert canceled.json()["batch"]["status"] == "canceled"
        assert item["status"] == "canceled"
        assert item["baseline_id"] is None
        assert item["partial_evidence"] is True
        assert client.get("/api/v1/console/references").json()["items"] == []
        assert client.get(f"/api/v1/console/evidence/{item['audit_id']}/samples").status_code == 200


def test_restart_marks_unfinished_reference_collection_interrupted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def blocking_collect(
        self,
        endpoint,
        *,
        output_path,
        cancel_event,
        progress_callback,
        **kwargs,
    ):
        progress_callback(
            {
                "stage": "sampling",
                "done": 0,
                "total": 40,
                "errors": 0,
                "detail": "waiting",
            }
        )
        await cancel_event.wait()
        raise FingerprintPausedError("shutdown")

    monkeypatch.setattr(FingerprintRunner, "collect", blocking_collect)
    configured = settings(tmp_path)
    app = create_app(configured)
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(["model-a"]),
        )
        batch_id = created.json()["batch"]["id"]

    with TestClient(create_app(configured)) as client:
        assert client.get("/api/v1/console/reference-collections/active").json() == {
            "batch": None,
            "items": [],
        }
        interrupted = client.get(f"/api/v1/console/reference-collections/{batch_id}").json()
        assert interrupted["batch"]["status"] == "interrupted"
        assert interrupted["items"][0]["status"] == "interrupted"


def test_completed_reference_download_catalog_and_samples_reject_tampering(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def fake_collect_paper(
        self,
        endpoint,
        *,
        output_path,
        samples_output_path,
        **kwargs,
    ):
        return write_paper(
            output_path,
            samples_output_path,
            endpoint.model,
            partial=False,
        )

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(
                ["model-a"],
                method_profile_id="bruckner-2026-canonical40/v1",
                cells=40,
            ),
        )
        completed = wait_for_batch(client, created.json()["batch"]["id"])
        artifact_id = completed["items"][0]["audit_id"]
        fingerprint_path = app.state.evidence.fingerprint_path(artifact_id)
        samples_path = app.state.evidence.fingerprint_samples_path(artifact_id)
        fingerprint_bytes = fingerprint_path.read_bytes()

        download = client.get(f"/api/v1/console/evidence/{artifact_id}")
        assert download.status_code == 200
        assert download.content == fingerprint_bytes
        assert client.get("/api/v1/console/references").status_code == 200
        assert client.get(f"/api/v1/console/evidence/{artifact_id}/samples").status_code == 200

        fingerprint_path.write_bytes(fingerprint_bytes + b"\n")
        assert client.get(f"/api/v1/console/evidence/{artifact_id}").status_code == 409
        catalog = client.get("/api/v1/console/references")
        assert catalog.status_code == 200
        assert catalog.json()["items"][0]["evidence_integrity"] == "corrupt"
        assert client.get(f"/api/v1/console/evidence/{artifact_id}/samples").status_code == 409

        fingerprint_path.write_bytes(fingerprint_bytes)
        samples_path.write_bytes(samples_path.read_bytes() + b"{}\n")
        assert client.get(f"/api/v1/console/evidence/{artifact_id}/samples").status_code == 409


def test_v2_reference_with_mismatched_raw_evidence_does_not_create_baseline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def fake_collect_paper(
        self,
        endpoint,
        *,
        output_path,
        samples_output_path,
        **kwargs,
    ):
        result = write_paper(
            output_path,
            samples_output_path,
            endpoint.model,
            partial=False,
        )
        samples_output_path.write_bytes(samples_output_path.read_bytes() + b"{}\n")
        return result

    monkeypatch.setattr(FingerprintRunner, "collect_paper_profile", fake_collect_paper)
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/console/reference-collections",
            json=request_payload(
                ["model-a"],
                method_profile_id="bruckner-2026-canonical40/v1",
                cells=40,
            ),
        )
        completed = wait_for_batch(client, created.json()["batch"]["id"])
        item = completed["items"][0]
        assert item["status"] == "failed"
        assert item["baseline_id"] is None
        assert "digest mismatch" in item["error_message"]
        assert client.get("/api/v1/console/references").json()["items"] == []


def test_comparison_history_and_download_reject_registered_artifact_tampering(
    tmp_path: Path,
) -> None:
    audit_id = "22222222-2222-2222-2222-222222222222"
    batch_id = "33333333-3333-3333-3333-333333333333"
    reference_id = "11111111-1111-1111-1111-111111111111"
    app = create_app(settings(tmp_path))
    with TestClient(app) as client:
        database = app.state.database
        database.create_run(
            audit_id=audit_id,
            detector="one_token_verify",
            target_base_url="https://relay.example/v1",
            model="target-model",
        )
        database.create_comparison_record(
            audit_id=audit_id,
            batch_id=batch_id,
            total_items=1,
            station_name="Relay",
            reference_artifact_id=reference_id,
            reference_name="Reference",
            reference_model="reference-model",
            cells=4,
            samples=10,
            concurrency=2,
        )
        artifact = app.state.evidence.write_json(
            "verification",
            audit_id,
            {
                "methodProfileId": "legacy-one-token/v1",
                "comparison": {"verdict": "match", "meanJsd": 0.01},
                "target": {"errorCount": 0},
            },
        )
        database.finish_run(
            audit_id,
            status="completed",
            verdict="match",
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
        )
        database.finish_comparison_record(audit_id)

        history = client.get("/api/v1/console/comparisons")
        assert history.status_code == 200
        download = client.get(f"/api/v1/console/evidence/{audit_id}")
        assert download.status_code == 200
        assert download.content == artifact.path.read_bytes()

        artifact.path.write_bytes(artifact.path.read_bytes() + b"\n")
        history = client.get("/api/v1/console/comparisons")
        assert history.status_code == 200
        assert history.json()["items"][0]["evidence_integrity"] == "corrupt"
        latest = client.get("/api/v1/console/comparisons/latest")
        assert latest.status_code == 200
        assert latest.json()["items"][0]["evidence_integrity"] == "corrupt"
        assert client.get(f"/api/v1/console/evidence/{audit_id}").status_code == 409


def test_second_active_comparison_batch_returns_existing_batch_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reference_id = "11111111-1111-1111-1111-111111111111"
    app = create_app(settings(tmp_path))

    async def block_worker(runtime) -> None:
        await runtime.interrupt_event.wait()

    monkeypatch.setattr(app.state.batches, "_run", block_worker)
    with TestClient(app) as client:
        fingerprint = app.state.evidence.write_json(
            "fingerprints",
            reference_id,
            {
                "formatVersion": 1,
                "protocol": "one-token/v1",
                "model": "reference-model",
                "postReasoning": False,
                "cells": {},
            },
        )
        app.state.database.create_run(
            audit_id=reference_id,
            detector="one_token_collect",
            target_base_url="https://official.example/v1",
            model="reference-model",
        )
        app.state.database.finish_run(
            reference_id,
            status="completed",
            verdict="recorded",
            artifact_path=str(fingerprint.path),
            artifact_sha256=fingerprint.sha256,
        )
        payload = {
            "items": [
                {
                    "endpoint": {
                        "base_url": "https://relay.example/v1",
                        "model": "target-model",
                    },
                    "reference_artifact_id": reference_id,
                    "station_name": "Relay",
                    "reference_name": "Reference",
                    "reference_model": "reference-model",
                }
            ],
            "cells": 4,
            "samples": 10,
            "concurrency": 2,
        }
        first = client.post("/api/v1/console/comparison-batches", json=payload)
        assert first.status_code == 202
        batch_id = first.json()["batch"]["id"]

        second = client.post("/api/v1/console/comparison-batches", json=payload)
        assert second.status_code == 409
        assert second.json()["detail"]["batch_id"] == batch_id
