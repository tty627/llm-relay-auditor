import asyncio
import hashlib
import json
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pydantic import ValidationError

from relay_auditor.detectors.fingerprint import (
    FingerprintPausedError,
    FingerprintRunner,
    FingerprintStalledError,
)
from relay_auditor.schemas import (
    EndpointSpec,
    EphemeralConnectionSpec,
    ManagedEndpointCreateRequest,
)

TASKS = (
    "num100-random",
    "num10-random",
    "num-favorite",
    "letter-random",
    "word-random",
    "color-random",
    "color-favorite",
    "animal-random",
    "city-random",
    "coin-flip",
)
LANGUAGES = ("en", "ru", "zh", "ar")
CELL_IDS = [f"{task}:{language}" for task in TASKS for language in LANGUAGES]
PROTOCOL = "bruckner-2026-canonical40/v1"


def write_paper_artifacts(
    output_path: Path,
    samples_path: Path,
    *,
    role: str = "audit",
    scheduler_seed: str = "safe-seed",
    model: str = "paper-model",
) -> dict:
    evidence = [
        {
            "evidenceVersion": 1,
            "protocolId": PROTOCOL,
            "requestedModel": model,
            "role": role,
            "schedulerSeed": scheduler_seed,
            "jobId": hashlib.sha256(f"{cell_id}\0{0}\0fixed-author-prompt/v1".encode()).hexdigest(),
            "cellId": cell_id,
            "taskId": cell_id.split(":", 1)[0],
            "language": cell_id.split(":", 1)[1],
            "repetitionIndex": 0,
            "promptVariantId": "fixed-author-prompt/v1",
            "requestedAt": "2026-08-21T00:00:00.000Z",
            "receivedAt": "2026-08-21T00:00:00.001Z",
            "latencyMs": 1,
            "provider": None,
            "reportedModel": model,
            "generationId": None,
            "finishReason": "stop",
            "category": "valid",
            "raw": "7",
            "normalized": "7",
            "normalizationCandidate": "7",
            "normalizationCategory": "valid",
            "excludedFromDistribution": False,
            "exclusionReason": None,
            "reasoningTraceFields": [],
            "reasoningTraceCharacterCount": 0,
            "sensitiveCredentialEchoFields": [],
            "usage": {
                "promptTokens": 1,
                "completionTokens": 1,
                "reasoningTokens": 0,
                "costUsd": None,
                "cachedPromptTokens": None,
            },
            "errorKind": None,
        }
        for cell_id in sorted(CELL_IDS)
    ]
    evidence_text = "".join(
        f"{json.dumps(sample, sort_keys=True, separators=(',', ':'))}\n" for sample in evidence
    )
    samples_path.write_text(evidence_text, encoding="utf-8")
    digest = hashlib.sha256(evidence_text.encode()).hexdigest()
    cells = {
        cell_id: {
            "cellId": cell_id,
            "counts": {"7": 1},
            "validCount": 1,
            "invalidCount": 0,
            "refusalCount": 0,
            "emptyCount": 0,
            "errorCount": 0,
            "totalCount": 1,
            "entropyBits": 0,
            "normalizedEntropy": 0,
            "medianLatencyMs": 1,
            "meanCompletionTokens": 1,
            "meanReasoningTokens": 0,
        }
        for cell_id in CELL_IDS
    }
    fingerprint = {
        "formatVersion": 2,
        "protocol": PROTOCOL,
        "model": model,
        "collectedAt": "2026-08-21T00:00:00.000Z",
        "samplesPerCell": 1,
        "postReasoning": False,
        "cells": cells,
        "manifest": {
            "manifestVersion": 1,
            "protocolId": PROTOCOL,
            "battery": {
                "id": "bruckner-2026-canonical40",
                "version": "1.0.0",
                "digest": (
                    "sha256:9ef56c982a503b4dba94710b63866aaff47db1e37cc34538e225acb9f5fe1341"
                ),
            },
            "prompts": {
                "systemPromptDigest": (
                    "sha256:1f5353a59436724ba9c9140ad159d47dc274ea7d0783db5ea6792f90dd277962"
                ),
                "templateDigest": (
                    "sha256:f6f519484809a7f585e272ee68468927b0b3d4db574351b444acc2d6383c8937"
                ),
            },
            "normalization": {
                "id": "bruckner-author-compatible-normalizer/v1",
                "version": "1.0.0",
                "digest": (
                    "sha256:8f755ca604e4814126c253f44135199b1636ddfedcb070fa4ece3368fb858fa8"
                ),
            },
            "sampling": {
                "temperature": 1,
                "topP": None,
                "maxTokens": 16,
                "answerConstraint": "fixed-system-single-word-or-number",
                "reasoningPolicy": "disabled-required",
            },
        },
        "plan": {
            "planVersion": 1,
            "role": role,
            "cellIds": list(CELL_IDS),
            "samplesPerCell": 1,
            "expectedSamples": 40,
            "schedulerSeed": scheduler_seed,
            "schedulerPolicy": "bruckner-seeded-shuffle-mulberry32-v1",
        },
        "quality": {
            "qualityVersion": 1,
            "complete": True,
            "completedSamples": 40,
            "expectedSamples": 40,
            "validSamples": 40,
            "invalidSamples": 0,
            "refusalSamples": 0,
            "emptySamples": 0,
            "errorSamples": 0,
            "directness": "verified",
            "reasoningTraceCount": 0,
            "reasoningTokenCount": 0,
            "reasoningUsageObservedSamples": 40,
            "rawEvidenceSha256": digest,
        },
        "completedSamples": 40,
        "expectedSamples": 40,
        "errorCount": 0,
    }
    output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
    return {
        "fingerprint": fingerprint,
        "collection": {
            "artifactKind": "paper-profile-collection-v2",
            "interpretation": "uncalibrated-non-decision-evidence",
            "decisionEligible": False,
            "protocol": PROTOCOL,
            "model": model,
            "role": role,
            "cellCount": 40,
            "samplesPerCell": 1,
            "expectedSamples": 40,
            "validSamples": 40,
            "invalidSamples": 0,
            "errorSamples": 0,
            "directness": "verified",
            "splitHalfMeanJsd": None,
            "splitHalfComparableCells": 0,
            "rawEvidenceSha256": digest,
        },
    }


def write_partial_paper_artifacts(
    output_path: Path,
    samples_path: Path,
    *,
    completed: int = 2,
    role: str = "audit",
    scheduler_seed: str = "safe-seed",
    model: str = "paper-model",
) -> dict:
    payload = write_paper_artifacts(
        output_path,
        samples_path,
        role=role,
        scheduler_seed=scheduler_seed,
        model=model,
    )
    fingerprint = payload["fingerprint"]
    evidence = [
        json.loads(line)
        for line in samples_path.read_text(encoding="utf-8").splitlines()[:completed]
    ]
    evidence_text = "".join(
        f"{json.dumps(sample, sort_keys=True, separators=(',', ':'))}\n"
        for sample in evidence
    )
    samples_path.write_text(evidence_text, encoding="utf-8")
    for cell in fingerprint["cells"].values():
        cell.update(
            counts={},
            validCount=0,
            invalidCount=0,
            refusalCount=0,
            emptyCount=0,
            errorCount=0,
            totalCount=0,
            entropyBits=0,
            normalizedEntropy=0,
            medianLatencyMs=None,
            meanCompletionTokens=None,
            meanReasoningTokens=None,
        )
    for sample in evidence:
        cell = fingerprint["cells"][sample["cellId"]]
        cell["counts"] = {"7": 1}
        cell["validCount"] = 1
        cell["totalCount"] = 1
        cell["medianLatencyMs"] = 1
        cell["meanCompletionTokens"] = 1
        cell["meanReasoningTokens"] = 0
    fingerprint.update(
        partial=True,
        completedSamples=completed,
        expectedSamples=40,
        errorCount=0,
        incompleteReason="sampling_in_progress",
    )
    fingerprint["quality"].update(
        complete=False,
        completedSamples=completed,
        expectedSamples=40,
        validSamples=completed,
        invalidSamples=0,
        refusalSamples=0,
        emptySamples=0,
        errorSamples=0,
        directness="verified",
        reasoningTraceCount=0,
        reasoningTokenCount=0,
        reasoningUsageObservedSamples=completed,
        rawEvidenceSha256=hashlib.sha256(evidence_text.encode()).hexdigest(),
    )
    output_path.write_text(json.dumps(fingerprint), encoding="utf-8")
    return fingerprint


@pytest.mark.asyncio
async def test_collect_paper_profile_keeps_key_out_of_argv_and_stdout(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    captured = {}

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        captured.update(arguments=arguments, environment=environment)
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        return write_paper_artifacts(actual_output, actual_samples)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    secret = "sk-paper-bridge-secret"
    result = await runner.collect_paper_profile(
        EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
        role="audit",
        scheduler_seed="safe-seed",
        output_path=output_path,
        samples_output_path=samples_path,
        samples=1,
        concurrency=2,
        api_key=secret,
    )

    assert secret not in captured["arguments"]
    assert secret in captured["environment"].values()
    assert "--cells" not in captured["arguments"]
    assert "--preset" not in captured["arguments"]
    assert "paper-fingerprint" in captured["arguments"]
    assert set(result) == {"fingerprint", "collection"}
    assert "samples" not in result
    assert "evidence" not in result


@pytest.mark.asyncio
async def test_collect_paper_profile_forwards_long_task_controls(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    captured = {}
    progress = []
    cancel_event = asyncio.Event()

    async def fake_execute_with_code(
        arguments,
        *,
        accepted_exit_codes,
        environment,
        progress_callback,
        cancel_event,
        idle_timeout_seconds,
    ):
        captured.update(
            arguments=arguments,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
            idle_timeout_seconds=idle_timeout_seconds,
        )
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        progress_callback(
            {
                "stage": "sampling",
                "done": 1,
                "total": 40,
                "errors": 0,
                "detail": None,
                "lastErrorKind": None,
                "lastHttpStatus": None,
                "retrying": False,
            }
        )
        return 0, payload

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    result = await runner.collect_paper_profile(
        EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
        role="audit",
        scheduler_seed="safe-seed",
        output_path=tmp_path / "fingerprint.json",
        samples_output_path=tmp_path / "samples.jsonl",
        samples=1,
        concurrency=2,
        progress_callback=progress.append,
        cancel_event=cancel_event,
        idle_timeout_seconds=30,
    )

    assert result["fingerprint"]["formatVersion"] == 2
    assert captured["progress_callback"] == progress.append
    assert captured["cancel_event"] is cancel_event
    assert captured["idle_timeout_seconds"] == 30
    assert "--quiet" not in captured["arguments"]
    assert progress[0]["done"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("interruption", "expected_error", "expected_reason"),
    [
        ("pause", FingerprintPausedError, "execution_interrupted"),
        ("stall", FingerprintStalledError, "progress_timeout"),
    ],
)
async def test_collect_paper_profile_preserves_valid_partial_pair(
    tmp_path,
    monkeypatch,
    interruption,
    expected_error,
    expected_reason,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")

    async def fake_execute_with_code(arguments, **kwargs):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        write_partial_paper_artifacts(actual_output, actual_samples, completed=2)
        if interruption == "pause":
            raise FingerprintPausedError("paused")
        raise FingerprintStalledError(30)

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    call_options = (
        {"cancel_event": asyncio.Event()}
        if interruption == "pause"
        else {"idle_timeout_seconds": 30}
    )
    with pytest.raises(expected_error) as caught:
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
            **call_options,
        )

    fingerprint = json.loads(output_path.read_text(encoding="utf-8"))
    assert fingerprint["partial"] is True
    assert fingerprint["completedSamples"] == 2
    assert fingerprint["incompleteReason"] == expected_reason
    assert len(samples_path.read_text(encoding="utf-8").splitlines()) == 2
    assert caught.value.partial_artifact == {
        "partial": True,
        "completedSamples": 2,
        "expectedSamples": 40,
        "errorCount": 0,
        "incompleteReason": expected_reason,
        "model": "paper-model",
    }
    assert not list(tmp_path.glob(".*.tmp*"))


@pytest.mark.asyncio
async def test_collect_paper_profile_task_cancellation_preserves_valid_partial(
    tmp_path,
    monkeypatch,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"

    async def fake_execute_with_code(arguments, **kwargs):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        write_partial_paper_artifacts(actual_output, actual_samples, completed=1)
        raise asyncio.CancelledError

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    with pytest.raises(asyncio.CancelledError):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=1,
            progress_callback=lambda event: None,
        )

    fingerprint = json.loads(output_path.read_text(encoding="utf-8"))
    assert fingerprint["completedSamples"] == 1
    assert fingerprint["incompleteReason"] == "execution_interrupted"
    assert hashlib.sha256(samples_path.read_bytes()).hexdigest() == fingerprint["quality"][
        "rawEvidenceSha256"
    ]


@pytest.mark.asyncio
async def test_collect_paper_profile_drops_normalized_credential_echo_partial(
    tmp_path,
    monkeypatch,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")
    secret = "sk-Café-Partial-12345678"
    normalized_secret = "sk-cafe\u0301-partial-12345678"

    async def fake_execute_with_code(arguments, **kwargs):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        fingerprint = write_partial_paper_artifacts(
            actual_output,
            actual_samples,
            completed=1,
        )
        fingerprint["meta"] = {"unsafe": normalized_secret}
        actual_output.write_text(json.dumps(fingerprint), encoding="utf-8")
        raise FingerprintPausedError("paused")

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    with pytest.raises(FingerprintPausedError) as caught:
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
            api_key=secret,
            cancel_event=asyncio.Event(),
        )

    assert caught.value.partial_artifact is None
    assert output_path.read_text(encoding="utf-8") == "old fingerprint"
    assert samples_path.read_text(encoding="utf-8") == "old samples"
    assert not list(tmp_path.glob(".*.tmp*"))


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["sha", "plan", "completed"])
async def test_collect_paper_profile_rejects_tampered_partial_and_preserves_existing_pair(
    tmp_path,
    monkeypatch,
    tamper,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")
    validated_completed = []
    original_validate_evidence = FingerprintRunner._validate_paper_evidence_jsonl

    def validate_evidence_with_observation(*args, **kwargs):
        validated_completed.append(kwargs.get("expected_completed"))
        return original_validate_evidence(*args, **kwargs)

    async def fake_execute_with_code(arguments, **kwargs):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        fingerprint = write_partial_paper_artifacts(
            actual_output,
            actual_samples,
            completed=2,
        )
        if tamper == "sha":
            fingerprint["quality"]["rawEvidenceSha256"] = "0" * 64
        elif tamper == "plan":
            fingerprint["plan"]["schedulerSeed"] = "tampered-seed"
        else:
            fingerprint["completedSamples"] = 3
            fingerprint["quality"]["completedSamples"] = 3
            fingerprint["quality"]["validSamples"] = 3
            first_sample = json.loads(
                actual_samples.read_text(encoding="utf-8").splitlines()[0]
            )
            cell = fingerprint["cells"][first_sample["cellId"]]
            cell["counts"] = {"7": 2}
            cell["validCount"] = 2
            cell["totalCount"] = 2
        actual_output.write_text(json.dumps(fingerprint), encoding="utf-8")
        raise FingerprintPausedError("paused")

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    monkeypatch.setattr(
        FingerprintRunner,
        "_validate_paper_evidence_jsonl",
        staticmethod(validate_evidence_with_observation),
    )
    with pytest.raises(FingerprintPausedError) as caught:
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
            cancel_event=asyncio.Event(),
        )

    assert caught.value.partial_artifact is None
    assert validated_completed == ([3] if tamper == "completed" else [])
    assert output_path.read_text(encoding="utf-8") == "old fingerprint"
    assert samples_path.read_text(encoding="utf-8") == "old samples"
    assert not list(tmp_path.glob(".*.tmp*"))
    assert not list(tmp_path.glob(".*.backup"))


@pytest.mark.asyncio
async def test_collect_paper_profile_partial_commit_failure_restores_existing_pair(
    tmp_path,
    monkeypatch,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")
    captured = {}

    async def fake_execute_with_code(arguments, **kwargs):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        captured["temporary_fingerprint"] = actual_output
        write_partial_paper_artifacts(actual_output, actual_samples, completed=2)
        raise FingerprintPausedError("paused")

    original_replace = Path.replace
    injected_failures = 0

    def fail_second_promotion(self, target):
        nonlocal injected_failures
        if self == captured.get("temporary_fingerprint") and Path(target) == output_path:
            injected_failures += 1
            raise OSError("simulated partial fingerprint promotion failure")
        return original_replace(self, target)

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    monkeypatch.setattr(Path, "replace", fail_second_promotion)
    with pytest.raises(FingerprintPausedError) as caught:
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
            cancel_event=asyncio.Event(),
        )

    assert caught.value.partial_artifact is None
    assert injected_failures == 1
    assert output_path.read_text(encoding="utf-8") == "old fingerprint"
    assert samples_path.read_text(encoding="utf-8") == "old samples"
    assert not list(tmp_path.glob(".*.tmp*"))
    assert not list(tmp_path.glob(".*.backup"))


@pytest.mark.asyncio
async def test_collect_paper_profile_partial_restore_failure_is_not_silenced(
    tmp_path,
    monkeypatch,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")
    captured = {}

    async def fake_execute_with_code(arguments, **kwargs):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        captured["temporary_fingerprint"] = actual_output
        write_partial_paper_artifacts(actual_output, actual_samples, completed=2)
        raise FingerprintPausedError("paused")

    original_replace = Path.replace
    injected_failures = {"promotion": 0, "restore": 0}

    def fail_promotion_and_fingerprint_restore(self, target):
        target_path = Path(target)
        if self == captured.get("temporary_fingerprint") and target_path == output_path:
            injected_failures["promotion"] += 1
            raise OSError("simulated partial fingerprint promotion failure")
        if self.name.endswith(".backup") and target_path == output_path:
            injected_failures["restore"] += 1
            raise OSError("simulated fingerprint restore failure")
        return original_replace(self, target)

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute_with_code)
    monkeypatch.setattr(Path, "replace", fail_promotion_and_fingerprint_restore)
    with pytest.raises(RuntimeError, match="could not be fully restored"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
            cancel_event=asyncio.Event(),
        )

    assert injected_failures == {"promotion": 1, "restore": 1}
    assert not output_path.exists()
    assert samples_path.read_text(encoding="utf-8") == "old samples"
    fingerprint_backups = list(tmp_path.glob(".*.backup"))
    assert len(fingerprint_backups) == 1
    assert fingerprint_backups[0].read_text(encoding="utf-8") == "old fingerprint"
    assert not list(tmp_path.glob(".*.tmp*"))


@pytest.mark.asyncio
async def test_real_paper_cli_cancel_after_first_progress_preserves_sha_bound_partial(
    tmp_path,
):
    cli_path = (
        Path(__file__).resolve().parents[1]
        / "llm-fingerprint-detector"
        / "dist"
        / "cli.js"
    )
    if not cli_path.is_file():
        pytest.skip("detector CLI must be built before running the real bridge contract")

    release_requests = threading.Event()
    request_lock = threading.Lock()
    request_count = 0

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            nonlocal request_count
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            with request_lock:
                request_count += 1
                current_request = request_count
            if current_request > 1:
                release_requests.wait(timeout=10)
            response = json.dumps(
                {
                    "id": f"local-generation-{current_request}",
                    "model": "paper-model",
                    "choices": [
                        {
                            "message": {"role": "assistant", "content": "7"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "completion_tokens_details": {"reasoning_tokens": 0},
                    },
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(response)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    cancel_event = asyncio.Event()
    progress = []
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"

    def on_progress(event):
        progress.append(event)
        if (
            event.get("stage") == "sampling"
            and event.get("done") == 1
            and event.get("retrying") is False
        ):
            cancel_event.set()

    try:
        runner = FingerprintRunner(cli_path)
        with pytest.raises(FingerprintPausedError) as caught:
            await asyncio.wait_for(
                runner.collect_paper_profile(
                    EndpointSpec(
                        base_url=f"http://127.0.0.1:{server.server_port}/v1",
                        model="paper-model",
                    ),
                    role="audit",
                    scheduler_seed="real-cli-cancel-contract",
                    output_path=output_path,
                    samples_output_path=samples_path,
                    samples=1,
                    concurrency=1,
                    timeout=5_000,
                    progress_callback=on_progress,
                    cancel_event=cancel_event,
                ),
                timeout=10,
            )
    finally:
        release_requests.set()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    fingerprint = json.loads(output_path.read_text(encoding="utf-8"))
    sample_bytes = samples_path.read_bytes()
    assert any(event.get("done") == 1 for event in progress)
    assert fingerprint["partial"] is True
    assert fingerprint["quality"]["complete"] is False
    assert fingerprint["completedSamples"] == 1
    assert fingerprint["quality"]["completedSamples"] == 1
    assert fingerprint["expectedSamples"] == 40
    assert fingerprint["incompleteReason"] == "execution_interrupted"
    assert len(sample_bytes.splitlines()) == 1
    assert hashlib.sha256(sample_bytes).hexdigest() == fingerprint["quality"][
        "rawEvidenceSha256"
    ]
    assert caught.value.partial_artifact == {
        "partial": True,
        "completedSamples": 1,
        "expectedSamples": 40,
        "errorCount": 0,
        "incompleteReason": "execution_interrupted",
        "model": "paper-model",
    }
    assert not list(tmp_path.glob(".*.tmp*"))


@pytest.mark.asyncio
async def test_collect_paper_profile_rejects_tampered_jsonl(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        actual_samples.write_text(
            actual_samples.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        return payload

    monkeypatch.setattr(runner, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="SHA-256"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["manifest", "cell_order", "scheduler"])
async def test_collect_paper_profile_rejects_protocol_drift(tmp_path, monkeypatch, drift):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        fingerprint = payload["fingerprint"]
        if drift == "manifest":
            fingerprint["manifest"]["prompts"]["templateDigest"] = f"sha256:{'b' * 64}"
        elif drift == "cell_order":
            fingerprint["plan"]["cellIds"][:2] = reversed(fingerprint["plan"]["cellIds"][:2])
        else:
            fingerprint["plan"]["schedulerPolicy"] = "repetition-index-seeded"
        actual_output.write_text(json.dumps(fingerprint), encoding="utf-8")
        return payload

    monkeypatch.setattr(runner, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="manifest|ordered|scheduler"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=tmp_path / "fingerprint.json",
            samples_output_path=tmp_path / "samples.jsonl",
            samples=1,
            concurrency=2,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("normalized_value", ["101", None])
async def test_collect_paper_profile_accepts_canonical_ordinary_invalid(
    tmp_path,
    monkeypatch,
    normalized_value,
):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        lines = actual_samples.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first.update(
            {
                "raw": "101" if normalized_value is not None else "not-a-canonical-answer",
                "normalized": normalized_value,
                "normalizationCandidate": normalized_value,
                "category": "invalid",
                "normalizationCategory": "invalid",
                "excludedFromDistribution": False,
                "exclusionReason": None,
                "errorKind": None,
            }
        )
        lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
        evidence_text = "\n".join(lines) + "\n"
        actual_samples.write_text(evidence_text, encoding="utf-8")
        digest = hashlib.sha256(evidence_text.encode()).hexdigest()
        cell = payload["fingerprint"]["cells"][first["cellId"]]
        cell.update({"counts": {}, "validCount": 0, "invalidCount": 1})
        quality = payload["fingerprint"]["quality"]
        quality.update(
            {
                "validSamples": 39,
                "invalidSamples": 1,
                "rawEvidenceSha256": digest,
            }
        )
        payload["collection"].update(
            {
                "validSamples": 39,
                "invalidSamples": 1,
                "rawEvidenceSha256": digest,
            }
        )
        actual_output.write_text(json.dumps(payload["fingerprint"]), encoding="utf-8")
        return payload

    monkeypatch.setattr(runner, "_execute", fake_execute)
    result = await runner.collect_paper_profile(
        EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
        role="audit",
        scheduler_seed="safe-seed",
        output_path=tmp_path / "fingerprint.json",
        samples_output_path=tmp_path / "samples.jsonl",
        samples=1,
        concurrency=2,
    )

    assert result["fingerprint"]["quality"]["invalidSamples"] == 1
    assert result["collection"]["invalidSamples"] == 1


@pytest.mark.asyncio
async def test_collect_paper_profile_rebuilds_distribution_from_jsonl(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        first_cell = payload["fingerprint"]["cells"][CELL_IDS[0]]
        first_cell["counts"] = {"forged": 1}
        actual_output.write_text(json.dumps(payload["fingerprint"]), encoding="utf-8")
        return payload

    monkeypatch.setattr(runner, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="distribution is not evidence-derived"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=tmp_path / "fingerprint.json",
            samples_output_path=tmp_path / "samples.jsonl",
            samples=1,
            concurrency=2,
        )


@pytest.mark.asyncio
async def test_collect_paper_profile_rejects_extra_jsonl_fields(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        lines = actual_samples.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["errorBody"] = "must-not-be-retained"
        lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
        evidence_text = "\n".join(lines) + "\n"
        actual_samples.write_text(evidence_text, encoding="utf-8")
        digest = hashlib.sha256(evidence_text.encode()).hexdigest()
        payload["fingerprint"]["quality"]["rawEvidenceSha256"] = digest
        payload["collection"]["rawEvidenceSha256"] = digest
        actual_output.write_text(json.dumps(payload["fingerprint"]), encoding="utf-8")
        return payload

    monkeypatch.setattr(runner, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="unsupported shape"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=tmp_path / "fingerprint.json",
            samples_output_path=tmp_path / "samples.jsonl",
            samples=1,
            concurrency=2,
        )


@pytest.mark.asyncio
async def test_collect_paper_profile_leak_failure_preserves_final_paths(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")
    secret = "sk-paper-output-leak"

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        payload = write_paper_artifacts(actual_output, actual_samples)
        payload["fingerprint"]["meta"] = {"note": secret}
        actual_output.write_text(json.dumps(payload["fingerprint"]), encoding="utf-8")
        return payload

    monkeypatch.setattr(runner, "_execute", fake_execute)
    with pytest.raises(RuntimeError, match="API key material"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
            api_key=secret,
        )
    assert output_path.read_text(encoding="utf-8") == "old fingerprint"
    assert samples_path.read_text(encoding="utf-8") == "old samples"
    assert not list(tmp_path.glob(".*.tmp*"))


@pytest.mark.asyncio
async def test_collect_paper_profile_commit_failure_restores_existing_pair(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    output_path = tmp_path / "fingerprint.json"
    samples_path = tmp_path / "samples.jsonl"
    output_path.write_text("old fingerprint", encoding="utf-8")
    samples_path.write_text("old samples", encoding="utf-8")

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        actual_output = Path(arguments[arguments.index("--out") + 1])
        actual_samples = Path(arguments[arguments.index("--samples-out") + 1])
        return write_paper_artifacts(actual_output, actual_samples)

    original_replace = Path.replace

    def fail_second_promotion(self, target):
        if Path(target) == output_path and self.name.endswith(".tmp"):
            raise OSError("simulated fingerprint promotion failure")
        return original_replace(self, target)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    monkeypatch.setattr(Path, "replace", fail_second_promotion)
    with pytest.raises(OSError, match="simulated fingerprint promotion failure"):
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=output_path,
            samples_output_path=samples_path,
            samples=1,
            concurrency=2,
        )
    assert output_path.read_text(encoding="utf-8") == "old fingerprint"
    assert samples_path.read_text(encoding="utf-8") == "old samples"
    assert not list(tmp_path.glob(".*.tmp*"))
    assert not list(tmp_path.glob(".*.backup"))


@pytest.mark.parametrize(
    "schema",
    [
        lambda: EndpointSpec(base_url="https://user:secret@example.test/v1", model="m"),
        lambda: EphemeralConnectionSpec(base_url="https://user:secret@example.test/v1"),
        lambda: ManagedEndpointCreateRequest(
            name="test",
            provider="test",
            base_url="https://user:secret@example.test/v1",
            model="m",
        ),
    ],
)
def test_endpoint_schemas_reject_url_userinfo(schema):
    with pytest.raises(ValidationError, match="must not contain username or password"):
        schema()


@pytest.mark.asyncio
async def test_paper_cli_error_is_redacted_and_subcommand_is_reordered(tmp_path):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text(
        """
if (process.argv[2] !== 'paper-fingerprint') process.exit(8)
const index = process.argv.indexOf('--api-key-env')
process.stderr.write(process.env[process.argv[index + 1]])
process.exit(7)
""",
        encoding="utf-8",
    )
    runner = FingerprintRunner(cli_path)
    secret = "sk-paper-cli-error-secret"
    with pytest.raises(RuntimeError, match="exit code 7") as captured:
        await runner.collect_paper_profile(
            EndpointSpec(base_url="https://example.test/v1", model="paper-model"),
            role="audit",
            scheduler_seed="safe-seed",
            output_path=tmp_path / "fingerprint.json",
            samples_output_path=tmp_path / "samples.jsonl",
            samples=1,
            concurrency=1,
            api_key=secret,
        )
    assert secret not in str(captured.value)
    assert "[REDACTED]" in str(captured.value)


@pytest.mark.asyncio
async def test_v2_offline_compare_remains_non_decision_evidence(tmp_path, monkeypatch):
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// fake", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    enrollment = tmp_path / "enrollment.json"
    audit = tmp_path / "audit.json"
    write_paper_artifacts(
        enrollment,
        tmp_path / "enrollment.jsonl",
        role="enrollment",
        scheduler_seed="enrollment-seed",
    )
    write_paper_artifacts(audit, tmp_path / "audit.jsonl")

    async def fake_execute(arguments, *, accepted_exit_codes, environment, **kwargs):
        return 0, {"verdict": "match", "meanJsd": 0.1}

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute)
    result = await runner.compare_paper_fingerprints(
        enrollment_path=enrollment,
        audit_path=audit,
    )
    assert result["decisionEligible"] is False
    assert result["interpretation"] == "uncalibrated-non-decision-evidence"
    assert result["verdictSemantics"] == "legacy-exploratory"
