import asyncio
import json
import os
from pathlib import Path

import pytest

from relay_auditor.config import Settings
from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import (
    FingerprintPausedError,
    FingerprintRunner,
    FingerprintStalledError,
    InvalidCliJsonError,
    safeguard_verification_result,
)
from relay_auditor.evidence import EvidenceStore
from relay_auditor.recovery import recover_failed_verification
from relay_auditor.schemas import EndpointSpec


def write_fingerprint(path: Path, *, model: str, post_reasoning: bool = False) -> dict:
    fingerprint = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": model,
        "collectedAt": "2026-08-20T00:00:00.000Z",
        "samplesPerCell": 15,
        "postReasoning": post_reasoning,
        "cells": {},
    }
    path.write_text(json.dumps(fingerprint), encoding="utf-8")
    return fingerprint


def comparison_payload(*, verdict: str = "uncertain") -> dict:
    return {
        "a": "target-model",
        "b": "reference-model",
        "meanJsd": 0.31,
        "verdict": verdict,
        "cells": [],
        "comparableCellCount": 4,
        "protocolMismatch": False,
        "thresholds": {"match": 0.25, "mismatch": 0.35},
        "baselines": {
            "sameModelSelf": 0.14,
            "sameModelCrossProvider": 0.227,
            "differentModel": 0.463,
        },
    }


def test_parse_jsonl_progress_preserves_safe_error_state() -> None:
    event = FingerprintRunner._parse_progress_line(
        'LLMFP_PROGRESS {"stage":"sampling","done":7,"total":40,'
        '"errors":2,"detail":"retry 1/2 in 5000ms",'
        '"lastErrorKind":"http","lastHttpStatus":503,"retrying":true}\n'
    )
    assert event == {
        "stage": "sampling",
        "done": 7,
        "total": 40,
        "errors": 2,
        "detail": "retry 1/2 in 5000ms",
        "lastErrorKind": "http",
        "lastHttpStatus": 503,
        "retrying": True,
    }
    assert FingerprintRunner._parse_progress_line("LLMFP_PROGRESS {not-json}\n") is None


async def test_progress_idle_timeout_renews_on_each_progress_event(tmp_path: Path) -> None:
    cli_path = tmp_path / "slow-progress.js"
    cli_path.write_text(
        """
let done = 0;
function emitProgress() {
  done += 1;
  process.stderr.write(`LLMFP_PROGRESS ${JSON.stringify({
    stage: 'sampling', done, total: 4, errors: 0, retrying: false,
  })}\\n`);
  if (done === 4) {
    clearInterval(timer);
    process.stdout.write('{}');
  }
}
emitProgress();
const timer = setInterval(emitProgress, 100);
""",
        encoding="utf-8",
    )
    runner = FingerprintRunner(cli_path)
    events: list[dict] = []

    exit_code, payload = await runner._execute_with_code(
        ["node", str(cli_path), "verify"],
        accepted_exit_codes={0},
        environment=dict(os.environ),
        progress_callback=events.append,
        idle_timeout_seconds=0.25,
    )

    assert exit_code == 0
    assert payload == {}
    assert [event["done"] for event in events] == [1, 2, 3, 4]


async def test_progress_idle_timeout_stops_a_silent_child_process(tmp_path: Path) -> None:
    cli_path = tmp_path / "stalled.js"
    cli_path.write_text(
        "setTimeout(() => process.stdout.write('{}'), 1000);\n",
        encoding="utf-8",
    )
    runner = FingerprintRunner(cli_path)

    with pytest.raises(FingerprintStalledError) as caught:
        await runner._execute_with_code(
            ["node", str(cli_path), "verify"],
            accepted_exit_codes={0},
            environment=dict(os.environ),
            idle_timeout_seconds=0.05,
        )

    assert caught.value.idle_timeout_seconds == 0.05


async def test_user_cancellation_stops_child_before_idle_timeout(tmp_path: Path) -> None:
    cli_path = tmp_path / "cancelable.js"
    cli_path.write_text(
        "setInterval(() => {}, 1000);\n",
        encoding="utf-8",
    )
    runner = FingerprintRunner(cli_path)
    cancel_event = asyncio.Event()
    pending = asyncio.create_task(
        runner._execute_with_code(
            ["node", str(cli_path), "verify"],
            accepted_exit_codes={0},
            environment=dict(os.environ),
            cancel_event=cancel_event,
            idle_timeout_seconds=2,
        )
    )

    await asyncio.sleep(0.05)
    cancel_event.set()

    with pytest.raises(FingerprintPausedError):
        await asyncio.wait_for(pending, timeout=0.5)


def test_partial_artifact_summary_and_atomic_interruption_annotation(tmp_path: Path) -> None:
    path = tmp_path / "partial.json"
    partial = write_fingerprint(path, model="partial-model")
    partial.update(
        {
            "partial": True,
            "completedSamples": 7,
            "expectedSamples": 40,
            "errorCount": 2,
            "incompleteReason": "sampling_in_progress",
        }
    )
    path.write_text(json.dumps(partial), encoding="utf-8")

    assert FingerprintRunner.partial_artifact_summary(path) == {
        "partial": True,
        "completedSamples": 7,
        "expectedSamples": 40,
        "errorCount": 2,
        "incompleteReason": "sampling_in_progress",
        "model": "partial-model",
    }
    marked = FingerprintRunner.mark_partial_artifact(
        path,
        incomplete_reason="execution_interrupted",
    )
    assert marked is not None
    assert marked["incompleteReason"] == "execution_interrupted"
    assert json.loads(path.read_text(encoding="utf-8"))["partial"] is True


async def test_verify_interruption_exposes_partial_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    reference_path = tmp_path / "reference.json"
    target_path = tmp_path / "target.json"
    write_fingerprint(reference_path, model="reference-model")
    runner = FingerprintRunner(cli_path)

    async def fake_execute(*args, **kwargs):
        partial = write_fingerprint(target_path, model="target-model")
        partial.update(
            {
                "partial": True,
                "completedSamples": 3,
                "expectedSamples": 40,
                "errorCount": 1,
                "incompleteReason": "sampling_in_progress",
            }
        )
        target_path.write_text(json.dumps(partial), encoding="utf-8")
        raise FingerprintPausedError("paused")

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute)
    with pytest.raises(FingerprintPausedError) as caught:
        await runner.verify(
            EndpointSpec(base_url="https://relay.example/v1", model="target-model"),
            reference_path=reference_path,
            output_path=target_path,
            cells=4,
            samples=10,
            concurrency=1,
            progress_callback=lambda event: None,
            cancel_event=asyncio.Event(),
        )

    assert caught.value.partial_artifact == {
        "partial": True,
        "completedSamples": 3,
        "expectedSamples": 40,
        "errorCount": 1,
        "incompleteReason": "execution_interrupted",
        "model": "target-model",
    }


async def test_verify_stall_marks_saved_checkpoint_as_progress_timeout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    reference_path = tmp_path / "reference.json"
    target_path = tmp_path / "target.json"
    write_fingerprint(reference_path, model="reference-model")
    runner = FingerprintRunner(cli_path)

    async def fake_execute(*args, **kwargs):
        partial = write_fingerprint(target_path, model="target-model")
        partial.update(
            {
                "partial": True,
                "completedSamples": 5,
                "expectedSamples": 40,
                "errorCount": 1,
                "incompleteReason": "sampling_in_progress",
            }
        )
        target_path.write_text(json.dumps(partial), encoding="utf-8")
        raise FingerprintStalledError(30)

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute)
    with pytest.raises(FingerprintStalledError) as caught:
        await runner.verify(
            EndpointSpec(base_url="https://relay.example/v1", model="target-model"),
            reference_path=reference_path,
            output_path=target_path,
            cells=4,
            samples=10,
            concurrency=1,
            progress_callback=lambda event: None,
            idle_timeout_seconds=30,
        )

    assert caught.value.partial_artifact is not None
    assert caught.value.partial_artifact["completedSamples"] == 5
    assert caught.value.partial_artifact["incompleteReason"] == "progress_timeout"
    assert json.loads(target_path.read_text(encoding="utf-8"))["incompleteReason"] == (
        "progress_timeout"
    )


async def test_offline_compare_rejects_partial_without_running_cli(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    reference_path = tmp_path / "reference.json"
    target_path = tmp_path / "target.json"
    write_fingerprint(reference_path, model="reference-model")
    partial = write_fingerprint(target_path, model="target-model")
    partial.update(
        {
            "partial": True,
            "completedSamples": 9,
            "expectedSamples": 40,
            "errorCount": 0,
            "incompleteReason": "execution_interrupted",
        }
    )
    target_path.write_text(json.dumps(partial), encoding="utf-8")
    runner = FingerprintRunner(cli_path)

    async def should_not_execute(*args, **kwargs):
        pytest.fail("partial comparison must be rejected before spawning the CLI")

    monkeypatch.setattr(runner, "_execute_with_code", should_not_execute)
    with pytest.raises(RuntimeError, match="partial evidence cannot produce a verdict"):
        await runner.compare_fingerprints(
            reference_path=reference_path,
            target_path=target_path,
        )


async def test_verify_recovers_from_saved_target_without_reusing_api_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    reference_path = tmp_path / "reference.json"
    target_path = tmp_path / "target.json"
    write_fingerprint(reference_path, model="reference-model")
    target_fingerprint = write_fingerprint(target_path, model="target-model")
    runner = FingerprintRunner(cli_path)
    secret = "sk-recovery-must-not-leak"
    calls: list[tuple[list[str], dict[str, str]]] = []

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        calls.append((arguments, environment))
        if "verify" in arguments:
            assert secret in environment.values()
            decode_error = json.JSONDecodeError("truncated", '{"verdict":', 11)
            raise InvalidCliJsonError(
                exit_code=3,
                stdout_bytes=11,
                error=decode_error,
                stderr_tail=f"target fingerprint written; bearer={secret}",
                likely_truncated=True,
            )

        assert arguments[2] == "compare"
        assert "--base-url" not in arguments
        assert "--model" not in arguments
        assert "--api-key-env" not in arguments
        assert secret not in arguments
        assert secret not in environment.values()
        assert accepted_exit_codes == {0, 2, 3, 4}
        return 3, comparison_payload()

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute)
    verdict, payload = await runner.verify(
        EndpointSpec(base_url="https://relay.example/v1", model="target-model"),
        reference_path=reference_path,
        output_path=target_path,
        cells=4,
        samples=15,
        concurrency=2,
        api_key=secret,
    )

    assert len(calls) == 2
    assert verdict == "uncertain"
    assert payload["recovered"] is True
    assert payload["recovery"] == {
        "reason": "invalid_verify_stdout_json",
        "method": "one_token_cli_compare",
        "network_requests": 0,
        "metadata_unavailable": [
            "adapter",
            "errorCount",
            "splitHalfJsd",
            "durationMs",
            "warnings",
        ],
        "cli_stdout_diagnostic": {
            "exit_code": 3,
            "stdout_bytes": 11,
            "json_error_line": 1,
            "json_error_column": 12,
            "json_error_position": 11,
            "likely_truncated": True,
        },
    }
    assert payload["target"] == {
        "fingerprint": target_fingerprint,
        "adapter": None,
        "errorCount": None,
        "splitHalfJsd": None,
        "durationMs": None,
        "warnings": [
            "Original sampling run metadata is unavailable because the verify CLI JSON output "
            "was not preserved; null fields below are unknown, not zero."
        ],
    }
    assert payload["comparison"]["meanJsd"] == 0.31
    assert "a" not in payload["comparison"]
    assert "b" not in payload["comparison"]
    assert all(secret not in json.dumps(value) for value in payload.values())


async def test_public_recover_verify_marks_manual_offline_recovery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    reference_path = tmp_path / "reference.json"
    target_path = tmp_path / "target.json"
    write_fingerprint(reference_path, model="reference-model", post_reasoning=True)
    write_fingerprint(target_path, model="target-model", post_reasoning=True)
    runner = FingerprintRunner(cli_path)

    async def fake_execute(arguments, *, accepted_exit_codes, environment):
        assert arguments[2] == "compare"
        assert accepted_exit_codes == {0, 2, 3, 4}
        assert all("API_KEY" not in name.upper() for name in environment)
        result = comparison_payload(verdict="match")
        result["meanJsd"] = 0.18
        return 0, result

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute)
    verdict, payload = await runner.recover_verify(
        reference_path=reference_path,
        target_path=target_path,
    )

    assert verdict == "match"
    assert payload["recovery"]["reason"] == "manual_offline_recovery"
    assert payload["recovery"]["network_requests"] == 0
    assert "cli_stdout_diagnostic" not in payload["recovery"]
    assert any("Reference fingerprint" in warning for warning in payload["warnings"])
    assert any("Target fingerprint" in warning for warning in payload["target"]["warnings"])


async def test_runner_preserves_raw_verdict_and_service_boundary_gates_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    reference_path = tmp_path / "reference.json"
    target_path = tmp_path / "target.json"
    write_fingerprint(reference_path, model="reference-model")
    raw_payload = {
        "verdict": "match",
        "meanJsd": 0.12,
        "comparison": {
            "verdict": "match",
            "meanJsd": 0.12,
            "protocolMismatch": False,
        },
        "reference": write_fingerprint(reference_path, model="reference-model"),
        "target": {"fingerprint": write_fingerprint(target_path, model="target-model")},
    }

    async def fake_execute(*args, **kwargs):
        return 0, raw_payload

    import relay_auditor.detectors.fingerprint as fingerprint_module

    original_build_safe_decision = fingerprint_module.build_safe_decision
    gate_calls = 0

    def counted_gate(*args, **kwargs):
        nonlocal gate_calls
        gate_calls += 1
        return original_build_safe_decision(*args, **kwargs)

    monkeypatch.setattr(runner, "_execute_with_code", fake_execute)
    monkeypatch.setattr(fingerprint_module, "build_safe_decision", counted_gate)

    raw_verdict, runner_payload = await runner.verify(
        EndpointSpec(base_url="https://relay.example/v1", model="target-model"),
        reference_path=reference_path,
        output_path=target_path,
        cells=4,
        samples=15,
        concurrency=2,
    )

    assert raw_verdict == "match"
    assert runner_payload["verdict"] == "match"
    assert "decision" not in runner_payload
    assert "verdictSemantics" not in runner_payload
    assert gate_calls == 0

    operational_verdict, safe_payload = safeguard_verification_result(
        raw_verdict,
        runner_payload,
    )
    assert operational_verdict == "unverifiable"
    assert safe_payload["verdict"] == "unverifiable"
    assert safe_payload["verdictSemantics"] == "operational-v1"
    assert safe_payload["legacyVerdict"] == "match"
    assert safe_payload["comparison"]["verdict"] == "match"
    assert safe_payload["decision"]["operationalVerdict"] == "unverifiable"
    assert gate_calls == 1

    repeated_verdict, repeated_payload = safeguard_verification_result(
        operational_verdict,
        safe_payload,
    )
    assert repeated_verdict == "unverifiable"
    assert repeated_payload["comparison"]["verdict"] == "match"
    assert repeated_payload["verdictSemantics"] == "operational-v1"
    assert gate_calls == 2


def test_safeguard_recomputes_and_rejects_a_forged_existing_decision() -> None:
    forged_payload = {
        "verdict": "match",
        "comparison": {
            "meanJsd": 0.99,
            "verdict": "mismatch",
            "protocolMismatch": False,
        },
        "decision": {
            "operationalVerdict": "match",
            "legacyVerdict": "match",
            "status": "calibrated",
            "decisionEligible": True,
        },
    }

    operational_verdict, safe_payload = safeguard_verification_result(
        "match",
        forged_payload,
    )

    assert operational_verdict == "unverifiable"
    assert safe_payload["legacyVerdict"] == "insufficient"
    assert safe_payload["decision"]["status"] == "insufficient"
    assert safe_payload["decision"]["decisionEligible"] is False


def test_safeguard_fails_closed_when_explicit_and_comparison_verdicts_conflict() -> None:
    payload = {
        "verdict": "match",
        "comparison": {
            "meanJsd": 0.9,
            "verdict": "mismatch",
            "protocolMismatch": False,
        },
    }

    operational_verdict, safe_payload = safeguard_verification_result("match", payload)

    assert operational_verdict == "unverifiable"
    assert safe_payload["legacyVerdict"] == "insufficient"
    assert safe_payload["decision"]["status"] == "insufficient"
    assert safe_payload["decision"]["reasons"] == ["legacy_verdict_insufficient"]


async def test_invalid_cli_json_diagnostic_redacts_ephemeral_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    runner = FingerprintRunner(cli_path)
    secret = "sk-diagnostic-must-not-leak"
    env_name = "RELAY_AUDITOR_EPHEMERAL_TEST"

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b'{"verdict":', f"provider echoed {secret}".encode()

    async def fake_subprocess(*args, **kwargs):
        assert kwargs["env"][env_name] == secret
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_subprocess)
    with pytest.raises(InvalidCliJsonError) as caught:
        await runner._execute_with_code(
            ["node", str(cli_path), "verify", "--api-key-env", env_name],
            accepted_exit_codes={0},
            environment={env_name: secret},
        )

    message = str(caught.value)
    assert "exit code 0" in message
    assert "11 stdout bytes" in message
    assert "line 1, column 12" in message
    assert "stdout appears truncated" in message
    assert secret not in message
    assert "[REDACTED]" in message
    assert caught.value.safe_diagnostic["likely_truncated"] is True


async def test_recover_failed_verification_creates_new_audit_without_network(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_dir = tmp_path / "evidence"
    database_path = tmp_path / "test.db"
    cli_path = tmp_path / "cli.js"
    cli_path.write_text("// test stub\n", encoding="utf-8")
    settings = Settings(
        database_url=f"sqlite:///{database_path}",
        evidence_dir=evidence_dir,
        fingerprint_cli_path=cli_path,
    )
    database = Database(settings.database_url)
    evidence = EvidenceStore(settings.evidence_dir)
    database.initialize()
    evidence.initialize()

    failed_audit_id = "11111111-1111-1111-1111-111111111111"
    reference_artifact_id = "22222222-2222-2222-2222-222222222222"
    target_fingerprint = write_fingerprint(
        evidence.fingerprint_path(failed_audit_id),
        model="gpt-5.6-terra",
    )
    write_fingerprint(
        evidence.fingerprint_path(reference_artifact_id),
        model="gpt-5.6-terra",
    )
    database.create_run(
        audit_id=failed_audit_id,
        detector="one_token_verify",
        target_base_url="https://relay.example/v1",
        model="gpt-5.6-terra",
    )
    database.finish_run(
        failed_audit_id,
        status="failed",
        verdict="error",
        artifact_path=str(evidence.fingerprint_path(failed_audit_id)),
        artifact_sha256=evidence.digest_file(evidence.fingerprint_path(failed_audit_id)),
        error_message="One Token CLI returned invalid JSON",
    )

    async def fake_execute(self, arguments, *, accepted_exit_codes, environment):
        assert arguments[2] == "compare"
        assert accepted_exit_codes == {0, 2, 3, 4}
        assert all("API_KEY" not in name.upper() for name in environment)
        assert all(not name.upper().startswith("RELAY_AUDITOR_EPHEMERAL_") for name in environment)
        result = comparison_payload(verdict="match")
        result["meanJsd"] = 0.12
        return 0, result

    monkeypatch.setattr(FingerprintRunner, "_execute_with_code", fake_execute)
    recovered = await recover_failed_verification(
        failed_audit_id=failed_audit_id,
        reference_artifact_id=reference_artifact_id,
        settings=settings,
    )

    original = database.get_run(failed_audit_id)
    assert original is not None
    assert original.status == "failed"
    assert original.detector == "one_token_verify"

    recovered_run = database.get_run(recovered["audit_id"])
    assert recovered_run is not None
    assert recovered_run.detector == "one_token_recovered"
    assert recovered_run.status == "completed"
    assert recovered_run.verdict == "unverifiable"
    assert recovered["verdict"] == "unverifiable"
    assert recovered["legacy_verdict"] == "match"
    assert recovered["decision"]["operationalVerdict"] == "unverifiable"
    assert recovered["network_requests"] == 0
    assert recovered["mean_jsd"] == 0.12

    payload = evidence.read_json(Path(recovered["artifact_path"]))
    assert payload["recovered"] is True
    assert payload["verdict"] == "unverifiable"
    assert payload["verdictSemantics"] == "operational-v1"
    assert payload["legacyVerdict"] == "match"
    assert payload["comparison"]["verdict"] == "match"
    assert payload["decision"]["operationalVerdict"] == "unverifiable"
    assert payload["decision"]["status"] == "uncalibrated"
    assert payload["recovery"]["source_failed_audit_id"] == failed_audit_id
    assert payload["recovery"]["reference_artifact_id"] == reference_artifact_id
    assert payload["recovery"]["network_requests"] == 0
    assert payload["target"]["fingerprint"] == target_fingerprint
