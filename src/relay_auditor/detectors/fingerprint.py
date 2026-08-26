import asyncio
import hashlib
import json
import math
import os
import re
import unicodedata
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from relay_auditor.one_token_decision import build_safe_decision
from relay_auditor.one_token_policy import ComparisonScope, ThresholdPolicy
from relay_auditor.schemas import EndpointSpec
from relay_auditor.secret_safety import reject_secret_artifact

_PAPER_PROTOCOL = "bruckner-2026-canonical40/v1"
_CREDENTIAL_ECHO_ERROR = (
    "One Token output was rejected because it contained a possible credential echo"
)
_PAPER_CELL_COUNT = 40
_PAPER_LANGUAGE_ORDER = ("en", "ru", "zh", "ar")
_PAPER_TASK_ORDER = (
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
_PAPER_ORDERED_CELL_IDS = tuple(
    f"{task_id}:{language}" for task_id in _PAPER_TASK_ORDER for language in _PAPER_LANGUAGE_ORDER
)
_PAPER_CELL_IDS = set(_PAPER_ORDERED_CELL_IDS)
_PAPER_MANIFEST = {
    "manifestVersion": 1,
    "protocolId": _PAPER_PROTOCOL,
    "battery": {
        "id": "bruckner-2026-canonical40",
        "version": "1.0.0",
        "digest": "sha256:9ef56c982a503b4dba94710b63866aaff47db1e37cc34538e225acb9f5fe1341",
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
        "digest": "sha256:8f755ca604e4814126c253f44135199b1636ddfedcb070fa4ece3368fb858fa8",
    },
    "sampling": {
        "temperature": 1,
        "topP": None,
        "maxTokens": 16,
        "answerConstraint": "fixed-system-single-word-or-number",
        "reasoningPolicy": "disabled-required",
    },
}
_PAPER_SCHEDULER_POLICY = "bruckner-seeded-shuffle-mulberry32-v1"
_PAPER_PROMPT_VARIANT_ID = "fixed-author-prompt/v1"
_PAPER_EVIDENCE_KEYS = {
    "evidenceVersion",
    "protocolId",
    "role",
    "schedulerSeed",
    "jobId",
    "cellId",
    "taskId",
    "language",
    "repetitionIndex",
    "promptVariantId",
    "requestedModel",
    "requestedAt",
    "receivedAt",
    "latencyMs",
    "provider",
    "reportedModel",
    "generationId",
    "finishReason",
    "raw",
    "normalized",
    "normalizationCandidate",
    "category",
    "normalizationCategory",
    "excludedFromDistribution",
    "exclusionReason",
    "reasoningTraceFields",
    "reasoningTraceCharacterCount",
    "sensitiveCredentialEchoFields",
    "usage",
    "errorKind",
}
_PAPER_USAGE_KEYS = {
    "promptTokens",
    "completionTokens",
    "reasoningTokens",
    "costUsd",
    "cachedPromptTokens",
}
_PAPER_COLLECTION_KEYS = {
    "artifactKind",
    "interpretation",
    "decisionEligible",
    "protocol",
    "model",
    "role",
    "cellCount",
    "samplesPerCell",
    "expectedSamples",
    "validSamples",
    "invalidSamples",
    "errorSamples",
    "directness",
    "splitHalfMeanJsd",
    "splitHalfComparableCells",
    "rawEvidenceSha256",
}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROTOCOL_CELL_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}:[a-z][a-z0-9-]{0,31}$")


def _is_non_negative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _require_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _require_non_empty_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{label} must be a non-empty string")
    return value


def _require_non_negative_integer(value: Any, *, label: str) -> int:
    if not _is_non_negative_integer(value):
        raise RuntimeError(f"{label} must be a non-negative integer")
    return value


def _require_positive_integer(value: Any, *, label: str) -> int:
    parsed = _require_non_negative_integer(value, label=label)
    if parsed == 0:
        raise RuntimeError(f"{label} must be greater than zero")
    return parsed


def _require_finite_number(value: Any, *, label: str, minimum: float = 0) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < minimum
    ):
        raise RuntimeError(f"{label} must be a finite number greater than or equal to {minimum}")
    return float(value)


class InvalidCliJsonError(RuntimeError):
    """The CLI completed, but its machine-readable stdout was not valid JSON."""

    def __init__(
        self,
        *,
        exit_code: int,
        stdout_bytes: int,
        error: json.JSONDecodeError,
        stderr_tail: str,
        likely_truncated: bool,
    ) -> None:
        self.safe_diagnostic: dict[str, Any] = {
            "exit_code": exit_code,
            "stdout_bytes": stdout_bytes,
            "json_error_line": error.lineno,
            "json_error_column": error.colno,
            "json_error_position": error.pos,
            "likely_truncated": likely_truncated,
        }
        state = "stdout appears truncated" if likely_truncated else "stdout is malformed"
        stderr_detail = stderr_tail or "(empty stderr)"
        super().__init__(
            "One Token CLI returned invalid JSON "
            f"(exit code {exit_code}, {stdout_bytes} stdout bytes, "
            f"JSON error at line {error.lineno}, column {error.colno}; {state}). "
            f"stderr tail: {stderr_detail}"
        )


class FingerprintPausedError(RuntimeError):
    """The active CLI process was stopped because its batch was paused."""

    def __init__(
        self,
        message: str,
        *,
        partial_artifact: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.partial_artifact = partial_artifact


class FingerprintStalledError(RuntimeError):
    """The CLI was stopped after producing no observable progress for too long."""

    def __init__(
        self,
        idle_timeout_seconds: float,
        *,
        partial_artifact: dict[str, Any] | None = None,
    ) -> None:
        self.idle_timeout_seconds = idle_timeout_seconds
        self.partial_artifact = partial_artifact
        super().__init__(
            "One Token CLI produced no progress for "
            f"{idle_timeout_seconds:g} seconds and was stopped"
        )


def safeguard_verification_result(
    verdict: str,
    payload: dict[str, Any],
    *,
    reference_metadata: dict[str, Any] | None = None,
    threshold_policy: ThresholdPolicy | None = None,
    comparison_scope: ComparisonScope | None = None,
    raw_evidence_jsonl: dict[str, bytes] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Attach the fail-closed operational decision without losing raw CLI evidence."""

    # Never trust a decision embedded in input evidence. Recompute the operational
    # result on every call so a forged or stale decision cannot bypass current gates.
    comparison = payload.get("comparison")
    comparison_verdict = comparison.get("verdict") if isinstance(comparison, dict) else None
    legacy_values = {"match", "uncertain", "mismatch", "insufficient"}
    if (
        verdict in legacy_values
        and comparison_verdict in legacy_values
        and verdict != comparison_verdict
    ):
        legacy_verdict = "insufficient"
    elif comparison_verdict in legacy_values:
        legacy_verdict = str(comparison_verdict)
    elif verdict in legacy_values:
        legacy_verdict = verdict
    else:
        legacy_verdict = "insufficient"
    decision = build_safe_decision(
        payload,
        legacy_verdict=legacy_verdict,
        reference_metadata=reference_metadata,
        threshold_policy=threshold_policy,
        comparison_scope=comparison_scope,
        raw_evidence_jsonl=raw_evidence_jsonl,
    )
    operational_verdict = str(decision["operationalVerdict"])
    safe_payload = {
        **payload,
        "legacyVerdict": legacy_verdict,
        "verdict": operational_verdict,
        "verdictSemantics": "operational-v1",
        "decision": decision,
    }
    return operational_verdict, safe_payload


class FingerprintRunner:
    def __init__(self, cli_path: Path) -> None:
        self.cli_path = cli_path.resolve()

    def ensure_ready(self) -> None:
        if not self.cli_path.is_file():
            raise FileNotFoundError(
                f"One Token CLI not built: {self.cli_path}. "
                "Run `cd llm-fingerprint-detector && npm ci && npm run build`."
            )

    async def collect(
        self,
        endpoint: EndpointSpec,
        *,
        output_path: Path,
        cells: int,
        samples: int,
        concurrency: int,
        api_key: str | None = None,
    ) -> dict[str, Any]:
        arguments, environment, credential = self._base_arguments(
            endpoint,
            cells,
            samples,
            concurrency,
            subcommand="fingerprint",
            api_key=api_key,
        )
        arguments.extend(["--out", str(output_path), "--json", "--quiet"])
        try:
            payload = await self._execute(
                arguments,
                accepted_exit_codes={0},
                environment=environment,
            )
        except asyncio.CancelledError:
            self._discard_credential_echo(output_path, credential=credential)
            raise
        except Exception as error:
            if self._discard_credential_echo(output_path, credential=credential):
                raise RuntimeError(_CREDENTIAL_ECHO_ERROR) from error
            raise
        if self._discard_credential_echo(
            output_path,
            payload=payload,
            credential=credential,
        ):
            raise RuntimeError(_CREDENTIAL_ECHO_ERROR)
        return payload

    async def collect_paper_profile(
        self,
        endpoint: EndpointSpec,
        *,
        role: str,
        scheduler_seed: str,
        output_path: Path,
        samples_output_path: Path,
        samples: int = 30,
        concurrency: int,
        timeout: int = 90_000,
        api_key: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: asyncio.Event | None = None,
        idle_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Explicitly collect the pinned paper profile and verify its evidence contract.

        The JSONL sample evidence remains on disk. Only the CLI's aggregate V2
        fingerprint and non-decision collection summary are returned.
        """

        self.ensure_ready()
        if role not in {"enrollment", "audit"}:
            raise ValueError('role must be "enrollment" or "audit"')
        if not isinstance(scheduler_seed, str) or not scheduler_seed.strip():
            raise ValueError("scheduler_seed must be a non-empty string")
        if len(scheduler_seed) > 256:
            raise ValueError("scheduler_seed must be at most 256 characters")
        if not _is_non_negative_integer(samples) or samples == 0:
            raise ValueError("samples must be a positive integer")
        if not _is_non_negative_integer(concurrency) or concurrency == 0:
            raise ValueError("concurrency must be a positive integer")
        if not _is_non_negative_integer(timeout) or timeout < 100:
            raise ValueError("timeout must be an integer greater than or equal to 100 ms")

        fingerprint_path = output_path.resolve()
        samples_path = samples_output_path.resolve()
        if fingerprint_path == samples_path:
            raise ValueError("output_path and samples_output_path must be different files")
        if samples_path.suffix != ".jsonl":
            raise ValueError("samples_output_path must use the .jsonl extension")

        fingerprint_path.parent.mkdir(parents=True, exist_ok=True)
        samples_path.parent.mkdir(parents=True, exist_ok=True)
        run_token = uuid4().hex
        temporary_fingerprint_path = fingerprint_path.with_name(
            f".{fingerprint_path.name}.{run_token}.tmp"
        )
        temporary_samples_path = samples_path.with_name(
            f".{samples_path.stem}.{run_token}.tmp.jsonl"
        )

        credential_arguments, environment, credential = self._credential_arguments(
            endpoint,
            api_key=api_key,
        )
        arguments = [
            "node",
            str(self.cli_path),
            "paper-fingerprint",
            "--base-url",
            str(endpoint.base_url).rstrip("/"),
            "--model",
            endpoint.model,
            *credential_arguments,
            "--role",
            role,
            "--scheduler-seed",
            scheduler_seed,
            "--samples",
            str(samples),
            "--concurrency",
            str(concurrency),
            "--timeout",
            str(timeout),
            "--out",
            str(temporary_fingerprint_path),
            "--samples-out",
            str(temporary_samples_path),
            "--json",
        ]
        if progress_callback is None and idle_timeout_seconds is None:
            arguments.append("--quiet")
        if credential and any(credential in argument for argument in arguments):
            raise RuntimeError("paper-fingerprint API key must not appear in process arguments")

        try:
            if progress_callback is None and cancel_event is None and idle_timeout_seconds is None:
                payload = await self._execute(
                    arguments,
                    accepted_exit_codes={0},
                    environment=environment,
                )
            else:
                _, payload = await self._execute_with_code(
                    arguments,
                    accepted_exit_codes={0},
                    environment=environment,
                    progress_callback=progress_callback,
                    cancel_event=cancel_event,
                    idle_timeout_seconds=idle_timeout_seconds,
                )
            validated = self._validate_paper_collection(
                payload,
                output_path=temporary_fingerprint_path,
                samples_output_path=temporary_samples_path,
                endpoint=endpoint,
                role=role,
                scheduler_seed=scheduler_seed,
                samples=samples,
                credential=credential,
            )
            self._commit_paper_artifact_pair(
                temporary_fingerprint_path=temporary_fingerprint_path,
                temporary_samples_path=temporary_samples_path,
                fingerprint_path=fingerprint_path,
                samples_path=samples_path,
            )
            return validated
        except FingerprintPausedError as error:
            error.partial_artifact = self._preserve_paper_partial_collection(
                temporary_fingerprint_path=temporary_fingerprint_path,
                temporary_samples_path=temporary_samples_path,
                fingerprint_path=fingerprint_path,
                samples_path=samples_path,
                endpoint=endpoint,
                role=role,
                scheduler_seed=scheduler_seed,
                samples=samples,
                credential=credential,
                incomplete_reason="execution_interrupted",
            )
            raise
        except FingerprintStalledError as error:
            error.partial_artifact = self._preserve_paper_partial_collection(
                temporary_fingerprint_path=temporary_fingerprint_path,
                temporary_samples_path=temporary_samples_path,
                fingerprint_path=fingerprint_path,
                samples_path=samples_path,
                endpoint=endpoint,
                role=role,
                scheduler_seed=scheduler_seed,
                samples=samples,
                credential=credential,
                incomplete_reason="progress_timeout",
            )
            raise
        except asyncio.CancelledError:
            self._preserve_paper_partial_collection(
                temporary_fingerprint_path=temporary_fingerprint_path,
                temporary_samples_path=temporary_samples_path,
                fingerprint_path=fingerprint_path,
                samples_path=samples_path,
                endpoint=endpoint,
                role=role,
                scheduler_seed=scheduler_seed,
                samples=samples,
                credential=credential,
                incomplete_reason="execution_interrupted",
            )
            raise
        finally:
            temporary_fingerprint_path.unlink(missing_ok=True)
            temporary_samples_path.unlink(missing_ok=True)

    @staticmethod
    def _commit_paper_artifact_pair(
        *,
        temporary_fingerprint_path: Path,
        temporary_samples_path: Path,
        fingerprint_path: Path,
        samples_path: Path,
    ) -> None:
        """Commit both outputs together, restoring the previous pair on failure."""

        token = uuid4().hex
        fingerprint_backup = fingerprint_path.with_name(f".{fingerprint_path.name}.{token}.backup")
        samples_backup = samples_path.with_name(f".{samples_path.name}.{token}.backup")
        fingerprint_backed_up = False
        samples_backed_up = False
        fingerprint_promoted = False
        samples_promoted = False
        try:
            if fingerprint_path.exists():
                fingerprint_path.replace(fingerprint_backup)
                fingerprint_backed_up = True
            if samples_path.exists():
                samples_path.replace(samples_backup)
                samples_backed_up = True
            temporary_samples_path.replace(samples_path)
            samples_promoted = True
            temporary_fingerprint_path.replace(fingerprint_path)
            fingerprint_promoted = True
        except Exception as error:
            if fingerprint_promoted:
                fingerprint_path.unlink(missing_ok=True)
            if samples_promoted:
                samples_path.unlink(missing_ok=True)
            restore_errors: list[Exception] = []
            if fingerprint_backed_up:
                try:
                    fingerprint_backup.replace(fingerprint_path)
                    fingerprint_backed_up = False
                except Exception as restore_error:  # pragma: no cover - catastrophic FS failure
                    restore_errors.append(restore_error)
            if samples_backed_up:
                try:
                    samples_backup.replace(samples_path)
                    samples_backed_up = False
                except Exception as restore_error:  # pragma: no cover - catastrophic FS failure
                    restore_errors.append(restore_error)
            if restore_errors:
                raise RuntimeError(
                    "paper-fingerprint output commit failed and prior artifacts "
                    "could not be fully restored"
                ) from error
            raise
        else:
            fingerprint_backup.unlink(missing_ok=True)
            samples_backup.unlink(missing_ok=True)

    @classmethod
    def _preserve_paper_partial_collection(
        cls,
        *,
        temporary_fingerprint_path: Path,
        temporary_samples_path: Path,
        fingerprint_path: Path,
        samples_path: Path,
        endpoint: EndpointSpec,
        role: str,
        scheduler_seed: str,
        samples: int,
        credential: str | None,
        incomplete_reason: str,
    ) -> dict[str, Any] | None:
        """Validate and promote a credential-free V2 checkpoint after interruption."""

        try:
            evidence_bytes = temporary_samples_path.read_bytes()
            fingerprint = cls._load_fingerprint(
                temporary_fingerprint_path,
                label="partial paper fingerprint artifact",
            )
            if credential:
                evidence_values = [
                    json.loads(line)
                    for line in evidence_bytes.decode("utf-8").splitlines()
                ]
                if cls._contains_credential_echo(
                    fingerprint,
                    credential=credential,
                ) or cls._contains_credential_echo(
                    evidence_values,
                    credential=credential,
                ):
                    return None
            if fingerprint.get("formatVersion") != 2 or fingerprint.get("partial") is not True:
                return None
            plan = fingerprint["plan"]
            quality = fingerprint["quality"]
            expected_samples = _PAPER_CELL_COUNT * samples
            completed = quality.get("completedSamples")
            if (
                fingerprint.get("protocol") != _PAPER_PROTOCOL
                or fingerprint.get("model") != endpoint.model
                or fingerprint.get("manifest") != _PAPER_MANIFEST
                or fingerprint.get("postReasoning") is not False
                or tuple(plan.get("cellIds", ())) != _PAPER_ORDERED_CELL_IDS
                or plan.get("role") != role
                or plan.get("schedulerSeed") != scheduler_seed
                or plan.get("schedulerPolicy") != _PAPER_SCHEDULER_POLICY
                or fingerprint.get("samplesPerCell") != samples
                or plan.get("samplesPerCell") != samples
                or plan.get("expectedSamples") != expected_samples
                or quality.get("expectedSamples") != expected_samples
                or quality.get("complete") is not False
                or not _is_non_negative_integer(completed)
                or completed == 0
                or completed >= expected_samples
                or fingerprint.get("completedSamples") != completed
                or fingerprint.get("expectedSamples") != expected_samples
                or fingerprint.get("errorCount") != quality.get("errorSamples")
            ):
                return None
            raw_evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
            if quality.get("rawEvidenceSha256") != raw_evidence_sha:
                return None

            evidence_summary = cls._validate_paper_evidence_jsonl(
                evidence_bytes,
                protocol=_PAPER_PROTOCOL,
                model=endpoint.model,
                role=role,
                scheduler_seed=scheduler_seed,
                samples=samples,
                cell_ids=set(_PAPER_ORDERED_CELL_IDS),
                expected_completed=completed,
            )
            for category in ("valid", "invalid", "refusal", "empty", "error"):
                if evidence_summary[category] != quality.get(f"{category}Samples"):
                    return None
            if evidence_summary["reasoningTrace"] != quality.get("reasoningTraceCount"):
                return None
            if evidence_summary["reasoningTokens"] != quality.get("reasoningTokenCount"):
                return None
            if evidence_summary["reasoningUsageObserved"] != quality.get(
                "reasoningUsageObservedSamples"
            ):
                return None
            contaminated = (
                evidence_summary["reasoningTrace"] > 0
                or evidence_summary["reasoningTokens"] > 0
            )
            expected_directness = (
                "violated"
                if contaminated
                else "unknown"
                if (
                    evidence_summary["error"] > 0
                    or evidence_summary["reasoningUsageObserved"]
                    != evidence_summary["observableResponse"]
                )
                else "verified"
            )
            if quality.get("directness") != expected_directness:
                return None
            evidence_cells = evidence_summary["cells"]
            for cell_id in _PAPER_ORDERED_CELL_IDS:
                fingerprint_cell = fingerprint["cells"][cell_id]
                evidence_cell = evidence_cells[cell_id]
                for category in ("valid", "invalid", "refusal", "empty", "error"):
                    if fingerprint_cell[f"{category}Count"] != evidence_cell[category]:
                        return None
                if (
                    fingerprint_cell["totalCount"] != evidence_cell["total"]
                    or fingerprint_cell["counts"] != evidence_cell["counts"]
                ):
                    return None

            marked = cls.mark_partial_artifact(
                temporary_fingerprint_path,
                incomplete_reason=incomplete_reason,
            )
            if marked is None or marked["incompleteReason"] != incomplete_reason:
                return None
            cls._commit_paper_artifact_pair(
                temporary_fingerprint_path=temporary_fingerprint_path,
                temporary_samples_path=temporary_samples_path,
                fingerprint_path=fingerprint_path,
                samples_path=samples_path,
            )
            return cls.partial_artifact_summary(fingerprint_path)
        except (
            OSError,
            RuntimeError,
            KeyError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return None

    async def verify(
        self,
        endpoint: EndpointSpec,
        *,
        reference_path: Path,
        output_path: Path,
        cells: int,
        samples: int,
        concurrency: int,
        api_key: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: asyncio.Event | None = None,
        request_timeout_ms: int | None = None,
        idle_timeout_seconds: float | None = None,
    ) -> tuple[str, dict[str, Any]]:
        arguments, environment, credential = self._base_arguments(
            endpoint,
            cells,
            samples,
            concurrency,
            subcommand="verify",
            api_key=api_key,
        )
        if request_timeout_ms is not None:
            arguments.extend(["--timeout", str(request_timeout_ms)])
        arguments.extend(
            [
                "--reference",
                str(reference_path),
                "--out",
                str(output_path),
                "--json",
            ]
        )
        if progress_callback is None and idle_timeout_seconds is None:
            arguments.append("--quiet")
        try:
            if progress_callback is None and cancel_event is None and idle_timeout_seconds is None:
                exit_code, payload = await self._execute_with_code(
                    arguments,
                    accepted_exit_codes={0, 2, 3, 4},
                    environment=environment,
                )
            else:
                exit_code, payload = await self._execute_with_code(
                    arguments,
                    accepted_exit_codes={0, 2, 3, 4},
                    environment=environment,
                    progress_callback=progress_callback,
                    cancel_event=cancel_event,
                    idle_timeout_seconds=idle_timeout_seconds,
                )
        except FingerprintPausedError as error:
            if self._discard_credential_echo(output_path, credential=credential):
                raise RuntimeError(_CREDENTIAL_ECHO_ERROR) from error
            summary = self.mark_partial_artifact(
                output_path,
                incomplete_reason="execution_interrupted",
            )
            error.partial_artifact = summary
            raise
        except asyncio.CancelledError:
            self._discard_credential_echo(output_path, credential=credential)
            self.mark_partial_artifact(
                output_path,
                incomplete_reason="execution_interrupted",
            )
            raise
        except FingerprintStalledError as error:
            if self._discard_credential_echo(output_path, credential=credential):
                raise RuntimeError(_CREDENTIAL_ECHO_ERROR) from error
            summary = self.mark_partial_artifact(
                output_path,
                incomplete_reason="progress_timeout",
            )
            error.partial_artifact = summary
            raise
        except InvalidCliJsonError as error:
            if self._discard_credential_echo(output_path, credential=credential):
                raise RuntimeError(_CREDENTIAL_ECHO_ERROR) from error
            try:
                recovered_verdict, recovered_payload = await self._recover_verify(
                    reference_path=reference_path,
                    target_path=output_path,
                    recovery_reason="invalid_verify_stdout_json",
                    cli_stdout_diagnostic=error.safe_diagnostic,
                )
                reject_secret_artifact(
                    recovered_payload,
                    credential,
                    paths=(output_path,),
                    source="One Token fingerprint recovery",
                )
                return recovered_verdict, recovered_payload
            except Exception as recovery_error:
                raise RuntimeError(
                    f"{error} Offline recovery from the saved target fingerprint failed: "
                    f"{recovery_error}"
                ) from error
        except Exception as error:
            if self._discard_credential_echo(output_path, credential=credential):
                raise RuntimeError(_CREDENTIAL_ECHO_ERROR) from error
            raise
        if self._discard_credential_echo(
            output_path,
            payload=payload,
            credential=credential,
        ):
            raise RuntimeError(_CREDENTIAL_ECHO_ERROR)
        verdict_by_exit = {0: "match", 2: "mismatch", 3: "uncertain", 4: "insufficient"}
        legacy_verdict = verdict_by_exit[exit_code]
        payload_verdict = payload.get("verdict")
        comparison = payload.get("comparison")
        comparison_verdict = comparison.get("verdict") if isinstance(comparison, dict) else None
        if payload_verdict != legacy_verdict or comparison_verdict != legacy_verdict:
            raise RuntimeError(
                "One Token verify returned a verdict inconsistent with its exit code"
            )
        return legacy_verdict, payload

    async def recover_verify(
        self,
        *,
        reference_path: Path,
        target_path: Path,
    ) -> tuple[str, dict[str, Any]]:
        """Rebuild a verify result from two saved fingerprints without network access.

        This is intentionally public so an already-failed audit whose target artifact
        survived can be recovered without sampling the endpoint again.
        """

        return await self._recover_verify(
            reference_path=reference_path,
            target_path=target_path,
            recovery_reason="manual_offline_recovery",
            cli_stdout_diagnostic=None,
        )

    async def compare_fingerprints(
        self,
        *,
        reference_path: Path,
        target_path: Path,
    ) -> dict[str, Any]:
        """Compare two local fingerprints without accepting endpoint credentials."""

        self.ensure_ready()
        reference = self._load_fingerprint(reference_path, label="reference fingerprint")
        target = self._load_fingerprint(target_path, label="target fingerprint")
        paper_v2_comparison = (
            reference.get("formatVersion") == 2 or target.get("formatVersion") == 2
        )
        for label, fingerprint in (
            ("reference fingerprint", reference),
            ("target fingerprint", target),
        ):
            if fingerprint.get("partial") is True:
                completed = fingerprint.get("completedSamples", 0)
                expected = fingerprint.get("expectedSamples", "?")
                raise RuntimeError(
                    f"{label} is incomplete ({completed}/{expected} samples); "
                    "partial evidence cannot produce a verdict"
                )
        arguments = [
            "node",
            str(self.cli_path),
            "compare",
            str(reference_path.resolve()),
            str(target_path.resolve()),
            "--json",
        ]
        exit_code, raw_comparison = await self._execute_with_code(
            arguments,
            accepted_exit_codes={0, 2, 3, 4},
            environment=self._offline_environment(),
        )
        comparison = {key: value for key, value in raw_comparison.items() if key not in {"a", "b"}}
        verdict = comparison.get("verdict")
        verdict_by_exit = {0: "match", 2: "mismatch", 3: "uncertain", 4: "insufficient"}
        if verdict not in verdict_by_exit.values():
            raise RuntimeError("One Token offline compare returned an invalid verdict")
        if verdict_by_exit[exit_code] != verdict:
            raise RuntimeError(
                "One Token offline compare returned a verdict inconsistent with its exit code"
            )
        result = {
            **comparison,
            "method": "one_token_cli_compare",
            "networkRequests": 0,
        }
        if paper_v2_comparison:
            result.update(
                {
                    "interpretation": "uncalibrated-non-decision-evidence",
                    "decisionEligible": False,
                    "verdictSemantics": "legacy-exploratory",
                }
            )
        return result

    async def compare_paper_fingerprints(
        self,
        *,
        enrollment_path: Path,
        audit_path: Path,
    ) -> dict[str, Any]:
        """Compare two complete paper V2 artifacts as exploratory evidence only."""

        for path, label in (
            (enrollment_path, "paper enrollment fingerprint"),
            (audit_path, "paper audit fingerprint"),
        ):
            fingerprint = self._load_fingerprint(path, label=label)
            if fingerprint.get("formatVersion") != 2:
                raise RuntimeError(f"{label} must use formatVersion 2")
            if fingerprint.get("protocol") != _PAPER_PROTOCOL:
                raise RuntimeError(f"{label} does not use the paper profile protocol")
        return await self.compare_fingerprints(
            reference_path=enrollment_path,
            target_path=audit_path,
        )

    async def _recover_verify(
        self,
        *,
        reference_path: Path,
        target_path: Path,
        recovery_reason: str,
        cli_stdout_diagnostic: dict[str, Any] | None,
    ) -> tuple[str, dict[str, Any]]:
        reference = self._load_fingerprint(reference_path, label="reference fingerprint")
        target = self._load_fingerprint(target_path, label="target fingerprint")
        comparison = await self.compare_fingerprints(
            reference_path=reference_path,
            target_path=target_path,
        )
        verdict = comparison["verdict"]

        unavailable = ["adapter", "errorCount", "splitHalfJsd", "durationMs", "warnings"]
        run_warnings = [
            "Original sampling run metadata is unavailable because the verify CLI JSON output "
            "was not preserved; null fields below are unknown, not zero."
        ]
        if target.get("postReasoning") is True:
            run_warnings.append(
                "Target fingerprint was collected over the post-reasoning channel "
                "(reduced confidence)."
            )

        warnings = [
            "Verification result recovered from saved fingerprint artifacts using the local "
            "One Token compare command; no endpoint requests were made during recovery."
        ]
        if comparison.get("protocolMismatch") is True:
            warnings.append(
                f'Protocol mismatch: target "{target.get("protocol", "unknown")}" vs '
                f'reference "{reference.get("protocol", "unknown")}". Fingerprints collected '
                "under different prompts/batteries are only loosely comparable."
            )
        if reference.get("postReasoning") is True:
            warnings.append(
                "Reference fingerprint was collected over the post-reasoning channel "
                "(reduced confidence)."
            )

        recovery: dict[str, Any] = {
            "reason": recovery_reason,
            "method": "one_token_cli_compare",
            "network_requests": 0,
            "metadata_unavailable": unavailable,
        }
        if cli_stdout_diagnostic is not None:
            recovery["cli_stdout_diagnostic"] = cli_stdout_diagnostic

        payload: dict[str, Any] = {
            "verdict": verdict,
            "meanJsd": comparison.get("meanJsd"),
            "comparison": comparison,
            "target": {
                "fingerprint": target,
                "adapter": None,
                "errorCount": None,
                "splitHalfJsd": None,
                "durationMs": None,
                "warnings": run_warnings,
            },
            "reference": reference,
            "warnings": warnings,
            "recovered": True,
            "recovery": recovery,
        }
        return str(verdict), payload

    @classmethod
    def _validate_v2_fingerprint(
        cls,
        payload: dict[str, Any],
        *,
        label: str,
    ) -> dict[str, Any]:
        allowed_root_keys = {
            "formatVersion",
            "protocol",
            "model",
            "collectedAt",
            "samplesPerCell",
            "postReasoning",
            "cells",
            "manifest",
            "plan",
            "quality",
            "partial",
            "completedSamples",
            "expectedSamples",
            "errorCount",
            "incompleteReason",
            "meta",
        }
        unknown_root_keys = set(payload) - allowed_root_keys
        if unknown_root_keys:
            raise RuntimeError(
                f"{label} contains unsupported V2 fields: {sorted(unknown_root_keys)}"
            )

        protocol = _require_non_empty_string(payload.get("protocol"), label=f"{label}.protocol")
        _require_non_empty_string(payload.get("model"), label=f"{label}.model")
        collected_at = _require_non_empty_string(
            payload.get("collectedAt"),
            label=f"{label}.collectedAt",
        )
        try:
            parsed_timestamp = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise RuntimeError(f"{label}.collectedAt must be an ISO-8601 timestamp") from error
        if parsed_timestamp.tzinfo is None:
            raise RuntimeError(f"{label}.collectedAt must include a timezone")

        samples_per_cell = _require_positive_integer(
            payload.get("samplesPerCell"),
            label=f"{label}.samplesPerCell",
        )
        if not isinstance(payload.get("postReasoning"), bool):
            raise RuntimeError(f"{label}.postReasoning must be a boolean")
        if "partial" in payload and payload["partial"] is not True:
            raise RuntimeError(f"{label}.partial may only be true when present")
        partial = payload.get("partial") is True

        manifest = _require_mapping(payload.get("manifest"), label=f"{label}.manifest")
        if set(manifest) != {
            "manifestVersion",
            "protocolId",
            "battery",
            "prompts",
            "normalization",
            "sampling",
        }:
            raise RuntimeError(f"{label}.manifest has an unsupported shape")
        if manifest.get("manifestVersion") != 1:
            raise RuntimeError(f"{label}.manifest.manifestVersion must equal 1")
        if manifest.get("protocolId") != protocol:
            raise RuntimeError(f"{label}.manifest.protocolId must equal protocol")
        battery = _require_mapping(manifest.get("battery"), label=f"{label}.manifest.battery")
        normalization = _require_mapping(
            manifest.get("normalization"),
            label=f"{label}.manifest.normalization",
        )
        prompts = _require_mapping(manifest.get("prompts"), label=f"{label}.manifest.prompts")
        sampling = _require_mapping(manifest.get("sampling"), label=f"{label}.manifest.sampling")
        if set(battery) != {"id", "version", "digest"}:
            raise RuntimeError(f"{label}.manifest.battery has an unsupported shape")
        if set(normalization) != {"id", "version", "digest"}:
            raise RuntimeError(f"{label}.manifest.normalization has an unsupported shape")
        if set(prompts) != {"systemPromptDigest", "templateDigest"}:
            raise RuntimeError(f"{label}.manifest.prompts has an unsupported shape")
        if set(sampling) != {
            "temperature",
            "topP",
            "maxTokens",
            "answerConstraint",
            "reasoningPolicy",
        }:
            raise RuntimeError(f"{label}.manifest.sampling has an unsupported shape")
        for scope_name, scope in (("battery", battery), ("normalization", normalization)):
            _require_non_empty_string(scope.get("id"), label=f"{label}.manifest.{scope_name}.id")
            _require_non_empty_string(
                scope.get("version"),
                label=f"{label}.manifest.{scope_name}.version",
            )
            digest = _require_non_empty_string(
                scope.get("digest"),
                label=f"{label}.manifest.{scope_name}.digest",
            )
            if not _DIGEST_PATTERN.fullmatch(digest):
                raise RuntimeError(f"{label}.manifest.{scope_name}.digest must be a sha256 digest")
        for key in ("systemPromptDigest", "templateDigest"):
            digest = _require_non_empty_string(
                prompts.get(key),
                label=f"{label}.manifest.prompts.{key}",
            )
            if not _DIGEST_PATTERN.fullmatch(digest):
                raise RuntimeError(f"{label}.manifest.prompts.{key} must be a sha256 digest")
        _require_finite_number(
            sampling.get("temperature"),
            label=f"{label}.manifest.sampling.temperature",
        )
        top_p = sampling.get("topP")
        if top_p is not None:
            parsed_top_p = _require_finite_number(
                top_p,
                label=f"{label}.manifest.sampling.topP",
            )
            if parsed_top_p > 1:
                raise RuntimeError(f"{label}.manifest.sampling.topP must not exceed 1")
        _require_positive_integer(
            sampling.get("maxTokens"),
            label=f"{label}.manifest.sampling.maxTokens",
        )
        _require_non_empty_string(
            sampling.get("answerConstraint"),
            label=f"{label}.manifest.sampling.answerConstraint",
        )
        _require_non_empty_string(
            sampling.get("reasoningPolicy"),
            label=f"{label}.manifest.sampling.reasoningPolicy",
        )

        plan = _require_mapping(payload.get("plan"), label=f"{label}.plan")
        if set(plan) != {
            "planVersion",
            "role",
            "cellIds",
            "samplesPerCell",
            "expectedSamples",
            "schedulerSeed",
            "schedulerPolicy",
        }:
            raise RuntimeError(f"{label}.plan has an unsupported shape")
        if plan.get("planVersion") != 1:
            raise RuntimeError(f"{label}.plan.planVersion must equal 1")
        if plan.get("role") not in {"enrollment", "audit"}:
            raise RuntimeError(f"{label}.plan.role must be enrollment or audit")
        cell_ids = plan.get("cellIds")
        if not isinstance(cell_ids, list) or not cell_ids:
            raise RuntimeError(f"{label}.plan.cellIds must be a non-empty array")
        if any(
            not isinstance(cell_id, str)
            or len(cell_id) > 96
            or not _PROTOCOL_CELL_ID_PATTERN.fullmatch(cell_id)
            for cell_id in cell_ids
        ):
            raise RuntimeError(f"{label}.plan.cellIds contains an invalid protocol cell id")
        if len(set(cell_ids)) != len(cell_ids):
            raise RuntimeError(f"{label}.plan.cellIds must not contain duplicates")
        plan_samples = _require_positive_integer(
            plan.get("samplesPerCell"),
            label=f"{label}.plan.samplesPerCell",
        )
        if plan_samples != samples_per_cell:
            raise RuntimeError(f"{label}.plan.samplesPerCell must equal samplesPerCell")
        plan_expected = _require_non_negative_integer(
            plan.get("expectedSamples"),
            label=f"{label}.plan.expectedSamples",
        )
        if plan_expected != len(cell_ids) * plan_samples:
            raise RuntimeError(
                f"{label}.plan.expectedSamples must equal cell count times samplesPerCell"
            )
        scheduler_seed = _require_non_empty_string(
            plan.get("schedulerSeed"),
            label=f"{label}.plan.schedulerSeed",
        )
        if len(scheduler_seed) > 256:
            raise RuntimeError(f"{label}.plan.schedulerSeed must be at most 256 characters")
        if plan.get("schedulerPolicy") not in {
            "repetition-index-seeded",
            "bruckner-seeded-shuffle-mulberry32-v1",
        }:
            raise RuntimeError(f"{label}.plan.schedulerPolicy is unsupported")

        cells = _require_mapping(payload.get("cells"), label=f"{label}.cells")
        if set(cells) != set(cell_ids):
            raise RuntimeError(f"{label}.cells keys must exactly match plan.cellIds")
        aggregate = {name: 0 for name in ("valid", "invalid", "refusal", "empty", "error", "total")}
        allowed_cell_keys = {
            "cellId",
            "counts",
            "validCount",
            "invalidCount",
            "refusalCount",
            "emptyCount",
            "errorCount",
            "totalCount",
            "entropyBits",
            "normalizedEntropy",
            "medianLatencyMs",
            "meanCompletionTokens",
            "meanReasoningTokens",
        }
        for cell_id in cell_ids:
            cell = _require_mapping(cells[cell_id], label=f"{label}.cells.{cell_id}")
            if set(cell) != allowed_cell_keys:
                raise RuntimeError(f"{label}.cells.{cell_id} has an unsupported shape")
            if cell.get("cellId") != cell_id:
                raise RuntimeError(f"{label}.cells.{cell_id}.cellId must equal its key")
            counts = _require_mapping(
                cell.get("counts"),
                label=f"{label}.cells.{cell_id}.counts",
            )
            count_total = 0
            for answer, count in counts.items():
                if not isinstance(answer, str):
                    raise RuntimeError(f"{label}.cells.{cell_id}.counts keys must be strings")
                count_total += _require_non_negative_integer(
                    count,
                    label=f"{label}.cells.{cell_id}.counts.{answer}",
                )
            parsed_counts = {
                name: _require_non_negative_integer(
                    cell.get(f"{name}Count"),
                    label=f"{label}.cells.{cell_id}.{name}Count",
                )
                for name in ("valid", "invalid", "refusal", "empty", "error", "total")
            }
            if count_total != parsed_counts["valid"]:
                raise RuntimeError(f"{label}.cells.{cell_id}.counts must sum to validCount")
            category_total = sum(
                parsed_counts[name] for name in ("valid", "invalid", "refusal", "empty", "error")
            )
            if category_total != parsed_counts["total"]:
                raise RuntimeError(
                    f"{label}.cells.{cell_id} category counts must sum to totalCount"
                )
            for name in aggregate:
                aggregate[name] += parsed_counts[name]
            _require_finite_number(
                cell.get("entropyBits"),
                label=f"{label}.cells.{cell_id}.entropyBits",
            )
            normalized_entropy = _require_finite_number(
                cell.get("normalizedEntropy"),
                label=f"{label}.cells.{cell_id}.normalizedEntropy",
            )
            if normalized_entropy > 1:
                raise RuntimeError(f"{label}.cells.{cell_id}.normalizedEntropy must not exceed 1")
            for key in ("medianLatencyMs", "meanCompletionTokens", "meanReasoningTokens"):
                if cell.get(key) is not None:
                    _require_finite_number(
                        cell[key],
                        label=f"{label}.cells.{cell_id}.{key}",
                    )

        quality = _require_mapping(payload.get("quality"), label=f"{label}.quality")
        quality_keys = {
            "qualityVersion",
            "complete",
            "completedSamples",
            "expectedSamples",
            "validSamples",
            "invalidSamples",
            "refusalSamples",
            "emptySamples",
            "errorSamples",
            "directness",
            "reasoningTraceCount",
            "reasoningTokenCount",
            "reasoningUsageObservedSamples",
            "rawEvidenceSha256",
        }
        if set(quality) != quality_keys:
            raise RuntimeError(f"{label}.quality has an unsupported shape")
        if quality.get("qualityVersion") != 1:
            raise RuntimeError(f"{label}.quality.qualityVersion must equal 1")
        if not isinstance(quality.get("complete"), bool):
            raise RuntimeError(f"{label}.quality.complete must be a boolean")
        if quality["complete"] is partial:
            raise RuntimeError(f"{label}.quality.complete must be false exactly for partial V2")
        parsed_quality = {
            name: _require_non_negative_integer(
                quality.get(f"{name}Samples"),
                label=f"{label}.quality.{name}Samples",
            )
            for name in ("valid", "invalid", "refusal", "empty", "error")
        }
        completed = _require_non_negative_integer(
            quality.get("completedSamples"),
            label=f"{label}.quality.completedSamples",
        )
        expected = _require_non_negative_integer(
            quality.get("expectedSamples"),
            label=f"{label}.quality.expectedSamples",
        )
        if expected != plan_expected:
            raise RuntimeError(f"{label}.quality.expectedSamples must equal plan.expectedSamples")
        if sum(parsed_quality.values()) != completed:
            raise RuntimeError(f"{label}.quality category counts must sum to completedSamples")
        if quality["complete"] and completed != expected:
            raise RuntimeError(f"{label}.quality completedSamples must equal expectedSamples")
        if not quality["complete"] and completed > expected:
            raise RuntimeError(f"{label}.quality completedSamples must not exceed expectedSamples")
        for name in ("valid", "invalid", "refusal", "empty", "error"):
            if parsed_quality[name] != aggregate[name]:
                raise RuntimeError(
                    f"{label}.quality.{name}Samples must equal aggregate cell counts"
                )
        if completed != aggregate["total"]:
            raise RuntimeError(f"{label}.quality.completedSamples must equal aggregate cell totals")
        if quality.get("directness") not in {"verified", "claimed", "violated", "unknown"}:
            raise RuntimeError(f"{label}.quality.directness is unsupported")
        reasoning_trace_count = _require_non_negative_integer(
            quality.get("reasoningTraceCount"),
            label=f"{label}.quality.reasoningTraceCount",
        )
        if reasoning_trace_count > completed:
            raise RuntimeError(f"{label}.quality.reasoningTraceCount exceeds completedSamples")
        _require_non_negative_integer(
            quality.get("reasoningTokenCount"),
            label=f"{label}.quality.reasoningTokenCount",
        )
        reasoning_usage_observed = _require_non_negative_integer(
            quality.get("reasoningUsageObservedSamples"),
            label=f"{label}.quality.reasoningUsageObservedSamples",
        )
        if reasoning_usage_observed > completed:
            raise RuntimeError(
                f"{label}.quality.reasoningUsageObservedSamples exceeds completedSamples"
            )
        raw_evidence_sha = quality.get("rawEvidenceSha256")
        if raw_evidence_sha is not None and (
            not isinstance(raw_evidence_sha, str) or not _SHA256_PATTERN.fullmatch(raw_evidence_sha)
        ):
            raise RuntimeError(f"{label}.quality.rawEvidenceSha256 must be a SHA-256 digest")

        duplicate_fields = {
            "completedSamples": completed,
            "expectedSamples": expected,
            "errorCount": parsed_quality["error"],
        }
        for key, expected_value in duplicate_fields.items():
            if key in payload and payload[key] != expected_value:
                raise RuntimeError(f"{label}.{key} must agree with quality")
        if partial:
            _require_non_empty_string(
                payload.get("incompleteReason"),
                label=f"{label}.incompleteReason",
            )
        return payload

    @classmethod
    def _load_fingerprint(cls, path: Path, *, label: str) -> dict[str, Any]:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            raise RuntimeError(f"cannot read {label}: {path}") from error
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"{label} is not valid JSON: {path}") from error
        if not isinstance(payload, dict):
            raise RuntimeError(f"{label} must contain a JSON object: {path}")
        format_version = payload.get("formatVersion")
        if format_version not in {1, 2}:
            raise RuntimeError(f"{label} has an unsupported formatVersion: {path}")
        if not isinstance(payload.get("model"), str) or not payload["model"]:
            raise RuntimeError(f'{label} is missing "model": {path}')
        if not isinstance(payload.get("cells"), dict):
            raise RuntimeError(f'{label} is missing "cells": {path}')
        if format_version == 2:
            cls._validate_v2_fingerprint(payload, label=label)
        return payload

    @classmethod
    def _validate_paper_collection(
        cls,
        payload: dict[str, Any],
        *,
        output_path: Path,
        samples_output_path: Path,
        endpoint: EndpointSpec,
        role: str,
        scheduler_seed: str,
        samples: int,
        credential: str | None,
    ) -> dict[str, Any]:
        if set(payload) != {"fingerprint", "collection"}:
            raise RuntimeError(
                "paper-fingerprint stdout must contain only fingerprint and collection"
            )
        try:
            fingerprint_bytes = output_path.read_bytes()
            evidence_bytes = samples_output_path.read_bytes()
        except OSError as error:
            raise RuntimeError("paper-fingerprint did not write both required artifacts") from error
        if credential:
            secret = credential.encode()
            serialized_stdout = json.dumps(payload, ensure_ascii=False).encode()
            persisted = (fingerprint_bytes, evidence_bytes, serialized_stdout)
            if any(secret in content for content in persisted):
                raise RuntimeError("paper-fingerprint output contains API key material")

        file_fingerprint = cls._load_fingerprint(
            output_path,
            label="paper fingerprint artifact",
        )
        stdout_fingerprint = _require_mapping(
            payload.get("fingerprint"),
            label="paper-fingerprint stdout.fingerprint",
        )
        cls._validate_v2_fingerprint(
            stdout_fingerprint,
            label="paper-fingerprint stdout.fingerprint",
        )
        if stdout_fingerprint != file_fingerprint:
            raise RuntimeError("paper-fingerprint stdout and persisted fingerprint differ")

        plan = file_fingerprint["plan"]
        quality = file_fingerprint["quality"]
        manifest = file_fingerprint["manifest"]
        if file_fingerprint["formatVersion"] != 2:
            raise RuntimeError("paper-fingerprint must persist formatVersion 2")
        if file_fingerprint["protocol"] != _PAPER_PROTOCOL:
            raise RuntimeError("paper-fingerprint used an unexpected protocol")
        if file_fingerprint["model"] != endpoint.model:
            raise RuntimeError("paper-fingerprint model does not match the requested endpoint")
        if tuple(plan["cellIds"]) != _PAPER_ORDERED_CELL_IDS:
            raise RuntimeError("paper-fingerprint must contain the ordered canonical 40 cells")
        if plan["role"] != role or plan["schedulerSeed"] != scheduler_seed:
            raise RuntimeError("paper-fingerprint collection plan does not match the request")
        if plan["schedulerPolicy"] != _PAPER_SCHEDULER_POLICY:
            raise RuntimeError("paper-fingerprint scheduler policy is not canonical")
        expected_samples = _PAPER_CELL_COUNT * samples
        if (
            file_fingerprint["samplesPerCell"] != samples
            or plan["samplesPerCell"] != samples
            or plan["expectedSamples"] != expected_samples
            or quality["expectedSamples"] != expected_samples
        ):
            raise RuntimeError("paper-fingerprint sample plan does not match the request")
        if file_fingerprint.get("partial") is True or quality["complete"] is not True:
            raise RuntimeError("partial paper-fingerprint evidence is not accepted")
        if manifest != _PAPER_MANIFEST:
            raise RuntimeError("paper-fingerprint manifest is not the pinned canonical40 manifest")
        if file_fingerprint["postReasoning"] is not False:
            raise RuntimeError("paper-fingerprint postReasoning must remain false")

        raw_evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
        if quality["rawEvidenceSha256"] != raw_evidence_sha:
            raise RuntimeError("paper-fingerprint JSONL SHA-256 does not match fingerprint quality")
        evidence_summary = cls._validate_paper_evidence_jsonl(
            evidence_bytes,
            protocol=file_fingerprint["protocol"],
            model=file_fingerprint["model"],
            role=role,
            scheduler_seed=scheduler_seed,
            samples=samples,
            cell_ids=set(plan["cellIds"]),
        )
        for category in ("valid", "invalid", "refusal", "empty", "error"):
            if evidence_summary[category] != quality[f"{category}Samples"]:
                raise RuntimeError(
                    f"paper-fingerprint JSONL {category} count does not match quality"
                )
        if evidence_summary["reasoningTrace"] != quality["reasoningTraceCount"]:
            raise RuntimeError("paper-fingerprint reasoning trace count does not match quality")
        if evidence_summary["reasoningTokens"] != quality["reasoningTokenCount"]:
            raise RuntimeError("paper-fingerprint reasoning token count does not match quality")
        if evidence_summary["reasoningUsageObserved"] != quality["reasoningUsageObservedSamples"]:
            raise RuntimeError("paper-fingerprint reasoning usage coverage does not match quality")
        contaminated = (
            evidence_summary["reasoningTrace"] > 0 or evidence_summary["reasoningTokens"] > 0
        )
        expected_directness = (
            "violated"
            if contaminated
            else "unknown"
            if (
                evidence_summary["error"] > 0
                or evidence_summary["reasoningUsageObserved"]
                != evidence_summary["observableResponse"]
            )
            else "verified"
        )
        if quality["directness"] != expected_directness:
            raise RuntimeError("paper-fingerprint directness does not match retained evidence")
        evidence_cells = evidence_summary["cells"]
        for cell_id in _PAPER_ORDERED_CELL_IDS:
            fingerprint_cell = file_fingerprint["cells"][cell_id]
            evidence_cell = evidence_cells[cell_id]
            for category in ("valid", "invalid", "refusal", "empty", "error"):
                if fingerprint_cell[f"{category}Count"] != evidence_cell[category]:
                    raise RuntimeError(
                        f"paper-fingerprint cell {cell_id} {category} count is not evidence-derived"
                    )
            if fingerprint_cell["totalCount"] != evidence_cell["total"]:
                raise RuntimeError(
                    f"paper-fingerprint cell {cell_id} total count is not evidence-derived"
                )
            if fingerprint_cell["counts"] != evidence_cell["counts"]:
                raise RuntimeError(
                    f"paper-fingerprint cell {cell_id} distribution is not evidence-derived"
                )

        collection = _require_mapping(
            payload.get("collection"),
            label="paper-fingerprint stdout.collection",
        )
        if set(collection) != _PAPER_COLLECTION_KEYS:
            raise RuntimeError("paper-fingerprint collection summary has an unsupported shape")
        expected_summary = {
            "artifactKind": "paper-profile-collection-v2",
            "interpretation": "uncalibrated-non-decision-evidence",
            "decisionEligible": False,
            "protocol": file_fingerprint["protocol"],
            "model": file_fingerprint["model"],
            "role": role,
            "cellCount": _PAPER_CELL_COUNT,
            "samplesPerCell": samples,
            "expectedSamples": expected_samples,
            "validSamples": quality["validSamples"],
            "invalidSamples": quality["invalidSamples"],
            "errorSamples": quality["errorSamples"],
            "directness": quality["directness"],
            "rawEvidenceSha256": raw_evidence_sha,
        }
        for key, expected in expected_summary.items():
            if collection.get(key) != expected:
                raise RuntimeError(f"paper-fingerprint collection.{key} is inconsistent")
        comparable_cells = _require_non_negative_integer(
            collection.get("splitHalfComparableCells"),
            label="paper-fingerprint collection.splitHalfComparableCells",
        )
        if comparable_cells > _PAPER_CELL_COUNT:
            raise RuntimeError("paper-fingerprint split-half cell count exceeds 40")
        split_half = collection.get("splitHalfMeanJsd")
        if split_half is not None:
            parsed_split_half = _require_finite_number(
                split_half,
                label="paper-fingerprint collection.splitHalfMeanJsd",
            )
            if parsed_split_half > 1:
                raise RuntimeError("paper-fingerprint split-half JSD must not exceed 1")
        if (split_half is None) != (comparable_cells == 0):
            raise RuntimeError("paper-fingerprint split-half summary is inconsistent")
        return payload

    @staticmethod
    def _validate_paper_evidence_jsonl(
        content: bytes,
        *,
        protocol: str,
        model: str,
        role: str,
        scheduler_seed: str,
        samples: int,
        cell_ids: set[str],
        expected_completed: int | None = None,
    ) -> dict[str, Any]:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("paper-fingerprint sample evidence is not UTF-8 JSONL") from error
        if not text or not text.endswith("\n"):
            raise RuntimeError("paper-fingerprint sample evidence must end with a newline")
        lines = text.splitlines()
        expected_count = (
            len(cell_ids) * samples if expected_completed is None else expected_completed
        )
        if len(lines) != expected_count:
            raise RuntimeError("paper-fingerprint JSONL sample count does not match the plan")
        summary: dict[str, Any] = {
            "valid": 0,
            "invalid": 0,
            "refusal": 0,
            "empty": 0,
            "error": 0,
            "reasoningTrace": 0,
            "reasoningTokens": 0,
            "observableResponse": 0,
            "reasoningUsageObserved": 0,
            "cells": {
                cell_id: {
                    "valid": 0,
                    "invalid": 0,
                    "refusal": 0,
                    "empty": 0,
                    "error": 0,
                    "total": 0,
                    "counts": {},
                }
                for cell_id in cell_ids
            },
        }
        observed: set[tuple[str, int]] = set()
        evidence_order: list[tuple[str, int, str, str]] = []

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            parsed: dict[str, Any] = {}
            for key, value in pairs:
                if key in parsed:
                    raise ValueError(f"duplicate JSON key: {key}")
                parsed[key] = value
            return parsed

        def nullable_string(value: Any, *, label: str) -> None:
            if value is not None and (not isinstance(value, str) or len(value) > 512):
                raise RuntimeError(f"{label} must be null or a bounded string")

        for line_number, line in enumerate(lines, start=1):
            try:
                sample = json.loads(line, object_pairs_hook=reject_duplicate_keys)
            except (json.JSONDecodeError, ValueError) as error:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} is invalid JSON"
                ) from error
            if not isinstance(sample, dict):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} is not an object"
                )
            if set(sample) != _PAPER_EVIDENCE_KEYS:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has an unsupported shape"
                )
            if (
                sample.get("evidenceVersion") != 1
                or sample.get("protocolId") != protocol
                or sample.get("requestedModel") != model
                or sample.get("role") != role
                or sample.get("schedulerSeed") != scheduler_seed
            ):
                raise RuntimeError(
                    "paper-fingerprint sample evidence line "
                    f"{line_number} has inconsistent metadata"
                )
            cell_id = sample.get("cellId")
            repetition = sample.get("repetitionIndex")
            if (
                cell_id not in cell_ids
                or not _is_non_negative_integer(repetition)
                or repetition >= samples
            ):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has an invalid job"
                )
            job = (cell_id, repetition)
            if job in observed:
                raise RuntimeError("paper-fingerprint sample evidence contains a duplicate job")
            observed.add(job)
            task_id, language = str(cell_id).split(":", 1)
            if sample.get("taskId") != task_id or sample.get("language") != language:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid cell metadata"
                )
            if sample.get("promptVariantId") != _PAPER_PROMPT_VARIANT_ID:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid prompt variant"
                )
            expected_job_id = hashlib.sha256(
                f"{cell_id}\0{repetition}\0{_PAPER_PROMPT_VARIANT_ID}".encode()
            ).hexdigest()
            if sample.get("jobId") != expected_job_id:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has invalid jobId"
                )
            evidence_order.append(
                (str(cell_id), int(repetition), _PAPER_PROMPT_VARIANT_ID, expected_job_id)
            )
            category = sample.get("category")
            if category not in {"valid", "invalid", "refusal", "empty", "error"}:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has an invalid category"
                )
            summary[category] += 1
            cell_summary = summary["cells"][cell_id]
            cell_summary[category] += 1
            cell_summary["total"] += 1
            if not isinstance(sample.get("raw"), str):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has invalid raw text"
                )
            normalized = sample.get("normalized")
            normalization_candidate = sample.get("normalizationCandidate")
            if normalized is not None and not isinstance(normalized, str):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid normalized text"
                )
            if normalization_candidate is not None and not isinstance(normalization_candidate, str):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid normalization candidate"
                )
            if not isinstance(sample.get("excludedFromDistribution"), bool):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid exclusion flag"
                )
            normalization_category = sample.get("normalizationCategory")
            if normalization_category not in {None, "valid", "invalid", "refusal", "empty"}:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid normalization category"
                )
            if sample.get("exclusionReason") not in {
                None,
                "reasoning_contamination",
                "provider_error",
                "malformed_response",
                "sensitive_credential_echo",
            }:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid exclusion reason"
                )
            if sample.get("errorKind") not in {
                None,
                "request_failed",
                "provider_error",
                "malformed_response",
                "sensitive_credential_echo",
            }:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has invalid error kind"
                )
            for key in ("provider", "reportedModel", "generationId", "finishReason"):
                nullable_string(
                    sample.get(key),
                    label=f"paper-fingerprint sample line {line_number} {key}",
                )
            for key in ("requestedAt", "receivedAt"):
                timestamp = sample.get(key)
                if not isinstance(timestamp, str):
                    raise RuntimeError(
                        f"paper-fingerprint sample evidence line {line_number} "
                        "has invalid timestamp"
                    )
                try:
                    parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError as error:
                    raise RuntimeError(
                        f"paper-fingerprint sample evidence line {line_number} "
                        "has invalid timestamp"
                    ) from error
                if parsed_timestamp.tzinfo is None:
                    raise RuntimeError(
                        f"paper-fingerprint sample evidence line {line_number} has naive timestamp"
                    )
            _require_finite_number(
                sample.get("latencyMs"),
                label=f"paper-fingerprint sample line {line_number} latencyMs",
            )
            trace_fields = sample.get("reasoningTraceFields")
            if not isinstance(trace_fields, list) or any(
                not isinstance(field, str) for field in trace_fields
            ):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} has invalid trace fields"
                )
            trace_characters = _require_non_negative_integer(
                sample.get("reasoningTraceCharacterCount"),
                label=(f"paper-fingerprint sample line {line_number} reasoningTraceCharacterCount"),
            )
            if bool(trace_fields) != (trace_characters > 0):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has inconsistent trace metadata"
                )
            if trace_fields:
                summary["reasoningTrace"] += 1
            sensitive_fields = sample.get("sensitiveCredentialEchoFields")
            if (
                not isinstance(sensitive_fields, list)
                or any(not isinstance(field, str) for field in sensitive_fields)
                or len(sensitive_fields) != len(set(sensitive_fields))
                or any(
                    field
                    not in {"raw", "provider", "reportedModel", "generationId", "finishReason"}
                    for field in sensitive_fields
                )
            ):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has invalid sensitive credential echo metadata"
                )
            usage = sample.get("usage")
            if usage is not None:
                if not isinstance(usage, dict) or set(usage) != _PAPER_USAGE_KEYS:
                    raise RuntimeError(
                        f"paper-fingerprint sample evidence line {line_number} has invalid usage"
                    )
                for key in (
                    "promptTokens",
                    "completionTokens",
                    "reasoningTokens",
                    "cachedPromptTokens",
                ):
                    value = usage.get(key)
                    if value is not None:
                        _require_non_negative_integer(
                            value,
                            label=f"paper-fingerprint sample line {line_number} {key}",
                        )
                cost = usage.get("costUsd")
                if cost is not None:
                    _require_finite_number(
                        cost,
                        label=f"paper-fingerprint sample line {line_number} costUsd",
                    )
                reasoning_tokens = usage.get("reasoningTokens")
                if reasoning_tokens is not None:
                    summary["reasoningTokens"] += _require_non_negative_integer(
                        reasoning_tokens,
                        label=f"paper-fingerprint sample line {line_number} reasoningTokens",
                    )
            contaminated = bool(trace_fields) or (
                isinstance(usage, dict)
                and _is_non_negative_integer(usage.get("reasoningTokens"))
                and usage["reasoningTokens"] > 0
            )
            excluded = sample["excludedFromDistribution"]
            exclusion_reason = sample.get("exclusionReason")
            error_kind = sample.get("errorKind")
            if category == "valid":
                canonical_state = (
                    isinstance(normalized, str)
                    and normalization_candidate == normalized
                    and normalization_category == "valid"
                    and excluded is False
                    and exclusion_reason is None
                    and error_kind is None
                    and not contaminated
                )
            elif category == "invalid":
                if contaminated:
                    if normalization_category == "valid":
                        candidate_state = isinstance(normalization_candidate, str)
                    elif normalization_category == "invalid":
                        candidate_state = normalization_candidate is None or isinstance(
                            normalization_candidate,
                            str,
                        )
                    else:
                        candidate_state = normalization_candidate is None
                    canonical_state = (
                        normalized is None
                        and normalization_category in {"valid", "invalid", "refusal", "empty"}
                        and candidate_state
                        and excluded is True
                        and exclusion_reason == "reasoning_contamination"
                        and error_kind is None
                    )
                else:
                    canonical_state = (
                        normalization_candidate == normalized
                        and normalization_category == "invalid"
                        and excluded is False
                        and exclusion_reason is None
                        and error_kind is None
                    )
            elif category in {"refusal", "empty"}:
                canonical_state = (
                    normalized is None
                    and normalization_candidate is None
                    and normalization_category == category
                    and excluded is False
                    and exclusion_reason is None
                    and error_kind is None
                    and not contaminated
                )
            else:
                expected_exclusion = None if error_kind == "request_failed" else error_kind
                canonical_state = (
                    normalized is None
                    and normalization_candidate is None
                    and normalization_category is None
                    and excluded is True
                    and error_kind is not None
                    and exclusion_reason == expected_exclusion
                    and (not contaminated or error_kind != "request_failed")
                )
            if not canonical_state:
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "has a non-canonical category/normalization/exclusion state"
                )
            if category == "valid":
                cell_summary["counts"][normalized] = cell_summary["counts"].get(normalized, 0) + 1
            if sensitive_fields and (
                category != "error"
                or sample.get("excludedFromDistribution") is not True
                or sample.get("exclusionReason") != "sensitive_credential_echo"
                or sample.get("errorKind") != "sensitive_credential_echo"
            ):
                raise RuntimeError(
                    f"paper-fingerprint sample evidence line {line_number} "
                    "does not exclude credential echo evidence"
                )
            if sample.get("errorKind") is None:
                summary["observableResponse"] += 1
                if isinstance(usage, dict) and usage.get("reasoningTokens") is not None:
                    summary["reasoningUsageObserved"] += 1
        planned_jobs = {
            (cell_id, repetition) for cell_id in cell_ids for repetition in range(samples)
        }
        if expected_completed is None and observed != planned_jobs:
            raise RuntimeError("paper-fingerprint sample evidence does not cover the full plan")
        if expected_completed is not None and not observed.issubset(planned_jobs):
            raise RuntimeError("paper-fingerprint partial evidence contains an unplanned job")
        if evidence_order != sorted(evidence_order):
            raise RuntimeError("paper-fingerprint sample evidence is not in canonical job order")
        return summary

    @staticmethod
    def partial_artifact_summary(path: Path) -> dict[str, Any] | None:
        """Return safe checkpoint metadata without exposing samples or credentials."""

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("partial") is not True:
            return None

        def safe_count(name: str) -> int:
            value = payload.get(name)
            return value if isinstance(value, int) and value >= 0 else 0

        return {
            "partial": True,
            "completedSamples": safe_count("completedSamples"),
            "expectedSamples": safe_count("expectedSamples"),
            "errorCount": safe_count("errorCount"),
            "incompleteReason": str(payload.get("incompleteReason") or "sampling_in_progress"),
            "model": str(payload.get("model") or ""),
        }

    @classmethod
    def mark_partial_artifact(
        cls,
        path: Path,
        *,
        incomplete_reason: str,
    ) -> dict[str, Any] | None:
        """Atomically annotate an existing partial artifact after interruption."""

        summary = cls.partial_artifact_summary(path)
        if summary is None:
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["incompleteReason"] = incomplete_reason
            encoded = f"{json.dumps(payload, ensure_ascii=False, indent=2)}\n"
            temporary = path.with_suffix(f"{path.suffix}.partial.tmp")
            temporary.write_text(encoded, encoding="utf-8")
            os.replace(temporary, path)
        except (OSError, json.JSONDecodeError):
            return summary
        return cls.partial_artifact_summary(path)

    @staticmethod
    def _offline_environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TMPDIR",
            "SYSTEMROOT",
            "NODE_EXTRA_CA_CERTS",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }
        return {name: value for name, value in os.environ.items() if name in allowed}

    def _base_arguments(
        self,
        endpoint: EndpointSpec,
        cells: int,
        samples: int,
        concurrency: int,
        *,
        subcommand: str,
        api_key: str | None = None,
    ) -> tuple[list[str], dict[str, str], str | None]:
        self.ensure_ready()
        if subcommand not in {"fingerprint", "verify"}:
            raise ValueError("unsupported endpoint subcommand")
        arguments = ["node", str(self.cli_path), subcommand]
        credential_arguments, environment, credential = self._credential_arguments(
            endpoint,
            api_key=api_key,
        )
        common = [
            "--base-url",
            str(endpoint.base_url).rstrip("/"),
            "--model",
            endpoint.model,
            "--cells",
            str(cells),
            "--samples",
            str(samples),
            "--concurrency",
            str(concurrency),
            *credential_arguments,
        ]
        arguments.extend(common)
        return arguments, environment, credential

    @staticmethod
    def _credential_arguments(
        endpoint: EndpointSpec,
        *,
        api_key: str | None,
    ) -> tuple[list[str], dict[str, str], str | None]:
        # Start from the same small environment used by offline comparison. This
        # prevents the child CLI from silently borrowing ambient provider keys.
        environment = FingerprintRunner._offline_environment()
        if endpoint.api_key_env:
            environment.pop(endpoint.api_key_env, None)
        if api_key is None:
            if endpoint.api_key_env:
                raise ValueError("api_key_env must be resolved by the service before sampling")
            return [], environment, None
        credential = api_key.strip()
        if not credential:
            raise ValueError("api_key must not be empty")

        ephemeral_name = f"RELAY_AUDITOR_EPHEMERAL_{uuid4().hex.upper()}"
        environment[ephemeral_name] = credential
        return ["--api-key-env", ephemeral_name], environment, credential

    @staticmethod
    def _credential_variants(credential: str) -> set[str]:
        canonical = unicodedata.normalize("NFC", credential).casefold().strip()
        cleaned = "".join(
            character
            for character in canonical
            if character.isalnum() or character.isspace()
        )
        digit_translation = str.maketrans(
            "０１２３４５６７８９٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹",
            "012345678901234567890123456789",
        )
        legacy_candidate = cleaned.translate(digit_translation).strip().split(maxsplit=1)[0]
        return {variant for variant in (canonical, legacy_candidate) if variant}

    @classmethod
    def _contains_credential_echo(cls, value: Any, *, credential: str) -> bool:
        variants = cls._credential_variants(credential)

        def string_matches(candidate: str) -> bool:
            normalized = unicodedata.normalize("NFC", candidate).casefold()
            return any(
                normalized == variant or (len(variant) >= 8 and variant in normalized)
                for variant in variants
            )

        def walk(item: Any) -> bool:
            if isinstance(item, str):
                return string_matches(item)
            if isinstance(item, dict):
                return any(string_matches(str(key)) or walk(child) for key, child in item.items())
            if isinstance(item, (list, tuple)):
                return any(walk(child) for child in item)
            return False

        return walk(value)

    @classmethod
    def _discard_credential_echo(
        cls,
        output_path: Path,
        *,
        credential: str | None,
        payload: dict[str, Any] | None = None,
    ) -> bool:
        if not credential:
            return False
        detected = payload is not None and cls._contains_credential_echo(
            payload,
            credential=credential,
        )
        if output_path.is_file():
            try:
                artifact_text = output_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                artifact_text = ""
            if artifact_text:
                try:
                    artifact: Any = json.loads(artifact_text)
                except json.JSONDecodeError:
                    artifact = artifact_text
                detected = detected or cls._contains_credential_echo(
                    artifact,
                    credential=credential,
                )
        if detected:
            output_path.unlink(missing_ok=True)
        return detected

    async def _execute(
        self,
        arguments: list[str],
        *,
        accepted_exit_codes: set[int],
        environment: dict[str, str],
    ) -> dict[str, Any]:
        _, payload = await self._execute_with_code(
            arguments,
            accepted_exit_codes=accepted_exit_codes,
            environment=environment,
        )
        return payload

    async def _execute_with_code(
        self,
        arguments: list[str],
        *,
        accepted_exit_codes: set[int],
        environment: dict[str, str],
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: asyncio.Event | None = None,
        idle_timeout_seconds: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if len(arguments) < 3 or arguments[2] not in {
            "compare",
            "fingerprint",
            "paper-fingerprint",
            "verify",
        }:
            raise ValueError("CLI subcommand must be explicit at argument index 2")
        command = list(arguments)

        if idle_timeout_seconds is not None and idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be greater than zero")
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        if progress_callback is None and cancel_event is None and idle_timeout_seconds is None:
            stdout, stderr = await process.communicate()
            return self._decode_process_result(
                process.returncode,
                stdout,
                stderr,
                accepted_exit_codes=accepted_exit_codes,
                command=command,
                environment=environment,
            )
        progress_event = asyncio.Event()

        def observe_progress(event: dict[str, Any]) -> None:
            # A completed sample and a retry notification are both meaningful
            # activity for a slow or rate-limited relay. Either one renews the
            # idle window; elapsed wall-clock time alone never kills the run.
            progress_event.set()
            if progress_callback is not None:
                progress_callback(event)

        stderr_callback = (
            observe_progress
            if progress_callback is not None or idle_timeout_seconds is not None
            else None
        )
        stdout_task = asyncio.create_task(process.stdout.read())
        stderr_task = asyncio.create_task(self._read_stderr(process.stderr, stderr_callback))
        process_task = asyncio.create_task(process.wait())
        cancel_task = asyncio.create_task(cancel_event.wait()) if cancel_event is not None else None
        progress_task = (
            asyncio.create_task(progress_event.wait()) if idle_timeout_seconds is not None else None
        )
        try:
            while not process_task.done():
                waiters = {process_task}
                if cancel_task is not None:
                    waiters.add(cancel_task)
                if progress_task is not None:
                    waiters.add(progress_task)
                done, _ = await asyncio.wait(
                    waiters,
                    timeout=idle_timeout_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # Complete output wins when process exit and cancellation become
                # observable in the same scheduler turn.
                if process_task in done:
                    break
                if cancel_task is not None and cancel_task in done and cancel_event.is_set():
                    await self._stop_process(process)
                    await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
                    raise FingerprintPausedError("comparison paused by user")
                if progress_task is not None and progress_task in done:
                    progress_event.clear()
                    progress_task = asyncio.create_task(progress_event.wait())
                    continue
                if not done and idle_timeout_seconds is not None:
                    await self._stop_process(process)
                    await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
                    raise FingerprintStalledError(idle_timeout_seconds)
            await process_task
            stdout = await stdout_task
            stderr = await stderr_task
        except asyncio.CancelledError:
            await self._stop_process(process)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise
        finally:
            if cancel_task is not None and not cancel_task.done():
                cancel_task.cancel()
            if progress_task is not None and not progress_task.done():
                progress_task.cancel()
        return self._decode_process_result(
            process.returncode,
            stdout,
            stderr,
            accepted_exit_codes=accepted_exit_codes,
            command=command,
            environment=environment,
        )

    @staticmethod
    async def _stop_process(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            process.kill()
            await process.wait()

    def _decode_process_result(
        self,
        return_code: int,
        stdout: bytes,
        stderr: bytes,
        *,
        accepted_exit_codes: set[int],
        command: list[str],
        environment: dict[str, str],
    ) -> tuple[int, dict[str, Any]]:
        stderr_text = stderr.decode(errors="replace").strip()
        stderr_text = self._redact_api_key(stderr_text, command, environment)
        if return_code not in accepted_exit_codes:
            raise RuntimeError(
                f"One Token CLI failed with exit code {return_code}: {stderr_text[-2000:]}"
            )
        stdout_text = stdout.decode(errors="replace")
        try:
            payload = json.loads(stdout_text)
        except json.JSONDecodeError as error:
            stripped = stdout_text.rstrip()
            likely_truncated = bool(stripped) and (
                error.pos >= len(stripped) - 1 or stripped[-1] not in "}]"
            )
            raise InvalidCliJsonError(
                exit_code=return_code,
                stdout_bytes=len(stdout),
                error=error,
                stderr_tail=stderr_text[-1000:],
                likely_truncated=likely_truncated,
            ) from error
        if not isinstance(payload, dict):
            raise RuntimeError("One Token CLI returned a non-object JSON payload")
        return return_code, payload

    async def _read_stderr(
        self,
        stream: asyncio.StreamReader,
        progress_callback: Callable[[dict[str, Any]], None] | None,
    ) -> bytes:
        chunks: list[bytes] = []
        while True:
            line = await stream.readline()
            if not line:
                break
            chunks.append(line)
            if progress_callback is not None:
                event = self._parse_progress_line(line.decode(errors="replace"))
                if event is not None:
                    progress_callback(event)
        return b"".join(chunks)

    @staticmethod
    def _parse_progress_line(line: str) -> dict[str, Any] | None:
        prefix = "LLMFP_PROGRESS "
        stripped = line.strip()
        if stripped.startswith(prefix):
            try:
                payload = json.loads(stripped[len(prefix) :])
            except json.JSONDecodeError:
                return None
            if not isinstance(payload, dict) or payload.get("stage") not in {
                "adapter",
                "sampling",
            }:
                return None

            def safe_int(name: str, default: int = 0) -> int:
                value = payload.get(name)
                return value if isinstance(value, int) and value >= 0 else default

            status = payload.get("lastHttpStatus")
            return {
                "stage": str(payload["stage"]),
                "done": safe_int("done"),
                "total": safe_int("total"),
                "errors": safe_int("errors"),
                "detail": (str(payload["detail"]) if payload.get("detail") is not None else None),
                "lastErrorKind": (
                    str(payload["lastErrorKind"])
                    if payload.get("lastErrorKind") is not None
                    else None
                ),
                "lastHttpStatus": status if isinstance(status, int) else None,
                "retrying": payload.get("retrying") is True,
            }
        adapter = re.search(r"probing reasoning adapter \(([^)]+)\)", line)
        if adapter:
            return {
                "stage": "adapter",
                "done": 0,
                "total": 1,
                "errors": 0,
                "detail": adapter.group(1),
            }
        sampling = re.search(r"sampling (\d+)/(\d+)(?:, errors: (\d+))?", line)
        if sampling:
            return {
                "stage": "sampling",
                "done": int(sampling.group(1)),
                "total": int(sampling.group(2)),
                "errors": int(sampling.group(3) or 0),
                "detail": None,
            }
        return None

    @staticmethod
    def _redact_api_key(
        text: str,
        command: list[str],
        environment: dict[str, str],
    ) -> str:
        try:
            env_name = command[command.index("--api-key-env") + 1]
        except (ValueError, IndexError):
            return text
        secret = environment.get(env_name)
        if not secret:
            return text
        return text.replace(secret, "[REDACTED]")
