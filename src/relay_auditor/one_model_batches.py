from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4

from relay_auditor import __version__
from relay_auditor.batch_reports import (
    SecretCanaryScanner,
    build_terminal_batch_report,
    write_terminal_batch_report,
    write_verified_batch_csv,
)
from relay_auditor.credentials import CredentialSource, RuntimeCredentialStore
from relay_auditor.database import (
    ONE_MODEL_ITEM_TERMINAL_STATUSES,
    Database,
)
from relay_auditor.detectors.fingerprint import FingerprintPausedError, FingerprintRunner
from relay_auditor.evidence import EvidenceStore
from relay_auditor.execution_utils import (
    ExecutionInterrupted,
    await_interruptibly,
    jsonl_observations,
    safe_failure_code,
    strict_preflight_with_retry,
)
from relay_auditor.network_safety import (
    EndpointResolution,
    Resolver,
    revalidate_public_endpoint,
    system_resolver,
    validate_public_endpoint,
)
from relay_auditor.one_model_schemas import OneModelBatchCreateRequest
from relay_auditor.reference_set_batches import load_verified_reference_bundle
from relay_auditor.reference_sets import (
    assess_fingerprint_quality,
    compare_target_to_reference,
    load_reference_set_manifest,
    validate_member_fingerprint,
)
from relay_auditor.schemas import EndpointSpec
from relay_auditor.strict_preflight import StrictPreflightError, run_strict_preflight

TERMINAL_BATCH_STATUSES = {"completed", "failed", "canceled", "interrupted"}
DEFAULT_REPORT_FINALIZATION_TIMEOUT_SECONDS = 600.0


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    secret: str
    source: CredentialSource


@dataclass(frozen=True, slots=True)
class PreparedBatchReport:
    report_path: Path
    csv_path: Path
    report_sha256: str


@dataclass(slots=True)
class TargetRuntime:
    item_id: str
    row_id: str
    station_name: str
    model: str
    base_url: str
    origin: str
    resolution: EndpointResolution
    credential_ref: str
    remaining_timeout_seconds: float


@dataclass(slots=True)
class OneModelBatchRuntime:
    batch_id: str
    reference_set: Any
    reference_rows: list[tuple[Any, Any, dict[str, Any]]]
    targets: list[TargetRuntime]
    protocol: str
    transport_profile_id: str
    default_model: str
    station_concurrency: int
    station_slots: int
    request_timeout_seconds: float
    station_timeout_seconds: float
    batch_timeout_seconds: float
    retry_budget: int
    remaining_timeout_seconds: float
    interrupt_event: asyncio.Event
    lock: asyncio.Lock
    worker: asyncio.Task[None] | None = None
    pause_requested: bool = False
    cancel_requested: bool = False
    shutdown_requested: bool = False


class OneModelBatchManager:
    """Run up to four independent station collectors without persisting credentials."""

    def __init__(
        self,
        database: Database,
        evidence: EvidenceStore,
        fingerprint: FingerprintRunner,
        credentials: RuntimeCredentialStore,
        *,
        resolver: Resolver = system_resolver,
        preflight_runner=run_strict_preflight,
        allow_test_loopback: bool = False,
        git_sha: str = "unknown",
        report_finalization_timeout_seconds: float = DEFAULT_REPORT_FINALIZATION_TIMEOUT_SECONDS,
    ) -> None:
        if (
            isinstance(report_finalization_timeout_seconds, bool)
            or not isinstance(report_finalization_timeout_seconds, (int, float))
            or not 0 < report_finalization_timeout_seconds < float("inf")
        ):
            raise ValueError("report finalization timeout must be a positive finite number")
        self.database = database
        self.evidence = evidence
        self.fingerprint = fingerprint
        self.credentials = credentials
        self.resolver = resolver
        self.preflight_runner = preflight_runner
        self.allow_test_loopback = allow_test_loopback
        self.git_sha = git_sha
        self.report_finalization_timeout_seconds = float(
            report_finalization_timeout_seconds
        )
        self._runtimes: dict[str, OneModelBatchRuntime] = {}
        self._origin_locks: dict[str, asyncio.Lock] = {}
        self._report_finalizers: set[asyncio.Task[PreparedBatchReport]] = set()

    async def start(
        self,
        request: OneModelBatchCreateRequest,
        *,
        resolved_credentials: dict[str, ResolvedCredential],
    ) -> str:
        SecretCanaryScanner(
            credential.secret for credential in resolved_credentials.values()
        ).reject(
            {
                "reference_set_id": request.reference_set_id,
                "default_model_id": request.default_model_id,
                "targets": [
                    {
                        "row_id": target.row_id,
                        "station_name": target.station_name,
                        "base_url": str(target.base_url),
                        "model_id": target.model_id,
                    }
                    for target in request.targets
                ],
            }
        )
        reference_set, reference_rows = load_verified_reference_bundle(
            self.database,
            self.evidence,
            request.reference_set_id,
        )
        expected_rows = {target.row_id for target in request.targets}
        if set(resolved_credentials) != expected_rows:
            raise ValueError("resolved credentials do not match all input rows")
        resolutions = await asyncio.gather(
            *(
                validate_public_endpoint(
                    str(target.base_url),
                    reference_set.protocol,
                    resolver=self.resolver,
                    allow_test_loopback=self.allow_test_loopback,
                )
                for target in request.targets
            )
        )
        normalized_identities: set[tuple[str, str]] = set()
        target_specs: list[dict[str, str]] = []
        runtime_targets: list[TargetRuntime] = []
        registered: list[str] = []
        batch_id = str(uuid4())
        try:
            for target, resolution in zip(request.targets, resolutions, strict=True):
                model = (target.model_id or request.default_model_id).strip()
                identity = (resolution.base_url, model)
                if identity in normalized_identities:
                    raise ValueError("duplicate canonical base_url and model_id")
                normalized_identities.add(identity)
                item_id = str(uuid4())
                resolved = resolved_credentials[target.row_id]
                credential_ref = self.credentials.register(
                    scope="target",
                    row_id=target.row_id,
                    canonical_base_url=resolution.base_url,
                    model=model,
                    protocol=reference_set.protocol,
                    source=resolved.source,
                    secret=resolved.secret,
                )
                registered.append(credential_ref)
                target_specs.append(
                    {
                        "item_id": item_id,
                        "row_id": target.row_id,
                        "station_name": target.station_name.strip(),
                        "canonical_base_url": resolution.base_url,
                        "model": model,
                    }
                )
                runtime_targets.append(
                    TargetRuntime(
                        item_id=item_id,
                        row_id=target.row_id,
                        station_name=target.station_name.strip(),
                        model=model,
                        base_url=resolution.base_url,
                        origin=resolution.origin,
                        resolution=resolution,
                        credential_ref=credential_ref,
                        remaining_timeout_seconds=request.station_timeout_seconds,
                    )
                )
            self.database.create_one_model_batch_queue(
                batch_id=batch_id,
                reference_set_id=reference_set.id,
                protocol=reference_set.protocol,
                transport_profile_id=reference_set.transport_profile_id,
                default_model=request.default_model_id.strip(),
                items=target_specs,
                max_parallel_stations=request.max_parallel_stations,
                per_station_concurrency=request.per_station_concurrency,
                global_request_concurrency=request.global_request_concurrency,
                request_timeout_seconds=request.request_timeout_seconds,
                station_timeout_seconds=request.station_timeout_seconds,
                batch_timeout_seconds=request.batch_timeout_seconds,
                retry_budget=request.retry_budget,
            )
        except Exception:
            for credential_ref in registered:
                self.credentials.discard(credential_ref)
            raise
        effective_station_concurrency = min(
            request.per_station_concurrency,
            request.global_request_concurrency,
        )
        station_slots = min(
            request.max_parallel_stations,
            max(1, request.global_request_concurrency // effective_station_concurrency),
        )
        runtime = OneModelBatchRuntime(
            batch_id=batch_id,
            reference_set=reference_set,
            reference_rows=reference_rows,
            targets=runtime_targets,
            protocol=reference_set.protocol,
            transport_profile_id=reference_set.transport_profile_id,
            default_model=request.default_model_id.strip(),
            station_concurrency=effective_station_concurrency,
            station_slots=station_slots,
            request_timeout_seconds=request.request_timeout_seconds,
            station_timeout_seconds=request.station_timeout_seconds,
            batch_timeout_seconds=request.batch_timeout_seconds,
            retry_budget=request.retry_budget,
            remaining_timeout_seconds=request.batch_timeout_seconds,
            interrupt_event=asyncio.Event(),
            lock=asyncio.Lock(),
        )
        self._runtimes[batch_id] = runtime
        runtime.worker = asyncio.create_task(self._run(runtime))
        return batch_id

    async def pause(self, batch_id: str) -> None:
        runtime = self._active_runtime(batch_id)
        async with runtime.lock:
            batch = self.database.get_one_model_batch(batch_id)
            if batch is None:
                raise LookupError(f"one-model batch not found: {batch_id}")
            if batch.status == "paused":
                return
            if batch.status in TERMINAL_BATCH_STATUSES or batch.status == "finalizing":
                raise ValueError("terminal one-model batch cannot be paused")
            runtime.pause_requested = True
            runtime.interrupt_event.set()
            worker = runtime.worker
        if worker is not None and not worker.done():
            await asyncio.shield(worker)

    async def resume(self, batch_id: str) -> None:
        runtime = self._active_runtime(batch_id)
        async with runtime.lock:
            self.database.resume_one_model_batch(batch_id)
            runtime.pause_requested = False
            runtime.shutdown_requested = False
            runtime.interrupt_event.clear()
            runtime.worker = asyncio.create_task(self._run(runtime))

    async def cancel(self, batch_id: str) -> None:
        runtime = self._active_runtime(batch_id)
        async with runtime.lock:
            runtime.cancel_requested = True
            runtime.pause_requested = False
            self.database.request_one_model_batch_cancel(batch_id)
            runtime.interrupt_event.set()
            worker = runtime.worker
        if worker is not None and not worker.done():
            await asyncio.shield(worker)

    async def shutdown(self) -> None:
        workers: list[asyncio.Task[None]] = []
        for runtime in list(self._runtimes.values()):
            runtime.shutdown_requested = True
            runtime.interrupt_event.set()
            if runtime.worker is not None and not runtime.worker.done():
                workers.append(runtime.worker)
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        # Paused workers are already done and therefore cannot consume the
        # shutdown event. Terminalize and report them before discarding keys.
        for runtime in list(self._runtimes.values()):
            batch = self.database.get_one_model_batch(runtime.batch_id)
            if batch is None or batch.status in TERMINAL_BATCH_STATUSES:
                continue
            self._terminalize_unfinished(runtime, "interrupted", "service_shutdown")
            await self._finalize_and_cleanup(runtime, "interrupted")
        self.credentials.discard_scope("target")

    async def recover_interrupted_reports(self) -> dict[str, int]:
        """Build reports for restart-terminalized ledgers without replaying requests."""

        generated = 0
        failed = 0
        for batch in self.database.list_one_model_batches_without_reports():
            if not await self._finalize_batch_report_fail_closed(
                batch.id,
                batch.status,
                secret_scanner=SecretCanaryScanner(),
            ):
                failed += 1
            else:
                generated += 1
        return {"generated": generated, "failed": failed}

    def _active_runtime(self, batch_id: str) -> OneModelBatchRuntime:
        batch = self.database.get_one_model_batch(batch_id)
        if batch is None:
            raise LookupError(f"one-model batch not found: {batch_id}")
        runtime = self._runtimes.get(batch_id)
        if runtime is None:
            if batch.status in TERMINAL_BATCH_STATUSES:
                raise ValueError("one-model batch is already terminal")
            raise ValueError("batch credentials are unavailable after service restart")
        return runtime

    async def _run(self, runtime: OneModelBatchRuntime) -> None:
        semaphore = asyncio.Semaphore(runtime.station_slots)
        try:
            active_started = monotonic()
            try:
                if runtime.remaining_timeout_seconds <= 0:
                    raise TimeoutError
                async with asyncio.timeout(runtime.remaining_timeout_seconds):
                    await asyncio.gather(
                        *(
                            self._run_target(runtime, target, semaphore)
                            for target in runtime.targets
                        )
                    )
            finally:
                runtime.remaining_timeout_seconds = max(
                    0.0,
                    runtime.remaining_timeout_seconds - (monotonic() - active_started),
                )
            if runtime.cancel_requested:
                self.database.cancel_one_model_batch(runtime.batch_id)
                await self._finalize_and_cleanup(runtime, "canceled")
                return
            if runtime.shutdown_requested:
                self._terminalize_unfinished(runtime, "interrupted", "service_shutdown")
                await self._finalize_and_cleanup(runtime, "interrupted")
                return
            if runtime.pause_requested:
                self.database.pause_one_model_batch(runtime.batch_id)
                return
            self._terminalize_unfinished(runtime, "failed", "scheduler_incomplete")
            await self._finalize_and_cleanup(runtime, "completed")
        except TimeoutError:
            runtime.interrupt_event.set()
            self._terminalize_unfinished(runtime, "failed", "batch_wall_clock_timeout")
            await self._finalize_and_cleanup(runtime, "failed")
        except Exception:
            runtime.interrupt_event.set()
            self._terminalize_unfinished(runtime, "failed", "batch_scheduler_failed")
            await self._finalize_and_cleanup(runtime, "failed")

    async def _run_target(
        self,
        runtime: OneModelBatchRuntime,
        target: TargetRuntime,
        semaphore: asyncio.Semaphore,
    ) -> None:
        item = self.database.get_one_model_batch_item(target.item_id)
        if item is None or item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
            return
        async with semaphore:
            if runtime.interrupt_event.is_set():
                return
            origin_lock = self._origin_locks.setdefault(target.origin, asyncio.Lock())
            async with origin_lock:
                if runtime.interrupt_event.is_set():
                    return
                try:
                    active_started = monotonic()
                    try:
                        if target.remaining_timeout_seconds <= 0:
                            raise TimeoutError
                        await asyncio.wait_for(
                            self._collect_target(runtime, target),
                            timeout=target.remaining_timeout_seconds,
                        )
                    finally:
                        target.remaining_timeout_seconds = max(
                            0.0,
                            target.remaining_timeout_seconds - (monotonic() - active_started),
                        )
                except (ExecutionInterrupted, FingerprintPausedError):
                    return
                except TimeoutError:
                    await self._finish_failure(
                        runtime,
                        target,
                        code="station_wall_clock_timeout",
                    )
                except Exception as error:
                    code, status = safe_failure_code(error)
                    exploratory = (
                        "unsupported_protocol"
                        if code == "unsupported_protocol"
                        else "request_failed"
                    )
                    await self._finish_failure(
                        runtime,
                        target,
                        code=code,
                        http_status=status,
                        exploratory_status=exploratory,
                    )

    async def _collect_target(
        self,
        runtime: OneModelBatchRuntime,
        target: TargetRuntime,
    ) -> None:
        item = self.database.get_one_model_batch_item(target.item_id)
        if item is None or item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
            return
        prior_attempts = int(item.request_attempts)
        prior_retries = int(item.retry_count)
        prior_retry_budget_used = int(item.retry_budget_used)
        remaining_retry_budget = max(
            0,
            runtime.retry_budget - prior_retry_budget_used,
        )
        resolution = await await_interruptibly(
            revalidate_public_endpoint(
                target.resolution,
                resolver=self.resolver,
                allow_test_loopback=self.allow_test_loopback,
            ),
            runtime.interrupt_event,
            timeout_seconds=runtime.request_timeout_seconds,
        )
        secret = self.credentials.resolve(
            target.credential_ref,
            scope="target",
            row_id=target.row_id,
            canonical_base_url=target.base_url,
            model=target.model,
            protocol=runtime.protocol,
        )
        preflight: dict[str, Any] = {}
        preflight_attempts = 0
        preflight_retries = 0
        preflight_retry_budget_used = 0

        def preflight_progress(event: dict[str, int]) -> None:
            nonlocal preflight_retry_budget_used
            preflight_retry_budget_used = int(event["retry_budget_used"])
            self.database.update_one_model_batch_item_progress(
                target.item_id,
                status="running",
                stage="preflight",
                done=0,
                errors=0,
                request_attempts=prior_attempts + int(event["attempt_count"]),
                retry_count=prior_retries + int(event["retry_count"]),
                retry_budget_used=(
                    prior_retry_budget_used + preflight_retry_budget_used
                ),
            )

        try:
            preflight, preflight_attempts, preflight_retries = (
                await strict_preflight_with_retry(
                    resolution,
                    model=target.model,
                    api_key=secret,
                    timeout_seconds=runtime.request_timeout_seconds,
                    workspace_id=None,
                    interrupt_event=runtime.interrupt_event,
                    retry_budget=remaining_retry_budget,
                    runner=self.preflight_runner,
                    progress_callback=preflight_progress,
                )
            )
        except StrictPreflightError as error:
            attempts = int(getattr(error, "attempts", 1))
            retries = int(getattr(error, "retries", 0))
            self.database.update_one_model_batch_item_progress(
                target.item_id,
                status="running",
                stage="preflight",
                done=0,
                errors=1,
                request_attempts=prior_attempts + attempts,
                retry_count=prior_retries + retries,
                retry_budget_used=(
                    prior_retry_budget_used + preflight_retry_budget_used
                ),
            )
            raise
        self.database.update_one_model_batch_item_progress(
            target.item_id,
            status="running",
            stage="sampling",
            done=0,
            errors=0,
            request_attempts=prior_attempts + preflight_attempts,
            retry_count=prior_retries + preflight_retries,
            retry_budget_used=(
                prior_retry_budget_used + preflight_retry_budget_used
            ),
        )
        output_path = self.evidence.fingerprint_path(target.item_id)
        samples_path = self.evidence.fingerprint_samples_path(target.item_id)
        observed_node_attempts = 0
        observed_node_retries = 0
        observed_node_retry_budget_used = 0

        def progress(event: dict[str, Any]) -> None:
            nonlocal observed_node_attempts
            nonlocal observed_node_retries
            nonlocal observed_node_retry_budget_used
            observed_node_attempts = int(event.get("attemptCount") or 0)
            observed_node_retries = int(event.get("retryCount") or 0)
            observed_node_retry_budget_used = int(
                event.get("retryBudgetUsed") or 0
            )
            done = int(event.get("done") or 0)
            self.database.update_one_model_batch_item_progress(
                target.item_id,
                status="running",
                stage=str(event.get("stage") or "sampling"),
                done=done,
                errors=int(event.get("errors") or 0),
                request_attempts=(
                    prior_attempts + preflight_attempts + observed_node_attempts
                ),
                retry_count=prior_retries + preflight_retries + observed_node_retries,
                retry_budget_used=(
                    prior_retry_budget_used
                    + preflight_retry_budget_used
                    + observed_node_retry_budget_used
                ),
            )

        try:
            collection_result = await self.fingerprint.collect_paper_profile(
                EndpointSpec(base_url=target.base_url, model=target.model),
                role="audit",
                scheduler_seed=f"relay-auditor:batch:{runtime.batch_id}:row:{target.row_id}",
                output_path=output_path,
                samples_output_path=samples_path,
                samples=30,
                concurrency=runtime.station_concurrency,
                timeout=round(runtime.request_timeout_seconds * 1000),
                api_key=secret,
                transport_profile_id=runtime.transport_profile_id,
                retry_budget=max(
                    0,
                    runtime.retry_budget
                    - prior_retry_budget_used
                    - preflight_retry_budget_used,
                ),
                progress_callback=progress,
                cancel_event=runtime.interrupt_event,
                idle_timeout_seconds=runtime.station_timeout_seconds,
            )
        except Exception as error:
            code, _ = safe_failure_code(error)
            if code == "credential_echo_detected":
                output_path.unlink(missing_ok=True)
                samples_path.unlink(missing_ok=True)
            raise
        if runtime.interrupt_event.is_set():
            raise ExecutionInterrupted("control_interrupt")
        fingerprint = self.evidence.read_json(output_path)
        contract = load_reference_set_manifest(runtime.reference_set.immutable_manifest_json)
        validate_member_fingerprint(
            fingerprint,
            contract,
            require_complete=True,
            protocol=runtime.protocol,
            transport_profile_id=runtime.transport_profile_id,
        )
        raw_sha256 = self.evidence.digest_file(samples_path)
        if fingerprint.get("quality", {}).get("rawEvidenceSha256") != raw_sha256:
            raise ValueError("target raw evidence digest mismatch")
        observations = jsonl_observations(samples_path)
        comparison = await await_interruptibly(
            asyncio.to_thread(
                compare_target_to_reference,
                fingerprint,
                [member_fingerprint for _, _, member_fingerprint in runtime.reference_rows],
                contract,
                runtime.reference_set.pairwise_statistics_json,
                target_protocol=runtime.protocol,
                target_transport_profile_id=runtime.transport_profile_id,
                seed_material=f"batch:{runtime.batch_id}:row:{target.row_id}",
            ),
            runtime.interrupt_event,
        )
        if runtime.interrupt_event.is_set():
            raise ExecutionInterrupted("control_interrupt")
        collection = collection_result.get("collection")
        collection = collection if isinstance(collection, dict) else {}
        quality = assess_fingerprint_quality(fingerprint, cell_ids=contract.cell_ids)
        safe_quality = self._safe_quality(quality, collection)
        node_attempts = int(collection.get("attemptCount") or 1200)
        node_retries = int(collection.get("retryCount") or 0)
        if (
            observed_node_attempts != node_attempts
            or observed_node_retries != node_retries
            or observed_node_retry_budget_used < node_retries
        ):
            raise ValueError("collector request counters do not match progress evidence")
        total_attempts = prior_attempts + preflight_attempts + node_attempts
        total_retries = prior_retries + preflight_retries + node_retries
        total_retry_budget_used = (
            prior_retry_budget_used
            + preflight_retry_budget_used
            + observed_node_retry_budget_used
        )
        discarded_attempts = max(0, total_attempts - total_retries - 1201)
        self.database.update_one_model_batch_item_progress(
            target.item_id,
            status="running",
            stage="comparing",
            done=1200,
            errors=safe_quality["error_samples"],
            request_attempts=total_attempts,
            retry_count=total_retries,
            retry_budget_used=total_retry_budget_used,
        )
        result = self._target_result(
            runtime,
            target,
            comparison,
            preflight=preflight,
            preflight_attempts=preflight_attempts,
            preflight_retries=preflight_retries,
            quality=safe_quality,
            observations=observations,
            total_attempts=total_attempts,
            total_retries=total_retries,
            total_retry_budget_used=total_retry_budget_used,
            discarded_attempts=discarded_attempts,
            artifact_sha256=self.evidence.digest_file(output_path),
            raw_sha256=raw_sha256,
        )
        artifact = self._write_target_result(target, result, secret)
        self.database.finish_one_model_batch_item(
            target.item_id,
            status="completed",
            exploratory_status=str(comparison["status"]),
            reported_model=observations["reported_model"] or preflight.get("reportedModel"),
            latency_p50_ms=observations["latency_p50_ms"],
            latency_p95_ms=observations["latency_p95_ms"],
            quality=safe_quality,
            comparison_json_path=str(artifact.path),
            comparison_json_sha256=artifact.sha256,
            artifact_id=target.item_id,
            artifact_sha256=result["evidence"]["artifact_sha256"],
            raw_evidence_sha256=raw_sha256,
        )
        self._write_partial_checkpoint(runtime)

    async def _finish_failure(
        self,
        runtime: OneModelBatchRuntime,
        target: TargetRuntime,
        *,
        code: str,
        http_status: int | None = None,
        exploratory_status: str = "request_failed",
    ) -> None:
        item = self.database.get_one_model_batch_item(target.item_id)
        if item is None or item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
            return
        secret = self.credentials.resolve(
            target.credential_ref,
            scope="target",
            row_id=target.row_id,
            canonical_base_url=target.base_url,
            model=target.model,
            protocol=runtime.protocol,
        )
        output_path = self.evidence.fingerprint_path(target.item_id)
        samples_path = self.evidence.fingerprint_samples_path(target.item_id)
        if code == "credential_echo_detected":
            output_path.unlink(missing_ok=True)
            samples_path.unlink(missing_ok=True)
        result = {
            "row_id": target.row_id,
            "status": "failed",
            "exploratory_status": exploratory_status,
            "reason_codes": [code],
            "preflight": {
                "status": "failed",
                "http_status": http_status,
                "attempts": item.request_attempts,
                "reason_code": code,
            },
            "error": {"code": code, "http_status": http_status},
            "requests": {
                "logical_samples": item.progress_done,
                "attempts": item.request_attempts,
                "retries": item.retry_count,
                "retry_budget_used": item.retry_budget_used,
                "discarded_attempts": max(
                    0,
                    item.request_attempts - item.retry_count - item.progress_done,
                ),
            },
            "decision_eligible": False,
            "operational_verdict": "unverifiable",
        }
        artifact = self._write_target_result(target, result, secret)
        partial_sha = self.evidence.digest_file(output_path) if output_path.is_file() else None
        self.database.finish_one_model_batch_item(
            target.item_id,
            status="failed",
            exploratory_status=exploratory_status,
            safe_error_code=code,
            error_http_status=http_status,
            quality=item.quality_json,
            comparison_json_path=str(artifact.path),
            comparison_json_sha256=artifact.sha256,
            artifact_id=target.item_id if output_path.is_file() else None,
            partial_artifact_sha256=partial_sha,
        )
        self._write_partial_checkpoint(runtime)

    @staticmethod
    def _safe_quality(quality: dict[str, Any], collection: dict[str, Any]) -> dict[str, Any]:
        return {
            "valid_samples": int(quality.get("validSamples") or 0),
            "invalid_samples": int(quality.get("invalidSamples") or 0)
            + int(quality.get("refusalSamples") or 0)
            + int(quality.get("emptySamples") or 0),
            "refusal_samples": int(quality.get("refusalSamples") or 0),
            "empty_samples": int(quality.get("emptySamples") or 0),
            "error_samples": int(quality.get("errorSamples") or 0),
            "coverage_cells": int(quality.get("sufficientCellCount") or 0),
            "total_cells": int(quality.get("cellCount") or 40),
            "directness": quality.get("directness"),
            "split_half_mean_jsd": collection.get("splitHalfMeanJsd"),
        }

    def _target_result(
        self,
        runtime: OneModelBatchRuntime,
        target: TargetRuntime,
        comparison: dict[str, Any],
        *,
        preflight: dict[str, Any],
        preflight_attempts: int,
        preflight_retries: int,
        quality: dict[str, Any],
        observations: dict[str, Any],
        total_attempts: int,
        total_retries: int,
        total_retry_budget_used: int,
        discarded_attempts: int,
        artifact_sha256: str,
        raw_sha256: str,
    ) -> dict[str, Any]:
        members = [row[1] for row in runtime.reference_rows]
        distances = []
        for item in comparison.get("distances", []):
            ordinal = int(item["referenceMemberOrdinal"])
            interval = item["confidenceInterval95"]
            distances.append(
                {
                    "member_id": members[ordinal - 1].audit_id,
                    "mean_jsd": item["meanJsdBase2"],
                    "ci_lower": interval["lower"],
                    "ci_upper": interval["upper"],
                }
            )
        return {
            "row_id": target.row_id,
            "status": "completed",
            "reported_model": observations["reported_model"] or preflight.get("reportedModel"),
            "exploratory_status": comparison["status"],
            "reason_codes": comparison.get("reasonCodes", []),
            "preflight": {
                "status": "passed",
                "http_status": preflight.get("statusCode"),
                "attempts": preflight_attempts,
                "latency_ms": preflight.get("latencyMs"),
                "retries": preflight_retries,
            },
            "metrics": quality,
            "distances": {
                "members": distances,
                "median_mean_jsd": comparison.get("medianMeanJsdBase2"),
                "mad_mean_jsd": comparison.get("madMeanJsdBase2"),
                "min_mean_jsd": comparison.get("minimumMeanJsdBase2"),
                "max_mean_jsd": comparison.get("maximumMeanJsdBase2"),
            },
            "latency": {
                "p50_ms": observations["latency_p50_ms"],
                "p95_ms": observations["latency_p95_ms"],
            },
            "requests": {
                "logical_samples": 1200,
                "attempts": total_attempts,
                "retries": total_retries,
                "retry_budget_used": total_retry_budget_used,
                "discarded_attempts": discarded_attempts,
            },
            "evidence": {
                "artifact_id": target.item_id,
                "artifact_sha256": artifact_sha256,
                "raw_evidence_sha256": raw_sha256,
            },
            "decision_eligible": False,
            "operational_verdict": "unverifiable",
        }

    def _write_target_result(
        self,
        target: TargetRuntime,
        result: dict[str, Any],
        secret: str,
    ):
        scanner = SecretCanaryScanner([secret])
        path = self.evidence.target_comparison_path(target.item_id)
        scanner.reject(result, delete_paths=(path,))
        return self.evidence.write_json("target_comparisons", target.item_id, result)

    def _terminalize_unfinished(
        self,
        runtime: OneModelBatchRuntime,
        status: str,
        reason_code: str,
    ) -> None:
        for target in runtime.targets:
            item = self.database.get_one_model_batch_item(target.item_id)
            if item is None or item.status in ONE_MODEL_ITEM_TERMINAL_STATUSES:
                continue
            output_path = self.evidence.fingerprint_path(target.item_id)
            self.database.finish_one_model_batch_item(
                target.item_id,
                status=status,
                exploratory_status=status,
                safe_error_code=reason_code,
                quality=item.quality_json,
                artifact_id=target.item_id if output_path.is_file() else None,
                partial_artifact_sha256=(
                    self.evidence.digest_file(output_path) if output_path.is_file() else None
                ),
            )

    def _write_partial_checkpoint(self, runtime: OneModelBatchRuntime) -> None:
        batch = self.database.get_one_model_batch(runtime.batch_id)
        if batch is None:
            return
        payload = {
            "schema_version": "relay-auditor.one-model-batch-checkpoint.v1",
            "batch_id": runtime.batch_id,
            "status": batch.status,
            "reference_set_id": runtime.reference_set.id,
            "items": [
                {
                    key: value
                    for key, value in item.as_dict().items()
                    if key
                    not in {
                        "comparison_json_path",
                    }
                }
                for item in self.database.list_one_model_batch_items(runtime.batch_id)
            ],
        }
        scanner = self._runtime_scanner(runtime)
        path = self.evidence.path_for("batch_checkpoints", runtime.batch_id)
        scanner.reject(payload, delete_paths=(path,))
        self.evidence.write_json("batch_checkpoints", runtime.batch_id, payload)

    async def _finalize_and_cleanup(
        self,
        runtime: OneModelBatchRuntime,
        status: str,
    ) -> bool:
        try:
            return await self._finalize_report(runtime, status)
        finally:
            self._cleanup(runtime)

    async def _finalize_report(self, runtime: OneModelBatchRuntime, status: str) -> bool:
        return await self._finalize_batch_report_fail_closed(
            runtime.batch_id,
            status,
            secret_scanner=self._runtime_scanner(runtime),
        )

    async def _finalize_batch_report_fail_closed(
        self,
        batch_id: str,
        status: str,
        *,
        secret_scanner: SecretCanaryScanner,
    ) -> bool:
        batch = self.database.get_one_model_batch(batch_id)
        if batch is None:
            return False
        # A crash can leave canonical files linked just before the database CAS.
        # They are not registered evidence and must not block the next recovery
        # attempt from publishing a freshly re-verified report.
        with suppress(Exception):
            self._discard_unregistered_report_artifacts(batch_id)
        expected_status = batch.status
        expected_updated_at = batch.updated_at
        attempt_id = uuid4().hex
        canonical_report_path = self.evidence.batch_report_path(batch_id)
        canonical_csv_path = self.evidence.batch_csv_path(batch_id)
        staging_report_path = canonical_report_path.with_name(
            f".{canonical_report_path.name}.{attempt_id}.staging"
        )
        staging_csv_path = canonical_csv_path.with_name(
            f".{canonical_csv_path.name}.{attempt_id}.staging"
        )
        finalizer = asyncio.create_task(
            asyncio.to_thread(
                self._prepare_persisted_report,
                batch_id,
                status,
                secret_scanner=secret_scanner,
                report_path=staging_report_path,
                csv_path=staging_csv_path,
            )
        )
        self._report_finalizers.add(finalizer)
        try:
            prepared = await asyncio.wait_for(
                asyncio.shield(finalizer),
                timeout=self.report_finalization_timeout_seconds,
            )
        except asyncio.CancelledError:
            self._defer_staging_cleanup(
                batch_id,
                finalizer,
                staging_report_path,
                staging_csv_path,
            )
            with suppress(Exception):
                self._fail_report_finalization(
                    batch_id,
                    expected_status=expected_status,
                    expected_updated_at=expected_updated_at,
                    staging_paths=(staging_report_path, staging_csv_path),
                )
            raise
        except Exception:
            if finalizer.done():
                self._report_finalizers.discard(finalizer)
            else:
                self._defer_staging_cleanup(
                    batch_id,
                    finalizer,
                    staging_report_path,
                    staging_csv_path,
                )
            with suppress(Exception):
                self._fail_report_finalization(
                    batch_id,
                    expected_status=expected_status,
                    expected_updated_at=expected_updated_at,
                    staging_paths=(staging_report_path, staging_csv_path),
                )
            return False
        self._report_finalizers.discard(finalizer)
        try:
            self._publish_prepared_report(
                batch_id,
                status,
                prepared,
                expected_status=expected_status,
                expected_updated_at=expected_updated_at,
            )
        except Exception:
            with suppress(Exception):
                self._fail_report_finalization(
                    batch_id,
                    expected_status=expected_status,
                    expected_updated_at=expected_updated_at,
                    staging_paths=(staging_report_path, staging_csv_path),
                )
            return False
        return True

    def _fail_report_finalization(
        self,
        batch_id: str,
        *,
        expected_status: str,
        expected_updated_at: Any,
        staging_paths: tuple[Path, Path],
    ) -> None:
        try:
            self.database.fail_one_model_batch_finalization(
                batch_id,
                expected_status=expected_status,
                expected_updated_at=expected_updated_at,
            )
        finally:
            self._discard_paths(staging_paths)
            self._discard_unregistered_report_artifacts(batch_id)

    def _defer_staging_cleanup(
        self,
        batch_id: str,
        finalizer: asyncio.Task[PreparedBatchReport],
        report_path: Path,
        csv_path: Path,
    ) -> None:
        finalizer.add_done_callback(
            lambda completed: self._finish_late_finalizer(
                batch_id,
                completed,
                report_path,
                csv_path,
            )
        )

    def _finish_late_finalizer(
        self,
        batch_id: str,
        finalizer: asyncio.Task[PreparedBatchReport],
        report_path: Path,
        csv_path: Path,
    ) -> None:
        self._report_finalizers.discard(finalizer)
        with suppress(asyncio.CancelledError, Exception):
            finalizer.result()
        self._discard_paths((report_path, csv_path))
        self._discard_unregistered_report_artifacts(batch_id)

    def _publish_prepared_report(
        self,
        batch_id: str,
        status: str,
        prepared: PreparedBatchReport,
        *,
        expected_status: str,
        expected_updated_at: Any,
    ) -> None:
        report_path = self.evidence.batch_report_path(batch_id)
        csv_path = self.evidence.batch_csv_path(batch_id)
        try:
            os.link(prepared.report_path, report_path)
            os.link(prepared.csv_path, csv_path)
            self._fsync_directory(report_path.parent)
            if csv_path.parent != report_path.parent:
                self._fsync_directory(csv_path.parent)
            self.database.attach_one_model_batch_report(
                batch_id,
                status=status,
                report_path=str(report_path),
                report_sha256=prepared.report_sha256,
                expected_status=expected_status,
                expected_updated_at=expected_updated_at,
            )
        finally:
            self._discard_paths((prepared.report_path, prepared.csv_path))

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor: int | None = None
        with suppress(OSError):
            descriptor = os.open(path, os.O_RDONLY)
        if descriptor is None:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _discard_paths(paths: tuple[Path, ...]) -> None:
        for path in paths:
            with suppress(OSError):
                path.unlink(missing_ok=True)

    def _discard_unregistered_report_artifacts(self, batch_id: str) -> None:
        try:
            batch = self.database.get_one_model_batch(batch_id)
        except Exception:
            return
        if batch is None or batch.report_path is not None or batch.report_sha256 is not None:
            return
        self._discard_paths(
            (
                self.evidence.batch_report_path(batch_id),
                self.evidence.batch_csv_path(batch_id),
            )
        )

    def _prepare_persisted_report(
        self,
        batch_id: str,
        status: str,
        *,
        secret_scanner: SecretCanaryScanner,
        report_path: Path,
        csv_path: Path,
    ) -> PreparedBatchReport:
        batch = self.database.get_one_model_batch(batch_id)
        if batch is None:
            raise LookupError(f"one-model batch not found: {batch_id}")
        reference_set, reference_rows = load_verified_reference_bundle(
            self.database,
            self.evidence,
            batch.reference_set_id,
        )
        reference_payload = self._reference_report_payload(reference_set, reference_rows)
        items = self.database.list_one_model_batch_items(batch_id)
        input_rows = [
            {
                "row_id": item.row_id,
                "station_name": item.station_name,
                "base_url": item.canonical_base_url,
                "model_id": item.model,
            }
            for item in items
        ]
        results = self._verified_target_results(
            batch,
            items,
            reference_set,
            reference_rows,
        )
        report = build_terminal_batch_report(
            batch={
                "batch_id": batch.id,
                "status": status,
                "protocol": batch.protocol,
                "transport_profile": batch.transport_profile_id,
                "logical_model": reference_set.logical_model,
                "default_model_id": batch.default_model,
                "created_at": batch.as_dict()["created_at"],
                "completed_at": batch.as_dict()["completed_at"],
            },
            reference_set=reference_payload,
            input_rows=input_rows,
            target_results=results,
            tool={"name": "relay-model-auditor", "version": __version__, "git_sha": self.git_sha},
            secret_scanner=secret_scanner,
        )
        report_artifact = write_terminal_batch_report(
            report_path,
            report,
            secret_scanner=secret_scanner,
        )
        write_verified_batch_csv(
            csv_path,
            json_path=report_path,
            expected_json_sha256=report_artifact.sha256,
            secret_scanner=secret_scanner,
        )
        return PreparedBatchReport(
            report_path=report_path,
            csv_path=csv_path,
            report_sha256=report_artifact.sha256,
        )

    def _verified_target_results(
        self,
        batch: Any,
        items: list[Any],
        reference_set: Any,
        reference_rows: list[tuple[Any, Any, dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        """Re-verify terminal evidence and recompute every completed comparison."""

        contract = load_reference_set_manifest(reference_set.immutable_manifest_json)
        reference_fingerprints = [row[2] for row in reference_rows]
        member_ids = [row[1].audit_id for row in reference_rows]
        results: list[dict[str, Any]] = []
        for item in items:
            stored = self._stored_target_result(item)
            if item.status != "completed":
                results.append(stored)
                continue
            if (
                item.artifact_id != item.id
                or not item.artifact_sha256
                or not item.raw_evidence_sha256
                or not item.comparison_json_sha256
            ):
                raise ValueError("completed target evidence registration is incomplete")
            fingerprint_path = self.evidence.fingerprint_path(item.id)
            fingerprint = self.evidence.read_verified_json(
                fingerprint_path,
                item.artifact_sha256,
                expected_path=fingerprint_path,
            )
            raw_path = self.evidence.fingerprint_samples_path(item.id)
            self.evidence.verify_registered_path(
                raw_path,
                item.raw_evidence_sha256,
                expected_path=raw_path,
            )
            validate_member_fingerprint(
                fingerprint,
                contract,
                expected_model=item.model,
                expected_raw_evidence_sha256=item.raw_evidence_sha256,
                require_complete=True,
                protocol=batch.protocol,
                transport_profile_id=batch.transport_profile_id,
            )
            comparison = compare_target_to_reference(
                fingerprint,
                reference_fingerprints,
                contract,
                reference_set.pairwise_statistics_json,
                target_protocol=batch.protocol,
                target_transport_profile_id=batch.transport_profile_id,
                seed_material=f"batch:{batch.id}:row:{item.row_id}",
            )
            expected_distances = []
            for distance in comparison.get("distances", []):
                ordinal = int(distance["referenceMemberOrdinal"])
                interval = distance["confidenceInterval95"]
                expected_distances.append(
                    {
                        "member_id": member_ids[ordinal - 1],
                        "mean_jsd": distance["meanJsdBase2"],
                        "ci_lower": interval["lower"],
                        "ci_upper": interval["upper"],
                    }
                )
            expected_distance_summary = {
                "members": expected_distances,
                "median_mean_jsd": comparison.get("medianMeanJsdBase2"),
                "mad_mean_jsd": comparison.get("madMeanJsdBase2"),
                "min_mean_jsd": comparison.get("minimumMeanJsdBase2"),
                "max_mean_jsd": comparison.get("maximumMeanJsdBase2"),
            }
            assessed = assess_fingerprint_quality(fingerprint, cell_ids=contract.cell_ids)
            expected_quality = self._safe_quality(
                assessed,
                {"splitHalfMeanJsd": stored.get("metrics", {}).get("split_half_mean_jsd")},
            )
            for key, expected in expected_quality.items():
                if stored.get("metrics", {}).get(key) != expected:
                    raise ValueError("stored target quality does not match fingerprint evidence")
            if (
                stored.get("status") != "completed"
                or stored.get("exploratory_status") != comparison["status"]
                or stored.get("reason_codes") != comparison.get("reasonCodes", [])
                or stored.get("distances") != expected_distance_summary
                or stored.get("decision_eligible") is not False
                or stored.get("operational_verdict") != "unverifiable"
            ):
                raise ValueError("stored target comparison does not match recomputed evidence")
            requests = stored.get("requests", {})
            if (
                requests.get("logical_samples") != 1200
                or requests.get("attempts") != item.request_attempts
                or requests.get("retries") != item.retry_count
                or requests.get("retry_budget_used") != item.retry_budget_used
                or requests.get("discarded_attempts")
                != max(0, item.request_attempts - item.retry_count - 1201)
            ):
                raise ValueError("stored target request counters do not match the ledger")
            stored_evidence = stored.get("evidence", {})
            if (
                stored_evidence.get("artifact_id") != item.id
                or stored_evidence.get("artifact_sha256") != item.artifact_sha256
                or stored_evidence.get("raw_evidence_sha256") != item.raw_evidence_sha256
            ):
                raise ValueError("stored target evidence hashes do not match the ledger")
            results.append(stored)
        return results

    def _reference_report_payload(
        self,
        reference_set: Any,
        reference_rows: list[tuple[Any, Any, dict[str, Any]]],
    ) -> dict[str, Any]:
        members = [row[1] for row in reference_rows]
        contract = load_reference_set_manifest(reference_set.immutable_manifest_json)
        statistics = reference_set.pairwise_statistics_json
        member_ids = {member.ordinal: member.audit_id for member in members}
        pairwise = [
            {
                "left_member_id": member_ids[item["leftMemberOrdinal"]],
                "right_member_id": member_ids[item["rightMemberOrdinal"]],
                "mean_jsd": item["meanJsdBase2"],
                "ci_lower": item["confidenceInterval95"]["lower"],
                "ci_upper": item["confidenceInterval95"]["upper"],
            }
            for item in statistics["pairwiseComparisons"]
        ]
        return {
            "reference_set_id": reference_set.id,
            "name": reference_set.reference_name,
            "source_type": reference_set.source_type,
            "protocol": reference_set.protocol,
            "transport_profile": reference_set.transport_profile_id,
            "logical_model": reference_set.logical_model,
            "model_id": reference_set.actual_model,
            "base_url": reference_set.normalized_base_url,
            "battery_sha256": reference_set.immutable_manifest_json[
                "batteryManifestSha256"
            ],
            "samples_per_cell": reference_set.samples_per_cell,
            "created_at": reference_set.as_dict()["created_at"],
            "members": [
                {
                    "member_id": member.audit_id,
                    "ordinal": member.ordinal,
                    "seed_id": member.scheduler_seed,
                    "artifact_id": member.artifact_id,
                    "artifact_sha256": member.artifact_sha256,
                    "raw_evidence_sha256": member.raw_evidence_sha256,
                    "created_at": member.as_dict()["created_at"],
                    # The database stores the collector's quality block.  Coverage
                    # is independently derived from the verified fingerprint so a
                    # stale or incomplete database summary cannot make a damaged
                    # reference look selectable in a terminal report.
                    "quality": self._reference_member_quality(
                        assess_fingerprint_quality(
                            fingerprint,
                            cell_ids=contract.cell_ids,
                        ),
                        member.quality_json,
                    ),
                }
                for _audit, member, fingerprint in reference_rows
            ],
            "pairwise_distances": pairwise,
            "envelope": {"max_upper_jsd": statistics["referenceEnvelope"]},
        }

    @staticmethod
    def _reference_member_quality(
        assessed: dict[str, Any],
        collector_quality: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "valid_samples": assessed.get("validSamples"),
            "invalid_samples": (
                int(assessed.get("invalidSamples") or 0)
                + int(assessed.get("refusalSamples") or 0)
                + int(assessed.get("emptySamples") or 0)
            ),
            "error_samples": assessed.get("errorSamples"),
            "coverage_cells": assessed.get("sufficientCellCount"),
            "total_cells": assessed.get("cellCount"),
            "directness": assessed.get("directness"),
            "split_half_mean_jsd": collector_quality.get("splitHalfMeanJsd"),
        }

    def _stored_target_result(self, item: Any) -> dict[str, Any]:
        if item.comparison_json_path and item.comparison_json_sha256:
            return self.evidence.read_verified_json(
                item.comparison_json_path,
                item.comparison_json_sha256,
                expected_path=self.evidence.target_comparison_path(item.id),
            )
        return {
            "row_id": item.row_id,
            "status": item.status,
            "reported_model": item.reported_model,
            "exploratory_status": item.exploratory_status or item.status,
            "reason_codes": [item.safe_error_code] if item.safe_error_code else [],
            "metrics": item.quality_json,
            "requests": {
                "logical_samples": item.progress_done,
                "attempts": item.request_attempts,
                "retries": item.retry_count,
                "retry_budget_used": item.retry_budget_used,
                "discarded_attempts": max(
                    0,
                    item.request_attempts - item.retry_count - item.progress_done,
                ),
            },
            "evidence": {
                "artifact_id": item.artifact_id,
                "artifact_sha256": item.artifact_sha256,
                "raw_evidence_sha256": item.raw_evidence_sha256,
                "partial_artifact_sha256": item.partial_artifact_sha256,
            },
            "error": {"code": item.safe_error_code, "http_status": item.error_http_status},
        }

    def _runtime_scanner(self, runtime: OneModelBatchRuntime) -> SecretCanaryScanner:
        secrets: list[str] = []
        for target in runtime.targets:
            try:
                secrets.append(
                    self.credentials.resolve(
                        target.credential_ref,
                        scope="target",
                        row_id=target.row_id,
                        canonical_base_url=target.base_url,
                        model=target.model,
                        protocol=runtime.protocol,
                    )
                )
            except ValueError:
                continue
        return SecretCanaryScanner(secrets)

    def _cleanup(self, runtime: OneModelBatchRuntime) -> None:
        for target in runtime.targets:
            self.credentials.discard(target.credential_ref)
        self._runtimes.pop(runtime.batch_id, None)
