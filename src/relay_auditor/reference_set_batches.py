from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import Any
from uuid import uuid4

from relay_auditor.batch_reports import SecretCanaryScanner
from relay_auditor.credentials import CredentialSource, RuntimeCredentialStore
from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import (
    FingerprintPausedError,
    FingerprintRunner,
    paper_manifest_for_transport,
    paper_profile_cell_ids,
)
from relay_auditor.evidence import EvidenceStore
from relay_auditor.execution_utils import (
    ExecutionInterrupted,
    await_interruptibly,
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
from relay_auditor.reference_sets import (
    DEFAULT_BOOTSTRAP_ITERATIONS,
    assess_fingerprint_quality,
    build_reference_set_manifest,
    build_reference_statistics,
    fingerprint_manifest_sha256,
    load_reference_set_manifest,
    reference_manifest_sha256,
    validate_member_fingerprint,
    validate_reference_statistics_payload,
)
from relay_auditor.schemas import EndpointSpec, ReferenceSetCreateRequest
from relay_auditor.strict_preflight import StrictPreflightError, run_strict_preflight

TERMINAL_REFERENCE_STATUSES = {"ready", "failed", "canceled", "interrupted"}


@dataclass(slots=True)
class ReferenceSetRuntime:
    reference_set_id: str
    audit_ids: list[str]
    protocol: str
    transport_profile_id: str
    actual_model: str
    base_url: str
    workspace_id: str | None
    concurrency: int
    request_timeout_seconds: float
    member_timeout_seconds: float
    credential_ref: str
    resolution: EndpointResolution
    member_remaining_seconds: dict[str, float]
    interrupt_event: asyncio.Event
    lock: asyncio.Lock
    worker: asyncio.Task[None] | None = None
    pause_requested: bool = False
    cancel_requested: bool = False
    shutdown_requested: bool = False


def load_verified_reference_bundle(
    database: Database,
    evidence: EvidenceStore,
    reference_set_id: str,
    *,
    require_ready: bool = True,
) -> tuple[Any, list[tuple[Any, Any, dict[str, Any]]]]:
    reference_set = database.get_reference_set(reference_set_id)
    if reference_set is None:
        raise LookupError(f"ReferenceSet not found: {reference_set_id}")
    if require_ready and reference_set.status != "ready":
        raise ValueError("ReferenceSet is not ready")
    contract = load_reference_set_manifest(reference_set.immutable_manifest_json)
    if reference_manifest_sha256(contract.as_dict()) != reference_set.immutable_manifest_sha256:
        raise ValueError("ReferenceSet immutable manifest digest mismatch")
    rows = database.get_reference_set_rows(reference_set_id)
    if len(rows) != 3:
        raise ValueError("ReferenceSet does not contain exactly three members")
    verified: list[tuple[Any, Any, dict[str, Any]]] = []
    for run, member in rows:
        if member.status != "completed":
            raise ValueError("ReferenceSet contains an incomplete member")
        expected_fingerprint = evidence.fingerprint_path(member.audit_id)
        fingerprint = evidence.read_verified_json(
            member.artifact_path,
            member.artifact_sha256,
            expected_path=expected_fingerprint,
        )
        raw_path = evidence.fingerprint_samples_path(member.audit_id)
        evidence.verify_registered_path(
            raw_path,
            member.raw_evidence_sha256,
            expected_path=raw_path,
        )
        FingerprintRunner._validate_v2_fingerprint(
            fingerprint,
            label=f"ReferenceSet member {member.ordinal}",
        )
        validate_member_fingerprint(
            fingerprint,
            contract,
            expected_model=contract.actual_model,
            expected_raw_evidence_sha256=member.raw_evidence_sha256,
            protocol=contract.protocol,
            transport_profile_id=contract.transport_profile_id,
        )
        if fingerprint_manifest_sha256(fingerprint) != member.fingerprint_manifest_sha256:
            raise ValueError("ReferenceSet member fingerprint manifest digest mismatch")
        verified.append((run, member, fingerprint))
    if require_ready:
        if not isinstance(reference_set.pairwise_statistics_json, dict):
            raise ValueError("ReferenceSet statistics are missing")
        statistics = validate_reference_statistics_payload(
            reference_set.pairwise_statistics_json
        )
        if statistics["referenceManifestSha256"] != reference_set.immutable_manifest_sha256:
            raise ValueError("ReferenceSet statistics manifest digest mismatch")
        if any(
            comparison["confidenceInterval95"]["iterations"]
            != DEFAULT_BOOTSTRAP_ITERATIONS
            for comparison in statistics["pairwiseComparisons"]
        ):
            raise ValueError("ReferenceSet statistics require exactly 2000 bootstrap iterations")
        if reference_set.reference_envelope != statistics["referenceEnvelope"]:
            raise ValueError("ReferenceSet stored envelope does not match verified statistics")
    return reference_set, verified


class ReferenceSetManager:
    """Sequentially collect three immutable members with process-local credentials."""

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
    ) -> None:
        self.database = database
        self.evidence = evidence
        self.fingerprint = fingerprint
        self.credentials = credentials
        self.resolver = resolver
        self.preflight_runner = preflight_runner
        self.allow_test_loopback = allow_test_loopback
        self._runtimes: dict[str, ReferenceSetRuntime] = {}

    async def start(
        self,
        request: ReferenceSetCreateRequest,
        *,
        credential_secret: str,
        credential_source: CredentialSource,
    ) -> str:
        SecretCanaryScanner([credential_secret]).reject(
            {
                "reference_name": request.reference_name,
                "source_type": request.source_type,
                "protocol": request.protocol,
                "transport_profile_id": request.transport_profile_id,
                "logical_model": request.logical_model,
                "actual_model": request.actual_model,
                "base_url": str(request.base_url),
                "anthropic_workspace_id": request.anthropic_workspace_id,
            }
        )
        resolution = await validate_public_endpoint(
            str(request.base_url),
            request.protocol,
            resolver=self.resolver,
            allow_test_loopback=self.allow_test_loopback,
        )
        reference_set_id = str(uuid4())
        audit_ids = [str(uuid4()) for _ in range(3)]
        scheduler_seeds = [
            f"relay-auditor:reference:{reference_set_id}:member:{ordinal}:{uuid4().hex}"
            for ordinal in range(1, 4)
        ]
        battery_manifest = paper_manifest_for_transport(request.transport_profile_id)
        manifest = build_reference_set_manifest(
            protocol=request.protocol,
            transport_profile_id=request.transport_profile_id,
            logical_model=request.logical_model.strip(),
            actual_model=request.actual_model.strip(),
            base_url=resolution.base_url,
            cell_ids=paper_profile_cell_ids(),
            battery_manifest=battery_manifest,
        )
        credential_ref = self.credentials.register(
            scope="reference",
            row_id=reference_set_id,
            canonical_base_url=resolution.base_url,
            model=request.actual_model.strip(),
            protocol=request.protocol,
            source=credential_source,
            secret=credential_secret,
        )
        try:
            self.database.create_reference_set_queue(
                reference_set_id=reference_set_id,
                audit_ids=audit_ids,
                scheduler_seeds=scheduler_seeds,
                reference_name=request.reference_name.strip(),
                source_type=request.source_type,
                immutable_manifest=manifest,
            )
        except Exception:
            self.credentials.discard(credential_ref)
            raise
        runtime = ReferenceSetRuntime(
            reference_set_id=reference_set_id,
            audit_ids=audit_ids,
            protocol=request.protocol,
            transport_profile_id=request.transport_profile_id,
            actual_model=request.actual_model.strip(),
            base_url=resolution.base_url,
            workspace_id=request.anthropic_workspace_id,
            concurrency=request.concurrency,
            request_timeout_seconds=request.request_timeout_seconds,
            member_timeout_seconds=request.member_timeout_seconds,
            credential_ref=credential_ref,
            resolution=resolution,
            member_remaining_seconds={
                audit_id: request.member_timeout_seconds for audit_id in audit_ids
            },
            interrupt_event=asyncio.Event(),
            lock=asyncio.Lock(),
        )
        self._runtimes[reference_set_id] = runtime
        runtime.worker = asyncio.create_task(self._run(runtime))
        return reference_set_id

    async def pause(self, reference_set_id: str) -> None:
        runtime = self._active_runtime(reference_set_id)
        async with runtime.lock:
            current = self.database.get_reference_set(reference_set_id)
            if current is None:
                raise LookupError(f"ReferenceSet not found: {reference_set_id}")
            if current.status == "paused":
                return
            if current.status in TERMINAL_REFERENCE_STATUSES:
                raise ValueError("terminal ReferenceSet cannot be paused")
            runtime.pause_requested = True
            self.database.set_reference_set_status(reference_set_id, "pausing")
            runtime.interrupt_event.set()
            worker = runtime.worker
        if worker is not None and not worker.done():
            await asyncio.shield(worker)

    async def resume(self, reference_set_id: str) -> None:
        runtime = self._active_runtime(reference_set_id)
        async with runtime.lock:
            current = self.database.get_reference_set(reference_set_id)
            if current is None:
                raise LookupError(f"ReferenceSet not found: {reference_set_id}")
            if current.status != "paused":
                raise ValueError("only a paused ReferenceSet can be resumed")
            runtime.pause_requested = False
            runtime.shutdown_requested = False
            runtime.interrupt_event.clear()
            self.database.set_reference_set_status(reference_set_id, "collecting")
            runtime.worker = asyncio.create_task(self._run(runtime))

    async def cancel(self, reference_set_id: str) -> None:
        runtime = self._active_runtime(reference_set_id)
        async with runtime.lock:
            runtime.cancel_requested = True
            runtime.pause_requested = False
            self.database.set_reference_set_status(reference_set_id, "canceling")
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
        # A paused worker has already exited, so it cannot observe the shutdown
        # event. Close those snapshots explicitly while the in-memory key is
        # still available, preserving completed member evidence.
        for runtime in list(self._runtimes.values()):
            current = self.database.get_reference_set(runtime.reference_set_id)
            if current is not None and current.status not in TERMINAL_REFERENCE_STATUSES:
                self._terminalize_unfinished(
                    runtime,
                    "interrupted",
                    "service_shutdown",
                )
                self._cleanup(runtime)
        self.credentials.discard_scope("reference")

    def _active_runtime(self, reference_set_id: str) -> ReferenceSetRuntime:
        reference_set = self.database.get_reference_set(reference_set_id)
        if reference_set is None:
            raise LookupError(f"ReferenceSet not found: {reference_set_id}")
        runtime = self._runtimes.get(reference_set_id)
        if runtime is None:
            if reference_set.status in TERMINAL_REFERENCE_STATUSES:
                raise ValueError("ReferenceSet is already terminal")
            raise ValueError("ReferenceSet credential is unavailable after service restart")
        return runtime

    async def _run(self, runtime: ReferenceSetRuntime) -> None:
        try:
            while True:
                if runtime.interrupt_event.is_set():
                    raise ExecutionInterrupted("control_interrupt")
                pending = [
                    (run, member)
                    for run, member in self.database.get_reference_set_rows(
                        runtime.reference_set_id
                    )
                    if member.status in {"queued", "paused"}
                ]
                if not pending:
                    await self._finalize(runtime)
                    self._cleanup(runtime)
                    return
                _, member = pending[0]
                remaining = runtime.member_remaining_seconds[member.audit_id]
                active_started = monotonic()
                try:
                    if remaining <= 0:
                        raise TimeoutError
                    await asyncio.wait_for(
                        self._collect_member(runtime, member),
                        timeout=remaining,
                    )
                finally:
                    runtime.member_remaining_seconds[member.audit_id] = max(
                        0.0,
                        remaining - (monotonic() - active_started),
                    )
        except (ExecutionInterrupted, FingerprintPausedError):
            if runtime.cancel_requested:
                self._terminalize_unfinished(runtime, "canceled", "reference_set_canceled")
                self._cleanup(runtime)
            elif runtime.shutdown_requested:
                self._terminalize_unfinished(
                    runtime,
                    "interrupted",
                    "credential_lost_after_restart",
                )
                self._cleanup(runtime)
            elif runtime.pause_requested:
                for _, member in self.database.get_reference_set_rows(runtime.reference_set_id):
                    if member.status in {"queued", "running"}:
                        self.database.pause_reference_set_member(member.audit_id)
                self.database.set_reference_set_status(runtime.reference_set_id, "paused")
        except TimeoutError:
            self._terminalize_unfinished(runtime, "failed", "member_wall_clock_timeout")
            self._cleanup(runtime)
        except Exception as error:
            code, _ = safe_failure_code(error)
            self._terminalize_unfinished(runtime, "failed", code)
            self._cleanup(runtime)

    async def _collect_member(self, runtime: ReferenceSetRuntime, member: Any) -> None:
        member = self.database.set_reference_set_member_running(member.audit_id)
        prior_attempts = int(member.request_attempts)
        prior_retries = int(member.retry_count)
        prior_retry_budget_used = int(member.retry_budget_used)
        resolution = await await_interruptibly(
            revalidate_public_endpoint(
                runtime.resolution,
                resolver=self.resolver,
                allow_test_loopback=self.allow_test_loopback,
            ),
            runtime.interrupt_event,
            timeout_seconds=runtime.request_timeout_seconds,
        )
        secret = self.credentials.resolve(
            runtime.credential_ref,
            scope="reference",
            row_id=runtime.reference_set_id,
            canonical_base_url=runtime.base_url,
            model=runtime.actual_model,
            protocol=runtime.protocol,
        )
        preflight_progress = {
            "attempt_count": 0,
            "retry_count": 0,
            "retry_budget_used": 0,
        }

        def update_preflight_progress(event: dict[str, int]) -> None:
            preflight_progress.update(event)
            self.database.update_reference_set_member_progress(
                member.audit_id,
                stage="preflight",
                done=0,
                errors=0,
                request_attempts=prior_attempts + event["attempt_count"],
                retry_count=prior_retries + event["retry_count"],
                retry_budget_used=(
                    prior_retry_budget_used + event["retry_budget_used"]
                ),
            )

        try:
            _, preflight_attempts, preflight_retries = await strict_preflight_with_retry(
                resolution,
                model=runtime.actual_model,
                api_key=secret,
                timeout_seconds=runtime.request_timeout_seconds,
                workspace_id=runtime.workspace_id,
                interrupt_event=runtime.interrupt_event,
                retry_budget=max(0, 240 - prior_retry_budget_used),
                runner=self.preflight_runner,
                progress_callback=update_preflight_progress,
            )
        except StrictPreflightError:
            self.database.update_reference_set_member_progress(
                member.audit_id,
                stage="preflight",
                done=0,
                errors=1,
                request_attempts=(
                    prior_attempts + preflight_progress["attempt_count"]
                ),
                retry_count=prior_retries + preflight_progress["retry_count"],
                retry_budget_used=(
                    prior_retry_budget_used
                    + preflight_progress["retry_budget_used"]
                ),
            )
            raise
        preflight_retry_budget_used = preflight_progress["retry_budget_used"]
        self.database.update_reference_set_member_progress(
            member.audit_id,
            stage="sampling",
            done=0,
            errors=0,
            request_attempts=prior_attempts + preflight_attempts,
            retry_count=prior_retries + preflight_retries,
            retry_budget_used=prior_retry_budget_used + preflight_retry_budget_used,
        )
        output_path = self.evidence.fingerprint_path(member.audit_id)
        samples_path = self.evidence.fingerprint_samples_path(member.audit_id)
        node_progress = {
            "attempt_count": 0,
            "retry_count": 0,
            "retry_budget_used": 0,
            "done": 0,
            "errors": 0,
        }

        def progress(event: dict[str, Any]) -> None:
            for event_key, state_key in (
                ("attemptCount", "attempt_count"),
                ("retryCount", "retry_count"),
                ("retryBudgetUsed", "retry_budget_used"),
                ("done", "done"),
                ("errors", "errors"),
            ):
                value = event.get(event_key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    node_progress[state_key] = value
            self.database.update_reference_set_member_progress(
                member.audit_id,
                stage=str(event.get("stage") or "sampling"),
                done=node_progress["done"],
                errors=node_progress["errors"],
                request_attempts=(
                    prior_attempts
                    + preflight_attempts
                    + node_progress["attempt_count"]
                ),
                retry_count=(
                    prior_retries + preflight_retries + node_progress["retry_count"]
                ),
                retry_budget_used=(
                    prior_retry_budget_used
                    + preflight_retry_budget_used
                    + node_progress["retry_budget_used"]
                ),
            )

        try:
            result = await self.fingerprint.collect_paper_profile(
                EndpointSpec(base_url=runtime.base_url, model=runtime.actual_model),
                role="enrollment",
                scheduler_seed=member.scheduler_seed,
                output_path=output_path,
                samples_output_path=samples_path,
                samples=30,
                concurrency=runtime.concurrency,
                timeout=round(runtime.request_timeout_seconds * 1000),
                api_key=secret,
                transport_profile_id=runtime.transport_profile_id,
                anthropic_workspace_id=runtime.workspace_id,
                retry_budget=max(
                    0,
                    240 - prior_retry_budget_used - preflight_retry_budget_used,
                ),
                progress_callback=progress,
                cancel_event=runtime.interrupt_event,
                idle_timeout_seconds=runtime.member_timeout_seconds,
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
        raw_sha256 = self.evidence.digest_file(samples_path)
        contract = load_reference_set_manifest(
            self.database.get_reference_set(runtime.reference_set_id).immutable_manifest_json
        )
        validate_member_fingerprint(
            fingerprint,
            contract,
            expected_model=runtime.actual_model,
            expected_raw_evidence_sha256=raw_sha256,
            protocol=runtime.protocol,
            transport_profile_id=runtime.transport_profile_id,
        )
        quality = assess_fingerprint_quality(fingerprint, cell_ids=contract.cell_ids)
        collection = result.get("collection")
        if not isinstance(collection, dict):
            raise ValueError("collector did not return request counter evidence")
        node_attempts = int(collection.get("attemptCount") or 0)
        node_retries = int(collection.get("retryCount") or 0)
        node_retry_budget_used = node_progress["retry_budget_used"]
        if (
            node_progress["attempt_count"] != node_attempts
            or node_progress["retry_count"] != node_retries
            or node_retry_budget_used < node_retries
        ):
            raise ValueError("collector request counters do not match progress evidence")
        total_attempts = prior_attempts + preflight_attempts + node_attempts
        total_retries = prior_retries + preflight_retries + node_retries
        total_retry_budget_used = (
            prior_retry_budget_used
            + preflight_retry_budget_used
            + node_retry_budget_used
        )
        discarded_attempts = max(
            0,
            total_attempts - total_retries - 1_201,
        )
        self.database.update_reference_set_member_progress(
            member.audit_id,
            stage="sampling",
            done=1_200,
            errors=node_progress["errors"],
            request_attempts=total_attempts,
            retry_count=total_retries,
            retry_budget_used=total_retry_budget_used,
        )
        quality["splitHalfMeanJsd"] = collection.get("splitHalfMeanJsd")
        quality["attemptCount"] = total_attempts
        quality["retryCount"] = total_retries
        quality["retryBudgetUsed"] = total_retry_budget_used
        quality["discardedAttemptCount"] = discarded_attempts
        artifact_sha256 = self.evidence.digest_file(output_path)
        self.database.complete_reference_set_member(
            member.audit_id,
            artifact_id=member.audit_id,
            artifact_path=str(output_path),
            artifact_sha256=artifact_sha256,
            raw_evidence_sha256=raw_sha256,
            reference_manifest_sha256=reference_manifest_sha256(contract.as_dict()),
            fingerprint_manifest_sha256=fingerprint_manifest_sha256(fingerprint),
            quality=quality,
        )

    async def _finalize(self, runtime: ReferenceSetRuntime) -> None:
        reference_set, rows = load_verified_reference_bundle(
            self.database,
            self.evidence,
            runtime.reference_set_id,
            require_ready=False,
        )
        statistics = await await_interruptibly(
            asyncio.to_thread(
                build_reference_statistics,
                [fingerprint for _, _, fingerprint in rows],
                reference_set.immutable_manifest_json,
                seed_material=f"reference-set:{runtime.reference_set_id}",
            ),
            runtime.interrupt_event,
        )
        if runtime.interrupt_event.is_set():
            raise ExecutionInterrupted("control_interrupt")
        self.database.finalize_reference_set(runtime.reference_set_id, statistics=statistics)

    def _terminalize_unfinished(
        self,
        runtime: ReferenceSetRuntime,
        status: str,
        reason_code: str,
    ) -> None:
        for _, member in self.database.get_reference_set_rows(runtime.reference_set_id):
            if member.status == "completed":
                continue
            output_path = self.evidence.fingerprint_path(member.audit_id)
            artifact_path = str(output_path) if output_path.is_file() else None
            artifact_sha256 = (
                self.evidence.digest_file(output_path) if output_path.is_file() else None
            )
            self.database.fail_reference_set_member(
                member.audit_id,
                status=status,
                reason_code=reason_code,
                artifact_path=artifact_path,
                artifact_sha256=artifact_sha256,
            )

    def _cleanup(self, runtime: ReferenceSetRuntime) -> None:
        self.credentials.discard(runtime.credential_ref)
        self._runtimes.pop(runtime.reference_set_id, None)
