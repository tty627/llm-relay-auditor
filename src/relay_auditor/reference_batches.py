import asyncio
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from relay_auditor.database import Database, ReferenceCollectionItem
from relay_auditor.detectors.fingerprint import (
    FingerprintPausedError,
    FingerprintRunner,
    FingerprintStalledError,
)
from relay_auditor.evidence import EvidenceStore
from relay_auditor.schemas import (
    PAPER_ONE_TOKEN_PROFILE,
    ConsoleReferenceCollectionRequest,
    EndpointSpec,
)

TERMINAL_STATUSES = {"completed", "failed", "canceled", "interrupted"}


@dataclass
class ReferenceCollectionRuntime:
    batch_id: str
    request: ConsoleReferenceCollectionRequest
    audit_ids: list[str]
    interrupt_event: asyncio.Event
    lock: asyncio.Lock
    worker: asyncio.Task[None] | None = None
    current_audit_id: str | None = None
    pause_requested: bool = False
    cancel_requested: bool = False
    shutdown_requested: bool = False


class ReferenceCollectionManager:
    """Persist reference work while keeping endpoint credentials in memory only."""

    def __init__(
        self,
        database: Database,
        evidence: EvidenceStore,
        fingerprint: FingerprintRunner,
    ) -> None:
        self.database = database
        self.evidence = evidence
        self.fingerprint = fingerprint
        self._runtimes: dict[str, ReferenceCollectionRuntime] = {}

    def start(self, request: ConsoleReferenceCollectionRequest) -> str:
        batch_id = str(uuid4())
        audit_ids = [str(uuid4()) for _ in request.models]
        self.database.create_reference_collection_batch_queue(
            batch_id=batch_id,
            audit_ids=audit_ids,
            reference_name=request.reference_name.strip(),
            provider=request.provider.strip(),
            base_url=str(request.endpoint.base_url),
            models=request.models,
            method_profile_id=request.method_profile_id,
            cells=request.cells,
            samples=request.samples,
            max_concurrency=request.concurrency,
            concurrency_mode=request.concurrency_mode,
            request_timeout_seconds=request.request_timeout_seconds,
            model_timeout_seconds=request.model_timeout_seconds,
            valid_days=request.valid_days,
        )
        runtime = ReferenceCollectionRuntime(
            batch_id=batch_id,
            request=request,
            audit_ids=audit_ids,
            interrupt_event=asyncio.Event(),
            lock=asyncio.Lock(),
        )
        self._runtimes[batch_id] = runtime
        runtime.worker = asyncio.create_task(self._run(runtime))
        return batch_id

    async def pause(self, batch_id: str) -> None:
        runtime = self._active_runtime(batch_id)
        async with runtime.lock:
            batch = self._require_batch(batch_id)
            if batch.status == "paused":
                return
            if batch.status in TERMINAL_STATUSES:
                raise ValueError("finished reference collection cannot be paused")
            runtime.pause_requested = True
            self.database.set_reference_collection_batch_status(batch_id, "pausing")
            runtime.interrupt_event.set()
            worker = runtime.worker
        if worker is not None and not worker.done():
            await asyncio.shield(worker)

    async def resume(self, batch_id: str) -> None:
        runtime = self._active_runtime(batch_id)
        async with runtime.lock:
            batch = self._require_batch(batch_id)
            if batch.status != "paused":
                raise ValueError("only a paused reference collection can be resumed")
            if runtime.worker is not None and not runtime.worker.done():
                raise ValueError("reference collection is still stopping")
            runtime.pause_requested = False
            runtime.shutdown_requested = False
            runtime.interrupt_event.clear()
            if runtime.current_audit_id is not None:
                run = self.database.get_run(runtime.current_audit_id)
                if run is not None and run.status == "paused":
                    self.database.update_run_status(
                        runtime.current_audit_id,
                        status="queued",
                        reset_started_at=False,
                    )
                    self.database.update_reference_collection_progress(
                        runtime.current_audit_id,
                        stage="queued",
                        detail="等待继续采集当前参考模型",
                    )
            self.database.set_reference_collection_batch_status(batch_id, "running")
            runtime.worker = asyncio.create_task(self._run(runtime))

    async def cancel(self, batch_id: str) -> None:
        runtime = self._active_runtime(batch_id)
        async with runtime.lock:
            batch = self._require_batch(batch_id)
            if batch.status in TERMINAL_STATUSES:
                return
            runtime.cancel_requested = True
            runtime.pause_requested = False
            self.database.set_reference_collection_batch_status(batch_id, "canceling")
            runtime.interrupt_event.set()
            worker = runtime.worker
            if worker is None or worker.done():
                self._cancel_unfinished(runtime, "用户取消了整个参考采集批次")
                self.database.set_reference_collection_batch_status(batch_id, "canceled")
                self._runtimes.pop(batch_id, None)
                return
        if worker is not None and not worker.done():
            await asyncio.shield(worker)

    async def shutdown(self) -> None:
        workers: list[asyncio.Task[None]] = []
        for runtime in list(self._runtimes.values()):
            async with runtime.lock:
                runtime.shutdown_requested = True
                runtime.pause_requested = True
                runtime.interrupt_event.set()
                if runtime.worker is not None and not runtime.worker.done():
                    workers.append(runtime.worker)
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    def _require_batch(self, batch_id: str):
        batch = self.database.get_reference_collection_batch(batch_id)
        if batch is None:
            raise LookupError(f"reference collection batch not found: {batch_id}")
        return batch

    def _active_runtime(self, batch_id: str) -> ReferenceCollectionRuntime:
        batch = self._require_batch(batch_id)
        runtime = self._runtimes.get(batch_id)
        if runtime is None:
            if batch.status in TERMINAL_STATUSES:
                raise ValueError("reference collection is already finished")
            raise ValueError("reference collection credentials were cleared by a service restart")
        return runtime

    async def _run(self, runtime: ReferenceCollectionRuntime) -> None:
        try:
            self.database.set_reference_collection_batch_status(runtime.batch_id, "running")
            while True:
                if runtime.cancel_requested:
                    self._cancel_unfinished(runtime, "用户取消了整个参考采集批次")
                    self.database.set_reference_collection_batch_status(
                        runtime.batch_id,
                        "canceled",
                    )
                    self._runtimes.pop(runtime.batch_id, None)
                    return
                if runtime.pause_requested:
                    self.database.set_reference_collection_batch_status(
                        runtime.batch_id,
                        "paused",
                    )
                    return
                audit_id = self._next_audit_id(runtime)
                if audit_id is None:
                    self.database.set_reference_collection_batch_status(
                        runtime.batch_id,
                        "completed",
                    )
                    self._runtimes.pop(runtime.batch_id, None)
                    return
                runtime.current_audit_id = audit_id
                try:
                    await self._run_item(runtime, audit_id)
                except FingerprintPausedError:
                    if runtime.cancel_requested:
                        self._finish_canceled(audit_id, "用户取消了整个参考采集批次")
                        self._cancel_unfinished(runtime, "用户取消了整个参考采集批次")
                        self.database.set_reference_collection_batch_status(
                            runtime.batch_id,
                            "canceled",
                        )
                        self._runtimes.pop(runtime.batch_id, None)
                        return
                    self.database.update_run_status(
                        audit_id,
                        status="paused",
                        reset_started_at=False,
                    )
                    self.database.update_reference_collection_progress(
                        audit_id,
                        stage="paused",
                        detail="已暂停；继续后会重新采集当前参考模型",
                    )
                    self.database.set_reference_collection_batch_status(
                        runtime.batch_id,
                        "paused",
                    )
                    return
                finally:
                    if not runtime.pause_requested:
                        runtime.current_audit_id = None
                    runtime.interrupt_event.clear()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._fail_unfinished(runtime, f"参考采集调度失败：{error}")
            self.database.set_reference_collection_batch_status(runtime.batch_id, "failed")
            self._runtimes.pop(runtime.batch_id, None)

    def _next_audit_id(self, runtime: ReferenceCollectionRuntime) -> str | None:
        if runtime.current_audit_id is not None:
            run = self.database.get_run(runtime.current_audit_id)
            if run is not None and run.status in {"queued", "paused"}:
                return runtime.current_audit_id
        for audit_id in runtime.audit_ids:
            run = self.database.get_run(audit_id)
            if run is not None and run.status in {"queued", "paused"}:
                return audit_id
        return None

    def _select_concurrency(
        self,
        runtime: ReferenceCollectionRuntime,
        audit_id: str,
    ) -> tuple[int, str]:
        maximum = runtime.request.concurrency
        if runtime.request.concurrency_mode == "fixed":
            return maximum, f"使用固定并发 {maximum}"
        rows = self.database.get_reference_collection_rows(runtime.batch_id)
        prior: list[tuple[Any, ReferenceCollectionItem]] = []
        for run, item in rows:
            if item.audit_id == audit_id:
                break
            if item.finished_at is not None:
                prior.append((run, item))
        if not prior:
            selected = min(2, maximum)
            return selected, f"本批首个模型采用保守并发 {selected}"

        previous_run, previous_item = prior[-1]
        previous = previous_item.effective_concurrency or min(2, maximum)
        error_rate = previous_item.errors / max(1, previous_item.total)
        if previous_run.status != "completed" or error_rate > 0.05:
            selected = max(1, math.ceil(previous / 2))
            return (
                selected,
                f"上一模型未稳定完成或错误率 {error_rate * 100:.1f}%，降到并发 {selected}",
            )
        if previous_item.errors > 0 or previous_item.retry_count > 0:
            selected = max(1, previous - 1)
            return (
                selected,
                "上一模型出现 "
                f"{previous_item.errors} 次错误、{previous_item.retry_count} 次重试活动，"
                f"降到并发 {selected}",
            )
        candidates = sorted(
            value for value in {1, 2, 4, 8, 12, 16, 20, maximum} if value <= maximum
        )
        selected = next((value for value in candidates if value > previous), previous)
        return selected, f"上一模型零错误稳定完成，试探提升到并发 {selected}"

    async def _run_item(
        self,
        runtime: ReferenceCollectionRuntime,
        audit_id: str,
    ) -> None:
        run = self.database.get_run(audit_id)
        if run is None:
            raise LookupError(f"reference collection audit not found: {audit_id}")
        endpoint = EndpointSpec(
            base_url=runtime.request.endpoint.base_url,
            model=run.model,
        )
        api_key = runtime.request.endpoint.reveal_api_key()
        concurrency, concurrency_reason = self._select_concurrency(runtime, audit_id)
        self.database.set_reference_collection_concurrency(
            audit_id,
            effective_concurrency=concurrency,
            reason=concurrency_reason,
        )
        self.database.update_run_status(audit_id, status="running")
        self.database.update_reference_collection_progress(
            audit_id,
            stage="starting",
            done=0,
            errors=0,
            detail=concurrency_reason,
        )
        output_path = self.evidence.fingerprint_path(audit_id)

        def on_progress(event: dict[str, Any]) -> None:
            self.database.update_reference_collection_progress(
                audit_id,
                stage=str(event.get("stage") or "sampling"),
                done=int(event.get("done", 0)),
                total=int(event.get("total", 0)),
                errors=int(event.get("errors", 0)),
                retrying=event.get("retrying") is True,
                detail=str(event.get("detail")) if event.get("detail") else None,
            )

        try:
            if runtime.request.method_profile_id == PAPER_ONE_TOKEN_PROFILE:
                result = await self.fingerprint.collect_paper_profile(
                    endpoint,
                    role="enrollment",
                    scheduler_seed=f"relay-auditor:enrollment:{audit_id}",
                    output_path=output_path,
                    samples_output_path=self.evidence.fingerprint_samples_path(audit_id),
                    samples=runtime.request.samples,
                    concurrency=concurrency,
                    timeout=round(runtime.request.request_timeout_seconds * 1000),
                    api_key=api_key,
                    progress_callback=on_progress,
                    cancel_event=runtime.interrupt_event,
                    idle_timeout_seconds=runtime.request.model_timeout_seconds,
                )
            else:
                result = await self.fingerprint.collect(
                    endpoint,
                    output_path=output_path,
                    cells=runtime.request.cells,
                    samples=runtime.request.samples,
                    concurrency=concurrency,
                    api_key=api_key,
                    progress_callback=on_progress,
                    cancel_event=runtime.interrupt_event,
                    request_timeout_ms=round(runtime.request.request_timeout_seconds * 1000),
                    idle_timeout_seconds=runtime.request.model_timeout_seconds,
                )
            if runtime.interrupt_event.is_set():
                raise FingerprintPausedError(
                    "reference collection interrupted before baseline registration"
                )
            artifact_sha256 = self.evidence.digest_file(output_path)
            raw_evidence_sha256 = (
                self._validated_paper_raw_evidence_sha256(
                    audit_id,
                    output_path,
                    result,
                )
                if runtime.request.method_profile_id == PAPER_ONE_TOKEN_PROFILE
                else None
            )
            profile_cells = (
                40
                if runtime.request.method_profile_id == PAPER_ONE_TOKEN_PROFILE
                else runtime.request.cells
            )
            protocol = (
                PAPER_ONE_TOKEN_PROFILE
                if runtime.request.method_profile_id == PAPER_ONE_TOKEN_PROFILE
                else "one-token/v1"
            )
            endpoint_name = self._endpoint_name(
                runtime.request.reference_name.strip(),
                run.model,
            )
            self.database.complete_reference_collection_item(
                audit_id,
                artifact_path=str(output_path),
                artifact_sha256=artifact_sha256,
                endpoint_id=str(uuid4()),
                endpoint_name=endpoint_name,
                baseline_id=str(uuid4()),
                metadata={
                    "source": "local_console_background",
                    "reference_name": runtime.request.reference_name.strip(),
                    "cells": profile_cells,
                    "samples": runtime.request.samples,
                    "concurrency": concurrency,
                    "concurrency_mode": runtime.request.concurrency_mode,
                    "protocol": protocol,
                    "method_profile_id": runtime.request.method_profile_id,
                    "ground_truth": "unverified_user_reference",
                    "decision_eligible": False,
                    "calibration_policy_id": None,
                    "raw_evidence_sha256": raw_evidence_sha256,
                },
            )
        except FingerprintPausedError:
            self._attach_partial(audit_id, output_path)
            raise
        except asyncio.CancelledError:
            self._attach_partial(audit_id, output_path)
            raise FingerprintPausedError(
                "reference collection interrupted during shutdown"
            ) from None
        except FingerprintStalledError as error:
            self._attach_partial(audit_id, output_path)
            self._finish_failed(
                audit_id,
                f"连续 {error.idle_timeout_seconds:g} 秒没有采样或重试进度",
                api_key,
                output_path,
            )
        except Exception as error:
            self._attach_partial(audit_id, output_path)
            self._finish_failed(audit_id, str(error), api_key, output_path)

    def _validated_paper_raw_evidence_sha256(
        self,
        audit_id: str,
        output_path: Path,
        result: dict[str, Any],
    ) -> str:
        fingerprint = self.evidence.read_json(output_path)
        if (
            fingerprint.get("formatVersion") != 2
            or fingerprint.get("protocol") != PAPER_ONE_TOKEN_PROFILE
        ):
            raise ValueError("canonical V2 reference artifact has an invalid protocol")
        quality = fingerprint.get("quality")
        if (
            not isinstance(quality, dict)
            or quality.get("complete") is not True
            or fingerprint.get("partial") is True
        ):
            raise ValueError("canonical V2 reference artifact is incomplete")
        expected_sha256 = quality.get("rawEvidenceSha256")
        collection = result.get("collection")
        result_sha256 = (
            collection.get("rawEvidenceSha256") if isinstance(collection, dict) else None
        )
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or result_sha256 != expected_sha256
        ):
            raise ValueError("canonical V2 raw evidence digest metadata is inconsistent")
        samples_path = self.evidence.fingerprint_samples_path(audit_id, must_exist=True)
        actual_sha256 = hashlib.sha256(samples_path.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise ValueError("canonical V2 raw sample evidence digest mismatch")
        return expected_sha256

    @staticmethod
    def _endpoint_name(reference_name: str, model: str) -> str:
        raw_name = f"{reference_name} · {model}"
        if len(raw_name) <= 100:
            return raw_name
        suffix = hashlib.sha256(raw_name.encode()).hexdigest()[:8]
        return f"{raw_name[:89]}-{suffix}"

    def _attach_partial(self, audit_id: str, output_path: Path) -> None:
        if not output_path.is_file():
            return
        self.database.update_run_artifact(
            audit_id,
            artifact_path=str(output_path),
            artifact_sha256=self.evidence.digest_file(output_path),
        )

    def _finish_failed(
        self,
        audit_id: str,
        detail: str,
        api_key: str | None,
        output_path: Path,
    ) -> None:
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        artifact_path = str(output_path) if output_path.is_file() else None
        artifact_sha256 = (
            self.evidence.digest_file(output_path) if artifact_path is not None else None
        )
        self.database.finish_reference_collection_item(
            audit_id,
            status="failed",
            verdict="error",
            detail=detail,
            artifact_path=artifact_path,
            artifact_sha256=artifact_sha256,
        )

    def _finish_canceled(self, audit_id: str, detail: str) -> None:
        run = self.database.get_run(audit_id)
        if run is None or run.status in TERMINAL_STATUSES:
            return
        self.database.finish_reference_collection_item(
            audit_id,
            status="canceled",
            verdict="canceled",
            detail=detail,
            artifact_path=run.artifact_path,
            artifact_sha256=run.artifact_sha256,
        )

    def _cancel_unfinished(self, runtime: ReferenceCollectionRuntime, detail: str) -> None:
        for audit_id in runtime.audit_ids:
            self._finish_canceled(audit_id, detail)

    def _fail_unfinished(self, runtime: ReferenceCollectionRuntime, detail: str) -> None:
        for audit_id in runtime.audit_ids:
            run = self.database.get_run(audit_id)
            if run is None or run.status in TERMINAL_STATUSES:
                continue
            self.database.finish_reference_collection_item(
                audit_id,
                status="failed",
                verdict="error",
                detail=detail,
                artifact_path=run.artifact_path,
                artifact_sha256=run.artifact_sha256,
            )
