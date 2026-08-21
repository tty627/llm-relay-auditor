import asyncio
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from time import monotonic
from typing import Any
from uuid import uuid4

from relay_auditor.database import Database
from relay_auditor.detectors.fingerprint import (
    FingerprintPausedError,
    FingerprintRunner,
    FingerprintStalledError,
    safeguard_verification_result,
)
from relay_auditor.detectors.preflight import (
    FingerprintPreflightError,
    run_fingerprint_preflight,
)
from relay_auditor.evidence import EvidenceStore
from relay_auditor.schemas import (
    ConsoleComparisonBatchItemRequest,
    ConsoleComparisonBatchRequest,
)

TERMINAL_RUN_STATUSES = {"completed", "failed", "canceled", "interrupted"}
TERMINAL_BATCH_STATUSES = {"completed", "failed", "canceled", "interrupted"}


@dataclass
class BatchItemRuntime:
    audit_id: str
    request: ConsoleComparisonBatchItemRequest
    sequence: int
    priority: int
    preflight_attempts: int = 0
    preflight_started_at: float | None = None
    preflight_retry_at: float = 0.0
    preflight_waited_seconds: float = 0.0
    preflight_failures: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BatchRuntime:
    batch_id: str
    request: ConsoleComparisonBatchRequest
    items: list[BatchItemRuntime]
    interrupt_event: asyncio.Event
    lock: asyncio.Lock
    station_order: list[str]
    station_cursor_by_priority: dict[int, int] = field(default_factory=dict)
    station_retry_at: dict[str, float] = field(default_factory=dict)
    worker: asyncio.Task[None] | None = None
    current_audit_id: str | None = None
    pause_requested: bool = False
    shutdown_requested: bool = False
    batch_cancel_requested: bool = False
    item_cancel_requested: str | None = None
    paused_at: float | None = None


class ComparisonBatchManager:
    """Run comparison queues independently of the browser page lifetime.

    API keys live only in the in-memory runtime. Refreshing a page does not
    affect the queue. A service restart discards credentials and startup
    recovery marks unfinished records as interrupted.
    """

    def __init__(
        self,
        database: Database,
        evidence: EvidenceStore,
        fingerprint: FingerprintRunner,
        preflight: Callable[..., Awaitable[dict[str, Any]]] | None = None,
        *,
        preflight_max_attempts: int = 12,
        preflight_retry_base_seconds: float = 5.0,
        preflight_retry_cap_seconds: float = 60.0,
    ) -> None:
        self.database = database
        self.evidence = evidence
        self.fingerprint = fingerprint
        self.preflight = preflight or run_fingerprint_preflight
        self.preflight_max_attempts = max(1, preflight_max_attempts)
        self.preflight_retry_base_seconds = max(0.0, preflight_retry_base_seconds)
        self.preflight_retry_cap_seconds = max(
            self.preflight_retry_base_seconds,
            preflight_retry_cap_seconds,
        )
        self._runtimes: dict[str, BatchRuntime] = {}

    def start(self, request: ConsoleComparisonBatchRequest) -> str:
        for item in request.items:
            self.evidence.fingerprint_path(item.reference_artifact_id, must_exist=True)

        batch_id = str(uuid4())
        indexed_items = list(enumerate(request.items))
        indexed_items.sort(key=lambda entry: (-entry[1].priority, entry[0]))
        runtime_items: list[BatchItemRuntime] = []
        for sequence, item in indexed_items:
            audit_id = str(uuid4())
            endpoint = item.endpoint.public_endpoint()
            self.database.create_run(
                audit_id=audit_id,
                detector="one_token_verify",
                target_base_url=str(endpoint.base_url),
                model=endpoint.model,
                status="queued",
            )
            self.database.create_comparison_record(
                audit_id=audit_id,
                batch_id=batch_id,
                total_items=len(request.items),
                station_name=item.station_name,
                reference_artifact_id=item.reference_artifact_id,
                reference_name=item.reference_name,
                reference_model=item.reference_model,
                cells=request.cells,
                samples=request.samples,
                concurrency=request.concurrency,
                priority=item.priority,
                concurrency_mode=request.concurrency_mode,
            )
            self.database.update_task_progress(
                audit_id,
                stage="queued",
                detail=f"已进入队列 · 优先级 {item.priority}",
            )
            runtime_items.append(
                BatchItemRuntime(
                    audit_id=audit_id,
                    request=item,
                    sequence=sequence,
                    priority=item.priority,
                )
            )

        runtime = BatchRuntime(
            batch_id=batch_id,
            request=request,
            items=runtime_items,
            interrupt_event=asyncio.Event(),
            lock=asyncio.Lock(),
            station_order=list(dict.fromkeys(item.station_name for item in request.items)),
        )
        self._runtimes[batch_id] = runtime
        runtime.worker = asyncio.create_task(self._run(runtime))
        return batch_id

    async def pause(self, batch_id: str) -> None:
        runtime = self._runtime_for_active_batch(batch_id)
        worker: asyncio.Task[None] | None
        async with runtime.lock:
            batch = self._require_batch(batch_id)
            if batch.status == "paused":
                return
            if batch.status in TERMINAL_BATCH_STATUSES:
                raise ValueError("finished comparison batch cannot be paused")
            if runtime.batch_cancel_requested or runtime.item_cancel_requested:
                raise ValueError("a cancellation is already being processed")
            runtime.pause_requested = True
            runtime.paused_at = monotonic()
            self.database.set_batch_status(batch_id, "pausing")
            runtime.interrupt_event.set()
            worker = runtime.worker
        if worker is not None and not worker.done():
            await asyncio.shield(worker)

    async def resume(self, batch_id: str) -> None:
        runtime = self._runtime_for_active_batch(batch_id)
        async with runtime.lock:
            batch = self._require_batch(batch_id)
            if batch.status != "paused":
                raise ValueError("only a paused comparison batch can be resumed")
            if runtime.worker is not None and not runtime.worker.done():
                raise ValueError("comparison batch is still stopping")
            runtime.pause_requested = False
            runtime.shutdown_requested = False
            runtime.item_cancel_requested = None
            runtime.interrupt_event.clear()
            if runtime.paused_at is not None:
                paused_seconds = max(0.0, monotonic() - runtime.paused_at)
                for item in runtime.items:
                    if item.preflight_started_at is not None:
                        item.preflight_started_at += paused_seconds
                    if item.preflight_retry_at > 0:
                        item.preflight_retry_at += paused_seconds
                for station_name, retry_at in runtime.station_retry_at.items():
                    if retry_at > 0:
                        runtime.station_retry_at[station_name] = retry_at + paused_seconds
                runtime.paused_at = None
            for item in runtime.items:
                run = self.database.get_run(item.audit_id)
                if run is not None and run.status == "paused":
                    self.database.update_run_status(item.audit_id, status="queued")
                    self.database.update_task_progress(
                        item.audit_id,
                        stage="queued",
                        detail="等待继续执行",
                    )
            self.database.set_batch_status(batch_id, "running")
            runtime.worker = asyncio.create_task(self._run(runtime))

    async def cancel_batch(self, batch_id: str) -> None:
        batch = self._require_batch(batch_id)
        if batch.status in TERMINAL_BATCH_STATUSES:
            return
        runtime = self._runtime_for_active_batch(batch_id)
        async with runtime.lock:
            batch = self._require_batch(batch_id)
            if batch.status in TERMINAL_BATCH_STATUSES:
                return
            runtime.batch_cancel_requested = True
            runtime.pause_requested = False
            runtime.item_cancel_requested = None
            self.database.set_batch_status(batch_id, "canceling")
            runtime.interrupt_event.set()
            worker_active = runtime.worker is not None and not runtime.worker.done()
            if not worker_active:
                self._cancel_remaining(runtime, "用户取消了整个批次")
                self.database.set_batch_status(batch_id, "canceled")
                self._runtimes.pop(batch_id, None)

    async def cancel_item(self, batch_id: str, audit_id: str) -> None:
        runtime = self._runtime_for_active_batch(batch_id)
        async with runtime.lock:
            item = self._runtime_item(runtime, audit_id)
            run = self.database.get_run(audit_id)
            if run is None:
                raise LookupError(f"comparison task not found: {audit_id}")
            if run.status in TERMINAL_RUN_STATUSES:
                return
            if runtime.batch_cancel_requested:
                raise ValueError("the whole batch is already being canceled")
            if runtime.current_audit_id == audit_id:
                runtime.item_cancel_requested = audit_id
                self.database.update_run_status(audit_id, status="canceling")
                self.database.update_task_progress(
                    audit_id,
                    stage="canceling",
                    detail="正在终止当前模型的采样请求",
                )
                runtime.interrupt_event.set()
                return
            self._mark_canceled(item.audit_id, "用户取消了该模型任务")
            if runtime.current_audit_id is None:
                # Wake a scheduler that may be sleeping until this item's
                # preflight cooldown expires.
                runtime.interrupt_event.set()
            if self._all_items_terminal(runtime):
                final_status = self._terminal_batch_status(runtime)
                self.database.set_batch_status(batch_id, final_status)
                self._runtimes.pop(batch_id, None)

    async def prioritize_item(self, batch_id: str, audit_id: str) -> int:
        runtime = self._runtime_for_active_batch(batch_id)
        async with runtime.lock:
            item = self._runtime_item(runtime, audit_id)
            run = self.database.get_run(audit_id)
            if run is None:
                raise LookupError(f"comparison task not found: {audit_id}")
            if run.status not in {"queued", "paused"}:
                raise ValueError("only a queued or paused task can be prioritized")
            for candidate in runtime.items:
                if candidate.audit_id == audit_id or candidate.priority < 100:
                    continue
                candidate_run = self.database.get_run(candidate.audit_id)
                if candidate_run is not None and candidate_run.status in {"queued", "paused"}:
                    candidate.priority = 99
                    self.database.update_task_priority(candidate.audit_id, 99)
            item.priority = 100
            item.sequence = (
                min(
                    (candidate.sequence for candidate in runtime.items),
                    default=item.sequence,
                )
                - 1
            )
            self.database.update_task_priority(audit_id, item.priority)
            retry_at = max(
                item.preflight_retry_at,
                runtime.station_retry_at.get(item.request.station_name, 0.0),
            )
            waiting_for_retry = run.status == "queued" and retry_at > monotonic()
            self.database.update_task_progress(
                audit_id,
                stage="waiting_retry" if waiting_for_retry else run.status,
                detail=(
                    f"已提升为下一优先任务 · 优先级 {item.priority}；"
                    "当前中转站仍在冷却，冷却结束后优先执行"
                    if waiting_for_retry
                    else f"已提升为下一优先任务 · 优先级 {item.priority}"
                ),
            )
            return item.priority

    async def shutdown(self) -> None:
        workers: list[asyncio.Task[None]] = []
        for runtime in list(self._runtimes.values()):
            async with runtime.lock:
                if runtime.batch_cancel_requested:
                    continue
                runtime.shutdown_requested = True
                runtime.pause_requested = True
                runtime.interrupt_event.set()
                if runtime.worker is not None and not runtime.worker.done():
                    workers.append(runtime.worker)
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    async def _run(self, runtime: BatchRuntime) -> None:
        try:
            batch = self._require_batch(runtime.batch_id)
            if batch.status != "canceling":
                self.database.set_batch_status(runtime.batch_id, "running")
            while True:
                retry_delay: float | None = None
                async with runtime.lock:
                    if (
                        runtime.interrupt_event.is_set()
                        and runtime.current_audit_id is None
                        and not runtime.batch_cancel_requested
                        and not runtime.pause_requested
                        and runtime.item_cancel_requested is None
                    ):
                        # A queued/waiting item was canceled while the worker
                        # was in an interruptible preflight cooldown.
                        runtime.interrupt_event.clear()
                    if runtime.batch_cancel_requested:
                        self._cancel_remaining(runtime, "用户取消了整个批次")
                        self.database.set_batch_status(runtime.batch_id, "canceled")
                        self._runtimes.pop(runtime.batch_id, None)
                        return
                    if runtime.pause_requested:
                        self.database.set_batch_status(runtime.batch_id, "paused")
                        return
                    item = self._next_item(runtime)
                    if item is None:
                        retry_delay = self._next_retry_delay(runtime)
                        if retry_delay is None:
                            final_status = self._terminal_batch_status(runtime)
                            self.database.set_batch_status(runtime.batch_id, final_status)
                            self._runtimes.pop(runtime.batch_id, None)
                            return
                    else:
                        runtime.current_audit_id = item.audit_id

                if item is None:
                    await self._wait_for_retry(runtime, retry_delay or 0.0)
                    continue

                try:
                    await self._run_item(runtime, item)
                except FingerprintPausedError:
                    async with runtime.lock:
                        runtime.current_audit_id = None
                        if runtime.batch_cancel_requested:
                            self._mark_canceled(item.audit_id, "用户取消了整个批次")
                            self._cancel_remaining(runtime, "用户取消了整个批次")
                            self.database.set_batch_status(runtime.batch_id, "canceled")
                            self._runtimes.pop(runtime.batch_id, None)
                            return
                        if runtime.item_cancel_requested == item.audit_id:
                            self._mark_canceled(item.audit_id, "用户取消了该模型任务")
                            runtime.item_cancel_requested = None
                            runtime.interrupt_event.clear()
                            continue
                        self._mark_paused(runtime, item.audit_id)
                        return
                else:
                    async with runtime.lock:
                        runtime.current_audit_id = None
                        runtime.interrupt_event.clear()
        except asyncio.CancelledError:
            batch = self.database.get_comparison_batch(runtime.batch_id)
            if batch is not None and batch.status not in TERMINAL_BATCH_STATUSES:
                self.database.set_batch_status(runtime.batch_id, "paused")
            raise
        except Exception as error:
            self._fail_remaining(runtime, f"批次调度失败：{error}")
            self.database.set_batch_status(runtime.batch_id, "failed")
            self._runtimes.pop(runtime.batch_id, None)

    def _next_item(self, runtime: BatchRuntime) -> BatchItemRuntime | None:
        pending: list[BatchItemRuntime] = []
        now = monotonic()
        for item in runtime.items:
            run = self.database.get_run(item.audit_id)
            retry_at = max(
                item.preflight_retry_at,
                runtime.station_retry_at.get(item.request.station_name, 0.0),
            )
            if run is not None and run.status == "queued" and retry_at <= now:
                pending.append(item)
        if not pending:
            return None
        priority = max(item.priority for item in pending)
        candidates = [item for item in pending if item.priority == priority]
        if not runtime.station_order:
            return min(candidates, key=lambda item: item.sequence)
        cursor = runtime.station_cursor_by_priority.get(priority, 0) % len(runtime.station_order)
        for offset in range(len(runtime.station_order)):
            station_index = (cursor + offset) % len(runtime.station_order)
            station = runtime.station_order[station_index]
            station_items = [item for item in candidates if item.request.station_name == station]
            if station_items:
                runtime.station_cursor_by_priority[priority] = (station_index + 1) % len(
                    runtime.station_order
                )
                return min(station_items, key=lambda item: item.sequence)
        return min(candidates, key=lambda item: item.sequence)

    def _next_retry_delay(self, runtime: BatchRuntime) -> float | None:
        now = monotonic()
        retry_times: list[float] = []
        for item in runtime.items:
            retry_at = max(
                item.preflight_retry_at,
                runtime.station_retry_at.get(item.request.station_name, 0.0),
            )
            run = self.database.get_run(item.audit_id)
            if retry_at > now and run is not None and run.status == "queued":
                retry_times.append(retry_at)
        if not retry_times:
            return None
        return max(0.0, min(retry_times) - now)

    async def _wait_for_retry(self, runtime: BatchRuntime, delay: float) -> None:
        """Wait for the next cooldown without blocking pause/cancel controls."""

        if delay <= 0:
            await asyncio.sleep(0)
            return
        sleep_task = asyncio.create_task(asyncio.sleep(delay))
        interrupt_task = asyncio.create_task(runtime.interrupt_event.wait())
        try:
            await asyncio.wait(
                {sleep_task, interrupt_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            sleep_task.cancel()
            interrupt_task.cancel()
            await asyncio.gather(sleep_task, interrupt_task, return_exceptions=True)

    def _mark_paused(self, runtime: BatchRuntime, audit_id: str) -> None:
        run = self.database.get_run(audit_id)
        if run is not None and run.status not in TERMINAL_RUN_STATUSES:
            self.database.update_run_status(audit_id, status="paused")
            self.database.update_task_progress(
                audit_id,
                stage="paused",
                detail="已暂停；继续后会重新采集当前模型",
            )
        self.database.set_batch_status(runtime.batch_id, "paused")

    def _mark_canceled(self, audit_id: str, detail: str) -> None:
        run = self.database.get_run(audit_id)
        if run is None or run.status in TERMINAL_RUN_STATUSES:
            return
        self.database.finish_run(
            audit_id,
            status="canceled",
            verdict="canceled",
            artifact_path=run.artifact_path,
            artifact_sha256=run.artifact_sha256,
            error_message=detail,
        )
        self.database.update_task_progress(
            audit_id,
            stage="canceled",
            detail=detail,
        )
        self.database.finish_comparison_record(audit_id)

    def _cancel_remaining(self, runtime: BatchRuntime, detail: str) -> None:
        for item in runtime.items:
            self._mark_canceled(item.audit_id, detail)

    def _fail_remaining(self, runtime: BatchRuntime, detail: str) -> None:
        for item in runtime.items:
            run = self.database.get_run(item.audit_id)
            if run is None or run.status in TERMINAL_RUN_STATUSES:
                continue
            self.database.finish_run(
                item.audit_id,
                status="failed",
                verdict="error",
                error_message=detail,
            )
            self.database.update_task_progress(
                item.audit_id,
                stage="failed",
                detail=detail,
            )
            self.database.finish_comparison_record(item.audit_id)

    def _all_items_terminal(self, runtime: BatchRuntime) -> bool:
        return all(
            (run := self.database.get_run(item.audit_id)) is not None
            and run.status in TERMINAL_RUN_STATUSES
            for item in runtime.items
        )

    def _terminal_batch_status(self, runtime: BatchRuntime) -> str:
        statuses = {
            run.status
            for item in runtime.items
            if (run := self.database.get_run(item.audit_id)) is not None
        }
        return "canceled" if statuses == {"canceled"} else "completed"

    def _runtime_for_active_batch(self, batch_id: str) -> BatchRuntime:
        batch = self._require_batch(batch_id)
        runtime = self._runtimes.get(batch_id)
        if runtime is None:
            if batch.status in TERMINAL_BATCH_STATUSES:
                raise ValueError("comparison batch is already finished")
            raise ValueError(
                "batch credentials were cleared by a service restart; submit a new batch"
            )
        return runtime

    def _require_batch(self, batch_id: str):
        batch = self.database.get_comparison_batch(batch_id)
        if batch is None:
            raise LookupError(f"comparison batch not found: {batch_id}")
        return batch

    @staticmethod
    def _runtime_item(runtime: BatchRuntime, audit_id: str) -> BatchItemRuntime:
        for item in runtime.items:
            if item.audit_id == audit_id:
                return item
        raise LookupError(f"comparison task does not belong to batch: {audit_id}")

    def _select_concurrency(
        self,
        runtime: BatchRuntime,
        item: BatchItemRuntime,
    ) -> dict[str, Any]:
        maximum = runtime.request.concurrency
        if runtime.request.concurrency_mode == "fixed":
            return {
                "mode": "fixed",
                "selected": maximum,
                "maximum": maximum,
                "historyObservations": 0,
                "reason": f"使用固定并发 {maximum}",
            }

        endpoint = item.request.endpoint.public_endpoint()
        observations = self.database.list_concurrency_observations(
            str(endpoint.base_url),
            model=endpoint.model,
            station_name=item.request.station_name,
        )
        stats: dict[int, dict[str, Any]] = {}
        for run, options, batch in observations:
            selected = options.effective_concurrency
            if selected is None or selected > maximum:
                continue
            bucket = stats.setdefault(
                selected,
                {
                    "attempts": 0,
                    "failures": 0,
                    "errorRates": [],
                    "splitHalf": [],
                    "throughputs": [],
                },
            )
            bucket["attempts"] += 1
            if run.status != "completed" or not run.artifact_path:
                bucket["failures"] += 1
                continue
            try:
                result = self.evidence.read_json(Path(run.artifact_path))
            except (OSError, ValueError):
                bucket["failures"] += 1
                continue
            target = result.get("target", {})
            total = max(1, batch.cells * batch.samples)
            error_count = target.get("errorCount")
            split_half = target.get("splitHalfJsd")
            duration = target.get("durationMs")
            if isinstance(error_count, int):
                bucket["errorRates"].append(error_count / total)
            if isinstance(split_half, (int, float)):
                bucket["splitHalf"].append(float(split_half))
            if isinstance(duration, (int, float)) and duration > 0:
                bucket["throughputs"].append(total * 1000 / float(duration))

        candidates = sorted(
            {value for value in (1, 2, 4, 8, 12, 16, 20, maximum) if value <= maximum}
        )
        conservative = max(value for value in candidates if value <= min(2, maximum))
        if not stats:
            return {
                "mode": "auto",
                "selected": conservative,
                "maximum": maximum,
                "historyObservations": 0,
                "reason": f"暂无该中转站与模型的历史，首次采用保守并发 {conservative}",
            }

        stable: list[int] = []
        for concurrency, bucket in stats.items():
            rates = bucket["errorRates"]
            error_rate = median(rates) if rates else 1.0
            completion_rate = (bucket["attempts"] - bucket["failures"]) / bucket["attempts"]
            if completion_rate >= 0.9 and rates and error_rate <= 0.02:
                stable.append(concurrency)

        if stable:
            mature = [value for value in stable if stats[value]["attempts"] >= 3]
            if mature:
                throughput_by_value = {
                    value: median(stats[value]["throughputs"])
                    for value in mature
                    if stats[value]["throughputs"]
                }
                if throughput_by_value:
                    best_throughput = max(throughput_by_value.values())
                    efficient = [
                        value
                        for value, throughput in throughput_by_value.items()
                        if throughput >= best_throughput * 0.9
                    ]
                    selected = min(efficient)
                else:
                    selected = max(mature)
            else:
                selected = max(stable)

            bucket = stats[selected]
            higher = [value for value in candidates if value > selected and value not in stats]
            if bucket["attempts"] >= 3 and higher:
                trial = min(higher)
                return {
                    "mode": "auto",
                    "selected": trial,
                    "maximum": maximum,
                    "historyObservations": len(observations),
                    "reason": (
                        f"并发 {selected} 已稳定 {bucket['attempts']} 次，本次试探提升到 {trial}"
                    ),
                }

            error_rate = median(bucket["errorRates"]) * 100
            split_text = (
                f"，内部 JSD 中位数 {median(bucket['splitHalf']):.3f}"
                if bucket["splitHalf"]
                else ""
            )
            return {
                "mode": "auto",
                "selected": selected,
                "maximum": maximum,
                "historyObservations": len(observations),
                "reason": (
                    f"历史 {bucket['attempts']} 次错误率中位数 {error_rate:.1f}%"
                    f"{split_text}，选择稳定且不过度并发的 {selected}"
                ),
            }

        lowest_observed = min(stats)
        lower = [value for value in candidates if value < lowest_observed]
        selected = max(lower) if lower else 1
        return {
            "mode": "auto",
            "selected": selected,
            "maximum": maximum,
            "historyObservations": len(observations),
            "reason": f"已有并发均出现失败或较高错误率，本次降到 {selected}",
        }

    async def _identify_candidates(
        self,
        runtime: BatchRuntime,
        item: BatchItemRuntime,
        target_path: Path,
        trigger_verdict: str,
    ) -> dict[str, Any]:
        self.database.update_task_progress(
            item.audit_id,
            stage="identifying",
            detail="正在与本地其他参考指纹离线比较，不会请求中转站",
        )
        target_fingerprint = self.evidence.read_json(target_path)
        grouped: dict[str, list[dict[str, Any]]] = {}
        exclusions: list[dict[str, str]] = []
        seen_model_fingerprints: set[tuple[str, str]] = set()
        catalog = [
            catalog_item
            for catalog_item in self.database.list_reference_catalog()
            if str(catalog_item["baseline"]["artifact_id"]) != item.request.reference_artifact_id
        ]
        for index, catalog_item in enumerate(catalog, start=1):
            baseline = catalog_item["baseline"]
            endpoint = catalog_item["endpoint"]
            artifact_id = str(baseline["artifact_id"])
            if runtime.interrupt_event.is_set():
                raise FingerprintPausedError("comparison interrupted during identification")
            self.database.update_task_progress(
                item.audit_id,
                stage="identifying",
                detail=(f"正在离线比较本地参考 {index}/{len(catalog)}；不会向中转站发起新请求"),
            )
            try:
                reference_path = self.evidence.fingerprint_path(artifact_id, must_exist=True)
                expected_sha = catalog_item.get("artifact_sha256")
                if expected_sha and self.evidence.digest_file(reference_path) != expected_sha:
                    raise ValueError("指纹 SHA-256 与目录记录不一致")
                reference_fingerprint = self.evidence.read_json(reference_path)
                model = str(endpoint.get("model") or reference_fingerprint.get("model"))
                fingerprint_sha = str(expected_sha or self.evidence.digest_file(reference_path))
                fingerprint_key = (model, fingerprint_sha)
                if fingerprint_key in seen_model_fingerprints:
                    raise ValueError("同一模型下的重复参考指纹")
                seen_model_fingerprints.add(fingerprint_key)
                if reference_fingerprint.get("protocol") != target_fingerprint.get("protocol"):
                    raise ValueError("指纹协议不同")
                if reference_fingerprint.get("postReasoning") != target_fingerprint.get(
                    "postReasoning"
                ):
                    raise ValueError("推理通道不同")
                comparison = await asyncio.wait_for(
                    self.fingerprint.compare_fingerprints(
                        reference_path=reference_path,
                        target_path=target_path,
                    ),
                    timeout=30,
                )
                mean_jsd = comparison.get("meanJsd")
                comparable = comparison.get("comparableCellCount")
                if not isinstance(mean_jsd, (int, float)):
                    raise ValueError("没有可用的平均 JSD")
                if not isinstance(comparable, int) or comparable < 4:
                    raise ValueError("可比较探针少于 4 个")
            except (OSError, RuntimeError, TimeoutError, ValueError) as error:
                exclusions.append({"artifactId": artifact_id, "reason": str(error)})
                continue
            metadata = baseline.get("metadata") or {}
            grouped.setdefault(model, []).append(
                {
                    "referenceArtifactId": artifact_id,
                    "referenceName": str(
                        metadata.get("reference_name") or endpoint.get("name") or "本地参考端"
                    ),
                    "referenceModel": model,
                    "groundTruth": metadata.get("ground_truth"),
                    "meanJsd": float(mean_jsd),
                    "comparableCellCount": comparable,
                    "verdict": str(comparison.get("verdict") or "insufficient"),
                }
            )

        candidates: list[dict[str, Any]] = []
        verdict_order = {"match": 0, "uncertain": 1, "mismatch": 2, "insufficient": 3}
        for model, model_results in grouped.items():
            representative = min(
                model_results,
                key=lambda result: (
                    result["meanJsd"],
                    verdict_order.get(result["verdict"], 9),
                ),
            )
            values = [result["meanJsd"] for result in model_results]
            verdict_counts: dict[str, int] = {}
            for result in model_results:
                verdict_counts[result["verdict"]] = verdict_counts.get(result["verdict"], 0) + 1
            support_count = len(model_results)
            if verdict_counts.get("match", 0) > support_count / 2:
                aggregate_verdict = "match"
            elif verdict_counts.get("match", 0) or verdict_counts.get("uncertain", 0):
                aggregate_verdict = "uncertain"
            elif verdict_counts.get("mismatch", 0):
                aggregate_verdict = "mismatch"
            else:
                aggregate_verdict = "insufficient"
            candidates.append(
                {
                    **representative,
                    "referenceModel": model,
                    "bestReferenceVerdict": representative["verdict"],
                    "verdict": aggregate_verdict,
                    "medianMeanJsd": median(values),
                    "bestMeanJsd": min(values),
                    "worstMeanJsd": max(values),
                    "supportCount": support_count,
                    "sourceCount": len({result["referenceName"] for result in model_results}),
                    "verdictCounts": verdict_counts,
                }
            )
        candidates.sort(
            key=lambda candidate: (
                candidate["medianMeanJsd"],
                verdict_order.get(candidate["verdict"], 9),
            )
        )
        ranked = [
            {"rank": rank, **candidate} for rank, candidate in enumerate(candidates[:5], start=1)
        ]
        matching_models = [candidate for candidate in ranked if candidate["verdict"] == "match"]
        uncertain_models = [
            candidate for candidate in ranked if candidate["verdict"] == "uncertain"
        ]
        if len(matching_models) > 1:
            outcome = "ambiguous_candidates"
        elif len(matching_models) == 1:
            outcome = "possible_candidate"
        elif uncertain_models:
            outcome = "weak_candidates"
        elif ranked:
            outcome = "no_close_candidate"
        else:
            outcome = "insufficient_reference_library"
        return {
            "attempted": True,
            "triggerVerdict": trigger_verdict,
            "networkRequests": 0,
            "outcome": outcome,
            "candidateCount": len(candidates),
            "candidateCluster": [candidate["referenceModel"] for candidate in matching_models],
            "exclusions": exclusions,
            "candidates": ranked,
            "closestCandidate": ranked[0] if ranked else None,
            "notice": (
                "候选仅表示与本地参考指纹的相对距离，不等同于模型身份确认；未输出未经校准的概率。"
            ),
        }

    @staticmethod
    def _format_wait_seconds(seconds: float) -> str:
        if seconds >= 10:
            return f"{math.ceil(seconds):d}"
        if seconds < 1:
            return f"{seconds:.2f}".rstrip("0").rstrip(".")
        return f"{seconds:.1f}".rstrip("0").rstrip(".")

    def _schedule_preflight_retry(
        self,
        runtime: BatchRuntime,
        item: BatchItemRuntime,
        error: FingerprintPreflightError,
    ) -> bool:
        """Put a transiently blocked item back into the station-aware queue."""

        now = monotonic()
        started_at = item.preflight_started_at or now
        elapsed = max(0.0, now - started_at)
        retry_number = item.preflight_attempts
        exponential = min(
            self.preflight_retry_cap_seconds,
            self.preflight_retry_base_seconds * (2 ** max(0, retry_number - 1)),
        )
        retry_after = error.retry_after_seconds
        delay = max(exponential, retry_after or 0.0)
        remaining = max(0.0, runtime.request.model_timeout_seconds - elapsed)
        failure = {
            "attempt": retry_number,
            "statusCode": error.status_code,
            "errorKind": error.error_kind,
            "retryAfterSeconds": retry_after,
            "detail": str(error),
        }

        if retry_number >= self.preflight_max_attempts or delay >= remaining:
            item.preflight_failures.append(failure)
            return False

        item.preflight_retry_at = now + delay
        station_name = item.request.station_name
        runtime.station_retry_at[station_name] = max(
            runtime.station_retry_at.get(station_name, 0.0),
            item.preflight_retry_at,
        )
        item.preflight_waited_seconds += delay
        failure["cooldownSeconds"] = delay
        item.preflight_failures.append(failure)
        self.database.update_run_status(
            item.audit_id,
            status="queued",
            reset_started_at=False,
        )
        wait_text = self._format_wait_seconds(delay)
        retry_after_text = (
            f"（遵循 Retry-After {self._format_wait_seconds(retry_after)} 秒）"
            if retry_after is not None and retry_after >= exponential
            else ""
        )
        self.database.update_task_progress(
            item.audit_id,
            stage="waiting_retry",
            done=0,
            total=runtime.request.cells * runtime.request.samples,
            errors=retry_number,
            detail=(
                f"预检第 {retry_number} 次遇到可恢复错误：{error}；"
                f"冷却 {wait_text} 秒后自动重试{retry_after_text}；"
                "等待期间会继续执行其他中转站任务，可随时暂停或取消"
            ),
        )
        for sibling in runtime.items:
            if sibling.audit_id == item.audit_id or sibling.request.station_name != station_name:
                continue
            sibling_run = self.database.get_run(sibling.audit_id)
            if (
                sibling_run is None
                or sibling_run.status != "queued"
                or sibling.preflight_retry_at > now
            ):
                continue
            self.database.update_task_progress(
                sibling.audit_id,
                stage="waiting_retry",
                detail=(
                    f"同一中转站“{station_name}”刚遇到可恢复错误；"
                    f"共享冷却 {wait_text} 秒后再执行，期间优先处理其他中转站；"
                    "可随时暂停或取消"
                ),
            )
        return True

    def _preflight_exhausted_detail(
        self,
        runtime: BatchRuntime,
        item: BatchItemRuntime,
        error: FingerprintPreflightError,
    ) -> str:
        elapsed = (
            max(0.0, monotonic() - item.preflight_started_at)
            if item.preflight_started_at is not None
            else 0.0
        )
        if item.preflight_attempts >= self.preflight_max_attempts:
            reason = f"已达到 {self.preflight_max_attempts} 次预检上限"
        else:
            reason = f"下一次冷却会超过 {runtime.request.model_timeout_seconds:g} 秒预检等待窗口"
        return (
            f"{error}；已进行 {item.preflight_attempts} 次预检、累计冷却约 "
            f"{self._format_wait_seconds(item.preflight_waited_seconds)} 秒、"
            f"经过约 {self._format_wait_seconds(elapsed)} 秒，{reason}；"
            "本次才停止，正式采样尚未开始"
        )

    async def _preflight_with_interrupt(
        self,
        runtime: BatchRuntime,
        endpoint: Any,
        api_key: str | None,
    ) -> dict[str, Any]:
        preflight_task = asyncio.ensure_future(
            self.preflight(
                endpoint,
                api_key=api_key,
                timeout_seconds=runtime.request.request_timeout_seconds,
            )
        )
        interrupt_task = asyncio.create_task(runtime.interrupt_event.wait())
        try:
            await asyncio.wait(
                {preflight_task, interrupt_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if runtime.interrupt_event.is_set():
                preflight_task.cancel()
                await asyncio.gather(preflight_task, return_exceptions=True)
                raise FingerprintPausedError("comparison interrupted during preflight")
            return await preflight_task
        finally:
            interrupt_task.cancel()
            await asyncio.gather(interrupt_task, return_exceptions=True)

    def _attach_partial_artifact(self, audit_id: str, target_path: Path | None) -> None:
        if target_path is None or not target_path.is_file():
            return
        try:
            self.database.update_run_artifact(
                audit_id,
                artifact_path=str(target_path),
                artifact_sha256=self.evidence.digest_file(target_path),
            )
        except (LookupError, OSError, ValueError):
            # Preserving partial evidence is best-effort and must never turn a
            # successful pause/cancel into a scheduler-wide failure.
            return

    async def _run_item(self, runtime: BatchRuntime, item: BatchItemRuntime) -> None:
        request = item.request
        endpoint = request.endpoint.public_endpoint()
        api_key = request.endpoint.reveal_api_key()
        audit_id = item.audit_id
        target_path: Path | None = None
        concurrency = self._select_concurrency(runtime, item)
        selected_concurrency = int(concurrency["selected"])
        self.database.set_task_concurrency(
            audit_id,
            effective_concurrency=selected_concurrency,
            reason=str(concurrency["reason"]),
        )
        self.database.update_run_status(
            audit_id,
            status="running",
            reset_started_at=item.preflight_attempts == 0,
        )
        self.database.update_task_progress(
            audit_id,
            stage="starting",
            done=0,
            total=runtime.request.cells * runtime.request.samples,
            errors=0,
            detail=str(concurrency["reason"]),
        )

        def on_progress(event: dict[str, Any]) -> None:
            detail = event.get("detail")
            if event["stage"] == "adapter":
                detail = (
                    f"并发 {selected_concurrency} · 正在探测请求参数：{detail}；"
                    f"每次网络尝试最多 {runtime.request.request_timeout_seconds:g} 秒；"
                    f"连续无进度最多 {runtime.request.model_timeout_seconds:g} 秒"
                )
            elif event["stage"] == "sampling":
                status = event.get("lastHttpStatus")
                error_kind = event.get("lastErrorKind")
                if event.get("retrying"):
                    retry = re.search(
                        r"retry\s+(\d+)/(\d+)\s+in\s+(\d+)ms",
                        str(detail or ""),
                    )
                    retry_text = (
                        f"正在重试 {retry.group(1)}/{retry.group(2)}" if retry else "正在重试"
                    )
                    status_text = (
                        f" · HTTP {status}"
                        if isinstance(status, int)
                        else " · 最近请求超时"
                        if error_kind == "timeout"
                        else f" · 最近错误 {error_kind}"
                        if error_kind
                        else ""
                    )
                    wait_text = f" · 等待 {retry.group(3)}ms" if retry else ""
                    detail = f"{retry_text}{status_text}{wait_text}"
                elif error_kind == "timeout":
                    detail = "最近请求超时；正在继续采样"
                elif isinstance(status, int) and status >= 400:
                    detail = f"最近请求 HTTP {status}；正在继续采样"
            self.database.update_task_progress(
                audit_id,
                stage=str(event["stage"]),
                done=int(event.get("done", 0)),
                total=int(event.get("total", 0)),
                errors=int(event.get("errors", 0)),
                detail=str(detail) if detail else None,
            )

        try:
            reference_path = self.evidence.fingerprint_path(
                request.reference_artifact_id,
                must_exist=True,
            )
            reference_metadata = self.database.get_reference_metadata(request.reference_artifact_id)
            target_path = self.evidence.fingerprint_path(audit_id)
            if item.preflight_started_at is None:
                item.preflight_started_at = monotonic()
            item.preflight_attempts += 1
            item.preflight_retry_at = 0.0
            self.database.update_task_progress(
                audit_id,
                stage="preflight",
                done=0,
                total=runtime.request.cells * runtime.request.samples,
                errors=0,
                detail=(
                    f"正在进行第 {item.preflight_attempts} 次兼容性预检"
                    "（本次参数不兼容时最多尝试 2 种请求体）；"
                    "429、502、503、504 或超时会冷却后重新排队，不会一次判死"
                ),
            )
            try:
                preflight = await self._preflight_with_interrupt(runtime, endpoint, api_key)
            except FingerprintPreflightError as error:
                if error.transient and self._schedule_preflight_retry(runtime, item, error):
                    return
                if error.transient:
                    raise RuntimeError(
                        self._preflight_exhausted_detail(runtime, item, error)
                    ) from error
                raise
            latency_seconds = max(0.0, float(preflight.get("latencyMs") or 0) / 1000)
            total_requests = runtime.request.cells * runtime.request.samples
            waves = math.ceil(total_requests / selected_concurrency)
            minimum_seconds = latency_seconds * waves
            estimated_seconds = latency_seconds * (waves + 4) * 1.25
            preflight = {
                **preflight,
                "schedulerAttempts": item.preflight_attempts,
                "transientFailures": item.preflight_failures,
                "cooldownSeconds": round(item.preflight_waited_seconds, 3),
                "estimatedMinimumSeconds": round(minimum_seconds, 2),
                "estimatedWithMarginSeconds": round(estimated_seconds, 2),
            }
            self.database.update_task_progress(
                audit_id,
                stage="starting",
                detail=(
                    f"预检通过 · HTTP {preflight['statusCode']} · "
                    f"{preflight['latencyMs']:g}ms；按当前速度预计约 "
                    f"{math.ceil(estimated_seconds)} 秒；只要持续有进度就继续执行，"
                    f"连续 {runtime.request.model_timeout_seconds:g} 秒无进度才停止"
                ),
            )
            try:
                verdict, result = await self.fingerprint.verify(
                    endpoint,
                    reference_path=reference_path,
                    output_path=target_path,
                    cells=runtime.request.cells,
                    samples=runtime.request.samples,
                    concurrency=selected_concurrency,
                    api_key=api_key,
                    progress_callback=on_progress,
                    cancel_event=runtime.interrupt_event,
                    request_timeout_ms=round(runtime.request.request_timeout_seconds * 1000),
                    idle_timeout_seconds=runtime.request.model_timeout_seconds,
                )
            except FingerprintStalledError as error:
                raise RuntimeError(
                    f"连续 {error.idle_timeout_seconds:g} 秒没有收到任何采样或重试进度，"
                    "为避免永久挂起已停止；已完成的部分证据会保留"
                ) from error
            verdict, result = safeguard_verification_result(
                verdict,
                result,
                reference_metadata=reference_metadata,
            )
            result = {
                **result,
                "reference_artifact_id": request.reference_artifact_id,
                "execution": {
                    "priority": item.priority,
                    "concurrency": concurrency,
                    "preflight": preflight,
                },
            }
            legacy_verdict = result["decision"]["legacyVerdict"]
            if legacy_verdict in {"uncertain", "mismatch"}:
                try:
                    result["identification"] = await asyncio.wait_for(
                        self._identify_candidates(
                            runtime,
                            item,
                            target_path,
                            legacy_verdict,
                        ),
                        timeout=30,
                    )
                    result["identification"]["decisionBasis"] = "legacy_exploratory"
                except FingerprintPausedError:
                    raise
                except Exception as identification_error:
                    result["identification"] = {
                        "attempted": True,
                        "triggerVerdict": legacy_verdict,
                        "decisionBasis": "legacy_exploratory",
                        "networkRequests": 0,
                        "outcome": "identification_failed",
                        "candidateCount": 0,
                        "candidates": [],
                        "closestCandidate": None,
                        "error": str(identification_error),
                        "notice": (
                            "本地候选比较失败，但不会改变原始对比结论；"
                            "候选距离不等同于模型身份确认。"
                        ),
                    }
            if runtime.interrupt_event.is_set():
                raise FingerprintPausedError("comparison interrupted before evidence write")
            artifact = self.evidence.write_json("verification", audit_id, result)
            self.database.finish_run(
                audit_id,
                status="completed",
                verdict=verdict,
                artifact_path=str(artifact.path),
                artifact_sha256=artifact.sha256,
            )
            self.database.finish_comparison_record(audit_id)
        except FingerprintPausedError:
            self._attach_partial_artifact(audit_id, target_path)
            raise
        except asyncio.CancelledError:
            self._attach_partial_artifact(audit_id, target_path)
            raise FingerprintPausedError("comparison interrupted during shutdown") from None
        except Exception as error:
            detail = str(error)
            if api_key:
                detail = detail.replace(api_key, "[REDACTED]")
            partial_path = str(target_path) if target_path and target_path.is_file() else None
            partial_sha = (
                self.evidence.digest_file(target_path) if partial_path and target_path else None
            )
            self.database.finish_run(
                audit_id,
                status="failed",
                verdict="error",
                artifact_path=partial_path,
                artifact_sha256=partial_sha,
                error_message=detail,
            )
            self.database.update_task_progress(
                audit_id,
                stage="failed",
                detail=detail,
            )
            self.database.finish_comparison_record(audit_id)
