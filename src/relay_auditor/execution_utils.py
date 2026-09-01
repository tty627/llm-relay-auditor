from __future__ import annotations

import asyncio
import json
import math
import random
from collections import Counter
from collections.abc import Awaitable, Callable
from pathlib import Path
from statistics import median
from typing import Any, TypedDict, TypeVar

from relay_auditor.network_safety import EndpointResolution
from relay_auditor.strict_preflight import StrictPreflightError, run_strict_preflight


class ExecutionInterrupted(RuntimeError):
    """A pause, cancellation, shutdown, or wall-clock control interrupted work."""


PreflightCallable = Callable[..., Awaitable[dict[str, Any]]]


class PreflightRetryProgress(TypedDict):
    attempt_count: int
    retry_count: int
    retry_budget_used: int


PreflightProgressCallback = Callable[[PreflightRetryProgress], None]
T = TypeVar("T")


async def await_interruptibly(
    awaitable: Awaitable[T],
    interrupt_event: asyncio.Event,
    *,
    timeout_seconds: float | None = None,
) -> T:
    """Race work against control interruption and cancel the losing awaitable."""

    async def bounded() -> T:
        if timeout_seconds is None:
            return await awaitable
        async with asyncio.timeout(timeout_seconds):
            return await awaitable

    if interrupt_event.is_set():
        if hasattr(awaitable, "close"):
            awaitable.close()  # type: ignore[union-attr]
        raise ExecutionInterrupted("control_interrupt")
    work = asyncio.create_task(bounded())
    interrupted = asyncio.create_task(interrupt_event.wait())
    try:
        done, _ = await asyncio.wait(
            {work, interrupted},
            return_when=asyncio.FIRST_COMPLETED,
        )
        # A completed operation wins a simultaneous control race so verified
        # evidence is never discarded after it has become immutable.
        if work in done:
            return await work
        work.cancel()
        await asyncio.gather(work, return_exceptions=True)
        raise ExecutionInterrupted("control_interrupt")
    finally:
        if not interrupted.done():
            interrupted.cancel()
            await asyncio.gather(interrupted, return_exceptions=True)


async def wait_interruptibly(event: asyncio.Event, delay_seconds: float) -> None:
    if event.is_set():
        raise ExecutionInterrupted("control_interrupt")
    if delay_seconds <= 0:
        await asyncio.sleep(0)
        return
    try:
        await asyncio.wait_for(event.wait(), timeout=delay_seconds)
    except TimeoutError:
        return
    raise ExecutionInterrupted("control_interrupt")


async def strict_preflight_with_retry(
    resolution: EndpointResolution,
    *,
    model: str,
    api_key: str,
    timeout_seconds: float,
    workspace_id: str | None,
    interrupt_event: asyncio.Event,
    retry_budget: int,
    runner: PreflightCallable = run_strict_preflight,
    jitter: Callable[[], float] | None = None,
    progress_callback: PreflightProgressCallback | None = None,
) -> tuple[dict[str, Any], int, int]:
    """Run strict preflight and publish exact physical-attempt retry progress.

    ``retry_count`` counts retries whose request has started, while
    ``retry_budget_used`` counts retry slots reserved before interruptible
    cooldown. The return value retains the legacy ``(result, attempts, retries)``
    shape.
    """

    attempts = 0
    retries = 0
    retry_budget_used = 0
    random_fraction = jitter or random.SystemRandom().random

    def report_progress() -> None:
        if progress_callback is not None:
            progress_callback(
                {
                    "attempt_count": attempts,
                    "retry_count": retries,
                    "retry_budget_used": retry_budget_used,
                }
            )

    while True:
        if interrupt_event.is_set():
            raise ExecutionInterrupted("control_interrupt")
        attempts += 1
        if attempts > 1:
            retries += 1
        # Publish before constructing/awaiting the runner so an interruption in
        # DNS, connect, TLS, headers, or body still leaves an exact started-attempt
        # count in the caller's durable ledger.
        report_progress()
        try:
            result = await await_interruptibly(
                runner(
                    resolution,
                    model=model,
                    api_key=api_key,
                    timeout_seconds=timeout_seconds,
                    workspace_id=workspace_id,
                ),
                interrupt_event,
                timeout_seconds=timeout_seconds,
            )
            return result, attempts, retries
        except StrictPreflightError as error:
            can_retry = (
                error.transient
                and retry_budget_used < 2
                and retry_budget_used < retry_budget
            )
            if not can_retry:
                error.attempts = attempts
                error.retries = retries
                raise
            # Reserve the budget before the interruptible cooldown. A pause in
            # that cooldown has consumed retry capacity but has not yet sent the
            # retry, which is why retry_budget_used and retry_count are distinct.
            retry_budget_used += 1
            report_progress()
            base_delay = (
                error.retry_after_seconds
                if error.retry_after_seconds is not None
                else min(60.0, 0.5 * (2 ** (retry_budget_used - 1)))
            )
            delay = min(60.0, max(0.0, base_delay) + min(1.0, random_fraction()))
            await wait_interruptibly(interrupt_event, delay)


def safe_failure_code(error: BaseException) -> tuple[str, int | None]:
    if isinstance(error, StrictPreflightError):
        return error.code, error.status_code
    lowered = str(error).casefold()
    if "credential" in lowered and "echo" in lowered:
        return "credential_echo_detected", None
    if "timeout" in lowered or "timed out" in lowered or "stalled" in lowered:
        return "timeout", None
    if "protocol" in lowered or "transport profile" in lowered or "manifest" in lowered:
        return "unsupported_protocol", None
    if isinstance(error, (FileNotFoundError, ConnectionError, OSError)):
        return "request_failed", None
    return "request_failed", None


def jsonl_observations(path: Path) -> dict[str, Any]:
    """Derive safe latency/model summaries; never return raw completion text."""

    latencies: list[float] = []
    models: Counter[str] = Counter()
    attempts = 0
    with path.open("r", encoding="utf-8") as source:
        for raw_line in source:
            if not raw_line.strip():
                continue
            sample = json.loads(raw_line)
            if not isinstance(sample, dict):
                raise ValueError("raw evidence line is not an object")
            attempts += 1
            latency = sample.get("latencyMs")
            if (
                isinstance(latency, (int, float))
                and not isinstance(latency, bool)
                and math.isfinite(float(latency))
                and latency >= 0
            ):
                latencies.append(float(latency))
            reported = sample.get("reportedModel")
            if isinstance(reported, str) and reported.strip() and len(reported) <= 255:
                models[reported.strip()] += 1
    latencies.sort()

    def quantile(probability: float) -> float | None:
        if not latencies:
            return None
        position = (len(latencies) - 1) * probability
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return latencies[lower]
        weight = position - lower
        return latencies[lower] * (1 - weight) + latencies[upper] * weight

    reported_model = None
    if models:
        reported_model = sorted(models.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return {
        "latency_p50_ms": median(latencies) if latencies else None,
        "latency_p95_ms": quantile(0.95),
        "reported_model": reported_model,
        "logical_samples": attempts,
    }
