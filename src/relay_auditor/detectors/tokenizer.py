import asyncio
import math
import os
import random
from datetime import UTC, datetime
from statistics import median
from typing import Any

import httpx

from relay_auditor.schemas import EndpointSpec

REPETITIONS = [0, 1, 2, 4, 8]
PROBE_UNITS = {
    "cjk": "中转站模型验真。",
    "english": " antidisestablishmentarianism",
    "emoji": " 👨‍👩‍👧‍👦🚀",
    "structure": '\n{"alpha":[1,2,3],"ok":true}',
    "opaque": " 550e8400-e29b-41d4-a716-446655440000/aG93bGVubGdl",
    "mixed": " 模型Audit東京테스트-42",
}
PROMPT_PREFIX = "Return only OK. Probe payload follows:"


def linear_fit(xs: list[int], ys: list[float]) -> dict[str, float]:
    if len(xs) != len(ys) or len(xs) < 2:
        raise ValueError("linear fit requires paired samples")
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    denominator = sum((value - mean_x) ** 2 for value in xs)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    slope = slope / denominator if denominator else 0.0
    intercept = mean_y - slope * mean_x
    predictions = [intercept + slope * value for value in xs]
    residual_sum = sum(
        (actual - predicted) ** 2 for actual, predicted in zip(ys, predictions, strict=True)
    )
    total_sum = sum((actual - mean_y) ** 2 for actual in ys)
    r_squared = 1.0 if total_sum == 0 and residual_sum == 0 else 1 - residual_sum / total_sum
    return {
        "slope": round(slope, 6),
        "intercept": round(intercept, 6),
        "r_squared": round(r_squared, 6),
        "rmse": round(math.sqrt(residual_sum / len(xs)), 6),
    }


async def collect_tokenizer_fingerprint(
    endpoint: EndpointSpec,
    *,
    timeout_seconds: float,
    samples_per_point: int,
    concurrency: int,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if endpoint.api_key_env:
        api_key = os.environ.get(endpoint.api_key_env)
        if not api_key:
            raise ValueError(f"environment variable is not set: {endpoint.api_key_env}")
        headers["authorization"] = f"Bearer {api_key}"

    jobs = [
        (probe_id, repetition, sample_index)
        for probe_id in PROBE_UNITS
        for repetition in REPETITIONS
        for sample_index in range(samples_per_point)
    ]
    random.SystemRandom().shuffle(jobs)
    semaphore = asyncio.Semaphore(concurrency)
    url = f"{str(endpoint.base_url).rstrip('/')}/chat/completions"
    results: dict[str, dict[int, list[int]]] = {
        probe_id: {repetition: [] for repetition in REPETITIONS} for probe_id in PROBE_UNITS
    }

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:

        async def run_job(probe_id: str, repetition: int, _: int) -> tuple[str, int, int]:
            prompt = f"{PROMPT_PREFIX}\n{PROBE_UNITS[probe_id] * repetition}"
            payload = {
                "model": endpoint.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "max_tokens": 1,
            }
            async with semaphore:
                response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
            usage = body.get("usage") if isinstance(body, dict) else None
            prompt_tokens = usage.get("prompt_tokens") if isinstance(usage, dict) else None
            if not isinstance(prompt_tokens, int):
                raise ValueError("endpoint did not return integer usage.prompt_tokens")
            return probe_id, repetition, prompt_tokens

        collected = await asyncio.gather(*(run_job(*job) for job in jobs))

    for probe_id, repetition, prompt_tokens in collected:
        results[probe_id][repetition].append(prompt_tokens)

    probes: dict[str, dict[str, Any]] = {}
    slope_vector: dict[str, float] = {}
    unstable_probes: list[str] = []
    for probe_id, by_repetition in results.items():
        medians = [float(median(by_repetition[value])) for value in REPETITIONS]
        fit = linear_fit(REPETITIONS, medians)
        variable_points = [
            repetition for repetition, values in by_repetition.items() if len(set(values)) > 1
        ]
        if fit["r_squared"] < 0.98 or variable_points:
            unstable_probes.append(probe_id)
        probes[probe_id] = {
            "counts": {str(key): values for key, values in by_repetition.items()},
            "medians": medians,
            "fit": fit,
            "variable_points": variable_points,
        }
        slope_vector[probe_id] = fit["slope"]

    return {
        "protocol": "tokenizer-slope/v1",
        "model": endpoint.model,
        "base_url": str(endpoint.base_url),
        "collected_at": datetime.now(UTC).isoformat(),
        "repetitions": REPETITIONS,
        "samples_per_point": samples_per_point,
        "probes": probes,
        "slope_vector": slope_vector,
        "unstable_probes": unstable_probes,
    }


def compare_tokenizer_fingerprints(
    reference: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    reference_vector = reference.get("slope_vector")
    target_vector = target.get("slope_vector")
    if not isinstance(reference_vector, dict) or not isinstance(target_vector, dict):
        raise ValueError("tokenizer evidence is missing slope_vector")
    probe_ids = sorted(set(reference_vector) & set(target_vector))
    if not probe_ids:
        raise ValueError("tokenizer evidence has no comparable probes")

    absolute_deltas = {
        probe_id: abs(float(target_vector[probe_id]) - float(reference_vector[probe_id]))
        for probe_id in probe_ids
    }
    denominator = sum(max(abs(float(reference_vector[probe_id])), 1.0) for probe_id in probe_ids)
    normalized_l1 = sum(absolute_deltas.values()) / denominator
    unstable = sorted(set(target.get("unstable_probes") or []))

    if normalized_l1 > 0.10:
        verdict = "mismatch"
    elif unstable:
        verdict = "unstable"
    elif normalized_l1 > 0.03:
        verdict = "uncertain"
    else:
        verdict = "match"

    return {
        "verdict": verdict,
        "normalized_l1": round(normalized_l1, 6),
        "thresholds": {"match_max": 0.03, "uncertain_max": 0.10},
        "threshold_source": "engineering_default_pending_official_calibration",
        "absolute_slope_deltas": absolute_deltas,
        "reference_slope_vector": reference_vector,
        "target_slope_vector": target_vector,
        "target_unstable_probes": unstable,
    }
