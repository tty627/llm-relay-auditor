import json
from pathlib import Path

import httpx

from relay_auditor.calibration import small_sample_upper_threshold

BASE_URL = "http://127.0.0.1:8000"
MOCK_URL = f"{BASE_URL}/mock/v1"
SAME_RUNS = 10
SUBSTITUTE_RUNS = 5


def post(client: httpx.Client, path: str, payload: dict[str, object]) -> dict[str, object]:
    response = client.post(f"{BASE_URL}{path}", json=payload, timeout=120)
    response.raise_for_status()
    return response.json()


def verify(client: httpx.Client, model: str, reference_id: str) -> float:
    result = post(
        client,
        "/api/v1/fingerprints/verify",
        {
            "endpoint": {"base_url": MOCK_URL, "model": model},
            "reference_artifact_id": reference_id,
            "cells": 4,
            "samples": 15,
            "concurrency": 6,
        },
    )
    return float(result["result"]["comparison"]["meanJsd"])


def main() -> int:
    with httpx.Client() as client:
        reference = post(
            client,
            "/api/v1/fingerprints/collect",
            {
                "endpoint": {"base_url": MOCK_URL, "model": "reference-model"},
                "cells": 4,
                "samples": 15,
                "concurrency": 6,
            },
        )
        reference_id = str(reference["artifact_id"])
        same_distances = [verify(client, "reference-model", reference_id) for _ in range(SAME_RUNS)]
        substitute_distances = [
            verify(client, "substitute-model", reference_id) for _ in range(SUBSTITUTE_RUNS)
        ]

    calibration = small_sample_upper_threshold(same_distances)
    threshold = calibration["threshold"]
    report = {
        "protocol": "one-token/v1",
        "reference_artifact_id": reference_id,
        "same_model": {
            "runs": SAME_RUNS,
            "distances": same_distances,
            **calibration,
            "observed_false_positive_count": sum(value > threshold for value in same_distances),
            "robust_false_positive_count": sum(
                value > calibration["robust_threshold"] for value in same_distances
            ),
        },
        "known_substitution": {
            "runs": SUBSTITUTE_RUNS,
            "distances": substitute_distances,
            "detected_count": sum(value > threshold for value in substitute_distances),
        },
        "separation": {
            "max_same": max(same_distances),
            "min_substitute": min(substitute_distances),
            "margin": min(substitute_distances) - max(same_distances),
        },
    }
    output_path = Path("reports/mock_one_token_calibration.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"校准报告已写入 {output_path}")
    passed = (
        report["separation"]["margin"] > 0
        and report["same_model"]["observed_false_positive_count"] == 0
        and report["known_substitution"]["detected_count"] == SUBSTITUTE_RUNS
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
