import json
import sys

import httpx

BASE_URL = "http://127.0.0.1:8000"
MOCK_URL = f"{BASE_URL}/mock/v1"


def post(client: httpx.Client, path: str, payload: dict[str, object]) -> dict[str, object]:
    response = client.post(f"{BASE_URL}{path}", json=payload, timeout=120)
    response.raise_for_status()
    body = response.json()
    print(json.dumps({"path": path, "verdict": body.get("verdict")}, ensure_ascii=False))
    return body


def main() -> int:
    with httpx.Client() as client:
        health = client.get(f"{BASE_URL}/health", timeout=5)
        health.raise_for_status()
        print(json.dumps(health.json(), ensure_ascii=False))

        post(
            client,
            "/api/v1/audits/smoke",
            {"target": {"base_url": MOCK_URL, "model": "reference-model"}},
        )
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
        reference_id = reference["artifact_id"]

        same = post(
            client,
            "/api/v1/fingerprints/verify",
            {
                "endpoint": {"base_url": MOCK_URL, "model": "reference-model"},
                "reference_artifact_id": reference_id,
                "cells": 4,
                "samples": 15,
                "concurrency": 6,
            },
        )
        substitute = post(
            client,
            "/api/v1/fingerprints/verify",
            {
                "endpoint": {"base_url": MOCK_URL, "model": "substitute-model"},
                "reference_artifact_id": reference_id,
                "cells": 4,
                "samples": 15,
                "concurrency": 6,
            },
        )

    if same.get("verdict") != "match" or substitute.get("verdict") != "mismatch":
        print("演示判定未达到预期", file=sys.stderr)
        return 1
    print("本地闭环通过：相同模型=MATCH，替换模型=MISMATCH")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
