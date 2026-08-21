import json
import sys

import httpx

BASE_URL = "http://127.0.0.1:8000"
MOCK_URL = f"{BASE_URL}/mock/v1"


def post(client: httpx.Client, path: str, payload: dict[str, object]) -> dict[str, object]:
    response = client.post(f"{BASE_URL}{path}", json=payload, timeout=120)
    response.raise_for_status()
    return response.json()


def get_or_create_endpoint(client: httpx.Client) -> dict[str, object]:
    endpoints = client.get(f"{BASE_URL}/api/v1/endpoints", timeout=10).json()["items"]
    existing = next((item for item in endpoints if item["name"] == "mock-official"), None)
    if existing:
        return existing
    return post(
        client,
        "/api/v1/endpoints",
        {
            "name": "mock-official",
            "provider": "local",
            "base_url": MOCK_URL,
            "model": "reference-model",
        },
    )


def verify(
    client: httpx.Client,
    model: str,
    reference_artifact_id: str,
) -> dict[str, object]:
    result = post(
        client,
        "/api/v1/tokenizers/verify",
        {
            "endpoint": {"base_url": MOCK_URL, "model": model},
            "reference_artifact_id": reference_artifact_id,
            "samples_per_point": 2,
            "concurrency": 6,
        },
    )
    comparison = result["result"]["comparison"]
    print(
        json.dumps(
            {
                "model": model,
                "operational_verdict": result["verdict"],
                "exploratory_verdict": comparison["exploratory_verdict"],
                "normalized_l1": comparison["normalized_l1"],
                "unstable_probes": comparison["target_unstable_probes"],
            },
            ensure_ascii=False,
        )
    )
    return result


def main() -> int:
    with httpx.Client() as client:
        endpoint = get_or_create_endpoint(client)
        reference = post(
            client,
            "/api/v1/tokenizers/collect",
            {
                "endpoint": {"base_url": MOCK_URL, "model": "reference-model"},
                "samples_per_point": 2,
                "concurrency": 6,
            },
        )
        reference_id = str(reference["artifact_id"])
        post(
            client,
            "/api/v1/baselines",
            {
                "endpoint_id": endpoint["id"],
                "detector": "tokenizer",
                "artifact_id": reference_id,
                "valid_days": 14,
                "metadata": {"source": "local-mock-demo"},
            },
        )

        same = verify(client, "reference-model", reference_id)
        substitute = verify(client, "substitute-model", reference_id)
        mixed = verify(client, "mixed-20", reference_id)

    same_comparison = same["result"]["comparison"]
    substitute_comparison = substitute["result"]["comparison"]
    mixed_comparison = mixed["result"]["comparison"]
    expected = (
        all(result["verdict"] == "unverifiable" for result in (same, substitute, mixed))
        and same_comparison["exploratory_verdict"] == "match"
        and substitute_comparison["exploratory_verdict"] == "mismatch"
        and mixed_comparison["exploratory_verdict"] in {"unstable", "mismatch"}
    )
    if not expected:
        print("Tokenizer 演示判定未达到预期", file=sys.stderr)
        return 1
    print("Tokenizer 闭环通过：operational=UNVERIFIABLE，探索性距离按预期区分场景")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
