import httpx

from relay_auditor.detectors.smoke import run_smoke
from relay_auditor.schemas import EndpointSpec


async def test_smoke_collects_safe_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") is None
        return httpx.Response(
            200,
            headers={"x-request-id": "req-test"},
            json={
                "model": "reference-model",
                "choices": [{"message": {"content": "AUDIT_OK"}}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 1, "total_tokens": 10},
            },
        )

    result = await run_smoke(
        EndpointSpec(base_url="https://mock.example/v1", model="reference-model"),
        "Reply with exactly: AUDIT_OK",
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )

    assert result["verdict"] == "pass"
    assert result["response"]["request_id"] == "req-test"
    assert "authorization" not in result["request"]
