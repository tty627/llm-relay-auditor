import json
from pathlib import Path

import httpx
import pytest

from relay_auditor.detectors.smoke import run_smoke
from relay_auditor.evidence import EvidenceStore
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


async def test_smoke_redacts_nested_api_key_echoes_before_payload_and_artifact(
    tmp_path: Path,
) -> None:
    secret = "sk-smoke-response-echo-must-not-persist"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {secret}"
        return httpx.Response(
            200,
            headers={"x-request-id": f"request/{secret}/suffix"},
            json={
                "model": f"relay-{secret}",
                "choices": [{"message": {"content": "AUDIT_OK"}}],
                "usage": {
                    "nested": [
                        {
                            "authorization": f"Bearer {secret}",
                            "json": json.dumps({"api_key": secret}),
                        }
                    ],
                    f"credential-{secret}": {"echo": secret},
                },
            },
        )

    result = await run_smoke(
        EndpointSpec(base_url="https://mock.example/v1", model="reference-model"),
        "Reply with exactly: AUDIT_OK",
        timeout_seconds=5,
        api_key=secret,
        transport=httpx.MockTransport(handler),
    )

    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert secret not in serialized
    assert result["response"]["model"] == "relay-[REDACTED]"
    assert result["response"]["request_id"] == "request/[REDACTED]/suffix"
    assert "credential-[REDACTED]" in result["response"]["usage"]

    evidence = EvidenceStore(tmp_path / "evidence")
    evidence.initialize()
    artifact = evidence.write_json(
        "smoke",
        "11111111-1111-1111-1111-111111111111",
        result,
    )
    assert secret not in artifact.path.read_text(encoding="utf-8")


async def test_smoke_network_exception_does_not_retain_api_key() -> None:
    secret = "sk-smoke-exception-echo-must-not-leak"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"transport echoed {secret}", request=request)

    with pytest.raises(RuntimeError) as caught:
        await run_smoke(
            EndpointSpec(base_url="https://mock.example/v1", model="reference-model"),
            "Reply with exactly: AUDIT_OK",
            timeout_seconds=5,
            api_key=secret,
            transport=httpx.MockTransport(handler),
        )

    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
