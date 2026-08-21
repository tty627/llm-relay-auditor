import asyncio
import json

import httpx
import pytest

from relay_auditor.detectors.preflight import (
    FingerprintPreflightError,
    run_fingerprint_preflight,
)
from relay_auditor.schemas import EndpointSpec


def test_preflight_redacts_api_key_echoed_in_request_id() -> None:
    secret = "sk-preflight-request-id-echo-must-not-persist"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {secret}"
        return httpx.Response(
            200,
            headers={"x-request-id": f"request/{secret}/suffix"},
            json={"choices": [{"message": {"content": "42"}}]},
        )

    result = asyncio.run(
        run_fingerprint_preflight(
            EndpointSpec(base_url="https://relay.example/v1", model="model-a"),
            api_key=secret,
            timeout_seconds=3,
            transport=httpx.MockTransport(handler),
        )
    )

    assert result["requestId"] == "request/[REDACTED]/suffix"
    assert secret not in json.dumps(result, ensure_ascii=False)


def test_preflight_redacts_api_key_before_truncating_remote_error() -> None:
    secret = "sk-preflight-error-echo-must-not-leak"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"message": f"{'x' * 230}{secret}/suffix"}},
        )

    with pytest.raises(FingerprintPreflightError) as caught:
        asyncio.run(
            run_fingerprint_preflight(
                EndpointSpec(base_url="https://relay.example/v1", model="model-a"),
                api_key=secret,
                timeout_seconds=3,
                transport=httpx.MockTransport(handler),
            )
        )

    message = str(caught.value)
    assert secret not in message
    assert secret[:16] not in message
