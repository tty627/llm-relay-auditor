import asyncio

import httpx
import pytest

from relay_auditor.detectors.models import discover_models
from relay_auditor.schemas import EphemeralConnectionSpec


@pytest.mark.parametrize("echo_field", ["id", "owned_by"])
def test_model_discovery_rejects_credential_echo_without_returning_secret(
    echo_field: str,
) -> None:
    secret = "Discovery-Secret-Marker"

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {secret}"
        model = {"id": "safe-model", "owned_by": "safe-owner"}
        model[echo_field] = f"prefix-{secret.casefold()}-suffix"
        return httpx.Response(200, json={"data": [model]})

    endpoint = EphemeralConnectionSpec(
        base_url="https://relay.example/v1",
        api_key=secret,
    )
    with pytest.raises(ValueError) as caught:
        asyncio.run(
            discover_models(
                endpoint,
                timeout_seconds=1,
                transport=httpx.MockTransport(handler),
            )
        )

    assert str(caught.value) == (
        "endpoint /models response contained a possible credential echo"
    )
    assert secret not in str(caught.value)


def test_model_discovery_returns_only_safe_model_fields() -> None:
    secret = "local-test-key"

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "model-b", "owned_by": None, "ignored": "remote metadata"},
                    {"id": "model-a", "owned_by": "vendor"},
                ]
            },
        )

    result = asyncio.run(
        discover_models(
            EphemeralConnectionSpec(
                base_url="https://relay.example/v1",
                api_key=secret,
            ),
            timeout_seconds=1,
            transport=httpx.MockTransport(handler),
        )
    )

    assert result["models"] == [
        {"id": "model-a", "owned_by": "vendor"},
        {"id": "model-b", "owned_by": None},
    ]
    assert secret not in str(result)
