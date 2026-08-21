import asyncio
from typing import Any

import httpx

from relay_auditor.detectors.preflight import (
    normalize_fingerprint_base_url,
    retry_after_seconds,
)
from relay_auditor.schemas import EphemeralConnectionSpec
from relay_auditor.secret_safety import reject_secret_echo

_TRANSIENT_STATUS_CODES = {429, 502, 503, 504}
_MAX_RETRY_DELAY_SECONDS = 30.0


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    requested = retry_after_seconds(response)
    if requested is None:
        requested = 0.25 * (2**attempt)
    return min(max(requested, 0.0), _MAX_RETRY_DELAY_SECONDS)


async def discover_models(
    endpoint: EphemeralConnectionSpec,
    *,
    timeout_seconds: float,
    api_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    max_retries: int = 2,
) -> dict[str, Any]:
    if max_retries < 0:
        raise ValueError("max_retries must be non-negative")
    headers = {"accept": "application/json"}
    raw_credential = api_key if api_key is not None else endpoint.reveal_api_key()
    credential = raw_credential.strip() if raw_credential is not None else None
    if raw_credential is not None and not credential:
        raise ValueError("api_key must not be empty")
    if credential:
        headers["authorization"] = f"Bearer {credential}"

    normalized_base_url = normalize_fingerprint_base_url(str(endpoint.base_url))
    url = f"{normalized_base_url}/models"
    attempts = 0
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        transport=transport,
        follow_redirects=False,
    ) as client:
        while True:
            attempts += 1
            try:
                response = await client.get(url, headers=headers)
            except httpx.TransportError:
                if attempts > max_retries:
                    raise
                await asyncio.sleep(min(0.25 * (2 ** (attempts - 1)), 2.0))
                continue
            if response.status_code not in _TRANSIENT_STATUS_CODES or attempts > max_retries:
                break
            delay = _retry_delay(response, attempts - 1)
            if delay:
                await asyncio.sleep(delay)
    if not response.is_success:
        response.raise_for_status()
        raise RuntimeError(f"model discovery returned HTTP {response.status_code}")
    payload = response.json()
    raw_models = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(raw_models, list):
        raise ValueError("endpoint /models response is missing a data array")

    models: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for item in raw_models:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str):
            continue
        model_id = model_id.strip()
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        owner = item.get("owned_by")
        models.append(
            {
                "id": model_id,
                "owned_by": owner if isinstance(owner, str) else None,
            }
        )
    models.sort(key=lambda item: item["id"].lower())
    result = {
        "base_url": normalized_base_url,
        "models_url": url,
        "count": len(models),
        "models": models,
        "attempts": attempts,
        "retries": attempts - 1,
    }
    reject_secret_echo(result, credential, source="model discovery response")
    return result
