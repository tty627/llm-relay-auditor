import unicodedata
from typing import Any

import httpx

from relay_auditor.schemas import EphemeralConnectionSpec


async def discover_models(
    endpoint: EphemeralConnectionSpec,
    *,
    timeout_seconds: float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    headers = {"accept": "application/json"}
    api_key = endpoint.reveal_api_key()
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    url = f"{str(endpoint.base_url).rstrip('/')}/models"
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        transport=transport,
    ) as client:
        response = await client.get(url, headers=headers)
    response.raise_for_status()
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
        if not isinstance(model_id, str) or not model_id.strip() or model_id in seen:
            continue
        model_id = model_id.strip()
        owner = item.get("owned_by")
        if api_key:
            normalized_key = unicodedata.normalize("NFC", api_key).casefold()
            untrusted_strings = [model_id]
            if isinstance(owner, str):
                untrusted_strings.append(owner)
            if any(
                normalized_key in unicodedata.normalize("NFC", value).casefold()
                for value in untrusted_strings
            ):
                raise ValueError(
                    "endpoint /models response contained a possible credential echo"
                )
        seen.add(model_id)
        models.append(
            {
                "id": model_id,
                "owned_by": owner if isinstance(owner, str) else None,
            }
        )
    models.sort(key=lambda item: item["id"].lower())
    return {
        "base_url": str(endpoint.base_url),
        "models_url": url,
        "count": len(models),
        "models": models,
    }
