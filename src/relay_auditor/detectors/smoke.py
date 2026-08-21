from time import perf_counter
from typing import Any

import httpx

from relay_auditor.detectors.preflight import normalize_fingerprint_base_url
from relay_auditor.schemas import EndpointSpec
from relay_auditor.secret_safety import reject_secret_echo


async def run_smoke(
    endpoint: EndpointSpec,
    prompt: str,
    *,
    timeout_seconds: float,
    api_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    if endpoint.api_key_env and api_key is None:
        raise ValueError("api_key_env must be resolved by the service before smoke testing")
    credential = api_key.strip() if api_key is not None else None
    if api_key is not None and not credential:
        raise ValueError("api_key must not be empty")
    headers = {"content-type": "application/json"}
    if credential:
        headers["authorization"] = f"Bearer {credential}"

    normalized_base_url = normalize_fingerprint_base_url(str(endpoint.base_url))
    url = f"{normalized_base_url}/chat/completions"
    payload = {
        "model": endpoint.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 16,
    }
    started = perf_counter()
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        transport=transport,
        follow_redirects=False,
    ) as client:
        response = await client.post(url, headers=headers, json=payload)
    latency_ms = round((perf_counter() - started) * 1000, 2)

    response_json: dict[str, Any]
    try:
        parsed = response.json()
        response_json = parsed if isinstance(parsed, dict) else {"body": parsed}
    except ValueError:
        response_json = {"body_preview": response.text[:500]}

    choices = response_json.get("choices")
    has_content = bool(
        isinstance(choices, list)
        and choices
        and isinstance(choices[0], dict)
        and isinstance(choices[0].get("message"), dict)
        and choices[0]["message"].get("content")
    )
    passed = response.is_success and has_content
    result = {
        "verdict": "pass" if passed else "fail",
        "request": {
            "url": url,
            "model": endpoint.model,
            "prompt": prompt,
            "api_key_env": endpoint.api_key_env,
        },
        "response": {
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "model": response_json.get("model"),
            "usage": response_json.get("usage"),
            "has_content": has_content,
            "request_id": response.headers.get("x-request-id"),
        },
    }
    reject_secret_echo(result, credential, source="smoke response")
    return result
