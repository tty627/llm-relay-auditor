import os
from time import perf_counter
from typing import Any

import httpx

from relay_auditor.schemas import EndpointSpec


async def run_smoke(
    endpoint: EndpointSpec,
    prompt: str,
    *,
    timeout_seconds: float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if endpoint.api_key_env:
        api_key = os.environ.get(endpoint.api_key_env)
        if not api_key:
            raise ValueError(f"environment variable is not set: {endpoint.api_key_env}")
        headers["authorization"] = f"Bearer {api_key}"

    url = f"{str(endpoint.base_url).rstrip('/')}/chat/completions"
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
    return {
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
