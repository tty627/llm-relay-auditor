import re
import unicodedata
from time import perf_counter
from typing import Any

import httpx

from relay_auditor.schemas import EndpointSpec


def _redact_api_key_echo(value: Any, api_key: str | None) -> Any:
    """Recursively remove an explicitly supplied credential from untrusted fields."""

    if not api_key:
        return value
    if isinstance(value, str):
        normalized_key = unicodedata.normalize("NFC", api_key)
        normalized_value = unicodedata.normalize("NFC", value)
        if normalized_key.casefold() not in normalized_value.casefold():
            return value
        redacted = re.sub(
            re.escape(normalized_key),
            "[REDACTED]",
            normalized_value,
            flags=re.IGNORECASE,
        )
        return redacted if redacted != normalized_value else "[REDACTED]"
    if isinstance(value, list):
        return [_redact_api_key_echo(item, api_key) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            safe_key = _redact_api_key_echo(key, api_key) if isinstance(key, str) else key
            redacted[safe_key] = _redact_api_key_echo(item, api_key)
        return redacted
    return value


async def run_smoke(
    endpoint: EndpointSpec,
    prompt: str,
    *,
    timeout_seconds: float,
    api_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    url = f"{str(endpoint.base_url).rstrip('/')}/chat/completions"
    payload = {
        "model": endpoint.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 16,
    }
    started = perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            transport=transport,
            follow_redirects=False,
        ) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as error:
        raise RuntimeError(f"Smoke request failed: {error.__class__.__name__}") from None
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
            "url": _redact_api_key_echo(url, api_key),
            "model": _redact_api_key_echo(endpoint.model, api_key),
            "prompt": _redact_api_key_echo(prompt, api_key),
            "api_key_env": _redact_api_key_echo(endpoint.api_key_env, api_key),
        },
        "response": {
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "model": _redact_api_key_echo(response_json.get("model"), api_key),
            "usage": _redact_api_key_echo(response_json.get("usage"), api_key),
            "has_content": has_content,
            "request_id": _redact_api_key_echo(response.headers.get("x-request-id"), api_key),
        },
    }
