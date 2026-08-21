import re
import unicodedata
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit

import httpx

from relay_auditor.schemas import EndpointSpec


class FingerprintPreflightError(RuntimeError):
    """A safe, classified failure from the single-request connectivity gate."""

    def __init__(
        self,
        message: str,
        *,
        transient: bool = False,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
        error_kind: str = "permanent",
    ) -> None:
        super().__init__(message)
        self.transient = transient
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds
        self.error_kind = error_kind


def normalize_fingerprint_base_url(base_url: str) -> str:
    """Mirror llm-fingerprint-detector's normalizeBaseUrl behaviour."""

    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise FingerprintPreflightError("预检失败：中转站地址无效")
    path = parsed.path.rstrip("/")
    if path.endswith("/chat/completions"):
        path = path[: -len("/chat/completions")]
    if not path:
        path = "/v1"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _first_adapter_body(base_url: str) -> dict[str, Any]:
    lowered = base_url.lower()
    if "api.openai.com" in lowered or "api.deepseek.com" in lowered:
        return {"reasoning_effort": "none"}
    if "bigmodel.cn" in lowered:
        return {"thinking": {"type": "disabled"}}
    return {"reasoning": {"enabled": False}}


def _extract_content(message: object) -> str:
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "".join(parts)
    return ""


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


def _safe_error_message(response: httpx.Response, api_key: str | None) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    message = error.get("message") if isinstance(error, dict) else None
    if not isinstance(message, str) or not message.strip():
        return None
    redacted = _redact_api_key_echo(message, api_key)
    return " ".join(redacted.split())[:240]


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse Retry-After without ever following a remote-provided URL."""

    value = response.headers.get("retry-after")
    if not value:
        return None
    stripped = value.strip()
    try:
        seconds = float(stripped)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(stripped)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        seconds = (retry_at - datetime.now(UTC)).total_seconds()
    if seconds < 0:
        return 0.0
    return seconds


def _is_transient_http_status(status_code: int) -> bool:
    """Classify retryable response codes without retrying unsupported gateways."""

    if status_code in {408, 425, 429}:
        return True
    return 500 <= status_code < 600 and status_code not in {501, 505}


async def run_fingerprint_preflight(
    endpoint: EndpointSpec,
    *,
    api_key: str | None,
    timeout_seconds: float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Send one One Token-compatible connectivity probe.

    A 400/422 from the first adapter-shaped body gets one bare-body
    compatibility probe because the real CLI would move on to another adapter.
    This function classifies retryable failures; the batch scheduler owns the
    interruptible cooldown/requeue policy so one slow relay cannot block others.
    """

    normalized = normalize_fingerprint_base_url(str(endpoint.base_url))
    url = f"{normalized}/chat/completions"
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    base_payload: dict[str, Any] = {
        "model": endpoint.model,
        "temperature": 1.0,
        "max_tokens": 16,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": "Answer with exactly one word. No punctuation, no explanation.",
            },
            {
                "role": "user",
                "content": "Name a random number between 1 and 100.",
            },
        ],
    }
    adapter_body = _first_adapter_body(normalized)
    payload = {**base_payload, **adapter_body}
    strategy = next(iter(adapter_body))
    attempts = 1
    started = perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            transport=transport,
            follow_redirects=False,
        ) as client:
            request_started = perf_counter()
            response = await client.post(url, headers=headers, json=payload)
            latency_ms = round((perf_counter() - request_started) * 1000, 2)
            if response.status_code in {400, 422}:
                attempts = 2
                strategy = "none"
                request_started = perf_counter()
                response = await client.post(url, headers=headers, json=base_payload)
                latency_ms = round((perf_counter() - request_started) * 1000, 2)
    except httpx.TimeoutException:
        raise FingerprintPreflightError(
            f"预检超时：{timeout_seconds:g} 秒内没有收到中转站响应；未开始正式采样",
            transient=True,
            error_kind="timeout",
        ) from None
    except httpx.HTTPError as error:
        raise FingerprintPreflightError(
            f"预检网络失败：{error.__class__.__name__}；未开始正式采样",
            transient=True,
            error_kind="network",
        ) from None

    total_latency_ms = round((perf_counter() - started) * 1000, 2)
    if not response.is_success:
        status_code = response.status_code
        explanation = {
            401: "API Key 被拒绝",
            403: "当前 Key 无权访问该模型",
            429: "中转站限流或额度不足",
            410: "上游路由或服务已停用",
        }.get(status_code)
        if explanation is None and status_code >= 500:
            explanation = "中转站上游服务暂不可用"
        explanation = explanation or "请求参数或接口不兼容"
        remote_message = _safe_error_message(response, api_key)
        suffix = f" · {remote_message}" if remote_message else ""
        transient = _is_transient_http_status(status_code)
        raise FingerprintPreflightError(
            f"预检失败：HTTP {status_code}，{explanation}{suffix}；未开始正式采样",
            transient=transient,
            status_code=status_code,
            retry_after_seconds=_retry_after_seconds(response) if transient else None,
            error_kind="http",
        )

    try:
        body = response.json()
    except ValueError as error:
        raise FingerprintPreflightError(
            f"预检失败：HTTP {response.status_code} 但响应不是 JSON；未开始正式采样"
        ) from error
    choices = body.get("choices") if isinstance(body, dict) else None
    message = choices[0].get("message") if isinstance(choices, list) and choices else None
    if not _extract_content(message).strip():
        raise FingerprintPreflightError(
            f"预检失败：HTTP {response.status_code} 但没有可见文本；未开始正式采样"
        )
    return {
        "statusCode": response.status_code,
        "latencyMs": latency_ms,
        "hasContent": True,
        "requestId": _redact_api_key_echo(response.headers.get("x-request-id"), api_key),
        "normalizedBaseUrl": normalized,
        "retries": 0,
        "attempts": attempts,
        "strategy": strategy,
        "totalLatencyMs": total_latency_ms,
    }
