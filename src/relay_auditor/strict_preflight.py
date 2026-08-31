from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import perf_counter
from typing import Any

import httpcore
import httpx

from relay_auditor.batch_reports import SecretCanaryDetected, SecretCanaryScanner
from relay_auditor.network_safety import EndpointResolution
from relay_auditor.pinned_http import PinnedAsyncHTTPTransport


class StrictPreflightError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        status_code: int | None = None,
        transient: bool = False,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.transient = transient
        self.retry_after_seconds = retry_after_seconds


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        seconds = float(raw.strip())
    except (ValueError, OverflowError):
        try:
            retry_at = parsedate_to_datetime(raw.strip())
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        seconds = (retry_at - datetime.now(UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return min(60.0, max(0.0, seconds))


def _request(
    *,
    protocol: str,
    model: str,
    api_key: str,
    workspace_id: str | None,
) -> tuple[dict[str, str], dict[str, Any]]:
    system_prompt = "Answer with exactly one word or number. No punctuation or explanation."
    user_prompt = "Name a random number between 1 and 100."
    if protocol == "openai_chat":
        return (
            {
                "authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 1,
                "max_tokens": 16,
                "reasoning": {"enabled": False},
                "usage": {"include": True},
            },
        )
    if protocol == "anthropic_messages":
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        if workspace_id is not None:
            headers["anthropic-workspace-id"] = workspace_id
        return (
            headers,
            {
                "model": model,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "temperature": 1,
                "max_tokens": 16,
                "thinking": {"type": "disabled"},
                "output_config": {"effort": "high"},
            },
        )
    raise StrictPreflightError("unsupported_protocol")


def _openai_text(payload: dict[str, Any]) -> tuple[str, bool]:
    choices = payload.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices else None
    message = choice.get("message") if isinstance(choice, dict) else None
    if not isinstance(message, dict):
        return "", False
    contaminated = choice.get("finish_reason") in {"tool_calls", "function_call"} or any(
        message.get(name) not in (None, "", [], {})
        for name in (
            "reasoning",
            "reasoning_content",
            "reasoning_details",
            "thinking",
            "tool_calls",
            "function_call",
        )
    )
    content = message.get("content")
    if isinstance(content, str):
        return content, contaminated
    if isinstance(content, list):
        if any(
            not isinstance(block, dict) or block.get("type") not in {None, "text"}
            for block in content
        ):
            contaminated = True
        texts = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") in {None, "text"}
        ]
        return "".join(text for text in texts if isinstance(text, str)), contaminated
    return "", contaminated


_INTERNAL_XML = re.compile(
    r"<\s*\/?\s*(?:think(?:ing)?|analysis|reasoning|tool(?:_use|_result)?|"
    r"function_calls?|invoke|use_mcp_tool)\b[^>]*>",
    re.IGNORECASE,
)


def _anthropic_text(payload: dict[str, Any]) -> tuple[str, bool]:
    content = payload.get("content")
    if not isinstance(content, list):
        return "", False
    texts: list[str] = []
    contaminated = False
    for block in content:
        if not isinstance(block, dict):
            contaminated = True
            continue
        block_type = block.get("type")
        if block_type == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
        else:
            contaminated = True
    text = "".join(texts)
    return (
        text,
        contaminated
        or payload.get("stop_reason") == "tool_use"
        or bool(_INTERNAL_XML.search(text)),
    )


def _positive_reasoning_usage(payload: dict[str, Any]) -> bool:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return False
    candidates: list[Any] = [usage.get("reasoning_tokens")]
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        candidates.append(details.get("reasoning_tokens"))
    return any(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in candidates
    )


async def run_strict_preflight(
    resolution: EndpointResolution,
    *,
    model: str,
    api_key: str,
    timeout_seconds: float = 30.0,
    workspace_id: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    credential = api_key.strip()
    if not credential:
        raise StrictPreflightError("missing_credential")
    credential_scanner = SecretCanaryScanner([credential])
    headers, body = _request(
        protocol=resolution.protocol,
        model=model,
        api_key=credential,
        workspace_id=workspace_id,
    )
    started = perf_counter()
    owned_transport = transport or PinnedAsyncHTTPTransport(resolution)
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            transport=owned_transport,
            follow_redirects=False,
            trust_env=False,
        ) as client, client.stream(
            "POST",
            resolution.endpoint_url,
            headers=headers,
            json=body,
        ) as response:
            status = response.status_code
            try:
                credential_scanner.reject(dict(response.headers))
            except SecretCanaryDetected:
                raise StrictPreflightError(
                    "credential_echo_detected",
                    status_code=status,
                ) from None
            if not response.is_success:
                transient = status == 429 or status in {500, 502, 503, 504}
                if status in {401, 403}:
                    code = "authentication_failed"
                elif 300 <= status < 400:
                    code = "redirect_forbidden"
                elif status in {400, 404, 405, 422}:
                    code = "unsupported_protocol"
                else:
                    code = "upstream_unavailable" if transient else "request_failed"
                raise StrictPreflightError(
                    code,
                    status_code=status,
                    transient=transient,
                    retry_after_seconds=(
                        _retry_after_seconds(response) if transient else None
                    ),
                )
            encoded = bytearray()
            async for chunk in response.aiter_bytes():
                encoded.extend(chunk)
                if len(encoded) > 64 * 1024:
                    raise StrictPreflightError(
                        "response_too_large",
                        status_code=status,
                    )
            response_request_id = response.headers.get(
                "request-id"
            ) or response.headers.get("x-request-id")
    except (httpx.TimeoutException, httpcore.TimeoutException):
        raise StrictPreflightError("timeout", transient=True) from None
    except (httpx.HTTPError, httpcore.NetworkError, httpcore.ProtocolError):
        raise StrictPreflightError("network", transient=True) from None
    latency_ms = round((perf_counter() - started) * 1000, 3)
    try:
        payload = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise StrictPreflightError("non_json_response", status_code=status) from None
    if not isinstance(payload, dict):
        raise StrictPreflightError("malformed_response", status_code=status)
    try:
        credential_scanner.reject(payload)
    except SecretCanaryDetected:
        raise StrictPreflightError("credential_echo_detected", status_code=status) from None
    if resolution.protocol == "openai_chat":
        text, contaminated = _openai_text(payload)
    else:
        text, contaminated = _anthropic_text(payload)
    contaminated = contaminated or _positive_reasoning_usage(payload)
    if contaminated:
        raise StrictPreflightError("reasoning_contamination", status_code=status)
    if not text.strip():
        raise StrictPreflightError("missing_text", status_code=status)
    if len(text) > 4096:
        raise StrictPreflightError("response_too_large", status_code=status)
    try:
        credential_scanner.reject(text)
    except SecretCanaryDetected:
        raise StrictPreflightError("credential_echo_detected", status_code=status) from None
    result = {
        "statusCode": status,
        "latencyMs": latency_ms,
        "hasContent": True,
        "reportedModel": payload.get("model") if isinstance(payload.get("model"), str) else None,
        "requestId": response_request_id,
        "protocol": resolution.protocol,
        "endpointUrl": resolution.endpoint_url,
    }
    try:
        credential_scanner.reject(result)
    except SecretCanaryDetected:
        raise StrictPreflightError("credential_echo_detected", status_code=status) from None
    return result
