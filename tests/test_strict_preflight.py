from __future__ import annotations

import asyncio

import httpx
import pytest

from relay_auditor.execution_utils import ExecutionInterrupted, strict_preflight_with_retry
from relay_auditor.network_safety import EndpointResolution
from relay_auditor.strict_preflight import StrictPreflightError, run_strict_preflight


def resolution(protocol: str) -> EndpointResolution:
    suffix = "chat/completions" if protocol == "openai_chat" else "messages"
    return EndpointResolution(
        protocol=protocol,
        base_url="https://relay.example/v1",
        endpoint_url=f"https://relay.example/v1/{suffix}",
        origin="https://relay.example",
        hostname="relay.example",
        port=443,
        addresses=("8.8.8.8",),
    )


async def test_openai_preflight_sends_one_strict_body_without_fallback() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "headers": dict(request.headers),
                "json": __import__("json").loads(request.content),
            }
        )
        return httpx.Response(
            200,
            json={
                "model": "opus-alias",
                "choices": [{"message": {"role": "assistant", "content": "42"}}],
                "usage": {
                    "completion_tokens": 1,
                    "completion_tokens_details": {"reasoning_tokens": 0},
                },
            },
        )

    result = await run_strict_preflight(
        resolution("openai_chat"),
        model="opus-alias",
        api_key="sk-openai-canary",
        transport=httpx.MockTransport(handler),
    )
    assert result["reportedModel"] == "opus-alias"
    assert len(seen) == 1
    body = seen[0]["json"]
    assert body == {
        "model": "opus-alias",
        "messages": [
            {
                "role": "system",
                "content": "Answer with exactly one word or number. No punctuation or explanation.",
            },
            {"role": "user", "content": "Name a random number between 1 and 100."},
        ],
        "temperature": 1,
        "max_tokens": 16,
        "reasoning": {"enabled": False},
        "usage": {"include": True},
    }
    assert seen[0]["headers"]["authorization"] == "Bearer sk-openai-canary"


async def test_anthropic_preflight_sends_opus5_thinking_disabled_profile() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["json"] = __import__("json").loads(request.content)
        return httpx.Response(
            200,
            headers={"request-id": "req-safe"},
            json={
                "model": "claude-opus-5",
                "content": [{"type": "text", "text": "blue"}],
                "usage": {"input_tokens": 20, "output_tokens": 1},
            },
        )

    result = await run_strict_preflight(
        resolution("anthropic_messages"),
        model="claude-opus-5",
        api_key="sk-ant-canary",
        workspace_id="wrkspc_123",
        transport=httpx.MockTransport(handler),
    )
    assert result["requestId"] == "req-safe"
    assert captured["headers"]["x-api-key"] == "sk-ant-canary"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert captured["headers"]["anthropic-workspace-id"] == "wrkspc_123"
    assert captured["json"] == {
        "model": "claude-opus-5",
        "system": "Answer with exactly one word or number. No punctuation or explanation.",
        "messages": [{"role": "user", "content": "Name a random number between 1 and 100."}],
        "temperature": 1,
        "max_tokens": 16,
        "thinking": {"type": "disabled"},
        "output_config": {"effort": "high"},
    }


@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_redirects_are_never_followed(status: int) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, headers={"location": "https://evil.example/steal"})

    with pytest.raises(StrictPreflightError, match="redirect_forbidden"):
        await run_strict_preflight(
            resolution("anthropic_messages"),
            model="claude-opus-5",
            api_key="sk-ant-canary",
            transport=httpx.MockTransport(handler),
        )
    assert calls == 1


@pytest.mark.parametrize("status,transient", [(401, False), (403, False), (429, True), (503, True)])
async def test_failures_are_typed_without_response_body(
    status: int,
    transient: bool,
) -> None:
    secret = "sk-body-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"retry-after": "600"},
            json={"error": {"message": f"upstream echoed {secret}"}},
        )

    with pytest.raises(StrictPreflightError) as caught:
        await run_strict_preflight(
            resolution("openai_chat"),
            model="opus",
            api_key=secret,
            transport=httpx.MockTransport(handler),
        )
    assert caught.value.transient is transient
    assert secret not in str(caught.value)
    if transient:
        assert caught.value.retry_after_seconds == 60


@pytest.mark.parametrize(
    "content",
    [
        [{"type": "thinking", "thinking": "secret reasoning"}, {"type": "text", "text": "42"}],
        [{"type": "text", "text": "<thinking>secret reasoning</thinking>42"}],
        [{"type": "tool_use", "id": "toolu_1", "name": "answer", "input": {}}],
    ],
)
async def test_anthropic_reasoning_or_tool_contamination_is_rejected(content) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "claude-opus-5", "content": content})

    with pytest.raises(StrictPreflightError, match="reasoning_contamination"):
        await run_strict_preflight(
            resolution("anthropic_messages"),
            model="claude-opus-5",
            api_key="sk-ant",
            transport=httpx.MockTransport(handler),
        )


async def test_successful_completion_echoing_credential_is_rejected_without_echoing_it() -> None:
    secret = "sk-preflight-echo-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"model": "opus", "choices": [{"message": {"content": secret}}]},
        )

    with pytest.raises(StrictPreflightError) as caught:
        await run_strict_preflight(
            resolution("openai_chat"),
            model="opus",
            api_key=secret,
            transport=httpx.MockTransport(handler),
        )
    assert caught.value.code == "credential_echo_detected"
    assert secret not in str(caught.value)


async def test_openai_tool_finish_reason_is_reasoning_contamination() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {"role": "assistant", "content": "42"},
                    }
                ]
            },
        )

    with pytest.raises(StrictPreflightError, match="reasoning_contamination"):
        await run_strict_preflight(
            resolution("openai_chat"),
            model="opus",
            api_key="sk-safe-canary",
            transport=httpx.MockTransport(handler),
        )


@pytest.mark.parametrize(
    "location,echoed",
    [
        ("body", "SK-PREFLIGHT ECHO CANARY"),
        ("header", "skpreflightechocanary"),
    ],
    ids=("body-variant", "header-variant"),
)
async def test_credential_variants_in_any_response_channel_are_rejected(
    location: str,
    echoed: str,
) -> None:
    secret = "sk-Preflight-Echo-Canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        headers = {"x-debug": echoed} if location == "header" else {}
        payload = {
            "debug": echoed if location == "body" else "safe",
            "choices": [{"message": {"role": "assistant", "content": "42"}}],
        }
        return httpx.Response(200, headers=headers, json=payload)

    with pytest.raises(StrictPreflightError) as caught:
        await run_strict_preflight(
            resolution("openai_chat"),
            model="opus",
            api_key=secret,
            transport=httpx.MockTransport(handler),
        )
    assert caught.value.code == "credential_echo_detected"
    assert echoed not in str(caught.value)


async def test_malformed_retry_after_never_escapes_as_raw_header_error() -> None:
    secret = "sk-retry-after-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "not-a-number"})

    with pytest.raises(StrictPreflightError) as caught:
        await run_strict_preflight(
            resolution("openai_chat"),
            model="opus",
            api_key=secret,
            transport=httpx.MockTransport(handler),
        )
    assert caught.value.code == "upstream_unavailable"
    assert caught.value.retry_after_seconds is None


async def test_preflight_retry_progress_distinguishes_reserved_and_sent_retry() -> None:
    calls = 0
    progress: list[dict[str, int]] = []

    async def runner(*_args, **_kwargs) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise StrictPreflightError(
                "upstream_unavailable",
                transient=True,
                retry_after_seconds=0,
            )
        return {"statusCode": 200}

    result, attempts, retries = await strict_preflight_with_retry(
        resolution("openai_chat"),
        model="opus",
        api_key="sk-progress-canary",
        timeout_seconds=3,
        workspace_id=None,
        interrupt_event=asyncio.Event(),
        retry_budget=2,
        runner=runner,
        jitter=lambda: 0,
        progress_callback=progress.append,
    )

    assert result == {"statusCode": 200}
    assert (attempts, retries) == (2, 1)
    assert progress == [
        {"attempt_count": 1, "retry_count": 0, "retry_budget_used": 0},
        {"attempt_count": 1, "retry_count": 0, "retry_budget_used": 1},
        {"attempt_count": 2, "retry_count": 1, "retry_budget_used": 1},
    ]


async def test_preflight_pause_in_request_exposes_started_attempt_first() -> None:
    interrupt = asyncio.Event()
    request_started = asyncio.Event()
    never_complete = asyncio.Event()
    progress: list[dict[str, int]] = []

    async def runner(*_args, **_kwargs) -> dict[str, object]:
        request_started.set()
        await never_complete.wait()
        return {"statusCode": 200}

    task = asyncio.create_task(
        strict_preflight_with_retry(
            resolution("openai_chat"),
            model="opus",
            api_key="sk-progress-canary",
            timeout_seconds=3,
            workspace_id=None,
            interrupt_event=interrupt,
            retry_budget=2,
            runner=runner,
            progress_callback=progress.append,
        )
    )
    await asyncio.wait_for(request_started.wait(), timeout=1)
    interrupt.set()

    with pytest.raises(ExecutionInterrupted, match="control_interrupt"):
        await task

    assert progress == [
        {"attempt_count": 1, "retry_count": 0, "retry_budget_used": 0}
    ]


async def test_preflight_pause_in_cooldown_exposes_reserved_budget_first() -> None:
    interrupt = asyncio.Event()
    retry_reserved = asyncio.Event()
    progress: list[dict[str, int]] = []
    calls = 0

    async def runner(*_args, **_kwargs) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise StrictPreflightError(
            "upstream_unavailable",
            transient=True,
            retry_after_seconds=60,
        )

    def observe(event: dict[str, int]) -> None:
        progress.append(event)
        if event["retry_budget_used"] == 1:
            retry_reserved.set()

    task = asyncio.create_task(
        strict_preflight_with_retry(
            resolution("openai_chat"),
            model="opus",
            api_key="sk-progress-canary",
            timeout_seconds=3,
            workspace_id=None,
            interrupt_event=interrupt,
            retry_budget=2,
            runner=runner,
            jitter=lambda: 0,
            progress_callback=observe,
        )
    )
    await asyncio.wait_for(retry_reserved.wait(), timeout=1)
    interrupt.set()

    with pytest.raises(ExecutionInterrupted, match="control_interrupt"):
        await task

    assert calls == 1
    assert progress == [
        {"attempt_count": 1, "retry_count": 0, "retry_budget_used": 0},
        {"attempt_count": 1, "retry_count": 0, "retry_budget_used": 1},
    ]


async def test_preflight_terminal_error_keeps_legacy_attempt_attributes() -> None:
    progress: list[dict[str, int]] = []

    async def runner(*_args, **_kwargs) -> dict[str, object]:
        raise StrictPreflightError("authentication_failed", transient=False)

    with pytest.raises(StrictPreflightError) as caught:
        await strict_preflight_with_retry(
            resolution("openai_chat"),
            model="opus",
            api_key="sk-progress-canary",
            timeout_seconds=3,
            workspace_id=None,
            interrupt_event=asyncio.Event(),
            retry_budget=2,
            runner=runner,
            progress_callback=progress.append,
        )

    assert caught.value.attempts == 1
    assert caught.value.retries == 0
    assert progress == [
        {"attempt_count": 1, "retry_count": 0, "retry_budget_used": 0}
    ]
