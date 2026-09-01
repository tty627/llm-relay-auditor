from __future__ import annotations

import pytest

from relay_auditor.network_safety import (
    UnsafeEndpointError,
    address_is_public,
    canonical_endpoint_url,
    revalidate_public_endpoint,
    validate_public_endpoint,
)


def test_ipv6_special_purpose_ranges_are_not_public() -> None:
    for address in (
        "100::1",
        "2001:10::1",
        "64:ff9b:1::c0a8:101",
        "5f00::1",
        "fec0::1",
        "::192.168.1.1",
    ):
        assert address_is_public(address) is False
    assert address_is_public("2606:4700:4700::1111") is True


def test_protocol_urls_are_canonical_and_exact() -> None:
    assert canonical_endpoint_url(
        "https://Relay.Example/v1/chat/completions/",
        "openai_chat",
    )[:3] == (
        "https://relay.example/v1",
        "https://relay.example/v1/chat/completions",
        "https://relay.example",
    )
    assert canonical_endpoint_url(
        "https://relay.example/gateway/v1/messages",
        "anthropic_messages",
    )[1] == "https://relay.example/gateway/v1/messages"
    assert canonical_endpoint_url(
        "https://relay.example",
        "anthropic_messages",
    )[1] == "https://relay.example/v1/messages"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://relay.example/v1",
        "https://user:secret@relay.example/v1",
        "https://relay.example/v1?key=secret",
        "https://relay.example/v1#fragment",
        "https://metadata.google.internal/v1",
    ],
)
def test_malformed_or_credential_bearing_urls_are_rejected(url: str) -> None:
    with pytest.raises(UnsafeEndpointError):
        canonical_endpoint_url(url, "openai_chat")


def test_cross_protocol_exact_path_is_rejected() -> None:
    with pytest.raises(UnsafeEndpointError, match="selected protocol"):
        canonical_endpoint_url("https://relay.example/v1/messages", "openai_chat")


async def test_public_dns_is_accepted_and_mixed_private_dns_is_rejected() -> None:
    async def public_resolver(hostname: str, port: int):
        assert hostname == "relay.example"
        assert port == 443
        return ["8.8.8.8", "1.1.1.1"]

    result = await validate_public_endpoint(
        "https://relay.example/v1",
        "openai_chat",
        resolver=public_resolver,
    )
    assert result.addresses == ("1.1.1.1", "8.8.8.8")

    async def mixed_resolver(_hostname: str, _port: int):
        return ["8.8.8.8", "10.0.0.8"]

    with pytest.raises(UnsafeEndpointError, match="non-public"):
        await validate_public_endpoint(
            "https://relay.example/v1",
            "openai_chat",
            resolver=mixed_resolver,
        )


async def test_literal_private_and_link_local_addresses_are_rejected() -> None:
    async def identity_resolver(hostname: str, _port: int):
        return [hostname]

    for url in (
        "https://127.0.0.1/v1",
        "https://10.0.0.1/v1",
        "https://169.254.169.254/v1",
        "https://[::1]/v1",
        "https://[fe80::1]/v1",
    ):
        with pytest.raises(UnsafeEndpointError):
            await validate_public_endpoint(url, "openai_chat", resolver=identity_resolver)


async def test_explicit_test_mode_allows_only_http_loopback() -> None:
    async def loopback_resolver(_hostname: str, _port: int):
        return ["127.0.0.1"]

    result = await validate_public_endpoint(
        "http://localhost:8123/v1",
        "openai_chat",
        resolver=loopback_resolver,
        allow_test_loopback=True,
    )
    assert result.endpoint_url == "http://localhost:8123/v1/chat/completions"


async def test_public_to_private_dns_rebinding_is_rejected() -> None:
    async def initial_resolver(_hostname: str, _port: int):
        return ["8.8.8.8"]

    pinned = await validate_public_endpoint(
        "https://relay.example/v1",
        "anthropic_messages",
        resolver=initial_resolver,
    )

    async def rebound_resolver(_hostname: str, _port: int):
        return ["192.168.1.9"]

    with pytest.raises(UnsafeEndpointError, match="non-public"):
        await revalidate_public_endpoint(pinned, resolver=rebound_resolver)
