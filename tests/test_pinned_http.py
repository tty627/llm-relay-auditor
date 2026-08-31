from __future__ import annotations

import ssl

import httpcore
import pytest

from relay_auditor.network_safety import EndpointResolution
from relay_auditor.pinned_http import PinnedNetworkBackend


def _resolution() -> EndpointResolution:
    return EndpointResolution(
        protocol="openai_chat",
        base_url="https://relay.example/v1",
        endpoint_url="https://relay.example/v1/chat/completions",
        origin="https://relay.example",
        hostname="relay.example",
        port=443,
        addresses=("8.8.8.8", "2001:4860:4860::8888"),
    )


class _Stream(httpcore.AsyncNetworkStream):
    def __init__(self, peer: str) -> None:
        self.peer = peer
        self.server_hostname: str | None = None
        self.closed = False

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        return b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del buffer, timeout

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, timeout
        self.server_hostname = server_hostname
        return self

    def get_extra_info(self, info: str):
        if info == "server_addr":
            return (self.peer, 443)
        return None


class _Backend(httpcore.AsyncNetworkBackend):
    def __init__(self, peer: str = "8.8.8.8") -> None:
        self.peer = peer
        self.hosts: list[str] = []
        self.streams: list[_Stream] = []

    async def connect_tcp(self, host: str, port: int, **_kwargs):
        assert port == 443
        self.hosts.append(host)
        stream = _Stream(self.peer)
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(self, path: str, **_kwargs):
        raise AssertionError(path)

    async def sleep(self, seconds: float) -> None:
        del seconds


async def test_pinned_backend_connects_literal_ip_but_preserves_tls_hostname() -> None:
    delegate = _Backend()
    backend = PinnedNetworkBackend(_resolution(), backend=delegate)
    stream = await backend.connect_tcp("relay.example", 443)
    secured = await stream.start_tls(ssl.create_default_context(), "relay.example")

    assert delegate.hosts == ["8.8.8.8"]
    assert delegate.streams[0].server_hostname == "relay.example"
    assert secured.get_extra_info("server_addr") == ("8.8.8.8", 443)


async def test_pinned_backend_rejects_unexpected_origin_before_connect() -> None:
    delegate = _Backend()
    backend = PinnedNetworkBackend(_resolution(), backend=delegate)
    with pytest.raises(httpcore.ConnectError, match="unexpected origin"):
        await backend.connect_tcp("metadata.google.internal", 443)
    assert delegate.hosts == []


async def test_pinned_backend_rejects_remote_peer_outside_validated_set() -> None:
    delegate = _Backend(peer="127.0.0.1")
    backend = PinnedNetworkBackend(_resolution(), backend=delegate)
    with pytest.raises(httpcore.ConnectError, match="connection failed"):
        await backend.connect_tcp("relay.example", 443)
