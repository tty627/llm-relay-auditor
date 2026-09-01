from __future__ import annotations

import ssl
from collections.abc import AsyncIterator, Iterable
from ipaddress import ip_address
from typing import Any

import httpcore
import httpx

from relay_auditor.network_safety import EndpointResolution


def _plain_address(value: str) -> str:
    return str(ip_address(value.split("%", 1)[0]))


class PinnedNetworkStream(httpcore.AsyncNetworkStream):
    """A network stream whose remote peer must remain in the validated set."""

    def __init__(
        self,
        stream: httpcore.AsyncNetworkStream,
        allowed_addresses: frozenset[str],
    ) -> None:
        self._stream = stream
        self._allowed_addresses = allowed_addresses
        self._validate_peer()

    def _validate_peer(self) -> None:
        remote = self._stream.get_extra_info("server_addr")
        candidate = remote[0] if isinstance(remote, tuple) and remote else remote
        if not isinstance(candidate, str):
            raise httpcore.ConnectError("pinned endpoint peer address is unavailable")
        try:
            normalized = _plain_address(candidate)
        except ValueError as error:
            raise httpcore.ConnectError("pinned endpoint peer address is invalid") from error
        if normalized not in self._allowed_addresses:
            raise httpcore.ConnectError("pinned endpoint peer address changed")

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._stream.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        secured = await self._stream.start_tls(
            ssl_context,
            server_hostname=server_hostname,
            timeout=timeout,
        )
        try:
            return PinnedNetworkStream(secured, self._allowed_addresses)
        except httpcore.ConnectError:
            await secured.aclose()
            raise

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to IPs from one validated EndpointResolution.

    HTTP and TLS continue to see the original hostname, so Host, SNI and
    certificate verification retain their normal semantics. Only the TCP
    destination is substituted with a validated literal address.
    """

    def __init__(
        self,
        resolution: EndpointResolution,
        *,
        backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._hostname = resolution.hostname.rstrip(".").casefold()
        self._port = resolution.port
        self._addresses = tuple(_plain_address(value) for value in resolution.addresses)
        self._allowed = frozenset(self._addresses)
        if not self._addresses:
            raise ValueError("pinned endpoint requires at least one validated address")
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.rstrip(".").casefold() != self._hostname or port != self._port:
            raise httpcore.ConnectError("pinned transport rejected an unexpected origin")
        for address in self._addresses:
            try:
                stream = await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                try:
                    return PinnedNetworkStream(stream, self._allowed)
                except httpcore.ConnectError:
                    await stream.aclose()
                    continue
            except (httpcore.ConnectError, httpcore.ConnectTimeout):
                continue
        raise httpcore.ConnectError("pinned endpoint connection failed")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise httpcore.ConnectError("pinned transport forbids Unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _CoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterator[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close is not None:
            await close()


class PinnedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """Minimal httpx/httpcore bridge using the pinned connection backend."""

    def __init__(self, resolution: EndpointResolution) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpcore.default_ssl_context(),
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(resolution),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise TypeError("pinned transport requires an async request stream")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        core_response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_CoreResponseStream(core_response.stream),
            extensions=core_response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
