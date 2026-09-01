from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import SplitResult, urlsplit, urlunsplit


class UnsafeEndpointError(ValueError):
    """An endpoint is malformed or could route credentials to a local network."""


Resolver = Callable[[str, int], Awaitable[Iterable[str]]]

_PROTOCOL_SUFFIXES = {
    "openai_chat": "/chat/completions",
    "anthropic_messages": "/messages",
}
_KNOWN_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.internal.",
}


@dataclass(frozen=True, slots=True)
class EndpointResolution:
    protocol: str
    base_url: str
    endpoint_url: str
    origin: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


def _canonical_host(parsed: SplitResult) -> tuple[str, int]:
    hostname = parsed.hostname
    if hostname is None:
        raise UnsafeEndpointError("endpoint URL has no hostname")
    hostname = hostname.encode("idna").decode("ascii").lower()
    try:
        port = parsed.port
    except ValueError as error:
        raise UnsafeEndpointError("endpoint URL has an invalid port") from error
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return hostname, port


def canonical_endpoint_url(raw_url: str, protocol: str) -> tuple[str, str, str, str, int]:
    """Return canonical base URL, exact endpoint URL, origin, host and port."""

    suffix = _PROTOCOL_SUFFIXES.get(protocol)
    if suffix is None:
        raise UnsafeEndpointError(f"unsupported endpoint protocol: {protocol}")
    parsed = urlsplit(raw_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UnsafeEndpointError("endpoint URL must be absolute HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeEndpointError("endpoint URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise UnsafeEndpointError("endpoint URL must not contain query parameters or fragments")
    hostname, port = _canonical_host(parsed)
    if hostname in _KNOWN_METADATA_HOSTS:
        raise UnsafeEndpointError("cloud metadata endpoints are forbidden")

    path = parsed.path.rstrip("/")
    other_suffixes = set(_PROTOCOL_SUFFIXES.values()) - {suffix}
    if any(path.endswith(other) for other in other_suffixes):
        raise UnsafeEndpointError("endpoint path does not match the selected protocol")
    base_path = path[: -len(suffix)] if path.endswith(suffix) else path
    if not base_path:
        base_path = "/v1"
    if not base_path.startswith("/"):
        base_path = "/" + base_path

    default_port = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = display_host if default_port else f"{display_host}:{port}"
    base_url = urlunsplit((parsed.scheme, authority, base_path, "", ""))
    endpoint_url = urlunsplit((parsed.scheme, authority, base_path + suffix, "", ""))
    origin = urlunsplit((parsed.scheme, authority, "", "", ""))
    return base_url, endpoint_url, origin, hostname, port


def _parse_address(value: str) -> IPv4Address | IPv6Address:
    try:
        return ip_address(value.split("%", 1)[0])
    except ValueError as error:
        raise UnsafeEndpointError("DNS resolver returned an invalid IP address") from error


def address_is_public(value: str) -> bool:
    address = _parse_address(value)
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not getattr(address, "is_site_local", False)
        and not address.is_unspecified
    )


async def system_resolver(hostname: str, port: int) -> tuple[str, ...]:
    def lookup() -> tuple[str, ...]:
        records = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return tuple(sorted({str(record[4][0]).split("%", 1)[0] for record in records}))

    try:
        async with asyncio.timeout(10):
            return await asyncio.to_thread(lookup)
    except TimeoutError:
        raise UnsafeEndpointError("endpoint hostname resolution timed out") from None
    except socket.gaierror as error:
        raise UnsafeEndpointError("endpoint hostname could not be resolved") from error


async def validate_public_endpoint(
    raw_url: str,
    protocol: str,
    *,
    resolver: Resolver = system_resolver,
    allow_test_loopback: bool = False,
) -> EndpointResolution:
    base_url, endpoint_url, origin, hostname, port = canonical_endpoint_url(raw_url, protocol)
    resolved = tuple(sorted(set(await resolver(hostname, port))))
    if not resolved:
        raise UnsafeEndpointError("endpoint hostname did not resolve to an address")
    parsed_addresses = tuple(_parse_address(value) for value in resolved)
    loopback_only = all(address.is_loopback for address in parsed_addresses)
    scheme = urlsplit(endpoint_url).scheme
    if scheme != "https" and not (
        allow_test_loopback and scheme == "http" and loopback_only
    ):
        raise UnsafeEndpointError("endpoint must use HTTPS")
    if not loopback_only or not allow_test_loopback:
        unsafe = [value for value in resolved if not address_is_public(value)]
        if unsafe:
            raise UnsafeEndpointError("endpoint DNS resolved to a non-public address")
    return EndpointResolution(
        protocol=protocol,
        base_url=base_url,
        endpoint_url=endpoint_url,
        origin=origin,
        hostname=hostname,
        port=port,
        addresses=resolved,
    )


async def revalidate_public_endpoint(
    pinned: EndpointResolution,
    *,
    resolver: Resolver = system_resolver,
    allow_test_loopback: bool = False,
) -> EndpointResolution:
    """Resolve again immediately before sending credentials.

    Public CDN address rotation is allowed. A public-to-private DNS rebind is not.
    Callers retain both address sets in volatile task state for audit diagnostics.
    """

    return await validate_public_endpoint(
        pinned.base_url,
        pinned.protocol,
        resolver=resolver,
        allow_test_loopback=allow_test_loopback,
    )
