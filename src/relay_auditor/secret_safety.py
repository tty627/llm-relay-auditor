from pathlib import Path
from typing import Any


def contains_secret(value: Any, secret: str | None) -> bool:
    """Return whether a structured value contains the exact credential."""

    if not secret:
        return False
    if isinstance(value, str):
        return secret in value
    if isinstance(value, bytes):
        return secret.encode() in value
    if isinstance(value, dict):
        return any(
            contains_secret(key, secret) or contains_secret(item, secret)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_secret(item, secret) for item in value)
    return False


def reject_secret_echo(value: Any, secret: str | None, *, source: str) -> None:
    if contains_secret(value, secret):
        raise RuntimeError(f"{source} echoed the API credential; output was rejected")


def reject_secret_artifact(
    value: Any,
    secret: str | None,
    *,
    paths: tuple[Path, ...],
    source: str,
) -> None:
    if not secret:
        return
    leaked = contains_secret(value, secret)
    encoded = secret.encode()
    for path in paths:
        if path.is_file() and encoded in path.read_bytes():
            leaked = True
    if not leaked:
        return
    for path in paths:
        path.unlink(missing_ok=True)
    raise RuntimeError(f"{source} echoed the API credential; output was rejected")
