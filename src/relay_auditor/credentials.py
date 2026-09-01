from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Literal
from uuid import uuid4

CredentialScope = Literal["reference", "target"]
CredentialSource = Literal["ephemeral", "env_ref"]


@dataclass(frozen=True, slots=True)
class CredentialBinding:
    reference: str
    scope: CredentialScope
    row_id: str
    canonical_base_url: str
    model: str
    protocol: str
    source: CredentialSource
    secret: str = field(repr=False)


class CredentialBindingError(ValueError):
    """A runtime credential was requested outside its immutable binding."""


class RuntimeCredentialStore:
    """Process-local credential handles with fail-closed endpoint binding.

    Handles, environment variable names and secrets are deliberately absent from
    persisted records and reports. A service restart destroys the complete store.
    """

    def __init__(self) -> None:
        self._bindings: dict[str, CredentialBinding] = {}

    def register(
        self,
        *,
        scope: CredentialScope,
        row_id: str,
        canonical_base_url: str,
        model: str,
        protocol: str,
        source: CredentialSource,
        secret: str,
    ) -> str:
        normalized_secret = secret.strip()
        if not normalized_secret:
            raise CredentialBindingError("credential must not be empty")
        if not row_id or not canonical_base_url or not model or not protocol:
            raise CredentialBindingError("credential binding fields must not be empty")
        reference = uuid4().hex
        self._bindings[reference] = CredentialBinding(
            reference=reference,
            scope=scope,
            row_id=row_id,
            canonical_base_url=canonical_base_url,
            model=model,
            protocol=protocol,
            source=source,
            secret=normalized_secret,
        )
        return reference

    @staticmethod
    def _equal(left: str, right: str) -> bool:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))

    def resolve(
        self,
        reference: str,
        *,
        scope: CredentialScope,
        row_id: str,
        canonical_base_url: str,
        model: str,
        protocol: str,
    ) -> str:
        binding = self._bindings.get(reference)
        if binding is None:
            raise CredentialBindingError("credential is unavailable after restart or cleanup")
        expected = (scope, row_id, canonical_base_url, model, protocol)
        actual = (
            binding.scope,
            binding.row_id,
            binding.canonical_base_url,
            binding.model,
            binding.protocol,
        )
        if not all(self._equal(left, right) for left, right in zip(actual, expected, strict=True)):
            raise CredentialBindingError("credential binding does not match this task")
        return binding.secret

    def source(self, reference: str) -> CredentialSource:
        binding = self._bindings.get(reference)
        if binding is None:
            raise CredentialBindingError("credential is unavailable after restart or cleanup")
        return binding.source

    def discard(self, reference: str) -> None:
        self._bindings.pop(reference, None)

    def discard_scope(self, scope: CredentialScope, row_ids: set[str] | None = None) -> None:
        doomed = [
            reference
            for reference, binding in self._bindings.items()
            if binding.scope == scope and (row_ids is None or binding.row_id in row_ids)
        ]
        for reference in doomed:
            del self._bindings[reference]

    def clear(self) -> None:
        self._bindings.clear()

    def __len__(self) -> int:
        return len(self._bindings)
