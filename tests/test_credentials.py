from __future__ import annotations

import pytest

from relay_auditor.credentials import CredentialBindingError, RuntimeCredentialStore


def test_credentials_are_isolated_by_scope_row_url_model_and_protocol() -> None:
    store = RuntimeCredentialStore()
    reference = store.register(
        scope="reference",
        row_id="reference-set-1",
        canonical_base_url="https://official.example/v1",
        model="claude-opus-5",
        protocol="anthropic_messages",
        source="ephemeral",
        secret="sk-reference-secret",
    )
    target = store.register(
        scope="target",
        row_id="row-a",
        canonical_base_url="https://relay.example/v1",
        model="opus-5-alias",
        protocol="anthropic_messages",
        source="env_ref",
        secret="sk-target-secret",
    )

    assert store.resolve(
        target,
        scope="target",
        row_id="row-a",
        canonical_base_url="https://relay.example/v1",
        model="opus-5-alias",
        protocol="anthropic_messages",
    ) == "sk-target-secret"
    with pytest.raises(CredentialBindingError, match="does not match"):
        store.resolve(
            reference,
            scope="target",
            row_id="row-a",
            canonical_base_url="https://relay.example/v1",
            model="opus-5-alias",
            protocol="anthropic_messages",
        )
    with pytest.raises(CredentialBindingError, match="does not match"):
        store.resolve(
            target,
            scope="target",
            row_id="row-a",
            canonical_base_url="https://evil.example/v1",
            model="opus-5-alias",
            protocol="anthropic_messages",
        )


def test_repr_and_public_metadata_never_contain_secret_or_env_name() -> None:
    store = RuntimeCredentialStore()
    reference = store.register(
        scope="target",
        row_id="row-a",
        canonical_base_url="https://relay.example/v1",
        model="model-a",
        protocol="openai_chat",
        source="env_ref",
        secret="sk-canary-do-not-print",
    )
    assert "sk-canary-do-not-print" not in repr(store._bindings[reference])
    assert store.source(reference) == "env_ref"


def test_cleanup_makes_credentials_unresolvable() -> None:
    store = RuntimeCredentialStore()
    reference = store.register(
        scope="target",
        row_id="row-a",
        canonical_base_url="https://relay.example/v1",
        model="model-a",
        protocol="openai_chat",
        source="ephemeral",
        secret="sk-secret",
    )
    store.discard_scope("target", {"row-a"})
    assert len(store) == 0
    with pytest.raises(CredentialBindingError, match="unavailable"):
        store.resolve(
            reference,
            scope="target",
            row_id="row-a",
            canonical_base_url="https://relay.example/v1",
            model="model-a",
            protocol="openai_chat",
        )


def test_empty_credentials_are_rejected() -> None:
    store = RuntimeCredentialStore()
    with pytest.raises(CredentialBindingError, match="must not be empty"):
        store.register(
            scope="target",
            row_id="row-a",
            canonical_base_url="https://relay.example/v1",
            model="model-a",
            protocol="openai_chat",
            source="ephemeral",
            secret="   ",
        )
