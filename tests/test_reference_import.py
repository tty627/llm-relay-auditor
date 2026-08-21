import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from relay_auditor.database import Database
from relay_auditor.evidence import EvidenceStore
from relay_auditor.reference_import import import_reference_directory


def write_fingerprint(path: Path, *, model: str, collected_at: datetime, answer: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "formatVersion": 1,
        "protocol": "one-token/v1",
        "model": model,
        "collectedAt": collected_at.isoformat().replace("+00:00", "Z"),
        "samplesPerCell": 15,
        "postReasoning": False,
        "cells": {
            "random-number-1-100:en": {
                "cellId": "random-number-1-100:en",
                "counts": {answer: 15},
                "validCount": 15,
                "invalidCount": 0,
                "refusalCount": 0,
                "emptyCount": 0,
                "errorCount": 0,
                "totalCount": 15,
                "entropyBits": 0,
                "normalizedEntropy": 0,
                "medianLatencyMs": 1,
                "meanCompletionTokens": 1,
                "meanReasoningTokens": 0,
            }
        },
        "meta": {"tool": "llm-fingerprint-detector"},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_import_reference_directory_is_catalogued_and_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "source"
    collected_at = datetime.now(UTC) - timedelta(minutes=5)
    write_fingerprint(
        source / "key-a" / "model-a.fingerprint.json",
        model="model-a",
        collected_at=collected_at,
        answer="42",
    )
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    evidence = EvidenceStore(tmp_path / "evidence")

    first = import_reference_directory(
        source,
        database=database,
        evidence=evidence,
        base_url="https://relay.example/v1/",
        provider="relay_snapshot",
        reference_prefix="Relay snapshot",
        extra_metadata={"comparison_report": "references/report.md"},
    )
    second = import_reference_directory(
        source,
        database=database,
        evidence=evidence,
        base_url="https://relay.example/v1",
        provider="relay_snapshot",
        reference_prefix="Relay snapshot",
    )

    assert first[0].artifact_id == second[0].artifact_id
    assert evidence.fingerprint_path(first[0].artifact_id, must_exist=True).is_file()
    catalog = database.list_reference_catalog()
    assert len(catalog) == 1
    assert catalog[0]["endpoint"]["model"] == "model-a"
    assert catalog[0]["endpoint"]["api_key_env"] is None
    assert catalog[0]["baseline"]["metadata"]["ground_truth"] == ("relay_snapshot_not_official")
    assert catalog[0]["baseline"]["metadata"]["source_label"] == "key-a"
    assert catalog[0]["baseline"]["metadata"]["valid_samples"] == 15
    assert catalog[0]["baseline"]["metadata"]["quality_flags"] == []
    assert catalog[0]["collected_at"] == collected_at.isoformat()


def test_changed_snapshot_supersedes_prior_baseline(tmp_path: Path) -> None:
    source = tmp_path / "source"
    path = source / "key-a" / "model-a.fingerprint.json"
    collected_at = datetime.now(UTC) - timedelta(minutes=5)
    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    evidence = EvidenceStore(tmp_path / "evidence")
    kwargs = {
        "database": database,
        "evidence": evidence,
        "base_url": "https://relay.example/v1",
        "provider": "relay_snapshot",
        "reference_prefix": "Relay snapshot",
    }

    write_fingerprint(path, model="model-a", collected_at=collected_at, answer="42")
    first = import_reference_directory(source, **kwargs)
    write_fingerprint(
        path,
        model="model-a",
        collected_at=collected_at + timedelta(minutes=1),
        answer="57",
    )
    second = import_reference_directory(source, **kwargs)

    assert first[0].artifact_id != second[0].artifact_id
    active = database.list_reference_catalog()
    all_items = database.list_reference_catalog(active_only=False)
    assert len(active) == 1
    assert len(all_items) == 2
    statuses = {item["baseline"]["artifact_id"]: item["baseline"]["status"] for item in all_items}
    assert statuses[first[0].artifact_id] == "superseded"
    assert statuses[second[0].artifact_id] == "active"


def test_import_rejects_filename_model_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    write_fingerprint(
        source / "key-a" / "wrong-name.fingerprint.json",
        model="model-a",
        collected_at=datetime.now(UTC),
        answer="42",
    )

    database = Database(f"sqlite:///{tmp_path / 'auditor.db'}")
    evidence = EvidenceStore(tmp_path / "evidence")
    try:
        import_reference_directory(
            source,
            database=database,
            evidence=evidence,
            base_url="https://relay.example/v1",
            provider="relay_snapshot",
            reference_prefix="Relay snapshot",
        )
    except ValueError as error:
        assert "filename/model mismatch" in str(error)
    else:
        raise AssertionError("expected filename/model mismatch to be rejected")
