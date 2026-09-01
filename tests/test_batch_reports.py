import csv
import hashlib
import io
import json
import unicodedata
from copy import deepcopy
from pathlib import Path

import pytest

from relay_auditor.batch_reports import (
    CSV_COLUMNS,
    REPORT_SCHEMA_VERSION,
    BatchReportIntegrityError,
    BatchReportValidationError,
    SecretCanaryDetected,
    SecretCanaryScanner,
    build_terminal_batch_report,
    canonical_report_bytes,
    csv_bytes_from_verified_report,
    empty_secret_scanner_for_tests,
    load_verified_batch_report,
    reject_secret_canaries,
    validate_batch_report,
    write_terminal_batch_report,
    write_verified_batch_csv,
)


def _digest(character: str) -> str:
    return character * 64


def _reference_set(**overrides: object) -> dict[str, object]:
    members = [
        {
            "member_id": f"member-{ordinal}",
            "ordinal": ordinal,
            "seed_id": f"frozen-seed-{ordinal}",
            "artifact_id": f"reference-artifact-{ordinal}",
            "artifact_sha256": _digest(str(ordinal)),
            "raw_evidence_sha256": _digest(chr(96 + ordinal)),
            "created_at": f"2026-08-31T0{ordinal}:00:00+00:00",
            "quality": {
                "valid_samples": 1200,
                "invalid_samples": 0,
                "error_samples": 0,
                "coverage_cells": 40,
                "total_cells": 40,
                "directness": "verified",
                "split_half_mean_jsd": 0.01 * ordinal,
            },
        }
        for ordinal in range(1, 4)
    ]
    payload: dict[str, object] = {
        "reference_set_id": "reference-set-1",
        "name": "Official Opus 5 snapshot",
        "source_type": "official_api",
        "protocol": "anthropic_messages",
        "transport_profile": "anthropic-messages-opus5-onetoken-v1",
        "logical_model": "opus-5",
        "model_id": "claude-opus-5",
        "base_url": "https://api.anthropic.com/v1/",
        "battery_sha256": _digest("f"),
        "samples_per_cell": 30,
        "created_at": "2026-08-31T00:00:00+00:00",
        "members": members,
        "pairwise_distances": [
            {
                "left_member_id": "member-1",
                "right_member_id": "member-2",
                "mean_jsd": 0.01,
                "ci_lower": 0.008,
                "ci_upper": 0.012,
            },
            {
                "left_member_id": "member-1",
                "right_member_id": "member-3",
                "mean_jsd": 0.02,
                "ci_lower": 0.017,
                "ci_upper": 0.023,
            },
            {
                "left_member_id": "member-2",
                "right_member_id": "member-3",
                "mean_jsd": 0.015,
                "ci_lower": 0.012,
                "ci_upper": 0.019,
            },
        ],
        "envelope": {"max_upper_jsd": 0.023},
    }
    payload.update(overrides)
    return payload


def _batch(status: str = "completed") -> dict[str, object]:
    return {
        "batch_id": "batch-1",
        "status": status,
        "protocol": "anthropic_messages",
        "transport_profile": "anthropic-messages-opus5-onetoken-v1",
        "logical_model": "opus-5",
        "default_model_id": "claude-opus-5",
        "created_at": "2026-08-31T10:00:00+00:00",
        "completed_at": "2026-08-31T11:00:00+00:00",
    }


def _rows() -> list[dict[str, object]]:
    return [
        {
            "row_id": "row-1",
            "station_name": "Relay Alpha",
            "base_url": "https://alpha.example/v1/",
            "model_id": "opus-5-alpha",
        },
        {
            "row_id": "row-2",
            "station_name": "Relay Beta",
            "base_url": "https://beta.example/v1",
            "model_id": "opus-5-beta",
        },
    ]


def _member_distances() -> list[dict[str, object]]:
    return [
        {
            "member_id": "member-1",
            "mean_jsd": 0.01,
            "ci_lower": 0.008,
            "ci_upper": 0.012,
        },
        {
            "member_id": "member-2",
            "mean_jsd": 0.015,
            "ci_lower": 0.012,
            "ci_upper": 0.019,
        },
        {
            "member_id": "member-3",
            "mean_jsd": 0.02,
            "ci_lower": 0.017,
            "ci_upper": 0.023,
        },
    ]


def _completed_result(row_id: str = "row-1", **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "row_id": row_id,
        "status": "completed",
        "reported_model": "claude-opus-5-202608",
        "exploratory_status": "exploratory_reference_like",
        "reason_codes": ["within_reference_envelope"],
        "preflight": {
            "status": "passed",
            "http_status": 200,
            "attempts": 1,
            "latency_ms": 83.2,
        },
        "metrics": {
            "valid_samples": 1200,
            "invalid_samples": 0,
            "error_samples": 0,
            "coverage_cells": 40,
            "total_cells": 40,
            "directness": "verified",
            "split_half_mean_jsd": 0.018,
        },
        "distances": {
            "members": _member_distances(),
            "median_mean_jsd": 0.015,
            "mad_mean_jsd": 0.005,
            "min_mean_jsd": 0.01,
            "max_mean_jsd": 0.02,
        },
        "latency": {"p50_ms": 712.5, "p95_ms": 1220.0},
        "requests": {"logical_samples": 1200, "attempts": 1208, "retries": 7},
        "evidence": {
            "artifact_id": f"target-artifact-{row_id}",
            "artifact_sha256": _digest("d"),
            "raw_evidence_sha256": _digest("e"),
        },
    }
    payload.update(overrides)
    return payload


def _failed_result(row_id: str = "row-2") -> dict[str, object]:
    return {
        "row_id": row_id,
        "status": "failed",
        "exploratory_status": "request_failed",
        "reason_codes": ["authentication_failed"],
        "preflight": {
            "status": "failed",
            "http_status": 401,
            "attempts": 1,
            "latency_ms": 42,
            "reason_code": "authentication_failed",
        },
        "error": {
            "code": "authentication_failed",
            "http_status": 401,
        },
        "requests": {"logical_samples": 0, "attempts": 1, "retries": 0},
    }


def _build(
    *,
    batch_status: str = "completed",
    rows: list[dict[str, object]] | None = None,
    results: list[dict[str, object]] | None = None,
    scanner: SecretCanaryScanner | None = None,
) -> dict[str, object]:
    return build_terminal_batch_report(
        batch=_batch(batch_status),
        reference_set=_reference_set(),
        input_rows=rows or _rows(),
        target_results=results or [_completed_result(), _failed_result()],
        tool={"name": "relay-model-auditor", "version": "0.2.0", "git_sha": "1683796"},
        generated_at="2026-08-31T11:00:01+00:00",
        secret_scanner=scanner or empty_secret_scanner_for_tests(),
    )


def test_builder_whitelists_secrets_and_forces_nondecision_semantics() -> None:
    secret = "sk-report-canary-Exact-123"
    env_name = "PRIVATE_RELAY_KEY"
    rows = _rows()
    rows[0].update(
        {
            "api_key": secret,
            "key_env": env_name,
            "credential_ref": "credential-handle-1",
            "credential_hash": _digest("9"),
        }
    )
    reference = _reference_set(
        api_key=secret,
        key_env=env_name,
        credential_ref="reference-credential-handle",
    )
    completed = _completed_result(
        operational_verdict="match",
        decision_eligible=True,
        raw_error_body=f"provider echoed {secret}",
        error={"body": f"bearer {secret}", "message": secret},
    )

    report = build_terminal_batch_report(
        batch=_batch(),
        reference_set=reference,
        input_rows=rows,
        target_results=[completed, _failed_result()],
        tool={"name": "relay-model-auditor", "version": "0.2.0", "git_sha": "1683796"},
        generated_at="2026-08-31T11:00:01+00:00",
        secret_scanner=SecretCanaryScanner([secret]),
    )
    encoded = canonical_report_bytes(report)

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["batch"]["decision_eligible"] is False
    assert report["batch"]["operational_verdict"] == "unverifiable"
    assert all(target["decision_eligible"] is False for target in report["targets"])
    assert all(target["operational_verdict"] == "unverifiable" for target in report["targets"])
    assert secret.encode() not in encoded
    assert env_name.encode() not in encoded
    assert b"credential-handle" not in encoded
    assert b"raw_error_body" not in encoded
    assert b"error body" not in encoded


def test_interrupted_report_terminalizes_every_input_row_in_input_order() -> None:
    rows = _rows() + [
        {
            "row_id": "row-3",
            "station_name": "Relay Gamma",
            "base_url": "https://gamma.example/v1",
            "model_id": "opus-5-gamma",
        }
    ]
    report = _build(
        batch_status="interrupted",
        rows=rows,
        results=[
            _completed_result(),
            {"row_id": "row-2", "status": "running"},
        ],
    )

    assert [target["row_id"] for target in report["targets"]] == ["row-1", "row-2", "row-3"]
    assert [target["status"] for target in report["targets"]] == [
        "completed",
        "interrupted",
        "interrupted",
    ]
    assert report["targets"][1]["reason_codes"] == [
        "batch_interrupted_before_target_terminal"
    ]
    assert report["targets"][2]["reason_codes"] == [
        "batch_interrupted_before_target_terminal"
    ]


def test_completed_batch_refuses_missing_or_nonterminal_rows() -> None:
    with pytest.raises(BatchReportValidationError, match="missing terminal result"):
        _build(results=[_completed_result()])
    with pytest.raises(BatchReportValidationError, match="non-terminal row"):
        _build(results=[_completed_result(), {"row_id": "row-2", "status": "running"}])


def test_atomic_canonical_json_is_hashed_and_verified(tmp_path: Path) -> None:
    report = _build()
    report_path = tmp_path / "batch-1.report.json"
    scanner = empty_secret_scanner_for_tests()
    artifact = write_terminal_batch_report(report_path, report, secret_scanner=scanner)

    assert artifact.path == report_path
    assert artifact.sha256 == hashlib.sha256(report_path.read_bytes()).hexdigest()
    assert artifact.size_bytes == len(report_path.read_bytes())
    assert report_path.read_bytes() == canonical_report_bytes(report)
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []

    verified = load_verified_batch_report(
        report_path, artifact.sha256, secret_scanner=scanner
    )
    assert verified.payload == report
    assert verified.sha256 == artifact.sha256


def test_verified_loader_rejects_digest_mismatch_and_noncanonical_json(tmp_path: Path) -> None:
    report = _build()
    report_path = tmp_path / "report.json"
    scanner = empty_secret_scanner_for_tests()
    artifact = write_terminal_batch_report(report_path, report, secret_scanner=scanner)
    report_path.write_bytes(report_path.read_bytes() + b" ")
    with pytest.raises(BatchReportIntegrityError, match="SHA-256"):
        load_verified_batch_report(
            report_path, artifact.sha256, secret_scanner=scanner
        )

    noncanonical = json.dumps(report, ensure_ascii=False, indent=2).encode()
    report_path.write_bytes(noncanonical)
    noncanonical_sha = hashlib.sha256(noncanonical).hexdigest()
    with pytest.raises(BatchReportIntegrityError, match="not canonical"):
        load_verified_batch_report(
            report_path, noncanonical_sha, secret_scanner=scanner
        )


@pytest.mark.parametrize(
    "candidate",
    [
        "prefix-SÉCRET-１２３-Key-suffix",
        unicodedata.normalize("NFD", "sécret-１２３-key"),
        "sÉcret-１２３-kEY",
        "sécret123key",
    ],
    ids=("embedded-exact", "nfd", "casefold", "legacy-compact"),
)
def test_secret_scanner_detects_exact_nfc_casefold_and_legacy_variants(candidate: str) -> None:
    scanner = SecretCanaryScanner(["SÉCRET-１２３-Key"])

    assert scanner.contains({"nested": [candidate]}) is True
    with pytest.raises(SecretCanaryDetected) as caught:
        scanner.reject({"value": candidate})
    assert "sécret" not in str(caught.value).casefold()
    assert "123key" not in str(caught.value).casefold()


def test_standalone_canary_gate_deletes_polluted_temporary_files(tmp_path: Path) -> None:
    secret = "sk-canary-delete-me-456"
    temporary = tmp_path / ".polluted.tmp"
    temporary.write_text(f"legacy={secret.replace('-', '')}", encoding="utf-8")

    with pytest.raises(SecretCanaryDetected):
        reject_secret_canaries(
            temporary.read_bytes(),
            [secret],
            delete_paths=(temporary,),
        )

    assert not temporary.exists()


def test_contaminated_report_is_not_published_or_allowed_to_replace_existing(
    tmp_path: Path,
) -> None:
    secret = "sk-never-publish-this-789"
    safe_report = _build()
    contaminated = deepcopy(safe_report)
    contaminated["targets"][0]["station_name"] = f"Relay {secret.casefold()}"
    destination = tmp_path / "report.json"
    destination.write_bytes(b"previous verified report")

    with pytest.raises(SecretCanaryDetected):
        write_terminal_batch_report(
            destination,
            contaminated,
            secret_scanner=SecretCanaryScanner([secret]),
        )

    assert destination.read_bytes() == b"previous verified report"
    assert not any(path.suffix == ".tmp" for path in tmp_path.iterdir())


def test_csv_is_one_row_per_station_verified_only_and_formula_safe(tmp_path: Path) -> None:
    rows = _rows()
    rows[0]["station_name"] = "\x01=HYPERLINK(\"https://evil.invalid\")"
    rows[0]["model_id"] = "+cmd|' /C calc'!A0"
    rows[1]["station_name"] = "-2+3"
    report = _build(
        rows=rows,
        results=[
            _completed_result(reported_model="@SUM(1+1)"),
            _failed_result(),
        ],
    )
    scanner = empty_secret_scanner_for_tests()
    json_artifact = write_terminal_batch_report(
        tmp_path / "report.json", report, secret_scanner=scanner
    )
    csv_artifact = write_verified_batch_csv(
        tmp_path / "report.csv",
        json_path=json_artifact.path,
        expected_json_sha256=json_artifact.sha256,
        secret_scanner=scanner,
    )

    assert csv_artifact.sha256 == hashlib.sha256(csv_artifact.path.read_bytes()).hexdigest()
    parsed = list(csv.DictReader(io.StringIO(csv_artifact.path.read_text(encoding="utf-8"))))
    assert len(parsed) == len(rows)
    assert tuple(parsed[0]) == CSV_COLUMNS
    assert parsed[0]["station_name"].startswith("'\x01=")
    assert parsed[0]["requested_model"].startswith("'+")
    assert parsed[0]["reported_model"].startswith("'@")
    assert parsed[1]["station_name"].startswith("'-")
    assert parsed[0]["reference_member_1_id"] == "member-1"
    assert parsed[0]["reference_member_3_mean_jsd"] == "0.02"
    assert parsed[0]["coverage_cells"] == "40"
    assert parsed[0]["latency_p95_ms"] == "1220.0"
    assert parsed[0]["retries"] == "7"
    assert parsed[0]["retry_budget_used"] == "7"
    assert parsed[0]["discarded_attempts"] == "0"
    assert parsed[0]["artifact_sha256"] == _digest("d")

    with pytest.raises(TypeError, match="VerifiedBatchReport"):
        csv_bytes_from_verified_report(report)  # type: ignore[arg-type]


def test_csv_refuses_tampered_json_and_leaves_no_output(tmp_path: Path) -> None:
    report = _build()
    scanner = empty_secret_scanner_for_tests()
    json_artifact = write_terminal_batch_report(
        tmp_path / "report.json", report, secret_scanner=scanner
    )
    json_artifact.path.write_bytes(json_artifact.path.read_bytes() + b"\n")
    csv_path = tmp_path / "report.csv"

    with pytest.raises(BatchReportIntegrityError):
        write_verified_batch_csv(
            csv_path,
            json_path=json_artifact.path,
            expected_json_sha256=json_artifact.sha256,
            secret_scanner=scanner,
        )

    assert not csv_path.exists()


def test_schema_rejects_forbidden_fields_and_wrong_reference_ensemble() -> None:
    report = _build()
    report["targets"][0]["credential_ref"] = "not-allowed"
    with pytest.raises(BatchReportValidationError, match="forbidden sensitive field"):
        validate_batch_report(report)

    broken_reference = _reference_set()
    broken_reference["members"] = broken_reference["members"][:2]
    with pytest.raises(BatchReportValidationError, match="exactly three members"):
        build_terminal_batch_report(
            batch=_batch(),
            reference_set=broken_reference,
            input_rows=_rows(),
            target_results=[_completed_result(), _failed_result()],
            tool={"name": "relay-model-auditor", "version": "0.2.0", "git_sha": "1683796"},
            secret_scanner=empty_secret_scanner_for_tests(),
        )


def test_reference_and_target_evidence_fields_are_preserved() -> None:
    completed = _completed_result()
    report = _build(results=[completed, _failed_result()])

    assert len(report["reference_set"]["members"]) == 3
    assert report["reference_set"]["members"][0]["artifact_sha256"] == _digest("1")
    assert report["reference_set"]["members"][0]["raw_evidence_sha256"] == _digest("a")
    assert report["reference_set"]["envelope"] == {
        "method": "max_reference_pairwise_bootstrap_upper",
        "max_upper_jsd": 0.023,
    }
    target = report["targets"][0]
    assert target["metrics"]["valid_samples"] == 1200
    assert target["distances"]["median_mean_jsd"] == 0.015
    assert len(target["distances"]["members"]) == 3
    assert target["latency"] == {"p50_ms": 712.5, "p95_ms": 1220.0}
    assert target["requests"] == {
        "logical_samples": 1200,
        "attempts": 1208,
        "retries": 7,
        "retry_budget_used": 7,
        "discarded_attempts": 0,
    }
    assert target["evidence"]["raw_evidence_sha256"] == _digest("e")
    comparison_bytes = (
        json.dumps(completed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    assert target["evidence"]["comparison_artifact_sha256"] == hashlib.sha256(
        comparison_bytes
    ).hexdigest()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda report: report["reference_set"]["members"][0].update(
                {"raw_evidence_sha256": None}
            ),
            "raw_evidence_sha256",
        ),
        (
            lambda report: report["reference_set"]["members"][0].update(
                {"artifact_sha256": None}
            ),
            "artifact_sha256",
        ),
        (
            lambda report: report["reference_set"]["members"][0]["quality"].update(
                {"valid_samples": 1199}
            ),
            "sample totals must equal 1200",
        ),
        (
            lambda report: report["reference_set"]["envelope"].update(
                {"max_upper_jsd": 0.022}
            ),
            "maximum pairwise bootstrap upper bound",
        ),
        (
            lambda report: report["batch"].update(
                {"transport_profile": "openai-chat-onetoken-v1"}
            ),
            "protocol and transport_profile",
        ),
        (
            lambda report: report["reference_set"].update(
                {"transport_profile": "openai-chat-onetoken-v1"}
            ),
            "transport_profile does not match reference_set",
        ),
        (
            lambda report: report["tool"].update({"git_sha": "unknown"}),
            "7 to 64 character hex SHA",
        ),
        (
            lambda report: report["targets"][0]["evidence"].update(
                {"comparison_artifact_sha256": None}
            ),
            "comparison_artifact_sha256 must be a non-empty string",
        ),
        (
            lambda report: report["targets"][0]["evidence"].update(
                {"artifact_sha256": None}
            ),
            "artifact_sha256 evidence",
        ),
        (
            lambda report: report["targets"][0]["evidence"].update(
                {"raw_evidence_sha256": None}
            ),
            "raw_evidence_sha256 evidence",
        ),
        (
            lambda report: report["targets"][0]["requests"].update(
                {"logical_samples": 1199}
            ),
            "must contain 1200 logical samples",
        ),
        (
            lambda report: report["targets"][0]["requests"].update(
                {"attempts": 1207}
            ),
            "request attempts are inconsistent",
        ),
        (
            lambda report: report["targets"][0]["requests"].update(
                {"discarded_attempts": 1}
            ),
            "request attempts are inconsistent",
        ),
        (
            lambda report: report["targets"][0]["requests"].update(
                {"discarded_attempts": -1}
            ),
            "discarded_attempts must be an integer >= 0",
        ),
        (
            lambda report: report["targets"][0]["requests"].update(
                {"retry_budget_used": 6}
            ),
            "retry_budget_used cannot be below physical retries",
        ),
        (
            lambda report: report["targets"][0]["requests"].update(
                {"retry_budget_used": -1}
            ),
            "retry_budget_used must be an integer >= 0",
        ),
        (
            lambda report: report["targets"][0]["latency"].update(
                {"p50_ms": 1300.0}
            ),
            "latency p95 is below p50",
        ),
        (
            lambda report: report["targets"][0]["preflight"].update(
                {"http_status": 700}
            ),
            "preflight.http_status must be <= 599",
        ),
        (
            lambda report: report["targets"][0]["metrics"].update(
                {"coverage_cells": 41}
            ),
            "coverage_cells exceeds total_cells",
        ),
        (
            lambda report: report["targets"][0]["metrics"].update(
                {"invalid_samples": 1}
            ),
            "quality sample totals do not equal logical_samples",
        ),
        (
            lambda report: report["targets"][0]["distances"].update(
                {"median_mean_jsd": 0.02}
            ),
            "is not derived from member means",
        ),
        (
            lambda report: report["targets"][0].update(
                {"exploratory_status": "inconclusive"}
            ),
            "classification contradicts",
        ),
        (
            lambda report: report["targets"][0]["metrics"].update(
                {
                    "valid_samples": 1170,
                    "invalid_samples": 30,
                    "coverage_cells": 39,
                }
            ),
            "insufficient quality must take classification priority",
        ),
        (
            lambda report: report["targets"][0].update(
                {"decision_eligible": True}
            ),
            "operationally unverifiable",
        ),
        (
            lambda report: report["targets"][0].update(
                {"operational_verdict": "match"}
            ),
            "operationally unverifiable",
        ),
    ],
)
def test_validator_rejects_internally_contradictory_reports(
    mutation,
    message: str,
) -> None:
    report = _build()
    mutation(report)

    with pytest.raises(BatchReportValidationError, match=message):
        validate_batch_report(report)


def test_insufficient_quality_is_accepted_only_without_distances() -> None:
    insufficient = _completed_result(
        exploratory_status="insufficient_quality",
        reason_codes=["minimum_valid_samples_per_cell_not_met"],
        metrics={
            "valid_samples": 1170,
            "invalid_samples": 30,
            "error_samples": 0,
            "coverage_cells": 39,
            "total_cells": 40,
            "directness": "verified",
            "split_half_mean_jsd": 0.018,
        },
        distances={
            "members": [],
            "median_mean_jsd": None,
            "mad_mean_jsd": None,
            "min_mean_jsd": None,
            "max_mean_jsd": None,
        },
    )
    report = _build(results=[insufficient, _failed_result()])

    assert report["targets"][0]["exploratory_status"] == "insufficient_quality"
    assert report["targets"][0]["distances"]["members"] == []


def test_discarded_attempts_make_pause_resume_work_auditable() -> None:
    resumed = _completed_result(
        requests={
            "logical_samples": 1200,
            "attempts": 2409,
            "retries": 7,
            "retry_budget_used": 12,
            "discarded_attempts": 1201,
        }
    )
    report = _build(results=[resumed, _failed_result()])

    assert report["targets"][0]["requests"] == {
        "logical_samples": 1200,
        "attempts": 2409,
        "retries": 7,
        "retry_budget_used": 12,
        "discarded_attempts": 1201,
    }


def test_retry_budget_can_exceed_physical_retries_without_changing_attempt_count() -> None:
    result = _completed_result(
        requests={
            "logical_samples": 1200,
            "attempts": 1208,
            "retries": 7,
            "retry_budget_used": 20,
            "discarded_attempts": 0,
        }
    )
    report = _build(results=[result, _failed_result()])

    requests = report["targets"][0]["requests"]
    assert requests["retries"] == 7
    assert requests["retry_budget_used"] == 20
    assert requests["attempts"] == 1208


def test_report_entry_points_require_an_explicit_secret_scanner(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="explicit SecretCanaryScanner"):
        build_terminal_batch_report(
            batch=_batch(),
            reference_set=_reference_set(),
            input_rows=_rows(),
            target_results=[_completed_result(), _failed_result()],
            tool={"name": "relay-model-auditor", "version": "0.2.0", "git_sha": "1683796"},
        )

    report = _build()
    with pytest.raises(TypeError, match="explicit SecretCanaryScanner"):
        write_terminal_batch_report(tmp_path / "report.json", report)
