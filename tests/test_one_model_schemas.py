from __future__ import annotations

import pytest
from pydantic import ValidationError

from relay_auditor.one_model_schemas import OneModelBatchCreateRequest


def payload() -> dict[str, object]:
    return {
        "reference_set_id": "11111111-1111-1111-1111-111111111111",
        "default_model_id": "claude-opus-5",
        "targets": [
            {
                "row_id": "relay-a",
                "station_name": "Relay A",
                "base_url": "https://a.example/v1",
                "credential": {"mode": "ephemeral", "api_key": "sk-a"},
            },
            {
                "row_id": "relay-b",
                "station_name": "Relay B",
                "base_url": "https://b.example/v1",
                "credential": {"mode": "env_ref", "name": "RELAY_B_KEY"},
                "model_id": "opus-5-vendor-alias",
            },
        ],
    }


def test_default_one_model_batch_contract_is_bounded_4_by_3() -> None:
    request = OneModelBatchCreateRequest.model_validate(payload())
    assert request.max_parallel_stations == 4
    assert request.per_station_concurrency == 3
    assert request.global_request_concurrency == 12
    assert request.retry_budget == 240
    assert request.targets[1].model_id == "opus-5-vendor-alias"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["targets"].append(value["targets"][0].copy()),
        lambda value: value["targets"][1].update({"row_id": "relay-a"}),
        lambda value: value.update({"max_parallel_stations": 4, "per_station_concurrency": 2}),
    ],
)
def test_duplicate_rows_and_impossible_global_concurrency_are_rejected(mutation) -> None:
    candidate = payload()
    mutation(candidate)
    with pytest.raises(ValidationError):
        OneModelBatchCreateRequest.model_validate(candidate)


def test_credentials_and_unknown_fields_are_secret_and_strict() -> None:
    candidate = payload()
    candidate["targets"][0]["unknown"] = "sk-should-not-echo"
    with pytest.raises(ValidationError) as caught:
        OneModelBatchCreateRequest.model_validate(candidate)
    assert "sk-a" not in str(caught.value)
