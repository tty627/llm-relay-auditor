import math

import pytest

from relay_auditor.detectors.tokenizer import (
    PROBE_UNITS,
    compare_tokenizer_fingerprints,
    linear_fit,
)
from relay_auditor.mock_api import _mock_prompt_tokens, _route_backend


def test_linear_fit_recovers_slope() -> None:
    result = linear_fit([0, 1, 2, 4, 8], [10, 13, 16, 22, 34])
    assert result["slope"] == 3
    assert result["intercept"] == 10
    assert result["r_squared"] == 1


def test_tokenizer_comparison_verdicts() -> None:
    def evidence(*, scale: float = 1, unstable: list[str] | None = None) -> dict:
        return {
            "protocol": "tokenizer-slope/v1",
            "slope_vector": {
                probe_id: (index + 1) * scale for index, probe_id in enumerate(PROBE_UNITS)
            },
            "unstable_probes": unstable or [],
        }

    reference = evidence()
    same = evidence()
    changed = evidence(scale=2)
    unstable = evidence(unstable=["cjk"])
    unstable_reference = evidence(unstable=["english"])

    same_result = compare_tokenizer_fingerprints(reference, same)
    assert same_result["verdict"] == "match"
    assert same_result["exploratory_verdict"] == "match"
    assert same_result["operational_verdict"] == "unverifiable"
    assert same_result["decision_eligible"] is False
    assert compare_tokenizer_fingerprints(reference, changed)["verdict"] == "mismatch"
    assert compare_tokenizer_fingerprints(reference, unstable)["verdict"] == "unstable"
    assert compare_tokenizer_fingerprints(unstable_reference, changed)["verdict"] == "unstable"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("protocol"),
        lambda value: value["slope_vector"].pop("cjk"),
        lambda value: value["slope_vector"].update({"unknown": 1}),
        lambda value: value["slope_vector"].update({"cjk": math.nan}),
        lambda value: value["slope_vector"].update({"cjk": math.inf}),
        lambda value: value["slope_vector"].update({"cjk": -1}),
        lambda value: value["slope_vector"].update({"cjk": True}),
        lambda value: value.update({"unstable_probes": ["unknown"]}),
    ],
)
def test_tokenizer_comparison_rejects_malformed_evidence(mutation) -> None:
    evidence = {
        "protocol": "tokenizer-slope/v1",
        "slope_vector": {probe_id: 1.0 for probe_id in PROBE_UNITS},
        "unstable_probes": [],
    }
    mutation(evidence)

    with pytest.raises(ValueError):
        compare_tokenizer_fingerprints(
            evidence,
            {
                "protocol": "tokenizer-slope/v1",
                "slope_vector": {probe_id: 1.0 for probe_id in PROBE_UNITS},
                "unstable_probes": [],
            },
        )


def test_mock_has_distinct_token_accounting() -> None:
    prompt = "中转站Audit🚀" * 20
    reference = _mock_prompt_tokens(prompt, "reference")
    substitute = _mock_prompt_tokens(prompt, "substitute")
    assert substitute > reference


def test_mixed_router_is_close_to_requested_ratio() -> None:
    substitutions = sum(
        _route_backend("mixed-20", f"probe-{index}") == "substitute" for index in range(1000)
    )
    assert 150 <= substitutions <= 250
