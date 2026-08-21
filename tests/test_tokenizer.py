from relay_auditor.detectors.tokenizer import (
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
    reference = {
        "slope_vector": {"cjk": 8.0, "english": 6.0},
        "unstable_probes": [],
    }
    same = {
        "slope_vector": {"cjk": 8.0, "english": 6.0},
        "unstable_probes": [],
    }
    changed = {
        "slope_vector": {"cjk": 12.0, "english": 9.0},
        "unstable_probes": [],
    }
    unstable = {
        "slope_vector": {"cjk": 8.0, "english": 6.0},
        "unstable_probes": ["cjk"],
    }

    assert compare_tokenizer_fingerprints(reference, same)["verdict"] == "match"
    assert compare_tokenizer_fingerprints(reference, changed)["verdict"] == "mismatch"
    assert compare_tokenizer_fingerprints(reference, unstable)["verdict"] == "unstable"


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
