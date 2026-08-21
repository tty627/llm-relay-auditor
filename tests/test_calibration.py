import pytest

from relay_auditor.calibration import (
    median_absolute_deviation,
    small_sample_upper_threshold,
    upper_threshold,
)


def test_robust_upper_threshold() -> None:
    values = [0.10, 0.11, 0.12, 0.12, 0.13, 0.50]
    result = upper_threshold(values)

    assert result["median"] == pytest.approx(0.12)
    assert result["mad"] == pytest.approx(0.01)
    assert result["threshold"] == pytest.approx(0.15)


def test_small_sample_threshold_covers_observed_tail() -> None:
    values = [0.02, 0.05, 0.06, 0.07, 0.11]
    result = small_sample_upper_threshold(values)

    assert result["robust_threshold"] < max(values)
    assert result["threshold"] > max(values)
    assert result["safety_margin"] >= 0.01


def test_mad_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        median_absolute_deviation([])
