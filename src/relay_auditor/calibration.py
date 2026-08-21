from statistics import median


def median_absolute_deviation(values: list[float]) -> float:
    if not values:
        raise ValueError("calibration requires at least one value")
    center = median(values)
    return float(median(abs(value - center) for value in values))


def upper_threshold(values: list[float], multiplier: float = 3.0) -> dict[str, float]:
    if multiplier <= 0:
        raise ValueError("multiplier must be positive")
    center = float(median(values))
    mad = median_absolute_deviation(values)
    return {
        "median": center,
        "mad": mad,
        "multiplier": multiplier,
        "threshold": center + multiplier * mad,
    }


def small_sample_upper_threshold(
    values: list[float],
    *,
    multiplier: float = 3.0,
    minimum_margin: float = 0.01,
) -> dict[str, float]:
    if minimum_margin <= 0:
        raise ValueError("minimum_margin must be positive")
    robust = upper_threshold(values, multiplier)
    observed_max = max(values)
    safety_margin = max(robust["mad"], minimum_margin)
    recommended = max(robust["threshold"], observed_max + safety_margin)
    return {
        **robust,
        "robust_threshold": robust["threshold"],
        "observed_max": observed_max,
        "safety_margin": safety_margin,
        "threshold": recommended,
    }
