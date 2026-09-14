"""
ECDAT Stochastic Monte Carlo Mosca Simulator:
Replaces rigid scalar calculations with 5,000+ iteration Monte Carlo simulation
modeling quantum computer arrival year Z (GRI 2025 distribution), data lifespan X,
and engineering migration lead time Y uncertainty using pure standard library.
"""

import random
import math
from typing import List, Tuple, Dict, Any, Optional

from ecdat.constants import CURRENT_YEAR
from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    PrimitiveType,
    IntentClass,
    StochasticMoscaResult,
)
from ecdat.mosca.engine import is_safe_quantum_or_symmetric

# GRI 2025 Physical Quantum Arrival Parameters
GRI_CRQC_MIN_YEAR = 2029.0
GRI_CRQC_MODE_YEAR = 2034.0
GRI_CRQC_MAX_YEAR = 2042.0

def _percentile(data: List[float], p: float) -> float:
    """Calculates percentile p (0-100) from a sorted list of floats."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return d0 + d1

def simulate_asset_stochastic_mosca(
    asset: CryptoAsset,
    score: MoscaScore,
    iterations: int = 5000,
    current_year: int = CURRENT_YEAR,
    random_seed: Optional[int] = 42,
) -> StochasticMoscaResult:
    """
    Runs a Monte Carlo simulation over X (data lifetime), Y (migration effort),
    and Z (CRQC quantum arrival year per GRI 2025) to compute empirical breach probability.
    """
    # If algorithm is already post-quantum or grover-safe symmetric, breach probability is 0.0
    if is_safe_quantum_or_symmetric(asset.algorithm):
        return StochasticMoscaResult(
            asset_id=asset.asset_id,
            algorithm=asset.algorithm,
            iterations=iterations,
            breach_probability=0.0,
            p50_safety_margin_years=25.0,
            p95_safety_margin_years=20.0,
            var_95_breach_year=2050,
            risk_category="LOW",
        )

    # Operational utility (ETag, cache dedup) has 0 quantum vulnerability
    intent_val = asset.intent_class if isinstance(asset.intent_class, IntentClass) else IntentClass(str(asset.intent_class))
    if intent_val == IntentClass.OPERATIONAL_UTILITY:
        return StochasticMoscaResult(
            asset_id=asset.asset_id,
            algorithm=asset.algorithm,
            iterations=iterations,
            breach_probability=0.0,
            p50_safety_margin_years=30.0,
            p95_safety_margin_years=25.0,
            var_95_breach_year=2050,
            risk_category="LOW",
        )

    p_hndl = getattr(asset, "p_hndl", 1.0)
    if p_hndl <= 0.0:
        return StochasticMoscaResult(
            asset_id=asset.asset_id,
            algorithm=asset.algorithm,
            iterations=iterations,
            breach_probability=0.0,
            p50_safety_margin_years=20.0,
            p95_safety_margin_years=15.0,
            var_95_breach_year=2050,
            risk_category="LOW",
        )

    rng = random.Random(random_seed)

    x_base = max(0.1, score.x_years_effective)
    # Estimate baseline Y code duration (in years)
    prim_type = asset.primitive_type if isinstance(asset.primitive_type, PrimitiveType) else PrimitiveType(str(asset.primitive_type))
    y_base = 2.0 if prim_type in (PrimitiveType.KEY_EXCHANGE, PrimitiveType.SIGNATURE) else 1.0

    z_regulatory = float(score.z_regulatory_year)
    z_mode = min(GRI_CRQC_MODE_YEAR, z_regulatory)

    breach_count = 0
    safety_margins: List[float] = []
    earliest_breach_years: List[float] = []

    for _ in range(iterations):
        # 1. Sample Z ~ Triangular(min, max, mode)
        z_sample = rng.triangular(GRI_CRQC_MIN_YEAR, GRI_CRQC_MAX_YEAR, z_mode)

        # 2. Sample X ~ Uniform(0.80 * X_base, 1.25 * X_base)
        x_sample = rng.uniform(0.80 * x_base, 1.25 * x_base)

        # 3. Sample Y ~ Triangular(0.70 * Y_base, 1.50 * Y_base, Y_base)
        y_sample = rng.triangular(0.70 * y_base, 1.50 * y_base, y_base)

        exposure_year = current_year + x_sample + y_sample
        earliest_breach_years.append(exposure_year)

        # Breach condition: CurrentYear + X + Y > Z
        if exposure_year > z_sample:
            breach_count += 1

        safety_margins.append(z_sample - exposure_year)

    raw_breach_prob = breach_count / float(iterations)
    breach_probability = round(float(raw_breach_prob * p_hndl), 3)

    p50_margin = round(_percentile(safety_margins, 50.0), 2)
    # 5th percentile of safety margins gives the 95% Value-at-Risk conservative safety window
    p95_worst_margin = round(_percentile(safety_margins, 5.0), 2)

    var_95_year = int(round(_percentile(earliest_breach_years, 95.0)))

    # Risk categorization
    if breach_probability >= 0.50 or p95_worst_margin <= 0.0:
        risk_category = "CRITICAL"
    elif breach_probability >= 0.20 or p95_worst_margin <= 2.0:
        risk_category = "HIGH"
    elif breach_probability >= 0.05:
        risk_category = "MEDIUM"
    else:
        risk_category = "LOW"

    return StochasticMoscaResult(
        asset_id=asset.asset_id,
        algorithm=asset.algorithm,
        iterations=iterations,
        breach_probability=breach_probability,
        p50_safety_margin_years=p50_margin,
        p95_safety_margin_years=p95_worst_margin,
        var_95_breach_year=var_95_year,
        risk_category=risk_category,
    )

def simulate_estate_stochastic_mosca(
    assessments: List[Tuple[CryptoAsset, MoscaScore, Any]],
    iterations: int = 5000,
    current_year: int = CURRENT_YEAR,
) -> Dict[str, Any]:
    """
    Runs stochastic Monte Carlo simulation across the entire cryptographic estate.
    Returns portfolio-level breach metrics and per-asset stochastic distributions.
    """
    results: List[StochasticMoscaResult] = []

    for asset, score, _ in assessments:
        res = simulate_asset_stochastic_mosca(
            asset=asset,
            score=score,
            iterations=iterations,
            current_year=current_year,
        )
        results.append(res)

    valid_probs = [r.breach_probability for r in results if r.breach_probability > 0.0]
    estate_mean_breach_prob = round(sum(valid_probs) / len(valid_probs), 3) if valid_probs else 0.0
    estate_max_breach_prob = round(max((r.breach_probability for r in results), default=0.0), 3)

    critical_count = sum(1 for r in results if r.risk_category == "CRITICAL")
    high_count = sum(1 for r in results if r.risk_category == "HIGH")

    return {
        "iterations": iterations,
        "total_simulated_assets": len(results),
        "mean_breach_probability": estate_mean_breach_prob,
        "max_breach_probability": estate_max_breach_prob,
        "critical_probabilistic_assets": critical_count,
        "high_probabilistic_assets": high_count,
        "results": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in results],
    }
