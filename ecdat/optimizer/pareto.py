"""
ECDAT Pareto Migration Portfolio Optimizer:
Implements Pillar 7 resource-constrained knapsack optimization and efficient frontier
calculation over R0 blast radius, CAMS engineering effort, and HNDL quantum risk.
"""

from typing import List, Tuple, Dict, Any, Optional, Set
from pathlib import Path
from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    PrimitiveType,
    AgilityLevel,
    IntentClass,
    ParetoItem,
    ParetoPortfolioResult,
)
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.contagion.engine import ContagionGraphResult
from ecdat.mosca.engine import is_safe_quantum_or_symmetric

# Base engineering effort in developer-weeks by cryptographic role
BASE_DEV_WEEKS = {
    PrimitiveType.KEY_EXCHANGE: 2.0,
    PrimitiveType.SIGNATURE: 2.0,
    PrimitiveType.ENCRYPTION: 1.5,
    PrimitiveType.HASH: 0.5,
}

# CAMS Agility Multipliers (effort discount when agile abstraction exists)
CAMS_EFFORT_MULTIPLIERS = {
    AgilityLevel.RIGID: 1.0,        # Hardcoded literal: baseline full effort
    AgilityLevel.CONFIGURABLE: 0.7, # Config/env loaded: 30% discount
    AgilityLevel.PROVIDER: 0.4,     # Factory/DI abstracted: 60% discount
    AgilityLevel.RUNTIME_AGILE: 0.15, # Runtime agile facade: 85% discount
}

# Risk severity base weights
RISK_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
}

# DSIS Functional Intent Weights (suppresses operational caching utilities)
INTENT_WEIGHTS = {
    IntentClass.OPERATIONAL_UTILITY: 0.0,
    IntentClass.INTEGRITY_CHECKSUM: 0.3,
    IntentClass.AUTHENTICATION_SIGNATURE: 1.0,
    IntentClass.CONFIDENTIALITY_ENVELOPE: 1.0,
}

def _resolve_r0(asset: CryptoAsset, contagion_result: Optional[ContagionGraphResult]) -> int:
    """Resolves downstream R0 infection count from contagion graph."""
    if not contagion_result:
        return 1

    asset_stem = Path(asset.file_path).stem if asset.file_path else ""
    comp_name = asset.component_name

    # Try matching exact node in contagion graph
    for node in contagion_result.nodes:
        if node.node_id in (comp_name, asset_stem) or node.file_path == asset.file_path:
            return max(1, node.r0_score)

    return 1

def compute_item_pareto_metrics(
    asset: CryptoAsset,
    score: MoscaScore,
    rec: MigrationRecommendation,
    r0: int,
) -> Tuple[float, float, float]:
    """
    Computes (delta_r, cost_dev_weeks, efficiency) for an individual asset.
    - delta_r: Blast-radius-weighted quantum risk reduction
    - cost_dev_weeks: Engineering migration effort in dev-weeks
    - efficiency: delta_r / cost_dev_weeks
    """
    # If already post-quantum secure, risk reduction is 0.0
    if is_safe_quantum_or_symmetric(asset.algorithm):
        return 0.0, 0.2, 0.0

    # Functional Intent Weight
    intent_val = asset.intent_class if isinstance(asset.intent_class, IntentClass) else IntentClass(str(asset.intent_class))
    w_intent = INTENT_WEIGHTS.get(intent_val, 1.0)
    if w_intent == 0.0:
        return 0.0, 0.2, 0.0

    # Adversarial exposure factor
    p_hndl = getattr(asset, "p_hndl", 1.0)
    if p_hndl <= 0.0:
        return 0.0, 0.2, 0.0

    # Risk level weight
    risk_weight = RISK_WEIGHTS.get(score.risk_level, 2.0)

    # Blast-radius weighted risk reduction Delta R
    delta_r = round(float(r0) * p_hndl * w_intent * risk_weight, 2)

    # Cost calculation: Base * Fan-out complexity * CAMS discount
    prim_type = asset.primitive_type if isinstance(asset.primitive_type, PrimitiveType) else PrimitiveType(str(asset.primitive_type))
    base_cost = BASE_DEV_WEEKS.get(prim_type, 1.5)

    cams_lvl = asset.agility_level if isinstance(asset.agility_level, AgilityLevel) else AgilityLevel(int(asset.agility_level))
    cams_mult = CAMS_EFFORT_MULTIPLIERS.get(cams_lvl, 1.0)

    # Fan-out penalty: each downstream dependent adds 15% refactoring complexity
    fan_out_factor = 1.0 + (0.15 * min(r0, 5))

    cost_dev_weeks = round(max(0.2, base_cost * fan_out_factor * cams_mult), 2)
    efficiency = round(delta_r / cost_dev_weeks, 3) if cost_dev_weeks > 0 else 0.0

    return delta_r, cost_dev_weeks, efficiency

def compute_efficient_frontier(items: List[ParetoItem]) -> List[Dict[str, Any]]:
    """
    Constructs the Pareto efficient frontier curve from sorted portfolio items.
    Returns coordinates [{cost, risk_pct, asset_id, algorithm}].
    """
    total_risk = sum(item.delta_r for item in items)
    if total_risk <= 0:
        return [{"cost": 0.0, "risk_pct": 100.0, "asset_id": "none", "algorithm": "none"}]

    frontier = [{"cost": 0.0, "risk_pct": 0.0, "asset_id": "origin", "algorithm": "none"}]
    cum_cost = 0.0
    cum_risk = 0.0

    for item in items:
        if item.delta_r <= 0:
            continue
        cum_cost = round(cum_cost + item.cost_dev_weeks, 2)
        cum_risk += item.delta_r
        pct = round(min(100.0, (cum_risk / total_risk) * 100.0), 1)
        frontier.append({
            "cost": cum_cost,
            "risk_pct": pct,
            "asset_id": item.asset_id,
            "algorithm": item.algorithm,
        })

    return frontier

def optimize_pareto_portfolio(
    assessments: List[Tuple[CryptoAsset, MoscaScore, MigrationRecommendation]],
    contagion_result: Optional[ContagionGraphResult] = None,
    budget_dev_weeks: float = 10.0,
) -> ParetoPortfolioResult:
    """
    Solves resource-constrained migration planning for a given sprint budget B.
    Ranks remediation backlog by efficiency (Delta R / Cost) and builds the efficient frontier.
    """
    raw_items: List[ParetoItem] = []

    for asset, score, rec in assessments:
        r0 = _resolve_r0(asset, contagion_result)
        delta_r, cost, efficiency = compute_item_pareto_metrics(asset, score, rec, r0)

        cams_val = int(asset.agility_level) if hasattr(asset, "agility_level") else 0

        raw_items.append(ParetoItem(
            asset_id=asset.asset_id,
            component_name=asset.component_name,
            algorithm=asset.algorithm,
            primitive_type=asset.primitive_type.value if hasattr(asset.primitive_type, "value") else str(asset.primitive_type),
            file_path=asset.file_path,
            line_number=asset.line_number,
            r0_score=r0,
            cams_level=cams_val,
            risk_level=score.risk_level,
            delta_r=delta_r,
            cost_dev_weeks=cost,
            efficiency=efficiency,
            is_selected=False,
            cumulative_risk_pct=0.0,
            cumulative_cost_weeks=0.0,
        ))

    # Sort items by efficiency descending (primary), delta_r descending (secondary), cost ascending (tertiary)
    sorted_items = sorted(
        raw_items,
        key=lambda x: (x.efficiency, x.delta_r, -x.cost_dev_weeks),
        reverse=True,
    )

    total_estate_risk = sum(it.delta_r for it in sorted_items)
    frontier_points = compute_efficient_frontier(sorted_items)

def solve_01_knapsack_dp(items: List[ParetoItem], budget_weeks: float) -> Set[str]:
    """
    Solves the exact 0/1 Knapsack Dynamic Programming problem with integer scaling.
    Guarantees mathematically optimal subset selection subject to budget constraint.
    """
    scale = 100  # 0.01 dev-week integer discretization precision
    W = max(0, int(round(budget_weeks * scale)))

    candidates = [it for it in items if it.delta_r > 0]
    if not candidates or W <= 0:
        return set()

    n = len(candidates)
    weights = [max(1, int(round(it.cost_dev_weeks * scale))) for it in candidates]
    values = [it.delta_r for it in candidates]

    # 2D DP table: dp[i][w] stores maximum delta_r using a subset of first i items with weight <= w
    dp = [[0.0] * (W + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        w_i = weights[i - 1]
        v_i = values[i - 1]
        for w in range(W + 1):
            if w < w_i:
                dp[i][w] = dp[i - 1][w]
            else:
                take = dp[i - 1][w - w_i] + v_i
                dont = dp[i - 1][w]
                dp[i][w] = take if take > dont else dont

    # Backtrack to reconstruct the exact optimal portfolio subset
    selected_asset_ids = set()
    curr_w = W
    for i in range(n, 0, -1):
        if dp[i][curr_w] != dp[i - 1][curr_w]:
            selected_asset_ids.add(candidates[i - 1].asset_id)
            curr_w -= weights[i - 1]

    return selected_asset_ids

def optimize_pareto_portfolio(
    assessments: List[Tuple[CryptoAsset, MoscaScore, MigrationRecommendation]],
    contagion_result: Optional[ContagionGraphResult] = None,
    budget_dev_weeks: float = 10.0,
) -> ParetoPortfolioResult:
    """
    Solves resource-constrained migration planning for a given sprint budget B
    via exact 0/1 Knapsack Dynamic Programming and constructs the Pareto efficient frontier.
    """
    raw_items: List[ParetoItem] = []

    for asset, score, rec in assessments:
        r0 = _resolve_r0(asset, contagion_result)
        delta_r, cost, efficiency = compute_item_pareto_metrics(asset, score, rec, r0)

        cams_val = int(asset.agility_level) if hasattr(asset, "agility_level") else 0

        raw_items.append(ParetoItem(
            asset_id=asset.asset_id,
            component_name=asset.component_name,
            algorithm=asset.algorithm,
            primitive_type=asset.primitive_type.value if hasattr(asset.primitive_type, "value") else str(asset.primitive_type),
            file_path=asset.file_path,
            line_number=asset.line_number,
            r0_score=r0,
            cams_level=cams_val,
            risk_level=score.risk_level,
            delta_r=delta_r,
            cost_dev_weeks=cost,
            efficiency=efficiency,
            is_selected=False,
            cumulative_risk_pct=0.0,
            cumulative_cost_weeks=0.0,
        ))

    # Sort items by efficiency descending (primary), delta_r descending (secondary), cost ascending (tertiary)
    sorted_items = sorted(
        raw_items,
        key=lambda x: (x.efficiency, x.delta_r, -x.cost_dev_weeks),
        reverse=True,
    )

    total_estate_risk = sum(it.delta_r for it in sorted_items)
    frontier_points = compute_efficient_frontier(sorted_items)

    # Solve exact 0/1 Knapsack DP for optimal subset selection
    optimal_selected_ids = solve_01_knapsack_dp(sorted_items, budget_dev_weeks)

    allocated_cost = 0.0
    accumulated_risk = 0.0
    selected_count = 0

    running_cost = 0.0
    running_risk = 0.0
    for item in sorted_items:
        if item.asset_id in optimal_selected_ids:
            item.is_selected = True
            allocated_cost = round(allocated_cost + item.cost_dev_weeks, 2)
            accumulated_risk += item.delta_r
            selected_count += 1

        if item.delta_r > 0:
            running_cost = round(running_cost + item.cost_dev_weeks, 2)
            running_risk += item.delta_r
        item.cumulative_cost_weeks = running_cost
        item.cumulative_risk_pct = round(
            (running_risk / total_estate_risk * 100.0) if total_estate_risk > 0 else 100.0,
            1,
        )

    risk_reduction_pct = round(
        (accumulated_risk / total_estate_risk * 100.0) if total_estate_risk > 0 else 100.0,
        1,
    )

    return ParetoPortfolioResult(
        budget_dev_weeks=budget_dev_weeks,
        total_assets_count=len(sorted_items),
        selected_count=selected_count,
        total_cost_allocated=allocated_cost,
        total_risk_reduced=round(accumulated_risk, 2),
        total_estate_risk=round(total_estate_risk, 2),
        risk_reduction_pct=risk_reduction_pct,
        items=sorted_items,
        frontier_points=frontier_points,
    )
