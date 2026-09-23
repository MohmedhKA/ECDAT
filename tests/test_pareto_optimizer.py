"""
Unit tests for ECDAT Pareto Migration Portfolio Optimizer (Pillar 7).
"""

from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    PrimitiveType,
    XTier,
    AgilityLevel,
    IntentClass,
    ExposureProfile,
)
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.optimizer.pareto import (
    optimize_pareto_portfolio,
    compute_item_pareto_metrics,
    compute_efficient_frontier,
)

def test_pareto_metrics_critical_rsa_superspreader():
    asset = CryptoAsset(
        asset_id="asset-rsa-001",
        component_name="auth-service",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="auth/token.py",
        x_tier=XTier.ARCHIVAL,
        agility_level=AgilityLevel.RIGID,
        intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
        exposure_profile=ExposureProfile.PUBLIC,
        p_hndl=1.0,
    )
    score = MoscaScore(
        asset_id="asset-rsa-001",
        x_years_effective=10.0,
        z_regulatory_year=2030,
        z_regulatory_phase=3,
        z_physical_10yr_prob="High",
        y_max_years=-6.0,
        deadline_year=2024.0,
        risk_level="CRITICAL",
        crypto_shredding_viable=False,
        planning_note="Critical HNDL risk",
    )
    rec = MigrationRecommendation(
        current_algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        recommended_hybrid="X25519 + ML-KEM-768",
        recommended_pqc_standalone="ML-KEM-768",
        target_standard="NIST FIPS 203",
        size_overhead_factor=3.2,
        security_level="NIST Level 3",
        implementation_guidance="Migrate to hybrid KEM",
    )

    # R0 = 3 (superspreader infecting 3 downstream services)
    delta_r, cost, efficiency = compute_item_pareto_metrics(asset, score, rec, r0=3)

    # delta_r = r0(3) * p_hndl(1.0) * w_intent(1.0) * risk(10.0) = 30.0
    assert delta_r == 30.0
    # base cost 2.0 * fan_out(1.0 + 0.15 * 3 = 1.45) * CAMS L0(1.0) = 2.9
    assert cost == 2.9
    assert efficiency > 10.0

def test_pareto_suppresses_operational_utility():
    asset = CryptoAsset(
        asset_id="asset-md5-etag",
        component_name="web-cache",
        algorithm="MD5",
        primitive_type=PrimitiveType.HASH,
        file_path="cache/etag.py",
        x_tier=XTier.EPHEMERAL,
        agility_level=AgilityLevel.CONFIGURABLE,
        intent_class=IntentClass.OPERATIONAL_UTILITY,
        exposure_profile=ExposureProfile.PUBLIC,
        p_hndl=1.0,
    )
    score = MoscaScore(
        asset_id="asset-md5-etag",
        x_years_effective=0.0,
        z_regulatory_year=2035,
        z_regulatory_phase=5,
        z_physical_10yr_prob="Low",
        y_max_years=9.0,
        deadline_year=2035.0,
        risk_level="LOW",
        crypto_shredding_viable=False,
        planning_note="Operational utility",
    )
    rec = MigrationRecommendation(
        current_algorithm="MD5",
        primitive_type=PrimitiveType.HASH,
        recommended_hybrid="SHA-256",
        recommended_pqc_standalone="SHA-256",
        target_standard="FIPS 180-4",
        size_overhead_factor=1.0,
        security_level="Standard",
        implementation_guidance="Keep or replace with SHA-256",
    )

    delta_r, cost, efficiency = compute_item_pareto_metrics(asset, score, rec, r0=2)
    assert delta_r == 0.0
    assert efficiency == 0.0

def test_pareto_knapsack_portfolio_optimization():
    # Asset 1: High value, low cost (efficiency = 30 / 1.16 = 25.86)
    a1 = CryptoAsset(
        asset_id="a1", component_name="auth", algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE, file_path="auth.py",
        agility_level=AgilityLevel.PROVIDER, # CAMS L2 discount 0.4
        intent_class=IntentClass.AUTHENTICATION_SIGNATURE, p_hndl=1.0,
    )
    s1 = MoscaScore(
        asset_id="a1", x_years_effective=5.0, z_regulatory_year=2030,
        z_regulatory_phase=3, z_physical_10yr_prob="High", y_max_years=-1.0,
        deadline_year=2025.0, risk_level="CRITICAL", crypto_shredding_viable=False,
        planning_note="test",
    )
    r1 = MigrationRecommendation(
        current_algorithm="RSA-2048", primitive_type=PrimitiveType.KEY_EXCHANGE,
        recommended_hybrid="X25519+ML-KEM-768", recommended_pqc_standalone="ML-KEM-768",
        target_standard="FIPS 203", size_overhead_factor=3.0, security_level="L3",
        implementation_guidance="test",
    )

    # Asset 2: Lower value, rigid high cost
    a2 = CryptoAsset(
        asset_id="a2", component_name="storage", algorithm="3DES",
        primitive_type=PrimitiveType.ENCRYPTION, file_path="store.py",
        agility_level=AgilityLevel.RIGID,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE, p_hndl=1.0,
    )
    s2 = MoscaScore(
        asset_id="a2", x_years_effective=3.0, z_regulatory_year=2035,
        z_regulatory_phase=5, z_physical_10yr_prob="Medium", y_max_years=6.0,
        deadline_year=2032.0, risk_level="MEDIUM", crypto_shredding_viable=False,
        planning_note="test",
    )
    r2 = MigrationRecommendation(
        current_algorithm="3DES", primitive_type=PrimitiveType.ENCRYPTION,
        recommended_hybrid="AES-256-GCM", recommended_pqc_standalone="AES-256-GCM",
        target_standard="FIPS 197", size_overhead_factor=1.0, security_level="L5",
        implementation_guidance="test",
    )

    assessments = [(a1, s1, r1), (a2, s2, r2)]

    # Run optimizer with budget = 2.0 dev-weeks
    result = optimize_pareto_portfolio(assessments, budget_dev_weeks=2.0)

    assert result.total_assets_count == 2
    # a1 should be selected first due to higher efficiency
    assert result.selected_count >= 1
    assert result.items[0].asset_id == "a1"
    assert result.items[0].is_selected is True
    assert result.risk_reduction_pct > 0.0
    assert len(result.frontier_points) >= 2

def test_exact_01_knapsack_beats_greedy_heuristic():
    from ecdat.optimizer.pareto import solve_01_knapsack_dp
    from ecdat.models import ParetoItem

    # Classic knapsack counterexample where greedy-by-ratio is suboptimal:
    # Budget = 6.0 weeks
    # Item 1: cost 4.0, delta_r 10.0 (efficiency 2.5) -> greedy takes this first, leaves 2.0 budget, cannot take 2 & 3. Total = 10.0
    # Item 2: cost 3.0, delta_r 7.0 (efficiency 2.33)
    # Item 3: cost 3.0, delta_r 7.0 (efficiency 2.33)
    # Exact DP takes Item 2 + Item 3: cost 6.0, total delta_r = 14.0 (> 10.0)!
    items = [
        ParetoItem(
            asset_id="item-greedy-trap", component_name="trap", algorithm="RSA",
            primitive_type="SIGNATURE", file_path="t.py", line_number=1,
            r0_score=1, cams_level=0, risk_level="HIGH",
            delta_r=10.0, cost_dev_weeks=4.0, efficiency=2.5,
            is_selected=False, cumulative_risk_pct=0.0, cumulative_cost_weeks=0.0
        ),
        ParetoItem(
            asset_id="item-opt-1", component_name="opt1", algorithm="DES",
            primitive_type="ENCRYPTION", file_path="o1.py", line_number=2,
            r0_score=1, cams_level=0, risk_level="HIGH",
            delta_r=7.0, cost_dev_weeks=3.0, efficiency=2.33,
            is_selected=False, cumulative_risk_pct=0.0, cumulative_cost_weeks=0.0
        ),
        ParetoItem(
            asset_id="item-opt-2", component_name="opt2", algorithm="3DES",
            primitive_type="ENCRYPTION", file_path="o2.py", line_number=3,
            r0_score=1, cams_level=0, risk_level="HIGH",
            delta_r=7.0, cost_dev_weeks=3.0, efficiency=2.33,
            is_selected=False, cumulative_risk_pct=0.0, cumulative_cost_weeks=0.0
        ),
    ]

    selected_ids = solve_01_knapsack_dp(items, budget_weeks=6.0)
    # Exact DP must choose opt1 and opt2 (total value 14.0), not the greedy choice (total value 10.0)
    assert selected_ids == {"item-opt-1", "item-opt-2"}
    assert "item-greedy-trap" not in selected_ids
