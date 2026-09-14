"""
Unit tests for ECDAT Stochastic Monte Carlo Mosca Simulator.
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
from ecdat.mosca.stochastic import (
    simulate_asset_stochastic_mosca,
    simulate_estate_stochastic_mosca,
)

def test_stochastic_simulation_archival_rsa():
    asset = CryptoAsset(
        asset_id="asset-rsa-archival",
        component_name="identity-vault",
        algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="vault/keys.py",
        x_tier=XTier.ARCHIVAL,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        exposure_profile=ExposureProfile.PUBLIC,
        p_hndl=1.0,
    )
    score = MoscaScore(
        asset_id="asset-rsa-archival",
        x_years_effective=10.0, # 10 years of required confidentiality
        z_regulatory_year=2030,
        z_regulatory_phase=3,
        z_physical_10yr_prob="High",
        y_max_years=-6.0,
        deadline_year=2024.0,
        risk_level="CRITICAL",
        crypto_shredding_viable=False,
        planning_note="Critical archival risk",
    )

    res = simulate_asset_stochastic_mosca(asset, score, iterations=2000, current_year=2026)

    assert res.iterations == 2000
    # For archival data (10y) + migration (2y) = 12y from 2026 => 2038, which exceeds GRI mode (2030-2034)
    assert res.breach_probability > 0.60
    assert res.risk_category == "CRITICAL"
    assert res.p95_safety_margin_years < 0.0

def test_stochastic_simulation_post_quantum_safe():
    asset = CryptoAsset(
        asset_id="asset-mlkem-safe",
        component_name="pqc-gateway",
        algorithm="ML-KEM-768",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="gateway/kem.py",
        x_tier=XTier.OPERATIONAL,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        exposure_profile=ExposureProfile.PUBLIC,
        p_hndl=1.0,
    )
    score = MoscaScore(
        asset_id="asset-mlkem-safe",
        x_years_effective=5.0,
        z_regulatory_year=2050,
        z_regulatory_phase=0,
        z_physical_10yr_prob="None",
        y_max_years=20.0,
        deadline_year=2045.0,
        risk_level="LOW",
        crypto_shredding_viable=False,
        planning_note="PQC Safe",
    )

    res = simulate_asset_stochastic_mosca(asset, score, iterations=1000, current_year=2026)
    assert res.breach_probability == 0.0
    assert res.risk_category == "LOW"

def test_simulate_estate_stochastic():
    a1 = CryptoAsset(
        asset_id="a1", component_name="auth", algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE, file_path="auth.py",
        x_tier=XTier.ARCHIVAL, intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
    )
    s1 = MoscaScore(
        asset_id="a1", x_years_effective=8.0, z_regulatory_year=2030,
        z_regulatory_phase=3, z_physical_10yr_prob="High", y_max_years=-4.0,
        deadline_year=2024.0, risk_level="CRITICAL", crypto_shredding_viable=False,
        planning_note="test",
    )

    a2 = CryptoAsset(
        asset_id="a2", component_name="web", algorithm="SHA-256",
        primitive_type=PrimitiveType.HASH, file_path="web.py",
        x_tier=XTier.EPHEMERAL, intent_class=IntentClass.INTEGRITY_CHECKSUM,
    )
    s2 = MoscaScore(
        asset_id="a2", x_years_effective=0.1, z_regulatory_year=2050,
        z_regulatory_phase=0, z_physical_10yr_prob="None", y_max_years=24.0,
        deadline_year=2050.0, risk_level="LOW", crypto_shredding_viable=False,
        planning_note="test",
    )

    estate = simulate_estate_stochastic_mosca([(a1, s1, None), (a2, s2, None)], iterations=1000)

    assert estate["total_simulated_assets"] == 2
    assert estate["critical_probabilistic_assets"] >= 1
    assert len(estate["results"]) == 2
