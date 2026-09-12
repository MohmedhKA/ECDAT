import pytest
from ecdat.models import CryptoAsset, PrimitiveType, XTier, IntentClass, AgilityLevel, ExposureProfile
from ecdat.mosca.engine import compute_mosca_score

def test_operational_utility_alert_suppression():
    asset = CryptoAsset(
        asset_id="asset-etag-01",
        component_name="web:etag",
        algorithm="SHA-256",
        key_size=256,
        primitive_type=PrimitiveType.HASH,
        file_path="src/web/handler.py",
        x_tier=XTier.EPHEMERAL,
        intent_class=IntentClass.OPERATIONAL_UTILITY,
    )
    score = compute_mosca_score(asset, current_year=2026)
    assert score.r_q_score == 0.0
    assert score.risk_level == "LOW"
    assert "OPERATIONAL UTILITY" in score.planning_note

def test_airgapped_deployment_suppression():
    # Classical RSA-2048 with archival data, but airgapped deployment
    asset = CryptoAsset(
        asset_id="asset-airgap-01",
        component_name="airgap:keys",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/airgap/crypto.py",
        x_tier=XTier.ARCHIVAL,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        exposure_profile=ExposureProfile.AIRGAPPED,
        p_hndl=0.0,
    )
    score = compute_mosca_score(asset, current_year=2026)
    assert score.r_q_score == 0.0
    assert score.risk_level == "LOW"
    assert "AIRGAPPED" in score.planning_note

def test_cams_agility_discount_applied():
    # Compare rigid (CAMS 0) vs runtime agile (CAMS 3)
    rigid_asset = CryptoAsset(
        asset_id="asset-rigid",
        component_name="api:rigid",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/api.py",
        x_tier=XTier.OPERATIONAL,
        agility_level=AgilityLevel.RIGID,
        p_hndl=1.0,
    )
    rigid_score = compute_mosca_score(rigid_asset, current_year=2026)

    agile_asset = CryptoAsset(
        asset_id="asset-agile",
        component_name="api:agile",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/api.py",
        x_tier=XTier.OPERATIONAL,
        agility_level=AgilityLevel.RUNTIME_AGILE,
        p_hndl=1.0,
    )
    agile_score = compute_mosca_score(agile_asset, current_year=2026)

    assert agile_score.agility_factor == 0.85
    assert agile_score.r_q_score < rigid_score.r_q_score
