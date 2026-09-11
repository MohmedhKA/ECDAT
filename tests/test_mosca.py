import pytest
from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.mosca.engine import compute_mosca_score, evaluate_regulatory_z
from ecdat.constants import CURRENT_YEAR

def test_regulatory_z_mapping():
    kem_asset = CryptoAsset(
        asset_id="asset-1",
        component_name="auth-service",
        algorithm="ECDH-P256",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/auth/tls.py",
        x_tier=XTier.EPHEMERAL,
    )
    year, phase = evaluate_regulatory_z(kem_asset)
    assert year == 2030
    assert phase == 3

    sig_asset = CryptoAsset(
        asset_id="asset-2",
        component_name="ledger-service",
        algorithm="ECDSA-P256",
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/ledger/signer.py",
        x_tier=XTier.OPERATIONAL,
    )
    year, phase = evaluate_regulatory_z(sig_asset)
    assert year == 2031
    assert phase == 4

def test_mosca_ephemeral_vs_archival():
    # Ephemeral Key Exchange (TLS session)
    ephemeral_asset = CryptoAsset(
        asset_id="asset-ephemeral",
        component_name="gateway",
        algorithm="X25519",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/net/tls.py",
        x_tier=XTier.EPHEMERAL,
    )
    score_e = compute_mosca_score(ephemeral_asset, current_year=2026)
    assert score_e.x_years_effective == 0.0
    assert score_e.z_regulatory_year == 2030
    assert score_e.y_max_years == 4.0
    assert score_e.risk_level in ["MEDIUM", "LOW"]
    assert not score_e.crypto_shredding_viable

    # Archival Key Exchange (Encrypted backup)
    archival_asset = CryptoAsset(
        asset_id="asset-archival",
        component_name="db-backup",
        algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/db/backup.py",
        x_tier=XTier.ARCHIVAL,
    )
    score_a = compute_mosca_score(archival_asset, current_year=2026)
    assert score_a.x_years_effective == 10.0
    assert score_a.z_regulatory_year == 2030
    assert score_a.y_max_years == -6.0
    assert score_a.risk_level == "CRITICAL"
    assert "HNDL WINDOW OPEN" in score_a.planning_note

def test_crypto_shredding_lever():
    archival_shredded = CryptoAsset(
        asset_id="asset-shredded",
        component_name="db-backup",
        algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/db/backup.py",
        x_tier=XTier.ARCHIVAL,
        has_crypto_shredding=True,
    )
    score = compute_mosca_score(archival_shredded, current_year=2026)
    assert score.x_years_effective == 1.5
    assert score.crypto_shredding_viable is True
    # 2030 - 2026 = 4.0; 4.0 - 1.5 = 2.5
    assert score.y_max_years == 2.5
    assert score.risk_level == "HIGH"
    assert "LEVER APPLIED" in score.planning_note

def test_operational_signature_asset():
    sig_asset = CryptoAsset(
        asset_id="asset-doc-signer",
        component_name="doc-service",
        algorithm="ECDSA-P256",
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/docs/sign.py",
        x_tier=XTier.OPERATIONAL,
    )
    # Z = 2031 (Phase 4). Years to mandate = 5.0. X = 5.0 -> Y_max = 0.0
    score = compute_mosca_score(sig_asset, current_year=2026)
    assert score.x_years_effective == 5.0
    assert score.z_regulatory_year == 2031
    assert score.y_max_years == 0.0
    assert score.risk_level == "CRITICAL"
    assert score.deadline_year == 2026.0

def test_custom_override_x():
    asset = CryptoAsset(
        asset_id="asset-custom",
        component_name="custom-worker",
        algorithm="ECDH-P384",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/custom.py",
        x_tier=XTier.HUMAN_REVIEW,
    )
    score = compute_mosca_score(asset, override_x_years=2.0, current_year=2026)
    assert score.x_years_effective == 2.0
    # 2030 - 2026 = 4.0; 4.0 - 2.0 = 2.0
    assert score.y_max_years == 2.0
    assert score.risk_level == "HIGH"
