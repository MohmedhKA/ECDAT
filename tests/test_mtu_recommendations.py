import pytest
from ecdat.models import CryptoAsset, PrimitiveType, XTier, RouteProfile
from ecdat.network.mtu_prober import probe_network_mtu
from ecdat.agility.recommender import recommend_pqc_migration

def test_recommendation_standard_route():
    asset = CryptoAsset(
        asset_id="ASSET-001",
        component_name="api_gateway",
        algorithm="ECDH-P256",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="gateway.py",
        line_number=10,
        x_tier=XTier.EPHEMERAL,
    )
    pmtu = probe_network_mtu(override_profile=RouteProfile.STANDARD, override_mtu=1500)
    rec = recommend_pqc_migration(asset, path_mtu=pmtu)

    assert rec.path_profile == RouteProfile.STANDARD
    assert rec.mtu_constrained is False
    assert "ML-KEM-768" in rec.recommended_pqc_standalone
    assert "STANDARD_ROUTE" in rec.mtu_warning
    assert "ML-KEM-1024" in rec.mtu_warning

def test_recommendation_constrained_route_kem():
    asset = CryptoAsset(
        asset_id="ASSET-002",
        component_name="mobile_client",
        algorithm="ECDH-P256",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="client.py",
        line_number=20,
        x_tier=XTier.EPHEMERAL,
    )
    pmtu = probe_network_mtu(override_profile=RouteProfile.CONSTRAINED, override_mtu=1200)
    rec = recommend_pqc_migration(asset, path_mtu=pmtu)

    assert rec.path_profile == RouteProfile.CONSTRAINED
    assert rec.mtu_constrained is True
    assert "ML-KEM-512" in rec.recommended_pqc_standalone
    assert "RFC 8879" in rec.recommended_hybrid
    assert "CONSTRAINED_ROUTE" in rec.mtu_warning

def test_recommendation_constrained_route_signature():
    asset = CryptoAsset(
        asset_id="ASSET-003",
        component_name="auth_service",
        algorithm="ECDSA-P256",
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="auth.py",
        line_number=30,
        x_tier=XTier.EPHEMERAL,
    )
    pmtu = probe_network_mtu(override_profile=RouteProfile.CONSTRAINED, override_mtu=1200)
    rec = recommend_pqc_migration(asset, path_mtu=pmtu)

    assert rec.path_profile == RouteProfile.CONSTRAINED
    assert rec.mtu_constrained is True
    assert "CRITICAL_TRANSPORT_ALERT" in rec.mtu_warning
    assert "SLH-DSA-128s" in rec.mtu_warning
