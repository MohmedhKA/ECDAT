import pytest
from ecdat.models import CryptoAsset, MoscaScore, PrimitiveType, XTier
from ecdat.agility.recommender import recommend_pqc_migration
from ecdat.agility.buffer_audit import BufferHazard
from ecdat.mosca.engine import compute_mosca_score
from ecdat.contagion.engine import analyze_contagion
from ecdat.dashboard.generator import generate_html_dashboard, generate_html_report

def test_dashboard_html_generation(tmp_path):
    # Setup sample asset and score
    asset = CryptoAsset(
        asset_id="ASSET-TEST-001",
        component_name="payment_gateway",
        algorithm="ECDSA-P256",
        key_size=256,
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="gateway.py",
        line_number=42,
        x_tier=XTier.OPERATIONAL,
    )
    score = compute_mosca_score(asset)
    rec = recommend_pqc_migration(asset)
    assessments = [(asset, score, rec)]

    hazards = [
        BufferHazard(
            variable_name="sig_buf",
            allocated_bytes=64,
            required_bytes_pqc=3309,
            line_number=50,
            severity="CRITICAL",
            message="Fixed 64 B buffer too small for ML-DSA-65",
        )
    ]

    merkle_root = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

    # Minimal contagion graph
    contagion_res = analyze_contagion(
        file_paths=["gateway.py"],
        crypto_assets=[asset],
    )

    proof_packages = [
        {
            "asset_id": "ASSET-TEST-001",
            "leaf_index": 0,
            "salt": "TEST_SALT",
            "sanitized_asset": {
                "algorithm": "ECDSA-P256",
                "component_name": "payment_gateway",
            },
            "authentication_path": [],
        }
    ]

    html_content = generate_html_report(
        assessments=assessments,
        buffer_hazards=hazards,
        merkle_root_hex=merkle_root,
        contagion_result=contagion_res,
        proof_packages=proof_packages,
        ciso_report_md="# Sample Executive CISO Report",
    )

    assert "<!DOCTYPE html>" in html_content
    assert "ECDAT — Cryptographic Discovery & Attestation Report" in html_content
    assert merkle_root in html_content
    assert "ASSET-TEST-001" in html_content
    assert "payment_gateway" in html_content
    assert "gateway.py" in html_content
    assert "sig_buf" in html_content
    assert "crypto.subtle.digest" in html_content
    assert "d3.forceSimulation" in html_content
    assert "asset-drawer" in html_content
    assert "cbom-search" in html_content
    assert "Sample Executive CISO Report" in html_content

    # Verify alias works identically
    dashboard_alias = generate_html_dashboard(
        assessments=assessments,
        buffer_hazards=hazards,
        merkle_root_hex=merkle_root,
        contagion_result=contagion_res,
        proof_packages=proof_packages,
    )
    assert "<!DOCTYPE html>" in dashboard_alias
    assert "ECDAT" in dashboard_alias
