"""
Unit tests for ECDAT Negative Proof Certificate Generator (Pillar 6 Part B).
"""

from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    PrimitiveType,
    XTier,
    UnknownEntry,
)
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.attestation.negative_proof import (
    generate_negative_proof_certificate,
    verify_negative_proof_certificate,
)

def test_negative_proof_clean_perimeter():
    asset = CryptoAsset(
        asset_id="a1",
        component_name="api",
        algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="api.py",
        x_tier=XTier.SHORT_TERM,
    )
    score = MoscaScore(
        asset_id="a1",
        x_years_effective=1.0,
        z_regulatory_year=2030,
        z_regulatory_phase=3,
        z_physical_10yr_prob="Low",
        y_max_years=3.0,
        deadline_year=2029.0,
        risk_level="MEDIUM",
        crypto_shredding_viable=False,
        planning_note="clean",
    )
    rec = MigrationRecommendation(
        current_algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        recommended_hybrid="X25519 + ML-KEM-768",
        recommended_pqc_standalone="ML-KEM-768",
        target_standard="NIST FIPS 203",
        size_overhead_factor=3.0,
        security_level="NIST L3",
        implementation_guidance="Standard PQC migration",
    )
    unknowns = [
        UnknownEntry(
            item_path="node_modules",
            category="EXCLUDED_DIR",
            reason="Dependency tree boundary",
            recommended_action="Audit via package manifest",
        )
    ]

    cert = generate_negative_proof_certificate(
        assessments=[(asset, score, rec)],
        unknowns_ledger=unknowns,
        target_path="/testbeds/sample_app",
        merkle_root_hex="abc123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    assert cert.is_certified_clean is True
    assert cert.quarantined_unknowns_count == 1
    assert verify_negative_proof_certificate(cert) is True

def test_negative_proof_flags_forbidden_des():
    asset_des = CryptoAsset(
        asset_id="a_des",
        component_name="legacy",
        algorithm="DES",
        primitive_type=PrimitiveType.ENCRYPTION,
        file_path="legacy.py",
        x_tier=XTier.ARCHIVAL,
    )
    score = MoscaScore(
        asset_id="a_des",
        x_years_effective=5.0,
        z_regulatory_year=2025,
        z_regulatory_phase=5,
        z_physical_10yr_prob="High",
        y_max_years=-1.0,
        deadline_year=2024.0,
        risk_level="CRITICAL",
        crypto_shredding_viable=False,
        planning_note="Forbidden cipher",
    )
    rec = MigrationRecommendation(
        current_algorithm="DES",
        primitive_type=PrimitiveType.ENCRYPTION,
        recommended_hybrid="AES-256-GCM",
        recommended_pqc_standalone="AES-256-GCM",
        target_standard="FIPS 197",
        size_overhead_factor=1.0,
        security_level="FIPS 197",
        implementation_guidance="Replace DES immediately",
    )

    cert = generate_negative_proof_certificate(
        assessments=[(asset_des, score, rec)],
        unknowns_ledger=[],
        target_path="/testbeds/legacy_app",
        merkle_root_hex="1111111111111111111111111111111111111111111111111111111111111111",
    )

    assert cert.is_certified_clean is False
    assert cert.assertions[0]["status"] == "FAILED"
    assert verify_negative_proof_certificate(cert) is False

def test_negative_proof_flags_forbidden_md5():
    asset_md5 = CryptoAsset(
        asset_id="a_md5",
        component_name="hasher",
        algorithm="MD5",
        primitive_type=PrimitiveType.HASH,
        file_path="hasher.py",
        x_tier=XTier.EPHEMERAL,
    )
    score = MoscaScore(
        asset_id="a_md5",
        x_years_effective=0.1,
        z_regulatory_year=2024,
        z_regulatory_phase=5,
        z_physical_10yr_prob="High",
        y_max_years=-1.0,
        deadline_year=2024.0,
        risk_level="CRITICAL",
        crypto_shredding_viable=False,
        planning_note="Forbidden broken hash",
    )
    rec = MigrationRecommendation(
        current_algorithm="MD5",
        primitive_type=PrimitiveType.HASH,
        recommended_hybrid="SHA-256",
        recommended_pqc_standalone="SHA-256",
        target_standard="FIPS 180-4",
        size_overhead_factor=1.0,
        security_level="NIST L1",
        implementation_guidance="Replace MD5 immediately",
    )

    cert = generate_negative_proof_certificate(
        assessments=[(asset_md5, score, rec)],
        unknowns_ledger=[],
        target_path="/testbeds/broken_app",
        merkle_root_hex="2222222222222222222222222222222222222222222222222222222222222222",
    )

    assert cert.is_certified_clean is False
    assert cert.assertions[0]["status"] == "FAILED"
    assert "MD5" in cert.assertions[0]["details"]
    assert verify_negative_proof_certificate(cert) is False
