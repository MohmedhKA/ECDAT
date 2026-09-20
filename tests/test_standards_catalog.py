"""
Tests for ECDAT Declarative PQC Standards Catalog and Fine-Grained Recommender.
ZERO-REGEX ENFORCED: String operations, token streams, and AST lookups only.
"""

from pathlib import Path
import pytest
from ecdat.models import CryptoAsset, PrimitiveType, IntentClass, XTier, RouteProfile
from ecdat.network.mtu_prober import probe_network_mtu
from ecdat.agility.standards_catalog import (
    PQCStandardsCatalog,
    PQCAlgorithmSpec,
    MigrationRecommendation,
)
from ecdat.agility.recommender import AgilityRecommender, recommend_pqc_migration


def test_load_default_standards():
    """Verify that the declarative JSON catalog loads all required PQC standards."""
    catalog = PQCStandardsCatalog.load_default()
    assert catalog is not None

    required_standards = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHA2-256s",
        "Composite-KEM",
        "Composite-Sign",
    ]

    for name in required_standards:
        spec = catalog.get_spec(name)
        assert spec is not None, f"Standard {name} not found in catalog"
        assert spec.name.upper() == name.upper()
        assert spec.standard_org in ["NIST", "IETF", "NIST / IETF"]
        assert spec.security_level in [1, 2, 3, 5]
        assert spec.public_key_bytes > 0
        assert spec.ciphertext_or_signature_bytes > 0
        assert len(spec.replacement_targets) > 0
        assert spec.performance_rating in ["VERY_FAST", "FAST", "BALANCED", "MODERATE", "SLOW", "VERY_SLOW"]


def test_exact_spec_parameters():
    """Verify exact parameter sizes per NIST FIPS 203, 204, 205 and RFC 9180."""
    catalog = PQCStandardsCatalog.load_default()

    # ML-KEM parameters (FIPS 203)
    kem512 = catalog.get_spec("ML-KEM-512")
    assert kem512.public_key_bytes == 800
    assert kem512.ciphertext_or_signature_bytes == 768
    assert kem512.shared_secret_bytes == 32
    assert kem512.security_level == 1

    kem768 = catalog.get_spec("ML-KEM-768")
    assert kem768.public_key_bytes == 1184
    assert kem768.ciphertext_or_signature_bytes == 1088
    assert kem768.shared_secret_bytes == 32
    assert kem768.security_level == 3
    assert kem768.is_primary is True

    kem1024 = catalog.get_spec("ML-KEM-1024")
    assert kem1024.public_key_bytes == 1568
    assert kem1024.ciphertext_or_signature_bytes == 1568
    assert kem1024.shared_secret_bytes == 32
    assert kem1024.security_level == 5

    # ML-DSA parameters (FIPS 204)
    dsa44 = catalog.get_spec("ML-DSA-44")
    assert dsa44.public_key_bytes == 1312
    assert dsa44.ciphertext_or_signature_bytes == 2420
    assert dsa44.security_level == 2

    dsa65 = catalog.get_spec("ML-DSA-65")
    assert dsa65.public_key_bytes == 1952
    assert dsa65.ciphertext_or_signature_bytes == 3309
    assert dsa65.security_level == 3
    assert dsa65.is_primary is True

    dsa87 = catalog.get_spec("ML-DSA-87")
    assert dsa87.public_key_bytes == 2592
    assert dsa87.ciphertext_or_signature_bytes == 4627
    assert dsa87.security_level == 5

    # SLH-DSA parameters (FIPS 205)
    slh128s = catalog.get_spec("SLH-DSA-SHA2-128s")
    assert slh128s.public_key_bytes == 32
    assert slh128s.ciphertext_or_signature_bytes == 7856
    assert slh128s.security_level == 1

    slh256s = catalog.get_spec("SLH-DSA-SHA2-256s")
    assert slh256s.public_key_bytes == 64
    assert slh256s.ciphertext_or_signature_bytes == 29792
    assert slh256s.security_level == 5

    # Hybrid Composites (RFC 9180)
    ckem = catalog.get_spec("Composite-KEM")
    assert ckem.public_key_bytes == 1216
    assert ckem.ciphertext_or_signature_bytes == 1120
    assert ckem.security_level == 3

    csign = catalog.get_spec("Composite-Sign")
    assert csign.public_key_bytes == 2016
    assert csign.ciphertext_or_signature_bytes == 3373
    assert csign.security_level == 3


def test_case_insensitive_zero_regex_lookup():
    """Verify case-insensitive lookup without regular expressions."""
    catalog = PQCStandardsCatalog.load_default()

    assert catalog.get_spec("ml-kem-768") is not None
    assert catalog.get_spec("ML_KEM_768") is not None
    assert catalog.get_spec("Ml-Kem-768") is not None
    assert catalog.get_spec("ml-dsa-65") is not None
    assert catalog.get_spec("ML_DSA_65") is not None
    assert catalog.get_spec("composite-kem") is not None
    assert catalog.get_spec("COMPOSITE-SIGN") is not None
    assert catalog.get_spec("nonexistent_algo") is None


def test_dynamic_standard_registration():
    """Verify adding dynamic PQC standards at runtime without modifying code."""
    catalog = PQCStandardsCatalog.load_default()

    custom_spec = PQCAlgorithmSpec(
        name="BIKE-L1",
        standard_org="NIST",
        standard_ref="Round 4 Candidate",
        category="KEM",
        security_level=1,
        public_key_bytes=1541,
        ciphertext_or_signature_bytes=1573,
        shared_secret_bytes=32,
        replacement_targets=["RSA-2048", "ECDH-P256"],
        performance_rating="FAST",
        is_primary=False,
        description="BIKE Round 4 KEM specification",
    )

    catalog.register_standard(custom_spec)
    retrieved = catalog.get_spec("bike-l1")
    assert retrieved is not None
    assert retrieved.name == "BIKE-L1"
    assert retrieved.public_key_bytes == 1541
    assert retrieved.ciphertext_or_signature_bytes == 1573


def test_fine_grained_recommendation_rsa2048():
    """Verify fine-grained recommendations for RSA-2048."""
    catalog = PQCStandardsCatalog.load_default()

    # RSA-2048 for key exchange / confidentiality
    asset_kem = CryptoAsset(
        asset_id="rsa-kem-1",
        component_name="gateway",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        file_path="gateway/tls.py",
        x_tier=XTier.EPHEMERAL,
    )
    rec_kem = catalog.recommend_for_asset(asset_kem)
    assert "ML-KEM-768" in rec_kem.recommended_pqc_standalone
    assert "Composite" in rec_kem.recommended_hybrid or "X25519MLKEM768" in rec_kem.recommended_hybrid
    assert rec_kem.target_pqc_spec is not None
    assert rec_kem.target_pqc_spec.name == "ML-KEM-768"

    # RSA-2048 for signature / authentication
    asset_sig = CryptoAsset(
        asset_id="rsa-sig-1",
        component_name="auth",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.SIGNATURE,
        intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
        file_path="auth/jwt.py",
        x_tier=XTier.OPERATIONAL,
    )
    rec_sig = catalog.recommend_for_asset(asset_sig)
    assert "ML-DSA-65" in rec_sig.recommended_pqc_standalone
    assert "Composite" in rec_sig.recommended_hybrid or "ML-DSA" in rec_sig.recommended_hybrid
    assert rec_sig.target_pqc_spec is not None
    assert rec_sig.target_pqc_spec.name == "ML-DSA-65"


def test_fine_grained_recommendation_rsa4096():
    """Verify fine-grained recommendations for high-security RSA-4096 (Level 5)."""
    catalog = PQCStandardsCatalog.load_default()

    # RSA-4096 for key exchange / confidentiality
    asset_kem = CryptoAsset(
        asset_id="rsa-kem-4096",
        component_name="vault",
        algorithm="RSA-4096",
        key_size=4096,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        file_path="vault/keys.py",
        x_tier=XTier.ARCHIVAL,
    )
    rec_kem = catalog.recommend_for_asset(asset_kem)
    assert "ML-KEM-1024" in rec_kem.recommended_pqc_standalone
    assert "Category 5" in rec_kem.security_level or "Level 5" in rec_kem.security_level
    assert rec_kem.target_pqc_spec is not None
    assert rec_kem.target_pqc_spec.name == "ML-KEM-1024"

    # RSA-4096 for signature / authentication
    asset_sig = CryptoAsset(
        asset_id="rsa-sig-4096",
        component_name="root-ca",
        algorithm="RSA-4096",
        key_size=4096,
        primitive_type=PrimitiveType.SIGNATURE,
        intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
        file_path="ca/root.py",
        x_tier=XTier.ARCHIVAL,
    )
    rec_sig = catalog.recommend_for_asset(asset_sig)
    assert "ML-DSA-87" in rec_sig.recommended_pqc_standalone
    assert "Category 5" in rec_sig.security_level or "Level 5" in rec_sig.security_level
    assert rec_sig.target_pqc_spec is not None
    assert rec_sig.target_pqc_spec.name == "ML-DSA-87"


def test_fine_grained_recommendation_ecdsa():
    """Verify fine-grained recommendations for ECDSA P-256 and ECDSA P-384."""
    catalog = PQCStandardsCatalog.load_default()

    # ECDSA P-256
    asset_p256 = CryptoAsset(
        asset_id="ecdsa-p256",
        component_name="signer",
        algorithm="ECDSA-P256",
        key_size=256,
        primitive_type=PrimitiveType.SIGNATURE,
        intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
        file_path="signer/token.py",
        x_tier=XTier.OPERATIONAL,
    )
    rec_p256 = catalog.recommend_for_asset(asset_p256)
    assert "ML-DSA-65" in rec_p256.recommended_pqc_standalone
    assert "Composite" in rec_p256.recommended_hybrid
    assert rec_p256.target_pqc_spec is not None
    assert rec_p256.target_pqc_spec.name == "ML-DSA-65"

    # ECDSA P-384
    asset_p384 = CryptoAsset(
        asset_id="ecdsa-p384",
        component_name="signer-high",
        algorithm="ECDSA-P384",
        key_size=384,
        primitive_type=PrimitiveType.SIGNATURE,
        intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
        file_path="signer/high.py",
        x_tier=XTier.OPERATIONAL,
    )
    rec_p384 = catalog.recommend_for_asset(asset_p384)
    assert "ML-DSA-65" in rec_p384.recommended_pqc_standalone
    assert rec_p384.target_pqc_spec is not None
    assert rec_p384.target_pqc_spec.name == "ML-DSA-65"


def test_fine_grained_recommendation_dh_ecdh():
    """Verify fine-grained recommendations for Diffie-Hellman / ECDH."""
    catalog = PQCStandardsCatalog.load_default()

    # ECDH-P256 Standard Route
    asset_ecdh = CryptoAsset(
        asset_id="ecdh-p256",
        component_name="tls",
        algorithm="ECDH-P256",
        key_size=256,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        file_path="tls/handshake.py",
        x_tier=XTier.EPHEMERAL,
    )
    pmtu_std = probe_network_mtu(override_profile=RouteProfile.STANDARD, override_mtu=1500)
    rec_ecdh = catalog.recommend_for_asset(asset_ecdh, path_mtu=pmtu_std)
    assert "ML-KEM-768" in rec_ecdh.recommended_pqc_standalone
    assert rec_ecdh.target_pqc_spec is not None
    assert rec_ecdh.target_pqc_spec.name == "ML-KEM-768"

    # ECDH-P256 Constrained Route (< 1280 B MTU) -> ML-KEM-512
    pmtu_constrained = probe_network_mtu(override_profile=RouteProfile.CONSTRAINED, override_mtu=1200)
    rec_ecdh_c = catalog.recommend_for_asset(asset_ecdh, path_mtu=pmtu_constrained)
    assert "ML-KEM-512" in rec_ecdh_c.recommended_pqc_standalone
    assert rec_ecdh_c.target_pqc_spec is not None
    assert rec_ecdh_c.target_pqc_spec.name == "ML-KEM-512"

    # DH-2048
    asset_dh = CryptoAsset(
        asset_id="dh-2048",
        component_name="legacy-tls",
        algorithm="DH-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        file_path="tls/legacy.py",
        x_tier=XTier.SHORT_TERM,
    )
    rec_dh = catalog.recommend_for_asset(asset_dh)
    assert "ML-KEM-768" in rec_dh.recommended_pqc_standalone
    assert rec_dh.target_pqc_spec is not None
    assert rec_dh.target_pqc_spec.name == "ML-KEM-768"


def test_agility_recommender_class():
    """Verify AgilityRecommender wraps the catalog and integrates seamlessly."""
    recommender = AgilityRecommender()
    asset = CryptoAsset(
        asset_id="asset-test",
        component_name="auth",
        algorithm="ECDSA-P256",
        key_size=256,
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="auth.py",
    )
    rec = recommender.recommend(asset)
    assert isinstance(rec, MigrationRecommendation)
    assert "ML-DSA-65" in rec.recommended_pqc_standalone
    assert rec.target_pqc_spec is not None


def test_zero_regex_compliance_strict():
    """
    STRICT ZERO-REGEX AUDIT:
    Verifies that no regular expression modules or pattern methods exist
    in the newly created or modified files.
    Uses pure string inspection without regular expressions.
    """
    files_to_check = [
        Path("/home/mohmedh/personal/ECDAT/ecdat/agility/standards_catalog.py"),
        Path("/home/mohmedh/personal/ECDAT/ecdat/agility/recommender.py"),
        Path("/home/mohmedh/personal/ECDAT/tests/test_standards_catalog.py"),
    ]

    # Construct prohibited tokens without literal occurrences in this file
    mod_name = "r" + "e"
    prohibited_tokens = [
        "import " + mod_name + "\n",
        "import " + mod_name + " ",
        "from " + mod_name + " import",
        mod_name + ".compile",
        mod_name + ".search",
        mod_name + ".match",
        mod_name + ".sub",
        mod_name + ".findall",
        mod_name + ".finditer",
        mod_name + ".split",
    ]

    for file_path in files_to_check:
        if not file_path.exists():
            continue
        content = file_path.read_text(encoding="utf-8")
        for token in prohibited_tokens:
            assert token not in content, (
                f"Zero-regex violation: Found prohibited token '{token.strip()}' in {file_path}"
            )
