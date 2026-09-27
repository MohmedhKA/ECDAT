"""
Unit tests for ECDAT Scope Distinction (Production vs Test Fixture)
and MITRE CWE Vulnerability Taxonomy resolution.
"""

from pathlib import Path
from ecdat.models import AssetScope, PrimitiveType, XTier, EvidenceLevel
from ecdat.scanners.filters import is_test_file_path
from ecdat.scanners.factory import CryptoAssetFactory
from ecdat.attestation.cyclonedx_966 import enrich_cyclonedx_component_966
from ecdat.mosca.engine import compute_mosca_score
from ecdat.agility.recommender import recommend_pqc_migration
from ecdat.rules.signature_db import get_signature_db


def test_is_test_file_path_multi_ecosystem():
    # Java test files
    assert is_test_file_path("src/test/java/org/apache/activemq/broker/BrokerTest.java") is True
    assert is_test_file_path("src/test/java/org/apache/activemq/transport/tcp/SslTransportTest.java") is True
    assert is_test_file_path("activemq-unit-tests/src/test/java/MockRandom.java") is True
    assert is_test_file_path("src/main/java/org/apache/activemq/broker/BrokerService.java") is False
    assert is_test_file_path("src/main/java/org/apache/activemq/transport/tcp/SslTransportFactory.java") is False

    # Python test files
    assert is_test_file_path("tests/test_crypto.py") is True
    assert is_test_file_path("ecdat/tests/unit_test.py") is True
    assert is_test_file_path("ecdat/models.py") is False

    # Go test files
    assert is_test_file_path("pkg/crypto/signer_test.go") is True
    assert is_test_file_path("pkg/crypto/signer.go") is False

    # JavaScript / TypeScript test files
    assert is_test_file_path("test/cipher.test.js") is True
    assert is_test_file_path("src/__tests__/auth.spec.ts") is True
    assert is_test_file_path("src/services/crypto.ts") is False

    # Rust test files
    assert is_test_file_path("tests/integration_test.rs") is True
    assert is_test_file_path("benches/bench.rs") is True
    assert is_test_file_path("src/lib.rs") is False


def test_crypto_asset_factory_scope_and_cwe():
    # Production Asset
    prod_asset = CryptoAssetFactory.create_asset(
        asset_prefix="PROD",
        index=1,
        component_name="ActiveMQSslContext",
        algorithm="TLSv1.2",
        key_size=None,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/main/java/org/apache/activemq/transport/tcp/SslTransportFactory.java",
        line_number=45,
        tier=XTier.TRANSIENT,
        has_shredding=False,
        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
        evidence_source="ast:call",
        matched_code="SSLContext.getInstance(\"TLSv1.2\")",
        language="java",
    )
    assert prod_asset.scope == AssetScope.PRODUCTION
    assert prod_asset.cwe_id == "CWE-327"
    assert "Broken or Risky" in prod_asset.cwe_name

    # Test Fixture Asset with Weak PRNG
    test_asset = CryptoAssetFactory.create_asset(
        asset_prefix="TEST",
        index=2,
        component_name="FuzzRandomGenerator",
        algorithm="UNTRUSTED-PRNG",
        key_size=None,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/test/java/org/apache/activemq/broker/BenchmarkFuzzerTest.java",
        line_number=88,
        tier=XTier.TRANSIENT,
        has_shredding=False,
        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
        evidence_source="ast:call",
        matched_code="new java.util.Random()",
        language="java",
        cwe="UNTRUSTED-PRNG",
    )
    assert test_asset.scope == AssetScope.TEST_FIXTURE
    assert test_asset.cwe_id == "CWE-338"
    assert "Weak Pseudo-Random Number Generator" in test_asset.cwe_name


def test_cyclonedx_component_enrichment_scope_and_cwe():
    test_asset = CryptoAssetFactory.create_asset(
        asset_prefix="TEST",
        index=3,
        component_name="MockKeystoreSecret",
        algorithm="PREDICTABLE-KEYSTORE-PASSWORD",
        key_size=None,
        primitive_type=PrimitiveType.ENCRYPTION,
        file_path="src/test/java/org/apache/activemq/transport/tcp/TestKeystore.java",
        line_number=30,
        tier=XTier.SHORT_TERM,
        has_shredding=False,
        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
        evidence_source="ast:call",
        matched_code="keystore.load(is, \"password\".toCharArray())",
        language="java",
        cwe="PREDICTABLE-KEYSTORE-PASSWORD",
    )

    score = compute_mosca_score(test_asset, current_year=2026)
    rec = recommend_pqc_migration(test_asset)

    comp = {
        "type": "cryptographic-asset",
        "name": test_asset.component_name,
        "bom-ref": test_asset.asset_id,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "name": test_asset.algorithm,
                "keyLength": None,
                "primitive": test_asset.primitive_type.value,
            },
        },
    }

    enriched = enrich_cyclonedx_component_966(comp, test_asset, score, rec)
    # CycloneDX 1.6 Standard Scope
    assert enriched["scope"] == "optional"

    # Properties
    props = {p["name"]: p["value"] for p in enriched.get("properties", [])}
    assert props["ecdat:scope"] == "TEST_FIXTURE"
    assert props["ecdat:cwe_id"] == "CWE-259"
    assert "Hard-coded Password" in props["ecdat:cwe_name"]
