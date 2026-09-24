import pytest
from pathlib import Path
from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.scanners.theia_bridge import (
    find_theia_binary,
    run_theia_scan,
    parse_theia_components,
)

@pytest.mark.skipif(
    find_theia_binary() is None,
    reason="cbomkit-theia binary is not vendored (see README / scripts/setup_theia.sh)"
)
def test_find_theia_binary():
    bin_path = find_theia_binary()
    assert bin_path is not None
    assert bin_path.is_file()
    assert "cbomkit-theia" in bin_path.name

def test_parse_theia_components_synthetic():
    mock_components = [
        {
            "name": "RSA-2048",
            "evidence": {"occurrences": [{"location": "certs/server.key"}]},
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "type": "private-key",
                    "size": 2048,
                    "format": "PEM",
                },
            },
        },
        {
            "name": "internal.service.org",
            "evidence": {"occurrences": [{"location": "certs/server.crt"}]},
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": "internal.service.org",
                    "notValidAfter": "2027-10-01T00:00:00Z",
                },
            },
        },
    ]

    assets = parse_theia_components(mock_components)
    assert len(assets) == 2

    key_asset = next(a for a in assets if "private-key" in a.component_name)
    assert key_asset.algorithm == "RSA-2048"
    assert key_asset.key_size == 2048
    assert key_asset.x_tier == XTier.ARCHIVAL

    cert_asset = next(a for a in assets if "x509_cert" in a.component_name)
    assert cert_asset.primitive_type == PrimitiveType.SIGNATURE
    assert cert_asset.x_tier == XTier.OPERATIONAL

def test_run_theia_scan_live_on_certs():
    repo_root = Path(__file__).resolve().parent.parent
    certs_dir = str(repo_root / "testbeds" / "sample_crypto_app" / "certs")
    assets = run_theia_scan(certs_dir)

    assert len(assets) >= 2
    algos = [a.algorithm for a in assets]
    assert any("RSA" in alg for alg in algos)
    assert all(isinstance(a, CryptoAsset) for a in assets)
    assert all(a.x_confidence == "HIGH" for a in assets)

def test_run_theia_scan_missing_dir():
    assets = run_theia_scan("/nonexistent/directory/path/12345")
    assert assets == []

def test_theia_skips_env_and_tokens():
    mock_components = [
        {
            "name": ".env_key",
            "evidence": {"occurrences": [{"location": ".env"}]},
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "type": "generic-api-key",
                    "size": 256,
                    "format": "RAW",
                },
            },
        },
        {
            "name": "SECRET_TOKEN",
            "evidence": {"occurrences": [{"location": "config/.env.local"}]},
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "type": "token",
                    "size": 256,
                    "format": "RAW",
                },
            },
        },
        {
            "name": "RSA-2048",
            "evidence": {"occurrences": [{"location": "certs/server.key"}]},
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "type": "private-key",
                    "size": 2048,
                    "format": "PEM",
                },
            },
        },
    ]

    assets = parse_theia_components(mock_components)
    # Only the genuine RSA-2048 private key should be admitted
    assert len(assets) == 1
    assert assets[0].algorithm == "RSA-2048"

def test_native_fallback_when_binary_absent():
    from pathlib import Path
    certs_dir = str(Path(__file__).resolve().parent.parent / "testbeds" / "sample_crypto_app" / "certs")
    # Force theia_bin to a non-existent path
    dummy_bin = Path("/tmp/non_existent_theia_binary_for_test_12345")
    assets = run_theia_scan(certs_dir, theia_bin=dummy_bin)
    assert len(assets) >= 1
    # Check that certs were discovered natively
    assert any("x509_cert" in a.component_name for a in assets)

def test_password_protected_p12_quarantined(tmp_path):
    # Create an encrypted/unparseable .p12 file
    p12_file = tmp_path / "keystore.p12"
    p12_file.write_bytes(b"\x30\x82\x04\x00\x02\x01\x03bogus_encrypted_pkcs12_data")

    unknowns_ledger = []
    dummy_bin = Path("/tmp/non_existent_theia_binary_for_test_12345")
    assets = run_theia_scan(str(tmp_path), theia_bin=dummy_bin, unknowns_ledger=unknowns_ledger)

    # Must not crash, and must quarantine the .p12 file to unknowns_ledger
    assert len(unknowns_ledger) == 1
    assert unknowns_ledger[0].category == "ENCRYPTED_KEYSTORE"
    assert "keystore.p12" in unknowns_ledger[0].item_path


