import pytest
from pathlib import Path
from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.scanners.theia_bridge import (
    find_theia_binary,
    run_theia_scan,
    parse_theia_components,
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
