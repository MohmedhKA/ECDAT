import pytest
from ecdat.scanners.filters import should_scan_file

def test_should_scan_file_normal_sources():
    assert should_scan_file("backend/src/services/auth.js") is True
    assert should_scan_file("backend/src/routes/votes.ts") is True
    assert should_scan_file("blockchain/chaincode/evoting.go") is True
    assert should_scan_file("verifier/src/crypto.rs") is True
    assert should_scan_file("scripts/deploy.py") is True
    assert should_scan_file("backend/.env") is True
    assert should_scan_file("requirements.txt") is True
    assert should_scan_file("api/requirements-dev.txt") is True

def test_should_scan_file_excluded_directories():
    assert should_scan_file("node_modules/express/index.js") is False
    assert should_scan_file("backend/node_modules/bcrypt/index.js") is False
    assert should_scan_file("caliper/node_modules/pkcs11js/index.js") is False
    assert should_scan_file(".venv/lib/python3.11/site-packages/cryptography/hazmat/primitives.py") is False
    assert should_scan_file("Research/Campaign-1M/PROOF_REPORT.md") is False
    assert should_scan_file("docs/architecture/crypto.md") is False
    assert should_scan_file("reports/audit_2026.pdf") is False
    assert should_scan_file("target/debug/build/crypto-verifier.rs") is False
    assert should_scan_file("dist/bundle.js") is False
    assert should_scan_file("coverage/lcov.info") is False
    assert should_scan_file("tests/fixtures/sample_payload.json") is False
    assert should_scan_file("testdata/mock_cert.pem") is False

def test_should_scan_file_sample_and_template_patterns():
    assert should_scan_file(".env.example") is False
    assert should_scan_file("backend/.env.sample") is False
    assert should_scan_file("deploy/.env.template") is False
    assert should_scan_file("keys/mock-keypair.json") is False
    assert should_scan_file("keys/election-sample-keypair.json") is False
    assert should_scan_file("keys/trustee-test-keypair.json") is False
    assert should_scan_file("tests/crypto/fixture_rsa.pem") is False
    assert should_scan_file("tests/keys/mock_key.key") is False
