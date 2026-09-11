import json
from pathlib import Path
import pytest
from ecdat.scanners.manifest_scanner import (
    discover_manifest_crypto_dependencies,
    scan_package_json,
    scan_cargo_toml,
    scan_go_mod,
    scan_requirements_txt,
)

def test_scan_package_json(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "test-app",
        "dependencies": {
            "@noble/post-quantum": "^0.2.0",
            "node-forge": "^1.3.1",
            "express": "^4.18.2"
        }
    }), encoding="utf-8")

    deps = scan_package_json(pkg_json, tmp_path)
    assert len(deps) == 2
    names = {d.package_name for d in deps}
    assert "@noble/post-quantum" in names
    assert "node-forge" in names

    pqc = next(d for d in deps if d.package_name == "@noble/post-quantum")
    assert pqc.pqc_readiness == "MIGRATED_PQC"
    assert pqc.ecosystem == "npm"

    forge = next(d for d in deps if d.package_name == "node-forge")
    assert forge.pqc_readiness == "VULNERABLE_CLASSICAL"

def test_scan_cargo_toml(tmp_path):
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_toml.write_text("""
[package]
name = "crypto-crate"
version = "0.1.0"

[dependencies]
curve25519-dalek = "4.1"
serde = "1.0"
pqcrypto = "0.17"
sha2 = "0.10.8"
""", encoding="utf-8")

    deps = scan_cargo_toml(cargo_toml, tmp_path)
    assert len(deps) == 3
    names = {d.package_name for d in deps}
    assert "curve25519-dalek" in names
    assert "pqcrypto" in names
    assert "sha2" in names

    sha2_dep = next(d for d in deps if d.package_name == "sha2")
    assert sha2_dep.category == "SYMMETRIC_OR_HASH"
    assert sha2_dep.pqc_readiness == "SAFE_SYMMETRIC"
    assert "Maintain: Symmetric/hash algorithm" in sha2_dep.recommendation

def test_scan_go_mod(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text("""
module example.com/evoting

go 1.21

require (
    github.com/hyperledger/fabric-contract-api-go v1.2.2
    github.com/stretchr/testify v1.8.4
)
""", encoding="utf-8")

    deps = scan_go_mod(go_mod, tmp_path)
    assert len(deps) == 1
    assert deps[0].package_name == "github.com/hyperledger/fabric-contract-api-go"
    assert deps[0].ecosystem == "go"

def test_scan_requirements_txt(tmp_path):
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("""
cryptography>=41.0.0
flask==2.3.2
pycryptodome
""", encoding="utf-8")

    deps = scan_requirements_txt(req_txt, tmp_path)
    assert len(deps) == 2
    names = {d.package_name for d in deps}
    assert "cryptography" in names
    assert "pycryptodome" in names

def test_discover_manifest_crypto_dependencies(tmp_path):
    sub = tmp_path / "app"
    sub.mkdir()
    (sub / "requirements.txt").write_text("cryptography==42.0.0\n", encoding="utf-8")

    venv = tmp_path / "venv"
    venv.mkdir()
    (venv / "requirements.txt").write_text("node-forge\n", encoding="utf-8")

    results = discover_manifest_crypto_dependencies(str(tmp_path))
    assert len(results) == 1
    assert results[0].package_name == "cryptography"
