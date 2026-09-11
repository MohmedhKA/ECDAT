import pytest
from pathlib import Path
from ecdat.models import PrimitiveType, XTier
from ecdat.scanners.source_scanner import (
    scan_javascript_file,
    scan_go_file,
    scan_rust_file,
    discover_polyglot_crypto_assets,
)

def test_javascript_rsa_blind_signature_discovery(tmp_path):
    js_file = tmp_path / "rsa-blind.service.js"
    js_content = """
import forge from 'node-forge';
import { privateDecrypt, constants } from 'crypto';

class RsaBlindService {
    async generateForElection(electionId) {
        // HNDL mitigation - in-memory only
        forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keypair) => {});
    }

    destroyForElection(electionId) {
        this._keys.delete(electionId);
    }

    signBlinded(electionId, blindedMsg) {
        return privateDecrypt({ key: this.key, padding: constants.RSA_NO_PADDING }, buf);
    }
}
"""
    js_file.write_text(js_content)
    assets = scan_javascript_file(js_file, tmp_path)

    assert len(assets) >= 1
    rsa_asset = next((a for a in assets if a.algorithm == "RSA-2048"), None)
    assert rsa_asset is not None
    assert rsa_asset.primitive_type == PrimitiveType.SIGNATURE
    assert rsa_asset.key_size == 2048
    assert rsa_asset.x_tier == XTier.EPHEMERAL
    assert rsa_asset.has_crypto_shredding is True

def test_javascript_mldsa_post_quantum_discovery(tmp_path):
    js_file = tmp_path / "dilithium.service.js"
    js_content = """
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

class DilithiumService {
    generate() {
        const keys = ml_dsa65.keygen(seed);
        return keys;
    }
}
"""
    js_file.write_text(js_content)
    assets = scan_javascript_file(js_file, tmp_path)

    assert len(assets) >= 1
    mldsa_asset = next((a for a in assets if a.algorithm == "ML-DSA-65"), None)
    assert mldsa_asset is not None
    assert mldsa_asset.primitive_type == PrimitiveType.SIGNATURE
    assert mldsa_asset.key_size == 1952

def test_rust_crypto_discovery(tmp_path):
    rs_file = tmp_path / "verifier.rs"
    rs_content = """
pub struct U2048(pub [u64; 32]);

pub const LWE_Q: u64 = 137438953447;
pub struct LweCiphertext {
    pub a: Vec<u64>,
}
"""
    rs_file.write_text(rs_content)
    assets = scan_rust_file(rs_file, tmp_path)

    assert any(a.algorithm == "RSA-2048" for a in assets)
    assert any(a.algorithm == "LWE-2048" for a in assets)

def test_go_crypto_discovery(tmp_path):
    go_file = tmp_path / "chaincode.go"
    go_content = """
package main
import (
    "crypto/sha256"
    "crypto/rsa"
)
func HashPayload() {
    h := sha256.New()
}
"""
    go_file.write_text(go_content)
    assets = scan_go_file(go_file, tmp_path)

    assert any(a.algorithm == "SHA-256" for a in assets)

def test_discover_polyglot_crypto_assets_recursive(tmp_path):
    sub = tmp_path / "src"
    sub.mkdir()
    f1 = sub / "auth.ts"
    f1.write_text("import { ml_kem768 } from '@noble/post-quantum/ml-kem'; const k = ml_kem768.keygen();")
    f2 = sub / "server.go"
    f2.write_text("package main\nimport \"crypto/ecdsa\"\nfunc key() { ecdsa.GenerateKey(curve, rand) }")

    assets = discover_polyglot_crypto_assets(str(tmp_path))
    assert len(assets) >= 2
    algs = {a.algorithm for a in assets}
    assert "ML-KEM-768" in algs
    assert "ECDSA-P256" in algs
