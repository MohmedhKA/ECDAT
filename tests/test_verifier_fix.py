import pytest
import hashlib
from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.mosca.engine import compute_mosca_score
from ecdat.merkle.tree import MerkleTree, generate_asset_proof_package
from ecdat.merkle.verifier import verify_proof_package

def test_verifier_detects_metadata_claim_tampering():
    asset = CryptoAsset(
        asset_id="asset-auth-001",
        component_name="auth-service",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/auth/jwt.py",
        line_number=50,
        x_tier=XTier.SHORT_TERM,
    )
    score = compute_mosca_score(asset, current_year=2026)

    tree, _ = MerkleTree.from_assets([(asset, score)])
    proof_pkg = generate_asset_proof_package(asset, score, leaf_index=0, tree=tree)

    # 1. Valid proof package verifies
    is_valid, msg = verify_proof_package(proof_pkg)
    assert is_valid is True
    assert "VERIFIED" in msg

    # 2. Tampering with algorithm without altering leaf_hash MUST fail
    tampered_alg = dict(proof_pkg)
    tampered_alg["algorithm"] = "ML-DSA-65"
    is_valid, msg = verify_proof_package(tampered_alg)
    assert is_valid is False
    assert "METADATA TAMPER DETECTED" in msg

    # 3. Tampering with key size MUST fail
    tampered_key = dict(proof_pkg)
    tampered_key["key_size"] = 4096
    is_valid, msg = verify_proof_package(tampered_key)
    assert is_valid is False
    assert "METADATA TAMPER DETECTED" in msg

    # 4. Tampering with risk level MUST fail
    tampered_risk = dict(proof_pkg)
    tampered_risk["risk_level"] = "LOW"
    is_valid, msg = verify_proof_package(tampered_risk)
    assert is_valid is False
    assert "METADATA TAMPER DETECTED" in msg

    # 5. Tampering with component name MUST fail
    tampered_comp = dict(proof_pkg)
    tampered_comp["component_name"] = "fake-service"
    is_valid, msg = verify_proof_package(tampered_comp)
    assert is_valid is False
    assert "METADATA TAMPER DETECTED" in msg
