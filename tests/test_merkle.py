import pytest
import hashlib
from ecdat.models import CryptoAsset, PrimitiveType, XTier, MoscaScore
from ecdat.mosca.engine import compute_mosca_score
from ecdat.merkle.tree import hash_asset_leaf, MerkleTree, generate_asset_proof_package
from ecdat.merkle.verifier import verify_raw_merkle_path, verify_proof_package

@pytest.fixture
def sample_asset_and_score():
    asset = CryptoAsset(
        asset_id="asset-checkout-1",
        component_name="checkout-service",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/payments/crypto.py",
        line_number=42,
        x_tier=XTier.ARCHIVAL,
    )
    score = compute_mosca_score(asset, current_year=2026)
    return asset, score

def test_leaf_hash_determinism(sample_asset_and_score):
    asset, score = sample_asset_and_score
    h1 = hash_asset_leaf(asset, score, salt="test_salt")
    h2 = hash_asset_leaf(asset, score, salt="test_salt")
    assert h1 == h2
    assert len(h1) == 32  # SHA-256 is 32 bytes

    # Changing salt alters hash
    h3 = hash_asset_leaf(asset, score, salt="different_salt")
    assert h1 != h3

def test_merkle_tree_single_leaf():
    leaf = hashlib.sha256(b"single_leaf").digest()
    tree = MerkleTree([leaf])
    assert tree.root == leaf
    assert tree.root_hex == leaf.hex()
    proof = tree.get_proof(0)
    assert len(proof) == 0  # No siblings needed for single leaf

def test_merkle_tree_multi_leaves():
    # Test with power of 2 and odd numbers of leaves
    for num_leaves in [2, 3, 4, 7, 8, 15, 16]:
        leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(num_leaves)]
        tree = MerkleTree(leaves)

        assert len(tree.root) == 32
        assert len(tree.root_hex) == 64

        # Verify inclusion proof for every single leaf
        for idx in range(num_leaves):
            proof = tree.get_proof(idx)
            is_valid = verify_raw_merkle_path(
                leaf_hash_hex=leaves[idx].hex(),
                sibling_path=proof,
                expected_root_hex=tree.root_hex,
            )
            assert is_valid, f"Proof failed for leaf index {idx} in tree of size {num_leaves}"

def test_merkle_tamper_resistance():
    leaves = [hashlib.sha256(f"item_{i}".encode()).digest() for i in range(5)]
    tree = MerkleTree(leaves)

    proof = tree.get_proof(2)
    valid_leaf = leaves[2].hex()
    valid_root = tree.root_hex

    # 1. Tampering with leaf hash
    tampered_leaf = hashlib.sha256(b"tampered_data").hexdigest()
    assert not verify_raw_merkle_path(tampered_leaf, proof, valid_root)

    # 2. Tampering with a sibling in proof path
    tampered_proof = [dict(step) for step in proof]
    tampered_proof[0]["hash"] = hashlib.sha256(b"fake_sibling").hexdigest()
    assert not verify_raw_merkle_path(valid_leaf, tampered_proof, valid_root)

    # 3. Tampering with root hash
    fake_root = hashlib.sha256(b"fake_root").hexdigest()
    assert not verify_raw_merkle_path(valid_leaf, proof, fake_root)

def test_asset_proof_package_workflow(sample_asset_and_score):
    asset, score = sample_asset_and_score

    # Create a small inventory of assets
    assets = [
        sample_asset_and_score,
        (
            CryptoAsset(
                asset_id="asset-tls-2",
                component_name="api-gateway",
                algorithm="ECDH-P256",
                key_size=256,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path="src/gateway/tls.py",
                x_tier=XTier.EPHEMERAL,
            ),
            compute_mosca_score(
                CryptoAsset(
                    asset_id="asset-tls-2",
                    component_name="api-gateway",
                    algorithm="ECDH-P256",
                    key_size=256,
                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                    file_path="src/gateway/tls.py",
                    x_tier=XTier.EPHEMERAL,
                ),
                current_year=2026,
            ),
        ),
        (
            CryptoAsset(
                asset_id="asset-sign-3",
                component_name="ledger",
                algorithm="ML-DSA-65",
                key_size=1952,
                primitive_type=PrimitiveType.SIGNATURE,
                file_path="src/ledger/signer.py",
                x_tier=XTier.OPERATIONAL,
            ),
            compute_mosca_score(
                CryptoAsset(
                    asset_id="asset-sign-3",
                    component_name="ledger",
                    algorithm="ML-DSA-65",
                    key_size=1952,
                    primitive_type=PrimitiveType.SIGNATURE,
                    file_path="src/ledger/signer.py",
                    x_tier=XTier.OPERATIONAL,
                ),
                current_year=2026,
            ),
        ),
    ]

    tree, _ = MerkleTree.from_assets(assets)

    # Generate proof for the checkout asset (index 0)
    proof_pkg = generate_asset_proof_package(asset, score, leaf_index=0, tree=tree)

    # Verify proof package
    is_valid, msg = verify_proof_package(proof_pkg)
    assert is_valid is True
    assert "VERIFIED" in msg
    assert "checkout-service" in msg

    # Tamper with the proof package (e.g. claim it is ML-DSA instead of RSA)
    proof_pkg_tampered = dict(proof_pkg)
    proof_pkg_tampered["expected_root"] = hashlib.sha256(b"bogus_root").hexdigest()
    is_tampered_valid, tamper_msg = verify_proof_package(proof_pkg_tampered)
    assert is_tampered_valid is False
    assert "CRYPTOGRAPHIC MISMATCH" in tamper_msg
