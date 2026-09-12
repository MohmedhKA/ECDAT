"""
ECDAT Merkle Tree & Privacy-Preserving Attestation Module:
Constructs tamper-evident SHA-256 Merkle tree commitments from discovered crypto assets
and generates selective inclusion proofs for external compliance audits.
"""

import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple
from ecdat.models import CryptoAsset, MoscaScore

def hash_asset_leaf(asset: CryptoAsset, score: MoscaScore, salt: str = "ECDAT_SALT_2026") -> bytes:
    """
    Computes a canonical SHA-256 leaf hash for a single cryptographic asset.
    File paths are hashed to 16-hex characters to prevent leaking internal repository
    file structures to external auditors.
    """
    path_hash = hashlib.sha256(asset.file_path.encode("utf-8")).hexdigest()[:16]
    canonical_representation = (
        f"id:{asset.asset_id}|"
        f"comp:{asset.component_name}|"
        f"path_hash:{path_hash}|"
        f"alg:{asset.algorithm.upper()}|"
        f"key_size:{asset.key_size or 0}|"
        f"primitive:{asset.primitive_type.value}|"
        f"x_tier:{asset.x_tier.value}|"
        f"risk:{score.risk_level}|"
        f"y_max:{score.y_max_years:.2f}|"
        f"salt:{salt}"
    )
    return hashlib.sha256(canonical_representation.encode("utf-8")).digest()

class MerkleTree:
    """
    Binary Merkle Tree implementation using SHA-256.
    Produces a single 32-byte cryptographic root commitment and generates
    selective inclusion proofs (log2(N) sibling path).
    """

    def __init__(self, leaves: List[bytes]):
        if not leaves:
            raise ValueError("Cannot construct a MerkleTree with zero leaves.")
        self.leaves: List[bytes] = leaves
        self.layers: List[List[bytes]] = [leaves]
        self._build_tree()

    def _build_tree(self) -> None:
        current_layer = self.leaves
        while len(current_layer) > 1:
            next_layer: List[bytes] = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                # If odd number of nodes, duplicate the last element (standard convention)
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                combined = left + right
                parent_hash = hashlib.sha256(combined).digest()
                next_layer.append(parent_hash)
            self.layers.append(next_layer)
            current_layer = next_layer

    @property
    def root(self) -> bytes:
        """Returns the 32-byte binary root hash."""
        return self.layers[-1][0]

    @property
    def root_hex(self) -> str:
        """Returns the 64-character hexadecimal representation of the root hash."""
        return self.root.hex()

    def get_proof(self, leaf_index: int) -> List[Dict[str, str]]:
        """
        Generates a selective inclusion proof for the leaf at leaf_index.
        Returns a list of sibling hashes with position ('left' or 'right').
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of bounds (0 to {len(self.leaves)-1}).")

        proof: List[Dict[str, str]] = []
        idx = leaf_index

        for layer in self.layers[:-1]:
            is_right_child = (idx % 2 == 1)
            if is_right_child:
                sibling_idx = idx - 1
                sibling_pos = "left"
            else:
                sibling_idx = idx + 1 if idx + 1 < len(layer) else idx
                sibling_pos = "right"

            sibling_hash = layer[sibling_idx].hex()
            proof.append({
                "hash": sibling_hash,
                "position": sibling_pos,
            })
            idx = idx // 2

        return proof

    @classmethod
    def from_assets(
        cls,
        assets: List[Tuple[CryptoAsset, MoscaScore]],
        salt: str = "ECDAT_SALT_2026",
    ) -> Tuple["MerkleTree", List[bytes]]:
        """Constructs a MerkleTree directly from a list of (CryptoAsset, MoscaScore) tuples."""
        leaves = [hash_asset_leaf(asset, score, salt=salt) for asset, score in assets]
        return cls(leaves), leaves

def generate_asset_proof_package(
    asset: CryptoAsset,
    score: MoscaScore,
    leaf_index: int,
    tree: MerkleTree,
    salt: str = "ECDAT_SALT_2026",
) -> Dict[str, Any]:
    """
    Creates a verifiable disclosure package for an external compliance auditor:
    Contains the asset's verified compliance claim, its leaf hash, sibling proof path,
    and expected Merkle root.
    """
    path_hash = hashlib.sha256(asset.file_path.encode("utf-8")).hexdigest()[:16]
    leaf_hash = hash_asset_leaf(asset, score, salt=salt).hex()
    sibling_path = tree.get_proof(leaf_index)

    return {
        "asset_id": asset.asset_id,
        "component_name": asset.component_name,
        "path_hash": path_hash,
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "primitive_type": asset.primitive_type.value,
        "x_tier": asset.x_tier.value,
        "risk_level": score.risk_level,
        "y_max_years": score.y_max_years,
        "z_regulatory_year": score.z_regulatory_year,
        "leaf_index": leaf_index,
        "leaf_hash": leaf_hash,
        "sibling_path": sibling_path,
        "expected_root": tree.root_hex,
        "salt": salt,
    }
