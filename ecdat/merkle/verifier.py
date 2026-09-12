"""
ECDAT Merkle Proof Verifier:
Allows auditors and external regulators to cryptographically verify selective inclusion
proofs against a published 32-byte Merkle root without accessing internal codebases.
"""

import hashlib
import json
import sys
import argparse
from typing import List, Dict, Any, Tuple

def verify_raw_merkle_path(
    leaf_hash_hex: str,
    sibling_path: List[Dict[str, str]],
    expected_root_hex: str,
) -> bool:
    """
    Reconstructs the Merkle path from leaf_hash_hex through sibling_path
    and checks if the calculated root matches expected_root_hex.
    """
    try:
        current = bytes.fromhex(leaf_hash_hex)
        expected_root = bytes.fromhex(expected_root_hex)

        for step in sibling_path:
            sibling_hash = bytes.fromhex(step["hash"])
            position = step.get("position", "right").lower()

            if position == "left":
                # Sibling was the left child, current is the right child
                current = hashlib.sha256(sibling_hash + current).digest()
            else:
                # Sibling was the right child, current is the left child
                current = hashlib.sha256(current + sibling_hash).digest()

        return current == expected_root
    except Exception:
        return False

def verify_proof_package(proof_pkg: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Full cryptographic validation of a proof package:
    1. Verifies that the internal claims match the leaf hash.
    2. Verifies that the leaf hash computes to the expected root via the sibling path.
    """
    required_keys = ["leaf_hash", "sibling_path", "expected_root", "asset_id"]
    for key in required_keys:
        if key not in proof_pkg:
            return False, f"Missing required proof field: '{key}'"

    leaf_hash = proof_pkg["leaf_hash"]
    sibling_path = proof_pkg["sibling_path"]
    expected_root = proof_pkg["expected_root"]

    # Re-hash claimed metadata to verify internal claim integrity
    asset_id = proof_pkg["asset_id"]
    component = proof_pkg.get("component_name", "unknown")
    path_hash = proof_pkg.get("path_hash")
    alg = proof_pkg.get("algorithm", "unknown")
    key_size = proof_pkg.get("key_size", 0)
    primitive = proof_pkg.get("primitive_type", "")
    x_tier = proof_pkg.get("x_tier", "")
    risk = proof_pkg.get("risk_level", "unknown")
    y_max = proof_pkg.get("y_max_years", 0.0)
    salt = proof_pkg.get("salt", "ECDAT_SALT_2026")

    if path_hash is not None:
        canonical_representation = (
            f"id:{asset_id}|"
            f"comp:{component}|"
            f"path_hash:{path_hash}|"
            f"alg:{str(alg).upper()}|"
            f"key_size:{key_size or 0}|"
            f"primitive:{primitive}|"
            f"x_tier:{x_tier}|"
            f"risk:{risk}|"
            f"y_max:{float(y_max):.2f}|"
            f"salt:{salt}"
        )
        computed_leaf = hashlib.sha256(canonical_representation.encode("utf-8")).hexdigest()
        if computed_leaf != leaf_hash:
            return (
                False,
                f"METADATA TAMPER DETECTED: Claimed asset metadata does not hash to leaf commitment. "
                f"Expected {leaf_hash}, computed {computed_leaf}."
            )

    # Verify cryptographic path to root
    is_valid_path = verify_raw_merkle_path(leaf_hash, sibling_path, expected_root)
    if not is_valid_path:
        return False, "CRYPTOGRAPHIC MISMATCH: Sibling path does not compute to expected root. Proof is invalid or tampered."

    return True, (
        f"VERIFIED: Asset '{asset_id}' ({component}, {alg}, Risk: {risk}, Y_max: {y_max}y) "
        f"is cryptographically verified against Merkle root {expected_root[:16]}..."
    )

def main() -> int:
    parser = argparse.ArgumentParser(
        description="ECDAT Merkle Proof Verifier: Authenticate selective CBOM proofs against root commitment."
    )
    parser.add_argument("--proof", required=True, help="Path to proof JSON file (e.g. proof_asset_1.json)")
    parser.add_argument("--root", required=False, help="Optional root hex string or path to cbom_root.hex")

    args = parser.parse_args()

    try:
        with open(args.proof, "r", encoding="utf-8") as f:
            proof_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Could not load proof file: {e}")
        return 1

    if args.root:
        # Check if root is a file path
        try:
            with open(args.root, "r", encoding="utf-8") as f:
                expected_root = f.read().strip()
        except Exception:
            expected_root = args.root.strip()
        proof_data["expected_root"] = expected_root

    is_valid, message = verify_proof_package(proof_data)
    if is_valid:
        print(f"[+] SUCCESS — {message}")
        return 0
    else:
        print(f"[-] FAILED — {message}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
