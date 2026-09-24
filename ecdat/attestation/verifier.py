"""
ECDAT DSSE Attestation Envelope Verifier:
Cryptographically verifies in-toto v1.0 DSSE attestation envelopes against Ed25519 public keys
and validates subject digest matching against the CBOM Merkle root.
"""

import sys
import json
import base64
import argparse
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from ecdat.attestation.envelope import compute_dsse_pae, DSSE_PAYLOAD_TYPE

def verify_dsse_envelope(
    envelope: Dict[str, Any],
    public_key_pem: str,
    expected_root_hex: Optional[str] = None,
    mldsa_public_key_pem: Optional[str] = None,
    require_all_signatures: bool = False,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Verifies an in-toto DSSE envelope:
    1. Validates envelope payloadType is application/vnd.in-toto+json
    2. Reconstructs DSSE PAE and verifies Ed25519 and/or ML-DSA-65 cryptographic signatures
    3. Reconciles subject digest with expected Merkle root
    Returns (is_valid, status_message, parsed_statement).
    """
    # 1. Structural check
    payload_type = envelope.get("payloadType")
    if payload_type != DSSE_PAYLOAD_TYPE:
        return False, f"Invalid payloadType '{payload_type}'; expected '{DSSE_PAYLOAD_TYPE}'", None

    payload_b64 = envelope.get("payload")
    if not payload_b64:
        return False, "Missing payload in DSSE envelope", None

    try:
        payload_bytes = base64.b64decode(payload_b64)
    except Exception as e:
        return False, f"Base64 decoding failed for payload: {e}", None

    signatures = envelope.get("signatures", [])
    if not signatures:
        return False, "No signatures found in DSSE envelope", None

    # Reconstruct PAE
    pae_bytes = compute_dsse_pae(payload_type, payload_bytes)

    # 2. Verify primary public key (Ed25519 or ML-DSA-65)
    try:
        pubkey = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as e:
        return False, f"Public key PEM loading error: {e}", None

    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        ed_sig_entry = next((s for s in signatures if s.get("keyid", "").startswith("ed25519:") or s.get("scheme") == "ed25519"), None)
        if not ed_sig_entry:
            return False, "No Ed25519 signature entry found in envelope signatures", None
        try:
            sig_bytes = base64.b64decode(ed_sig_entry["sig"])
            pubkey.verify(sig_bytes, pae_bytes)
        except InvalidSignature:
            return False, "CRYPTOGRAPHIC ERROR: Ed25519 signature verification failed! Tampered payload detected.", None
        except Exception as e:
            return False, f"Ed25519 verification error: {e}", None

    elif isinstance(pubkey, mldsa.MLDSA65PublicKey):
        ml_sig_entry = next((s for s in signatures if s.get("keyid", "").startswith("mldsa65:") or s.get("scheme") == "ML-DSA-65"), None)
        if not ml_sig_entry:
            return False, "No ML-DSA-65 signature entry found in envelope signatures", None
        try:
            sig_bytes = base64.b64decode(ml_sig_entry["sig"])
            pubkey.verify(sig_bytes, pae_bytes)
        except InvalidSignature:
            return False, "CRYPTOGRAPHIC ERROR: ML-DSA-65 signature verification failed! Tampered payload detected.", None
        except Exception as e:
            return False, f"ML-DSA-65 verification error: {e}", None
    else:
        return False, f"Unsupported public key type: {type(pubkey).__name__}", None

    # Check if envelope contains an ML-DSA-65 signature
    has_mldsa_sig = any(s.get("keyid", "").startswith("mldsa65:") or s.get("scheme") == "ML-DSA-65" for s in signatures)

    # Secondary ML-DSA-65 verification if explicitly passed or required
    if mldsa_public_key_pem:
        try:
            ml_pubkey = serialization.load_pem_public_key(mldsa_public_key_pem.encode("utf-8"))
            if not isinstance(ml_pubkey, mldsa.MLDSA65PublicKey):
                return False, "Specified mldsa_public_key is not an MLDSA65PublicKey", None
            ml_sig_entry = next((s for s in signatures if s.get("keyid", "").startswith("mldsa65:") or s.get("scheme") == "ML-DSA-65"), None)
            if not ml_sig_entry:
                return False, "No ML-DSA-65 signature entry found in envelope", None
            sig_bytes = base64.b64decode(ml_sig_entry["sig"])
            ml_pubkey.verify(sig_bytes, pae_bytes)
        except InvalidSignature:
            return False, "CRYPTOGRAPHIC ERROR: ML-DSA-65 signature verification failed! Tampered payload detected.", None
        except Exception as e:
            return False, f"ML-DSA-65 verification error: {e}", None
    elif has_mldsa_sig and require_all_signatures and not isinstance(pubkey, mldsa.MLDSA65PublicKey):
        return False, "HYBRID VERIFICATION FAILED: Envelope contains an ML-DSA-65 post-quantum signature, but no ML-DSA-65 public key was provided to verify it.", None

    # 3. Parse and validate statement
    try:
        statement = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        return False, f"Statement JSON parsing failed: {e}", None

    # 4. Optional Merkle Root Reconciliation
    if expected_root_hex:
        clean_expected = expected_root_hex.replace("0x", "").strip().lower()
        subjects = statement.get("subject", [])
        if not subjects:
            return False, "Statement contains no subject entries", statement

        subject_digest = subjects[0].get("digest", {}).get("sha256", "").lower()
        if subject_digest != clean_expected:
            return (
                False,
                f"ROOT MISMATCH: Statement subject root '{subject_digest}' does not match expected '{clean_expected}'",
                statement,
            )

    return True, "VERIFIED: DSSE envelope signature and statement integrity valid.", statement

def verify_dsse_envelope_from_file(
    envelope_path: str,
    public_key_path: str,
    expected_root_hex: Optional[str] = None,
    mldsa_public_key_path: Optional[str] = None,
    require_all_signatures: bool = False,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Convenience helper to verify DSSE envelope from filesystem paths."""
    env_p = Path(envelope_path).resolve()
    pub_p = Path(public_key_path).resolve()

    if not env_p.exists():
        return False, f"Envelope file not found: {env_p}", None
    if not pub_p.exists():
        return False, f"Public key file not found: {pub_p}", None

    try:
        envelope = json.loads(env_p.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"Failed to parse envelope JSON: {e}", None

    try:
        pubkey_pem = pub_p.read_text(encoding="utf-8")
    except Exception as e:
        return False, f"Failed to read public key PEM: {e}", None

    mldsa_pubkey_pem = None
    if mldsa_public_key_path:
        ml_p = Path(mldsa_public_key_path).resolve()
        if not ml_p.exists():
            return False, f"ML-DSA public key file not found: {ml_p}", None
        try:
            mldsa_pubkey_pem = ml_p.read_text(encoding="utf-8")
        except Exception as e:
            return False, f"Failed to read ML-DSA public key PEM: {e}", None

    clean_root = None
    if expected_root_hex:
        r_path = Path(expected_root_hex)
        if r_path.exists() and r_path.is_file():
            clean_root = r_path.read_text(encoding="utf-8").strip()
        else:
            clean_root = expected_root_hex.strip()

    return verify_dsse_envelope(
        envelope,
        pubkey_pem,
        clean_root,
        mldsa_public_key_pem=mldsa_pubkey_pem,
        require_all_signatures=require_all_signatures,
    )

def main() -> int:
    parser = argparse.ArgumentParser(description="ECDAT in-toto DSSE Attestation Envelope Verifier")
    parser.add_argument("--envelope", required=True, help="Path to attestation.dsse.json file")
    parser.add_argument("--public-key", required=True, help="Path to Ed25519 (or ML-DSA-65) public key PEM file")
    parser.add_argument("--mldsa-key", required=False, help="Path to ML-DSA-65 public key PEM file for dual verification")
    parser.add_argument("--require-all", action="store_true", default=False, help="Fail closed if hybrid signatures are present but unverified")
    parser.add_argument("--root", required=False, help="Path to cbom_root.hex or raw root hex string")

    args = parser.parse_args()

    env_path = Path(args.envelope).resolve()
    pub_path = Path(args.public_key).resolve()

    if not env_path.exists():
        print(f"[-] Error: Envelope file not found: {env_path}", file=sys.stderr)
        return 1
    if not pub_path.exists():
        print(f"[-] Error: Public key file not found: {pub_path}", file=sys.stderr)
        return 1

    envelope = json.loads(env_path.read_text(encoding="utf-8"))
    pubkey_pem = pub_path.read_text(encoding="utf-8")

    mldsa_pubkey_pem = None
    if args.mldsa_key:
        ml_p = Path(args.mldsa_key).resolve()
        if not ml_p.exists():
            print(f"[-] Error: ML-DSA public key file not found: {ml_p}", file=sys.stderr)
            return 1
        mldsa_pubkey_pem = ml_p.read_text(encoding="utf-8")

    expected_root = None
    if args.root:
        r_path = Path(args.root)
        if r_path.exists():
            expected_root = r_path.read_text(encoding="utf-8").strip()
        else:
            expected_root = args.root.strip()

    is_valid, msg, stmt = verify_dsse_envelope(
        envelope,
        pubkey_pem,
        expected_root,
        mldsa_public_key_pem=mldsa_pubkey_pem,
        require_all_signatures=args.require_all,
    )

    if is_valid:
        proj_name = stmt["subject"][0].get("name", "unknown") if stmt else "unknown"
        root_claim = stmt["subject"][0]["digest"].get("sha256", "") if stmt else ""
        print(f"[+] SUCCESS — {msg}")
        print(f"    - Target Project: {proj_name}")
        print(f"    - Merkle Root:    0x{root_claim}")
        return 0
    else:
        print(f"[-] VERIFICATION FAILED: {msg}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
