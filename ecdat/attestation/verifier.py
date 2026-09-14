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

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from ecdat.attestation.envelope import compute_dsse_pae, DSSE_PAYLOAD_TYPE

def verify_dsse_envelope(
    envelope: Dict[str, Any],
    public_key_pem: str,
    expected_root_hex: Optional[str] = None,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Verifies an in-toto DSSE envelope:
    1. Validates envelope payloadType is application/vnd.in-toto+json
    2. Reconstructs DSSE PAE and verifies Ed25519 cryptographic signature
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

    # Find the Ed25519 signature
    ed25519_sig_entry = None
    for s in signatures:
        if s.get("keyid", "").startswith("ed25519:"):
            ed25519_sig_entry = s
            break
    if not ed25519_sig_entry:
        ed25519_sig_entry = signatures[0]

    try:
        sig_bytes = base64.b64decode(ed25519_sig_entry["sig"])
    except Exception as e:
        return False, f"Base64 decoding failed for signature: {e}", None

    # 2. Reconstruct PAE and verify signature
    pae_bytes = compute_dsse_pae(payload_type, payload_bytes)

    try:
        pubkey = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pubkey, ed25519.Ed25519PublicKey):
            return False, "Public key is not an Ed25519 key", None
        pubkey.verify(sig_bytes, pae_bytes)
    except InvalidSignature:
        return False, "CRYPTOGRAPHIC ERROR: Ed25519 signature verification failed! Tampered payload detected.", None
    except Exception as e:
        return False, f"Public key loading or verification error: {e}", None

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

    clean_root = None
    if expected_root_hex:
        r_path = Path(expected_root_hex)
        if r_path.exists() and r_path.is_file():
            clean_root = r_path.read_text(encoding="utf-8").strip()
        else:
            clean_root = expected_root_hex.strip()

    return verify_dsse_envelope(envelope, pubkey_pem, clean_root)

def main() -> int:
    parser = argparse.ArgumentParser(description="ECDAT in-toto DSSE Attestation Envelope Verifier")
    parser.add_argument("--envelope", required=True, help="Path to attestation.dsse.json file")
    parser.add_argument("--public-key", required=True, help="Path to attestation_pubkey.pem file")
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

    expected_root = None
    if args.root:
        r_path = Path(args.root)
        if r_path.exists():
            expected_root = r_path.read_text(encoding="utf-8").strip()
        else:
            expected_root = args.root.strip()

    is_valid, msg, stmt = verify_dsse_envelope(envelope, pubkey_pem, expected_root)

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
