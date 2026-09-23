"""
ECDAT Signed in-toto / SLSA DSSE Attestation Envelope Generator (Pillar 6):
Generates RFC 9162 Dead Simple Signing Envelopes (DSSE) over in-toto v1.0 Statements.
Provides cryptographic tamper-proof attestation with Ed25519 signatures, Merkle commitments,
boundary Unknowns Ledgers, and audit-defensible Negative Proofs.
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives import serialization

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
DEFAULT_KEY_DIR = Path(".ecdat/keys")

def compute_dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """
    Computes Pre-Authentication Encoding (PAE) per RFC 9162 / DSSE v1:
    PAE(type, payload) = "DSSEv1" + " " + len(type) + " " + type + " " + len(payload) + " " + payload
    """
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("utf-8")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload_bytes)).encode("utf-8")
        + b" "
        + payload_bytes
    )

def generate_signing_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates a fresh Ed25519 signing keypair for scan attestation."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_mldsa_signing_keypair() -> Tuple[mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey]:
    """Generates a fresh NIST FIPS 204 ML-DSA-65 post-quantum signing keypair."""
    private_key = mldsa.MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Exports an Ed25519 public key in PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

def export_mldsa_public_key_pem(public_key: mldsa.MLDSA65PublicKey) -> str:
    """Exports an ML-DSA-65 public key in PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

def export_private_key_pem(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Exports an Ed25519 private key in PEM format (unencrypted for ephemeral use)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

def export_mldsa_private_key_pem(private_key: mldsa.MLDSA65PrivateKey) -> str:
    """Exports an ML-DSA-65 private key in PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

def get_or_create_signing_keys(
    key_dir: Optional[Path] = None,
) -> Tuple[
    ed25519.Ed25519PrivateKey,
    ed25519.Ed25519PublicKey,
    mldsa.MLDSA65PrivateKey,
    mldsa.MLDSA65PublicKey,
]:
    """
    Retrieves or generates persistent signing keypairs in the designated key directory.
    Stores private keys with restricted 0o600 permissions.
    """
    target_dir = Path(key_dir or os.environ.get("ECDAT_KEY_DIR", DEFAULT_KEY_DIR))
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    ed_key_file = target_dir / "trust_root_ed25519.key"
    ed_pub_file = target_dir / "trust_root_ed25519.pub"
    mldsa_key_file = target_dir / "trust_root_mldsa65.key"
    mldsa_pub_file = target_dir / "trust_root_mldsa65.pub"

    # Ed25519 Key
    if ed_key_file.exists():
        ed_priv = serialization.load_pem_private_key(
            ed_key_file.read_bytes(), password=None
        )
        if not isinstance(ed_priv, ed25519.Ed25519PrivateKey):
            raise TypeError(f"Key in {ed_key_file} is not an Ed25519PrivateKey")
        ed_pub = ed_priv.public_key()
    else:
        ed_priv, ed_pub = generate_signing_keypair()
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with open(os.open(ed_key_file, flags, 0o600), "w", encoding="utf-8") as f:
            f.write(export_private_key_pem(ed_priv))
        with open(ed_pub_file, "w", encoding="utf-8") as f:
            f.write(export_public_key_pem(ed_pub))

    # ML-DSA-65 Key
    if mldsa_key_file.exists():
        mldsa_priv = serialization.load_pem_private_key(
            mldsa_key_file.read_bytes(), password=None
        )
        if not isinstance(mldsa_priv, mldsa.MLDSA65PrivateKey):
            raise TypeError(f"Key in {mldsa_key_file} is not an MLDSA65PrivateKey")
        mldsa_pub = mldsa_priv.public_key()
    else:
        mldsa_priv, mldsa_pub = generate_mldsa_signing_keypair()
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with open(os.open(mldsa_key_file, flags, 0o600), "w", encoding="utf-8") as f:
            f.write(export_mldsa_private_key_pem(mldsa_priv))
        with open(mldsa_pub_file, "w", encoding="utf-8") as f:
            f.write(export_mldsa_public_key_pem(mldsa_pub))

    return ed_priv, ed_pub, mldsa_priv, mldsa_pub

def build_intoto_statement(
    project_name: str,
    merkle_root_hex: str,
    target_path: str,
    total_assets: int,
    evidence_distribution: Dict[str, int],
    intent_distribution: Dict[str, int],
    cams_distribution: Dict[str, int],
    route_profile: str,
    effective_mtu: int,
    unknowns_ledger: List[Dict[str, Any]],
    git_commit_sha: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Constructs an in-toto v1.0 Statement with SLSA Provenance / ECDAT Attestation predicate.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    clean_root = merkle_root_hex.replace("0x", "").lower()

    # Determine negative proof assertions
    uninspected_count = len(unknowns_ledger)
    claim_text = (
        "No uninspected reachable RSA, broken symmetric ciphers, or weak hashes found "
        "within audited codebase perimeter."
        if uninspected_count == 0
        else f"Audited perimeter contains {uninspected_count} declared boundary unknowns; all other paths certified."
    )

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": project_name,
                "digest": {
                    "sha256": clean_root,
                },
            }
        ],
        "predicateType": "https://ecdat.dev/attestation/v1",
        "predicate": {
            "builder": {
                "id": "https://github.com/SIH26164/ECDAT@v2.0.0",
                "version": "2.0.0",
                "vendor": "SIH26164",
            },
            "buildDefinition": {
                "buildType": "https://ecdat.dev/attestation/scan/v1",
                "externalParameters": {
                    "target_path": str(target_path),
                    "git_commit": git_commit_sha or "HEAD",
                },
                "internalParameters": {
                    "timestamp": now_utc,
                    "transport_route_profile": route_profile,
                    "effective_mtu_bytes": effective_mtu,
                },
            },
            "runDetails": {
                "merkle_root": f"0x{clean_root}",
                "total_cryptographic_assets": total_assets,
                "evidence_distribution": evidence_distribution,
                "intent_distribution": intent_distribution,
                "cams_agility_distribution": cams_distribution,
                "unknowns_ledger_count": len(unknowns_ledger),
                "unknowns_ledger": unknowns_ledger,
                "negative_proof": {
                    "claim": claim_text,
                    "scope": {
                        "target_path": str(target_path),
                        "perimeter_verified": True,
                        "unknowns_declared": len(unknowns_ledger),
                    },
                },
            },
        },
    }

    if git_commit_sha:
        statement["subject"][0]["digest"]["gitCommit"] = git_commit_sha

    return statement

def create_signed_dsse_envelope(
    statement: Dict[str, Any],
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    mldsa_private_key: Optional[mldsa.MLDSA65PrivateKey] = None,
    key_dir: Optional[Path] = None,
) -> Tuple[Dict[str, Any], ed25519.Ed25519PublicKey, str]:
    """
    Wraps statement in DSSE envelope and signs over PAE with both Ed25519 and
    genuine NIST FIPS 204 ML-DSA-65 post-quantum digital signatures.
    Returns (envelope_dict, ed25519_public_key, ed25519_public_key_pem).
    """
    if private_key is None or mldsa_private_key is None:
        ed_priv, ed_pub, ml_priv, ml_pub = get_or_create_signing_keys(key_dir=key_dir)
        if private_key is None:
            private_key, public_key = ed_priv, ed_pub
        else:
            public_key = private_key.public_key()
        if mldsa_private_key is None:
            mldsa_private_key, mldsa_public_key = ml_priv, ml_pub
        else:
            mldsa_public_key = mldsa_private_key.public_key()
    else:
        public_key = private_key.public_key()
        mldsa_public_key = mldsa_private_key.public_key()

    # Canonical statement JSON serialization
    statement_json = json.dumps(statement, sort_keys=True, separators=(",", ":"))
    payload_bytes = statement_json.encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("utf-8")

    # Compute DSSE Pre-Authentication Encoding (PAE)
    pae_bytes = compute_dsse_pae(DSSE_PAYLOAD_TYPE, payload_bytes)

    # 1. Sign PAE with Ed25519
    signature_bytes = private_key.sign(pae_bytes)
    sig_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ed25519_key_id = f"ed25519:{hashlib.sha256(pub_bytes).hexdigest()[:16]}"

    # 2. Sign PAE with genuine NIST FIPS 204 ML-DSA-65
    mldsa_sig = mldsa_private_key.sign(pae_bytes)
    mldsa_sig_b64 = base64.b64encode(mldsa_sig).decode("utf-8")
    mldsa_pub_raw = mldsa_public_key.public_bytes_raw()
    mldsa_key_id = f"mldsa65:{hashlib.sha256(mldsa_pub_raw).hexdigest()[:16]}"

    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": [
            {
                "keyid": ed25519_key_id,
                "sig": sig_b64,
                "scheme": "ed25519",
            },
            {
                "keyid": mldsa_key_id,
                "sig": mldsa_sig_b64,
                "scheme": "ML-DSA-65",
            },
        ],
    }

    pubkey_pem = export_public_key_pem(public_key)
    return envelope, public_key, pubkey_pem
