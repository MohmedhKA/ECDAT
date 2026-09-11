"""
ECDAT Theia Go Binary Scanner Bridge:
Invokes the compiled Go binary (cbomkit-theia) to scan directory trees for
cryptographic certificates (X.509 PEM/DER), private/public keys, and keystores.
Normalizes discovered CycloneDX 1.6 / 1.7 CBOM components into ECDAT CryptoAsset models.
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from ecdat.models import CryptoAsset, PrimitiveType, XTier

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_THEIA_BINARY_PATH = REPO_ROOT / "bin" / "cbomkit-theia"

def find_theia_binary() -> Optional[Path]:
    """Locates the cbomkit-theia binary from default location, PATH, or environment."""
    env_bin = os.environ.get("THEIA_BIN")
    if env_bin and Path(env_bin).is_file() and os.access(env_bin, os.X_OK):
        return Path(env_bin)

    if DEFAULT_THEIA_BINARY_PATH.is_file() and os.access(str(DEFAULT_THEIA_BINARY_PATH), os.X_OK):
        return DEFAULT_THEIA_BINARY_PATH

    which_bin = shutil.which("cbomkit-theia")
    if which_bin:
        return Path(which_bin)

    return None

def run_theia_scan(
    target_dir: str,
    theia_bin: Optional[Path] = None,
    timeout_seconds: int = 60,
) -> List[CryptoAsset]:
    """
    Executes cbomkit-theia against target_dir and returns discovered CryptoAsset models.
    """
    bin_path = theia_bin or find_theia_binary()
    if not bin_path or not bin_path.exists():
        # Graceful fallback if binary is absent
        return []

    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        return []

    cmd = [str(bin_path), "dir", str(target_path), "--log-level", "warn"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception:
        return []

    stdout_clean = proc.stdout.strip()
    if not stdout_clean:
        return []

    # cbomkit-theia might output JSON starting after log lines
    json_start = stdout_clean.find("{")
    if json_start == -1:
        return []

    json_str = stdout_clean[json_start:]
    try:
        bom_data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    components = bom_data.get("components") or []
    return parse_theia_components(components, base_dir=target_path)

import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, dsa
from ecdat.scanners.filters import should_scan_file

def inspect_x509_certificate(cert_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses X.509 certificate bytes via native ASN.1 cryptography.
    Returns canonical algorithm, key size, primitive type, and DER SHA-256 fingerprint.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
        except Exception:
            return None

    pubkey = cert.public_key()
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der_bytes).hexdigest()

    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    not_valid_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        curve_name = pubkey.curve.name.lower()
        if "256" in curve_name or "secp256r1" in curve_name or "prime256v1" in curve_name:
            canonical_name = "ECDSA-P256"
        elif "384" in curve_name:
            canonical_name = "ECDSA-P384"
        elif "521" in curve_name:
            canonical_name = "ECDSA-P521"
        elif "secp256k1" in curve_name or "k1" in curve_name:
            canonical_name = "ECDSA-SECP256K1"
        else:
            canonical_name = f"ECDSA-{curve_name.upper()}"
        return {
            "algorithm": canonical_name,
            "key_size": pubkey.key_size,
            "primitive_type": PrimitiveType.SIGNATURE,
            "fingerprint": fingerprint,
            "subject": subject_str,
            "issuer": issuer_str,
            "not_valid_after": not_valid_after,
        }
    elif isinstance(pubkey, rsa.RSAPublicKey):
        return {
            "algorithm": f"RSA-{pubkey.key_size}",
            "key_size": pubkey.key_size,
            "primitive_type": PrimitiveType.SIGNATURE,
            "fingerprint": fingerprint,
            "subject": subject_str,
            "issuer": issuer_str,
            "not_valid_after": not_valid_after,
        }
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        return {
            "algorithm": "Ed25519",
            "key_size": 256,
            "primitive_type": PrimitiveType.SIGNATURE,
            "fingerprint": fingerprint,
            "subject": subject_str,
            "issuer": issuer_str,
            "not_valid_after": not_valid_after,
        }
    elif isinstance(pubkey, dsa.DSAPublicKey):
        return {
            "algorithm": f"DSA-{pubkey.key_size}",
            "key_size": pubkey.key_size,
            "primitive_type": PrimitiveType.SIGNATURE,
            "fingerprint": fingerprint,
            "subject": subject_str,
            "issuer": issuer_str,
            "not_valid_after": not_valid_after,
        }

    return {
        "algorithm": "X509-UNKNOWN",
        "key_size": getattr(pubkey, "key_size", 2048),
        "primitive_type": PrimitiveType.SIGNATURE,
        "fingerprint": fingerprint,
        "subject": subject_str,
        "issuer": issuer_str,
        "not_valid_after": not_valid_after,
    }

def parse_theia_components(
    components: List[Dict[str, Any]],
    base_dir: Optional[Path] = None,
) -> List[CryptoAsset]:
    """
    Translates CycloneDX 1.6/1.7 components into ECDAT CryptoAsset objects.
    Applies native ASN.1 public key inspection and content-addressable deduplication.
    """
    discovered_assets: List[CryptoAsset] = []
    seen_identifiers = set()
    seen_cert_fingerprints: Dict[str, CryptoAsset] = {}

    # Pre-collect all certificate file paths so Theia public-key components for the same files are suppressed
    cert_files = set()
    for comp in components:
        cp = comp.get("cryptoProperties") or {}
        if cp.get("assetType") == "certificate":
            evidence = comp.get("evidence", {})
            occurrences = evidence.get("occurrences", [])
            if occurrences and isinstance(occurrences, list):
                for occ in occurrences:
                    loc = occ.get("location", "")
                    if base_dir and os.path.isabs(loc):
                        try:
                            loc = os.path.relpath(loc, str(base_dir))
                        except ValueError:
                            pass
                    if loc:
                        cert_files.add(loc)

    for idx, comp in enumerate(components, start=1):
        crypto_props = comp.get("cryptoProperties") or {}
        asset_type = crypto_props.get("assetType", "")

        evidence = comp.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        rel_path = "unknown_file"
        if occurrences and isinstance(occurrences, list):
            first_occ = occurrences[0]
            rel_path = first_occ.get("location", "unknown_file")

        if base_dir and os.path.isabs(rel_path):
            try:
                rel_path = os.path.relpath(rel_path, str(base_dir))
            except ValueError:
                pass

        # Apply generalized file and path filter
        if not should_scan_file(rel_path):
            continue

        comp_name = comp.get("name", f"asset-{idx}")
        oid = crypto_props.get("oid")
        full_path = (base_dir / rel_path) if base_dir else Path(rel_path)

        # ── 1. Certificates (X.509) ──
        if asset_type == "certificate":
            cert_info = None
            if full_path.is_file():
                try:
                    cert_bytes = full_path.read_bytes()
                    cert_info = inspect_x509_certificate(cert_bytes)
                except Exception:
                    pass

            if cert_info:
                fingerprint = cert_info["fingerprint"]
                if fingerprint in seen_cert_fingerprints:
                    # Content-addressable deduplication: record replica location
                    seen_cert_fingerprints[fingerprint].raw_properties.setdefault("replicas", []).append(rel_path)
                    cert_files.add(rel_path)
                    continue

                alg_name = cert_info["algorithm"]
                key_size = cert_info["key_size"]
                prim = cert_info["primitive_type"]
                subject = cert_info["subject"]
                issuer = cert_info["issuer"]
                not_valid_after = cert_info["not_valid_after"]
            else:
                cert_props = crypto_props.get("certificateProperties", {})
                subject = cert_props.get("subjectName", comp_name)
                issuer = cert_props.get("issuerName")
                not_valid_after = cert_props.get("notValidAfter")
                alg_name = comp_name if ("RSA" in comp_name or "ECDSA" in comp_name) else "RSA-2048"
                key_size = 2048
                prim = PrimitiveType.SIGNATURE
                fingerprint = hashlib.sha256(rel_path.encode()).hexdigest()

            cert_files.add(rel_path)
            asset_id = f"THEIA-CERT-{len(discovered_assets) + 1:03d}"
            asset = CryptoAsset(
                asset_id=asset_id,
                component_name=f"x509_cert:{Path(rel_path).stem}",
                algorithm=alg_name,
                key_size=key_size,
                primitive_type=prim,
                file_path=rel_path,
                line_number=1,
                x_tier=XTier.OPERATIONAL,
                x_confidence="HIGH",
                has_crypto_shredding=False,
                raw_properties={
                    "source": "cbomkit-theia",
                    "assetType": "certificate",
                    "subject": subject,
                    "issuer": issuer,
                    "notValidAfter": not_valid_after,
                    "fingerprint": fingerprint,
                    "replicas": [rel_path],
                },
            )
            seen_cert_fingerprints[fingerprint] = asset
            discovered_assets.append(asset)

        # ── 2. Private and Public Keys ──
        elif asset_type == "related-crypto-material":
            mat_props = crypto_props.get("relatedCryptoMaterialProperties", {})
            mat_type = mat_props.get("type", "")
            key_size = mat_props.get("size", 2048) or 2048

            # Avoid duplicate public-key asset for a file already emitted or cataloged as a certificate
            if mat_type == "public-key":
                if rel_path in cert_files or full_path.suffix.lower() in (".crt", ".cer") or "-cert.pem" in rel_path.lower():
                    continue

            file_sample = ""
            key_content_hash = ""
            if full_path.is_file():
                try:
                    data_bytes = full_path.read_bytes()
                    key_content_hash = hashlib.sha256(data_bytes).hexdigest()
                    file_sample = data_bytes[:4096].decode("utf-8", errors="ignore")
                except Exception:
                    pass

            # Content-addressable deduplication for identical key files
            key_uid = f"{key_content_hash or rel_path}:{mat_type}"
            if key_uid in seen_identifiers:
                continue
            seen_identifiers.add(key_uid)

            name_upper = comp_name.upper()
            rel_lower = rel_path.lower()

            if "RSA" in name_upper or "rsa" in rel_lower or "BEGIN RSA" in file_sample:
                alg_name = f"RSA-{key_size}"
                if "blind" in rel_lower or "blind" in comp_name.lower():
                    prim = PrimitiveType.SIGNATURE
                    tier = XTier.EPHEMERAL
                else:
                    prim = PrimitiveType.KEY_EXCHANGE if mat_type == "private-key" else PrimitiveType.SIGNATURE
                    tier = XTier.ARCHIVAL if mat_type == "private-key" else XTier.OPERATIONAL
            elif "secp384r1" in file_sample or "1.3.132.0.34" in file_sample or "384" in rel_lower or "384" in comp_name:
                alg_name = "ECDSA-P384"
                prim = PrimitiveType.SIGNATURE
                key_size = 384
                tier = XTier.OPERATIONAL
            elif "secp521r1" in file_sample or "1.3.132.0.35" in file_sample or "521" in rel_lower or "521" in comp_name:
                alg_name = "ECDSA-P521"
                prim = PrimitiveType.SIGNATURE
                key_size = 521
                tier = XTier.OPERATIONAL
            elif "secp256k1" in file_sample or "1.3.132.0.10" in file_sample:
                alg_name = "ECDSA-secp256k1"
                prim = PrimitiveType.SIGNATURE
                key_size = 256
                tier = XTier.OPERATIONAL
            elif (
                "EC" in name_upper
                or "ecdsa" in rel_lower
                or "prime256v1" in file_sample
                or "secp256r1" in file_sample
                or "1.2.840.10045" in file_sample
                or "wallet" in rel_lower
                or "PRIVATE KEY" in file_sample
                or rel_path.endswith("_sk")
                or "priv_sk" in rel_path
                or "keystore" in rel_path
            ):
                alg_name = "ECDSA-P256"
                prim = PrimitiveType.SIGNATURE
                key_size = 256
                tier = XTier.OPERATIONAL
            elif "ED25519" in name_upper or "ed25519" in rel_lower:
                alg_name = "Ed25519"
                prim = PrimitiveType.SIGNATURE
                key_size = 256
                tier = XTier.OPERATIONAL
            elif rel_path.endswith(".env") or "generic-api-key" in comp_name.lower() or "secret" in comp_name.lower():
                alg_name = "SECRET-TOKEN"
                prim = PrimitiveType.ENCRYPTION
                key_size = 256
                tier = XTier.OPERATIONAL
            else:
                alg_name = comp_name
                prim = PrimitiveType.ENCRYPTION
                tier = XTier.ARCHIVAL if mat_type == "private-key" else XTier.OPERATIONAL

            asset_id = f"THEIA-KEY-{len(discovered_assets) + 1:03d}"
            asset = CryptoAsset(
                asset_id=asset_id,
                component_name=f"keyfile:{Path(rel_path).stem}_{mat_type}",
                algorithm=alg_name,
                key_size=key_size,
                primitive_type=prim,
                file_path=rel_path,
                line_number=1,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=False,
                raw_properties={
                    "source": "cbomkit-theia",
                    "assetType": "related-crypto-material",
                    "keyType": mat_type,
                    "format": mat_props.get("format", "PEM"),
                    "oid": oid,
                },
            )
            discovered_assets.append(asset)

    return discovered_assets
