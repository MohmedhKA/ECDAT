"""
ECDAT Cryptographic Asset Factory:
Instantiates strictly typed, polymorphic CryptoAsset subclasses (PostQuantumAsset,
ClassicalAsymmetricAsset, EllipticCurveAsset, SymmetricAsset, UnknownOrOpaqueAsset)
preserving mathematical units, security standards, and regulatory deadlines.
"""

from typing import Optional, Dict, Any, Tuple
from ecdat.models import (
    CryptoAsset,
    PostQuantumAsset,
    ClassicalAsymmetricAsset,
    EllipticCurveAsset,
    SymmetricAsset,
    UnknownOrOpaqueAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
    IntentClass,
    AgilityLevel,
)
from ecdat.intent.classifier import classify_intent
from ecdat.agility.cams_detector import detect_cams_agility


class CryptoAssetFactory:
    """Central factory constructing polymorphic cryptographic asset models."""

    @staticmethod
    def create_asset(
        asset_prefix: str,
        index: int,
        component_name: str,
        algorithm: str,
        key_size: Optional[int],
        primitive_type: PrimitiveType,
        file_path: str,
        line_number: int,
        tier: XTier,
        has_shredding: bool,
        evidence_level: EvidenceLevel,
        evidence_source: str,
        matched_code: str,
        language: str,
        cwe: Optional[str] = None,
        description: str = "",
        risk_level: Optional[str] = None,
        extra_properties: Optional[Dict[str, Any]] = None,
    ) -> CryptoAsset:
        alg_upper = algorithm.upper().strip()
        asset_id = f"{asset_prefix}-{index:03d}"

        # Classify intent & CAMS agility
        intent, _ = classify_intent(var_name=component_name, context_lines=matched_code, primitive_type=primitive_type)
        cams_level, cams_desc = detect_cams_agility(source_line=matched_code)

        raw_props: Dict[str, Any] = {
            "source": "contract_engine",
            "language": language,
            "matched_code": matched_code[:120],
            "description": description,
            "cams_evidence": cams_desc,
        }
        if cwe:
            raw_props["cwe"] = cwe
        if risk_level:
            raw_props["ecdat:risk_level"] = risk_level
        if extra_properties:
            raw_props.update(extra_properties)

        base_kwargs = dict(
            asset_id=asset_id,
            component_name=component_name,
            algorithm=algorithm,
            key_size=key_size,
            primitive_type=primitive_type,
            file_path=file_path,
            line_number=line_number,
            x_tier=tier,
            x_confidence="HIGH" if evidence_level != EvidenceLevel.E0_UNCONFIRMED else "LOW",
            has_crypto_shredding=has_shredding,
            raw_properties=raw_props,
            intent_class=intent,
            evidence_level=evidence_level,
            evidence_sources=[evidence_source],
            agility_level=cams_level,
        )

        # 1. Post-Quantum Cryptography (FIPS 203, 204, 205, LWE)
        if any(k in alg_upper for k in ["ML-DSA", "DILITHIUM", "ML-KEM", "KYBER", "SLH-DSA", "SPHINCS", "FALCON", "LWE", "PQC"]):
            if "ML-DSA" in alg_upper or "DILITHIUM" in alg_upper:
                level = 5 if ("87" in alg_upper or "5" in alg_upper) else (2 if ("44" in alg_upper or "2" in alg_upper) else 3)
                pub_bytes = 2592 if level == 5 else (1312 if level == 2 else 1952)
                sig_bytes = 4627 if level == 5 else (2420 if level == 2 else 3309)
                return PostQuantumAsset(
                    **base_kwargs,
                    nist_level=level,
                    pubkey_bytes=pub_bytes,
                    sig_bytes=sig_bytes,
                )
            elif "ML-KEM" in alg_upper or "KYBER" in alg_upper:
                level = 5 if ("1024" in alg_upper) else (1 if ("512" in alg_upper) else 3)
                pub_bytes = 1568 if level == 5 else (800 if level == 1 else 1184)
                ct_bytes = 1568 if level == 5 else (768 if level == 1 else 1088)
                return PostQuantumAsset(
                    **base_kwargs,
                    nist_level=level,
                    pubkey_bytes=pub_bytes,
                    ciphertext_bytes=ct_bytes,
                )
            elif "LWE" in alg_upper:
                return PostQuantumAsset(
                    **base_kwargs,
                    nist_level=5,
                    pubkey_bytes=65536,
                    ciphertext_bytes=38000,
                )
            return PostQuantumAsset(
                **base_kwargs,
                nist_level=3,
                pubkey_bytes=key_size if key_size else 1952,
            )

        # 2. Elliptic Curve Cryptography (ECDSA, ECDH, Ed25519, Ristretto)
        if any(k in alg_upper for k in ["ECDSA", "ECDH", "ED25519", "ED448", "X25519", "X448", "RISTRETTO", "SECP", "CURVE25519"]):
            curve_bits = 256
            if key_size and key_size in (224, 256, 384, 521):
                curve_bits = key_size
            elif "384" in alg_upper:
                curve_bits = 384
            elif "521" in alg_upper:
                curve_bits = 521
            return EllipticCurveAsset(
                **base_kwargs,
                curve_bits=curve_bits,
                curve_name=alg_upper,
            )

        # 3. Classical Asymmetric (RSA, DH, DSA)
        if any(k in alg_upper for k in ["RSA", "DIFFIEHELLMAN", "DH"]) or (alg_upper == "DSA" or alg_upper.startswith("DSA-")):
            modulus_bits = key_size if (key_size and key_size >= 512) else (1024 if "1024" in alg_upper else (4096 if "4096" in alg_upper else 2048))
            return ClassicalAsymmetricAsset(
                **base_kwargs,
                modulus_bits=modulus_bits,
            )

        # 4. Symmetric Cryptography, Hashes, MACs, KDFs
        if any(k in alg_upper for k in ["AES", "DES", "3DES", "CHACHA", "BLOWFISH", "RC4", "SHA", "MD5", "HMAC", "ARGON", "PBKDF", "BCRYPT", "SCRYPT"]):
            k_bits = key_size if key_size else (128 if "128" in alg_upper else (192 if "192" in alg_upper else (512 if "512" in alg_upper else 256)))
            mode = "ECB" if "ECB" in alg_upper else ("CBC" if "CBC" in alg_upper else "GCM")
            return SymmetricAsset(
                **base_kwargs,
                key_bits=k_bits,
                cipher_mode=mode,
            )

        # 5. Fallback: Generic / Opaque
        return UnknownOrOpaqueAsset(
            **base_kwargs,
            reason=f"Unmodeled primitive: {algorithm}",
        )
