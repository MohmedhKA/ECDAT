"""
ECDAT OASIS SARIF 2.1.0 Integration:
Generates standard static analysis results for GitHub Advanced Security,
GitLab SAST, and automated CI/CD security quality gates.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Union

from ecdat.models import CryptoAsset, PrimitiveType
import ecdat.agility.recommender as pqc_recommender

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "ECDAT"
TOOL_VERSION = "2.0.0"
TOOL_INFORMATION_URI = "https://github.com/SIH26164/ECDAT"

SARIF_RULES: List[Dict[str, Any]] = [
    {
        "id": "ECDAT-CWE-326",
        "name": "InadequateEncryptionStrength",
        "shortDescription": {
            "text": "Inadequate encryption strength or weak cryptographic key size (CWE-326)"
        },
        "fullDescription": {
            "text": (
                "The cryptographic primitive uses a key length below the minimum required "
                "by NIST SP 800-131A Rev 2 (e.g., RSA < 2048 bits or ECC < 224 bits), "
                "exposing encrypted data or signatures to factoring or brute-force attacks."
            )
        },
        "defaultConfiguration": {
            "level": "error"
        },
        "help": {
            "text": (
                "Upgrade key sizes to meet NIST SP 800-131A standards (RSA >= 2048/3072 bits, "
                "ECC >= 256 bits, AES >= 128/256 bits) and plan migration to standardized "
                "post-quantum algorithms (ML-KEM / ML-DSA)."
            )
        },
        "properties": {
            "tags": ["security", "cryptography", "cwe-326", "nist-sp-800-131a"],
            "precision": "very-high"
        }
    },
    {
        "id": "ECDAT-CWE-327",
        "name": "BrokenOrRiskyCryptographicAlgorithm",
        "shortDescription": {
            "text": "Use of a broken or risky cryptographic algorithm (CWE-327)"
        },
        "fullDescription": {
            "text": (
                "The cryptographic primitive is broken, obsolete, or banned by NIST and "
                "industry security standards (e.g., MD5, SHA-1, DES, 3DES, RC4, ECB mode)."
            )
        },
        "defaultConfiguration": {
            "level": "error"
        },
        "help": {
            "text": (
                "Replace deprecated algorithms with approved modern primitives (e.g., SHA-256/SHA-3, "
                "AES-256-GCM) and transition to post-quantum standards."
            )
        },
        "properties": {
            "tags": ["security", "cryptography", "cwe-327", "deprecated-crypto"],
            "precision": "very-high"
        }
    },
    {
        "id": "ECDAT-PQC-MIGRATE-FIPS203",
        "name": "QuantumVulnerableKeyExchange",
        "shortDescription": {
            "text": "Classical key exchange / KEM vulnerable to quantum Harvest-Now-Decrypt-Later (FIPS 203)"
        },
        "fullDescription": {
            "text": (
                "The key exchange or encapsulation mechanism relies on classical discrete logarithm "
                "or integer factorization, rendering it vulnerable to Shor's algorithm and retrospective "
                "Harvest-Now-Decrypt-Later (HNDL) attacks. Migrate to NIST FIPS 203 (ML-KEM)."
            )
        },
        "defaultConfiguration": {
            "level": "error"
        },
        "help": {
            "text": (
                "Upgrade to NIST FIPS 203 ML-KEM-768 or standardized hybrid key exchange "
                "(e.g., X25519MLKEM768 / SecP256r1MLKEM768 per RFC 9180 / IETF drafts)."
            )
        },
        "properties": {
            "tags": ["security", "cryptography", "post-quantum", "fips-203", "ml-kem", "hndl"],
            "precision": "very-high"
        }
    },
    {
        "id": "ECDAT-PQC-MIGRATE-FIPS204",
        "name": "QuantumVulnerableDigitalSignature",
        "shortDescription": {
            "text": "Classical digital signature scheme vulnerable to quantum forgery (FIPS 204)"
        },
        "fullDescription": {
            "text": (
                "The digital signature primitive relies on classical modular arithmetic or elliptic "
                "curves (RSA, ECDSA, Ed25519), which can be forged in polynomial time by a "
                "Cryptanalytically Relevant Quantum Computer (CRQC). Migrate to NIST FIPS 204 (ML-DSA)."
            )
        },
        "defaultConfiguration": {
            "level": "error"
        },
        "help": {
            "text": (
                "Upgrade to NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium) or stateful hash-based "
                "signatures for firmware verification (LMS/XMSS per RFC 8554 / RFC 8391)."
            )
        },
        "properties": {
            "tags": ["security", "cryptography", "post-quantum", "fips-204", "ml-dsa"],
            "precision": "very-high"
        }
    }
]

RULE_INDEX_MAP = {r["id"]: idx for idx, r in enumerate(SARIF_RULES)}


def _resolve_risk_level(asset: CryptoAsset) -> str:
    """Extracts or computes the risk level for a CryptoAsset without using regex."""
    if asset.risk_level:
        return asset.risk_level
    raw = getattr(asset, "raw_properties", {}) or {}
    if "risk_level" in raw and raw["risk_level"]:
        return str(raw["risk_level"])
    if "ecdat:risk_level" in raw and raw["ecdat:risk_level"]:
        return str(raw["ecdat:risk_level"])
    try:
        from ecdat.mosca.engine import compute_mosca_score
        return compute_mosca_score(asset).risk_level
    except Exception:
        return "HIGH"


def _map_asset_to_rule_id(asset: CryptoAsset) -> str:
    """
    Maps a cryptographic asset to a structured SARIF rule ID using
    deterministic string analysis (strictly zero-regex).
    """
    raw = getattr(asset, "raw_properties", {}) or {}
    raw_cwe = str(raw.get("cwe", "")).upper()
    if "326" in raw_cwe or "CWE-326" in raw_cwe:
        return "ECDAT-CWE-326"
    if "327" in raw_cwe or "CWE-327" in raw_cwe:
        return "ECDAT-CWE-327"

    alg = asset.algorithm.upper()
    pt = asset.primitive_type

    # 1. Inadequate key strength checks (CWE-326)
    if asset.key_size is not None:
        is_finite_field = (
            "RSA" in alg
            or ("DH" in alg and "ECDH" not in alg)
            or (alg == "DSA" or ("DSA" in alg and "ECDSA" not in alg and "ML-DSA" not in alg))
        )
        if is_finite_field and asset.key_size < 2048:
            return "ECDAT-CWE-326"
        if ("ECDSA" in alg or "ECDH" in alg) and asset.key_size < 224:
            return "ECDAT-CWE-326"
        if pt in (PrimitiveType.ENCRYPTION, PrimitiveType.SYMMETRIC_CIPHER) and asset.key_size < 128:
            return "ECDAT-CWE-326"

    # 2. Broken or obsolete primitives (CWE-327)
    broken_tokens = (
        "DES", "3DES", "DESEDE", "RC4", "ARCFOUR", "RC2", "RC5", "BLOWFISH", "IDEA",
        "MD5", "MD4", "MD2", "SHA-1", "SHA1", "HMAC-MD5", "HMAC-SHA1", "ECB",
        "STATIC-IV", "PREDICTABLE-KEY", "STATIC-SALT", "PREDICTABLE-SEED",
        "PBE-WEAK-ITERATION", "HARDCODED-PASSWORD", "PREDICTABLE-KEYSTORE",
        "CLEARTEXT-HTTP", "DUMMY-CERT", "DUMMY-HOSTNAME", "IMPROPER-SSL", "UNTRUSTED-PRNG"
    )
    if any(token in alg for token in broken_tokens):
        return "ECDAT-CWE-327"

    if asset.is_classically_broken:
        return "ECDAT-CWE-327"

    # 3. Quantum-vulnerable signatures (FIPS 204)
    if pt == PrimitiveType.SIGNATURE or any(s in alg for s in ("SIGN", "ECDSA", "ED25519", "DSA", "RSA-PSS")):
        return "ECDAT-PQC-MIGRATE-FIPS204"

    # 4. Quantum-vulnerable key exchanges / KEM (FIPS 203)
    if pt == PrimitiveType.KEY_EXCHANGE or any(k in alg for k in ("DH", "ECDH", "KEM", "KYBER", "ML-KEM", "KEY_EXCHANGE", "RSA")):
        return "ECDAT-PQC-MIGRATE-FIPS203"

    # 5. Default fallback based on primitive
    if pt == PrimitiveType.SIGNATURE:
        return "ECDAT-PQC-MIGRATE-FIPS204"
    elif pt == PrimitiveType.KEY_EXCHANGE:
        return "ECDAT-PQC-MIGRATE-FIPS203"
    elif pt in (PrimitiveType.ENCRYPTION, PrimitiveType.SYMMETRIC_CIPHER):
        return "ECDAT-CWE-326"
    return "ECDAT-CWE-326"


def _map_risk_to_sarif_level(risk_level: str) -> str:
    """Maps risk severity level to SARIF 2.1.0 result level."""
    rl = (risk_level or "").upper()
    if rl in ("CRITICAL", "HIGH"):
        return "error"
    elif rl in ("MEDIUM", "MANUAL_REVIEW_REQUIRED"):
        return "warning"
    return "note"


def generate_sarif_dict(assets: List[CryptoAsset]) -> Dict[str, Any]:
    """
    Emits a valid OASIS SARIF 2.1.0 dictionary containing full rule descriptors,
    source locations, and enriched quantum migration recommendations.
    """
    results: List[Dict[str, Any]] = []

    for asset in assets:
        risk_level = _resolve_risk_level(asset)
        rule_id = _map_asset_to_rule_id(asset)
        sarif_level = _map_risk_to_sarif_level(risk_level)
        rule_idx = RULE_INDEX_MAP.get(rule_id, 0)

        # Retrieve fine-grained migration recommendation
        try:
            rec = pqc_recommender.recommend_pqc_migration(asset)
            pqc_alt = rec.recommended_pqc_standalone or rec.recommended_hybrid or "ML-KEM / ML-DSA"
            nist_rec = rec.target_standard or "NIST FIPS 203/204"
            hybrid_rec = rec.recommended_hybrid or "Standardized Hybrid Combiner"
        except Exception:
            pqc_alt = "ML-KEM-768 / ML-DSA-65"
            nist_rec = "NIST SP 800-131A / FIPS 203/204"
            hybrid_rec = "Standardized Hybrid Combiner"

        msg_text = (
            f"Cryptographic asset '{asset.algorithm}' in component '{asset.component_name}' "
            f"evaluated at {risk_level} risk level. "
            f"NIST Recommendation: {nist_rec}. "
            f"Post-Quantum Alternative: {pqc_alt} (Hybrid: {hybrid_rec})."
        )

        norm_path = asset.file_path.replace("\\", "/") if asset.file_path else "unknown"
        line_num = asset.line_number if asset.line_number > 0 else 1

        result_obj: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_idx,
            "level": sarif_level,
            "message": {
                "text": msg_text
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": norm_path
                        },
                        "region": {
                            "startLine": line_num
                        }
                    }
                }
            ],
            "properties": {
                "assetId": asset.asset_id,
                "componentName": asset.component_name,
                "algorithm": asset.algorithm,
                "keySize": asset.key_size,
                "primitiveType": asset.primitive_type.value if hasattr(asset.primitive_type, "value") else str(asset.primitive_type),
                "riskLevel": risk_level,
                "nistRecommendation": nist_rec,
                "pqcAlternative": pqc_alt,
                "recommendedHybrid": hybrid_rec,
            }
        }
        results.append(result_obj)

    sarif_dict: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": SARIF_RULES
                    }
                },
                "results": results
            }
        ]
    }
    return sarif_dict


def export_sarif_file(assets: List[CryptoAsset], output_path: Union[str, Path]) -> Path:
    """
    Serializes discovered cryptographic assets to a SARIF 2.1.0 JSON file
    with indent=2 and utf-8 encoding.
    """
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_dict = generate_sarif_dict(assets)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif_dict, f, indent=2)
    return out_path
