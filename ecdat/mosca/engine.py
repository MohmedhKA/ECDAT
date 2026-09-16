"""
ECDAT Mosca Temporal Risk Engine: Implements Y_max = Z - X engineering budget
with dual-Z regulatory and physical quantum arrival groundings.
"""

from typing import Optional, Tuple
from ecdat.constants import (
    CURRENT_YEAR,
    OMB_M2615_SCHEDULE,
    GRI_2025_DISTRIBUTION,
    X_TIER_DEFAULT_YEARS,
    CAMS_AGILITY_DISCOUNTS,
    INTENT_CLASS_WEIGHTS,
)
from ecdat.models import CryptoAsset, MoscaScore, PrimitiveType, XTier, IntentClass

def is_post_quantum(alg: str) -> bool:
    alg_upper = alg.upper()
    return any(k in alg_upper for k in [
        "ML-DSA", "ML-KEM", "DILITHIUM", "KYBER", "SLH-DSA", "FALCON", "LWE", "SPHINCS", "POST-QUANTUM", "PQC", "LIBOQS"
    ])

def is_classically_broken_or_misuse(asset: CryptoAsset) -> bool:
    """
    Detects deprecated or disallowed classical cryptography and security misuses
    per NIST SP 800-131A Rev 2, OMB M-26-15, and CWE (CWE-327, CWE-326, CWE-321, CWE-330).
    """
    alg = asset.algorithm.upper()

    broken_primitives = [
        "DES", "3DES", "DESEDE", "RC4", "ARCFOUR", "RC2", "RC5", "BLOWFISH", "IDEA",
        "MD5", "MD4", "MD2", "SHA-1", "SHA1", "HMAC-MD5", "HMAC-SHA1",
        "ECB", "STATIC-IV", "PREDICTABLE-KEY", "STATIC-SALT", "PREDICTABLE-SEED",
        "PBE-WEAK-ITERATION", "HARDCODED-PASSWORD", "PREDICTABLE-KEYSTORE",
        "CLEARTEXT-HTTP", "DUMMY-CERT", "DUMMY-HOSTNAME", "IMPROPER-SSL", "UNTRUSTED-PRNG"
    ]
    if any(b in alg for b in broken_primitives):
        return True

    # Deprecated asymmetric key sizes (< 2048-bit RSA/DH/DSA)
    if asset.key_size and asset.key_size < 2048:
        if any(k in alg for k in ["RSA", "DH", "DSA"]):
            return True

    # Check explicit misuse properties or CWE tags
    raw = getattr(asset, "raw_properties", {}) or {}
    if raw.get("misuse_category") or raw.get("cwe"):
        return True

    return False

def is_safe_quantum_or_symmetric(alg: str) -> bool:
    alg_upper = alg.upper()
    return is_post_quantum(alg) or any(k in alg_upper for k in [
        "AES-256", "SECRET-TOKEN", "CHACHA20", "SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA3", "BLAKE", "BLAKE2", "BLAKE3", "RISTRETTO", "PEDERSEN",
        "SECURE-PRNG", "CSPRNG", "PBKDF2", "HOSTNAME-VERIFIER", "TLS-HOSTNAME-VERIFIER", "SECURE-RANDOM"
    ])

def evaluate_regulatory_z(asset: CryptoAsset) -> tuple[int, int]:
    """
    Determines Z_regulatory (year and OMB M-26-15 phase) based on primitive type.
    - Classically Broken / Misuses: Already disallowed (2026, immediate critical)
    - Phase 3 (2030): Key Establishment (KEM, DH, ECDH, RSA key exchange)
    - Phase 4 (2031): Digital Signatures (RSA signatures, ECDSA, DSA)
    - Phase 5 (2035): Full Classical Disallowance
    - PQC & Grover-Safe Symmetric Standards: Non-expiring (2050+)
    """
    if is_classically_broken_or_misuse(asset):
        return 2026, 0
    if is_safe_quantum_or_symmetric(asset.algorithm):
        return 2050, 0
    if asset.primitive_type == PrimitiveType.KEY_EXCHANGE:
        return OMB_M2615_SCHEDULE["PHASE_3"]["year"], 3
    elif asset.primitive_type == PrimitiveType.SIGNATURE:
        return OMB_M2615_SCHEDULE["PHASE_4"]["year"], 4
    else:
        alg = asset.algorithm.upper()
        if "RSA" in alg or "DH" in alg or "ECDH" in alg:
            return OMB_M2615_SCHEDULE["PHASE_3"]["year"], 3
        return OMB_M2615_SCHEDULE["PHASE_5"]["year"], 5

def compute_mosca_score(
    asset: CryptoAsset,
    override_x_years: Optional[float] = None,
    current_year: int = CURRENT_YEAR,
) -> MoscaScore:
    """
    Calculates the actionable Mosca score:
        Y_max = (Z_reg - current_year) - X_effective
    Treats migration time as an engineering budget per asset.
    """
    z_reg_year, z_reg_phase = evaluate_regulatory_z(asset)
    z_phys_prob = GRI_2025_DISTRIBUTION["10_YEAR"]["probability_range"]

    # Determine baseline X
    if override_x_years is not None:
        initial_x = override_x_years
    else:
        initial_x = X_TIER_DEFAULT_YEARS.get(asset.x_tier.value, 5.0)

    # Evaluate crypto-shredding lever
    crypto_shredding_viable = False
    effective_x = initial_x
    if asset.has_crypto_shredding and initial_x > 1.5:
        effective_x = 1.5
        crypto_shredding_viable = True

    # Remaining years until regulatory deadline
    years_to_mandate = float(z_reg_year - current_year)

    # Y_max: Available engineering budget before retrospective HNDL vulnerability
    y_max = round(years_to_mandate - effective_x, 2)
    deadline_year = round(current_year + y_max, 2)

    alg_upper = asset.algorithm.upper()

    # Enriched Quantum Risk Score R_Q
    y_code_baseline = 2.0 if asset.primitive_type in (PrimitiveType.KEY_EXCHANGE, PrimitiveType.SIGNATURE) else 1.0
    overdue_years = max(0.0, (effective_x + y_code_baseline) - years_to_mandate)

    p_hndl = getattr(asset, "p_hndl", 1.0)
    agility_level_val = asset.agility_level.value if hasattr(asset.agility_level, "value") else int(asset.agility_level)
    agility_discount = CAMS_AGILITY_DISCOUNTS.get(agility_level_val, 0.0)

    intent_val = asset.intent_class.value if hasattr(asset.intent_class, "value") else str(asset.intent_class)
    intent_weight = INTENT_CLASS_WEIGHTS.get(intent_val, 1.0)

    r_q = overdue_years * p_hndl * (1.0 - agility_discount) * intent_weight

    # Risk level categorization
    if is_classically_broken_or_misuse(asset):
        risk_level = "CRITICAL"
    elif is_safe_quantum_or_symmetric(asset.algorithm) or intent_weight == 0.0 or p_hndl == 0.0:
        risk_level = "LOW"
    elif y_max <= 1.0:
        risk_level = "CRITICAL"
    elif 1.0 < y_max <= 2.5:
        risk_level = "HIGH"
    elif 2.5 < y_max <= 4.5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Actionable planning notes for CISO
    if intent_val == "OPERATIONAL_UTILITY":
        planning_note = (
            "OPERATIONAL UTILITY: Used for non-sensitive operational caching/deduplication (ETag/cache key). "
            "Quantum exposure risk is 0.0; alert suppressed per DSIS policy."
        )
    elif p_hndl == 0.0:
        planning_note = (
            "AIRGAPPED DEPLOYMENT: No external network ingress/egress. "
            "Harvest-Now-Decrypt-Later (HNDL) adversary capture probability is 0.0."
        )
    elif is_classically_broken_or_misuse(asset):
        planning_note = (
            f"DISALLOWED CLASSICAL CRYPTO / MISUSE: '{asset.algorithm}' is cryptographically broken or insecure "
            f"under NIST SP 800-131A Rev 2 / CWE guidelines. Immediate remediation required (Z_reg <= {z_reg_year}, Y_max <= {y_max}y)."
        )
    elif "RISTRETTO" in alg_upper or "PEDERSEN" in alg_upper:
        planning_note = (
            "PEDERSEN COMMITMENT: Information-theoretically hiding. "
            "Quantum adversaries running Shor's algorithm cannot invert commitments to recover secrets. "
            "Maintain for active verification; plan migration of non-interactive proofs to lattice-based ZK."
        )
    elif "AES-256" in alg_upper or alg_upper == "SECRET-TOKEN" or "SHA" in alg_upper:
        planning_note = (
            "SYMMETRIC QUANTUM SAFE: 256-bit symmetric cipher/hash retains 128 bits of security under Grover's search. "
            "Compliant with NIST IR 8547 and OMB M-26-15 through 2050+."
        )
    elif is_post_quantum(asset.algorithm):
        planning_note = (
            f"POST-QUANTUM SECURE: {asset.algorithm} is fully compliant with NIST FIPS 203/204/205 standards. "
            "Maintain agility for future parameter revisions."
        )
    elif y_max < 0.0:
        planning_note = (
            f"HNDL WINDOW OPEN: Secrecy duration X ({effective_x}y) exceeds years to "
            f"Phase {z_reg_phase} mandate ({years_to_mandate:.1f}y). "
            f"Adversaries harvesting traffic today can decrypt after {z_reg_year}. "
            f"Immediate algorithm migration or crypto-shredding required."
        )
    elif y_max <= 1.0:
        planning_note = (
            f"URGENT MIGRATION: Only {y_max:.1f} years of engineering budget remain before "
            f"HNDL exposure begins. Prioritize in immediate development sprint."
        )
    elif crypto_shredding_viable:
        planning_note = (
            f"LEVER APPLIED: Automated crypto-shredding shrunk effective X from {initial_x}y to {effective_x}y, "
            f"expanding migration budget Y_max to {y_max:.1f} years."
        )
    else:
        planning_note = (
            f"SCHEDULED: Available migration budget Y_max is {y_max:.1f} years. "
            f"Aligned with OMB M-26-15 Phase {z_reg_phase} ({z_reg_year}) mandate."
        )

    return MoscaScore(
        asset_id=asset.asset_id,
        x_years_effective=effective_x,
        z_regulatory_year=z_reg_year,
        z_regulatory_phase=z_reg_phase,
        z_physical_10yr_prob=z_phys_prob,
        y_max_years=y_max,
        deadline_year=deadline_year,
        risk_level=risk_level,
        crypto_shredding_viable=crypto_shredding_viable,
        planning_note=planning_note,
        p_hndl=p_hndl,
        agility_factor=agility_discount,
        r_q_score=round(r_q, 2),
    )
