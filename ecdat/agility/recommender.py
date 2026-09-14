"""
ECDAT Hybrid-First Migration Recommender:
Maps quantum-vulnerable classical primitives to NIST FIPS 203/204/205 standards
and standardized hybrid combiners (RFC 9180, IETF composite drafts).
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from ecdat.models import CryptoAsset, PrimitiveType, RouteProfile, PathMTUResult

class MigrationRecommendation(BaseModel):
    current_algorithm: str
    primitive_type: PrimitiveType
    recommended_hybrid: str
    recommended_pqc_standalone: str
    target_standard: str
    size_overhead_factor: float = Field(..., description="Expansion multiplier vs classical primitive")
    security_level: str
    implementation_guidance: str

    # Master Plan Phase 2 Extensions: Active Path MTU & Fragmentation Readiness
    path_profile: Optional[RouteProfile] = Field(None, description="Network transport route profile")
    mtu_constrained: bool = Field(False, description="Whether network path restricts PQC algorithm choice")
    packet_segments: int = Field(1, description="Estimated TCP/IP flight segments required")
    mtu_warning: Optional[str] = Field(None, description="Transport fragmentation middlebox warning")

def recommend_pqc_migration(
    asset: CryptoAsset,
    path_mtu: Optional[PathMTUResult] = None,
    path_profile: Optional[RouteProfile] = None,
) -> MigrationRecommendation:
    """
    Generates standardized post-quantum migration guidance for a cryptographic asset,
    prioritizing hybrid-first deployment to maintain backward compatibility.
    """
    alg_upper = asset.algorithm.upper()

    # ── 0. ALREADY POST-QUANTUM (NIST FIPS 203/204/205 / Lattice LWE) ──
    if any(k in alg_upper for k in ["ML-DSA", "ML-KEM", "DILITHIUM", "KYBER", "SLH-DSA", "FALCON", "LWE"]):
        return MigrationRecommendation(
            current_algorithm=asset.algorithm,
            primitive_type=asset.primitive_type,
            recommended_hybrid="Native / FIPS-Compliant PQC Active",
            recommended_pqc_standalone=asset.algorithm,
            target_standard="NIST FIPS 203/204/205 Approved Standard",
            size_overhead_factor=1.0,
            security_level="NIST Security Category 3-5 (Post-Quantum Secure)",
            implementation_guidance=(
                f"{asset.algorithm} is already post-quantum secure and compliant with NIST standards. "
                "Maintain agility for future NIST parameter revisions."
            ),
        )

    # ── 0b. ZEROKNOWLEDGE COMMITMENTS (Ristretto255 / Pedersen) ──
    if "RISTRETTO" in alg_upper or "PEDERSEN" in alg_upper:
        return MigrationRecommendation(
            current_algorithm=asset.algorithm,
            primitive_type=asset.primitive_type,
            recommended_hybrid="Pedersen Commitment (Info-Theoretic Hiding Active)",
            recommended_pqc_standalone="Lattice-based Commitment (e.g. BDLOP / LWE)",
            target_standard="Information-Theoretic Hiding / Zero-Knowledge Proof",
            size_overhead_factor=1.0,
            security_level="Information-Theoretically Hiding (Shor Resilient for Secrecy)",
            implementation_guidance=(
                "Pedersen commitments over Ristretto255 are information-theoretically hiding; "
                "quantum adversaries cannot invert commitments to recover secrets. "
                "Maintain for real-time verification; plan migration of non-interactive proofs to lattice-based ZK."
            ),
        )

    # ── 0c. CRYPTOGRAPHIC HASH FUNCTIONS ──
    if asset.primitive_type == PrimitiveType.HASH or any(k in alg_upper for k in ["SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA3"]):
        return MigrationRecommendation(
            current_algorithm=asset.algorithm,
            primitive_type=PrimitiveType.HASH,
            recommended_hybrid="N/A (Cryptographic Hash)",
            recommended_pqc_standalone=asset.algorithm,
            target_standard="NIST FIPS 180-4 / FIPS 202",
            size_overhead_factor=1.0,
            security_level="Collision Resistant (Grover/Brassard-Hoyer-Tapp Resilient)",
            implementation_guidance=(
                f"{asset.algorithm} is quantum-resilient against preimage and collision attacks. "
                "Maintain minimum 256-bit digest size."
            ),
        )

    # ── 0d. SYMMETRIC SECRET TOKENS / CONFIG ──
    if "SECRET-TOKEN" in alg_upper or "API-KEY" in alg_upper:
        return MigrationRecommendation(
            current_algorithm=asset.algorithm,
            primitive_type=PrimitiveType.ENCRYPTION,
            recommended_hybrid="N/A (Symmetric Secret)",
            recommended_pqc_standalone="256-bit Symmetric Secret (CSPRNG)",
            target_standard="NIST SP 800-133",
            size_overhead_factor=1.0,
            security_level="Symmetric Secret (128-bit+ Grover Margin)",
            implementation_guidance=(
                "Symmetric configuration secret / token. Ensure key entropy >= 256 bits generated via CSPRNG. "
                "No public-key KEM migration required."
            ),
        )

    # Determine effective route profile and fragmentation estimates
    effective_profile = path_profile or (path_mtu.route_profile if path_mtu else RouteProfile.STANDARD)
    flight_estimates = path_mtu.pqc_flight_estimates if path_mtu else {}

    # ── 1. KEY ESTABLISHMENT (KEM / DH / ECDH) ──
    if asset.primitive_type == PrimitiveType.KEY_EXCHANGE or any(k in alg_upper for k in ["ECDH", "DH", "X25519"]):
        if effective_profile == RouteProfile.CONSTRAINED:
            rec_hybrid = "X25519MLKEM512 (with RFC 8879 Compression)"
            rec_pqc = "ML-KEM-512 (Constrained Route MTU)"
            seg = flight_estimates.get("ML-KEM-512", {}).get("packet_segments", 1)
            mtu_warn = (
                "CONSTRAINED_ROUTE: Path MTU < 1,280 B. ML-KEM-1024 and ML-KEM-768 exceed single packet MTU. "
                "Recommend ML-KEM-512 with RFC 8879 certificate compression."
            )
            is_constrained = True
        elif effective_profile == RouteProfile.STANDARD:
            rec_hybrid = "X25519MLKEM768 (ECDHE-ML-KEM Hybrid)"
            rec_pqc = "ML-KEM-768 (NIST FIPS 203)"
            seg = flight_estimates.get("ML-KEM-768", {}).get("packet_segments", 1)
            mtu_warn = (
                "STANDARD_ROUTE: ML-KEM-768 (1,184 B) fits within standard 1,500 B MTU. "
                "Avoid ML-KEM-1024 (1,568 B) to prevent middlebox packet fragmentation drops."
            )
            is_constrained = False
        else:
            rec_hybrid = "X25519MLKEM768 (ECDHE-ML-KEM Hybrid)"
            rec_pqc = "ML-KEM-1024 / ML-KEM-768"
            seg = 1
            mtu_warn = None
            is_constrained = False

        return MigrationRecommendation(
            current_algorithm=asset.algorithm,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            recommended_hybrid=rec_hybrid,
            recommended_pqc_standalone=rec_pqc,
            target_standard="NIST FIPS 203 / IETF RFC 9180",
            size_overhead_factor=34.0,  # 1088 bytes ciphertext vs 32 bytes X25519
            security_level="NIST Security Category 3 (AES-192 equivalent)",
            path_profile=effective_profile,
            mtu_constrained=is_constrained,
            packet_segments=seg,
            mtu_warning=mtu_warn,
            implementation_guidance=(
                "Deploy X25519MLKEM768 hybrid combiner in TLS 1.3 key_share extension. "
                "Maintains classical security if lattice problem experiences zero-day cryptanalytic break, "
                "while providing immediate protection against Harvest-Now-Decrypt-Later attacks."
            ),
        )

    # ── 2. DIGITAL SIGNATURES (ECDSA / RSA / DSA) ──
    elif asset.primitive_type == PrimitiveType.SIGNATURE or any(k in alg_upper for k in ["ECDSA", "DSA", "ED25519"]) or ("RSA" in alg_upper and "SIGN" in alg_upper):
        is_ecdsa = "ECDSA" in alg_upper or "ED25519" in alg_upper
        overhead = 51.7 if is_ecdsa else 12.9  # 3,309 B vs 64 B (ECDSA) or 256 B (RSA-2048)
        seg = flight_estimates.get("ML-DSA-65", {}).get("packet_segments", 4)

        if effective_profile == RouteProfile.CONSTRAINED:
            mtu_warn = (
                f"CRITICAL_TRANSPORT_ALERT: ML-DSA-65 expands to 3,309 B signature across constrained tunnel (<1,280 B MTU). "
                f"Requires {seg} TCP segments with severe middlebox drop risk. "
                "Recommend SLH-DSA-128s or composite ECDSA with RFC 8879 compression."
            )
            is_constrained = True
        else:
            mtu_warn = (
                f"TRANSPORT_ALERT: ML-DSA-65 certificate flight overhead (~5,261 B) requires {seg} TCP segments. "
                f"Middlebox packet drop risk is {'LOW' if effective_profile == RouteProfile.FLEXIBLE else 'MEDIUM'} on strict DF paths."
            )
            is_constrained = False

        return MigrationRecommendation(
            current_algorithm=asset.algorithm,
            primitive_type=PrimitiveType.SIGNATURE,
            recommended_hybrid="ECDSA-P256 + ML-DSA-65 (Composite Signature)",
            recommended_pqc_standalone="ML-DSA-65 (NIST FIPS 204)",
            target_standard="NIST FIPS 204 / IETF Composite Signatures",
            size_overhead_factor=overhead,
            security_level="NIST Security Category 3 (AES-192 equivalent)",
            path_profile=effective_profile,
            mtu_constrained=is_constrained,
            packet_segments=seg,
            mtu_warning=mtu_warn,
            implementation_guidance=(
                f"Replace classical signature with dual composite or ML-DSA-65. "
                f"CRITICAL: Signature size expands by {overhead:.1f}x (to 3,309 bytes). "
                "Audit message transport MTU, network packet fragmentation, and in-memory buffer allocations "
                "before rolling out."
            ),
        )

    # ── 3. GENERAL ENCRYPTION (Symmetric / Asymmetric OAEP) ──
    else:
        if "AES" in alg_upper and ("256" in alg_upper or "GCM" in alg_upper):
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.ENCRYPTION,
                recommended_hybrid="N/A (Symmetric)",
                recommended_pqc_standalone="AES-256-GCM",
                target_standard="NIST SP 800-38D",
                size_overhead_factor=1.0,
                security_level="256-bit Classical / 128-bit Post-Quantum (Grover resilient)",
                implementation_guidance=(
                    "AES-256 authenticated encryption provides 128 bits of security margin against Grover's quantum search algorithm. "
                    "No migration required under NIST IR 8547 and OMB M-26-15."
                ),
            )
        elif "AES" in alg_upper and "128" in alg_upper:
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.ENCRYPTION,
                recommended_hybrid="N/A (Symmetric)",
                recommended_pqc_standalone="AES-256-GCM",
                target_standard="NIST SP 800-38D",
                size_overhead_factor=1.0,
                security_level="256-bit Classical / 128-bit Post-Quantum (Grover resilient)",
                implementation_guidance=(
                    "Grover's quantum search algorithm reduces symmetric key search complexity from 2^128 to 2^64. "
                    "Upgrade key schedule to AES-256 to ensure 128 bits of quantum security margin."
                ),
            )
        elif any(k in alg_upper for k in ["3DES", "DES", "RC4"]):
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.ENCRYPTION,
                recommended_hybrid="N/A (Symmetric)",
                recommended_pqc_standalone="AES-256-GCM / ChaCha20-Poly1305",
                target_standard="NIST SP 800-38D",
                size_overhead_factor=1.0,
                security_level="Critical Vulnerability (Legacy)",
                implementation_guidance=(
                    "Legacy cipher vulnerable to both classical and quantum attacks. "
                    "Deprecate immediately and transition to AES-256-GCM authenticated encryption."
                ),
            )
        else:
            # Default fallback (e.g. general RSA)
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.ENCRYPTION,
                recommended_hybrid="X25519MLKEM768 (Key Exchange) or Composite ML-DSA",
                recommended_pqc_standalone="ML-KEM-768 / ML-DSA-65",
                target_standard="NIST FIPS 203 / 204",
                size_overhead_factor=13.0,
                security_level="NIST Security Category 3",
                implementation_guidance="Transition to NIST FIPS PQC standards per OMB M-26-15 roadmap.",
            )
