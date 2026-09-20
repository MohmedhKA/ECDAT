"""
ECDAT Declarative PQC Standards Catalog:
Machine-readable registry of NIST FIPS 203/204/205 post-quantum standards and RFC 9180
hybrid combiners with fine-grained parameter resolution and zero-regex matching.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    IntentClass,
    XTier,
    RouteProfile,
    PathMTUResult,
)

DEFAULT_STANDARDS_JSON_PATH = (
    Path(__file__).resolve().parent.parent / "rules" / "pqc_standards.json"
)


def _normalize_key(key: str) -> str:
    """Normalize algorithm identifier without regular expressions."""
    cleaned = key.strip().upper()
    res: List[str] = []
    for ch in cleaned:
        if ch in ("_", " ", "/", "+"):
            res.append("-")
        elif ch in ("(", ")", "[", "]", "{", "}"):
            continue
        else:
            res.append(ch)
    # Collapse multiple consecutive hyphens
    collapsed: List[str] = []
    prev_hyphen = False
    for ch in res:
        if ch == "-":
            if not prev_hyphen:
                collapsed.append("-")
                prev_hyphen = True
        else:
            collapsed.append(ch)
            prev_hyphen = False
    return "".join(collapsed).strip("-")


class PQCAlgorithmSpec(BaseModel):
    """Declarative specification for a standardized or candidate post-quantum algorithm."""

    name: str = Field(..., description="Canonical algorithm identifier (e.g. ML-KEM-768)")
    standard_org: str = Field(..., description="Standards organization (NIST, IETF, ISO)")
    standard_ref: Optional[str] = Field(None, description="Standard publication (FIPS 203, RFC 9180)")
    category: str = Field(..., description="Primitive category (KEM, SIGNATURE, HYBRID_KEM, HYBRID_SIGNATURE)")
    security_level: int = Field(..., description="NIST Security Category 1-5")
    public_key_bytes: int = Field(..., description="Public key wire length in bytes")
    ciphertext_or_signature_bytes: int = Field(..., description="Ciphertext (KEM) or Signature (DSA) wire length in bytes")
    shared_secret_bytes: Optional[int] = Field(None, description="Decapsulated symmetric key length in bytes")
    replacement_targets: List[str] = Field(default_factory=list, description="Classical primitives this replaces")
    performance_rating: str = Field("FAST", description="Relative computational throughput rating")
    is_primary: bool = Field(False, description="Whether this is the recommended primary default for the category")
    description: Optional[str] = Field(None, description="Technical summary and deployment advice")

    @property
    def signature_bytes(self) -> int:
        return self.ciphertext_or_signature_bytes

    @property
    def ciphertext_bytes(self) -> int:
        return self.ciphertext_or_signature_bytes


class MigrationRecommendation(BaseModel):
    """Post-quantum migration guidance with fine-grained parameter targets and transport safety."""

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

    # Declarative Standards Catalog Integration
    target_pqc_spec: Optional[PQCAlgorithmSpec] = Field(None, description="Detailed PQC specification from standards catalog")


class PQCStandardsCatalog:
    """
    Thread-safe, declarative catalog of PQC standards.
    Supports dynamic registration and zero-regex case-insensitive lookups.
    """

    def __init__(self, specs: Optional[Dict[str, PQCAlgorithmSpec]] = None) -> None:
        self._specs: Dict[str, PQCAlgorithmSpec] = {}
        if specs:
            for spec in specs.values():
                self.register_standard(spec)

    @classmethod
    def load_default(cls, json_path: Optional[Path] = None) -> "PQCStandardsCatalog":
        """Load the standard PQC algorithm definitions from the declarative JSON catalog."""
        path = Path(json_path) if json_path else DEFAULT_STANDARDS_JSON_PATH
        if not path.exists():
            raise FileNotFoundError(f"PQC standards catalog JSON not found at: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        specs: List[PQCAlgorithmSpec] = []
        if isinstance(data, dict):
            raw_list = data.get("standards", data.get("algorithms", []))
            if isinstance(raw_list, list):
                for item in raw_list:
                    specs.append(PQCAlgorithmSpec(**item))
            elif isinstance(raw_list, dict):
                for k, v in raw_list.items():
                    if "name" not in v:
                        v["name"] = k
                    specs.append(PQCAlgorithmSpec(**v))
        elif isinstance(data, list):
            for item in data:
                specs.append(PQCAlgorithmSpec(**item))

        catalog = cls()
        for spec in specs:
            catalog.register_standard(spec)
        return catalog

    def register_standard(self, spec: PQCAlgorithmSpec) -> None:
        """Register a new or custom PQC algorithm specification into the catalog."""
        norm = _normalize_key(spec.name)
        self._specs[norm] = spec

        # Register common variations and aliases
        upper = spec.name.upper()
        if "COMPOSITE-KEM" in upper or "X25519MLKEM768" in upper:
            self._specs["X25519MLKEM768"] = spec
            self._specs["X25519-ML-KEM-768"] = spec
            self._specs["COMPOSITE-KEM-X25519-ML-KEM-768"] = spec
        if "COMPOSITE-SIGN" in upper or "ECDSA-P256-ML-DSA-65" in upper:
            self._specs["COMPOSITE-SIGN-ECDSA-P256-ML-DSA-65"] = spec
            self._specs["ECDSA-P256-ML-DSA-65"] = spec

    def get_spec(self, name: str) -> Optional[PQCAlgorithmSpec]:
        """Case-insensitive, zero-regex lookup of a PQC algorithm specification."""
        norm = _normalize_key(name)
        if norm in self._specs:
            return self._specs[norm]

        # Zero-regex submatch fallback
        for k, spec in self._specs.items():
            if norm == k or norm in k or k in norm:
                return spec
        return None

    def recommend_for_asset(
        self,
        asset: CryptoAsset,
        path_mtu: Optional[PathMTUResult] = None,
        path_profile: Optional[RouteProfile] = None,
    ) -> MigrationRecommendation:
        """
        Generate fine-grained post-quantum migration guidance for a cryptographic asset,
        mapping quantum-vulnerable primitives to exact NIST FIPS parameter targets.
        """
        alg_upper = asset.algorithm.upper()

        # ── 0. ALREADY POST-QUANTUM ──
        if any(k in alg_upper for k in ["ML-DSA", "ML-KEM", "DILITHIUM", "KYBER", "SLH-DSA", "FALCON", "LWE"]):
            matched_spec = self.get_spec(asset.algorithm)
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
                target_pqc_spec=matched_spec,
            )

        # ── 0b. ZERO-KNOWLEDGE COMMITMENTS (Ristretto255 / Pedersen) ──
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

        # ── 0c. DYNAMIC UNRESOLVED CALL SITES ──
        if "DYNAMIC_UNRESOLVED" in alg_upper:
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=asset.primitive_type,
                recommended_hybrid="Manual Triage Required",
                recommended_pqc_standalone="Manual Triage Required",
                target_standard="Human Review Required",
                size_overhead_factor=1.0,
                security_level="UNKNOWN (Dynamic Call)",
                implementation_guidance=(
                    "Dynamic cryptographic instantiation cannot be statically verified. "
                    "Auditor intervention required to inspect runtime configuration or instrument dynamic execution (E4)."
                ),
            )

        # ── 0d. CRYPTOGRAPHIC HASH FUNCTIONS ──
        if asset.primitive_type == PrimitiveType.HASH or any(
            k in alg_upper for k in ["SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA3"]
        ):
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

        # ── 0e. SYMMETRIC SECRET TOKENS / CONFIG ──
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

        effective_profile = (
            path_profile
            or (path_mtu.route_profile if path_mtu else RouteProfile.STANDARD)
        )
        flight_estimates = path_mtu.pqc_flight_estimates if path_mtu else {}

        # ── 1. DIGITAL SIGNATURES (ECDSA / RSA-PSS / DSA / Ed25519) ──
        # Check if primitive is SIGNATURE, or IntentClass is AUTHENTICATION/INTEGRITY (unless KEY_EXCHANGE)
        is_signature = (
            asset.primitive_type == PrimitiveType.SIGNATURE
            or any(k in alg_upper for k in ["ECDSA", "DSA", "ED25519", "ED448"])
            or ("RSA" in alg_upper and ("SIGN" in alg_upper or "PSS" in alg_upper))
            or (
                asset.intent_class in (IntentClass.AUTHENTICATION_SIGNATURE, IntentClass.INTEGRITY_CHECKSUM)
                and asset.primitive_type != PrimitiveType.KEY_EXCHANGE
                and not any(k in alg_upper for k in ["ECDH", "DH", "X25519"])
            )
        )

        if is_signature:
            is_ecdsa = "ECDSA" in alg_upper or "ED25519" in alg_upper or "EC" in alg_upper
            seg = flight_estimates.get("ML-DSA-65", {}).get("packet_segments", 4)

            # Fine-grained parameter target selection:
            # - Category 5 (Level 5): RSA >= 4096, P-521, ED448, or Archival with high key size
            # - Category 2 (Level 2): Key size <= 1024 or explicit level 2 request
            # - Category 3 (Level 3): Default primary standard (ECDSA-P256, ECDSA-P384, RSA-2048, RSA-3072)
            if (
                (asset.key_size and asset.key_size >= 4096)
                or "4096" in alg_upper
                or "521" in alg_upper
                or "ED448" in alg_upper
                or (asset.x_tier == XTier.ARCHIVAL and asset.key_size and asset.key_size >= 384)
            ):
                target_spec = self.get_spec("ML-DSA-87")
                rec_hybrid = "Composite-Sign (ECDSA-P384 + ML-DSA-87)"
                rec_pqc = "ML-DSA-87 (NIST FIPS 204)"
                sec_level = "NIST Security Category 5 (AES-256 equivalent)"
                overhead = 72.3 if is_ecdsa else (9.0 if (asset.key_size and asset.key_size >= 4096) else 18.1)
                sig_bytes = 4627
            elif (
                (asset.key_size and asset.key_size <= 1024 and "256" not in alg_upper and "384" not in alg_upper)
                or "1024" in alg_upper
            ):
                target_spec = self.get_spec("ML-DSA-44")
                rec_hybrid = "Composite-Sign (ECDSA-P256 + ML-DSA-44)"
                rec_pqc = "ML-DSA-44 (NIST FIPS 204)"
                sec_level = "NIST Security Category 2 (AES-128 equivalent)"
                overhead = 37.8 if is_ecdsa else 9.5
                sig_bytes = 2420
            else:
                target_spec = self.get_spec("ML-DSA-65")
                rec_hybrid = "ECDSA-P256 + ML-DSA-65 (Composite Signature)"
                rec_pqc = "ML-DSA-65 (NIST FIPS 204)"
                sec_level = "NIST Security Category 3 (AES-192 equivalent)"
                overhead = 51.7 if is_ecdsa else 12.9
                sig_bytes = 3309

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
                recommended_hybrid=rec_hybrid,
                recommended_pqc_standalone=rec_pqc,
                target_standard="NIST FIPS 204 / IETF Composite Signatures",
                size_overhead_factor=overhead,
                security_level=sec_level,
                path_profile=effective_profile,
                mtu_constrained=is_constrained,
                packet_segments=seg,
                mtu_warning=mtu_warn,
                implementation_guidance=(
                    f"Replace classical signature with dual composite or {target_spec.name if target_spec else 'ML-DSA-65'}. "
                    f"CRITICAL: Signature size expands by {overhead:.1f}x (to {sig_bytes} bytes). "
                    "Audit message transport MTU, network packet fragmentation, and in-memory buffer allocations "
                    "before rolling out."
                ),
                target_pqc_spec=target_spec,
            )

        # ── 2. KEY ESTABLISHMENT / CONFIDENTIALITY (KEM / DH / ECDH / Asymmetric Encryption) ──
        is_kem = (
            asset.primitive_type == PrimitiveType.KEY_EXCHANGE
            or any(k in alg_upper for k in ["ECDH", "DH", "X25519", "KEM"])
            or (
                asset.intent_class == IntentClass.CONFIDENTIALITY_ENVELOPE
                and (
                    any(k in alg_upper for k in ["RSA", "DH", "ECDH", "X25519"])
                    or asset.primitive_type == PrimitiveType.KEY_EXCHANGE
                )
            )
        )

        if is_kem:
            if effective_profile == RouteProfile.CONSTRAINED:
                target_spec = self.get_spec("ML-KEM-512")
                rec_hybrid = "X25519MLKEM512 (with RFC 8879 Compression)"
                rec_pqc = "ML-KEM-512 (Constrained Route MTU)"
                seg = flight_estimates.get("ML-KEM-512", {}).get("packet_segments", 1)
                mtu_warn = (
                    "CONSTRAINED_ROUTE: Path MTU < 1,280 B. ML-KEM-1024 and ML-KEM-768 exceed single packet MTU. "
                    "Recommend ML-KEM-512 with RFC 8879 certificate compression."
                )
                is_constrained = True
                overhead = 24.0
                sec_level = "NIST Security Category 1 (AES-128 equivalent)"
            else:
                is_constrained = False
                # Fine-grained parameter target selection:
                # - Category 5: RSA-4096, P-521, DH-4096, Archival
                # - Category 1: Key size <= 1024
                # - Category 3: Default primary standard (RSA-2048, RSA-3072, ECDH-P256, ECDH-P384, DH-2048)
                if (
                    (asset.key_size and asset.key_size >= 4096)
                    or "4096" in alg_upper
                    or "521" in alg_upper
                    or (asset.x_tier == XTier.ARCHIVAL and asset.key_size and asset.key_size > 2048)
                ):
                    target_spec = self.get_spec("ML-KEM-1024")
                    rec_hybrid = "Composite-KEM (X25519 + ML-KEM-1024)"
                    rec_pqc = "ML-KEM-1024 (NIST FIPS 203)"
                    overhead = 49.0
                    sec_level = "NIST Security Category 5 (AES-256 equivalent)"
                    seg = flight_estimates.get("ML-KEM-1024", {}).get("packet_segments", 2)
                    mtu_warn = None if effective_profile == RouteProfile.FLEXIBLE else (
                        "STANDARD_ROUTE: ML-KEM-1024 (1,568 B) exceeds standard 1,500 B MTU. "
                        "May trigger middlebox fragmentation drops."
                    )
                elif (
                    (asset.key_size and asset.key_size <= 1024 and "256" not in alg_upper and "384" not in alg_upper)
                    or "1024" in alg_upper
                ):
                    target_spec = self.get_spec("ML-KEM-512")
                    rec_hybrid = "X25519MLKEM512 (ECDHE-ML-KEM Hybrid)"
                    rec_pqc = "ML-KEM-512 (NIST FIPS 203)"
                    overhead = 24.0
                    sec_level = "NIST Security Category 1 (AES-128 equivalent)"
                    seg = 1
                    mtu_warn = None
                else:
                    target_spec = self.get_spec("ML-KEM-768")
                    rec_hybrid = "X25519MLKEM768 (ECDHE-ML-KEM Hybrid)"
                    rec_pqc = "ML-KEM-768 (NIST FIPS 203)"
                    overhead = 34.0
                    sec_level = "NIST Security Category 3 (AES-192 equivalent)"
                    seg = flight_estimates.get("ML-KEM-768", {}).get("packet_segments", 1)
                    if effective_profile == RouteProfile.STANDARD:
                        mtu_warn = (
                            "STANDARD_ROUTE: ML-KEM-768 (1,184 B) fits within standard 1,500 B MTU. "
                            "Avoid ML-KEM-1024 (1,568 B) to prevent middlebox packet fragmentation drops."
                        )
                    else:
                        mtu_warn = None

            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                recommended_hybrid=rec_hybrid,
                recommended_pqc_standalone=rec_pqc,
                target_standard="NIST FIPS 203 / IETF RFC 9180",
                size_overhead_factor=overhead,
                security_level=sec_level,
                path_profile=effective_profile,
                mtu_constrained=is_constrained,
                packet_segments=seg,
                mtu_warning=mtu_warn,
                implementation_guidance=(
                    "Deploy X25519MLKEM768 hybrid combiner in TLS 1.3 key_share extension. "
                    "Maintains classical security if lattice problem experiences zero-day cryptanalytic break, "
                    "while providing immediate protection against Harvest-Now-Decrypt-Later attacks."
                ),
                target_pqc_spec=target_spec,
            )

        # ── 3. SYMMETRIC CIPHERS (AES / 3DES / DES / RC4) ──
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

        # ── 4. GENERAL ASYMMETRIC FALLBACK ──
        if (asset.key_size and asset.key_size >= 4096) or "4096" in alg_upper:
            target_spec = self.get_spec("ML-KEM-1024")
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.ENCRYPTION,
                recommended_hybrid="Composite-KEM (X25519 + ML-KEM-1024) or Composite ML-DSA-87",
                recommended_pqc_standalone="ML-KEM-1024 / ML-DSA-87",
                target_standard="NIST FIPS 203 / 204",
                size_overhead_factor=13.0,
                security_level="NIST Security Category 5 (AES-256 equivalent)",
                implementation_guidance="Transition to NIST FIPS PQC standards per OMB M-26-15 roadmap.",
                target_pqc_spec=target_spec,
            )
        else:
            target_spec = self.get_spec("ML-KEM-768")
            return MigrationRecommendation(
                current_algorithm=asset.algorithm,
                primitive_type=PrimitiveType.ENCRYPTION,
                recommended_hybrid="X25519MLKEM768 (Key Exchange) or Composite ML-DSA",
                recommended_pqc_standalone="ML-KEM-768 / ML-DSA-65",
                target_standard="NIST FIPS 203 / 204",
                size_overhead_factor=13.0,
                security_level="NIST Security Category 3",
                implementation_guidance="Transition to NIST FIPS PQC standards per OMB M-26-15 roadmap.",
                target_pqc_spec=target_spec,
            )
