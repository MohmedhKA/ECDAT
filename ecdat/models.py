"""
ECDAT Models: Pydantic schemas for cryptographic assets, persistence tiers,
evidence states, security intent, and temporal risk evaluations.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class XTier(str, Enum):
    EPHEMERAL = "EPHEMERAL"       # ~0 years (RAM only, zeroed after use)
    SHORT_TERM = "SHORT_TERM"     # ~1-2 years (session tokens, rotating keys)
    OPERATIONAL = "OPERATIONAL"   # ~3-7 years (standard relational DB, active records)
    ARCHIVAL = "ARCHIVAL"         # ~10+ years (backups, HIPAA/SOX archives)
    HUMAN_REVIEW = "HUMAN_REVIEW" # Ambiguous flow requiring auditor review

class PrimitiveType(str, Enum):
    KEY_EXCHANGE = "KEY_EXCHANGE" # KEM, DH, ECDH
    SIGNATURE = "SIGNATURE"       # DSA, ECDSA, RSA-PSS
    ENCRYPTION = "ENCRYPTION"     # Symmetric/Asymmetric cipher
    HASH = "HASH"                 # Hash functions / MAC

class IntentClass(str, Enum):
    """
    DSIS 4-Class Functional Security Intent Lattice:
    Classifies what purpose the cryptographic primitive serves to prevent primitive-flooding false alarms.
    """
    OPERATIONAL_UTILITY = "OPERATIONAL_UTILITY"           # ETags, cache dedup, hash maps (0% quantum risk)
    INTEGRITY_CHECKSUM = "INTEGRITY_CHECKSUM"             # Build hashes, short-lived file checksums
    AUTHENTICATION_SIGNATURE = "AUTHENTICATION_SIGNATURE" # JWT signing, mTLS, identity proofs
    CONFIDENTIALITY_ENVELOPE = "CONFIDENTIALITY_ENVELOPE" # At-rest DB encryption, in-transit TLS payloads

class EvidenceLevel(str, Enum):
    """
    E0–E5 State Taxonomy:
    Tracks epistemic confidence and verification stages for discovered cryptographic assets.
    """
    E0_UNCONFIRMED = "E0_UNCONFIRMED"         # Regex / string / keyword match only
    E1_STATIC_ARTIFACT = "E1_STATIC_ARTIFACT" # AST-confirmed API invocation
    E2_REACHABLE_PATH = "E2_REACHABLE_PATH"   # Confirmed reachable via static call-graph / data-flow
    E3_CONFIG_CONFIRMED = "E3_CONFIG_CONFIRMED" # Deployment config / certificate file on disk
    E4_RUNTIME_OBSERVED = "E4_RUNTIME_OBSERVED" # Dynamically observed executing at runtime
    E5_CORRELATED_SIGNED = "E5_CORRELATED_SIGNED" # Multi-source verified + cryptographically signed
    DORMANT = "DORMANT"                       # Static asset not observed during runtime coverage window

class AgilityLevel(int, Enum):
    """
    Cryptographic Agility Maturity Score (CAMS) 0–3:
    Measures ease of replacing cryptographic algorithms at the call-site.
    """
    RIGID = 0         # Hardcoded literal algorithm string (baseline effort)
    CONFIGURABLE = 1  # Loaded from environment variable or configuration file
    PROVIDER = 2      # Abstracted behind interface / dependency injection factory
    RUNTIME_AGILE = 3 # Policy-driven crypto-agile facade (e.g. Google Tink, KMS keyset)

class ExposureProfile(str, Enum):
    """Adversarial network exposure profile derived from deployment manifests."""
    PUBLIC = "PUBLIC"       # Internet ingress / LoadBalancer (P_HNDL = 1.0)
    INTERNAL = "INTERNAL"   # ClusterIP / private subnet (P_HNDL = 0.05)
    AIRGAPPED = "AIRGAPPED" # Standalone / no network egress (P_HNDL = 0.0)

class ConfidenceLevel(str, Enum):
    UNVALIDATED = "UNVALIDATED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED = "VERIFIED"

class UnknownEntry(BaseModel):
    """
    Unknowns Ledger Entry:
    Explicit declaration of uninspected files, excluded paths, or encrypted blobs
    to provide auditable boundary honesty.
    """
    item_path: str = Field(..., description="Path or identifier of the uninspected entity")
    category: str = Field(..., description="Category (e.g. EXCLUDED_DIR, ENCRYPTED_KEYSTORE, UNPARSEABLE_BINARY)")
    reason: str = Field(..., description="Technical limitation or filter rule why inspection was omitted")
    recommended_action: str = Field(..., description="Actionable recommendation for auditors")

class CryptoAsset(BaseModel):
    asset_id: str = Field(..., description="Unique asset identifier")
    component_name: str = Field(..., description="Service or module name")
    algorithm: str = Field(..., description="Cryptographic algorithm name (e.g., RSA-2048, ECDSA-P256)")
    key_size: Optional[int] = Field(None, description="Key length in bits (e.g., 2048, 256)")
    primitive_type: PrimitiveType = Field(..., description="Cryptographic role of primitive")
    file_path: str = Field(..., description="Source code or config file path")
    line_number: int = Field(0, description="Line number of cryptographic invocation")
    x_tier: XTier = Field(XTier.HUMAN_REVIEW, description="Inferred data lifespan tier")
    x_confidence: str = Field("LOW", description="Confidence level: HIGH, MEDIUM, LOW")
    has_crypto_shredding: bool = Field(False, description="Whether automated key destruction schedule exists")
    raw_properties: Dict[str, Any] = Field(default_factory=dict, description="Underlying CBOM attributes")

    # Master Plan Phase 1 Extensions
    intent_class: IntentClass = Field(IntentClass.CONFIDENTIALITY_ENVELOPE, description="Functional security intent")
    evidence_level: EvidenceLevel = Field(EvidenceLevel.E1_STATIC_ARTIFACT, description="E0-E5 evidence state")
    evidence_sources: List[str] = Field(default_factory=list, description="List of observation sources (AST, manifest, cert, etc.)")
    agility_level: AgilityLevel = Field(AgilityLevel.RIGID, description="CAMS agility maturity score 0-3")
    exposure_profile: ExposureProfile = Field(ExposureProfile.PUBLIC, description="Network adversarial exposure")
    p_hndl: float = Field(1.0, description="Harvest-Now-Decrypt-Later interception probability [0.0 - 1.0]")
    x_auto_source: str = Field("default", description="Provenance of data lifespan X (e.g. sql_schema, orm_ttl, default)")

class MoscaScore(BaseModel):
    asset_id: str
    x_years_effective: float = Field(..., description="Effective data secrecy duration X (years)")
    z_regulatory_year: int = Field(..., description="Regulatory deprecation deadline year Z_reg")
    z_regulatory_phase: int = Field(..., description="OMB M-26-15 Phase number (3, 4, or 5)")
    z_physical_10yr_prob: str = Field(..., description="Global Risk Institute 10-year CRQC arrival probability")
    y_max_years: float = Field(..., description="Remaining migration engineering budget Y_max = Z - X")
    deadline_year: float = Field(..., description="Calendar year before which migration must be fully deployed")
    risk_level: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")
    crypto_shredding_viable: bool = Field(..., description="Whether crypto-shredding shrank X")
    planning_note: str = Field(..., description="Actionable CISO engineering recommendation")

    # Master Plan Phase 1 Extensions
    p_hndl: float = Field(1.0, description="Network harvest probability factor")
    agility_factor: float = Field(0.0, description="CAMS agility discount [0.0 - 0.85]")
    r_q_score: float = Field(0.0, description="Enriched quantum risk score R_Q")
