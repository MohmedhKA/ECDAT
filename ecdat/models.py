"""
ECDAT Models: Pydantic schemas for cryptographic assets, persistence tiers,
and temporal risk evaluations.
"""

from enum import Enum
from typing import Optional, Dict, Any
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
