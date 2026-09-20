"""
ECDAT Cryptographic Contract Engine Base Framework:
Defines abstract interfaces, normalized cryptographic call fingerprints,
and shared context utilities across all language ecosystems.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
    IntentClass,
    AgilityLevel
)
from ecdat.intent.classifier import classify_intent
from ecdat.agility.cams_detector import detect_cams_agility

@dataclass
class CallFingerprint:
    """Normalized cryptographic invocation fingerprint extracted from AST or syntax stream."""
    ecosystem: str                       # 'go', 'java', 'python', 'ruby'
    namespace: str                       # Package / module name (e.g. 'crypto/des', 'OpenSSL::Cipher')
    contract: str                        # Interface / trait name (e.g. 'cipher.Block', 'CipherSpi')
    symbol: str                          # Invocation symbol (e.g. 'NewCipher', 'getInstance', 'new')
    raw_algorithm: Optional[str] = None  # Extracted argument string if provided
    key_size: Optional[int] = None       # Extracted or inferred key size in bits
    args: List[str] = field(default_factory=list)
    line_number: int = 1
    matched_code: str = ""
    evidence_sources: List[str] = field(default_factory=list)

class BaseContractEngine(ABC):
    """Abstract base class for language-specific cryptographic contract visitors."""

    @abstractmethod
    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        """Scans a single source file and returns discovered CryptoAsset models."""
        pass

    @staticmethod
    def extract_line_number(content: str, byte_offset: int) -> int:
        """Computes 1-indexed line number from character offset."""
        return content.count("\n", 0, byte_offset) + 1

    @staticmethod
    def check_crypto_shredding_context(content: str, line_no: int, window: Optional[int] = None) -> Tuple[bool, XTier]:
        """
        Inspects the full module and class scope for volatile memory zeroization,
        ephemeral key lifecycles, HNDL mitigation, or deletion schedules without arbitrary line-window truncation.
        Returns (has_shredding, inferred_tier).
        """
        full_lower = content.lower()

        ephemeral_terms = (
            "zeroize", "zero_memory", "memzero", "memset_s", "explicit_bzero",
            "timingsafeequal", "delete", "clear", "wipe", "shred",
            "ephemeral", "in-memory", "in_memory", "volatile", "hndl",
            "destroy", "destroyed", "never saved to disk", "session-scoped", "election-scoped"
        )

        persistent_sinks = (
            "fs.write", "file.write", "writefilesync", "createwritestream",
            "db.insert", "db.update", "db.query", "repository.save",
            "localstorage.set", "s3.upload", "s3.putobject"
        )

        is_ephemeral_lifecycle = any(term in full_lower for term in ephemeral_terms)
        has_persistent_sink = any(sink in full_lower for sink in persistent_sinks)

        if is_ephemeral_lifecycle and not has_persistent_sink:
            return True, XTier.EPHEMERAL
        elif is_ephemeral_lifecycle and has_persistent_sink:
            return True, XTier.SHORT_TERM
        return False, XTier.OPERATIONAL

    @staticmethod
    def build_crypto_asset(
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
        """Factory creating a standardized polymorphic CryptoAsset model."""
        from ecdat.scanners.factory import CryptoAssetFactory
        return CryptoAssetFactory.create_asset(
            asset_prefix=asset_prefix,
            index=index,
            component_name=component_name,
            algorithm=algorithm,
            key_size=key_size,
            primitive_type=primitive_type,
            file_path=file_path,
            line_number=line_number,
            tier=tier,
            has_shredding=has_shredding,
            evidence_level=evidence_level,
            evidence_source=evidence_source,
            matched_code=matched_code,
            language=language,
            cwe=cwe,
            description=description,
            risk_level=risk_level,
            extra_properties=extra_properties,
        )
