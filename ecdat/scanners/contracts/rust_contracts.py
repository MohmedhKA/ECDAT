"""
ECDAT Rust Cryptographic Contract Engine:
Statically discovers Rust cryptographic primitives and structures
(LWE homomorphic encryption, Ristretto255 Pedersen commitments, U2048 arithmetic)
using pure lexer token stream analysis without regular expressions.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from pygments.lexers import RustLexer
from pygments.token import Token

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
)
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.base import BaseContractEngine
from ecdat.scanners.factory import CryptoAssetFactory


class RustContractEngine(BaseContractEngine):
    """Token-driven Contract Engine for Rust."""

    def __init__(self):
        self.db = get_signature_db()
        self.lexer = RustLexer()

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem

        assets: List[CryptoAsset] = []
        seen_keys: Set[str] = set()

        raw_tokens = list(self.lexer.get_tokens(content))
        tokens: List[Tuple[Any, str, int]] = []
        curr_offset = 0
        for ttype, val in raw_tokens:
            start_off = curr_offset
            curr_offset += len(val)
            if not val.isspace():
                tokens.append((ttype, val, start_off))

        n_tokens = len(tokens)

        def get_line(offset: int) -> int:
            return content.count("\n", 0, offset) + 1

        def get_snippet(offset: int, length: int = 80) -> str:
            return content[offset:min(len(content), offset + length)].strip()

        idx = 0
        while idx < n_tokens:
            ttype, val, offset = tokens[idx]

            # 1. Modular arithmetic / Ephemeral verifier: struct U2048
            if val == "struct" and idx + 1 < n_tokens and tokens[idx + 1][1] == "U2048":
                line_no = get_line(offset)
                dedup_key = f"{rel_path}:RSA-2048:{line_no}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    assets.append(CryptoAssetFactory.create_asset(
                        asset_prefix="SRC-RS",
                        index=len(assets) + 1,
                        component_name=f"{stem}:u2048",
                        algorithm="RSA-2048",
                        key_size=2048,
                        primitive_type=PrimitiveType.SIGNATURE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=XTier.EPHEMERAL,
                        has_shredding=True,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="rust_contract:struct_U2048",
                        matched_code=get_snippet(offset),
                        language="rust",
                        description="Rust In-Memory 2048-bit Modular Arithmetic / Ephemeral Verifier",
                    ))
                idx += 2
                continue

            # 2. Ristretto255 group commitments (curve25519_dalek::ristretto)
            if val == "curve25519_dalek" and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "::" and tokens[idx + 2][1] == "ristretto":
                    line_no = get_line(offset)
                    dedup_key = f"{rel_path}:Ristretto255:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-RS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:ristretto255",
                            algorithm="Ristretto255",
                            key_size=256,
                            primitive_type=PrimitiveType.ENCRYPTION,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.EPHEMERAL,
                            has_shredding=True,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="rust_contract:curve25519_dalek",
                            matched_code=get_snippet(offset),
                            language="rust",
                            description="Pedersen Commitment & Sigma Proof (Information-Theoretic Hiding)",
                        ))
                    idx += 3
                    continue

            # 3. Lattice-based Learning With Errors: LWE_Q or LwePublicKey / LweCiphertext
            if (val == "const" and idx + 1 < n_tokens and tokens[idx + 1][1] == "LWE_Q") or \
               (val == "struct" and idx + 1 < n_tokens and tokens[idx + 1][1] in {"LwePublicKey", "LweSecretKey", "LweCiphertext"}):
                line_no = get_line(offset)
                dedup_key = f"{rel_path}:LWE-2048:{line_no}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    assets.append(CryptoAssetFactory.create_asset(
                        asset_prefix="SRC-RS",
                        index=len(assets) + 1,
                        component_name=f"{stem}:lwe_2048",
                        algorithm="LWE-2048",
                        key_size=2048,
                        primitive_type=PrimitiveType.ENCRYPTION,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=XTier.SHORT_TERM,
                        has_shredding=True,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="rust_contract:lwe_lattice",
                        matched_code=get_snippet(offset),
                        language="rust",
                        description="Lattice-based Learning With Errors (LWE) Homomorphic Encryption",
                    ))
                idx += 2
                continue

            # 4. Standard Hash: sha2::Sha256 / Sha512
            if val == "sha2" and idx + 2 < n_tokens and tokens[idx + 1][1] == "::":
                sub = tokens[idx + 2][1]
                if sub in {"Sha256", "Sha512"}:
                    line_no = get_line(offset)
                    alg = "SHA-256" if sub == "Sha256" else "SHA-512"
                    dedup_key = f"{rel_path}:{alg}:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-RS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:sha2",
                            algorithm=alg,
                            key_size=256 if sub == "Sha256" else 512,
                            primitive_type=PrimitiveType.HASH,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.OPERATIONAL,
                            has_shredding=False,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="rust_contract:sha2",
                            matched_code=get_snippet(offset),
                            language="rust",
                            description=f"Rust sha2::{sub} Cryptographic Hash",
                        ))
                    idx += 3
                    continue

            idx += 1

        return assets
