"""
ECDAT JavaScript & TypeScript Cryptographic Contract Engine:
Statically discovers cryptographic operations across Node.js, Web Crypto,
@noble/post-quantum, and node-forge using pure lexer token stream analysis
without relying on regular expressions.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from pygments.lexers import JavascriptLexer, TypeScriptLexer
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
from ecdat.scanners.contracts.evaluator import CallSiteEvaluator, StaticResolution, DynamicIngress


class JavaScriptContractEngine(BaseContractEngine):
    """Token-driven Contract Engine for JavaScript and TypeScript."""

    def __init__(self):
        self.db = get_signature_db()
        self.js_lexer = JavascriptLexer()
        self.ts_lexer = TypeScriptLexer()

    def _get_lexer(self, suffix: str):
        if suffix in {".ts", ".tsx", ".mts", ".cts"}:
            return self.ts_lexer
        return self.js_lexer

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem
        lexer = self._get_lexer(file_path.suffix.lower())

        assets: List[CryptoAsset] = []
        seen_keys: Set[str] = set()

        # Tokenize content
        raw_tokens = list(lexer.get_tokens(content))
        
        # Build token list with character offsets for precise line numbering
        tokens: List[Tuple[Any, str, int]] = []
        curr_offset = 0
        for ttype, val in raw_tokens:
            start_off = curr_offset
            curr_offset += len(val)
            if not val.isspace():
                tokens.append((ttype, val, start_off))

        n_tokens = len(tokens)

        # Helper to compute line number from offset
        def get_line(offset: int) -> int:
            return content.count("\n", 0, offset) + 1

        # Helper to extract code snippet
        def get_snippet(offset: int, length: int = 80) -> str:
            return content[offset:min(len(content), offset + length)].strip()

        idx = 0
        while idx < n_tokens:
            ttype, val, offset = tokens[idx]

            # 1. Post-Quantum Signatures & KEM (@noble/post-quantum)
            # Pattern: ml_dsa65.keygen(), ml_dsa65.sign(), ml_dsa65.verify()
            if val in {"ml_dsa44", "ml_dsa65", "ml_dsa87"}:
                alg_name = "ML-DSA-65" if val == "ml_dsa65" else ("ML-DSA-87" if val == "ml_dsa87" else "ML-DSA-44")
                if idx + 2 < n_tokens and tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"keygen", "sign", "verify"}:
                    op_name = tokens[idx + 2][1]
                    line_no = get_line(offset)
                    dedup_key = f"{rel_path}:{alg_name}:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-JS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:{val}",
                            algorithm=alg_name,
                            key_size=1952 if "65" in alg_name else (2592 if "87" in alg_name else 1312),
                            primitive_type=PrimitiveType.SIGNATURE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.OPERATIONAL,
                            has_shredding=False,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="js_contract:@noble/post-quantum",
                            matched_code=get_snippet(offset),
                            language="javascript",
                            description=f"Post-Quantum {alg_name} (FIPS 204) {op_name} invocation",
                        ))
                    idx += 3
                    continue

            # Pattern: ml_kem512.keygen(), ml_kem768.keygen(), ml_kem1024.keygen()
            if val in {"ml_kem512", "ml_kem768", "ml_kem1024"}:
                alg_name = "ML-KEM-768" if val == "ml_kem768" else ("ML-KEM-1024" if val == "ml_kem1024" else "ML-KEM-512")
                if idx + 2 < n_tokens and tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"keygen", "encapsulate", "decapsulate"}:
                    op_name = tokens[idx + 2][1]
                    line_no = get_line(offset)
                    dedup_key = f"{rel_path}:{alg_name}:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-JS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:{val}",
                            algorithm=alg_name,
                            key_size=1184 if "768" in alg_name else (1568 if "1024" in alg_name else 800),
                            primitive_type=PrimitiveType.KEY_EXCHANGE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.EPHEMERAL,
                            has_shredding=True,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="js_contract:@noble/post-quantum",
                            matched_code=get_snippet(offset),
                            language="javascript",
                            description=f"Post-Quantum {alg_name} (FIPS 203) {op_name} invocation",
                        ))
                    idx += 3
                    continue

            # 2. RSA Blind Signature & Key Generation (node-forge & node:crypto)
            # Pattern: forge.pki.rsa.generateKeyPair({ bits: 2048, ... })
            if val == "forge" and idx + 6 < n_tokens:
                if (tokens[idx + 1][1] == "." and tokens[idx + 2][1] == "pki" and
                    tokens[idx + 3][1] == "." and tokens[idx + 4][1] == "rsa" and
                    tokens[idx + 5][1] == "." and tokens[idx + 6][1] == "generateKeyPair"):
                    
                    line_no = get_line(offset)
                    bits = 2048
                    # Inspect arguments window up to 20 tokens ahead
                    for search_i in range(idx + 7, min(n_tokens, idx + 25)):
                        if tokens[search_i][1] == "bits" and search_i + 2 < n_tokens and tokens[search_i + 1][1] == ":":
                            try:
                                bits = int(tokens[search_i + 2][1])
                            except ValueError:
                                bits = 2048
                            break
                        if tokens[search_i][1] == ")":
                            break

                    is_shred, tier = self.check_crypto_shredding_context(content, line_no)
                    is_blind = "blind" in rel_path.lower() or "blind" in content.lower()
                    if is_blind:
                        tier = XTier.EPHEMERAL
                        is_shred = True
                    prim = PrimitiveType.SIGNATURE if is_blind else PrimitiveType.KEY_EXCHANGE
                    alg = f"RSA-{bits}"

                    dedup_key = f"{rel_path}:{alg}:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-JS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:rsa_keygen",
                            algorithm=alg,
                            key_size=bits,
                            primitive_type=prim,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=tier,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="js_contract:node-forge",
                            matched_code=get_snippet(offset),
                            language="javascript",
                            description="Forge RSA Keypair Generation",
                        ))
                    idx += 7
                    continue

            # Pattern: privateDecrypt / publicDecrypt with padding: constants.RSA_NO_PADDING
            if val in {"privateDecrypt", "publicDecrypt"}:
                line_no = get_line(offset)
                is_rsa_no_padding = False
                for search_i in range(idx + 1, min(n_tokens, idx + 30)):
                    if tokens[search_i][1] == "RSA_NO_PADDING":
                        is_rsa_no_padding = True
                        break
                    if tokens[search_i][1] == ";":
                        break
                
                if is_rsa_no_padding:
                    dedup_key = f"{rel_path}:RSA-2048-BLIND:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-JS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:rsa_blind_op",
                            algorithm="RSA-2048",
                            key_size=2048,
                            primitive_type=PrimitiveType.SIGNATURE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.EPHEMERAL,
                            has_shredding=True,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="js_contract:crypto.privateDecrypt",
                            matched_code=get_snippet(offset),
                            language="javascript",
                            description="RSA Blind Signature Operation (RSA_NO_PADDING)",
                        ))
                idx += 1
                continue

            # Pattern: rsaBlindService.verifyAsync() or rsaBlindService.signBlinded()
            if val == "rsaBlindService" and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"verifyAsync", "signBlinded"}:
                    line_no = get_line(offset)
                    dedup_key = f"{rel_path}:RSA-2048:{line_no}"
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        assets.append(CryptoAssetFactory.create_asset(
                            asset_prefix="SRC-JS",
                            index=len(assets) + 1,
                            component_name=f"{stem}:rsa_blind_service",
                            algorithm="RSA-2048",
                            key_size=2048,
                            primitive_type=PrimitiveType.SIGNATURE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.EPHEMERAL,
                            has_shredding=True,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="js_contract:rsaBlindService",
                            matched_code=get_snippet(offset),
                            language="javascript",
                            description="RSA Blind Signature Service Invocation",
                        ))
                    idx += 3
                    continue

            # 3. Node Native Crypto: crypto.generateKeyPair / crypto.generateKeyPairSync
            if val == "crypto" and idx + 4 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"generateKeyPair", "generateKeyPairSync"}:
                    line_no = get_line(offset)
                    # Check first argument string literal
                    type_arg = tokens[idx + 4][1].strip("'\"").lower()
                    is_shred, tier = self.check_crypto_shredding_context(content, line_no)
                    if type_arg == "rsa":
                        dedup_key = f"{rel_path}:RSA-2048:{line_no}"
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            assets.append(CryptoAssetFactory.create_asset(
                                asset_prefix="SRC-JS",
                                index=len(assets) + 1,
                                component_name=f"{stem}:rsa_keygen",
                                algorithm="RSA-2048",
                                key_size=2048,
                                primitive_type=PrimitiveType.SIGNATURE,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=tier,
                                has_shredding=is_shred,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="js_contract:crypto.generateKeyPair",
                                matched_code=get_snippet(offset),
                                language="javascript",
                                description="Node crypto RSA Keypair Generation",
                            ))
                    elif type_arg == "ec":
                        dedup_key = f"{rel_path}:ECDSA-P256:{line_no}"
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            assets.append(CryptoAssetFactory.create_asset(
                                asset_prefix="SRC-JS",
                                index=len(assets) + 1,
                                component_name=f"{stem}:ec_keygen",
                                algorithm="ECDSA-P256",
                                key_size=256,
                                primitive_type=PrimitiveType.SIGNATURE,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=XTier.OPERATIONAL,
                                has_shredding=False,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="js_contract:crypto.generateKeyPair",
                                matched_code=get_snippet(offset),
                                language="javascript",
                                description="Node crypto Elliptic Curve Keypair Generation",
                            ))
                    idx += 5
                    continue

                # Pattern: crypto.createCipheriv('aes-256-gcm', ...) or ('A~ES'.replace('~', ''))
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] == "createCipheriv" and idx + 4 < n_tokens:
                    line_no = get_line(offset)
                    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, idx + 4)

                    # Bifurcation: Static resolutions (.replace, constants) go to CBOM;
                    # Dynamic Ingress (process.env, config, DB) are excluded from CBOM (Father Marko only)
                    if isinstance(res, StaticResolution):
                        cipher_arg = res.value.upper()
                        bits = 256 if "256" in cipher_arg else 128
                        mode = "GCM" if "GCM" in cipher_arg else ("CBC" if "CBC" in cipher_arg else "GCM")
                        alg = f"AES-{bits}-{mode}"
                        dedup_key = f"{rel_path}:{alg}:{line_no}"
                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            assets.append(CryptoAssetFactory.create_asset(
                                asset_prefix="SRC-JS",
                                index=len(assets) + 1,
                                component_name=f"{stem}:aes_cipher",
                                algorithm=alg,
                                key_size=bits,
                                primitive_type=PrimitiveType.ENCRYPTION,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=XTier.OPERATIONAL,
                                has_shredding=False,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="js_contract:crypto.createCipheriv",
                                matched_code=get_snippet(offset),
                                language="javascript",
                                description=f"Node crypto {alg} Symmetric Cipher",
                            ))
                    idx = max(idx + 5, next_idx)
                    continue

            # 4. JSON Web Tokens: jwt.sign()
            if val == "jwt" and idx + 2 < n_tokens and tokens[idx + 1][1] == "." and tokens[idx + 2][1] == "sign":
                line_no = get_line(offset)
                dedup_key = f"{rel_path}:JWT-HMAC-SHA256:{line_no}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    assets.append(CryptoAssetFactory.create_asset(
                        asset_prefix="SRC-JS",
                        index=len(assets) + 1,
                        component_name=f"{stem}:jwt_sign",
                        algorithm="JWT-HMAC-SHA256",
                        key_size=256,
                        primitive_type=PrimitiveType.SIGNATURE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=XTier.SHORT_TERM,
                        has_shredding=True,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="js_contract:jwt.sign",
                        matched_code=get_snippet(offset),
                        language="javascript",
                        description="JSON Web Token Signing (Session Authentication)",
                    ))
                idx += 3
                continue

            idx += 1

        return assets
