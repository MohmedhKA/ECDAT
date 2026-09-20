"""
ECDAT Go Cryptographic Contract Engine:
Statically discovers Go cryptographic primitives across standard library (crypto/*)
and extended ecosystem (golang.org/x/crypto/*) by resolving interface contracts
(cipher.Block, cipher.AEAD, cipher.Stream, hash.Hash, crypto.Signer, TLS, KDF)
using pure lexer token stream analysis without regular expressions.
"""

from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any
from pygments.lexers import GoLexer
from pygments.token import Token

from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.base import BaseContractEngine


class GoContractEngine(BaseContractEngine):
    """AST/Syntax Contract Engine for Go cryptographic operations using token analysis."""

    def __init__(self):
        self.db = get_signature_db()
        self.lexer = GoLexer()

    def _extract_tokens(self, content: str) -> List[Tuple[Any, str, int]]:
        raw_tokens = list(self.lexer.get_tokens(content))
        tokens: List[Tuple[Any, str, int]] = []
        curr_offset = 0
        for ttype, val in raw_tokens:
            start_off = curr_offset
            curr_offset += len(val)
            if not val.isspace():
                tokens.append((ttype, val, start_off))
        return tokens

    def _extract_imports(self, tokens: List[Tuple[Any, str, int]]) -> Dict[str, str]:
        """
        Extracts single and grouped imports from Go tokens.
        Maps local package alias identifier to full package path.
        """
        imports: Dict[str, str] = {}
        idx = 0
        n = len(tokens)

        while idx < n:
            ttype, val, _ = tokens[idx]
            if val == "import" and idx + 1 < n:
                next_val = tokens[idx + 1][1]
                # Grouped imports: import ( ... )
                if next_val == "(":
                    idx += 2
                    while idx < n and tokens[idx][1] != ")":
                        # Could be alias + path or just path
                        if tokens[idx][1].startswith(('"', "'")):
                            full_path = tokens[idx][1].strip('"\'')
                            default_name = full_path.split("/")[-1]
                            imports[default_name] = full_path
                            idx += 1
                        elif idx + 1 < n and tokens[idx + 1][1].startswith(('"', "'")):
                            alias = tokens[idx][1]
                            full_path = tokens[idx + 1][1].strip('"\'')
                            imports[alias] = full_path
                            idx += 2
                        else:
                            idx += 1
                    idx += 1
                    continue
                # Single import with alias: import alias "path"
                elif idx + 2 < n and tokens[idx + 2][1].startswith(('"', "'")):
                    alias = tokens[idx + 1][1]
                    full_path = tokens[idx + 2][1].strip('"\'')
                    imports[alias] = full_path
                    idx += 3
                    continue
                # Single import without alias: import "path"
                elif next_val.startswith(('"', "'")):
                    full_path = next_val.strip('"\'')
                    default_name = full_path.split("/")[-1]
                    imports[default_name] = full_path
                    idx += 2
                    continue
            idx += 1

        return imports

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem
        tokens = self._extract_tokens(content)
        imports = self._extract_imports(tokens)
        assets: List[CryptoAsset] = []
        seen_keys: Set[str] = set()

        n = len(tokens)

        def get_line(offset: int) -> int:
            return content.count("\n", 0, offset) + 1

        def get_snippet(offset: int, length: int = 80) -> str:
            return content[offset:min(len(content), offset + length)].strip()

        # Find all qualified calls: <pkg>.<Function>( or <pkg>.<Function>{
        for idx in range(n - 3):
            pkg_alias = tokens[idx][1]
            dot = tokens[idx + 1][1]
            func_name = tokens[idx + 2][1]
            delimiter = tokens[idx + 3][1]
            offset = tokens[idx][2]

            if dot != "." or delimiter not in {"(", "{"}:
                continue

            # Go functions start with uppercase by convention
            if not func_name or not func_name[0].isupper():
                continue

            full_pkg = imports.get(pkg_alias)

            # Only inspect calls where package is known crypto import or crypto stdlib name
            if not full_pkg and pkg_alias not in {
                "aes", "des", "cipher", "rsa", "ecdsa", "ed25519", "md5", "sha1",
                "sha256", "sha512", "hmac", "rand", "tls", "x509", "rc4", "argon2",
                "bcrypt", "scrypt", "pbkdf2", "hkdf", "chacha20poly1305", "ssh"
            }:
                continue

            pkg_namespace = full_pkg if full_pkg else f"crypto/{pkg_alias}"

            # 1. Database Query: Exact Match by (ecosystem='go', namespace, symbol)
            sig = self.db.lookup_namespace_symbol("go", pkg_namespace, func_name)

            # 2. Contract-Level Semantic Resolution
            if not sig:
                sig = self._resolve_contract_fallback(pkg_namespace, pkg_alias, func_name)

            if not sig:
                continue

            line_no = get_line(offset)
            matched_code = get_snippet(offset)
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)

            alg = sig["normalized_alg"]
            prim_type = PrimitiveType(sig["primitive_type"])
            key_size = sig.get("key_size")

            dedup_key = f"{rel_path}:{alg}:{line_no}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            assets.append(self.build_crypto_asset(
                asset_prefix="SRC-GO",
                index=len(assets) + 1,
                component_name=f"{stem}:{alg.lower().replace('-', '_')}",
                algorithm=alg,
                key_size=key_size,
                primitive_type=prim_type,
                file_path=rel_path,
                line_number=line_no,
                tier=tier,
                has_shredding=is_shred,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_source=f"go_contract:{sig.get('contract', 'unknown')}",
                matched_code=matched_code,
                language="go",
                cwe=sig.get("cwe"),
                description=sig.get("description", f"Go {pkg_namespace}.{func_name} contract invocation"),
                risk_level=sig.get("default_risk")
            ))

        return assets

    def _resolve_contract_fallback(self, pkg_namespace: str, pkg_alias: str, func_name: str) -> Optional[Dict[str, Any]]:
        """
        Synthesizes a signature from language-level contract invariants when an explicit
        function entry is not pre-registered in the database.
        """
        # Block Cipher Contract (cipher.Block)
        if pkg_alias in {"aes", "des", "rc4"} or "crypto/des" in pkg_namespace or "crypto/aes" in pkg_namespace:
            if "cipher" in func_name.lower():
                alg = "DES" if "des" in pkg_alias else ("AES-256-GCM" if "aes" in pkg_alias else "RC4")
                if "triple" in func_name.lower() or "3des" in func_name.lower():
                    alg = "3DES"
                return {
                    "contract": "cipher.Block",
                    "normalized_alg": alg,
                    "primitive_type": "ENCRYPTION",
                    "key_size": 64 if alg == "DES" else (192 if alg == "3DES" else 256),
                    "default_risk": "CRITICAL" if alg in ("DES", "RC4") else ("HIGH" if alg == "3DES" else "LOW"),
                    "cwe": "CWE-327" if alg in ("DES", "3DES", "RC4") else None,
                    "description": f"Go {pkg_namespace}.{func_name} implements cipher.Block"
                }

        # AEAD Contract (cipher.AEAD)
        if pkg_alias == "cipher" and func_name in {"NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize"}:
            return {
                "contract": "cipher.AEAD",
                "normalized_alg": "AES-GCM",
                "primitive_type": "ENCRYPTION",
                "key_size": 256,
                "default_risk": "LOW",
                "cwe": None,
                "description": "Go crypto/cipher implements cipher.AEAD"
            }

        # Stream / BlockMode Contracts
        if pkg_alias == "cipher" and any(mode in func_name for mode in {"CBC", "CTR", "CFB", "OFB"}):
            mode_name = next(m for m in ("CBC", "CTR", "CFB", "OFB") if m in func_name)
            return {
                "contract": "cipher.BlockMode" if "CBC" in mode_name else "cipher.Stream",
                "normalized_alg": f"AES-{mode_name}",
                "primitive_type": "ENCRYPTION",
                "key_size": 256,
                "default_risk": "MEDIUM" if mode_name == "CBC" else "LOW",
                "cwe": "CWE-327" if mode_name == "CBC" else None,
                "description": f"Go crypto/cipher block mode {mode_name}"
            }

        # Hash Contract (hash.Hash)
        if pkg_alias in {"md5", "sha1", "sha256", "sha512", "hmac"} or pkg_namespace.startswith("crypto/sha") or pkg_namespace == "crypto/md5":
            if func_name in {"New", "Sum", "Sum256", "Sum512", "Equal"}:
                alg_map = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512", "hmac": "HMAC-SHA256"}
                alg = alg_map.get(pkg_alias, "SHA-256")
                is_broken = alg in ("MD5", "SHA-1")
                return {
                    "contract": "hash.Hash",
                    "normalized_alg": alg,
                    "primitive_type": "HASH",
                    "key_size": 128 if alg == "MD5" else (160 if alg == "SHA-1" else 256),
                    "default_risk": "CRITICAL" if alg == "MD5" else ("HIGH" if alg == "SHA-1" else "LOW"),
                    "cwe": "CWE-328" if is_broken else None,
                    "description": f"Go {pkg_namespace}.{func_name} implements hash.Hash"
                }

        # Signer / Asymmetric Contracts
        if pkg_alias in {"rsa", "ecdsa", "ed25519"}:
            if any(term in func_name for term in {"GenerateKey", "Sign", "Verify", "Encrypt", "Decrypt"}):
                alg_map = {"rsa": "RSA-2048", "ecdsa": "ECDSA-P256", "ed25519": "Ed25519"}
                alg = alg_map.get(pkg_alias, "RSA-2048")
                return {
                    "contract": "crypto.Signer",
                    "normalized_alg": alg,
                    "primitive_type": "SIGNATURE",
                    "key_size": 2048 if alg == "RSA-2048" else 256,
                    "default_risk": "HIGH",
                    "cwe": "CWE-326",
                    "description": f"Go crypto/{pkg_alias}.{func_name} asymmetric operation"
                }

        # Transport / PKI
        if pkg_alias == "tls" and func_name in {"Config", "Listen", "Dial", "DialWithDialer", "LoadX509KeyPair"}:
            return {
                "contract": "TLS",
                "normalized_alg": "TLS-CONFIG",
                "primitive_type": "KEY_EXCHANGE",
                "key_size": None,
                "default_risk": "MEDIUM",
                "cwe": None,
                "description": "Go crypto/tls handshake configuration"
            }

        if pkg_alias == "x509" and any(term in func_name for term in {"Parse", "Create", "NewCertPool"}):
            return {
                "contract": "PKI",
                "normalized_alg": "X509-CERT",
                "primitive_type": "KEY_EXCHANGE",
                "key_size": None,
                "default_risk": "MEDIUM",
                "cwe": None,
                "description": "Go crypto/x509 certificate management"
            }

        return None
