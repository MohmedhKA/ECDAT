"""
ECDAT Ruby Cryptographic Contract Engine:
Statically discovers Ruby cryptographic primitives across the standard OpenSSL module,
ActiveSupport cryptographic helpers, and modern gems (BCrypt, JWT)
using pure lexer token stream analysis without regular expressions.
"""

from pathlib import Path
from typing import List, Dict, Optional, Set, Any, Tuple
from pygments.lexers import RubyLexer
from pygments.token import Token

from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.base import BaseContractEngine


class RubyContractEngine(BaseContractEngine):
    """Token-driven Contract Engine for Ruby cryptographic operations."""

    def __init__(self):
        self.db = get_signature_db()
        self.lexer = RubyLexer()

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

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem
        tokens = self._extract_tokens(content)
        n = len(tokens)

        assets: List[CryptoAsset] = []
        seen_keys: Set[str] = set()

        def get_line(offset: int) -> int:
            return content.count("\n", 0, offset) + 1

        def extract_next_string(start_idx: int, max_ahead: int = 10) -> Optional[str]:
            for i in range(start_idx, min(n, start_idx + max_ahead)):
                t, v, _ = tokens[i]
                if t in Token.Literal.String:
                    clean = v.strip('"\'')
                    if clean:
                        return clean
                if v in (")", ";"):
                    break
            return None

        idx = 0
        while idx < n:
            ttype, val, offset = tokens[idx]

            # 1. OpenSSL calls: OpenSSL::Cipher, OpenSSL::Digest, OpenSSL::HMAC, OpenSSL::PKey, OpenSSL::KDF
            if val == "OpenSSL" and idx + 2 < n and tokens[idx + 1][1] == "::":
                sub_module = tokens[idx + 2][1]

                # OpenSSL::Cipher.new('AES-256-GCM')
                if sub_module == "Cipher":
                    line_no = get_line(offset)
                    raw_alg = extract_next_string(idx + 3) or "AES-256-CBC"
                    self._record_asset(assets, seen_keys, rel_path, stem, raw_alg, PrimitiveType.ENCRYPTION,
                                       line_no, offset, content, "OpenSSL::Cipher", "ruby")
                    idx += 4
                    continue

                # OpenSSL::Digest.new('SHA256') or OpenSSL::Digest::SHA256.new
                if sub_module == "Digest":
                    line_no = get_line(offset)
                    raw_alg = "SHA-256"
                    if idx + 4 < n and tokens[idx + 3][1] == "::":
                        raw_alg = tokens[idx + 4][1]
                    else:
                        s = extract_next_string(idx + 3)
                        if s:
                            raw_alg = s
                    self._record_asset(assets, seen_keys, rel_path, stem, raw_alg, PrimitiveType.HASH,
                                       line_no, offset, content, "OpenSSL::Digest", "ruby")
                    idx += 4
                    continue

                # OpenSSL::HMAC.digest or hexdigest('sha256', ...)
                if sub_module == "HMAC":
                    line_no = get_line(offset)
                    raw_alg = extract_next_string(idx + 3) or "SHA-256"
                    self._record_asset(assets, seen_keys, rel_path, stem, f"HMAC-{raw_alg}", PrimitiveType.HASH,
                                       line_no, offset, content, "OpenSSL::HMAC", "ruby")
                    idx += 4
                    continue

                # OpenSSL::KDF.pbkdf2_hmac / hkdf / scrypt
                if sub_module == "KDF" and idx + 4 < n and tokens[idx + 3][1] == ".":
                    kdf_func = tokens[idx + 4][1]
                    line_no = get_line(offset)
                    self._record_asset(assets, seen_keys, rel_path, stem, kdf_func.upper(), PrimitiveType.KEY_EXCHANGE,
                                       line_no, offset, content, "OpenSSL::KDF", "ruby")
                    idx += 5
                    continue

                # OpenSSL::PKey::RSA / EC / DSA
                if sub_module == "PKey" and idx + 4 < n and tokens[idx + 3][1] == "::":
                    pkey_type = tokens[idx + 4][1].upper()
                    line_no = get_line(offset)
                    bits = 2048 if pkey_type in ("RSA", "DSA") else 256
                    for search_i in range(idx + 5, min(n, idx + 15)):
                        if tokens[search_i][1].isdigit():
                            bits = int(tokens[search_i][1])
                            break
                        if tokens[search_i][1] in (")", ";"):
                            break
                    alg_name = f"{pkey_type}-{bits}"
                    self._record_asset(assets, seen_keys, rel_path, stem, alg_name, PrimitiveType.SIGNATURE,
                                       line_no, offset, content, f"OpenSSL::PKey::{pkey_type}", "ruby")
                    idx += 5
                    continue

            # 2. ActiveSupport::MessageEncryptor
            if val == "ActiveSupport" and idx + 2 < n and tokens[idx + 1][1] == "::" and tokens[idx + 2][1] == "MessageEncryptor":
                line_no = get_line(offset)
                self._record_asset(assets, seen_keys, rel_path, stem, "AES-256-GCM", PrimitiveType.ENCRYPTION,
                                   line_no, offset, content, "ActiveSupport::MessageEncryptor", "ruby")
                idx += 3
                continue

            # 3. BCrypt::Password
            if val == "BCrypt" and idx + 2 < n and tokens[idx + 1][1] == "::" and tokens[idx + 2][1] == "Password":
                line_no = get_line(offset)
                self._record_asset(assets, seen_keys, rel_path, stem, "Bcrypt", PrimitiveType.KEY_EXCHANGE,
                                   line_no, offset, content, "BCrypt::Password", "ruby")
                idx += 3
                continue

            # 4. JWT.encode / JWT.decode
            if val == "JWT" and idx + 2 < n and tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"encode", "decode"}:
                line_no = get_line(offset)
                jwt_alg = extract_next_string(idx + 3, max_ahead=15) or "HS256"
                self._record_asset(assets, seen_keys, rel_path, stem, f"JWT-{jwt_alg.upper()}", PrimitiveType.SIGNATURE,
                                   line_no, offset, content, "JWT", "ruby")
                idx += 3
                continue

            idx += 1

        return assets

    def _record_asset(self, assets: List[CryptoAsset], seen_keys: Set[str], rel_path: str, stem: str,
                      raw_alg: str, prim_type: PrimitiveType, line_no: int, offset: int, content: str,
                      contract_name: str, language: str):
        clean_alg = raw_alg.replace("_", "-").upper()
        sig = self.db.lookup_algorithm(clean_alg)
        key_size = 256
        cwe = None
        risk = "LOW"
        desc = f"Ruby {contract_name} cryptographic operation"

        if sig:
            alg = sig["normalized_alg"]
            prim_type = PrimitiveType(sig["primitive_type"])
            key_size = sig.get("key_size") or key_size
            cwe = sig.get("cwe")
            risk = sig.get("default_risk", risk)
            desc = sig.get("description", desc)
        else:
            alg = clean_alg
            if any(b in alg for b in ("DES", "RC4", "MD5", "SHA1")):
                cwe = "CWE-327" if "SHA" not in alg and "MD5" not in alg else "CWE-328"
                risk = "CRITICAL" if "MD5" in alg or "DES" in alg or "RC4" in alg else "HIGH"

        dedup_key = f"{rel_path}:{alg}:{line_no}"
        if dedup_key in seen_keys:
            return
        seen_keys.add(dedup_key)

        is_shred, tier = self.check_crypto_shredding_context(content, line_no)
        matched_code = content[offset:min(len(content), offset + 80)].strip()

        assets.append(self.build_crypto_asset(
            asset_prefix="SRC-RB",
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
            evidence_source=f"ruby_contract:{contract_name}",
            matched_code=matched_code,
            language=language,
            cwe=cwe,
            description=desc,
            risk_level=risk
        ))
