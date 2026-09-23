"""
ECDAT Python Cryptographic Contract Engine:
Statically discovers Python cryptographic primitives across standard library (hashlib, hmac, secrets)
and standard enterprise libraries (cryptography.hazmat, pycryptodome) using Python's native AST parser.
"""

import ast
from pathlib import Path
from typing import List, Dict, Optional, Set, Any

from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.base import BaseContractEngine

class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, content: str, file_path: str, stem: str, db):
        self.content = content
        self.file_path = file_path
        self.stem = stem
        self.db = db
        self.assets: List[CryptoAsset] = []
        self.seen_keys: Set[str] = set()
        self._current_assign_targets: List[str] = []

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_call_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return ""

    def visit_Assign(self, node: ast.Assign):
        self._current_assign_targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        self.generic_visit(node)
        self._current_assign_targets = []

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node.func)
        line_no = getattr(node, "lineno", 1)

        alg = None
        prim_type = PrimitiveType.ENCRYPTION
        key_size = 256
        cwe = None
        risk = "LOW"
        desc = ""

        # 1. hashlib calls (e.g. hashlib.sha256(), hashlib.md5(), hashlib.new('sha256'))
        if call_name.startswith("hashlib."):
            sub = call_name.split(".", 1)[1]
            if sub == "new" and node.args and isinstance(node.args[0], ast.Constant):
                alg_str = str(node.args[0].value).upper()
                alg = alg_str
            elif sub in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}:
                alg = sub.upper()

            if alg:
                prim_type = PrimitiveType.HASH
                is_broken = alg in ("MD5", "SHA1", "SHA-1")
                risk = "CRITICAL" if alg == "MD5" else ("HIGH" if "SHA1" in alg else "LOW")
                cwe = "CWE-328" if is_broken else None
                desc = f"Python hashlib.{alg.lower()} invocation"

        # 2. hmac calls
        elif call_name.startswith("hmac.") and "new" in call_name:
            alg = "HMAC-SHA256"
            prim_type = PrimitiveType.HASH
            desc = "Python hmac.new keyed message authentication"

        # 3. cryptography.hazmat calls (e.g. algorithms.AES, algorithms.TripleDES, hashes.SHA256)
        elif "algorithms." in call_name or "hashes." in call_name or "aead." in call_name:
            sub_alg = call_name.split(".")[-1]
            alg = sub_alg.upper()
            if "hashes." in call_name:
                prim_type = PrimitiveType.HASH
                is_broken = alg in ("MD5", "SHA1")
                risk = "CRITICAL" if alg == "MD5" else ("HIGH" if alg == "SHA1" else "LOW")
                cwe = "CWE-328" if is_broken else None
                desc = f"Python hazmat hash {alg}"
            else:
                prim_type = PrimitiveType.ENCRYPTION
                if "TRIPLEDES" in alg or "3DES" in alg:
                    alg = "3DES"
                    risk = "HIGH"
                    cwe = "CWE-327"
                elif "AES" in alg:
                    alg = "AES-256-GCM" if "GCM" in call_name else "AES"
                desc = f"Python hazmat cipher {alg}"

        # 4. Asymmetric Key Generation (rsa.generate_private_key, ec.generate_private_key)
        elif "generate_private_key" in call_name:
            prim_type = PrimitiveType.SIGNATURE
            if "rsa" in call_name.lower():
                alg = "RSA-2048"
                key_size = 2048
            elif "ec" in call_name.lower():
                alg = "ECDSA-P256"
                key_size = 256
            elif "ed25519" in call_name.lower():
                alg = "Ed25519"
                key_size = 256
            else:
                alg = "ASYMMETRIC-KEYGEN"
            risk = "HIGH"
            cwe = "CWE-326"
            desc = f"Python asymmetric key generation {alg}"

        # 5. Generic cipher / crypto engine method calls (e.g. cipher.encrypt, cipher.sign, signer.sign)
        elif any(call_name.endswith(f".{m}") for m in ("encrypt", "decrypt", "sign", "verify", "seal", "open")):
            method = call_name.rsplit(".", 1)[-1]
            if method in {"encrypt", "decrypt", "seal", "open"}:
                prim_type = PrimitiveType.ENCRYPTION
                alg = "AES-256-GCM"
                desc = f"Python {call_name} cipher encryption invocation"
            elif method in {"sign", "verify"}:
                prim_type = PrimitiveType.SIGNATURE
                alg = "ECDSA-P256"
                desc = f"Python {call_name} digital signature invocation"

        # 6. PyCryptodome / Fernet constructors
        elif any(call_name.startswith(pfx) for pfx in ("AES.", "DES.", "TripleDES.", "Blowfish.", "PKCS1_OAEP.", "PKCS1_v1_5.", "Fernet")):
            sub_alg = call_name.split(".")[0].upper()
            if sub_alg in {"DES", "TRIPLEDES", "BLOWFISH"}:
                alg = "3DES" if sub_alg == "TRIPLEDES" else sub_alg
                prim_type = PrimitiveType.ENCRYPTION
                risk = "HIGH"
                cwe = "CWE-327"
            elif "PKCS1" in sub_alg:
                alg = "RSA-2048"
                prim_type = PrimitiveType.ENCRYPTION if "OAEP" in sub_alg else PrimitiveType.SIGNATURE
            else:
                alg = "AES-256-GCM"
                prim_type = PrimitiveType.ENCRYPTION
            desc = f"Python {call_name} constructor invocation"

        if alg:
            # Query SQLite signature database
            sig = self.db.lookup_algorithm(alg)
            if sig:
                alg = sig["normalized_alg"]
                prim_type = PrimitiveType(sig["primitive_type"])
                key_size = sig.get("key_size") or key_size
                cwe = sig.get("cwe") or cwe
                risk = sig.get("default_risk") or risk

            dedup_key = f"{self.file_path}:{alg}:{line_no}"
            if dedup_key not in self.seen_keys:
                self.seen_keys.add(dedup_key)
                target_var = self._current_assign_targets[0] if self._current_assign_targets else ""
                matched_code = f"{target_var} = {call_name}" if target_var else call_name
                comp_tag = target_var if target_var else alg.lower().replace('-', '_')
                is_shred, tier = BaseContractEngine.check_crypto_shredding_context(self.content, line_no)

                self.assets.append(BaseContractEngine.build_crypto_asset(
                    asset_prefix="SRC-PY",
                    index=len(self.assets) + 1,
                    component_name=f"{self.stem}:{comp_tag}",
                    algorithm=alg,
                    key_size=key_size,
                    primitive_type=prim_type,
                    file_path=self.file_path,
                    line_number=line_no,
                    tier=tier,
                    has_shredding=is_shred,
                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                    evidence_source=f"python_contract:{call_name}",
                    matched_code=matched_code,
                    language="python",
                    cwe=cwe,
                    description=desc,
                    risk_level=risk
                ))

        self.generic_visit(node)

class PythonContractEngine(BaseContractEngine):
    """AST Contract Engine for Python cryptographic operations."""

    def __init__(self):
        self.db = get_signature_db()

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem
        visitor = PythonASTVisitor(content, rel_path, stem, self.db)
        visitor.visit(tree)
        return visitor.assets
