"""
ECDAT Polyglot Source Code Cryptographic Scanner:
Statically discovers in-code cryptographic primitive invocations across
JavaScript/TypeScript (.js, .mjs, .cjs, .ts), Go (.go), and Rust (.rs).

Extracts precise algorithm, key length, primitive type, line number,
evidence snippet, and 4-tier data lifespan (X-inference) with crypto-shredding detection.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel, IntentClass
from ecdat.intent.classifier import classify_intent
from ecdat.scanners.filters import should_scan_file

EXCLUDED_DIRS = {
    "venv", ".venv", "env", "node_modules", "site-packages",
    "__pycache__", ".git", "dist", "build", "target", ".cache"
}

# Regex patterns for JavaScript/TypeScript cryptographic operations
JS_PATTERNS = [
    # 1. RSA Blind Signature & Key Generation (node-forge & crypto)
    {
        "pattern": re.compile(r"forge\.pki\.rsa\.generateKeyPair\s*\(\s*\{([^}]*)\}", re.MULTILINE),
        "handler": "_handle_forge_rsa_keygen"
    },
    {
        "pattern": re.compile(r"(?:privateDecrypt|publicDecrypt)\s*\(\s*\{[^}]*padding:\s*constants\.RSA_NO_PADDING[^}]*\}", re.MULTILINE),
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "RSA Blind Signature Operation (RSA_NO_PADDING)",
        "tier": XTier.EPHEMERAL,
        "shredding": True
    },
    {
        "pattern": re.compile(r"rsaBlindService\.verifyAsync\s*\(", re.MULTILINE),
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "RSA Blind Signature Asynchronous Verification Worker",
        "tier": XTier.EPHEMERAL,
        "shredding": True
    },
    {
        "pattern": re.compile(r"rsaBlindService\.signBlinded\s*\(", re.MULTILINE),
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Blind Signature Issuance on Blinded Message",
        "tier": XTier.EPHEMERAL,
        "shredding": True
    },
    # 2. Post-Quantum Signatures & KEM (@noble/post-quantum)
    {
        "pattern": re.compile(r"\bml_dsa(?:44|65|87)\.keygen\s*\(", re.MULTILINE),
        "algorithm": "ML-DSA-65",
        "key_size": 1952,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Post-Quantum ML-DSA-65 (FIPS 204) Key Generation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"\bml_dsa(?:44|65|87)\.(?:sign|verify)\s*\(", re.MULTILINE),
        "algorithm": "ML-DSA-65",
        "key_size": 1952,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Post-Quantum ML-DSA-65 (FIPS 204) Signature Operation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"\bml_kem(?:512|768|1024)\.keygen\s*\(", re.MULTILINE),
        "algorithm": "ML-KEM-768",
        "key_size": 1184,
        "primitive": PrimitiveType.KEY_EXCHANGE,
        "description": "Post-Quantum ML-KEM-768 (FIPS 203) Key Encapsulation",
        "tier": XTier.EPHEMERAL,
        "shredding": True
    },
    # 3. Node Native Crypto & Generic Keypairs
    {
        "pattern": re.compile(r"crypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]", re.MULTILINE),
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Node crypto RSA Keypair Generation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"crypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]", re.MULTILINE),
        "algorithm": "ECDSA-P256",
        "key_size": 256,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Node crypto Elliptic Curve Keypair Generation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"crypto\.createCipheriv\s*\(\s*['\"]aes-(128|256)-(gcm|cbc)['\"]", re.MULTILINE),
        "handler": "_handle_aes_cipher"
    },
    {
        "pattern": re.compile(r"jwt\.sign\s*\(", re.MULTILINE),
        "algorithm": "JWT-HMAC-SHA256",
        "key_size": 256,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "JSON Web Token Signing (Session Authentication)",
        "tier": XTier.SHORT_TERM,
        "shredding": True
    },
]

# Regex patterns for Go cryptographic operations
GO_PATTERNS = [
    {
        "pattern": re.compile(r"\brsa\.GenerateKey\s*\(", re.MULTILINE),
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Go crypto/rsa Key Generation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"\becdsa\.GenerateKey\s*\(", re.MULTILINE),
        "algorithm": "ECDSA-P256",
        "key_size": 256,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Go crypto/ecdsa Key Generation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"\bed25519\.GenerateKey\s*\(", re.MULTILINE),
        "algorithm": "Ed25519",
        "key_size": 256,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Go crypto/ed25519 Key Generation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"\bsha256\.(?:New|Sum256)\s*\(", re.MULTILINE),
        "algorithm": "SHA-256",
        "key_size": 256,
        "primitive": PrimitiveType.HASH,
        "description": "Go crypto/sha256 Cryptographic Digest",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
    {
        "pattern": re.compile(r"\baes\.NewCipher\s*\(", re.MULTILINE),
        "algorithm": "AES-256-GCM",
        "key_size": 256,
        "primitive": PrimitiveType.ENCRYPTION,
        "description": "Go crypto/aes Cipher Initialisation",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
]

# Regex patterns for Rust cryptographic operations
RUST_PATTERNS = [
    {
        "pattern": re.compile(r"pub\s+struct\s+U2048\b|struct\s+U2048\b", re.MULTILINE),
        "algorithm": "RSA-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.SIGNATURE,
        "description": "Rust In-Memory 2048-bit Modular Arithmetic / Ephemeral Verifier",
        "tier": XTier.EPHEMERAL,
        "shredding": True
    },
    {
        "pattern": re.compile(r"\bcurve25519_dalek::ristretto::(?:RistrettoPoint|CompressedRistretto)\b", re.MULTILINE),
        "algorithm": "Ristretto255",
        "key_size": 256,
        "primitive": PrimitiveType.ENCRYPTION,
        "description": "Pedersen Commitment & Sigma Proof (Information-Theoretic Hiding)",
        "tier": XTier.EPHEMERAL,
        "shredding": True
    },
    {
        "pattern": re.compile(r"pub\s+struct\s+Lwe(?:PublicKey|SecretKey|Ciphertext)\b|const\s+LWE_Q\b", re.MULTILINE),
        "algorithm": "LWE-2048",
        "key_size": 2048,
        "primitive": PrimitiveType.ENCRYPTION,
        "description": "Lattice-based Learning With Errors (LWE) Homomorphic Encryption",
        "tier": XTier.SHORT_TERM,
        "shredding": True
    },
    {
        "pattern": re.compile(r"\bsha2::(?:Sha256|Sha512)\b", re.MULTILINE),
        "algorithm": "SHA-256",
        "key_size": 256,
        "primitive": PrimitiveType.HASH,
        "description": "Rust sha2 Cryptographic Hash",
        "tier": XTier.OPERATIONAL,
        "shredding": False
    },
]

# Regex patterns for Java Cryptography Architecture (JCA / JCE) operations
JAVA_PATTERNS = [
    {
        "pattern": re.compile(r"Cipher\.getInstance\s*\(\s*[\"']([^\"']+)[\"']", re.MULTILINE),
        "handler": "_handle_java_cipher"
    },
    {
        "pattern": re.compile(r"KeyGenerator\.getInstance\s*\(\s*[\"']([^\"']+)[\"']", re.MULTILINE),
        "handler": "_handle_java_key_generator"
    },
    {
        "pattern": re.compile(r"KeyPairGenerator\.getInstance\s*\(\s*[\"']([^\"']+)[\"']", re.MULTILINE),
        "handler": "_handle_java_keypair_generator"
    },
    {
        "pattern": re.compile(r"MessageDigest\.getInstance\s*\(\s*[\"']([^\"']+)[\"']", re.MULTILINE),
        "handler": "_handle_java_message_digest"
    },
    {
        "pattern": re.compile(r"Signature\.getInstance\s*\(\s*[\"']([^\"']+)[\"']", re.MULTILINE),
        "handler": "_handle_java_signature"
    },
    {
        "pattern": re.compile(r"new\s+SecretKeySpec\s*\([^,]+,\s*[\"']([^\"']+)[\"']\)", re.MULTILINE),
        "handler": "_handle_java_secret_key_spec"
    },
]

def _handle_java_cipher(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    transform = match_str.strip().upper()
    algo = transform.split("/")[0]
    is_ecb = "ECB" in transform
    if "DESEDE" in algo or "3DES" in algo:
        return "3DES-168", 168, PrimitiveType.ENCRYPTION
    elif "DES" in algo:
        return "DES-56", 56, PrimitiveType.ENCRYPTION
    elif "BLOWFISH" in algo:
        return "Blowfish-128", 128, PrimitiveType.ENCRYPTION
    elif "AES" in algo:
        if is_ecb:
            return "AES-ECB", 128, PrimitiveType.ENCRYPTION
        return "AES-256", 256, PrimitiveType.ENCRYPTION
    elif "RSA" in algo:
        return "RSA-2048", 2048, PrimitiveType.KEY_EXCHANGE
    elif "RC4" in algo or "ARCFOUR" in algo:
        return "RC4-128", 128, PrimitiveType.ENCRYPTION
    return algo, 128, PrimitiveType.ENCRYPTION

def _handle_java_key_generator(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "AES" in algo:
        return "AES-256", 256, PrimitiveType.ENCRYPTION
    elif "DESEDE" in algo or "3DES" in algo:
        return "3DES-168", 168, PrimitiveType.ENCRYPTION
    elif "DES" in algo:
        return "DES-56", 56, PrimitiveType.ENCRYPTION
    elif "BLOWFISH" in algo:
        return "Blowfish-128", 128, PrimitiveType.ENCRYPTION
    elif "HMAC" in algo:
        return algo, 256, PrimitiveType.HASH
    return algo, 128, PrimitiveType.ENCRYPTION

def _handle_java_keypair_generator(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "RSA" in algo:
        return "RSA-2048", 2048, PrimitiveType.SIGNATURE
    elif "EC" in algo or "ECDSA" in algo:
        return "ECDSA-P256", 256, PrimitiveType.SIGNATURE
    elif "DSA" in algo:
        return "DSA-1024", 1024, PrimitiveType.SIGNATURE
    elif "DIFFIEHELLMAN" in algo or "DH" in algo:
        return "DH-2048", 2048, PrimitiveType.KEY_EXCHANGE
    return algo, 2048, PrimitiveType.KEY_EXCHANGE

def _handle_java_message_digest(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "MD5" in algo:
        return "MD5", 128, PrimitiveType.HASH
    elif "MD2" in algo:
        return "MD2", 128, PrimitiveType.HASH
    elif "MD4" in algo:
        return "MD4", 128, PrimitiveType.HASH
    elif "SHA-1" in algo or "SHA1" in algo:
        return "SHA-1", 160, PrimitiveType.HASH
    elif "SHA-256" in algo or "SHA256" in algo:
        return "SHA-256", 256, PrimitiveType.HASH
    elif "SHA-512" in algo:
        return "SHA-512", 512, PrimitiveType.HASH
    elif "SHA-384" in algo:
        return "SHA-384", 384, PrimitiveType.HASH
    return algo, 256, PrimitiveType.HASH

def _handle_java_signature(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "RSA" in algo:
        return f"RSA-{algo}", 2048, PrimitiveType.SIGNATURE
    elif "ECDSA" in algo:
        return f"ECDSA-{algo}", 256, PrimitiveType.SIGNATURE
    elif "DSA" in algo:
        return f"DSA-{algo}", 1024, PrimitiveType.SIGNATURE
    return algo, 256, PrimitiveType.SIGNATURE

def _handle_java_secret_key_spec(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "AES" in algo:
        return "AES-256", 256, PrimitiveType.ENCRYPTION
    elif "DES" in algo:
        return "DES-56", 56, PrimitiveType.ENCRYPTION
    elif "BLOWFISH" in algo:
        return "Blowfish-128", 128, PrimitiveType.ENCRYPTION
    return algo, 128, PrimitiveType.ENCRYPTION

def _extract_line_number(source: str, match_start: int) -> int:
    """Computes 1-indexed line number from character offset."""
    return source[:match_start].count("\n") + 1

def _check_crypto_shredding_context(source: str, line_no: int) -> Tuple[bool, XTier]:
    """
    Checks if surrounding code indicates explicit ephemeral lifecycle
    or automated key destruction (crypto-shredding).
    """
    lines = source.splitlines()
    start = max(0, line_no - 20)
    end = min(len(lines), line_no + 20)
    window = "\n".join(lines[start:end]).lower()

    if any(k in window for k in ["hndl", "in-memory only", "destroyforelection", "destroy", "zeroed", "delete", "clear"]):
        return True, XTier.EPHEMERAL
    if any(k in window for k in ["redis", "expire", "session", "token", "cache", "short_term"]):
        return True, XTier.SHORT_TERM
    if any(k in window for k in ["s3", "archive", "backup", "cold"]):
        return False, XTier.ARCHIVAL
    return False, XTier.OPERATIONAL

def scan_javascript_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a JavaScript/TypeScript source file for in-code crypto operations."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    assets: List[CryptoAsset] = []
    rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
    stem = file_path.stem

    for rule in JS_PATTERNS:
        handler_name = rule.get("handler")
        if handler_name == "_handle_forge_rsa_keygen":
            for match in rule["pattern"].finditer(content):
                line_no = _extract_line_number(content, match.start())
                opts = match.group(1)
                bits = 2048
                bits_match = re.search(r"bits:\s*(\d+)", opts)
                if bits_match:
                    bits = int(bits_match.group(1))

                is_shred, tier = _check_crypto_shredding_context(content, line_no)
                is_blind = "blind" in rel_path.lower() or "blind" in content.lower()
                prim = PrimitiveType.SIGNATURE if is_blind else PrimitiveType.KEY_EXCHANGE
                alg = f"RSA-{bits}"

                assets.append(CryptoAsset(
                    asset_id=f"SRC-JS-{len(assets) + 1:03d}",
                    component_name=f"{stem}:rsa_keygen",
                    algorithm=alg,
                    key_size=bits,
                    primitive_type=prim,
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=tier if is_shred else XTier.EPHEMERAL,
                    x_confidence="HIGH",
                    has_crypto_shredding=True if is_shred or is_blind else False,
                    raw_properties={
                        "source": "source_scanner",
                        "language": "javascript",
                        "library": "node-forge",
                        "operation": "rsa.generateKeyPair",
                        "matched_code": match.group(0)[:80],
                    }
                ))
        elif handler_name == "_handle_aes_cipher":
            for match in rule["pattern"].finditer(content):
                line_no = _extract_line_number(content, match.start())
                bits = int(match.group(1))
                mode = match.group(2).upper()
                assets.append(CryptoAsset(
                    asset_id=f"SRC-JS-{len(assets) + 1:03d}",
                    component_name=f"{stem}:aes_cipher",
                    algorithm=f"AES-{bits}-{mode}",
                    key_size=bits,
                    primitive_type=PrimitiveType.ENCRYPTION,
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=XTier.OPERATIONAL,
                    x_confidence="HIGH",
                    has_crypto_shredding=False,
                    raw_properties={
                        "source": "source_scanner",
                        "language": "javascript",
                        "library": "crypto",
                        "operation": "createCipheriv",
                        "matched_code": match.group(0)[:80],
                    }
                ))
        else:
            for match in rule["pattern"].finditer(content):
                line_no = _extract_line_number(content, match.start())
                is_shred, inferred_tier = _check_crypto_shredding_context(content, line_no)
                tier = rule.get("tier", inferred_tier)
                shredding = rule.get("shredding", is_shred)

                assets.append(CryptoAsset(
                    asset_id=f"SRC-JS-{len(assets) + 1:03d}",
                    component_name=f"{stem}:{rule['algorithm'].lower()}",
                    algorithm=rule["algorithm"],
                    key_size=rule.get("key_size"),
                    primitive_type=rule["primitive"],
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=tier,
                    x_confidence="HIGH",
                    has_crypto_shredding=shredding,
                    raw_properties={
                        "source": "source_scanner",
                        "language": "javascript",
                        "description": rule.get("description", ""),
                        "matched_code": match.group(0)[:80],
                    }
                ))

    return assets

def scan_go_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Go source file for in-code crypto operations."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    assets: List[CryptoAsset] = []
    rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
    stem = file_path.stem

    for rule in GO_PATTERNS:
        for match in rule["pattern"].finditer(content):
            line_no = _extract_line_number(content, match.start())
            assets.append(CryptoAsset(
                asset_id=f"SRC-GO-{len(assets) + 1:03d}",
                component_name=f"{stem}:{rule['algorithm'].lower()}",
                algorithm=rule["algorithm"],
                key_size=rule.get("key_size"),
                primitive_type=rule["primitive"],
                file_path=rel_path,
                line_number=line_no,
                x_tier=rule["tier"],
                x_confidence="HIGH",
                has_crypto_shredding=rule["shredding"],
                raw_properties={
                    "source": "source_scanner",
                    "language": "go",
                    "description": rule["description"],
                    "matched_code": match.group(0)[:80],
                }
            ))

    return assets

def scan_rust_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Rust source file for in-code crypto operations."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    assets: List[CryptoAsset] = []
    rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
    stem = file_path.stem

    for rule in RUST_PATTERNS:
        for match in rule["pattern"].finditer(content):
            line_no = _extract_line_number(content, match.start())
            assets.append(CryptoAsset(
                asset_id=f"SRC-RS-{len(assets) + 1:03d}",
                component_name=f"{stem}:{rule['algorithm'].lower()}",
                algorithm=rule["algorithm"],
                key_size=rule.get("key_size"),
                primitive_type=rule["primitive"],
                file_path=rel_path,
                line_number=line_no,
                x_tier=rule["tier"],
                x_confidence="HIGH",
                has_crypto_shredding=rule["shredding"],
                raw_properties={
                    "source": "source_scanner",
                    "language": "rust",
                    "description": rule["description"],
                    "matched_code": match.group(0)[:80],
                }
            ))

    return assets

def scan_java_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Java source file for JCA/JCE in-code crypto operations."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    assets: List[CryptoAsset] = []
    rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
    stem = file_path.stem

    handler_map = {
        "_handle_java_cipher": _handle_java_cipher,
        "_handle_java_key_generator": _handle_java_key_generator,
        "_handle_java_keypair_generator": _handle_java_keypair_generator,
        "_handle_java_message_digest": _handle_java_message_digest,
        "_handle_java_signature": _handle_java_signature,
        "_handle_java_secret_key_spec": _handle_java_secret_key_spec,
    }

    for rule in JAVA_PATTERNS:
        handler = handler_map.get(rule.get("handler", ""))
        if not handler:
            continue
        for match in rule["pattern"].finditer(content):
            line_no = _extract_line_number(content, match.start())
            matched_arg = match.group(1)
            alg, key_size, prim = handler(matched_arg)
            is_shred, tier = _check_crypto_shredding_context(content, line_no)

            intent, _ = classify_intent(var_name=stem, context_lines=match.group(0), primitive_type=prim)

            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:{alg.lower().replace(' ', '_')}",
                algorithm=alg,
                key_size=key_size,
                primitive_type=prim,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=intent,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_ast_regex"],
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "jca_api": rule.get("handler", ""),
                    "matched_code": match.group(0)[:80],
                }
            ))

    return assets

def discover_polyglot_crypto_assets(target_dir: str) -> List[CryptoAsset]:
    """
    Recursively scans target_dir for in-code cryptographic operations across
    JavaScript (.js, .mjs, .cjs, .ts), Go (.go), Rust (.rs), and Java (.java).
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        return []

    all_assets: List[CryptoAsset] = []
    seen_keys = set()

    for p in sorted(target_path.glob("**/*")):
        if not p.is_file():
            continue
        rel = p.relative_to(target_path) if p.is_relative_to(target_path) else p
        if any(part in EXCLUDED_DIRS for part in rel.parts[:-1]):
            continue
        if not should_scan_file(str(p), base_dir=str(target_path)):
            continue

        file_assets: List[CryptoAsset] = []
        suffix = p.suffix.lower()

        if suffix in {".js", ".mjs", ".cjs", ".ts"}:
            file_assets = scan_javascript_file(p, target_path)
        elif suffix == ".go":
            file_assets = scan_go_file(p, target_path)
        elif suffix == ".rs":
            file_assets = scan_rust_file(p, target_path)
        elif suffix == ".java":
            file_assets = scan_java_file(p, target_path)

        for a in file_assets:
            # Deduplicate per file and algorithm to maintain clean, high-signal CBOM
            dedup_key = f"{a.file_path}:{a.algorithm}:{a.primitive_type.value}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            all_assets.append(a)

    for idx, a in enumerate(all_assets, start=1):
        a.asset_id = f"SRC-CRYPTO-{idx:03d}"

    return all_assets
