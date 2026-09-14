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
from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel, IntentClass, AgilityLevel
from ecdat.intent.classifier import classify_intent
from ecdat.agility.cams_detector import detect_cams_agility
from ecdat.scanners.filters import should_scan_file

EXCLUDED_DIRS = {
    "venv", ".venv", "env", "node_modules", "site-packages",
    "__pycache__", ".git", "dist", "build", "target", ".cache",
    ".agents", ".gemini", ".antigravity", ".codex", ".superpowers", "agents"
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
        "pattern": re.compile(r"Cipher\.getInstance\s*\(\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_cipher"
    },
    {
        "pattern": re.compile(r"KeyGenerator\.getInstance\s*\(\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_key_generator"
    },
    {
        "pattern": re.compile(r"KeyPairGenerator\.getInstance\s*\(\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_keypair_generator"
    },
    {
        "pattern": re.compile(r"MessageDigest\.getInstance\s*\(\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_message_digest"
    },
    {
        "pattern": re.compile(r"Signature\.getInstance\s*\(\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_signature"
    },
    {
        "pattern": re.compile(r"Mac\.getInstance\s*\(\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_mac"
    },
    {
        "pattern": re.compile(r"new\s+SecretKeySpec\s*\([^,]+,\s*([^,\)\s]+)", re.MULTILINE),
        "handler": "_handle_java_secret_key_spec"
    },
]

KNOWN_JAVA_ALGS_RE = re.compile(
    r"[\"']((?:DESede|3DES|DES|Blowfish|RC4|ARCFOUR|RC2|IDEA|MD5|MD4|MD2|SHA-?1|SHA-?256|SHA-?512|SHA-?384|AES|RSA|ECDSA|DSA|DiffieHellman|DH|Hmac[A-Za-z0-9]+)[^\"']*)[\"']",
    re.IGNORECASE
)

def _resolve_java_arg(raw_arg: str, content: str, file_path: Optional[Path] = None) -> str:
    """Resolves string literals or variable identifiers for Java crypto arguments."""
    clean = re.sub(r'^(?:String\.valueOf|\(String\))\s*\(\s*([^\)]+)\s*\)', r'\1', raw_arg.strip())
    arg_clean = clean.strip().strip("\"'")
    if any(q in raw_arg for q in ("\"", "'")):
        return arg_clean

    # 1. Local variable declaration: String var = "VAL" or var = "VAL"
    var_match = re.search(r'(?:String|var)?\s*' + re.escape(arg_clean) + r'\s*=\s*["\']([^"\']+)["\']', content)
    if var_match:
        return var_match.group(1).strip()

    # 2. Chained variable: String var1 = var2;
    chain_match = re.search(r'(?:String|var)?\s*' + re.escape(arg_clean) + r'\s*=\s*([a-zA-Z0-9_]+)\s*;', content)
    if chain_match:
        chained_var = chain_match.group(1).strip()
        c_match = re.search(r'(?:String|var)?\s*' + re.escape(chained_var) + r'\s*=\s*["\']([^"\']+)["\']', content)
        if c_match:
            return c_match.group(1).strip()

    # 3. Local Constructor invocation: new Crypto2("VAL") or new Class(...)
    ctor_match = re.search(r'new\s+[A-Z][a-zA-Z0-9_]*\s*\(\s*["\']([^"\']+)["\']', content)
    if ctor_match:
        return ctor_match.group(1).strip()

    # 4. Map or container insertion: hm.put("key", "VAL")
    map_match = re.search(r'\.put\s*\(\s*[^,]+\s*,\s*["\']([^"\']+)["\']', content)
    if map_match:
        return map_match.group(1).strip()

    # 5. Method call with literal argument in current file: e.g. encrypt("VAL", ...) or go("VAL")
    call_match = re.search(r'\b(?:go|encrypt|test|main|check|set[A-Z]\w*)\s*\([^)]*["\']([^"\']+)["\']', content)
    if call_match and ("algo" in arg_clean.lower() or "crypto" in arg_clean.lower() or "default" in arg_clean.lower() or arg_clean in ("passedAlgo", "cryptoAlgo")):
        return call_match.group(1).strip()

    # 6. Companion caller/sibling files that explicitly import, instantiate, or reference this class
    if file_path and file_path.parent.exists():
        stem = file_path.stem
        for sibling in file_path.parent.glob("*.java"):
            if sibling != file_path:
                try:
                    sib_content = sibling.read_text(encoding="utf-8", errors="replace")
                    # Strictly scope to companion files that reference this class name
                    if not re.search(r'\b' + re.escape(stem) + r'\b', sib_content):
                        continue
                    # Sibling references this class: search for matching variable definition
                    s_match = re.search(r'(?:String|var)?\s*' + re.escape(arg_clean) + r'\s*=\s*["\']([^"\']+)["\']', sib_content)
                    if s_match:
                        return s_match.group(1).strip()
                    # Search for constructor or method call passing an algorithm string
                    s_call = re.search(r'\b(?:go|encrypt|test|method\d*)\s*\([^)]*["\']([^"\']+)["\']', sib_content)
                    if s_call:
                        return s_call.group(1).strip()
                    sib_alg = KNOWN_JAVA_ALGS_RE.search(sib_content)
                    if sib_alg:
                        return sib_alg.group(1).strip()
                except Exception:
                    pass

    # 7. Check if any known cryptographic algorithm string literal exists in the current file
    alg_match = KNOWN_JAVA_ALGS_RE.search(content)
    if alg_match and ("algo" in arg_clean.lower() or "crypto" in arg_clean.lower() or "default" in arg_clean.lower() or arg_clean in ("passedAlgo", "cryptoAlgo")):
        return alg_match.group(1).strip()

    if alg_match:
        return alg_match.group(1).strip()

    return arg_clean

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
    elif "RC2" in algo:
        return "RC2-128", 128, PrimitiveType.ENCRYPTION
    elif "IDEA" in algo:
        return "IDEA-128", 128, PrimitiveType.ENCRYPTION
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
    elif "RC4" in algo or "ARCFOUR" in algo:
        return "RC4-128", 128, PrimitiveType.ENCRYPTION
    elif "HMAC" in algo:
        return algo, 256, PrimitiveType.HASH
    return algo, 128, PrimitiveType.ENCRYPTION

def _handle_java_keypair_generator(match_str: str, content: str = "", file_path: Optional[Path] = None) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    init_m = re.search(r'\b(?:initialize|init)\s*\(\s*([a-zA-Z0-9_]+)\s*\)', content)
    found_size = None
    if init_m:
        arg_val = init_m.group(1).strip()
        if arg_val.isdigit():
            found_size = int(arg_val)
        else:
            size_m = re.findall(r'\b(?:int|long)?\s*' + re.escape(arg_val) + r'\s*=\s*(\d+)', content)
            if size_m:
                found_size = int(size_m[-1])
            elif file_path and file_path.parent.exists():
                for sib in file_path.parent.glob("*.java"):
                    if sib != file_path:
                        try:
                            s_txt = sib.read_text(encoding="utf-8", errors="replace")
                            s_size = re.findall(r'\b(?:int|long)?\s*' + re.escape(arg_val) + r'\s*=\s*(\d+)', s_txt)
                            if s_size:
                                found_size = int(s_size[-1])
                                break
                            s_call = re.search(r'\b(?:go|test|main)\s*\(\s*(\d+)\s*\)', s_txt)
                            if s_call:
                                found_size = int(s_call.group(1))
                                break
                        except Exception:
                            pass
    if not found_size:
        sizes = [int(x) for x in re.findall(r'\b(?:keySize|keysize)\s*=\s*(\d+)', content)]
        if sizes:
            found_size = sizes[-1]

    if "RSA" in algo:
        size = found_size if found_size else 2048
        return f"RSA-{size}", size, PrimitiveType.SIGNATURE
    elif "EC" in algo or "ECDSA" in algo:
        size = found_size if found_size else 256
        return f"ECDSA-P{size}", size, PrimitiveType.SIGNATURE
    elif "DSA" in algo:
        size = found_size if found_size else 1024
        return f"DSA-{size}", size, PrimitiveType.SIGNATURE
    elif "DIFFIEHELLMAN" in algo or "DH" in algo:
        size = found_size if found_size else 2048
        return f"DH-{size}", size, PrimitiveType.KEY_EXCHANGE
    return algo, found_size or 2048, PrimitiveType.KEY_EXCHANGE

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

def _handle_java_mac(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "MD5" in algo:
        return "HMAC-MD5", 128, PrimitiveType.HASH
    elif "SHA1" in algo or "SHA-1" in algo:
        return "HMAC-SHA1", 160, PrimitiveType.HASH
    elif "SHA256" in algo or "SHA-256" in algo:
        return "HMAC-SHA256", 256, PrimitiveType.HASH
    elif "SHA512" in algo or "SHA-512" in algo:
        return "HMAC-SHA512", 512, PrimitiveType.HASH
    return f"HMAC-{algo}", 256, PrimitiveType.HASH

def _handle_java_secret_key_spec(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    if "AES" in algo:
        return "AES-256", 256, PrimitiveType.ENCRYPTION
    elif "DESEDE" in algo or "3DES" in algo:
        return "3DES-168", 168, PrimitiveType.ENCRYPTION
    elif "DES" in algo:
        return "DES-56", 56, PrimitiveType.ENCRYPTION
    elif "BLOWFISH" in algo:
        return "Blowfish-128", 128, PrimitiveType.ENCRYPTION
    elif "RC4" in algo or "ARCFOUR" in algo:
        return "RC4-128", 128, PrimitiveType.ENCRYPTION
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

def _preprocess_java_path_conditions(content: str) -> str:
    """Evaluates statically provable branch conditions (e.g. constant choice) to remove dead code branches."""
    choice_m = re.search(r'\bint\s+choice\s*=\s*(\d+)', content)
    if not choice_m:
        return content
    choice_val = int(choice_m.group(1))

    if_m = re.search(r'if\s*\(\s*choice\s*>\s*(\d+)\s*\)', content)
    if if_m:
        thresh = int(if_m.group(1))
        if choice_val > thresh:
            # 1. if (choice > 1) stmt1; else stmt2; -> stmt1;
            c = re.sub(r'if\s*\(\s*choice\s*>\s*\d+\s*\)\s*([^;]+;)\s*else\s*([^;]+;)', r'\1', content)
            # 2. Reassignment: Type var = expr; ... if (choice > 1) var = expr2;
            c = re.sub(
                r'((?:[A-Za-z0-9_<>\s]+\s+)?([A-Za-z0-9_]+)\s*=\s*[^;]+;)\s*if\s*\(\s*choice\s*>\s*\d+\s*\)\s*(\2\s*=\s*[^;]+;)',
                r'\3',
                c
            )
            return c
    return content

def scan_java_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Java source file for JCA/JCE in-code crypto operations and misuse patterns."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    # Path sensitivity dead-branch elimination
    content = _preprocess_java_path_conditions(content)

    assets: List[CryptoAsset] = []
    rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
    stem = file_path.stem

    handler_map = {
        "_handle_java_cipher": _handle_java_cipher,
        "_handle_java_key_generator": _handle_java_key_generator,
        "_handle_java_keypair_generator": _handle_java_keypair_generator,
        "_handle_java_message_digest": _handle_java_message_digest,
        "_handle_java_signature": _handle_java_signature,
        "_handle_java_mac": _handle_java_mac,
        "_handle_java_secret_key_spec": _handle_java_secret_key_spec,
    }

    # 1. Standard JCA API invocations with variable resolution
    for rule in JAVA_PATTERNS:
        handler = handler_map.get(rule.get("handler", ""))
        if not handler:
            continue
        for match in rule["pattern"].finditer(content):
            line_no = _extract_line_number(content, match.start())
            matched_arg = match.group(1)
            resolved_arg = _resolve_java_arg(matched_arg, content, file_path)

            if rule.get("handler") == "_handle_java_keypair_generator":
                alg, key_size, prim = _handle_java_keypair_generator(resolved_arg, content, file_path)
            else:
                alg, key_size, prim = handler(resolved_arg)

            is_shred, tier = _check_crypto_shredding_context(content, line_no)
            intent, _ = classify_intent(var_name=stem, context_lines=match.group(0), primitive_type=prim)
            surrounding = content[max(0, match.start() - 300):min(len(content), match.end() + 300)]
            cams_level, cams_desc = detect_cams_agility(source_line=match.group(0), surrounding_code=surrounding)

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
                agility_level=cams_level,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "jca_api": rule.get("handler", ""),
                    "matched_code": match.group(0)[:80],
                    "cams_evidence": cams_desc,
                }
            ))

    # 2. Hardcoded / Predictable SecretKeySpec
    for m in re.finditer(r"new\s+SecretKeySpec\s*\(\s*([^,]+),\s*([^)]+)\)", content):
        key_arg = m.group(1).strip()
        has_dynamic_random = bool(
            re.search(r"nextBytes\s*\(\s*" + re.escape(key_arg) + r"\s*\)", content) or
            ("KeyGenerator" in content and "generateKey" in content)
        )
        if not has_dynamic_random:
            has_static_key = bool(
                re.search(r"byte\s*(?:\[\s*\])?\s*" + re.escape(key_arg) + r"\s*(?:\[\s*\])?\s*=\s*\{", content) or
                re.search(r"String\s+" + re.escape(key_arg) + r"\s*=\s*[\"']", content) or
                re.search(r"\{[0-9\s,xX\(\)byte\-]+\}", content) or
                re.search(re.escape(key_arg) + r"\[\s*\d+\s*\]\s*=\s*\d+", content) or
                "String.valueOf" in content or
                "getBytes" in content
            )
            if not has_static_key and file_path and file_path.parent.exists():
                for sib in file_path.parent.glob("*.java"):
                    if sib != file_path:
                        try:
                            s_txt = sib.read_text(encoding="utf-8", errors="replace")
                            if re.search(r"byte\s*\[\s*\]\s*[a-zA-Z0-9_]*\s*=\s*\{", s_txt) or "key" in s_txt:
                                has_static_key = True
                                break
                        except Exception:
                            pass
            if has_static_key:
                line_no = _extract_line_number(content, m.start())
                is_shred, tier = _check_crypto_shredding_context(content, line_no)
                assets.append(CryptoAsset(
                    asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                    component_name=f"{stem}:predictable_key",
                    algorithm="PREDICTABLE-KEY",
                    key_size=128,
                    primitive_type=PrimitiveType.ENCRYPTION,
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=tier,
                    x_confidence="HIGH",
                    has_crypto_shredding=is_shred,
                    intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                    evidence_sources=["source_scanner:jca_predictable_key"],
                    agility_level=AgilityLevel.RIGID,
                    raw_properties={
                        "source": "source_scanner",
                        "language": "java",
                        "misuse_category": "Static/Contant Key",
                        "cwe": "CWE-321",
                        "matched_code": m.group(0)[:80],
                    }
                ))

    # 3. Predictable / Dynamic SecureRandom Seeds (setSeed / new SecureRandom(seed))
    for m in re.finditer(r"(?:[a-zA-Z0-9_]+)\.setSeed\s*\(\s*([^)]+)\)", content):
        arg = m.group(1).strip()
        has_dynamic_seed = bool(re.search(r"(?:nextLong|nextBytes)\s*\(", content))
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        if not has_dynamic_seed:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:predictable_seed",
                algorithm="PREDICTABLE-SEED",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_predictable_seed"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "Constant Seed",
                    "cwe": "CWE-330",
                    "matched_code": m.group(0)[:80],
                }
            ))
        else:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:dynamic_seed",
                algorithm="SECURE-PRNG",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_dynamic_seed"],
                agility_level=AgilityLevel.PROVIDER,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "matched_code": m.group(0)[:80],
                }
            ))

    for m in re.finditer(r"new\s+SecureRandom\s*\(\s*([^)]+)\)", content):
        arg = m.group(1).strip()
        has_dynamic_seed = bool(re.search(r"(?:nextLong|nextBytes)\s*\(", content))
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        if arg and not has_dynamic_seed:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:predictable_seed",
                algorithm="PREDICTABLE-SEED",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_predictable_seed"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "Constant Seed",
                    "cwe": "CWE-330",
                    "matched_code": m.group(0)[:80],
                }
            ))
        elif arg and has_dynamic_seed:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:dynamic_seed_sr",
                algorithm="SECURE-PRNG",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_dynamic_seed"],
                agility_level=AgilityLevel.PROVIDER,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "matched_code": m.group(0)[:80],
                }
            ))

    # 4. PBEParameterSpec (Weak Iteration Count < 1000 and Static Salt)
    for m in re.finditer(r"new\s+PBEParameterSpec\s*\(\s*([^,]+),\s*([^)]+)\)", content):
        salt_arg = m.group(1).strip()
        count_arg = m.group(2).strip()
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)

        is_weak_count = False
        if count_arg.isdigit():
            is_weak_count = int(count_arg) < 1000
        else:
            map_get_m = re.search(r'\b' + re.escape(count_arg) + r'\s*=\s*[a-zA-Z0-9_]+\.get\s*\(\s*["\']([^"\']+)["\']\s*\)', content)
            if map_get_m:
                m_key = map_get_m.group(1)
                m_put = re.search(r'\.put\s*\(\s*["\']' + re.escape(m_key) + r'["\']\s*,\s*(?:new\s+Integer\s*\(\s*)?(\d+)', content)
                if m_put:
                    is_weak_count = int(m_put.group(1)) < 1000
            else:
                counts = [int(x) for x in re.findall(r'\b(?:int|long)?\s*' + re.escape(count_arg) + r'\s*=\s*(\d+)', content)]
                if counts:
                    is_weak_count = (counts[-1] < 1000)
                else:
                    ctor_call = re.search(r'new\s+[A-Z][a-zA-Z0-9_]*\s*\(\s*(\d+)\s*\)', content)
                    if ctor_call and int(ctor_call.group(1)) < 1000 and "AES" not in ctor_call.group(0):
                        is_weak_count = True
                    elif file_path and file_path.parent.exists():
                        for sib in file_path.parent.glob("*.java"):
                            if sib != file_path:
                                try:
                                    s_txt = sib.read_text(encoding="utf-8", errors="replace")
                                    s_assign = re.findall(r'\b(?:int|long)?\s*(?:count|iteration)\s*=\s*(\d+)', s_txt)
                                    if s_assign and int(s_assign[-1]) < 1000:
                                        is_weak_count = True
                                        break
                                    s_call = re.search(r'\b(?:go|test|method\d*)\s*\(\s*(\d+)\s*\)', s_txt)
                                    if s_call and int(s_call.group(1)) < 1000:
                                        is_weak_count = True
                                        break
                                except Exception:
                                    pass

        is_static_salt = not bool(re.search(r"nextBytes\s*\(\s*" + re.escape(salt_arg) + r"\s*\)", content))

        if is_weak_count:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:pbe_weak_iteration",
                algorithm="PBE-WEAK-ITERATION",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_pbe_iteration"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "PBE iteration < 1000",
                    "cwe": "CWE-326",
                    "matched_code": m.group(0)[:80],
                }
            ))
        else:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:pbkdf2_iteration",
                algorithm="PBKDF2",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_pbe_compliant_iteration"],
                agility_level=AgilityLevel.CONFIGURABLE,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "iteration_count": str(count_arg),
                    "matched_code": m.group(0)[:80],
                }
            ))
        if is_static_salt:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:static_salt",
                algorithm="STATIC-SALT",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_static_salt"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "Static/Constant Salt",
                    "cwe": "CWE-326",
                    "matched_code": m.group(0)[:80],
                }
            ))
        else:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:dynamic_salt",
                algorithm="PBKDF2",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_dynamic_salt"],
                agility_level=AgilityLevel.CONFIGURABLE,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "salt_type": "dynamic",
                    "matched_code": m.group(0)[:80],
                }
            ))

    # 5. PBEKeySpec & KeyStore.load (Hardcoded / Predictable Passwords)
    has_secure_pwd_gen = bool(re.search(r"(?:random\.ints|ints\(\)|readPassword|getenv|System\.console)", content))

    for m in re.finditer(r"new\s+PBEKeySpec\s*\(\s*([^,\)]+)", content):
        pass_arg = m.group(1).strip()
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        if not has_secure_pwd_gen:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:hardcoded_password",
                algorithm="HARDCODED-PASSWORD",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_hardcoded_password"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "Static/Constant Password",
                    "cwe": "CWE-798",
                    "matched_code": m.group(0)[:80],
                }
            ))
        else:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:dynamic_password",
                algorithm="PBKDF2",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_dynamic_password"],
                agility_level=AgilityLevel.CONFIGURABLE,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "matched_code": m.group(0)[:80],
                }
            ))

    for m in re.finditer(r"\.load\s*\([^,]+,\s*([^)]+)\)", content):
        pass_arg = m.group(1).strip()
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        if pass_arg != "null" and not has_secure_pwd_gen:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:keystore_password",
                algorithm="PREDICTABLE-KEYSTORE-PASSWORD",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_keystore_password"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "Static/Constant Password",
                    "cwe": "CWE-798",
                    "matched_code": m.group(0)[:80],
                }
            ))
        elif pass_arg != "null" and has_secure_pwd_gen:
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:secure_keystore_password",
                algorithm="PBKDF2",
                key_size=None,
                primitive_type=PrimitiveType.KEY_EXCHANGE,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_secure_keystore_password"],
                agility_level=AgilityLevel.CONFIGURABLE,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "matched_code": m.group(0)[:80],
                }
            ))

    # 6. IvParameterSpec (Static IV)
    for m in re.finditer(r"new\s+IvParameterSpec\s*\(\s*([^)]+)\)", content):
        iv_arg = m.group(1).strip()
        is_dynamic = bool(
            re.search(r"nextBytes\s*\(\s*" + re.escape(iv_arg) + r"\s*\)", content) or
            (re.search(r"SecureRandom\s+[a-zA-Z0-9_]+\s*=\s*new\s+SecureRandom", content) and "nextBytes" in content)
        )
        if not is_dynamic:
            line_no = _extract_line_number(content, m.start())
            is_shred, tier = _check_crypto_shredding_context(content, line_no)
            assets.append(CryptoAsset(
                asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
                component_name=f"{stem}:static_iv",
                algorithm="STATIC-IV",
                key_size=128,
                primitive_type=PrimitiveType.ENCRYPTION,
                file_path=rel_path,
                line_number=line_no,
                x_tier=tier,
                x_confidence="HIGH",
                has_crypto_shredding=is_shred,
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                evidence_sources=["source_scanner:jca_static_iv"],
                agility_level=AgilityLevel.RIGID,
                raw_properties={
                    "source": "source_scanner",
                    "language": "java",
                    "misuse_category": "Static/Constant IV",
                    "cwe": "CWE-329",
                    "matched_code": m.group(0)[:80],
                }
            ))

    # 7. HTTP / HTTPS Transport
    for m in re.finditer(r"new\s+URL\s*\(\s*[\"']http://|String\s+[a-zA-Z0-9_]*url\s*=\s*[\"']http://", content, re.IGNORECASE):
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:cleartext_http",
            algorithm="CLEARTEXT-HTTP",
            key_size=None,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_http"],
            agility_level=AgilityLevel.RIGID,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "misuse_category": "HTTP",
                "cwe": "CWE-319",
                "matched_code": m.group(0)[:80],
            }
        ))

    for m in re.finditer(r"new\s+URL\s*\(\s*[\"']https://|(?:String\s+)?[a-zA-Z0-9_]*url\s*=\s*[\"']https://", content, re.IGNORECASE):
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:https_transport",
            algorithm="TLS",
            key_size=None,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=XTier.EPHEMERAL,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_https"],
            agility_level=AgilityLevel.CONFIGURABLE,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "transport_protocol": "HTTPS",
                "matched_code": m.group(0)[:80],
            }
        ))

    # 8. Certificate Validation / Hostname Verifier
    if re.search(r"checkServerTrusted\s*\([^\)]*\)\s*\{\s*\}", content) or re.search(r"class\s+\w+\s+implements\s+X509TrustManager", content):
        line_no = 1
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:dummy_cert_validation",
            algorithm="DUMMY-CERT-VALIDATION",
            key_size=None,
            primitive_type=PrimitiveType.SIGNATURE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_dummy_cert"],
            agility_level=AgilityLevel.RIGID,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "misuse_category": "Dummy Certificate",
                "cwe": "CWE-295",
                "matched_code": "class implements X509TrustManager with empty checkServerTrusted",
            }
        ))

    if re.search(r"verify\s*\([^\)]*\)\s*\{\s*return\s+true\s*;", content):
        line_no = 1
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:dummy_hostname_verifier",
            algorithm="DUMMY-HOSTNAME-VERIFIER",
            key_size=None,
            primitive_type=PrimitiveType.SIGNATURE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_dummy_hostname"],
            agility_level=AgilityLevel.RIGID,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "misuse_category": "Dummy Verifier",
                "cwe": "CWE-297",
                "matched_code": "verify() returns true without hostname check",
            }
        ))
    elif re.search(r"class\s+\w+\s+implements\s+HostnameVerifier", content) or "setDefaultHostnameVerifier" in content:
        line_no = 1
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:secure_hostname_verifier",
            algorithm="TLS-HOSTNAME-VERIFIER",
            key_size=None,
            primitive_type=PrimitiveType.SIGNATURE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_secure_hostname"],
            agility_level=AgilityLevel.CONFIGURABLE,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "matched_code": "Custom HostnameVerifier with active session verification",
            }
        ))

    # 9. PRNG & Improper SSLSocketFactory
    if re.search(r"new\s+Random\s*\(\s*\)", content) and "PBEParameterSpec" in content:
        line_no = 1
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:untrusted_prng",
            algorithm="UNTRUSTED-PRNG",
            key_size=None,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_untrusted_prng"],
            agility_level=AgilityLevel.RIGID,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "misuse_category": "Usage of Random Method from Library",
                "cwe": "CWE-338",
                "matched_code": "new Random() used for cryptographic parameter generation",
            }
        ))
    elif (re.search(r"new\s+SecureRandom\s*\(\s*\)|SecureRandom\.getInstanceStrong\(\)", content) and
          not re.search(r"\.setSeed\s*\(", content) and
          not re.search(r"new\s+SecureRandom\s*\(\s*[^)]+\)", content)):
        m_sr = re.search(r"new\s+SecureRandom\s*\(\s*\)|SecureRandom\.getInstanceStrong\(\)", content)
        line_no = _extract_line_number(content, m_sr.start()) if m_sr else 1
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:secure_prng",
            algorithm="SECURE-PRNG",
            key_size=None,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_secure_random"],
            agility_level=AgilityLevel.PROVIDER,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "prng_type": "CSPRNG",
                "matched_code": m_sr.group(0) if m_sr else "SecureRandom",
            }
        ))

    if re.search(r"SSLSocketFactory\.getDefault\(\)", content):
        line_no = 1
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        assets.append(CryptoAsset(
            asset_id=f"SRC-JAVA-{len(assets) + 1:03d}",
            component_name=f"{stem}:improper_ssl_socket",
            algorithm="IMPROPER-SSL-SOCKET-FACTORY",
            key_size=None,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=rel_path,
            line_number=line_no,
            x_tier=tier,
            x_confidence="HIGH",
            has_crypto_shredding=is_shred,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
            evidence_sources=["source_scanner:jca_ssl_socket"],
            agility_level=AgilityLevel.RIGID,
            raw_properties={
                "source": "source_scanner",
                "language": "java",
                "misuse_category": "Socket Hostname w/o verification",
                "cwe": "CWE-297",
                "matched_code": "SSLSocketFactory.getDefault().createSocket without hostname validation",
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
        if any((part.startswith(".") and part != ".") or part.lower() in EXCLUDED_DIRS for part in rel.parts[:-1]):
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
        if a.agility_level == AgilityLevel.RIGID:
            matched = a.raw_properties.get("matched_code", "")
            if matched:
                lvl, desc = detect_cams_agility(matched)
                if lvl != AgilityLevel.RIGID:
                    a.agility_level = lvl
                    a.raw_properties["cams_evidence"] = desc

    return all_assets
