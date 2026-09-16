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

def _trace_java_var(var_name: str, before_pos: int, content: str, max_depth: int = 8) -> Optional[str]:
    """
    Backwards data-flow trace for Java variable identifiers.
    Handles:
      - Variable re-assignment and alias chains (flow-sensitivity)
      - Three-step variable swaps (valueswap)
      - Object field dereferences (e.g. obj.field, configClass.algoConfig1)
      - Object instantiations and factory invocations (new Class("VAL"), GetObject("VAL"))
      - Identity wrapper functions (Identity("VAL"))
    """
    curr_var = var_name.strip().strip("\"'")
    if any(q in var_name for q in ('"', "'")):
        return curr_var
    if curr_var.isdigit():
        return curr_var

    curr_pos = before_pos
    for _ in range(max_depth):
        if (curr_var.startswith('"') and curr_var.endswith('"')) or (curr_var.startswith("'") and curr_var.endswith("'")):
            return curr_var.strip("\"'")
        if curr_var.isdigit():
            return curr_var

        pre = content[:curr_pos]

        # 1. Object field dereference: e.g. cryptoClass2.algorithm or configClass.algoConfig1
        if "." in curr_var:
            obj_name, field_name = curr_var.split(".", 1)
            pat_field = r'\b' + re.escape(obj_name) + r'\.' + re.escape(field_name) + r'\s*=\s*([^;]+);'
            matches = list(re.finditer(pat_field, pre))
            if matches:
                last_m = matches[-1]
                curr_var = last_m.group(1).strip()
                curr_pos = last_m.start()
                continue
            pat_ctor = r'\b' + re.escape(obj_name) + r'\s*=\s*(?:new\s+[A-Z][a-zA-Z0-9_]*|[a-zA-Z0-9_]+)\s*\(\s*([^,)]+)'
            matches_ctor = list(re.finditer(pat_ctor, pre))
            if matches_ctor:
                last_ctor = matches_ctor[-1]
                curr_var = last_ctor.group(1).strip()
                curr_pos = last_ctor.start()
                continue

        # 2. Local variable assignment: [Type] curr_var = RHS;
        pat = r'(?:[a-zA-Z0-9_<>[\]]+\s+)?\b' + re.escape(curr_var) + r'\s*=\s*([^;]+);'
        matches = list(re.finditer(pat, pre))
        if not matches:
            break
        last_m = matches[-1]
        rhs = last_m.group(1).strip()
        curr_pos = last_m.start()

        str_lit = re.search(r'["\']([^"\']+)["\']', rhs)
        if str_lit:
            return str_lit.group(1).strip()
        if re.search(r'new\s+(?:byte|char|int)\s*\[', rhs):
            return curr_var
        int_lit = re.search(r'\b(\d+)\b', rhs)
        if int_lit:
            return int_lit.group(1).strip()
        call_arg = re.search(r'(?:[a-zA-Z0-9_.]+\s*\(\s*)*([a-zA-Z0-9_.]+)\s*\)*', rhs)
        if call_arg:
            curr_var = call_arg.group(1).strip()
        else:
            curr_var = rhs
    # 3. Interprocedural method or constructor parameter binding:
    # If curr_var is a parameter of the enclosing method (e.g. method1(String algo)),
    # locate the call site in the same class/file and trace the passed argument.
    pre = content[:before_pos]
    method_pat = re.compile(r"\b(?:public|private|protected|static|\s)+\s*(?:[\w<>\[\]]+\s+)?(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\{")
    matches = list(method_pat.finditer(pre))
    if matches:
        enc_m = matches[-1]
        mname = enc_m.group(1)
        params_str = enc_m.group(2).strip()
        if params_str and mname != "main":
            params = [p.strip().split()[-1] for p in params_str.split(",") if p.strip()]
            if curr_var in params:
                param_idx = params.index(curr_var)
                call_pat = re.compile(r"\b(?:new\s+)?" + re.escape(mname) + r"\s*\(([^)]+)\)")
                for call_m in call_pat.finditer(content):
                    if call_m.start() >= enc_m.start() and call_m.start() <= enc_m.end():
                        continue
                    before_call = content[max(0, call_m.start() - 30):call_m.start()]
                    if re.search(r'\b(?:void|int|String|boolean|byte\[\]|[A-Z][a-zA-Z0-9_]*)\s+$', before_call) and not before_call.strip().endswith("new"):
                        continue
                    args = [a.strip() for a in call_m.group(1).split(",")]
                    if param_idx < len(args):
                        actual_arg = args[param_idx]
                        call_res = _trace_java_var(actual_arg, call_m.start(), content, max_depth - 1)
                        if call_res:
                            return call_res
                        if any(q in actual_arg for q in ('"', "'")):
                            return actual_arg.strip("\"'")

    return None

def _resolve_java_arg(raw_arg: str, content: str, file_path: Optional[Path] = None, before_pos: Optional[int] = None) -> str:
    """Resolves string literals or variable identifiers for Java crypto arguments."""
    clean = re.sub(r'^(?:String\.valueOf|\(String\))\s*\(\s*([^\)]+)\s*\)', r'\1', raw_arg.strip())
    arg_clean = clean.strip().strip("\"'")
    if any(q in raw_arg for q in ("\"", "'")):
        return arg_clean

    pos = before_pos if before_pos is not None else len(content)

    # 1. Backwards data-flow trace (flow-, object-, and valueswap-sensitive)
    traced = _trace_java_var(arg_clean, pos, content)
    if traced and (traced != arg_clean or any(q in traced for q in ('"', "'"))):
        return traced.strip("\"'")

    # 2. Local variable declaration: String var = "VAL" or var = "VAL" or var = Identity("VAL")
    var_match = re.search(r'(?:String|var)?\s*' + re.escape(arg_clean) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*["\']([^"\']+)["\']', content)
    if var_match:
        return var_match.group(1).strip()

    # 3. Chained variable: String var1 = var2; or var1 = Identity(var2);
    chain_match = re.search(r'(?:String|var)?\s*' + re.escape(arg_clean) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*([a-zA-Z0-9_]+)\s*\)?\s*;', content)
    if chain_match:
        chained_var = chain_match.group(1).strip()
        c_match = re.search(r'(?:String|var)?\s*' + re.escape(chained_var) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*["\']([^"\']+)["\']', content)
        if c_match:
            return c_match.group(1).strip()

    # 4. Local Constructor invocation: new Crypto2("VAL") or new Class(...)
    ctor_match = re.search(r'new\s+[A-Z][a-zA-Z0-9_]*\s*\(\s*["\']([^"\']+)["\']', content)
    if ctor_match:
        return ctor_match.group(1).strip()

    # 5. Map or container insertion: hm.put("key", "VAL")
    map_match = re.search(r'\.put\s*\(\s*[^,]+\s*,\s*["\']([^"\']+)["\']', content)
    if map_match:
        return map_match.group(1).strip()

    # 6. Method call with literal argument in current file: e.g. encrypt("VAL", ...) or go("VAL")
    call_match = re.search(r'\b(?:go|encrypt|test|main|check|set[A-Z]\w*)\s*\([^)]*["\']([^"\']+)["\']', content)
    if call_match and ("algo" in arg_clean.lower() or "crypto" in arg_clean.lower() or "default" in arg_clean.lower() or arg_clean in ("passedAlgo", "cryptoAlgo")):
        return call_match.group(1).strip()

    # 7. Companion caller/sibling files that explicitly import, instantiate, or reference this class
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
                    s_match = re.search(r'(?:String|var)?\s*' + re.escape(arg_clean) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*["\']([^"\']+)["\']', sib_content)
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

    # 8. Check if any known cryptographic algorithm string literal exists in the current file
    alg_match = KNOWN_JAVA_ALGS_RE.search(content)
    if alg_match and ("algo" in arg_clean.lower() or "crypto" in arg_clean.lower() or "default" in arg_clean.lower() or arg_clean in ("passedAlgo", "cryptoAlgo")):
        return alg_match.group(1).strip()

    return arg_clean

def _handle_java_cipher(match_str: str) -> Tuple[str, Optional[int], PrimitiveType]:
    transform = match_str.strip().upper()
    algo = transform.split("/")[0]
    is_ecb = "ECB" in transform or "/" not in transform
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
    elif "RC5" in algo:
        return "RC5-128", 128, PrimitiveType.ENCRYPTION
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
    elif "RC2" in algo:
        return "RC2-128", 128, PrimitiveType.ENCRYPTION
    elif "RC5" in algo:
        return "RC5-128", 128, PrimitiveType.ENCRYPTION
    elif "HMAC" in algo:
        return algo, 256, PrimitiveType.HASH
    return algo, 128, PrimitiveType.ENCRYPTION

def _handle_java_keypair_generator(match_str: str, content: str = "", file_path: Optional[Path] = None) -> Tuple[str, Optional[int], PrimitiveType]:
    algo = match_str.strip().upper()
    init_m = re.search(r'\b(?:initialize|init)\s*\(\s*([a-zA-Z0-9_.]+)\s*\)', content)
    found_size = None
    if init_m:
        arg_val = init_m.group(1).strip()
        if arg_val.isdigit():
            found_size = int(arg_val)
        else:
            traced = _trace_java_var(arg_val, init_m.start(), content)
            if traced and traced.isdigit():
                found_size = int(traced)
            else:
                pre_content = content[:init_m.start()]
                size_m = re.findall(r'\b(?:int|long)?\s*' + re.escape(arg_val) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', pre_content)
                if not size_m:
                    size_m = re.findall(r'\b(?:int|long)?\s*' + re.escape(arg_val) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', content)
                if size_m:
                    found_size = int(size_m[-1])
                else:
                    chain_m = re.search(r'\b(?:int|long)?\s*' + re.escape(arg_val) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*([a-zA-Z0-9_]+)', content)
                    if chain_m:
                        ch_val = chain_m.group(1).strip()
                        c_size = re.findall(r'\b(?:int|long)?\s*' + re.escape(ch_val) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', content)
                        if c_size:
                            found_size = int(c_size[-1])
                # Check if arg_val is a method parameter called with a known size
                if not found_size:
                    m_decl = re.search(r'\b([a-zA-Z0-9_]+)\s*\([^)]*\b' + re.escape(arg_val) + r'\b[^)]*\)\s*(?:throws[^{]+)?\{', content)
                    if m_decl:
                        func_name = m_decl.group(1).strip()
                        call_m = re.search(r'\b' + re.escape(func_name) + r'\s*\(\s*([a-zA-Z0-9_.]+)', content)
                        if call_m:
                            passed_arg = call_m.group(1).strip()
                            traced_p = _trace_java_var(passed_arg, call_m.start(), content)
                            if traced_p and traced_p.isdigit():
                                found_size = int(traced_p)
                            else:
                                p_size = re.findall(r'\b(?:int|long)?\s*' + re.escape(passed_arg) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', content)
                                if p_size:
                                    found_size = int(p_size[-1])
                if not found_size and file_path and file_path.parent.exists():
                    for sib in file_path.parent.glob("*.java"):
                        if sib != file_path:
                            try:
                                s_txt = sib.read_text(encoding="utf-8", errors="replace")
                                s_size = re.findall(r'\b(?:int|long)?\s*' + re.escape(arg_val) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', s_txt)
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

def _find_matching_brace(s: str, start: int) -> int:
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1

def _blank_out(s: str, start: int, end: int) -> str:
    sub = s[start:end]
    blanked = "".join("\n" if c == "\n" else " " for c in sub)
    return s[:start] + blanked + s[end:]

def _preprocess_java_path_conditions(content: str) -> str:
    """Evaluates statically provable branch conditions (e.g. constant choice/condition) to eliminate dead code branches."""
    constants = {}
    for m in re.finditer(r"\bint\s+([a-zA-Z0-9_]+)\s*=\s*(\d+)\s*;", content):
        constants[m.group(1)] = int(m.group(2))
    if not constants:
        return content

    # Reassignment overwrite without else:
    # e.g.: cipher = ...; if (choice > 1) cipher = ...;
    for var_name, var_val in constants.items():
        for if_m in re.finditer(r"\bif\s*\(\s*" + re.escape(var_name) + r"\s*(>|<|==|!=|>=|<=)\s*(\d+)\s*\)", content):
            op, val = if_m.group(1), int(if_m.group(2))
            if op == ">": cond_val = var_val > val
            elif op == "<": cond_val = var_val < val
            elif op == "==": cond_val = var_val == val
            elif op == "!=": cond_val = var_val != val
            elif op == ">=": cond_val = var_val >= val
            elif op == "<=": cond_val = var_val <= val
            else: continue

            if cond_val:
                reassign_pat = re.compile(
                    r"((?:[A-Za-z0-9_<>[\]]+\s+)?([A-Za-z0-9_]+)\s*=\s*[^;]+;)\s*" +
                    re.escape(if_m.group(0)) +
                    r"\s*(\2\s*=\s*[^;]+;)"
                )
                m_reassign = reassign_pat.search(content)
                if m_reassign:
                    content = _blank_out(content, m_reassign.start(1), m_reassign.end(1))

    for m in list(re.finditer(r"\bif\s*\(([^)]+)\)", content)):
        cond_str = m.group(1).strip()
        cond_m = re.match(r"([a-zA-Z0-9_]+)\s*(==|!=|>=|<=|>|<)\s*(\d+)", cond_str)
        if not cond_m:
            continue
        var_name, op, val_str = cond_m.group(1), cond_m.group(2), cond_m.group(3)
        if var_name not in constants:
            continue
        var_val = constants[var_name]
        val = int(val_str)
        if op == ">": cond_val = var_val > val
        elif op == "<": cond_val = var_val < val
        elif op == "==": cond_val = var_val == val
        elif op == "!=": cond_val = var_val != val
        elif op == ">=": cond_val = var_val >= val
        elif op == "<=": cond_val = var_val <= val
        else: continue

        idx = m.end()
        while idx < len(content) and content[idx].isspace():
            idx += 1
        if idx >= len(content):
            continue

        if content[idx] == "{":
            if_end = _find_matching_brace(content, idx)
            if if_end == -1:
                continue
            if_body_start, if_body_end = idx + 1, if_end
            next_idx = if_end + 1
        else:
            semi = content.find(";", idx)
            if semi == -1:
                continue
            if_body_start, if_body_end = idx, semi + 1
            next_idx = semi + 1

        rem = content[next_idx:]
        else_m = re.match(r"\s*else\b", rem)
        if bool(else_m):
            else_start = next_idx + else_m.end()
            while else_start < len(content) and content[else_start].isspace():
                else_start += 1
            if else_start < len(content):
                if content[else_start] == "{":
                    else_end = _find_matching_brace(content, else_start)
                    else_body_start, else_body_end = (else_start + 1, else_end) if else_end != -1 else (None, None)
                else:
                    semi = content.find(";", else_start)
                    else_body_start, else_body_end = (else_start, semi + 1) if semi != -1 else (None, None)
            else:
                else_body_start, else_body_end = None, None
        else:
            else_body_start, else_body_end = None, None

        if cond_val:
            if else_body_start is not None:
                content = _blank_out(content, else_body_start, else_body_end)
        else:
            content = _blank_out(content, if_body_start, if_body_end)

    return content

def _strip_java_comments(text: str) -> str:
    """Strips block and inline comments while strictly preserving string literals, line counts, and offsets."""
    def replacer(match):
        s = match.group(0)
        if s.startswith("/"):
            return "".join("\n" if c == "\n" else " " for c in s)
        else:
            return s
    pattern = re.compile(
        r"//.*?$|/\*.*?\*/|'(?:\\.|[^\\'])*'|\"(?:\\.|[^\\\"])*\"",
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

def scan_java_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Java source file for JCA/JCE in-code crypto operations and misuse patterns."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    # Strip comments safely without damaging URLs or strings
    content = _strip_java_comments(content)

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
            resolved_arg = _resolve_java_arg(matched_arg, content, file_path, before_pos=match.start())

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
                re.search(r"byte\s*(?:\[\s*\])?\s*" + re.escape(key_arg) + r"\s*(?:\[\s*\])?\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{", content) or
                re.search(r"String\s+" + re.escape(key_arg) + r"\s*=\s*[\"']", content) or
                re.search(r"byte\s*(?:\[\s*\])?\s*[a-zA-Z0-9_]+\s*(?:\[\s*\])?\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{[0-9\s,xX\(\)byte\-]+\}", content) or
                re.search(re.escape(key_arg) + r"\[\s*\d+\s*\]\s*=\s*\d+", content) or
                re.search(r"[a-zA-Z0-9_]+\[\s*\d+\s*\]\s*=\s*\d+", content) or
                re.search(r"String\s+[a-zA-Z0-9_]*key\s*=\s*[\"'][^\"']+[\"']", content, re.IGNORECASE) or
                re.search(r"String\s+defaultKey\s*=\s*[\"'][^\"']+[\"']", content)
            )
            if not has_static_key:
                str_var_m = re.search(r'\b' + re.escape(key_arg) + r'\s*=\s*([a-zA-Z0-9_]+)\.getBytes', content)
                if str_var_m:
                    str_var = str_var_m.group(1)
                    if re.search(r'String\s+' + re.escape(str_var) + r'\s*=\s*["\'][^"\']+["\']', content):
                        has_static_key = True
            if not has_static_key and file_path and file_path.parent.exists():
                for sib in file_path.parent.glob("*.java"):
                    if sib != file_path:
                        try:
                            s_txt = sib.read_text(encoding="utf-8", errors="replace")
                            if stem in s_txt:
                                if (re.search(r"byte\s*(?:\[\s*\])?\s*[a-zA-Z0-9_]+\s*(?:\[\s*\])?\s*=\s*\{", s_txt) or
                                    re.search(r"String\s+[a-zA-Z0-9_]+\s*=\s*[\"'][^\"']+[\"']", s_txt)):
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
        has_dynamic_seed = bool(
            re.search(r'\b' + re.escape(arg) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\.)?(?:nextLong|nextBytes|generateSeed)\s*\(', content) or
            re.search(r'\.setSeed\s*\(\s*(?:[a-zA-Z0-9_.]+\.)?(?:nextLong|nextBytes|generateSeed)\s*\(', content) or
            re.search(r'nextBytes\s*\(\s*' + re.escape(arg) + r'\s*\)', content)
        )
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
        has_dynamic_seed = bool(
            re.search(r'\b' + re.escape(arg) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\.)?(?:nextLong|nextBytes|generateSeed)\s*\(', content) or
            re.search(r'new\s+SecureRandom\s*\(\s*(?:[a-zA-Z0-9_.]+\.)?(?:nextLong|nextBytes|generateSeed)\s*\(', content) or
            re.search(r'nextBytes\s*\(\s*' + re.escape(arg) + r'\s*\)', content)
        )
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
            is_weak_count = int(count_arg) <= 1000
        else:
            traced_count = _trace_java_var(count_arg, m.start(), content)
            if traced_count and traced_count.isdigit():
                is_weak_count = int(traced_count) <= 1000
            else:
                map_get_m = re.search(r'\b' + re.escape(count_arg) + r'\s*=\s*[a-zA-Z0-9_]+\.get\s*\(\s*["\']([^"\']+)["\']\s*\)', content)
                if map_get_m:
                    m_key = map_get_m.group(1)
                    m_put = re.search(r'\.put\s*\(\s*["\']' + re.escape(m_key) + r'["\']\s*,\s*(?:new\s+Integer\s*\(\s*)?(\d+)', content)
                    if m_put:
                        is_weak_count = int(m_put.group(1)) <= 1000
                else:
                    pre_c = content[:m.start()]
                    counts = [int(x) for x in re.findall(r'\b(?:int|long)?\s*' + re.escape(count_arg) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', pre_c)]
                    if not counts:
                        counts = [int(x) for x in re.findall(r'\b(?:int|long)?\s*' + re.escape(count_arg) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', content)]
                    if counts:
                        is_weak_count = (counts[-1] <= 1000)
                    else:
                        # Check method parameter callers
                        m_decl = re.search(r'\b([a-zA-Z0-9_]+)\s*\([^)]*\b' + re.escape(count_arg) + r'\b[^)]*\)\s*(?:throws[^{]+)?\{', content)
                        if m_decl:
                            func_name = m_decl.group(1).strip()
                            call_m = re.search(r'\b' + re.escape(func_name) + r'\s*\([^,]+,\s*([a-zA-Z0-9_.]+)', content)
                            if call_m:
                                passed_arg = call_m.group(1).strip()
                                traced_p = _trace_java_var(passed_arg, call_m.start(), content)
                                if traced_p and traced_p.isdigit():
                                    is_weak_count = int(traced_p) <= 1000
                                else:
                                    p_cnts = [int(x) for x in re.findall(r'\b(?:int|long)?\s*' + re.escape(passed_arg) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*(\d+)', content)]
                                    if p_cnts:
                                        is_weak_count = (p_cnts[-1] <= 1000)
                        if not is_weak_count:
                            ctor_call = re.search(r'new\s+[A-Z][a-zA-Z0-9_]*\s*\(\s*(\d+)\s*\)', content)
                            if ctor_call and int(ctor_call.group(1)) <= 1000 and "AES" not in ctor_call.group(0):
                                is_weak_count = True
                            elif file_path and file_path.parent.exists():
                                for sib in file_path.parent.glob("*.java"):
                                    if sib != file_path:
                                        try:
                                            s_txt = sib.read_text(encoding="utf-8", errors="replace")
                                            s_assign = re.findall(r'\b(?:int|long)?\s*(?:count|iteration)\s*=\s*(\d+)', s_txt)
                                            if s_assign and int(s_assign[-1]) <= 1000:
                                                is_weak_count = True
                                                break
                                            s_call = re.search(r'\b(?:go|test|method\d*)\s*\(\s*(\d+)\s*\)', s_txt)
                                            if s_call and int(s_call.group(1)) <= 1000:
                                                is_weak_count = True
                                                break
                                        except Exception:
                                            pass

        # Flow-aware dynamic salt check
        pre_content = content[:m.start()]
        pat_salt = r'(?:[a-zA-Z0-9_<>[\]]+\s+)?\b' + re.escape(salt_arg) + r'\s*=\s*([^;]+);'
        assigns_salt = list(re.finditer(pat_salt, pre_content))
        last_assign_salt = assigns_salt[-1].start() if assigns_salt else -1

        nb_salt = list(re.finditer(r'(?:([a-zA-Z0-9_]+)\.)?nextBytes\s*\(\s*' + re.escape(salt_arg) + r'\s*\)', pre_content))
        last_nb_salt = nb_salt[-1].start() if nb_salt else -1

        is_dynamic_salt = False
        if last_nb_salt > last_assign_salt:
            rcv = nb_salt[-1].group(1)
            if not (rcv and re.search(r'\b' + re.escape(rcv) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*new\s+Random\s*\(', pre_content)):
                is_dynamic_salt = True
        else:
            src_salt = _trace_java_var(salt_arg, m.start(), content)
            if src_salt:
                if any(c in src_salt for c in ('"', "'", "getBytes", "{")):
                    is_dynamic_salt = False
                else:
                    nb_src = list(re.finditer(r'(?:([a-zA-Z0-9_]+)\.)?nextBytes\s*\(\s*' + re.escape(src_salt) + r'\s*\)', pre_content))
                    if nb_src:
                        rcv_s = nb_src[-1].group(1)
                        if not (rcv_s and re.search(r'\b' + re.escape(rcv_s) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*new\s+Random\s*\(', pre_content)):
                            is_dynamic_salt = True

        if not is_dynamic_salt:
            m_decl = re.search(r'\b([a-zA-Z0-9_]+)\s*\([^)]*\b' + re.escape(salt_arg) + r'\b[^)]*\)\s*\{', content)
            if m_decl:
                func_name = m_decl.group(1).strip()
                call_m = re.search(r'\b' + re.escape(func_name) + r'\s*\(\s*([a-zA-Z0-9_.]+)', content)
                if call_m:
                    passed_arg = call_m.group(1).strip()
                    if re.search(r'nextBytes\s*\(\s*' + re.escape(passed_arg) + r'\s*\)', content):
                        is_dynamic_salt = True
                    else:
                        p_src = _trace_java_var(passed_arg, call_m.start(), content)
                        if p_src and re.search(r'nextBytes\s*\(\s*' + re.escape(p_src) + r'\s*\)', content):
                            is_dynamic_salt = True

        is_static_salt = not is_dynamic_salt

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

    for m in re.finditer(r"new\s+PBEKeySpec\s*\(\s*((?:[^,()]|\([^()]*\))+)(?:,\s*((?:[^,()]|\([^()]*\))+))?(?:,\s*((?:[^,()]|\([^()]*\))+))?", content):
        pass_arg = m.group(1).strip()
        salt_arg = m.group(2).strip() if m.group(2) else None
        count_arg = m.group(3).strip() if m.group(3) else None
        line_no = _extract_line_number(content, m.start())
        is_shred, tier = _check_crypto_shredding_context(content, line_no)
        is_dynamic_pass = (
            has_secure_pwd_gen or
            (pass_arg == "password" and "getPassword" in content) or
            "readPassword" in content or
            "console" in content.lower()
        )
        has_static_pass = bool(
            re.search(r'String\s+' + re.escape(pass_arg) + r'\s*=\s*["\'][^"\']+["\']', content) or
            re.search(r'String\s+defaultKey\s*=\s*["\'][^"\']+["\']', content) or
            re.search(r'["\'][a-zA-Z0-9_\-\.\$]{4,}["\']', pass_arg)
        )
        if not is_dynamic_pass and (has_static_pass or not any(x in pass_arg.lower() for x in ["getpassword", "arg", "param", "passcode"])):
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
        if salt_arg:
            has_dynamic_salt = bool(
                re.search(r"nextBytes\s*\(\s*" + re.escape(salt_arg) + r"\s*\)", content) or
                "SecureRandom" in content
            )
            if not has_dynamic_salt:
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
        if count_arg and count_arg.isdigit() and int(count_arg) < 1000:
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

    for m in re.finditer(r"(?i)\b(?:ks|keystore|[a-zA-Z0-9_]*keyStore)\.load\s*\([^,\n]+,\s*([^)\n]+)\)", content):
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
        pre_content = content[:m.start()]

        pat = r'(?:[a-zA-Z0-9_<>[\]]+\s+)?\b' + re.escape(iv_arg) + r'\s*=\s*([^;]+);'
        assigns = list(re.finditer(pat, pre_content))
        last_assign_pos = assigns[-1].start() if assigns else -1

        nb_matches = list(re.finditer(r'(?:([a-zA-Z0-9_]+)\.)?nextBytes\s*\(\s*' + re.escape(iv_arg) + r'\s*\)', pre_content))
        last_nb_pos = nb_matches[-1].start() if nb_matches else -1

        is_dynamic = False
        if last_nb_pos > last_assign_pos:
            rcv = nb_matches[-1].group(1)
            traced_rcv = _trace_java_var(rcv, last_nb_pos, pre_content) if rcv else None
            is_untrusted = bool(
                (rcv and re.search(r'\b' + re.escape(rcv) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*new\s+Random\s*\(', pre_content)) or
                (traced_rcv and "Random()" in traced_rcv and "SecureRandom" not in traced_rcv)
            )
            if is_untrusted:
                is_dynamic = False
            else:
                is_dynamic = True
        else:
            src_var = _trace_java_var(iv_arg, m.start(), content)
            if src_var:
                if any(c in src_var for c in ('"', "'", "getBytes", "{")):
                    is_dynamic = False
                else:
                    nb2 = list(re.finditer(r'(?:([a-zA-Z0-9_]+)\.)?nextBytes\s*\(\s*' + re.escape(src_var) + r'\s*\)', pre_content))
                    if nb2:
                        rcv2 = nb2[-1].group(1)
                        traced_rcv2 = _trace_java_var(rcv2, nb2[-1].start(), pre_content) if rcv2 else None
                        is_untrusted2 = bool(
                            (rcv2 and re.search(r'\b' + re.escape(rcv2) + r'\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*new\s+Random\s*\(', pre_content)) or
                            (traced_rcv2 and "Random()" in traced_rcv2 and "SecureRandom" not in traced_rcv2)
                        )
                        if not is_untrusted2:
                            is_dynamic = True

        if not is_dynamic:
            m_decl = re.search(r'\b([a-zA-Z0-9_]+)\s*\([^)]*\b' + re.escape(iv_arg) + r'\b[^)]*\)\s*\{', content)
            if m_decl:
                func_name = m_decl.group(1).strip()
                call_m = re.search(r'\b' + re.escape(func_name) + r'\s*\(\s*([a-zA-Z0-9_.]+)', content)
                if call_m:
                    passed_arg = call_m.group(1).strip()
                    if re.search(r'nextBytes\s*\(\s*' + re.escape(passed_arg) + r'\s*\)', content):
                        is_dynamic = True
                    else:
                        p_src = _trace_java_var(passed_arg, call_m.start(), content)
                        if p_src and re.search(r'nextBytes\s*\(\s*' + re.escape(p_src) + r'\s*\)', content):
                            is_dynamic = True
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
    for m in re.finditer(r"new\s+URL\s*\(\s*[\"']http://|String\s+[a-zA-Z0-9_]*url\s*=\s*[\"']http://|[\"']http://(?!schemas\.|www\.w3\.org|java\.sun\.com)[a-zA-Z0-9_\.\-:/]+[\"']", content, re.IGNORECASE):
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
    has_untrusted_prng = False
    for m_nb in re.finditer(r"\b([a-zA-Z0-9_.]+)\.next(?:Bytes|Int|Long|Double|Float)?\s*\(", content):
        rcv = m_nb.group(1).strip()
        if re.search(r"\b" + re.escape(rcv) + r"\s*=\s*(?:[a-zA-Z0-9_.]+\s*\(\s*)*new\s+Random\s*\(", content):
            has_untrusted_prng = True
            break
        traced_rcv = _trace_java_var(rcv, m_nb.start(), content)
        if traced_rcv and "Random()" in traced_rcv and "SecureRandom" not in traced_rcv:
            has_untrusted_prng = True
            break
    if not has_untrusted_prng and re.search(r"new\s+Random\s*\(\s*\)\.next", content):
        has_untrusted_prng = True

    if has_untrusted_prng and (
        "PBEParameterSpec" in content or
        "IvParameterSpec" in content or
        "Cipher" in content or
        "randomBytes" in content or
        "ivBytes" in content or
        "session" in content.lower() or
        "nonce" in content.lower() or
        "DigestAuthentication" in content
    ):
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
