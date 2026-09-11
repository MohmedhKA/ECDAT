"""
ECDAT Manifest Scanner:
Discovers third-party cryptographic dependencies across polyglot package manifests:
- npm (package.json)
- Go (go.mod)
- Rust (Cargo.toml)
- Python (requirements.txt, pyproject.toml)

Classifies each library into PQC (quantum-safe), Classical Asymmetric (vulnerable to Shor's),
or Symmetric/Hash, providing SBOM visibility without polluting first-party AST code graphs.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

KNOWN_CRYPTO_LIBRARIES: Dict[str, Dict[str, str]] = {
    # Post-Quantum Cryptography (PQC)
    "@noble/post-quantum": {"category": "POST_QUANTUM", "readiness": "MIGRATED_PQC", "desc": "NIST FIPS 203/204/205 ML-KEM & ML-DSA"},
    "liboqs": {"category": "POST_QUANTUM", "readiness": "MIGRATED_PQC", "desc": "Open Quantum Safe C/C++ library"},
    "pqcrypto": {"category": "POST_QUANTUM", "readiness": "MIGRATED_PQC", "desc": "Rust/Python post-quantum bindings"},
    "oqs": {"category": "POST_QUANTUM", "readiness": "MIGRATED_PQC", "desc": "Open Quantum Safe wrappers"},
    "crystals-dilithium": {"category": "POST_QUANTUM", "readiness": "MIGRATED_PQC", "desc": "NIST ML-DSA reference implementation"},
    "crystals-kyber": {"category": "POST_QUANTUM", "readiness": "MIGRATED_PQC", "desc": "NIST ML-KEM reference implementation"},
    
    # Classical Asymmetric (Vulnerable to Shor's algorithm - HNDL Risk)
    "node-forge": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "RSA/ECC classical cipher suite (HNDL risk)"},
    "elliptic": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "Classical ECC curves (secp256k1, P-256)"},
    "rsa": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "Classical RSA implementation"},
    "curve25519-dalek": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "X25519/Ed25519 curve operations (requires ML-KEM hybrid)"},
    "ed25519-dalek": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "Ed25519 signature scheme (requires ML-DSA hybrid)"},
    "cryptography": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "Python OpenSSL bindings (classical public key primitives)"},
    "pycryptodome": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "Python cryptography library (RSA, DSA, ECC)"},
    "pyopenssl": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "Python OpenSSL wrapper"},
    "paramiko": {"category": "CLASSICAL_ASYMMETRIC", "readiness": "VULNERABLE_CLASSICAL", "desc": "SSH client/server with classical RSA/ECDSA handshakes"},
    
    # Blockchain / Enterprise Frameworks
    "github.com/hyperledger/fabric-contract-api-go": {"category": "BLOCKCHAIN_CORE", "readiness": "CLASSICAL_HYBRID", "desc": "Hyperledger Fabric chaincode SDK (PDC & state operations)"},
    "github.com/hyperledger/fabric-gateway": {"category": "BLOCKCHAIN_CORE", "readiness": "CLASSICAL_HYBRID", "desc": "Fabric client gateway with gRPC TLS"},
    "ethers": {"category": "BLOCKCHAIN_CORE", "readiness": "VULNERABLE_CLASSICAL", "desc": "Ethereum Web3 client with secp256k1 ECDSA"},
    "web3": {"category": "BLOCKCHAIN_CORE", "readiness": "VULNERABLE_CLASSICAL", "desc": "Ethereum Web3 RPC framework"},
    
    # Symmetric / Hash / Tokens (Quantum Agility Safe under Grover's)
    "crypto-js": {"category": "SYMMETRIC_OR_HASH", "readiness": "SAFE_SYMMETRIC", "desc": "AES, SHA-2/3, HMAC symmetric algorithms"},
    "sha2": {"category": "SYMMETRIC_OR_HASH", "readiness": "SAFE_SYMMETRIC", "desc": "SHA-256 / SHA-512 cryptographic hash functions"},
    "aes": {"category": "SYMMETRIC_OR_HASH", "readiness": "SAFE_SYMMETRIC", "desc": "AES symmetric block cipher (AES-256 quantum-safe)"},
    "jsonwebtoken": {"category": "SYMMETRIC_OR_HASH", "readiness": "DEPENDS_ON_ALG", "desc": "JWT auth (HMAC-SHA256 safe; RS256 vulnerable)"},
    "bcrypt": {"category": "SYMMETRIC_OR_HASH", "readiness": "SAFE_SYMMETRIC", "desc": "Password hashing function"},
    "argon2": {"category": "SYMMETRIC_OR_HASH", "readiness": "SAFE_SYMMETRIC", "desc": "Memory-hard password hashing"},
}

EXCLUDED_DIR_NAMES = {
    "node_modules", "venv", ".venv", "env", "site-packages",
    "__pycache__", ".git", "dist", "build", "target", ".cache"
}

class DependencyCryptoPackage(BaseModel):
    package_name: str
    ecosystem: str # npm, go, cargo, pypi
    version: str
    manifest_path: str
    category: str # POST_QUANTUM, CLASSICAL_ASYMMETRIC, BLOCKCHAIN_CORE, SYMMETRIC_OR_HASH
    pqc_readiness: str # MIGRATED_PQC, VULNERABLE_CLASSICAL, SAFE_SYMMETRIC, CLASSICAL_HYBRID
    description: str
    recommendation: str

from ecdat.scanners.filters import should_scan_file

def _is_path_excluded(path: Path) -> bool:
    if not should_scan_file(str(path)):
        return True
    return any(part in EXCLUDED_DIR_NAMES for part in path.parts)

def _generate_dependency_recommendation(info: Dict[str, str], ecosystem: str = "") -> str:
    readiness = info.get("readiness", "")
    category = info.get("category", "")
    
    if readiness == "MIGRATED_PQC" or category == "POST_QUANTUM":
        return "Validated: Post-Quantum standard algorithm"
    elif readiness == "SAFE_SYMMETRIC" or category == "SYMMETRIC_OR_HASH":
        return "Maintain: Symmetric/hash algorithm (ensure key size >= 256 bits for Grover resistance)"
    elif category == "BLOCKCHAIN_CORE":
        if readiness == "VULNERABLE_CLASSICAL":
            return "Urgent: Migrate classical blockchain signing keys to post-quantum hybrid"
        return "Evaluate PQC chaincode and ledger support for post-quantum transaction signing"
    elif readiness == "VULNERABLE_CLASSICAL" or category == "CLASSICAL_ASYMMETRIC":
        return "Urgent: Migrate classical RSA/ECC to hybrid NIST FIPS 203/204 (ML-KEM/ML-DSA)"
    else:
        return "Audit primitive usage: ensure parameters meet post-quantum and Grover security thresholds"

def scan_package_json(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, ver in deps.items():
            name_clean = name.lower()
            match = None
            for k, info in KNOWN_CRYPTO_LIBRARIES.items():
                if k.lower() == name_clean or k.lower() in name_clean:
                    match = (k, info)
                    break
            if match:
                k, info = match
                rec = _generate_dependency_recommendation(info, ecosystem="npm")
                results.append(DependencyCryptoPackage(
                    package_name=name,
                    ecosystem="npm",
                    version=str(ver),
                    manifest_path=str(fpath.relative_to(root_path)),
                    category=info["category"],
                    pqc_readiness=info["readiness"],
                    description=info["desc"],
                    recommendation=rec,
                ))
    except Exception:
        pass
    return results

def scan_cargo_toml(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        # Parse simple dependencies table
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_deps = "dependencies" in line.lower()
                continue
            if in_deps and "=" in line:
                pkg_name = line.split("=")[0].strip()
                ver_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', line)
                if ver_match:
                    pkg_ver = ver_match.group(1)
                else:
                    pkg_ver = line.split("=", 1)[1].strip().strip('"').strip("'").strip("{} ")
                name_clean = pkg_name.lower()
                match = None
                for k, info in KNOWN_CRYPTO_LIBRARIES.items():
                    if k.lower() == name_clean or k.lower() in name_clean:
                        match = (k, info)
                        break
                if match:
                    k, info = match
                    rec = _generate_dependency_recommendation(info, ecosystem="cargo")
                    results.append(DependencyCryptoPackage(
                        package_name=pkg_name,
                        ecosystem="cargo",
                        version=pkg_ver[:20],
                        manifest_path=str(fpath.relative_to(root_path)),
                        category=info["category"],
                        pqc_readiness=info["readiness"],
                        description=info["desc"],
                        recommendation=rec,
                    ))
    except Exception:
        pass
    return results

def scan_go_mod(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("module") or line.startswith("go "):
                continue
            parts = line.split()
            if len(parts) >= 2:
                mod_name = parts[0]
                mod_ver = parts[1]
                mod_clean = mod_name.lower()
                match = None
                for k, info in KNOWN_CRYPTO_LIBRARIES.items():
                    if k.lower() in mod_clean:
                        match = (k, info)
                        break
                if match:
                    k, info = match
                    rec = _generate_dependency_recommendation(info, ecosystem="go")
                    results.append(DependencyCryptoPackage(
                        package_name=mod_name,
                        ecosystem="go",
                        version=mod_ver,
                        manifest_path=str(fpath.relative_to(root_path)),
                        category=info["category"],
                        pqc_readiness=info["readiness"],
                        description=info["desc"],
                        recommendation=rec,
                    ))
    except Exception:
        pass
    return results

def scan_requirements_txt(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=<>~!]+(.*))?", line)
                if match:
                    pkg_name = match.group(1)
                    pkg_ver = match.group(2) or "latest"
                    pkg_clean = pkg_name.lower()
                    m = None
                    for k, info in KNOWN_CRYPTO_LIBRARIES.items():
                        if k.lower() == pkg_clean:
                            m = (k, info)
                            break
                    if m:
                        k, info = m
                        rec = _generate_dependency_recommendation(info, ecosystem="pypi")
                        results.append(DependencyCryptoPackage(
                            package_name=pkg_name,
                            ecosystem="pypi",
                            version=pkg_ver,
                            manifest_path=str(fpath.relative_to(root_path)),
                            category=info["category"],
                            pqc_readiness=info["readiness"],
                            description=info["desc"],
                            recommendation=rec,
                        ))
    except Exception:
        pass
    return results

def discover_manifest_crypto_dependencies(target_dir: str) -> List[DependencyCryptoPackage]:
    """
    Finds all package manifests in the target directory (excluding node_modules/venv),
    and audits declared cryptographic dependencies.
    """
    root = Path(target_dir).resolve()
    deps: List[DependencyCryptoPackage] = []
    seen = set()

    for path in root.rglob("*"):
        if not path.is_file() or _is_path_excluded(path):
            continue

        name = path.name.lower()
        if name == "package.json":
            for d in scan_package_json(path, root):
                key = (d.package_name, d.manifest_path)
                if key not in seen:
                    seen.add(key)
                    deps.append(d)
        elif name == "cargo.toml":
            for d in scan_cargo_toml(path, root):
                key = (d.package_name, d.manifest_path)
                if key not in seen:
                    seen.add(key)
                    deps.append(d)
        elif name == "go.mod":
            for d in scan_go_mod(path, root):
                key = (d.package_name, d.manifest_path)
                if key not in seen:
                    seen.add(key)
                    deps.append(d)
        elif name in ("requirements.txt", "requirements-dev.txt"):
            for d in scan_requirements_txt(path, root):
                key = (d.package_name, d.manifest_path)
                if key not in seen:
                    seen.add(key)
                    deps.append(d)

    return deps
