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
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel
from ecdat.rules.signature_db import get_signature_db

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

def _lookup_package_rule(pkg_name: str, ecosystem: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Resolves package info using SQLite signature DB."""
    try:
        db = get_signature_db()
        rule = db.lookup_package(ecosystem, pkg_name)
        if rule:
            info = {
                "category": rule["category"],
                "readiness": rule["pqc_readiness"],
                "desc": rule["description"],
                "rec": rule["recommendation"]
            }
            return pkg_name, info
    except Exception:
        pass
    return None

def scan_package_json(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, ver in deps.items():
            match = _lookup_package_rule(name, "npm")
            if match:
                k, info = match
                rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="npm")
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
                pkg_ver = "latest"
                val_part = line.split("=", 1)[1].strip()
                if "version" in val_part:
                    for sub in val_part.strip("{} ").split(","):
                        if "version" in sub and "=" in sub:
                            pkg_ver = sub.split("=")[1].strip().strip('"\' ')
                            break
                else:
                    pkg_ver = val_part.strip('"\' ')
                match = _lookup_package_rule(pkg_name, "cargo")
                if match:
                    k, info = match
                    rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="cargo")
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
                match = _lookup_package_rule(mod_name, "go")
                if match:
                    k, info = match
                    rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="go")
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
                # Split off environment markers or inline comments
                line = line.split(";")[0].split("#")[0].strip()
                if not line:
                    continue
                pkg_name = line
                pkg_ver = "latest"
                for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                    if sep in line:
                        parts = line.split(sep, 1)
                        pkg_name = parts[0].strip()
                        pkg_ver = parts[1].strip()
                        break
                match = _lookup_package_rule(pkg_name, "pypi")
                if match:
                    k, info = match
                    rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="pypi")
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
