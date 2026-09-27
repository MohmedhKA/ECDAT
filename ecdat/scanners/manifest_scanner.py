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
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel
from ecdat.rules.signature_db import get_signature_db

import os
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

EXCLUDED_DIR_NAMES = {
    "node_modules", "venv", ".venv", "env", "site-packages",
    "__pycache__", ".git", "dist", "build", "target", ".cache"
}

_CVE_CACHE: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

class DependencyCryptoPackage(BaseModel):
    package_name: str
    ecosystem: str # npm, go, cargo, pypi, maven
    version: str
    manifest_path: str
    category: str # POST_QUANTUM, CLASSICAL_ASYMMETRIC, BLOCKCHAIN_CORE, SYMMETRIC_OR_HASH
    pqc_readiness: str # MIGRATED_PQC, VULNERABLE_CLASSICAL, SAFE_SYMMETRIC, CLASSICAL_HYBRID
    description: str
    recommendation: str
    scope: str = "PRODUCTION" # PRODUCTION or TEST_FIXTURE
    cve_id: Optional[str] = None # e.g. "CVE-2023-46604"
    cve_severity: Optional[str] = None # CRITICAL, HIGH, MEDIUM, LOW
    cve_summary: Optional[str] = None
    advisory_url: Optional[str] = None

from ecdat.scanners.filters import should_scan_file

def _is_path_excluded(path: Path, root: Optional[Path] = None) -> bool:
    base_str = str(root) if root else None
    if not should_scan_file(str(path), base_dir=base_str):
        return True
    if root is not None:
        try:
            rel = path.relative_to(root)
            return any(part in EXCLUDED_DIR_NAMES for part in rel.parts[:-1])
        except ValueError:
            pass
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
        prod_deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**prod_deps, **dev_deps}
        for name, ver in all_deps.items():
            match = _lookup_package_rule(name, "npm")
            if match:
                k, info = match
                rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="npm")
                scope = "TEST_FIXTURE" if (name in dev_deps and name not in prod_deps) else "PRODUCTION"
                results.append(DependencyCryptoPackage(
                    package_name=name,
                    ecosystem="npm",
                    version=str(ver),
                    manifest_path=str(fpath.relative_to(root_path)),
                    category=info["category"],
                    pqc_readiness=info["readiness"],
                    description=info["desc"],
                    recommendation=rec,
                    scope=scope,
                ))
    except Exception:
        pass
    return results

def scan_cargo_toml(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        in_deps = False
        in_dev_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_dev_deps = "dev-dependencies" in line.lower()
                in_deps = ("dependencies" in line.lower()) and not in_dev_deps
                continue
            if (in_deps or in_dev_deps) and "=" in line:
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
                    scope = "TEST_FIXTURE" if in_dev_deps else "PRODUCTION"
                    results.append(DependencyCryptoPackage(
                        package_name=pkg_name,
                        ecosystem="cargo",
                        version=pkg_ver[:20],
                        manifest_path=str(fpath.relative_to(root_path)),
                        category=info["category"],
                        pqc_readiness=info["readiness"],
                        description=info["desc"],
                        recommendation=rec,
                        scope=scope,
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
                    scope = "TEST_FIXTURE" if ("_test" in mod_name or "/test" in mod_name) else "PRODUCTION"
                    results.append(DependencyCryptoPackage(
                        package_name=mod_name,
                        ecosystem="go",
                        version=mod_ver,
                        manifest_path=str(fpath.relative_to(root_path)),
                        category=info["category"],
                        pqc_readiness=info["readiness"],
                        description=info["desc"],
                        recommendation=rec,
                        scope=scope,
                    ))
    except Exception:
        pass
    return results

def scan_requirements_txt(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        is_dev = any(k in fpath.name.lower() for k in ("dev", "test"))
        scope = "TEST_FIXTURE" if is_dev else "PRODUCTION"
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
                        scope=scope,
                    ))
    except Exception:
        pass
    return results

def _extract_pom_properties(root_elem: ET.Element) -> Dict[str, str]:
    """Extracts properties and basic coordinates from a POM element tree."""
    props: Dict[str, str] = {}
    
    # Check parent info
    parent_version = ""
    parent_group = ""
    for elem in root_elem:
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if tag == "parent":
            for child in elem:
                ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if ctag == "version" and child.text:
                    parent_version = child.text.strip()
                elif ctag == "groupId" and child.text:
                    parent_group = child.text.strip()
        elif tag == "groupId" and elem.text:
            props["project.groupId"] = elem.text.strip()
        elif tag == "artifactId" and elem.text:
            props["project.artifactId"] = elem.text.strip()
        elif tag == "version" and elem.text:
            props["project.version"] = elem.text.strip()
        elif tag == "properties":
            for prop in elem:
                ptag = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
                if prop.text:
                    props[ptag] = prop.text.strip()

    if "project.version" not in props and parent_version:
        props["project.version"] = parent_version
    if "project.groupId" not in props and parent_group:
        props["project.groupId"] = parent_group

    if "project.version" in props:
        props["pom.version"] = props["project.version"]
        props["version"] = props["project.version"]

    return props

def _resolve_maven_placeholder(val: str, props: Dict[str, str], root_props: Dict[str, str]) -> str:
    """Recursively resolves ${...} placeholders using local and root POM properties."""
    if not val or not isinstance(val, str):
        return val
    
    for _ in range(3):
        m = re.search(r"\$\{([a-zA-Z0-9_\.-]+)\}", val)
        if not m:
            break
        key = m.group(1)
        subst = props.get(key) or root_props.get(key)
        if subst:
            val = val[:m.start()] + subst + val[m.end():]
        else:
            break
    return val

def scan_maven_pom(fpath: Path, root_path: Path, root_props: Optional[Dict[str, str]] = None) -> List[DependencyCryptoPackage]:
    results = []
    if root_props is None:
        root_props = {}
    try:
        tree = ET.parse(fpath)
        root = tree.getroot()
        local_props = _extract_pom_properties(root)

        # Self-identification for project exclusion
        proj_group = local_props.get("project.groupId") or root_props.get("project.groupId", "")
        proj_artifact = local_props.get("project.artifactId", "")
        root_group = root_props.get("project.groupId", "")

        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "dependency":
                group_id = ""
                artifact_id = ""
                version = "managed"
                scope_tag = ""
                for child in elem:
                    ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if ctag == "groupId" and child.text:
                        group_id = child.text.strip()
                    elif ctag == "artifactId" and child.text:
                        artifact_id = child.text.strip()
                    elif ctag == "version" and child.text:
                        version = child.text.strip()
                    elif ctag == "scope" and child.text:
                        scope_tag = child.text.strip().lower()

                group_id = _resolve_maven_placeholder(group_id, local_props, root_props)
                artifact_id = _resolve_maven_placeholder(artifact_id, local_props, root_props)
                version = _resolve_maven_placeholder(version, local_props, root_props)

                # If version is still managed, attempt to lookup property matching artifact-version or artifactId.version
                if version == "managed":
                    fallback_ver = (
                        local_props.get(f"{artifact_id}-version")
                        or root_props.get(f"{artifact_id}-version")
                        or local_props.get(f"{artifact_id}.version")
                        or root_props.get(f"{artifact_id}.version")
                    )
                    if fallback_ver:
                        version = _resolve_maven_placeholder(fallback_ver, local_props, root_props)

                # Skip self-referential / first-party project submodules
                if group_id and (
                    (root_group and group_id == root_group)
                    or (proj_group and group_id == proj_group)
                ):
                    continue

                if artifact_id:
                    full_name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                    # Lookup full group:artifact, then artifact, then group
                    match = _lookup_package_rule(full_name, "maven") or _lookup_package_rule(artifact_id, "maven")
                    if not match and group_id:
                        match = _lookup_package_rule(group_id, "maven")

                    if match:
                        k, info = match
                        rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="maven")
                        is_test = (scope_tag == "test") or ("/src/test/" in str(fpath).replace("\\", "/")) or ("/test/" in str(fpath).replace("\\", "/"))
                        scope = "TEST_FIXTURE" if is_test else "PRODUCTION"
                        results.append(DependencyCryptoPackage(
                            package_name=full_name,
                            ecosystem="maven",
                            version=version,
                            manifest_path=str(fpath.relative_to(root_path)),
                            category=info["category"],
                            pqc_readiness=info["readiness"],
                            description=info["desc"],
                            recommendation=rec,
                            scope=scope,
                        ))
    except Exception:
        pass
    return results

def scan_gradle_build(fpath: Path, root_path: Path) -> List[DependencyCryptoPackage]:
    results = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("/*"):
                continue
            if any(k in line for k in ("implementation", "api", "compileOnly", "runtimeOnly", "classpath", "testImplementation", "testCompile", "testRuntimeOnly")):
                m = re.search(r"['\"]([a-zA-Z0-9_\.-]+:[a-zA-Z0-9_\.-]+)(?::([a-zA-Z0-9_\.-]+))?['\"]", line)
                if m:
                    coord = m.group(1)
                    ver = m.group(2) or "latest"
                    match = _lookup_package_rule(coord, "maven")
                    if match:
                        k, info = match
                        rec = info.get("rec") or _generate_dependency_recommendation(info, ecosystem="maven")
                        is_test = any(k in line for k in ("testImplementation", "testCompile", "testRuntimeOnly")) or ("/src/test/" in str(fpath).replace("\\", "/"))
                        scope = "TEST_FIXTURE" if is_test else "PRODUCTION"
                        results.append(DependencyCryptoPackage(
                            package_name=coord,
                            ecosystem="maven",
                            version=ver,
                            manifest_path=str(fpath.relative_to(root_path)),
                            category=info["category"],
                            pqc_readiness=info["readiness"],
                            description=info["desc"],
                            recommendation=rec,
                            scope=scope,
                        ))
    except Exception:
        pass
    return results

ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "go": "Go",
}

def _query_single_package_cve(pkg: DependencyCryptoPackage) -> Optional[Dict[str, Any]]:
    cache_key = (pkg.ecosystem, pkg.package_name, pkg.version)
    if cache_key in _CVE_CACHE:
        return _CVE_CACHE[cache_key]

    osv_eco = ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), pkg.ecosystem)
    payload: Dict[str, Any] = {
        "package": {
            "name": pkg.package_name,
            "ecosystem": osv_eco,
        }
    }
    # Clean version string (remove ~ ^ >= <= or managed/latest)
    clean_ver = re.sub(r"[^0-9a-zA-Z\.\-_]", "", pkg.version)
    if clean_ver and clean_ver.lower() not in ("managed", "latest", "snapshot"):
        payload["version"] = clean_ver

    url = "https://api.osv.dev/v1/query"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "ECDAT-Scanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            if not vulns:
                res = {"cve_id": None, "cve_severity": None, "cve_summary": None, "advisory_url": None}
                _CVE_CACHE[cache_key] = res
                return res

            cve_id = None
            summary = None
            severity = None
            advisory_url = None

            for v in vulns:
                v_id = v.get("id", "")
                aliases = v.get("aliases", [])
                for a in aliases:
                    if a.startswith("CVE-"):
                        cve_id = a
                        break
                if not cve_id and v_id.startswith("CVE-"):
                    cve_id = v_id
                
                if not summary and v.get("summary"):
                    summary = v.get("summary").strip()

                db_spec = v.get("database_specific", {})
                if not severity and db_spec.get("severity"):
                    severity = str(db_spec.get("severity")).upper()

                if not advisory_url:
                    for ref in v.get("references", []):
                        if ref.get("type") in ("ADVISORY", "WEB"):
                            advisory_url = ref.get("url")
                            break
                    if not advisory_url and v_id:
                        advisory_url = f"https://osv.dev/vulnerability/{v_id}"

                if cve_id:
                    break

            if not cve_id and vulns:
                cve_id = vulns[0].get("id")

            if not summary and vulns:
                summary = (vulns[0].get("details", "") or "").split("\n")[0][:120]

            res = {
                "cve_id": cve_id,
                "cve_severity": severity or "HIGH",
                "cve_summary": summary,
                "advisory_url": advisory_url or (f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id and cve_id.startswith("CVE-") else None)
            }
            _CVE_CACHE[cache_key] = res
            return res
    except Exception:
        res = {"cve_id": None, "cve_severity": None, "cve_summary": None, "advisory_url": None}
        return res

def resolve_cves_via_api(packages: List[DependencyCryptoPackage]) -> None:
    """
    Enriches discovered dependency packages with real-time CVE intelligence
    via the OSV API concurrently with a fast timeout.
    """
    if not packages:
        return
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_query_single_package_cve, pkg): pkg for pkg in packages}
        for future in futures:
            pkg = futures[future]
            try:
                cve_info = future.result()
                if cve_info:
                    pkg.cve_id = cve_info.get("cve_id")
                    pkg.cve_severity = cve_info.get("cve_severity")
                    pkg.cve_summary = cve_info.get("cve_summary")
                    pkg.advisory_url = cve_info.get("advisory_url")
            except Exception:
                pass

def discover_manifest_crypto_dependencies(target_dir: str) -> List[DependencyCryptoPackage]:
    """
    Finds all package manifests in the target directory (excluding node_modules/venv),
    and audits declared cryptographic dependencies.
    """
    root = Path(target_dir).resolve()
    deps: List[DependencyCryptoPackage] = []
    seen = set()

    # Pre-extract root Maven POM properties if root pom.xml exists
    root_pom_props: Dict[str, str] = {}
    root_pom = root / "pom.xml"
    if root_pom.is_file():
        try:
            tree = ET.parse(root_pom)
            root_pom_props = _extract_pom_properties(tree.getroot())
        except Exception:
            pass

    for path in root.rglob("*"):
        if not path.is_file() or _is_path_excluded(path, root):
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
        elif name == "pom.xml":
            for d in scan_maven_pom(path, root, root_props=root_pom_props):
                key = (d.package_name, d.manifest_path)
                if key not in seen:
                    seen.add(key)
                    deps.append(d)
        elif name in ("build.gradle", "build.gradle.kts"):
            for d in scan_gradle_build(path, root):
                key = (d.package_name, d.manifest_path)
                if key not in seen:
                    seen.add(key)
                    deps.append(d)

    resolve_cves_via_api(deps)
    return deps
