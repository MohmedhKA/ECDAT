"""
ECDAT Kubernetes Manifest Exposure Parser:
Analyzes Service, Ingress, and Gateway YAML declarations to derive adversarial
interception probabilities (P_HNDL) using PyYAML with regex fallback.
"""

import re
from pathlib import Path
from typing import Dict, Tuple, List, Any
from ecdat.models import ExposureProfile

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

KIND_REGEX = re.compile(r"^kind:\s*([a-zA-Z0-9]+)", re.MULTILINE | re.IGNORECASE)
NAME_REGEX = re.compile(r"name:\s*([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)
TYPE_REGEX = re.compile(r"type:\s*([a-zA-Z0-9]+)", re.IGNORECASE)
BACKEND_SVC_REGEX = re.compile(r"service(?:Name)?:\s*(?:name:\s*)?([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)

def _parse_k8s_dict(doc: Dict[str, Any], fpath_name: str, results: Dict[str, Tuple[ExposureProfile, float, str]]) -> None:
    kind = str(doc.get("kind", "")).lower()
    metadata = doc.get("metadata") or {}
    svc_name = str(metadata.get("name", "")).lower()
    spec = doc.get("spec") or {}

    if kind == "service" and svc_name:
        svc_type = str(spec.get("type", "ClusterIP")).lower()
        if svc_type == "loadbalancer":
            results[svc_name] = (ExposureProfile.PUBLIC, 1.0, f"k8s_service:LoadBalancer:{fpath_name}")
        elif svc_type == "nodeport":
            results[svc_name] = (ExposureProfile.PUBLIC, 0.70, f"k8s_service:NodePort:{fpath_name}")
        else:
            results[svc_name] = (ExposureProfile.INTERNAL, 0.05, f"k8s_service:ClusterIP:{fpath_name}")

    elif kind in ("ingress", "gateway"):
        # Scan rules for backend services
        rules = spec.get("rules") or []
        for r in rules:
            http = (r.get("http") if isinstance(r, dict) else None) or {}
            paths = http.get("paths") or []
            for p in paths:
                backend = p.get("backend") or {}
                service = backend.get("service") or {}
                s_name = service.get("name") or backend.get("serviceName")
                if s_name:
                    results[str(s_name).lower()] = (ExposureProfile.PUBLIC, 1.0, f"k8s_ingress:{fpath_name}:{s_name}")

def scan_k8s_manifests(target_path: Path) -> Dict[str, Tuple[ExposureProfile, float, str]]:
    """
    Scans directory for Kubernetes YAML files and extracts service network exposure.
    """
    results: Dict[str, Tuple[ExposureProfile, float, str]] = {}

    for fpath in target_path.glob("**/*"):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in (".yaml", ".yml"):
            continue
        # Skip docker-compose files here
        if "compose" in fpath.name.lower():
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if HAS_YAML:
            try:
                for doc in yaml.safe_load_all(content):
                    if isinstance(doc, dict):
                        _parse_k8s_dict(doc, fpath.name, results)
                continue
            except Exception:
                pass  # Fallback to regex on parse error

        # Regex fallback
        documents = content.split("---")
        for doc in documents:
            kind_match = KIND_REGEX.search(doc)
            if not kind_match:
                continue
            kind = kind_match.group(1).lower()

            if kind == "service":
                name_match = NAME_REGEX.search(doc)
                svc_name = name_match.group(1).lower() if name_match else "unknown-service"

                type_match = TYPE_REGEX.search(doc)
                svc_type = type_match.group(1).lower() if type_match else "clusterip"

                if svc_type == "loadbalancer":
                    results[svc_name] = (ExposureProfile.PUBLIC, 1.0, f"k8s_service:LoadBalancer:{fpath.name}")
                elif svc_type == "nodeport":
                    results[svc_name] = (ExposureProfile.PUBLIC, 0.70, f"k8s_service:NodePort:{fpath.name}")
                else:
                    results[svc_name] = (ExposureProfile.INTERNAL, 0.05, f"k8s_service:ClusterIP:{fpath.name}")

            elif kind in ("ingress", "gateway"):
                for svc in BACKEND_SVC_REGEX.findall(doc):
                    svc_clean = svc.strip().lower()
                    results[svc_clean] = (ExposureProfile.PUBLIC, 1.0, f"k8s_ingress:{fpath.name}:{svc_clean}")

    return results
