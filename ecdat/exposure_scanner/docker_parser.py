"""
ECDAT Docker Compose Exposure Parser:
Analyzes docker-compose.yml port mappings and network configurations
to derive container-level P_HNDL interception probabilities using PyYAML with regex fallback.
"""

import re
from pathlib import Path
from typing import Dict, Tuple, Any
from ecdat.models import ExposureProfile

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

SERVICE_BLOCK_REGEX = re.compile(r"^\s{2}([a-zA-Z0-9_\-]+):\s*$", re.MULTILINE)

def _parse_docker_compose_dict(data: Dict[str, Any], fpath_name: str, results: Dict[str, Tuple[ExposureProfile, float, str]]) -> None:
    services = data.get("services") or {}
    for svc_name, svc_conf in services.items():
        if not isinstance(svc_conf, dict):
            continue
        svc_clean = str(svc_name).lower()
        ports = svc_conf.get("ports") or []

        if ports:
            # Check if all ports are localhost-bound
            is_all_local = True
            for p in ports:
                p_str = str(p)
                if not ("127.0.0.1:" in p_str or "localhost:" in p_str):
                    is_all_local = False
                    break
            if is_all_local:
                results[svc_clean] = (ExposureProfile.INTERNAL, 0.20, f"docker_compose:localhost_port:{fpath_name}:{svc_clean}")
            else:
                results[svc_clean] = (ExposureProfile.PUBLIC, 1.0, f"docker_compose:public_port:{fpath_name}:{svc_clean}")
        else:
            results[svc_clean] = (ExposureProfile.INTERNAL, 0.01, f"docker_compose:internal_network:{fpath_name}:{svc_clean}")

def scan_docker_compose(target_path: Path) -> Dict[str, Tuple[ExposureProfile, float, str]]:
    """
    Scans for compose YAML files and parses port bindings to determine exposure.
    """
    results: Dict[str, Tuple[ExposureProfile, float, str]] = {}

    for fpath in target_path.glob("**/*"):
        if not fpath.is_file():
            continue
        fname_lower = fpath.name.lower()
        if not (fname_lower.startswith("docker-compose") or fname_lower.startswith("compose")) or not fname_lower.endswith((".yml", ".yaml")):
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if HAS_YAML:
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    _parse_docker_compose_dict(data, fpath.name, results)
                    continue
            except Exception:
                pass

        # Regex fallback
        lines = content.splitlines()
        current_service: str = ""
        service_lines: Dict[str, list] = {}

        in_services = False
        for line in lines:
            stripped = line.strip()
            if stripped == "services:":
                in_services = True
                continue
            if not in_services:
                continue

            if line and not line.startswith(" ") and not line.startswith("\t"):
                in_services = False
                current_service = ""
                continue

            svc_match = SERVICE_BLOCK_REGEX.match(line)
            if svc_match:
                current_service = svc_match.group(1).lower()
                service_lines[current_service] = []
                continue

            if current_service:
                service_lines[current_service].append(line)

        for svc_name, s_lines in service_lines.items():
            svc_text = "\n".join(s_lines)
            if "ports:" in svc_text:
                if "127.0.0.1:" in svc_text or "localhost:" in svc_text:
                    results[svc_name] = (ExposureProfile.INTERNAL, 0.20, f"docker_compose:localhost_port:{fpath.name}:{svc_name}")
                else:
                    results[svc_name] = (ExposureProfile.PUBLIC, 1.0, f"docker_compose:public_port:{fpath.name}:{svc_name}")
            else:
                results[svc_name] = (ExposureProfile.INTERNAL, 0.01, f"docker_compose:internal_network:{fpath.name}:{svc_name}")

    return results
