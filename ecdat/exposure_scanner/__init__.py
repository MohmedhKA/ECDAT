"""
ECDAT Exposure Scanner Package:
Parses Kubernetes manifests and Docker Compose configurations to determine
adversarial network exposure and Harvest-Now-Decrypt-Later (HNDL) interception probability P_HNDL.
"""

from pathlib import Path
from typing import Dict, Tuple, List, Optional
from ecdat.models import ExposureProfile
from ecdat.exposure_scanner.k8s_parser import scan_k8s_manifests
from ecdat.exposure_scanner.docker_parser import scan_docker_compose

def scan_deployment_exposure(target_dir: str) -> Dict[str, Tuple[ExposureProfile, float, str]]:
    """
    Scans target_dir for deployment manifests (k8s YAMLs, docker-compose.yml),
    returning mapping: service_or_component -> (ExposureProfile, P_HNDL, description).
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        return {}

    exposure_map: Dict[str, Tuple[ExposureProfile, float, str]] = {}

    # Scan Kubernetes manifests
    k8s_results = scan_k8s_manifests(target_path)
    exposure_map.update(k8s_results)

    # Scan Docker Compose manifests
    docker_results = scan_docker_compose(target_path)
    exposure_map.update(docker_results)

    return exposure_map
