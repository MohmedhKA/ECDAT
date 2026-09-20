"""
ECDAT Fleet Registry & Metadata Manager:
Manages persistent project target locations, output directories,
and fleet inventory across runs without regular expressions.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


DEFAULT_BENCHMARK_TARGETS = {
    "evoting_backend": {
        "target_dir": "/home/mohmedh/personal/E-Voting-V2/backend",
        "relative_target": "../E-Voting-V2/backend",
        "description": "E-Voting-V2 High-Throughput Node.js & Rust Cryptographic Backend",
    },
    "cryptoapi_bench": {
        "target_dir": "testbeds/benchmarks/CryptoAPI-Bench",
        "description": "CryptoAPI-Bench Java Cryptographic Benchmark Suite",
    },
    "apache_cryptoapi_bench": {
        "target_dir": "testbeds/benchmarks/ApacheCryptoAPI-Bench",
        "description": "ApacheCryptoAPI-Bench Apache Software Foundation Benchmark",
    },
    "cambench": {
        "target_dir": "testbeds/benchmarks/CamBench",
        "description": "CamBench Cryptographic API Misuse Benchmark",
    },
    "cryben": {
        "target_dir": "testbeds/benchmarks/Cryben",
        "description": "Cryben Cryptographic Benchmark Corpus",
    },
    "masc": {
        "target_dir": "testbeds/benchmarks/MASC",
        "description": "MASC Mutation-based Android Security and Crypto Benchmark",
    },
}


def get_registry_file(reports_dir: Optional[Path] = None, base_dir: Optional[Path] = None) -> Path:
    """
    Locates or determines the primary persistent fleet_registry.json path.
    """
    if reports_dir and Path(reports_dir).exists():
        p = Path(reports_dir) / "fleet_registry.json"
        return p

    app_base = Path(base_dir or '/home/mohmedh/personal/ECDAT').resolve()

    candidate_scans = app_base / "scans" / "fleet_registry.json"
    if candidate_scans.exists():
        return candidate_scans

    candidate_bench = app_base / "testbeds" / "benchmarks" / "fleet_registry.json"
    if candidate_bench.exists():
        return candidate_bench

    home_reg = Path.home() / ".ecdat" / "fleet_registry.json"
    if home_reg.exists():
        return home_reg

    bench_dir = app_base / "testbeds" / "benchmarks"
    if bench_dir.exists():
        return bench_dir / "fleet_registry.json"
    
    scans_dir = app_base / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    return scans_dir / "fleet_registry.json"


def load_fleet_registry(reports_dir: Optional[Path] = None, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads persistent fleet projects registry. If not found or incomplete,
    seeds with known benchmarks and auto-discovered scanned reports.
    """
    reg_file = get_registry_file(reports_dir=reports_dir, base_dir=base_dir)
    registry: Dict[str, Any] = {"version": "1.0.0", "updated_at": "", "projects": {}}

    if reg_file.exists():
        try:
            loaded = json.loads(reg_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded, dict) and "projects" in loaded:
                registry = loaded
        except Exception:
            pass

    projects = registry.get("projects", {})
    app_base = Path(base_dir or '/home/mohmedh/personal/ECDAT').resolve()

    # Seed default benchmark targets if not already registered
    for name, info in DEFAULT_BENCHMARK_TARGETS.items():
        if name not in projects:
            candidate_target = info.get("target_dir", "")
            target_p = Path(candidate_target)
            if not target_p.is_absolute():
                target_p = (app_base / candidate_target).resolve()

            if not target_p.exists() and "relative_target" in info:
                alt_p = (app_base / info["relative_target"]).resolve()
                if alt_p.exists():
                    target_p = alt_p

            output_p = app_base / "testbeds" / "benchmarks" / ("reports" if name != "evoting_backend" else "") / name
            projects[name] = {
                "name": name,
                "target_dir": str(target_p),
                "output_dir": str(output_p.resolve()),
                "target_type": "CODEBASE",
                "description": info.get("description", ""),
                "last_scanned": "Unknown",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }

    registry["projects"] = projects
    registry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    save_fleet_registry(registry, reports_dir=reports_dir, base_dir=base_dir)
    return registry


def save_fleet_registry(registry: Dict[str, Any], reports_dir: Optional[Path] = None, base_dir: Optional[Path] = None) -> None:
    """
    Persists the fleet registry JSON to disk atomically.
    """
    reg_file = get_registry_file(reports_dir=reports_dir, base_dir=base_dir)
    reg_file.parent.mkdir(parents=True, exist_ok=True)
    registry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    tmp_file = reg_file.with_suffix(".tmp")
    try:
        tmp_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        tmp_file.replace(reg_file)
    except Exception:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except Exception:
                pass


def get_fleet_target(project_name: str, reports_dir: Optional[Path] = None, base_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves the registered target metadata for a specific project.
    """
    reg = load_fleet_registry(reports_dir=reports_dir, base_dir=base_dir)
    projects = reg.get("projects", {})
    if project_name in projects:
        return projects[project_name]

    for p_name, data in projects.items():
        if p_name.lower() == project_name.lower():
            return data
    return None


def register_fleet_target(
    name: str,
    target_dir: str,
    output_dir: Optional[str] = None,
    description: Optional[str] = None,
    asset_count: Optional[int] = None,
    reports_dir: Optional[Path] = None,
    base_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Registers or updates a fleet target with its exact codebase location and report output.
    Also writes fleet_metadata.json into output_dir.
    """
    reg = load_fleet_registry(reports_dir=reports_dir, base_dir=base_dir)
    projects = reg.get("projects", {})

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    existing = projects.get(name, {})

    target_resolved = str(Path(target_dir).resolve()) if Path(target_dir).exists() else str(target_dir)
    out_resolved = str(Path(output_dir).resolve()) if output_dir else existing.get("output_dir", "")

    proj_entry = {
        "name": name,
        "target_dir": target_resolved,
        "output_dir": out_resolved,
        "target_type": "LIVE_TLS" if (target_dir.startswith("http://") or target_dir.startswith("https://") or ":" in target_dir) else "CODEBASE",
        "description": description or existing.get("description") or f"Project {name}",
        "asset_count": asset_count if asset_count is not None else existing.get("asset_count", 0),
        "last_scanned": now_iso,
        "created_at": existing.get("created_at", now_iso),
    }

    projects[name] = proj_entry
    reg["projects"] = projects
    save_fleet_registry(reg, reports_dir=reports_dir, base_dir=base_dir)

    if out_resolved and Path(out_resolved).exists():
        try:
            meta_path = Path(out_resolved) / "fleet_metadata.json"
            meta_path.write_text(json.dumps(proj_entry, indent=2), encoding="utf-8")
        except Exception:
            pass

    return proj_entry
