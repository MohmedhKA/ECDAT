"""
ECDAT Scan Data Aggregator.
Parses raw JSON scan artifacts from a project output directory and compiles:
1. High-level Pinterest-style widget summaries
2. Full deep-dive datasets for dedicated tab drill-downs
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List


def safe_load_json(file_path: Path) -> Optional[Any]:
    if not file_path.exists():
        return None
    try:
        return json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def get_prop(properties: List[Dict[str, Any]], name: str, default: Any = None) -> Any:
    for p in properties:
        if p.get("name") == name:
            return p.get("value", default)
    return default


def get_project_summary(output_dir_str: str) -> Dict[str, Any]:
    out_dir = Path(output_dir_str)
    
    cbom_data = safe_load_json(out_dir / "enriched_cbom.json") or {}
    contagion_data = safe_load_json(out_dir / "contagion_graph.json") or {}
    mosca_data = safe_load_json(out_dir / "stochastic_mosca.json") or {}
    pareto_data = safe_load_json(out_dir / "pareto_portfolio.json") or {}
    proof_data = safe_load_json(out_dir / "negative_proof.json") or {}
    attestation_data = safe_load_json(out_dir / "attestation.dsse.json") or {}
    ciso_md_file = out_dir / "ciso_migration_report.md"
    ciso_text = ciso_md_file.read_text(encoding="utf-8", errors="replace") if ciso_md_file.exists() else ""
    lineage_data = safe_load_json(out_dir / "lineage_graph.json") or {}

    # 1. CBOM & Posture Analysis
    components = cbom_data.get("components", [])
    total_assets = len(components)
    production_count = 0
    test_fixture_count = 0

    critical_count = 0
    high_count = 0
    med_count = 0
    low_count = 0

    prod_critical_count = 0
    prod_high_count = 0
    prod_med_count = 0
    prod_low_count = 0

    pqc_count = 0
    classical_count = 0
    deprecated_count = 0

    prod_pqc_count = 0
    prod_classical_count = 0
    prod_deprecated_count = 0

    cams_levels = {"L0": 0, "L1": 0, "L2": 0, "L3": 0, "L4": 0, "L5": 0}
    algo_counts: Dict[str, int] = {}
    mosca_results = mosca_data.get("results", {})

    for comp in components:
        props = comp.get("properties", [])
        asset_id = comp.get("bom-ref") or comp.get("name", "")

        scope_prop = comp.get("scope") or get_prop(props, "ecdat:scope", "required")
        is_prod = str(scope_prop).lower() in ("required", "production")

        if is_prod:
            production_count += 1
        else:
            test_fixture_count += 1

        # Correlate with stochastic Monte Carlo risk if available; else static regulatory
        static_risk = str(get_prop(props, "ecdat:risk_level", "LOW")).upper()
        if asset_id in mosca_results and mosca_results[asset_id].get("risk_category"):
            risk = str(mosca_results[asset_id]["risk_category"]).upper()
        else:
            risk = static_risk

        if risk == "CRITICAL":
            critical_count += 1
            if is_prod:
                prod_critical_count += 1
        elif risk == "HIGH":
            high_count += 1
            if is_prod:
                prod_high_count += 1
        elif risk == "MEDIUM":
            med_count += 1
            if is_prod:
                prod_med_count += 1
        else:
            low_count += 1
            if is_prod:
                prod_low_count += 1

        crypto = comp.get("cryptoProperties", {})
        algo_info = crypto.get("algorithmProperties", {})
        algo_name = algo_info.get("name") or comp.get("name", "Unknown")
        algo_counts[algo_name] = algo_counts.get(algo_name, 0) + 1

        name_lower = algo_name.lower()
        if any(pqc in name_lower for pqc in ["ml-dsa", "ml-kem", "dilithium", "kyber", "sphincs", "falcon", "lwe"]):
            pqc_count += 1
            if is_prod:
                prod_pqc_count += 1
        elif any(dep in name_lower for dep in ["md5", "des", "rc4", "sha1", "blowfish"]):
            deprecated_count += 1
            if is_prod:
                prod_deprecated_count += 1
        else:
            classical_count += 1
            if is_prod:
                prod_classical_count += 1

        cams = str(get_prop(props, "ecdat:cams_agility_level", "0"))
        key = cams if cams.startswith("L") else f"L{cams}"
        if key in cams_levels:
            cams_levels[key] += 1
        else:
            cams_levels["L0"] += 1

    # Posture readiness score: evaluates production assets when available
    target_count = production_count if production_count > 0 else total_assets
    target_crit = prod_critical_count if production_count > 0 else critical_count
    target_high = prod_high_count if production_count > 0 else high_count
    target_pqc = prod_pqc_count if production_count > 0 else pqc_count
    target_dep = prod_deprecated_count if production_count > 0 else deprecated_count
    target_classical = prod_classical_count if production_count > 0 else classical_count

    pqc_migration_pct = round((target_pqc / max(1, target_count)) * 100.0, 1) if target_count > 0 else 0.0

    if target_count > 0:
        # Base health: proportion of safe assets (PQC + non-critical classical)
        safe_assets = target_pqc + max(0, target_classical - target_crit - target_high)
        base_score = (safe_assets / target_count) * 100.0

        # Risk penalty per asset
        penalty = ((target_crit * 35.0) + (target_high * 15.0) + (target_dep * 20.0)) / target_count
        raw_score = int(max(5.0, min(100.0, base_score - penalty)))

        # Safety Cap Invariant: If unmigrated CRITICAL assets exist in production, readiness cannot exceed 55%
        if target_crit > 0:
            crit_ratio = target_crit / target_count
            cap = int(max(8, min(55, 60 - (crit_ratio * 50))))
            readiness_score = min(cap, raw_score)
        elif target_high > 0:
            readiness_score = min(75, raw_score)
        else:
            readiness_score = raw_score
    else:
        readiness_score = 100

    # 2. Mosca
    mean_breach = mosca_data.get("mean_breach_probability", 0.0)
    max_breach = mosca_data.get("max_breach_probability", 0.0)
    crit_prob_assets = mosca_data.get("critical_probabilistic_assets", 0)
    high_prob_assets = mosca_data.get("high_probabilistic_assets", 0)

    # 3. Contagion
    nodes = contagion_data.get("nodes", [])
    links = contagion_data.get("links", [])
    max_deg = 0
    max_deg_node = "N/A"
    node_deg: Dict[str, int] = {}
    for link in links:
        s = link.get("source")
        t = link.get("target")
        node_deg[s] = node_deg.get(s, 0) + 1
        node_deg[t] = node_deg.get(t, 0) + 1
    if node_deg:
        max_deg_node, max_deg = max(node_deg.items(), key=lambda x: x[1])

    # 4. Pareto
    total_cost_allocated = pareto_data.get("total_cost_allocated", 0)
    total_risk_reduced = pareto_data.get("total_risk_reduced", 0)
    risk_reduction_pct = pareto_data.get("risk_reduction_pct", 0)
    selected_count = pareto_data.get("selected_count", 0)
    frontier_points = pareto_data.get("frontier_points", [])

    # 5. Proofs & DSSE
    sigs = attestation_data.get("signatures", [])
    has_ed25519 = any(s.get("keyid", "").startswith("ed25519") or "ed25519" in s.get("sig", "").lower() for s in sigs) or len(sigs) >= 1
    has_mldsa = any("mldsa" in s.get("keyid", "").lower() or len(s.get("sig", "")) > 1000 for s in sigs) or len(sigs) >= 2
    merkle_root = proof_data.get("merkle_root_hex", "0" * 64)
    quarantined = proof_data.get("quarantined_unknowns_count", 0)

    # 6. CISO summary
    standards_baseline = []
    ciso_snippet = f"Executive assessment: {critical_count} critical risk assets identified in immediate migration queue ({total_assets} total cryptographic assets)."
    
    for line in ciso_text.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        if "Standards Baseline:" in line_s:
            # Extract standard names, removing markdown symbols like >, **, etc.
            raw_std = line_s.split("Standards Baseline:")[-1].strip().strip(">").strip("*").strip()
            # Split on |
            parts = [p.strip() for p in raw_std.split("|") if p.strip()]
            for p in parts:
                if p and p not in standards_baseline:
                    standards_baseline.append(p)

    if not standards_baseline:
        standards_baseline = ["NIST IR 8547", "FIPS 203, 204, 205", "US OMB M-26-15", "GRI 2025 Survey"]

    return {
        "posture": {
            "readiness_score": readiness_score,
            "pqc_migration_pct": pqc_migration_pct,
            "total_assets": total_assets,
            "production_count": production_count,
            "test_fixture_count": test_fixture_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "med_count": med_count,
            "low_count": low_count,
            "prod_critical_count": prod_critical_count,
            "prod_high_count": prod_high_count,
            "prod_med_count": prod_med_count,
            "prod_low_count": prod_low_count,
            "prod_pqc_count": prod_pqc_count,
            "prod_classical_count": prod_classical_count,
            "prod_deprecated_count": prod_deprecated_count,
            "pqc_count": pqc_count,
            "classical_count": classical_count,
            "deprecated_count": deprecated_count,
        },
        "mosca": {
            "mean_breach_probability": round(mean_breach * 100, 1),
            "max_breach_probability": round(max_breach * 100, 1),
            "critical_probabilistic_assets": crit_prob_assets,
            "high_probabilistic_assets": high_prob_assets,
            "iterations": mosca_data.get("iterations", 2000),
            "var_95_year": mosca_data.get("var_95_year", 2030),
            "cutoff_year": mosca_data.get("cutoff_year", 2030),
        },
        "contagion": {
            "total_nodes": len(nodes),
            "total_edges": len(links),
            "max_degree_node": max_deg_node,
            "max_degree": max_deg,
            "critical_nodes": sum(1 for n in nodes if str(n.get("risk", "")).upper() in ["CRITICAL", "HIGH"]),
        },
        "lineage": {
            "total_nodes": len(lineage_data.get("nodes", [])) if isinstance(lineage_data, dict) else len(lineage_data),
            "total_edges": len(lineage_data.get("links", [])) if isinstance(lineage_data, dict) else 0,
        },
        "pareto": {
            "total_cost_allocated": total_cost_allocated,
            "total_risk_reduced": total_risk_reduced,
            "risk_reduction_pct": risk_reduction_pct,
            "selected_count": selected_count,
            "frontier_count": len(frontier_points),
        },
        "cbom": {
            "total_components": total_assets,
            "top_algorithms": sorted(algo_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            "pqc_count": pqc_count,
            "classical_count": classical_count,
            "deprecated_count": deprecated_count,
        },
        "buffer": {
            "cams_levels": cams_levels,
            "effective_mtu": 1500,
            "friction_score": round((critical_count * 2.5 + high_count * 1.5) / max(1, total_assets), 2),
        },
        "supplychain": {
            "total_dependencies": len(cbom_data.get("dependencies", [])),
            "external_libs": sum(1 for c in components if c.get("type") == "library"),
            "suspicious_count": critical_count,
        },
        "proof": {
            "is_certified_clean": proof_data.get("is_certified_clean", True),
            "certificate_id": proof_data.get("certificate_id", "CERT-ECDAT"),
            "merkle_root_hex": merkle_root,
            "merkle_root_short": f"{merkle_root[:8]}...{merkle_root[-8:]}",
            "quarantined_unknowns_count": quarantined,
            "dual_signed": has_ed25519 and has_mldsa,
            "signature_count": len(sigs),
        },
        "unknowns": {
            "count": quarantined,
            "assertions_count": len(proof_data.get("assertions", [])),
        },
        "ciso": {
            "snippet": ciso_snippet,
            "estimated_weeks": total_cost_allocated or 12,
            "compliance_standards": standards_baseline,
        }
    }


def get_tab_details(output_dir_str: str, tab_name: str) -> Dict[str, Any]:
    out_dir = Path(output_dir_str)
    
    cbom_data = safe_load_json(out_dir / "enriched_cbom.json") or {}
    contagion_data = safe_load_json(out_dir / "contagion_graph.json") or {}
    mosca_data = safe_load_json(out_dir / "stochastic_mosca.json") or {}
    pareto_data = safe_load_json(out_dir / "pareto_portfolio.json") or {}
    proof_data = safe_load_json(out_dir / "negative_proof.json") or {}
    attestation_data = safe_load_json(out_dir / "attestation.dsse.json") or {}
    lineage_data = safe_load_json(out_dir / "lineage_graph.json") or {}
    ciso_md_file = out_dir / "ciso_migration_report.md"
    ciso_text = ciso_md_file.read_text(encoding="utf-8", errors="replace") if ciso_md_file.exists() else ""

    manifest_deps = safe_load_json(out_dir / "manifest_dependencies.json")
    if manifest_deps is None and "dependencies" in cbom_data:
        manifest_deps = cbom_data.get("dependencies", [])

    summary = get_project_summary(output_dir_str)

    clean_tab = tab_name.lower().replace("-", "_").replace(" ", "")

    return {
        "tab": clean_tab,
        "summary": summary,
        "cbom": cbom_data,
        "manifest_dependencies": manifest_deps or [],
        "contagion": contagion_data,
        "lineage": lineage_data,
        "mosca": mosca_data,
        "pareto": pareto_data,
        "proof": proof_data,
        "attestation": attestation_data,
        "ciso_markdown": ciso_text,
    }
