"""
ECDAT Dynamic Dashboard Hydrator:
Decouples dashboard presentation from static compilation.
Reads live template.html and on-disk JSON artifacts (enriched_cbom.json,
lineage_graph.json, contagion_graph.json, pareto_portfolio.json, etc.)
to dynamically serve a living dashboard with graceful fallbacks for missing data.
"""

import json
import html
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

TEMPLATE_PATH = Path(__file__).parent / "template.html"
LOGO_B64_PATH = Path(__file__).parent / "assets" / "logo_b64.txt"


def load_project_data(project_dir: Path) -> Dict[str, Any]:
    """
    Extracts structured assessment data, graph data, and module statuses
    directly from individual JSON artifacts inside project_dir.
    """
    pdir = Path(project_dir).resolve()
    cbom_file = pdir / "enriched_cbom.json"
    
    cbom_data = {}
    if cbom_file.exists():
        try:
            cbom_data = json.loads(cbom_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            cbom_data = {}

    components = cbom_data.get("components", [])
    dependencies = cbom_data.get("dependencies", [])
    metadata = cbom_data.get("metadata", {})
    meta_props = {p.get("name", ""): p.get("value", "") for p in metadata.get("properties", [])}

    # Merkle root
    merkle_root = meta_props.get("ecdat:merkleRoot")
    if not merkle_root:
        root_file = pdir / "cbom_root.hex"
        if root_file.exists():
            try:
                merkle_root = root_file.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                merkle_root = "0x0"
    if not merkle_root:
        merkle_root = "0x0"

    # Assets Data extraction
    assets_data = []
    for c in components:
        props = {p.get("name", ""): p.get("value", "") for p in c.get("properties", [])}
        cprops = c.get("cryptoProperties", {})
        algprops = cprops.get("algorithmProperties", {})
        cdx_att = c.get("cdxAttestation", {}).get("discussion966", {})
        reach = cdx_att.get("reachabilityProof", {})

        call_loc = reach.get("callLocation") or props.get("ecdat:file_path") or "source:1"
        if ":" in call_loc:
            parts = call_loc.rsplit(":", 1)
            file_path = parts[0]
            line_number = int(parts[1]) if parts[1].isdigit() else 1
        else:
            file_path = call_loc
            line_number = 1

        confirmed_sinks = reach.get("confirmedSinks", [])
        evidence = confirmed_sinks[0] if confirmed_sinks else (props.get("ecdat:evidence") or "Direct Cryptographic Material")

        x_years = float(props.get("ecdat:x_years_effective", 0.0))
        y_max = float(props.get("ecdat:y_max_years", 0.0))
        risk = props.get("ecdat:risk_level") or c.get("raw_properties", {}).get("ecdat:risk_level", "LOW")

        pqc_rec = props.get("ecdat:recommended_pqc") or "ML-DSA-65 (FIPS 204)"
        target_std = "NIST FIPS 204" if ("DSA" in pqc_rec or "Signature" in pqc_rec) else ("NIST FIPS 203" if "KEM" in pqc_rec else "NIST Post-Quantum Standard")

        assets_data.append({
            "asset_id": c.get("bom-ref") or props.get("ecdat:asset_id") or "ASSET-UNK",
            "component": c.get("name") or "Component",
            "file_path": file_path,
            "line_number": line_number,
            "algorithm": algprops.get("name") or "Unknown",
            "key_size": algprops.get("keyLength") or 0,
            "primitive": algprops.get("primitive") or "UNKNOWN",
            "x_tier": props.get("ecdat:x_tier", "OPERATIONAL"),
            "x_years": x_years,
            "z_reg_year": int(props.get("ecdat:z_reg_year", 2030)),
            "y_max_years": y_max,
            "risk_level": risk,
            "hndl_vulnerable": x_years > 0,
            "recommended_hybrid": props.get("ecdat:recommended_hybrid", ""),
            "recommended_pqc": pqc_rec,
            "target_standard": target_std,
            "security_level": props.get("ecdat:security_level", "NIST Level 1 (AES-128 equivalent)"),
            "confidence": float(props.get("ecdat:confidence", 0.9)),
            "evidence": evidence,
            "guidance": props.get("ecdat:implementation_guidance", "Deploy NIST FIPS 203/204 standardized replacement."),
            "raw_properties": c.get("raw_properties", {}),
            "intent_class": props.get("ecdat:intent_class", "CONFIDENTIALITY_ENVELOPE"),
            "evidence_level": props.get("ecdat:evidence_level", "E1_STATIC_ARTIFACT"),
            "agility_level": int(props.get("ecdat:cams_agility_level", 0)),
            "exposure_profile": props.get("ecdat:exposure_profile", "PUBLIC"),
            "p_hndl": float(props.get("ecdat:p_hndl", 1.0)),
            "r_q_score": float(props.get("ecdat:r_q_score", 0.0)),
            "agility_factor": float(props.get("ecdat:agility_factor", 0.0)),
            "path_profile": props.get("ecdat:path_profile", "STANDARD"),
            "mtu_constrained": props.get("ecdat:mtu_constrained", "false").lower() == "true",
            "packet_segments": int(props.get("ecdat:packet_segments", 1)),
            "mtu_warning": props.get("ecdat:mtu_warning", ""),
        })

    # Lineage Graph Data & Availability Status
    lineage_file = pdir / "lineage_graph.json"
    lineage_data = {"nodes": [], "links": [], "stats": {"ingress": 0, "nexus": 0, "egress": 0, "edges": 0}}
    lineage_available = False
    if lineage_file.exists():
        try:
            parsed_lineage = json.loads(lineage_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(parsed_lineage, dict) and ("nodes" in parsed_lineage or "stats" in parsed_lineage):
                lineage_data = parsed_lineage
                lineage_available = True
        except Exception:
            pass

    # Contagion Graph Data & Availability Status
    contagion_file = pdir / "contagion_graph.json"
    contagion_data = {"nodes": [], "links": [], "superspreaders": []}
    contagion_available = False
    if contagion_file.exists():
        try:
            parsed_contagion = json.loads(contagion_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(parsed_contagion, dict) and "nodes" in parsed_contagion:
                contagion_data = parsed_contagion
                contagion_available = True
        except Exception:
            pass

    # Pareto Portfolio Data & Availability Status
    pareto_file = pdir / "pareto_portfolio.json"
    pareto_data = {}
    pareto_available = False
    if pareto_file.exists():
        try:
            parsed_pareto = json.loads(pareto_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(parsed_pareto, dict) and parsed_pareto:
                pareto_data = parsed_pareto
                pareto_available = True
        except Exception:
            pass

    # Stochastic Mosca Data & Availability Status
    stochastic_file = pdir / "stochastic_mosca.json"
    stochastic_data = {}
    stochastic_available = False
    if stochastic_file.exists():
        try:
            parsed_stoch = json.loads(stochastic_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(parsed_stoch, dict) and parsed_stoch:
                stochastic_data = parsed_stoch
                stochastic_available = True
        except Exception:
            pass

    # Negative Proof & Attestation
    negative_proof_file = pdir / "negative_proof.json"
    negative_proof_data = {}
    if negative_proof_file.exists():
        try:
            negative_proof_data = json.loads(negative_proof_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    attestation_file = pdir / "attestation.dsse.json"
    attestation_data = {}
    if attestation_file.exists():
        try:
            attestation_data = json.loads(attestation_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    pubkey_file = pdir / "attestation_pubkey.pem"
    pubkey_pem = pubkey_file.read_text(encoding="utf-8", errors="replace") if pubkey_file.exists() else ""

    ciso_file = pdir / "ciso_migration_report.md"
    ciso_md = ciso_file.read_text(encoding="utf-8", errors="replace") if ciso_file.exists() else ""

    path_mtu_file = pdir / "path_mtu.json"
    path_mtu_data = {}
    if path_mtu_file.exists():
        try:
            path_mtu_data = json.loads(path_mtu_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    # Buffer Hazards
    hazards_data = []
    hazards_file = pdir / "buffer_hazards.json"
    if hazards_file.exists():
        try:
            hazards_data = json.loads(hazards_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    # Polyglot Dependencies
    deps_data = dependencies

    # Unknowns Ledger
    unknowns_data = []
    unknowns_file = pdir / "unknowns_ledger.json"
    if unknowns_file.exists():
        try:
            unknowns_data = json.loads(unknowns_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    # Proof packages
    proofs_data = []
    proofs_dir = pdir / "proofs"
    if proofs_dir.is_dir():
        for pf in proofs_dir.glob("*.json"):
            try:
                proofs_data.append(json.loads(pf.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                pass

    # Project mtime
    target_stat = cbom_file if cbom_file.exists() else pdir
    mtime = target_stat.stat().st_mtime
    last_scanned = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))

    return {
        "project_name": pdir.name,
        "directory": str(pdir),
        "mtime": mtime,
        "last_scanned": last_scanned,
        "merkle_root": merkle_root,
        "enriched_cbom": cbom_data,
        "assets_data": assets_data,
        "deps_data": deps_data,
        "unknowns_data": unknowns_data,
        "hazards_data": hazards_data,
        "proofs_data": proofs_data,
        "lineage_data": lineage_data,
        "contagion_data": contagion_data,
        "pareto_data": pareto_data,
        "stochastic_data": stochastic_data,
        "negative_proof_data": negative_proof_data,
        "attestation_data": attestation_data,
        "pubkey_pem": pubkey_pem,
        "ciso_md": ciso_md,
        "path_mtu_data": path_mtu_data,
        "modules_status": {
            "cbom": len(assets_data) > 0,
            "lineage": lineage_available,
            "contagion": contagion_available,
            "pareto": pareto_available,
            "stochastic": stochastic_available,
            "attestation": bool(attestation_data),
            "ciso": bool(ciso_md)
        }
    }


def render_dynamic_project_dashboard(
    project_dir: Path,
    project_name: str,
    all_projects: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    Renders the live template.html dynamically populated with the latest
    data from project_dir. Supports instantaneous UI/visualizer hot-reloads.
    """
    pdir = Path(project_dir).resolve()
    cbom_file = pdir / "enriched_cbom.json"
    report_file = pdir / "report.html"

    # If enriched_cbom.json doesn't exist but legacy report.html does, fallback to reading report.html
    if not cbom_file.exists() and report_file.exists():
        return report_file.read_text(encoding="utf-8", errors="replace")

    # Load fresh dataset from disk
    pdata = load_project_data(pdir)
    assets_data = pdata["assets_data"]

    # Calculate metrics
    total_assets = len(assets_data)
    critical_count = sum(1 for a in assets_data if a["risk_level"] == "CRITICAL")
    high_count = sum(1 for a in assets_data if a["risk_level"] == "HIGH")
    medium_count = sum(1 for a in assets_data if a["risk_level"] == "MEDIUM")
    low_count = sum(1 for a in assets_data if a["risk_level"] == "LOW")
    manual_review_count = sum(1 for a in assets_data if a["risk_level"] == "MANUAL_REVIEW_REQUIRED")

    superspreader_count = 0
    if pdata["contagion_data"] and "superspreaders" in pdata["contagion_data"]:
        superspreader_count = len(pdata["contagion_data"]["superspreaders"])

    lineage_stats = pdata["lineage_data"].get("stats", {}) if pdata["lineage_data"] else {}
    lineage_ingress_count = lineage_stats.get("ingress", 0)
    lineage_nexus_count = lineage_stats.get("nexus", 0)
    lineage_egress_count = lineage_stats.get("egress", 0)

    hazards_count = len(pdata["hazards_data"])
    deps_count = len(pdata["deps_data"])
    unknowns_count = len(pdata["unknowns_data"])

    penalty = (critical_count * 12) + (high_count * 6) + (hazards_count * 8)
    readiness_score = max(5, min(100, 100 - penalty))

    merkle_root_hex = pdata["merkle_root"]
    merkle_short = f"{merkle_root_hex[:8]}...{merkle_root_hex[-8:]}" if len(merkle_root_hex) >= 16 else merkle_root_hex

    # Read live template directly from disk
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Dashboard template not found at {TEMPLATE_PATH}")
    template_str = TEMPLATE_PATH.read_text(encoding="utf-8")

    # Read logo base64
    logo_b64 = LOGO_B64_PATH.read_text(encoding="utf-8").strip() if LOGO_B64_PATH.exists() else ""

    # JSON serializations
    assets_json_str = json.dumps(assets_data)
    graph_json_str = json.dumps(pdata["contagion_data"])
    lineage_json_str = json.dumps(pdata["lineage_data"])
    hazards_json_str = json.dumps(pdata["hazards_data"])
    proofs_json_str = json.dumps(pdata["proofs_data"])
    deps_json_str = json.dumps(pdata["deps_data"])
    unknowns_json_str = json.dumps(pdata["unknowns_data"])
    attestation_json_str = json.dumps(pdata["attestation_data"])
    pubkey_pem_clean = pdata["pubkey_pem"].replace("`", "\\`")
    pareto_json_str = json.dumps(pdata["pareto_data"])
    stochastic_json_str = json.dumps(pdata["stochastic_data"])
    negative_proof_json_str = json.dumps(pdata["negative_proof_data"])
    path_mtu_json_str = json.dumps(pdata["path_mtu_data"])
    ciso_md_escaped = json.dumps(pdata["ciso_md"])

    # Module status payload for client-side fallback rendering
    module_status_json = json.dumps(pdata["modules_status"])

    rendered = (
        template_str
        .replace("__ASSETS_JSON__", assets_json_str)
        .replace("__GRAPH_JSON__", graph_json_str)
        .replace("__LINEAGE_JSON__", lineage_json_str)
        .replace("__HAZARDS_JSON__", hazards_json_str)
        .replace("__PROOFS_JSON__", proofs_json_str)
        .replace("__DEPS_JSON__", deps_json_str)
        .replace("__UNKNOWNS_JSON__", unknowns_json_str)
        .replace("__ATTESTATION_JSON__", attestation_json_str)
        .replace("__PUBKEY_PEM__", pubkey_pem_clean)
        .replace("__PARETO_JSON__", pareto_json_str)
        .replace("__STOCHASTIC_JSON__", stochastic_json_str)
        .replace("__NEGATIVE_PROOF_JSON__", negative_proof_json_str)
        .replace("__PATH_MTU_JSON__", path_mtu_json_str)
        .replace("__MERKLE_ROOT__", merkle_root_hex)
        .replace("__MERKLE_ROOT_SHORT__", merkle_short)
        .replace("__PROJECT_NAME__", html.escape(project_name))
        .replace("__TOTAL_ASSETS__", str(total_assets))
        .replace("__CRITICAL_COUNT__", str(critical_count))
        .replace("__HIGH_COUNT__", str(high_count))
        .replace("__MEDIUM_COUNT__", str(medium_count))
        .replace("__LOW_COUNT__", str(low_count))
        .replace("__MANUAL_REVIEW_COUNT__", str(manual_review_count))
        .replace("__SUPERSPREADER_COUNT__", str(superspreader_count))
        .replace("__LINEAGE_INGRESS_COUNT__", str(lineage_ingress_count))
        .replace("__LINEAGE_NEXUS_COUNT__", str(lineage_nexus_count))
        .replace("__LINEAGE_EGRESS_COUNT__", str(lineage_egress_count))
        .replace("__HAZARDS_COUNT__", str(hazards_count))
        .replace("__DEPS_COUNT__", str(deps_count))
        .replace("__UNKNOWNS_COUNT__", str(unknowns_count))
        .replace("__READINESS_SCORE__", str(readiness_score))
        .replace("__CISO_MD__", ciso_md_escaped)
        .replace("__ECDAT_LOGO_B64__", logo_b64)
    )

    # Inject module status and active project context into JS environment
    status_injection = f"""
    <script>
        window.ECDAT_MODULE_STATUS = {module_status_json};
        window.ECDAT_ACTIVE_PROJECT = "{html.escape(project_name)}";
        window.ECDAT_LAST_SCANNED = "{pdata['last_scanned']}";
        window.ECDAT_MTIME = {pdata['mtime']};
    </script>
    """
    if "</head>" in rendered:
        rendered = rendered.replace("</head>", status_injection + "\n</head>", 1)

    return rendered
