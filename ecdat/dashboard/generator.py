"""
ECDAT Visual Interactive Report & Dashboard Generator:
Generates an executive-grade, publication-ready HTML5/JS report ('report.html') featuring:
1. Academic & defense-grade mathematical typography with KaTeX.
2. D3.js force-directed bubble graph with R_0 contagion blast radius.
3. Pareto Migration Portfolio Optimizer with interactive sprint budget slider and efficient frontier.
4. Stochastic Monte Carlo Mosca simulation results (P(X+Y > Z)).
5. Transport Path MTU & PQC packet fragmentation flight visualizer.
6. Comprehensive CBOM inventory with DSIS intent, CAMS agility levels, and E0-E5 evidence states.
7. Buffer agility hazard inspector with side-by-side remediation diffs.
8. WebCrypto SHA-256 Merkle proof verification sandbox & SLSA signed attestation.
9. Standalone Negative Proof Certificate verification.
10. Native client-side exports for CycloneDX 1.6 CBOM, DSSE attestation, and CISO Markdown.
"""

import os
import json
import html
from typing import List, Dict, Tuple, Any, Optional
from pathlib import Path

from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    PathMTUResult,
    RouteProfile,
    ParetoPortfolioResult,
    NegativeProofCertificate,
)
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.agility.buffer_audit import BufferHazard
from ecdat.contagion.engine import ContagionGraphResult
from ecdat.optimizer.pareto import optimize_pareto_portfolio
from ecdat.mosca.stochastic import simulate_estate_stochastic_mosca
from ecdat.attestation.negative_proof import generate_negative_proof_certificate

TEMPLATE_PATH = Path(__file__).parent / "template.html"

def _load_html_template() -> str:
    """Loads the standalone HTML5 dashboard template from disk."""
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Dashboard template not found at {TEMPLATE_PATH}")
    return TEMPLATE_PATH.read_text(encoding="utf-8")

def generate_html_dashboard(
    assessments: List[Tuple[CryptoAsset, MoscaScore, MigrationRecommendation]],
    buffer_hazards: List[BufferHazard],
    merkle_root_hex: str,
    contagion_result: ContagionGraphResult,
    proof_packages: List[Dict[str, Any]],
    project_name: str = "Enterprise Cryptographic Estate",
    ciso_report_md: Optional[str] = None,
    manifest_dependencies: Optional[List[Any]] = None,
    unknowns_ledger: Optional[List[Any]] = None,
    path_mtu: Optional[PathMTUResult] = None,
    attestation_envelope: Optional[Dict[str, Any]] = None,
    pubkey_pem: Optional[str] = None,
    pareto_result: Optional[ParetoPortfolioResult] = None,
    stochastic_summary: Optional[Dict[str, Any]] = None,
    negative_proof: Optional[NegativeProofCertificate] = None,
    budget_dev_weeks: float = 10.0,
) -> str:
    """
    Generates a single, self-contained, publication-grade HTML5 report ('report.html').
    Adheres to StyleSeed UX flow (progressive disclosure, Miller's law, 5 top-level audit pillars).
    """
    template_str = _load_html_template()

    total_assets = len(assessments)
    critical_count = sum(1 for _, s, _ in assessments if s.risk_level == "CRITICAL")
    high_count = sum(1 for _, s, _ in assessments if s.risk_level == "HIGH")
    medium_count = sum(1 for _, s, _ in assessments if s.risk_level == "MEDIUM")
    low_count = sum(1 for _, s, _ in assessments if s.risk_level == "LOW")
    superspreader_count = len(contagion_result.superspreaders)

    penalty = (critical_count * 12) + (high_count * 6) + (len(buffer_hazards) * 8)
    readiness_score = max(5, min(100, 100 - penalty))

    # Auto-compute Pareto portfolio if not provided
    if pareto_result is None:
        pareto_result = optimize_pareto_portfolio(
            assessments=assessments,
            contagion_result=contagion_result,
            budget_dev_weeks=budget_dev_weeks,
        )

    # Auto-compute Stochastic Monte Carlo summary if not provided
    if stochastic_summary is None:
        stochastic_summary = simulate_estate_stochastic_mosca(
            assessments=assessments,
            iterations=2000,
        )

    # Auto-compute Negative Proof Certificate if not provided
    if negative_proof is None:
        negative_proof = generate_negative_proof_certificate(
            assessments=assessments,
            unknowns_ledger=unknowns_ledger or [],
            target_path=project_name,
            merkle_root_hex=merkle_root_hex,
            project_name=project_name,
        )

    assets_data = []
    for asset, score, rec in assessments:
        evidence = (
            asset.raw_properties.get("sink")
            or asset.raw_properties.get("evidence")
            or asset.raw_properties.get("subject")
            or "Direct Cryptographic Material"
        )
        assets_data.append({
            "asset_id": asset.asset_id,
            "component": asset.component_name,
            "file_path": asset.file_path,
            "line_number": asset.line_number,
            "algorithm": asset.algorithm,
            "key_size": asset.key_size,
            "primitive": asset.primitive_type.value,
            "x_tier": asset.x_tier.value,
            "x_years": score.x_years_effective,
            "z_reg_year": score.z_regulatory_year,
            "y_max_years": score.y_max_years,
            "risk_level": score.risk_level,
            "hndl_vulnerable": score.x_years_effective > 0,
            "recommended_hybrid": rec.recommended_hybrid,
            "recommended_pqc": rec.recommended_pqc_standalone,
            "target_standard": rec.target_standard,
            "security_level": rec.security_level,
            "confidence": asset.x_confidence,
            "evidence": evidence,
            "guidance": rec.implementation_guidance,
            "raw_properties": asset.raw_properties,
            "intent_class": asset.intent_class.value if hasattr(asset.intent_class, "value") else str(asset.intent_class),
            "evidence_level": asset.evidence_level.value if hasattr(asset.evidence_level, "value") else str(asset.evidence_level),
            "agility_level": int(asset.agility_level),
            "exposure_profile": asset.exposure_profile.value if hasattr(asset.exposure_profile, "value") else str(asset.exposure_profile),
            "p_hndl": getattr(score, "p_hndl", 1.0),
            "r_q_score": getattr(score, "r_q_score", 0.0),
            "agility_factor": getattr(score, "agility_factor", 0.0),
            "path_profile": rec.path_profile.value if rec.path_profile else (path_mtu.route_profile.value if path_mtu else "STANDARD"),
            "mtu_constrained": rec.mtu_constrained,
            "packet_segments": rec.packet_segments,
            "mtu_warning": rec.mtu_warning,
        })

    hazards_data = []
    for h in buffer_hazards:
        hazards_data.append({
            "variable": h.variable_name,
            "file": Path(h.file_path).name if hasattr(h, "file_path") and h.file_path else "source",
            "file_path": getattr(h, "file_path", "source"),
            "line": h.line_number,
            "allocated": h.allocated_bytes,
            "required": h.required_bytes_pqc,
            "severity": h.severity,
            "description": h.message,
        })

    deps_data = []
    if manifest_dependencies:
        for d in manifest_dependencies:
            if hasattr(d, "model_dump"):
                deps_data.append(d.model_dump())
            elif hasattr(d, "dict"):
                deps_data.append(d.dict())
            elif isinstance(d, dict):
                deps_data.append(d)

    unknowns_data = []
    if unknowns_ledger:
        for u in unknowns_ledger:
            if hasattr(u, "model_dump"):
                unknowns_data.append(u.model_dump())
            elif hasattr(u, "dict"):
                unknowns_data.append(u.dict())
            elif isinstance(u, dict):
                unknowns_data.append(u)

    assets_json_str = json.dumps(assets_data)
    hazards_json_str = json.dumps(hazards_data)
    graph_json_str = json.dumps(contagion_result.graph_json)
    proof_packages_json_str = json.dumps(proof_packages)
    deps_json_str = json.dumps(deps_data)
    unknowns_json_str = json.dumps(unknowns_data)
    ciso_md_escaped = json.dumps(ciso_report_md or "")
    merkle_short = f"{merkle_root_hex[:8]}...{merkle_root_hex[-8:]}" if len(merkle_root_hex) >= 16 else merkle_root_hex

    attestation_json_str = json.dumps(attestation_envelope or {})
    pubkey_pem_clean = (pubkey_pem or "").replace("`", "\\`")

    pareto_json_str = json.dumps(pareto_result.model_dump() if hasattr(pareto_result, "model_dump") else pareto_result.dict())
    stochastic_json_str = json.dumps(stochastic_summary)
    negative_proof_json_str = json.dumps(negative_proof.model_dump() if hasattr(negative_proof, "model_dump") else negative_proof.dict())
    path_mtu_json_str = json.dumps(path_mtu.model_dump() if path_mtu and hasattr(path_mtu, "model_dump") else (path_mtu.dict() if path_mtu else {}))

    report_html = (
        template_str
        .replace("__ASSETS_JSON__", assets_json_str)
        .replace("__GRAPH_JSON__", graph_json_str)
        .replace("__HAZARDS_JSON__", hazards_json_str)
        .replace("__PROOFS_JSON__", proof_packages_json_str)
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
        .replace("__SUPERSPREADER_COUNT__", str(superspreader_count))
        .replace("__HAZARDS_COUNT__", str(len(buffer_hazards)))
        .replace("__DEPS_COUNT__", str(len(deps_data)))
        .replace("__UNKNOWNS_COUNT__", str(len(unknowns_data)))
        .replace("__READINESS_SCORE__", str(readiness_score))
        .replace("__CISO_MD__", ciso_md_escaped)
    )

    return report_html

generate_html_report = generate_html_dashboard
