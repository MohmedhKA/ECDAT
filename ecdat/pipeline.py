"""
ECDAT Unified Discovery & Analysis Pipeline:
Orchestrates AST taint analysis, 4-tier X-inference, Mosca Y_max scoring,
PQC hybrid recommendations, buffer agility hazard audits, and Merkle tree root commitments.
"""

import os
import sys
import json
import argparse
import click
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional

from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    PrimitiveType,
    XTier,
    UnknownEntry,
    IntentClass,
    EvidenceLevel,
    ExposureProfile,
    AgilityLevel,
    RouteProfile,
    PathMTUResult,
)
from ecdat.constants import CURRENT_YEAR
from ecdat.x_inference.ast_tracer import analyze_python_file, XInferenceResult
from ecdat.agility.buffer_audit import audit_python_buffer_file, BufferHazard
from ecdat.agility.recommender import recommend_pqc_migration, MigrationRecommendation
from ecdat.mosca.engine import compute_mosca_score
from ecdat.merkle.tree import MerkleTree, generate_asset_proof_package
from ecdat.report import generate_ciso_report
from ecdat.contagion.engine import analyze_contagion
from ecdat.lineage.engine import analyze_crypto_lineage
from ecdat.dashboard.generator import generate_html_dashboard, generate_html_report
from ecdat.scanners.theia_bridge import run_theia_scan
from ecdat.scanners.manifest_scanner import discover_manifest_crypto_dependencies
from ecdat.scanners.source_scanner import discover_polyglot_crypto_assets
from ecdat.scanners.config_scanner import scan_server_configs
from ecdat.scanners.filters import should_scan_file
from ecdat.schema_extractor import extract_schemas_lifespan
from ecdat.exposure_scanner import scan_deployment_exposure
from ecdat.network.mtu_prober import probe_network_mtu
from ecdat.attestation.envelope import build_intoto_statement, create_signed_dsse_envelope
from ecdat.attestation.cyclonedx_966 import enrich_cyclonedx_component_966
from ecdat.optimizer.pareto import optimize_pareto_portfolio
from ecdat.mosca.stochastic import simulate_estate_stochastic_mosca
from ecdat.attestation.negative_proof import generate_negative_proof_certificate
from ecdat.report_sarif import export_sarif_file, generate_sarif_dict
from ecdat.gate import evaluate_quality_gate, GateResult


def _infer_primitive_and_alg(var_name: str, sink_call: Optional[str]) -> Tuple[PrimitiveType, str, int]:
    """Infers appropriate algorithm and primitive type from variable/call semantics."""
    v_lower = var_name.lower()
    s_lower = (sink_call or "").lower()

    if any(k in v_lower for k in ["sign", "sig", "cert"]):
        return PrimitiveType.SIGNATURE, "ECDSA-P256", 256
    elif any(k in v_lower for k in ["key", "session", "handshake"]):
        return PrimitiveType.KEY_EXCHANGE, "ECDH-P256", 256
    elif any(k in v_lower for k in ["backup", "archive"]):
        return PrimitiveType.KEY_EXCHANGE, "RSA-2048", 2048
    elif any(k in v_lower for k in ["pan", "card", "vault", "encrypt"]):
        return PrimitiveType.ENCRYPTION, "AES-128-CBC", 128
    else:
        return PrimitiveType.ENCRYPTION, "AES-256-GCM", 256

def _apply_schema_lifespan(asset: CryptoAsset, schema_lifespans: Dict[str, Tuple[XTier, float, str]]) -> None:
    """Correlates asset with autonomous SQL/ORM schema retention inferences."""
    if not schema_lifespans:
        return
    c_lower = asset.component_name.lower()
    f_lower = asset.file_path.lower()
    for entity, (tier, years, prov) in schema_lifespans.items():
        e_lower = entity.lower()
        if e_lower in c_lower or e_lower in f_lower:
            asset.x_tier = tier
            asset.x_auto_source = prov
            break

def _apply_deployment_exposure(asset: CryptoAsset, deployment_exposures: Dict[str, Tuple[ExposureProfile, float, str]]) -> None:
    """Correlates asset with Kubernetes / Docker Compose deployment exposure profiles."""
    if not deployment_exposures:
        return
    c_lower = asset.component_name.lower()
    f_lower = asset.file_path.lower()
    for svc, (prof, p_hndl, desc) in deployment_exposures.items():
        s_lower = svc.lower()
        if s_lower in c_lower or s_lower in f_lower or s_lower.replace("-", "") in c_lower.replace("-", ""):
            asset.exposure_profile = prof
            asset.p_hndl = p_hndl
            return
    # If all declared deployment services share a uniform profile, propagate to whole estate
    profiles = {p for p, _, _ in deployment_exposures.values()}
    if len(profiles) == 1:
        prof = list(profiles)[0]
        asset.exposure_profile = prof
        asset.p_hndl = list(deployment_exposures.values())[0][1]

def run_ecdat_scan(
    target_dir: str,
    output_dir: Optional[str] = None,
    salt: str = "ECDAT_SALT_2026",
    enable_theia: bool = True,
    probe_host: Optional[str] = None,
    mtu_profile: Optional[str] = None,
    override_mtu: Optional[int] = None,
    signing_key: Optional[Any] = None,
    budget_dev_weeks: float = 10.0,
    stochastic_runs: int = 5000,
    generate_negative_proof: bool = True,
    subdirs: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Executes an end-to-end cryptographic discovery, temporal risk analysis,
    and privacy-preserving attestation pipeline across a target directory.
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target directory '{target_path}' does not exist.")

    parsed_subdirs: Optional[List[str]] = None
    if subdirs:
        if isinstance(subdirs, str):
            parsed_subdirs = [s.strip() for s in subdirs.split(",") if s.strip()]
        elif isinstance(subdirs, (list, tuple, set)):
            parsed_subdirs = [str(s).strip() for s in subdirs if str(s).strip()]

    if output_dir:
        out_path = Path(output_dir).resolve()
    else:
        out_path = target_path / "ecdat_output"

    out_path.mkdir(parents=True, exist_ok=True)
    proofs_dir = out_path / "proofs"
    proofs_dir.mkdir(parents=True, exist_ok=True)
    for old_proof in proofs_dir.glob("proof_*.json"):
        try:
            old_proof.unlink()
        except OSError:
            pass

    # 0. Active Path MTU Prober & Route Profile (Pillar 5)
    effective_route_profile = None
    if mtu_profile:
        try:
            effective_route_profile = RouteProfile(mtu_profile.upper())
        except ValueError:
            effective_route_profile = None

    path_mtu = probe_network_mtu(
        target_host=probe_host,
        override_profile=effective_route_profile,
        override_mtu=override_mtu,
    )

    # 1. Discover all first-party source files (Python, JS/TS, Go, Rust, Java)
    EXCLUDED_DIRS = {
        "venv", ".venv", "env", "node_modules", "site-packages",
        "__pycache__", ".git", "dist", "build", "target", ".cache",
        ".agents", ".gemini", ".antigravity", ".codex", ".superpowers", "agents"
    }
    SOURCE_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".java"}
    UNINSPECTED_EXTENSIONS = {".so", ".dll", ".exe", ".bin", ".dylib", ".dat", ".class", ".o", ".a"}
    KEYSTORE_EXTENSIONS = {".p12", ".pfx", ".jks", ".keystore"}

    # 1a. Auditable Unknowns Ledger for boundary honesty
    unknowns_ledger: List[UnknownEntry] = []
    recorded_unknowns = set()

    for item in target_path.iterdir():
        if item.is_dir() and item.name in EXCLUDED_DIRS:
            rel = os.path.relpath(str(item), str(target_path))
            if rel not in recorded_unknowns:
                recorded_unknowns.add(rel)
                unknowns_ledger.append(UnknownEntry(
                    item_path=rel,
                    category="EXCLUDED_DIR",
                    reason=f"Standard dependency / build artifact directory '{item.name}' excluded by scanning policy",
                    recommended_action="Execute dedicated supply-chain audit on lockfiles if unmanaged vendor packages exist."
                ))

    for f in target_path.glob("**/*"):
        if f.is_dir():
            if f.name in EXCLUDED_DIRS and len(unknowns_ledger) < 100:
                rel = os.path.relpath(str(f), str(target_path))
                if rel not in recorded_unknowns:
                    recorded_unknowns.add(rel)
                    unknowns_ledger.append(UnknownEntry(
                        item_path=rel,
                        category="EXCLUDED_DIR",
                        reason=f"Subdirectory '{f.name}' excluded by scanning policy",
                        recommended_action="Review vendor dependency isolation."
                    ))
        elif f.is_file():
            sfx = f.suffix.lower()
            if sfx in UNINSPECTED_EXTENSIONS and not any(part in EXCLUDED_DIRS for part in f.parts) and len(unknowns_ledger) < 100:
                rel = os.path.relpath(str(f), str(target_path))
                if rel not in recorded_unknowns:
                    recorded_unknowns.add(rel)
                    unknowns_ledger.append(UnknownEntry(
                        item_path=rel,
                        category="UNINSPECTED_BINARY",
                        reason=f"Compiled binary format '{sfx}' cannot be analyzed via static source AST",
                        recommended_action="Perform binary symbol extraction or dynamic eBPF runtime audit."
                    ))
            elif sfx in KEYSTORE_EXTENSIONS and not any(part in EXCLUDED_DIRS for part in f.parts) and len(unknowns_ledger) < 100:
                rel = os.path.relpath(str(f), str(target_path))
                if rel not in recorded_unknowns:
                    recorded_unknowns.add(rel)
                    unknowns_ledger.append(UnknownEntry(
                        item_path=rel,
                        category="ENCRYPTED_KEYSTORE",
                        reason="Encrypted keystore container requires credential decryption to audit constituent keys",
                        recommended_action="Provide keystore password or credentials to unwrap and attest internal key material."
                    ))

    all_source_files = [
        f for f in target_path.glob("**/*")
        if f.is_file() and f.suffix.lower() in SOURCE_EXTENSIONS 
        and not any((part.startswith(".") and part != ".") or part.lower() in EXCLUDED_DIRS for part in f.parts[:-1])
        and should_scan_file(str(f))
    ]
    if parsed_subdirs:
        all_source_files = [
            f for f in all_source_files
            if any(sub in f.relative_to(target_path).parts for sub in parsed_subdirs)
        ]

    py_files = [f for f in all_source_files if f.suffix.lower() == ".py"]

    all_inferences: List[Tuple[str, XInferenceResult]] = []
    all_buffer_hazards: List[BufferHazard] = []

    for py_file in py_files:
        inf_results = analyze_python_file(str(py_file))
        for inf in inf_results:
            all_inferences.append((str(py_file), inf))

        hazards = audit_python_buffer_file(str(py_file))
        all_buffer_hazards.extend(hazards)

    # 1b. Audit Polyglot Package Manifests (package.json, go.mod, Cargo.toml, requirements.txt)
    manifest_deps = discover_manifest_crypto_dependencies(str(target_path))
    if parsed_subdirs:
        manifest_deps = [
            m for m in manifest_deps
            if any(sub in Path(getattr(m, "manifest_path", "")).parts for sub in parsed_subdirs)
        ]

    # 1c. Autonomous Schema Lifespans & Deployment Exposure Scans
    schema_lifespans = extract_schemas_lifespan(str(target_path))
    deployment_exposures = scan_deployment_exposure(str(target_path))

    # 2. Build CryptoAsset records & compute Mosca scores + PQC recommendations
    assessments: List[Tuple[CryptoAsset, MoscaScore, MigrationRecommendation]] = []
    assets_for_merkle: List[Tuple[CryptoAsset, MoscaScore]] = []

    # 2a. Python AST Inferences
    for fpath, inf in all_inferences:
        prim_type, alg, key_size = _infer_primitive_and_alg(inf.target_variable, inf.sink_call)
        component = Path(fpath).stem

        asset = CryptoAsset(
            asset_id=f"ASSET-{len(assessments) + 1:03d}",
            component_name=component,
            algorithm=alg,
            key_size=key_size,
            primitive_type=prim_type,
            file_path=os.path.relpath(fpath, str(target_path)),
            line_number=inf.line_number,
            x_tier=inf.tier,
            x_confidence=inf.confidence,
            has_crypto_shredding=False,
            intent_class=getattr(inf, "intent_class", IntentClass.CONFIDENTIALITY_ENVELOPE),
            evidence_level=getattr(inf, "evidence_level", EvidenceLevel.E1_STATIC_ARTIFACT),
            raw_properties={"evidence": inf.evidence, "sink": inf.sink_call},
        )
        _apply_schema_lifespan(asset, schema_lifespans)
        _apply_deployment_exposure(asset, deployment_exposures)

        score = compute_mosca_score(asset, current_year=CURRENT_YEAR)
        asset.risk_level = score.risk_level
        rec = recommend_pqc_migration(asset, path_mtu=path_mtu)

        assessments.append((asset, score, rec))
        assets_for_merkle.append((asset, score))

    # 2b. Polyglot In-Code Source Cryptographic Assets (JS/TS, Go, Rust, Java)
    polyglot_assets = discover_polyglot_crypto_assets(str(target_path))
    if parsed_subdirs:
        polyglot_assets = [
            p for p in polyglot_assets
            if any(sub in Path(p.file_path).parts for sub in parsed_subdirs)
        ]
    for p_asset in polyglot_assets:
        p_asset.asset_id = f"ASSET-{len(assessments) + 1:03d}"
        _apply_schema_lifespan(p_asset, schema_lifespans)
        _apply_deployment_exposure(p_asset, deployment_exposures)
        score = compute_mosca_score(p_asset, current_year=CURRENT_YEAR)
        p_asset.risk_level = score.risk_level
        rec = recommend_pqc_migration(p_asset, path_mtu=path_mtu)
        assessments.append((p_asset, score, rec))
        assets_for_merkle.append((p_asset, score))

    # 2c. Discover Filesystem Cryptographic Artifacts via Go binary (cbomkit-theia)
    theia_assets: List[CryptoAsset] = []
    if enable_theia:
        theia_assets = run_theia_scan(str(target_path))
        if parsed_subdirs:
            theia_assets = [
                f for f in theia_assets
                if any(sub in Path(f.file_path).parts for sub in parsed_subdirs)
            ]
        for fs_asset in theia_assets:
            fs_asset.asset_id = f"ASSET-{len(assessments) + 1:03d}"
            _apply_schema_lifespan(fs_asset, schema_lifespans)
            _apply_deployment_exposure(fs_asset, deployment_exposures)
            score = compute_mosca_score(fs_asset, current_year=CURRENT_YEAR)
            fs_asset.risk_level = score.risk_level
            rec = recommend_pqc_migration(fs_asset, path_mtu=path_mtu)
            assessments.append((fs_asset, score, rec))
            assets_for_merkle.append((fs_asset, score))

    # 2d. Discover Server Configuration Cryptographic Directives (Nginx/Apache TLS)
    config_assets = scan_server_configs(target_path)
    if parsed_subdirs:
        config_assets = [
            c for c in config_assets
            if any(sub in Path(c.file_path).parts for sub in parsed_subdirs)
        ]
    for c_asset in config_assets:
        c_asset.asset_id = f"ASSET-{len(assessments) + 1:03d}"
        _apply_schema_lifespan(c_asset, schema_lifespans)
        _apply_deployment_exposure(c_asset, deployment_exposures)
        score = compute_mosca_score(c_asset, current_year=CURRENT_YEAR)
        c_asset.risk_level = score.risk_level
        rec = recommend_pqc_migration(c_asset, path_mtu=path_mtu)
        assessments.append((c_asset, score, rec))
        assets_for_merkle.append((c_asset, score))

    if not assets_for_merkle:
        # Fallback: create a default root if no assets found
        merkle_root_hex = "00" * 32
        proof_packages = []
    else:
        # 3. Construct SHA-256 Merkle Tree & Proof Catalog
        tree, _ = MerkleTree.from_assets(assets_for_merkle, salt=salt)
        merkle_root_hex = tree.root_hex

        proof_packages = []
        for idx, (asset, score, _) in enumerate(assessments):
            pkg = generate_asset_proof_package(asset, score, leaf_index=idx, tree=tree, salt=salt)
            proof_packages.append(pkg)
            proof_file = proofs_dir / f"proof_{asset.asset_id}.json"
            with open(proof_file, "w", encoding="utf-8") as f:
                json.dump(pkg, f, indent=2)

    # 4. Write Root Hex commitment
    root_file = out_path / "cbom_root.hex"
    with open(root_file, "w", encoding="utf-8") as f:
        f.write(merkle_root_hex + "\n")

    # 4b. Epidemiological R0 Contagion Analysis & Graph Export
    contagion_result = analyze_contagion(
        file_paths=[str(f) for f in all_source_files],
        crypto_assets=[a for a, _, _ in assessments],
        manifest_dependencies=manifest_deps,
    )
    graph_file = out_path / "contagion_graph.json"
    with open(graph_file, "w", encoding="utf-8") as f:
        json.dump(contagion_result.graph_json, f, indent=2)

    # 4b2. Father Marko Tripartite Cryptographic Lineage Analysis & Graph Export
    lineage_result = analyze_crypto_lineage(
        file_paths=[str(f) for f in all_source_files],
        crypto_assets=[a for a, _, _ in assessments],
        target_dir=str(target_path),
    )
    lineage_graph_file = out_path / "lineage_graph.json"
    with open(lineage_graph_file, "w", encoding="utf-8") as f:
        json.dump(lineage_result.graph_json, f, indent=2)

    # 4c. Signed in-toto / SLSA DSSE Attestation Envelope Generation (Pillar 6)
    evidence_dist = {
        lvl.value: sum(1 for a, _, _ in assessments if getattr(a, "evidence_level", EvidenceLevel.E1_STATIC_ARTIFACT) == lvl)
        for lvl in EvidenceLevel
    }
    intent_dist = {
        i.value: sum(1 for a, _, _ in assessments if getattr(a, "intent_class", IntentClass.CONFIDENTIALITY_ENVELOPE) == i)
        for i in IntentClass
    }
    cams_dist = {
        f"L{lvl.value}_{lvl.name}": sum(1 for a, _, _ in assessments if getattr(a, "agility_level", AgilityLevel.RIGID) == lvl)
        for lvl in AgilityLevel
    }
    unknowns_dicts = [u.model_dump() if hasattr(u, "model_dump") else u.dict() for u in unknowns_ledger]

    intoto_statement = build_intoto_statement(
        project_name=target_path.name,
        merkle_root_hex=merkle_root_hex,
        target_path=str(target_path),
        total_assets=len(assessments),
        evidence_distribution=evidence_dist,
        intent_distribution=intent_dist,
        cams_distribution=cams_dist,
        route_profile=path_mtu.route_profile.value,
        effective_mtu=path_mtu.effective_mtu,
        unknowns_ledger=unknowns_dicts,
    )

    dsse_envelope, pubkey, pubkey_pem = create_signed_dsse_envelope(intoto_statement, private_key=signing_key)

    attestation_file = out_path / "attestation.dsse.json"
    with open(attestation_file, "w", encoding="utf-8") as f:
        json.dump(dsse_envelope, f, indent=2)

    pubkey_file = out_path / "attestation_pubkey.pem"
    with open(pubkey_file, "w", encoding="utf-8") as f:
        f.write(pubkey_pem)

    # 4d. Pareto Migration Portfolio Optimization (Pillar 7)
    pareto_result = optimize_pareto_portfolio(
        assessments=assessments,
        contagion_result=contagion_result,
        budget_dev_weeks=budget_dev_weeks,
    )
    pareto_file = out_path / "pareto_portfolio.json"
    with open(pareto_file, "w", encoding="utf-8") as f:
        json.dump(pareto_result.model_dump() if hasattr(pareto_result, "model_dump") else pareto_result.dict(), f, indent=2)

    # 4e. Stochastic Monte Carlo Mosca Risk Simulation
    stochastic_summary = simulate_estate_stochastic_mosca(
        assessments=assessments,
        iterations=stochastic_runs,
    )
    stochastic_file = out_path / "stochastic_mosca.json"
    with open(stochastic_file, "w", encoding="utf-8") as f:
        json.dump(stochastic_summary, f, indent=2)

    # 4f. Standalone Negative Proof Certificate Generation (Pillar 6 Part B)
    negative_proof_file = None
    negative_proof_cert = None
    if generate_negative_proof:
        negative_proof_cert = generate_negative_proof_certificate(
            assessments=assessments,
            unknowns_ledger=unknowns_ledger,
            target_path=str(target_path),
            merkle_root_hex=merkle_root_hex,
            project_name=target_path.name,
            total_files_audited=len(all_source_files),
        )
        negative_proof_file = out_path / "negative_proof.json"
        with open(negative_proof_file, "w", encoding="utf-8") as f:
            json.dump(negative_proof_cert.model_dump() if hasattr(negative_proof_cert, "model_dump") else negative_proof_cert.dict(), f, indent=2)

    # 5. Generate and write CISO Markdown report
    ciso_report_md = generate_ciso_report(
        assessments,
        all_buffer_hazards,
        merkle_root_hex,
        contagion_result=contagion_result,
        unknowns_ledger=unknowns_ledger,
        path_mtu=path_mtu,
        attestation_envelope=dsse_envelope,
        pareto_result=pareto_result,
        stochastic_summary=stochastic_summary,
        negative_proof=negative_proof_cert,
    )
    report_file = out_path / "ciso_migration_report.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(ciso_report_md)


    # 6. Generate enriched CycloneDX 1.6 / Discussion #966 CBOM JSON
    cbom_components = []
    for asset, score, rec in assessments:
        comp = {
            "type": "cryptographic-asset",
            "name": asset.component_name,
            "bom-ref": asset.asset_id,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "name": asset.algorithm,
                    "keyLength": asset.key_size,
                    "primitive": asset.primitive_type.value,
                },
            },
            "properties": [
                {"name": "ecdat:x_tier", "value": asset.x_tier.value},
                {"name": "ecdat:x_years_effective", "value": str(score.x_years_effective)},
                {"name": "ecdat:y_max_years", "value": str(score.y_max_years)},
                {"name": "ecdat:risk_level", "value": score.risk_level},
                {"name": "ecdat:intent_class", "value": asset.intent_class.value if hasattr(asset.intent_class, "value") else str(asset.intent_class)},
                {"name": "ecdat:evidence_level", "value": asset.evidence_level.value if hasattr(asset.evidence_level, "value") else str(asset.evidence_level)},
                {"name": "ecdat:exposure_profile", "value": asset.exposure_profile.value if hasattr(asset.exposure_profile, "value") else str(asset.exposure_profile)},
                {"name": "ecdat:p_hndl", "value": str(score.p_hndl)},
                {"name": "ecdat:r_q_score", "value": str(score.r_q_score)},
                {"name": "ecdat:recommended_hybrid", "value": rec.recommended_hybrid},
                {"name": "ecdat:recommended_pqc", "value": rec.recommended_pqc_standalone},
                {"name": "ecdat:cams_agility_level", "value": str(getattr(asset, "agility_level", AgilityLevel.RIGID).value)},
                {"name": "ecdat:cams_agility_name", "value": getattr(asset, "agility_level", AgilityLevel.RIGID).name},
            ],
        }
        enriched_comp = enrich_cyclonedx_component_966(comp, asset, score, rec, path_mtu=path_mtu)
        cbom_components.append(enriched_comp)

    enriched_cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:ecdat-{merkle_root_hex[:16]}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "ECDAT", "version": "2.0.0", "vendor": "SIH26164"}],
            "properties": [
                {"name": "ecdat:merkleRoot", "value": merkle_root_hex},
                {"name": "ecdat:totalAssets", "value": str(len(assessments))},
                {"name": "ecdat:manifestDependencies", "value": str(len(manifest_deps))},
                {"name": "ecdat:unknownsLogged", "value": str(len(unknowns_ledger))},
                {"name": "ecdat:routeProfile", "value": path_mtu.route_profile.value},
                {"name": "ecdat:effectiveMtu", "value": str(path_mtu.effective_mtu)},
                {"name": "ecdat:dsseSigned", "value": "true"},
            ],
        },
        "components": cbom_components,
        "dependencies": [d.model_dump() if hasattr(d, "model_dump") else d.dict() for d in manifest_deps],
    }

    cbom_file = out_path / "enriched_cbom.json"
    with open(cbom_file, "w", encoding="utf-8") as f:
        json.dump(enriched_cbom, f, indent=2)

    # 6b. Generate OASIS SARIF 2.1.0 Static Analysis Report
    sarif_file = out_path / "cbom.sarif.json"
    discovered_assets = [a for a, _, _ in assessments]
    export_sarif_file(discovered_assets, sarif_file)

    # 7. Generate standalone Visual Interactive HTML Report (and backward-compatible dashboard.html)
    report_html = generate_html_report(
        assessments=assessments,
        buffer_hazards=all_buffer_hazards,
        merkle_root_hex=merkle_root_hex,
        contagion_result=contagion_result,
        proof_packages=proof_packages,
        project_name=target_path.name,
        ciso_report_md=ciso_report_md,
        manifest_dependencies=manifest_deps,
        unknowns_ledger=unknowns_ledger,
        path_mtu=path_mtu,
        attestation_envelope=dsse_envelope,
        pubkey_pem=pubkey_pem,
        pareto_result=pareto_result,
        stochastic_summary=stochastic_summary,
        negative_proof=negative_proof_cert,
        budget_dev_weeks=budget_dev_weeks,
        lineage_result=lineage_result,
    )
    report_file_html = out_path / "report.html"
    with open(report_file_html, "w", encoding="utf-8") as f:
        f.write(report_html)

    # Clean up stale dashboard.html if present
    (out_path / "dashboard.html").unlink(missing_ok=True)

    return {
        "total_assets": len(assessments),
        "source_code_assets": len(all_inferences),
        "theia_assets_count": len(theia_assets),
        "manifest_dependencies_count": len(manifest_deps),
        "manifest_dependencies": [d.model_dump() if hasattr(d, "model_dump") else d.dict() for d in manifest_deps],
        "merkle_root": merkle_root_hex,
        "buffer_hazards": len(all_buffer_hazards),
        "contagion_superspreaders": len(contagion_result.superspreaders),
        "contagion_graph_file": str(graph_file),
        "lineage_graph_file": str(lineage_graph_file),
        "lineage_ingress_count": lineage_result.ingress_count,
        "lineage_nexus_count": lineage_result.nexus_count,
        "lineage_egress_count": lineage_result.egress_count,
        "report_file_html": str(report_file_html),
        "output_directory": str(out_path),
        "cbom_file": str(cbom_file),
        "sarif_file": str(sarif_file),
        "assets": discovered_assets,
        "report_file": str(report_file),
        "root_file": str(root_file),
        "attestation_file": str(attestation_file),
        "pubkey_file": str(pubkey_file),
        "pareto_portfolio_file": str(pareto_file),
        "stochastic_mosca_file": str(stochastic_file),
        "negative_proof_file": str(negative_proof_file) if negative_proof_file else None,
        "path_mtu": path_mtu.effective_mtu,
        "route_profile": path_mtu.route_profile.value,
        "dsse_envelope": dsse_envelope,
        "pubkey_pem": pubkey_pem,
        "proofs_count": len(proof_packages),
        "unknowns_count": len(unknowns_ledger),
        "unknowns_ledger": [u.model_dump() if hasattr(u, "model_dump") else u.dict() for u in unknowns_ledger],
    }


class PipelineResult(list):
    """
    List subclass containing CryptoAsset items, allowing both list operations
    and dictionary-like access to the underlying scan metadata.
    """
    def __init__(self, assets: List[CryptoAsset], scan_result: Optional[Dict[str, Any]] = None):
        super().__init__(assets)
        self.scan_result = scan_result or {}
        self.assets = assets

    def __getitem__(self, item):
        if isinstance(item, str):
            return self.scan_result[item]
        return super().__getitem__(item)

    def get(self, key: str, default: Any = None) -> Any:
        return self.scan_result.get(key, default)


def run_pipeline(target_dir: str, **kwargs) -> PipelineResult:
    """
    Executes the cryptographic discovery and risk pipeline, returning
    a PipelineResult with discovered CryptoAsset items and metadata.
    """
    scan_res = run_ecdat_scan(target_dir, **kwargs)
    assets = scan_res.get("assets", [])
    return PipelineResult(assets, scan_result=scan_res)


def probe_live_tls_infrastructure(
    endpoint: str,
    timeout: float = 5.0,
    output: Optional[str] = None,
) -> List[CryptoAsset]:
    """
    Connects to live TLS endpoint, inspects active cryptographic parameters,
    and returns a list of standardized CryptoAsset models.
    """
    from ecdat.network.tls_prober import LiveTLSProber, TLSProbeError

    prober = LiveTLSProber()
    try:
        host, port = prober.parse_target(endpoint)
    except ValueError as val_err:
        print(f"[!] INVALID ENDPOINT: {val_err}", file=sys.stderr)
        return []

    print("=" * 104)
    print("                      ECDAT Live External Infrastructure & TLS Prober")
    print("=" * 104)
    print(f"[*] Target Endpoint:   {endpoint}")
    print(f"[*] Resolved Host:     {host}")
    print(f"[*] Port:              {port}")
    print(f"[*] Handshake Timeout: {timeout}s")
    print("-" * 104)

    try:
        assets = prober.probe_endpoint(endpoint, timeout=timeout)
    except TLSProbeError as err:
        print(f"[!] PROBE FAILED: {err}", file=sys.stderr)
        return []
    except Exception as err:
        print(f"[!] UNEXPECTED HANDSHAKE FAILURE: {err}", file=sys.stderr)
        return []

    tls_ver = assets[1].raw_properties.get("tls_version", "UNKNOWN") if len(assets) > 1 else "UNKNOWN"
    cipher_suite = assets[2].raw_properties.get("cipher_suite", "UNKNOWN") if len(assets) > 2 else "UNKNOWN"

    print(f"[+] TLS Protocol:      {tls_ver}")
    print(f"[+] Cipher Suite:      {cipher_suite}")
    print(f"[+] Discovered Live Assets: {len(assets)}")
    print("-" * 104)
    print(f"{'Role / Component':<24} | {'Algorithm':<22} | {'Key / Bits':<10} | {'Tier':<12} | {'Quantum Risk Status'}")
    print("-" * 104)

    for a in assets:
        bits_str = f"{a.key_size} b" if a.key_size else "N/A"
        q_risk = a.raw_properties.get("quantum_risk", "UNKNOWN")
        pqc_stat = a.raw_properties.get("pqc_status", "")
        status_str = f"{q_risk} ({pqc_stat})" if pqc_stat else q_risk
        role = a.component_name.split(":")[0]
        print(f"{role:<24} | {a.algorithm:<22} | {bits_str:<10} | {a.x_tier.value:<12} | {status_str}")

    print("=" * 104)

    if output:
        out_path = Path(output)
        if out_path.is_dir() or output.endswith("/") or output.endswith("\\"):
            out_path.mkdir(parents=True, exist_ok=True)
            target_json = out_path / "live_tls_assets.json"
        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            target_json = out_path

        export_data = [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in assets]
        with open(target_json, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        print(f"[+] Discovered live assets written to JSON: {target_json}")

    return assets


@click.group()
def cli():
    """ECDAT: Enterprise Cryptographic Discovery and Analysis Tool CLI."""
    pass


@cli.command("probe")
@click.argument("endpoint")
@click.option("--timeout", default=5.0, help="Connection timeout in seconds")
@click.option("--output", "-o", default=None, help="Output directory or JSON file")
def probe_cmd(endpoint, timeout, output):
    """Probe live TLS endpoint and evaluate Post-Quantum readiness."""
    return probe_live_tls_infrastructure(endpoint=endpoint, timeout=timeout, output=output)


@cli.command("serve")
@click.option("--port", default=8080, type=int, help="Port to bind server (default: 8080)")
@click.option("--host", default="127.0.0.1", type=str, help="Host interface to bind (default: 127.0.0.1)")
@click.option("--reports-dir", default=None, type=str, help="Directory containing scanned project reports")
def serve_cmd(port, host, reports_dir):
    """Start the ECDAT Multi-Project Fleet Dashboard Server."""
    from ecdat.dashboard.server import start_server
    return start_server(host=host, port=port, reports_dir=reports_dir)


@cli.command("gate")
@click.option("--target", "-t", required=True, type=str, help="Target project directory to scan")
@click.option("--fail-on", default="CRITICAL", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False), help="Failure severity threshold")
@click.option("--max-allowed", default=0, type=int, help="Maximum allowed violations before gate failure")
@click.option("--sarif", default=None, type=str, help="Path to output SARIF JSON file")
@click.option("--policy", default="nist-sp-800-131a", type=str, help="Cryptographic compliance policy")
@click.pass_context
def gate_cmd(ctx, target, fail_on, max_allowed, sarif, policy):
    """Evaluate CI/CD Cryptographic Quality Gate against a target project."""
    assets = run_pipeline(target)
    gate_result = evaluate_quality_gate(
        assets,
        fail_on=fail_on.upper(),
        max_allowed=max_allowed,
        policy=policy,
    )
    if sarif:
        export_sarif_file(assets, Path(sarif))
        print(f"[+] SARIF 2.1.0 report written to: {sarif}")
    print(gate_result.banner)
    if ctx and hasattr(ctx, "exit"):
        ctx.exit(gate_result.exit_code)
    return gate_result.exit_code


@cli.command("scan")
@click.option("--target", "-t", required=True, type=str, help="Target project directory to scan")
@click.option("--output", "-o", default=None, help="Custom output directory for CBOM, report, and proofs")
@click.option("--format", "output_format", default="all", type=click.Choice(["cbom", "sarif", "all"], case_sensitive=False), help="Output format")
def scan_cmd(target, output, output_format):
    """Run discovery, risk scoring, and Merkle commitment on a codebase."""
    res = run_ecdat_scan(target_dir=target, output_dir=output)
    print(f"[+] Scan Complete: {res['total_assets']} assets found.")
    return 0


@cli.command("remediate")
@click.option("--target", "-t", required=True, type=str, help="Target file or directory to remediate")
@click.option("--rule", default=None, type=str, help="Specific remediation rule ID (e.g. REPLACE_CBC_GCM, REPLACE_MD5_SHA256)")
@click.option("--dry-run", is_flag=True, help="Preview unified diff without modifying files on disk")
@click.option("--journal", default=None, type=str, help="Custom journal path for transactions")
def remediate_cmd(target, rule, dry_run, journal):
    """1-Click automated code remediation for cryptographic vulnerabilities."""
    from ecdat.remediation.engine import RemediationEngine
    engine = RemediationEngine(journal_path=journal)
    results = engine.remediate_target(target, rule=rule, dry_run=dry_run)
    if dry_run:
        print(f"[*] ECDAT Remediation Dry-Run: {len(results)} potential patches found.\n")
        for r in results:
            print(f"--- File: {r['target_file']} ({r['rule_id']}) ---")
            print(r['diff'])
    else:
        print(f"[+] ECDAT Remediation Applied: {len(results)} transactions committed to journal.\n")
        for r in results:
            print(f"  [+] {r['tx_id']}: {r['description']} -> {r['target_file']}")
    return 0


@cli.command("undo")
@click.option("--tx", default=None, type=str, help="Specific transaction ID to undo (default: last applied)")
@click.option("--journal", default=None, type=str, help="Custom journal path")
def undo_cmd(tx, journal):
    """Revert the last (or specified) cryptographic remediation transaction."""
    from ecdat.remediation.engine import RemediationEngine
    engine = RemediationEngine(journal_path=journal)
    try:
        success = engine.undo_tx(tx) if tx else engine.undo_last()
        if success:
            print(f"[+] Successfully reverted remediation transaction{' ' + tx if tx else ''}.")
            return 0
        else:
            print("[-] No active remediation transaction found to undo.", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"[!] Undo failed: {e}", file=sys.stderr)
        return 1


@cli.command("redo")
@click.option("--tx", default=None, type=str, help="Specific transaction ID to redo (default: last reverted)")
@click.option("--journal", default=None, type=str, help="Custom journal path")
def redo_cmd(tx, journal):
    """Reapply the last (or specified) reverted cryptographic remediation transaction."""
    from ecdat.remediation.engine import RemediationEngine
    engine = RemediationEngine(journal_path=journal)
    try:
        success = engine.redo_tx(tx) if tx else engine.redo_last()
        if success:
            print(f"[+] Successfully reapplied remediation transaction{' ' + tx if tx else ''}.")
            return 0
        else:
            print("[-] No reverted remediation transaction found to redo.", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"[!] Redo failed: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="ECDAT: Enterprise Cryptographic Discovery and Analysis Tool CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run discovery, risk scoring, and Merkle commitment on a codebase")
    scan_parser.add_argument("--target", required=True, help="Target project directory to scan")
    scan_parser.add_argument("--output", required=False, help="Custom output directory for CBOM, report, and proofs")
    scan_parser.add_argument("--no-theia", action="store_false", dest="enable_theia", default=True, help="Disable cbomkit-theia Go filesystem scanner")
    scan_parser.add_argument("--probe-host", help="Probe remote network path MTU against target host (e.g. api.example.com)")
    scan_parser.add_argument("--mtu-profile", choices=["standard", "flexible", "constrained"], help="Override network path MTU profile")
    scan_parser.add_argument("--mtu-bytes", type=int, help="Override network path MTU in bytes (e.g. 1200 or 1500)")
    scan_parser.add_argument("--budget", type=float, default=10.0, help="Sprint capacity budget in dev-weeks for Pareto optimizer (default: 10.0)")
    scan_parser.add_argument("--stochastic-runs", type=int, default=5000, help="Number of Monte Carlo iterations for stochastic Mosca simulation (default: 5000)")
    scan_parser.add_argument("--no-negative-proof", action="store_false", dest="generate_negative_proof", default=True, help="Disable standalone negative proof certificate generation")
    scan_parser.add_argument("--subdirs", help="Comma-separated list of subdirectories to scan within target (e.g. backend,blockchain)")
    scan_parser.add_argument("--format", choices=["cbom", "sarif", "all"], default="all", help="Output format (cbom, sarif, or all; default: all)")

    gate_parser = subparsers.add_parser("gate", help="Evaluate CI/CD Cryptographic Quality Gate")
    gate_parser.add_argument("--target", required=True, help="Target project directory to scan")
    gate_parser.add_argument("--fail-on", default="CRITICAL", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Failure severity threshold (default: CRITICAL)")
    gate_parser.add_argument("--max-allowed", type=int, default=0, help="Maximum allowed violations before gate failure (default: 0)")
    gate_parser.add_argument("--sarif", default=None, help="Path to output SARIF JSON file")
    gate_parser.add_argument("--policy", default="nist-sp-800-131a", help="Cryptographic compliance policy (default: nist-sp-800-131a)")

    verify_parser = subparsers.add_parser("verify-attestation", help="Verify an in-toto / SLSA DSSE attestation envelope against public key")
    verify_parser.add_argument("--envelope", required=True, help="Path to attestation.dsse.json file")
    verify_parser.add_argument("--pubkey", required=True, help="Path to attestation_pubkey.pem file")
    verify_parser.add_argument("--root", required=False, help="Path to cbom_root.hex or raw root hex string")

    dash_parser = subparsers.add_parser("dashboard", help="Serve and view an ECDAT cryptographic audit report (report.html)")
    dash_parser.add_argument("--report", help="Path to report.html or output directory containing report.html")
    dash_parser.add_argument("--port", type=int, default=8000, help="Port to serve report on (default: 8000)")
    dash_parser.add_argument("--no-browser", action="store_true", help="Do not open web browser automatically")

    serve_parser = subparsers.add_parser("serve", help="Start the ECDAT Multi-Project Fleet Dashboard Server")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port to bind server (default: 8080)")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    serve_parser.add_argument("--reports-dir", default=None, help="Directory containing scanned project reports")

    probe_parser = subparsers.add_parser("probe", help="Probe remote TLS endpoint for live cryptographic posture")
    probe_parser.add_argument("endpoint", help="Target URL or hostname to probe (e.g. https://example.com:443)")
    probe_parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout in seconds")
    probe_parser.add_argument("--output", "-o", default=None, help="Output directory or JSON file")

    remed_parser = subparsers.add_parser("remediate", help="1-Click automated code remediation for cryptographic vulnerabilities")
    remed_parser.add_argument("--target", required=True, help="Target file or directory to remediate")
    remed_parser.add_argument("--rule", default=None, help="Specific remediation rule ID (e.g. REPLACE_CBC_GCM, REPLACE_MD5_SHA256)")
    remed_parser.add_argument("--dry-run", action="store_true", help="Preview unified diff without modifying files on disk")
    remed_parser.add_argument("--journal", default=None, help="Custom journal path for transactions")

    undo_parser = subparsers.add_parser("undo", help="Revert the last (or specified) cryptographic remediation transaction")
    undo_parser.add_argument("--tx", default=None, help="Specific transaction ID to undo (default: last applied)")
    undo_parser.add_argument("--journal", default=None, help="Custom journal path")

    redo_parser = subparsers.add_parser("redo", help="Reapply the last (or specified) reverted cryptographic remediation transaction")
    redo_parser.add_argument("--tx", default=None, help="Specific transaction ID to redo (default: last reverted)")
    redo_parser.add_argument("--journal", default=None, help="Custom journal path")

    args = parser.parse_args()

    if args.command == "dashboard":
        import http.server
        import socketserver
        import webbrowser

        report_arg = args.report
        report_path = None
        if report_arg:
            p = Path(report_arg).resolve()
            report_path = p / "report.html" if p.is_dir() else p
        else:
            candidates = [
                Path.cwd() / "report.html",
                Path.cwd() / "output" / "report.html",
                Path(__file__).resolve().parent.parent / "testbeds" / "benchmarks" / "evoting_backend" / "report.html",
                Path(__file__).resolve().parent.parent / "testbeds" / "benchmarks" / "reports" / "cryptoapi_bench" / "report.html",
                Path(__file__).resolve().parent.parent / "testbeds" / "benchmarks" / "reports" / "cryben" / "report.html",
            ]
            for c in candidates:
                if c.exists():
                    report_path = c
                    break

        if not report_path or not report_path.exists():
            print("[!] Error: report.html not found. Run 'ecdat scan' first or pass --report <path>.")
            return 1

        report_dir = str(report_path.parent)
        filename = report_path.name
        port = args.port
        url = f"http://localhost:{port}/{filename}"

        print(f"[*] Serving ECDAT Cryptographic Report: {report_path}")
        print(f"[+] Local Viewer URL: {url}")

        if not args.no_browser:
            webbrowser.open(url)

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=report_dir, **kw)
            def log_message(self, format, *a):
                pass

        print("[*] Press Ctrl+C to stop.")
        try:
            with socketserver.TCPServer(("", port), QuietHandler) as httpd:
                httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
            return 0
    elif args.command == "scan":
        print(f"[*] Starting ECDAT cryptographic discovery on: {args.target}")
        result = run_ecdat_scan(
            args.target,
            output_dir=args.output,
            enable_theia=args.enable_theia,
            probe_host=args.probe_host,
            mtu_profile=args.mtu_profile,
            override_mtu=args.mtu_bytes,
            budget_dev_weeks=args.budget,
            stochastic_runs=args.stochastic_runs,
            generate_negative_proof=args.generate_negative_proof,
            subdirs=args.subdirs,
        )
        print(f"[+] Scan Complete!")
        print(f"    - Total Assets:      {result['total_assets']}")
        print(f"      * AST Inferences:  {result['source_code_assets']}")
        print(f"      * Theia Filesystem:{result['theia_assets_count']} (X.509/Keys via cbomkit-theia)")
        print(f"      * Supply Chain:    {result['manifest_dependencies_count']} (Polyglot Manifest Packages)")
        print(f"    - Buffer Hazards:    {result['buffer_hazards']}")
        print(f"    - Superspreaders:    {result['contagion_superspreaders']}")
        print(f"    - Transport MTU:     {result['path_mtu']} B ({result['route_profile']})")
        print(f"    - Merkle Root:       0x{result['merkle_root']}")
        print(f"    - Signed DSSE:       {result['attestation_file']}")
        print(f"    - Attestation Key:   {result['pubkey_file']}")
        print(f"    - Pareto Portfolio:  {result.get('pareto_portfolio_file')}")
        print(f"    - Stochastic Mosca:  {result.get('stochastic_mosca_file')}")
        if result.get('negative_proof_file'):
            print(f"    - Negative Proof:    {result['negative_proof_file']}")
        print(f"    - Contagion Graph:   {result['contagion_graph_file']}")
        print(f"    - HTML Report:       {result['report_file_html']}")
        print(f"    - Output Directory:  {result['output_directory']}")
        print(f"    - CISO Report:       {result['report_file']}")
        print(f"    - Enriched CBOM:     {result['cbom_file']}")
        print(f"    - SARIF Report:      {result['sarif_file']}")
        return 0
    elif args.command == "gate":
        assets = run_pipeline(args.target)
        gate_result = evaluate_quality_gate(
            assets,
            fail_on=args.fail_on.upper(),
            max_allowed=args.max_allowed,
            policy=args.policy,
        )
        if args.sarif:
            export_sarif_file(assets, Path(args.sarif))
            print(f"[+] SARIF 2.1.0 report written to: {args.sarif}")
        print(gate_result.banner)
        return gate_result.exit_code
    elif args.command == "verify-attestation":
        from ecdat.attestation.verifier import verify_dsse_envelope_from_file
        is_valid, msg, stmt = verify_dsse_envelope_from_file(args.envelope, args.pubkey, expected_root_hex=args.root)
        if is_valid:
            proj = stmt["subject"][0].get("name", "unknown") if stmt else "unknown"
            root_val = stmt["subject"][0]["digest"].get("sha256", "") if stmt else ""
            print(f"[+] SUCCESS — {msg}")
            print(f"    - Target Project: {proj}")
            print(f"    - Merkle Root:    0x{root_val}")
            return 0
        else:
            print(f"[-] VERIFICATION FAILED: {msg}", file=sys.stderr)
            return 1
    elif args.command == "probe":
        assets = probe_live_tls_infrastructure(args.endpoint, timeout=args.timeout, output=args.output)
        return 0 if assets else 1
    elif args.command == "serve":
        from ecdat.dashboard.server import start_server
        return start_server(host=args.host, port=args.port, reports_dir=args.reports_dir)
    elif args.command == "remediate":
        from ecdat.remediation.engine import RemediationEngine
        engine = RemediationEngine(journal_path=args.journal)
        results = engine.remediate_target(args.target, rule=args.rule, dry_run=args.dry_run)
        if args.dry_run:
            print(f"[*] ECDAT Remediation Dry-Run: {len(results)} potential patches found.\n")
            for r in results:
                print(f"--- File: {r['target_file']} ({r['rule_id']}) ---")
                print(r['diff'])
        else:
            print(f"[+] ECDAT Remediation Applied: {len(results)} transactions committed to journal.\n")
            for r in results:
                print(f"  [+] {r['tx_id']}: {r['description']} -> {r['target_file']}")
        return 0
    elif args.command == "undo":
        from ecdat.remediation.engine import RemediationEngine
        engine = RemediationEngine(journal_path=args.journal)
        try:
            success = engine.undo_tx(args.tx) if args.tx else engine.undo_last()
            if success:
                print(f"[+] Successfully reverted remediation transaction{' ' + args.tx if args.tx else ''}.")
                return 0
            else:
                print("[-] No active remediation transaction found to undo.", file=sys.stderr)
                return 1
        except Exception as e:
            print(f"[!] Undo failed: {e}", file=sys.stderr)
            return 1
    elif args.command == "redo":
        from ecdat.remediation.engine import RemediationEngine
        engine = RemediationEngine(journal_path=args.journal)
        try:
            success = engine.redo_tx(args.tx) if args.tx else engine.redo_last()
            if success:
                print(f"[+] Successfully reapplied remediation transaction{' ' + args.tx if args.tx else ''}.")
                return 0
            else:
                print("[-] No reverted remediation transaction found to redo.", file=sys.stderr)
                return 1
        except Exception as e:
            print(f"[!] Redo failed: {e}", file=sys.stderr)
            return 1
    return 1

if __name__ == "__main__":
    sys.exit(main())
