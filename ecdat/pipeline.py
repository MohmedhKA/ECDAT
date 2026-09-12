"""
ECDAT Unified Discovery & Analysis Pipeline:
Orchestrates AST taint analysis, 4-tier X-inference, Mosca Y_max scoring,
PQC hybrid recommendations, buffer agility hazard audits, and Merkle tree root commitments.
"""

import os
import sys
import json
import argparse
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
)
from ecdat.constants import CURRENT_YEAR
from ecdat.x_inference.ast_tracer import analyze_python_file, XInferenceResult
from ecdat.agility.buffer_audit import audit_python_buffer_file, BufferHazard
from ecdat.agility.recommender import recommend_pqc_migration, MigrationRecommendation
from ecdat.mosca.engine import compute_mosca_score
from ecdat.merkle.tree import MerkleTree, generate_asset_proof_package
from ecdat.report import generate_ciso_report
from ecdat.contagion.engine import analyze_contagion
from ecdat.dashboard.generator import generate_html_dashboard, generate_html_report
from ecdat.scanners.theia_bridge import run_theia_scan
from ecdat.scanners.manifest_scanner import discover_manifest_crypto_dependencies
from ecdat.scanners.source_scanner import discover_polyglot_crypto_assets
from ecdat.scanners.filters import should_scan_file
from ecdat.schema_extractor import extract_schemas_lifespan
from ecdat.exposure_scanner import scan_deployment_exposure

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
) -> Dict[str, Any]:
    """
    Executes an end-to-end cryptographic discovery, temporal risk analysis,
    and privacy-preserving attestation pipeline across a target directory.
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target directory '{target_path}' does not exist.")

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

    # 1. Discover all first-party source files (Python, JS/TS, Go, Rust, Java)
    EXCLUDED_DIRS = {
        "venv", ".venv", "env", "node_modules", "site-packages",
        "__pycache__", ".git", "dist", "build", "target", ".cache"
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
        if f.is_file() and f.suffix.lower() in SOURCE_EXTENSIONS and not any(part in EXCLUDED_DIRS for part in f.parts) and should_scan_file(str(f))
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
        rec = recommend_pqc_migration(asset)

        assessments.append((asset, score, rec))
        assets_for_merkle.append((asset, score))

    # 2b. Polyglot In-Code Source Cryptographic Assets (JS/TS, Go, Rust, Java)
    polyglot_assets = discover_polyglot_crypto_assets(str(target_path))
    for p_asset in polyglot_assets:
        p_asset.asset_id = f"ASSET-{len(assessments) + 1:03d}"
        _apply_schema_lifespan(p_asset, schema_lifespans)
        _apply_deployment_exposure(p_asset, deployment_exposures)
        score = compute_mosca_score(p_asset, current_year=CURRENT_YEAR)
        rec = recommend_pqc_migration(p_asset)
        assessments.append((p_asset, score, rec))
        assets_for_merkle.append((p_asset, score))

    # 2c. Discover Filesystem Cryptographic Artifacts via Go binary (cbomkit-theia)
    theia_assets: List[CryptoAsset] = []
    if enable_theia:
        theia_assets = run_theia_scan(str(target_path))
        for fs_asset in theia_assets:
            fs_asset.asset_id = f"ASSET-{len(assessments) + 1:03d}"
            _apply_schema_lifespan(fs_asset, schema_lifespans)
            _apply_deployment_exposure(fs_asset, deployment_exposures)
            score = compute_mosca_score(fs_asset, current_year=CURRENT_YEAR)
            rec = recommend_pqc_migration(fs_asset)
            assessments.append((fs_asset, score, rec))
            assets_for_merkle.append((fs_asset, score))

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

    # 5. Generate and write CISO Markdown report
    ciso_report_md = generate_ciso_report(
        assessments,
        all_buffer_hazards,
        merkle_root_hex,
        contagion_result=contagion_result,
        unknowns_ledger=unknowns_ledger,
    )
    report_file = out_path / "ciso_migration_report.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(ciso_report_md)

    # 6. Generate enriched CycloneDX 1.6 / ECMA-424 CBOM JSON
    enriched_cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:ecdat-{merkle_root_hex[:16]}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "ECDAT", "version": "0.1.0", "vendor": "SIH26164"}],
            "properties": [
                {"name": "ecdat:merkleRoot", "value": merkle_root_hex},
                {"name": "ecdat:totalAssets", "value": str(len(assessments))},
                {"name": "ecdat:manifestDependencies", "value": str(len(manifest_deps))},
                {"name": "ecdat:unknownsLogged", "value": str(len(unknowns_ledger))},
            ],
        },
        "components": [
            {
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
                ],
            }
            for asset, score, rec in assessments
        ],
        "dependencies": [d.model_dump() if hasattr(d, "model_dump") else d.dict() for d in manifest_deps],
    }

    cbom_file = out_path / "enriched_cbom.json"
    with open(cbom_file, "w", encoding="utf-8") as f:
        json.dump(enriched_cbom, f, indent=2)

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
        "report_file_html": str(report_file_html),
        "output_directory": str(out_path),
        "cbom_file": str(cbom_file),
        "report_file": str(report_file),
        "root_file": str(root_file),
        "proofs_count": len(proof_packages),
        "unknowns_count": len(unknowns_ledger),
        "unknowns_ledger": [u.model_dump() if hasattr(u, "model_dump") else u.dict() for u in unknowns_ledger],
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="ECDAT: Enterprise Cryptographic Discovery and Analysis Tool CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run discovery, risk scoring, and Merkle commitment on a codebase")
    scan_parser.add_argument("--target", required=True, help="Target project directory to scan")
    scan_parser.add_argument("--output", required=False, help="Custom output directory for CBOM, report, and proofs")
    scan_parser.add_argument("--no-theia", action="store_false", dest="enable_theia", default=True, help="Disable cbomkit-theia Go filesystem scanner")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"[*] Starting ECDAT cryptographic discovery on: {args.target}")
        result = run_ecdat_scan(args.target, output_dir=args.output, enable_theia=args.enable_theia)
        print(f"[+] Scan Complete!")
        print(f"    - Total Assets:      {result['total_assets']}")
        print(f"      * AST Inferences:  {result['source_code_assets']}")
        print(f"      * Theia Filesystem:{result['theia_assets_count']} (X.509/Keys via cbomkit-theia)")
        print(f"      * Supply Chain:    {result['manifest_dependencies_count']} (Polyglot Manifest Packages)")
        print(f"    - Buffer Hazards:    {result['buffer_hazards']}")
        print(f"    - Superspreaders:    {result['contagion_superspreaders']}")
        print(f"    - Merkle Root:       0x{result['merkle_root']}")
        print(f"    - Contagion Graph:   {result['contagion_graph_file']}")
        print(f"    - HTML Report:       {result['report_file_html']}")
        print(f"    - Output Directory:  {result['output_directory']}")
        print(f"    - CISO Report:       {result['report_file']}")
        print(f"    - Enriched CBOM:     {result['cbom_file']}")
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
