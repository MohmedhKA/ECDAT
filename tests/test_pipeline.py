import os
import json
from pathlib import Path
import pytest

from ecdat.pipeline import run_ecdat_scan
from ecdat.merkle.verifier import verify_proof_package

def test_end_to_end_pipeline_on_sample_app(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    target_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    output_dir = str(tmp_path / "scan_output")

    result = run_ecdat_scan(target_dir=target_dir, output_dir=output_dir)

    # 1. Check discovery counts
    assert result["total_assets"] >= 5
    assert result["buffer_hazards"] >= 1
    assert len(result["merkle_root"]) == 64  # 32 bytes hex

    # 2. Verify generated files exist
    out_path = Path(output_dir)
    root_file = out_path / "cbom_root.hex"
    report_file = out_path / "ciso_migration_report.md"
    cbom_file = out_path / "enriched_cbom.json"
    proofs_dir = out_path / "proofs"

    assert root_file.exists()
    assert report_file.exists()
    assert cbom_file.exists()
    assert proofs_dir.exists()

    # 3. Verify Merkle root matches content
    with open(root_file, "r") as f:
        root_on_disk = f.read().strip()
    assert root_on_disk == result["merkle_root"]

    # 4. Cryptographically verify every generated selective inclusion proof
    proof_files = list(proofs_dir.glob("proof_*.json"))
    assert len(proof_files) == result["total_assets"]

    for pf in proof_files:
        with open(pf, "r", encoding="utf-8") as f:
            proof_data = json.load(f)
        is_valid, msg = verify_proof_package(proof_data)
        assert is_valid is True, f"Proof verification failed for {pf}: {msg}"
        assert "VERIFIED" in msg

    # 5. Check CISO Report Markdown contents
    with open(report_file, "r", encoding="utf-8") as f:
        report_content = f.read()
    assert "# ECDAT — Executive Cryptographic Risk & Migration Report" in report_content
    assert "4-Tier Data Lifespan ($X$) Distribution" in report_content
    assert "Functional Security Intent (DSIS Lattice)" in report_content
    assert "Deployment Exposure & Harvest Interception" in report_content
    assert "Auditable Unknowns Ledger & Boundary Declarations" in report_content
    assert "FIXED BUFFER HAZARD" in report_content or "Buffer Overflow Hazards" in report_content
    assert "Privacy-Preserving Attestation" in report_content

    # 6. Check enriched CycloneDX CBOM JSON format
    with open(cbom_file, "r", encoding="utf-8") as f:
        cbom_data = json.load(f)
    assert cbom_data["bomFormat"] == "CycloneDX"
    assert cbom_data["specVersion"] == "1.6"
    assert len(cbom_data["components"]) == result["total_assets"]
    assert cbom_data["metadata"]["timestamp"] != "2026-09-04T15:00:00Z"  # Dynamic UTC timestamp
    for comp in cbom_data["components"]:
        prop_names = [p["name"] for p in comp["properties"]]
        assert "ecdat:x_tier" in prop_names
        assert "ecdat:y_max_years" in prop_names
        assert "ecdat:risk_level" in prop_names
        assert "ecdat:intent_class" in prop_names
        assert "ecdat:evidence_level" in prop_names
        assert "ecdat:exposure_profile" in prop_names
        assert "ecdat:r_q_score" in prop_names
        assert "ecdat:recommended_hybrid" in prop_names

    # 7. Verify Contagion Graph JSON export
    graph_file = out_path / "contagion_graph.json"
    assert graph_file.exists()
    with open(graph_file, "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    assert "nodes" in graph_data
    assert "links" in graph_data
    assert len(graph_data["nodes"]) > 0
    assert "Epidemiological R0 Dependency Contagion" in report_content

    # 8. Verify Visual Interactive HTML Report export (single unified report.html, no duplicate dashboard.html)
    assert "report_file_html" in result
    report_html_file = Path(result["report_file_html"])
    assert report_html_file.exists()
    dashboard_file = out_path / "dashboard.html"
    assert not dashboard_file.exists(), "dashboard.html should be removed in favor of single report.html"

    with open(report_html_file, "r", encoding="utf-8") as f:
        html_data = f.read()
    assert "<!DOCTYPE html>" in html_data
    assert "ECDAT — Cryptographic Discovery & Attestation Report" in html_data
    assert "Cryptographic Contagion Graph" in html_data
    assert "d3.forceSimulation" in html_data
    assert "crypto.subtle.digest" in html_data
    assert "asset-drawer" in html_data
    assert "cbom-search" in html_data
    assert "tab-btn-unknowns" in html_data
    assert "btn-suppress-op" in html_data
    assert "tab-pane-unknowns" in html_data
    assert result["merkle_root"] in html_data

    # 9. Verify Unknowns Ledger output
    assert "unknowns_count" in result
    assert "unknowns_ledger" in result
    assert isinstance(result["unknowns_ledger"], list)

    # 10. Phase 2: Signed in-toto / SLSA DSSE Attestation Envelope & Public Key
    attestation_file = out_path / "attestation.dsse.json"
    pubkey_file = out_path / "attestation_pubkey.pem"
    assert attestation_file.exists()
    assert pubkey_file.exists()

    from ecdat.attestation.verifier import verify_dsse_envelope_from_file
    is_valid, msg, stmt = verify_dsse_envelope_from_file(
        str(attestation_file),
        str(pubkey_file),
        expected_root_hex=result["merkle_root"],
    )
    assert is_valid is True, f"DSSE verification failed: {msg}"
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicate"]["builder"]["id"] == "https://github.com/SIH26164/ECDAT@v2.0.0"
    assert "negative_proof" in stmt["predicate"]["runDetails"]
    assert stmt["predicate"]["buildDefinition"]["internalParameters"]["transport_route_profile"] == result["route_profile"]

    # 11. Phase 2: CycloneDX Discussion #966 Attestation & Metadata
    metadata_props = {p["name"]: p["value"] for p in cbom_data["metadata"]["properties"]}
    assert metadata_props["ecdat:dsseSigned"] == "true"
    assert "ecdat:routeProfile" in metadata_props
    assert "ecdat:effectiveMtu" in metadata_props

    for comp in cbom_data["components"]:
        prop_names = [p["name"] for p in comp["properties"]]
        assert "ecdat:cams_agility_level" in prop_names
        assert "cdxAttestation" in comp
        att = comp["cdxAttestation"]["discussion966"]
        assert "reachabilityProof" in att
        assert "dataLifetime" in att
        assert "adversarialExposure" in att
        assert "camsMaturity" in att
        assert "pathMtuProfile" in att

    # 12. Phase 2: CISO Report CAMS, MTU, and DSSE Sections
    assert "Cryptographic Agility Maturity (CAMS Model)" in report_content
    assert "Transport Network Path MTU & PQC Fragmentation Readiness" in report_content
    assert "SLSA / in-toto Signed DSSE Attestation & Negative Proofs" in report_content

    # 13. Phase 2: HTML Dashboard DSSE & Attestation Integration
    assert "Signed in-toto / SLSA DSSE Attestation" in html_data
    assert "exportDsseEnvelope" in html_data
    assert "ATTESTATION_DATA" in html_data

def test_pipeline_constrained_mtu_scan(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    target_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    output_dir = str(tmp_path / "constrained_output")

    result = run_ecdat_scan(
        target_dir=target_dir,
        output_dir=output_dir,
        mtu_profile="constrained",
        override_mtu=1200,
    )

    assert result["route_profile"] == "CONSTRAINED"
    assert result["path_mtu"] == 1200

    cbom_file = Path(output_dir) / "enriched_cbom.json"
    with open(cbom_file, "r", encoding="utf-8") as f:
        cbom_data = json.load(f)

    for comp in cbom_data["components"]:
        att = comp["cdxAttestation"]["discussion966"]
        assert att["pathMtuProfile"]["routeProfile"] == "CONSTRAINED"
        assert att["pathMtuProfile"]["effectiveMtuBytes"] == 1200

def test_pipeline_cli_verify_attestation(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    target_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    output_dir = str(tmp_path / "cli_output")

    scan_res = run_ecdat_scan(target_dir=target_dir, output_dir=output_dir)
    att_file = Path(output_dir) / "attestation.dsse.json"
    pub_file = Path(output_dir) / "attestation_pubkey.pem"

    from ecdat.attestation.verifier import verify_dsse_envelope_from_file
    is_valid, msg, stmt = verify_dsse_envelope_from_file(
        str(att_file), str(pub_file), expected_root_hex=scan_res["merkle_root"]
    )
    assert is_valid is True
    assert "VERIFIED" in msg
    assert stmt is not None
    assert stmt["subject"][0]["name"] == "sample_crypto_app"




