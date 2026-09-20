import json
import sys
from pathlib import Path
import pytest
from click.testing import CliRunner

from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.report_sarif import generate_sarif_dict, export_sarif_file
from ecdat.gate import evaluate_quality_gate, GateResult
from ecdat.pipeline import cli, main, run_pipeline, run_ecdat_scan


def _make_test_asset(
    asset_id: str,
    component_name: str,
    algorithm: str,
    primitive_type: PrimitiveType,
    key_size: int,
    file_path: str,
    line_number: int,
    x_tier: XTier = XTier.SHORT_TERM,
    risk_level: str = "HIGH",
    raw_properties: dict = None,
) -> CryptoAsset:
    """Helper to construct CryptoAsset for testing."""
    raw = raw_properties or {}
    raw["risk_level"] = risk_level
    raw["ecdat:risk_level"] = risk_level
    return CryptoAsset(
        asset_id=asset_id,
        component_name=component_name,
        algorithm=algorithm,
        key_size=key_size,
        primitive_type=primitive_type,
        file_path=file_path,
        line_number=line_number,
        x_tier=x_tier,
        risk_level=risk_level,
        raw_properties=raw,
    )


def test_zero_regex_compliance():
    """Verify strict Zero-Regex rule across new modules and test suite."""
    repo_root = Path(__file__).resolve().parent.parent
    target_files = [
        repo_root / "ecdat" / "report_sarif.py",
        repo_root / "ecdat" / "gate.py",
    ]
    for fpath in target_files:
        assert fpath.exists(), f"Expected file {fpath} does not exist"
        content = fpath.read_text(encoding="utf-8")
        assert "import re" not in content, f"Zero-Regex violation: 'import re' found in {fpath}"
        assert "from re import" not in content, f"Zero-Regex violation: 'from re import' found in {fpath}"
        assert "re.compile" not in content, f"Zero-Regex violation: 're.compile' found in {fpath}"
        assert "re.search" not in content, f"Zero-Regex violation: 're.search' found in {fpath}"

    test_lines = (repo_root / "tests" / "test_sarif_and_gate.py").read_text(encoding="utf-8").splitlines()
    for line in test_lines:
        stripped = line.strip()
        if stripped.startswith("import ") and not stripped.startswith("assert"):
            mod = stripped.split()[1].split(".")[0]
            assert mod != "re", f"Zero-Regex violation in test suite: {line}"
        if stripped.startswith("from ") and not stripped.startswith("assert"):
            mod = stripped.split()[1].split(".")[0]
            assert mod != "re", f"Zero-Regex violation in test suite: {line}"


def test_sarif_dict_schema_and_rules():
    """Test OASIS SARIF 2.1.0 schema, rule definitions, and result mappings."""
    assets = [
        _make_test_asset(
            asset_id="ASSET-001",
            component_name="legacy_auth",
            algorithm="MD5",
            primitive_type=PrimitiveType.HASH,
            key_size=128,
            file_path="src/auth.py",
            line_number=42,
            risk_level="CRITICAL",
        ),
        _make_test_asset(
            asset_id="ASSET-002",
            component_name="weak_crypto",
            algorithm="RSA-1024",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            key_size=1024,
            file_path="src/session.py",
            line_number=88,
            risk_level="CRITICAL",
        ),
        _make_test_asset(
            asset_id="ASSET-003",
            component_name="tls_handshake",
            algorithm="ECDH-P256",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            key_size=256,
            file_path="src/tls.py",
            line_number=105,
            risk_level="HIGH",
        ),
        _make_test_asset(
            asset_id="ASSET-004",
            component_name="jwt_signer",
            algorithm="ECDSA-P256",
            primitive_type=PrimitiveType.SIGNATURE,
            key_size=256,
            file_path="src/jwt.py",
            line_number=15,
            risk_level="HIGH",
        ),
        _make_test_asset(
            asset_id="ASSET-005",
            component_name="bulk_enc",
            algorithm="AES-128-CBC",
            primitive_type=PrimitiveType.ENCRYPTION,
            key_size=128,
            file_path="src/storage.py",
            line_number=204,
            risk_level="MEDIUM",
        ),
        _make_test_asset(
            asset_id="ASSET-006",
            component_name="post_quantum_kem",
            algorithm="ML-KEM-768",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            key_size=768,
            file_path="src/pqc.py",
            line_number=50,
            risk_level="LOW",
        ),
    ]

    sarif = generate_sarif_dict(assets)

    # 1. Top-level SARIF schema validation
    assert sarif["version"] == "2.1.0"
    assert "sarif" in sarif["$schema"].lower()
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ECDAT"
    assert driver["version"] == "2.0.0"

    # 2. Rule catalog validation
    rule_ids = {r["id"] for r in driver["rules"]}
    expected_rules = {
        "ECDAT-CWE-326",
        "ECDAT-CWE-327",
        "ECDAT-PQC-MIGRATE-FIPS203",
        "ECDAT-PQC-MIGRATE-FIPS204",
    }
    assert expected_rules.issubset(rule_ids), f"Missing rules: {expected_rules - rule_ids}"

    # 3. Results validation
    results = run["results"]
    assert len(results) == len(assets)

    # Asset 001: MD5 -> CWE-327, error
    assert results[0]["ruleId"] == "ECDAT-CWE-327"
    assert results[0]["level"] == "error"
    assert "MD5" in results[0]["message"]["text"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/auth.py"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

    # Asset 002: RSA-1024 -> CWE-326 (weak key length < 2048), error
    assert results[1]["ruleId"] == "ECDAT-CWE-326"
    assert results[1]["level"] == "error"
    assert "RSA-1024" in results[1]["message"]["text"]
    assert results[1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 88

    # Asset 003: ECDH-P256 -> PQC-MIGRATE-FIPS203 (key exchange), error
    assert results[2]["ruleId"] == "ECDAT-PQC-MIGRATE-FIPS203"
    assert results[2]["level"] == "error"
    assert "ML-KEM" in results[2]["message"]["text"]

    # Asset 004: ECDSA-P256 -> PQC-MIGRATE-FIPS204 (signature), error
    assert results[3]["ruleId"] == "ECDAT-PQC-MIGRATE-FIPS204"
    assert results[3]["level"] == "error"
    assert "ML-DSA" in results[3]["message"]["text"]

    # Asset 005: AES-128-CBC -> MEDIUM risk maps to 'warning'
    assert results[4]["level"] == "warning"

    # Asset 006: ML-KEM-768 -> LOW risk maps to 'note'
    assert results[5]["level"] == "note"


def test_sarif_file_export(tmp_path):
    """Test exporting SARIF 2.1.0 dictionary to formatted JSON file on disk."""
    assets = [
        _make_test_asset(
            asset_id="ASSET-001",
            component_name="crypto_service",
            algorithm="RSA-2048",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            key_size=2048,
            file_path="service/vault.py",
            line_number=33,
            risk_level="HIGH",
        )
    ]
    out_file = tmp_path / "output" / "scan.sarif.json"
    exported_path = export_sarif_file(assets, out_file)

    assert exported_path == out_file
    assert out_file.exists()

    raw_text = out_file.read_text(encoding="utf-8")
    assert "{\n  \"$schema\"" in raw_text or "{\n  \"version\"" in raw_text

    data = json.loads(raw_text)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "service/vault.py"


def test_gate_evaluation_passed_when_violations_within_threshold():
    """Test quality gate passes when violations <= max_allowed."""
    assets = [
        _make_test_asset("A1", "c1", "DES", PrimitiveType.ENCRYPTION, 56, "f1.py", 1, risk_level="CRITICAL"),
        _make_test_asset("A2", "c2", "AES-256-GCM", PrimitiveType.ENCRYPTION, 256, "f2.py", 2, risk_level="LOW"),
    ]
    # 1 CRITICAL violation, max_allowed=1 -> Should pass
    result = evaluate_quality_gate(assets, fail_on="CRITICAL", max_allowed=1)
    assert isinstance(result, GateResult)
    assert result.passed is True
    assert result.exit_code == 0
    assert len(result.violations) == 1
    assert result.violations[0].asset_id == "A1"
    assert result.max_allowed == 1
    assert result.threshold == "CRITICAL"
    assert "PASSED" in result.banner
    assert "CRITICAL" in result.banner


def test_gate_evaluation_failed_when_violations_exceed_threshold():
    """Test quality gate fails when violations > max_allowed."""
    assets = [
        _make_test_asset("A1", "c1", "MD5", PrimitiveType.HASH, 128, "f1.py", 1, risk_level="CRITICAL"),
        _make_test_asset("A2", "c2", "DES", PrimitiveType.ENCRYPTION, 56, "f2.py", 2, risk_level="CRITICAL"),
        _make_test_asset("A3", "c3", "AES-256", PrimitiveType.ENCRYPTION, 256, "f3.py", 3, risk_level="LOW"),
    ]
    # 2 CRITICAL violations, max_allowed=0 -> Should fail
    result = evaluate_quality_gate(assets, fail_on="CRITICAL", max_allowed=0)
    assert result.passed is False
    assert result.exit_code == 1
    assert len(result.violations) == 2
    assert "FAILED" in result.banner
    assert result.summary["critical_count"] == 2
    assert result.summary["violations_count"] == 2


def test_gate_severity_threshold_filtering():
    """Test severity threshold filtering: CRITICAL vs HIGH vs MEDIUM."""
    assets = [
        _make_test_asset("A1", "c1", "DES", PrimitiveType.ENCRYPTION, 56, "f1.py", 1, risk_level="CRITICAL"),
        _make_test_asset("A2", "c2", "RSA-2048", PrimitiveType.KEY_EXCHANGE, 2048, "f2.py", 2, risk_level="HIGH"),
        _make_test_asset("A3", "c3", "AES-128-CBC", PrimitiveType.ENCRYPTION, 128, "f3.py", 3, risk_level="MEDIUM"),
        _make_test_asset("A4", "c4", "ML-KEM-768", PrimitiveType.KEY_EXCHANGE, 768, "f4.py", 4, risk_level="LOW"),
    ]

    # fail_on='CRITICAL' -> only A1
    res_crit = evaluate_quality_gate(assets, fail_on="CRITICAL", max_allowed=10)
    assert [a.asset_id for a in res_crit.violations] == ["A1"]

    # fail_on='HIGH' -> A1 and A2
    res_high = evaluate_quality_gate(assets, fail_on="HIGH", max_allowed=10)
    assert [a.asset_id for a in res_high.violations] == ["A1", "A2"]

    # fail_on='MEDIUM' -> A1, A2, and A3
    res_med = evaluate_quality_gate(assets, fail_on="MEDIUM", max_allowed=10)
    assert [a.asset_id for a in res_med.violations] == ["A1", "A2", "A3"]


def test_cli_gate_command_click_runner(tmp_path):
    """Test Click CLI invocation of the gate subcommand."""
    repo_root = Path(__file__).resolve().parent.parent
    sample_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    sarif_file = tmp_path / "click_gate.sarif.json"

    runner = CliRunner()

    # 1. Test passing gate with high max_allowed
    res_pass = runner.invoke(
        cli,
        [
            "gate",
            "--target", sample_dir,
            "--fail-on", "CRITICAL",
            "--max-allowed", "100",
            "--sarif", str(sarif_file),
        ],
    )
    assert res_pass.exit_code == 0
    assert "QUALITY GATE: PASSED" in res_pass.output
    assert sarif_file.exists()

    # 2. Test failing gate with max_allowed 0 when violations exist
    res_fail = runner.invoke(
        cli,
        [
            "gate",
            "--target", sample_dir,
            "--fail-on", "HIGH",
            "--max-allowed", "0",
        ],
    )
    assert res_fail.exit_code == 1
    assert "QUALITY GATE: FAILED" in res_fail.output


def test_cli_gate_command_argparse(monkeypatch, tmp_path):
    """Test argparse CLI invocation of the gate subcommand via main()."""
    repo_root = Path(__file__).resolve().parent.parent
    sample_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    sarif_file = tmp_path / "argparse_gate.sarif.json"

    # Pass case
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ecdat",
            "gate",
            "--target", sample_dir,
            "--fail-on", "CRITICAL",
            "--max-allowed", "100",
            "--sarif", str(sarif_file),
        ],
    )
    ret_code = main()
    assert ret_code == 0
    assert sarif_file.exists()


def test_pipeline_scan_generates_sarif(tmp_path):
    """Test that run_ecdat_scan automatically produces cbom.sarif.json in output_dir."""
    repo_root = Path(__file__).resolve().parent.parent
    sample_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    out_dir = str(tmp_path / "scan_out")

    result = run_ecdat_scan(target_dir=sample_dir, output_dir=out_dir)

    sarif_file = Path(out_dir) / "cbom.sarif.json"
    assert sarif_file.exists()
    assert "sarif_file" in result
    assert result["sarif_file"] == str(sarif_file)

    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == result["total_assets"]
