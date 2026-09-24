"""
Unit tests for ECDAT in-kernel eBPF shared-library observer (Pillar 4).
"""

import pytest
from pathlib import Path

from ecdat.runtime.ebpf_observer import EBPFObserver
from ecdat.models import EvidenceLevel, PrimitiveType
from ecdat.pipeline import run_ecdat_scan

def test_ebpf_observer_availability_and_script_gen(tmp_path):
    observer = EBPFObserver()
    # is_available() should return a boolean safely without exceptions
    avail = observer.is_available()
    assert isinstance(avail, bool)

    # Test script generation
    script_file = tmp_path / "crypto_trace.bt"
    res_path = observer.generate_tracer_script(script_file)
    assert res_path.exists()
    content = res_path.read_text(encoding="utf-8")
    assert "EVP_EncryptInit_ex" in content
    assert "EVP_DigestInit_ex" in content
    assert "SSL_set_cipher_list" in content

def test_ebpf_parse_trace_log_honest_labels(tmp_path):
    observer = EBPFObserver()
    log_file = tmp_path / "test_trace.log"
    # Simulated log lines from bpftrace
    log_content = (
        "EVP_ENCRYPT_INIT: pid=4021 comm=nginx cipher=AES-256-GCM\n"
        "EVP_ENCRYPT_INIT: pid=4022 comm=node\n"
        "EVP_DIGEST_INIT: pid=4023 comm=ruby md=SHA-256\n"
        "EVP_DIGEST_INIT: pid=4024 comm=python\n"
        "SSL_CIPHER_LIST: pid=4025 comm=curl str=ECDHE-RSA-AES128-GCM-SHA256:HIGH\n"
    )
    log_file.write_text(log_content, encoding="utf-8")

    assets = observer.parse_trace_log(log_file)
    assert len(assets) == 5

    # Asset 1: Explicit cipher AES-256-GCM
    a1 = assets[0]
    assert a1.algorithm == "AES-256-GCM"
    assert a1.evidence_level == EvidenceLevel.E4_RUNTIME_OBSERVED
    assert a1.component_name == "nginx:4021:evp_encrypt"
    assert a1.raw_properties["pid"] == "4021"

    # Asset 2: Unmodeled cipher -> OPENSSL-EVP-CIPHER (not fabricated)
    a2 = assets[1]
    assert a2.algorithm == "OPENSSL-EVP-CIPHER"
    assert a2.x_confidence == "MEDIUM"
    assert a2.component_name == "node:4022:evp_encrypt"

    # Asset 3: Explicit digest SHA-256
    a3 = assets[2]
    assert a3.algorithm == "SHA-256"
    assert a3.primitive_type == PrimitiveType.HASH

    # Asset 4: Unmodeled digest -> OPENSSL-EVP-DIGEST (not fabricated)
    a4 = assets[3]
    assert a4.algorithm == "OPENSSL-EVP-DIGEST"
    assert a4.x_confidence == "MEDIUM"

    # Asset 5: SSL cipher list
    a5 = assets[4]
    assert a5.algorithm == "ECDHE-RSA-AES128-GCM-SHA256"
    assert a5.primitive_type == PrimitiveType.KEY_EXCHANGE

def test_ebpf_execute_trace_missing_prerequisites():
    observer = EBPFObserver()
    if not observer.is_available():
        with pytest.raises(RuntimeError, match="eBPF runtime observation unavailable"):
            observer.execute_live_trace(duration_seconds=1)

def test_pipeline_ingest_ebpf_trace_log(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    target_dir = str(repo_root / "testbeds" / "sample_crypto_app")
    out_dir = str(tmp_path / "scan_ebpf_out")

    # Create dummy eBPF trace log
    log_file = tmp_path / "runtime.log"
    log_file.write_text(
        "EVP_ENCRYPT_INIT: pid=9999 comm=microservice cipher=AES-256-GCM\n",
        encoding="utf-8"
    )

    result = run_ecdat_scan(
        target_dir=target_dir,
        output_dir=out_dir,
        ebpf_log=str(log_file),
    )

    assert result["ebpf_assets_count"] == 1
    # Check that CBOM contains the runtime observed asset
    cbom_file = Path(out_dir) / "enriched_cbom.json"
    assert cbom_file.exists()
    import json
    with open(cbom_file, "r", encoding="utf-8") as f:
        cbom = json.load(f)
    comp_names = [c["name"] for c in cbom["components"]]
    assert any("microservice:9999" in name for name in comp_names)
    correlated_comp = next(c for c in cbom["components"] if "microservice:9999" in c["name"])
    props = {p["name"]: p["value"] for p in correlated_comp.get("properties", [])}
    assert props.get("ecdat:evidence_level") == "E5_CORRELATED_SIGNED"

