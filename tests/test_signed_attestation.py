import pytest
import json
import base64
from ecdat.attestation import (
    build_intoto_statement,
    create_signed_dsse_envelope,
    verify_dsse_envelope,
    generate_signing_keypair,
    export_public_key_pem,
)

def test_signed_dsse_envelope_lifecycle():
    project_name = "test_project"
    root_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # 1. Build statement
    statement = build_intoto_statement(
        project_name=project_name,
        merkle_root_hex=root_hex,
        target_path="/app",
        total_assets=5,
        evidence_distribution={"E1_STATIC_ARTIFACT": 4, "E3_CONFIG_CONFIRMED": 1},
        intent_distribution={"CONFIDENTIALITY_ENVELOPE": 3, "AUTHENTICATION_SIGNATURE": 2},
        cams_distribution={"0": 4, "1": 1},
        route_profile="STANDARD",
        effective_mtu=1500,
        unknowns_ledger=[],
    )

    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"][0]["digest"]["sha256"] == root_hex
    assert "negative_proof" in statement["predicate"]["runDetails"]

    # 2. Sign envelope
    envelope, pubkey, pubkey_pem = create_signed_dsse_envelope(statement)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert len(envelope["signatures"]) >= 1
    assert "ed25519:" in envelope["signatures"][0]["keyid"]

    # 3. Verify envelope with matching root
    is_valid, msg, parsed_stmt = verify_dsse_envelope(envelope, pubkey_pem, expected_root_hex=root_hex)
    assert is_valid is True
    assert "VERIFIED" in msg
    assert parsed_stmt["subject"][0]["name"] == project_name

def test_signed_dsse_envelope_tamper_detection():
    root_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    statement = build_intoto_statement(
        project_name="tamper_test",
        merkle_root_hex=root_hex,
        target_path="/app",
        total_assets=1,
        evidence_distribution={"E1_STATIC_ARTIFACT": 1},
        intent_distribution={"CONFIDENTIALITY_ENVELOPE": 1},
        cams_distribution={"0": 1},
        route_profile="STANDARD",
        effective_mtu=1500,
        unknowns_ledger=[],
    )
    envelope, _, pubkey_pem = create_signed_dsse_envelope(statement)

    # Decode payload, alter statement (modify asset count), re-encode without signature
    payload_bytes = base64.b64decode(envelope["payload"])
    stmt_obj = json.loads(payload_bytes.decode("utf-8"))
    stmt_obj["predicate"]["runDetails"]["total_cryptographic_assets"] = 999
    tampered_bytes = json.dumps(stmt_obj).encode("utf-8")
    tampered_envelope = dict(envelope)
    tampered_envelope["payload"] = base64.b64encode(tampered_bytes).decode("utf-8")

    is_valid, msg, _ = verify_dsse_envelope(tampered_envelope, pubkey_pem, expected_root_hex=root_hex)
    assert is_valid is False
    assert "Tampered payload detected" in msg or "signature verification failed" in msg

def test_signed_dsse_envelope_root_mismatch():
    root_hex = "1111111111111111111111111111111111111111111111111111111111111111"
    wrong_root = "2222222222222222222222222222222222222222222222222222222222222222"

    statement = build_intoto_statement(
        project_name="mismatch_test",
        merkle_root_hex=root_hex,
        target_path="/app",
        total_assets=1,
        evidence_distribution={},
        intent_distribution={},
        cams_distribution={},
        route_profile="STANDARD",
        effective_mtu=1500,
        unknowns_ledger=[],
    )
    envelope, _, pubkey_pem = create_signed_dsse_envelope(statement)

    is_valid, msg, _ = verify_dsse_envelope(envelope, pubkey_pem, expected_root_hex=wrong_root)
    assert is_valid is False
    assert "ROOT MISMATCH" in msg
