import pytest
from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.agility.recommender import recommend_pqc_migration
from ecdat.agility.buffer_audit import audit_python_buffer_allocations

def test_ecdsa_signature_recommendation():
    asset = CryptoAsset(
        asset_id="sig-1",
        component_name="identity-service",
        algorithm="ECDSA-P256",
        key_size=256,
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/id/auth.py",
        x_tier=XTier.OPERATIONAL,
    )
    rec = recommend_pqc_migration(asset)
    assert "ML-DSA-65" in rec.recommended_pqc_standalone
    assert "Composite" in rec.recommended_hybrid
    assert rec.size_overhead_factor == 51.7
    assert "NIST FIPS 204" in rec.target_standard
    assert "51.7x" in rec.implementation_guidance

def test_rsa_key_exchange_recommendation():
    asset = CryptoAsset(
        asset_id="kem-1",
        component_name="tls-gateway",
        algorithm="RSA-2048",
        key_size=2048,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/gateway/tls.py",
        x_tier=XTier.EPHEMERAL,
    )
    rec = recommend_pqc_migration(asset)
    assert "ML-KEM-768" in rec.recommended_pqc_standalone
    assert "X25519MLKEM768" in rec.recommended_hybrid
    assert "RFC 9180" in rec.target_standard
    assert "NIST FIPS 203" in rec.target_standard
    assert rec.size_overhead_factor == 34.0

def test_symmetric_aes128_recommendation():
    asset = CryptoAsset(
        asset_id="sym-1",
        component_name="vault",
        algorithm="AES-128-CBC",
        key_size=128,
        primitive_type=PrimitiveType.ENCRYPTION,
        file_path="src/vault/store.py",
        x_tier=XTier.ARCHIVAL,
    )
    rec = recommend_pqc_migration(asset)
    assert "AES-256-GCM" in rec.recommended_pqc_standalone
    assert "Grover" in rec.implementation_guidance

def test_buffer_hazard_detection_bytearray():
    code = """
def sign_transaction(private_key, data):
    sig_buffer = bytearray(64)
    # writes 64-byte ECDSA signature
    return sig_buffer
"""
    hazards = audit_python_buffer_allocations(code, target_pqc_bytes=3309)
    assert len(hazards) == 1
    h = hazards[0]
    assert h.variable_name == "sig_buffer"
    assert h.allocated_bytes == 64
    assert h.required_bytes_pqc == 3309
    assert h.severity == "CRITICAL"
    assert "FIXED BUFFER HAZARD" in h.message

def test_buffer_hazard_detection_bytes_mult():
    code = """
def verify_block():
    rsa_buf = b"\\x00" * 256
    return rsa_buf
"""
    hazards = audit_python_buffer_allocations(code, target_pqc_bytes=3309)
    assert len(hazards) == 1
    h = hazards[0]
    assert h.variable_name == "rsa_buf"
    assert h.allocated_bytes == 256
    assert h.required_bytes_pqc == 3309
    assert h.severity == "CRITICAL"

def test_safe_buffer_not_flagged():
    code = """
def large_buffer():
    safe_buf = bytearray(4096)
    return safe_buf
"""
    hazards = audit_python_buffer_allocations(code, target_pqc_bytes=3309)
    assert len(hazards) == 0
