import pytest
from ecdat.models import IntentClass, EvidenceLevel, XTier
from ecdat.intent.classifier import classify_intent, IntentClassifier
from ecdat.x_inference.ast_tracer import analyze_python_source

def test_intent_classification_operational_utility():
    # ETag header write
    intent, desc = classify_intent(var_name="digest", sink_call="res.setHeader('ETag', digest)")
    assert intent == IntentClass.OPERATIONAL_UTILITY
    assert "0% quantum" in desc

    # Cache key
    intent, desc = classify_intent(var_name="cache_key", sink_call="redis.setex(cache_key, 300, val)")
    assert intent == IntentClass.OPERATIONAL_UTILITY

def test_intent_classification_integrity_checksum():
    intent, desc = classify_intent(var_name="pkg_hash", sink_call="verify_checksum(pkg_hash)")
    assert intent == IntentClass.INTEGRITY_CHECKSUM

def test_intent_classification_authentication_signature():
    intent, desc = classify_intent(var_name="jwt_token", sink_call="jwt.sign(payload, secret)")
    assert intent == IntentClass.AUTHENTICATION_SIGNATURE

def test_intent_classification_confidentiality_envelope():
    intent, desc = classify_intent(var_name="encrypted_record", sink_call="db.session.add(encrypted_record)")
    assert intent == IntentClass.CONFIDENTIALITY_ENVELOPE

def test_ast_tracer_captures_intent_and_evidence():
    code = """
import hashlib
from Crypto.Cipher import AES

def generate_etag(data):
    etag_val = hashlib.sha256(data).hexdigest()
    response.setHeader('ETag', etag_val)
    return etag_val

def store_secret(patient_data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext = cipher.encrypt(patient_data)
    db.session.add(ciphertext)
    return ciphertext
"""
    results = analyze_python_source(code)
    assert len(results) >= 2

    # Verify etag_val is classified as OPERATIONAL_UTILITY
    etag_res = next(r for r in results if r.target_variable == "etag_val")
    assert etag_res.intent_class == IntentClass.OPERATIONAL_UTILITY
    assert etag_res.evidence_level == EvidenceLevel.E2_REACHABLE_PATH

    # Verify ciphertext is classified as CONFIDENTIALITY_ENVELOPE and OPERATIONAL data lifespan
    cipher_res = next(r for r in results if r.target_variable == "ciphertext")
    assert cipher_res.intent_class == IntentClass.CONFIDENTIALITY_ENVELOPE
    assert cipher_res.tier == XTier.OPERATIONAL
    assert cipher_res.evidence_level == EvidenceLevel.E2_REACHABLE_PATH
