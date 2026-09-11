import pytest
from ecdat.models import XTier
from ecdat.x_inference.ast_tracer import analyze_python_source

def test_ephemeral_socket_write():
    code = """
def handle_tls_session(client_sock, plain_data):
    session_key = cipher.encrypt(plain_data)
    client_sock.sendall(session_key)
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "session_key"
    assert res.tier == XTier.EPHEMERAL
    assert res.confidence == "HIGH"
    assert res.review_required is False
    assert "Network socket" in res.evidence

def test_ephemeral_explicit_deletion():
    code = """
def transient_sign(message):
    token = hmac.sign(message)
    del token
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "token"
    assert res.tier == XTier.EPHEMERAL
    assert res.confidence == "HIGH"
    assert "del token" in res.evidence

def test_short_term_redis_cache():
    code = """
def cache_session(user_id, token_data):
    auth_token = cipher.encrypt(token_data)
    redis.setex(f"session:{user_id}", 3600, auth_token)
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "auth_token"
    assert res.tier == XTier.SHORT_TERM
    assert res.confidence == "HIGH"
    assert "redis.setex" in res.evidence

def test_operational_database_insert():
    code = """
def register_user(db_session, user_card):
    encrypted_pan = cipher.encrypt(user_card)
    db.session.add(encrypted_pan)
    db.session.commit()
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "encrypted_pan"
    assert res.tier == XTier.OPERATIONAL
    assert res.confidence == "HIGH"
    assert "database persistence sink" in res.evidence

def test_archival_cloud_s3_upload():
    code = """
def archive_backup(s3_client, payload):
    backup_blob = cipher.encrypt(payload)
    s3.put_object(Bucket="corp-archive", Key="backup.enc", Body=backup_blob)
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "backup_blob"
    assert res.tier == XTier.ARCHIVAL
    assert res.confidence == "HIGH"
    assert "cloud object storage" in res.evidence

def test_human_review_external_call():
    code = """
def process_sensitive_data(external_vendor_api, raw_data):
    opaque_blob = cipher.encrypt(raw_data)
    external_vendor_api.dispatch_record(opaque_blob)
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "opaque_blob"
    assert res.tier == XTier.HUMAN_REVIEW
    assert res.confidence == "LOW"
    assert res.review_required is True
    assert "unanalyzed function 'external_vendor_api.dispatch_record'" in res.evidence

def test_unpersisted_volatile_memory():
    code = """
def compute_mac(payload):
    mac_tag = cipher.encrypt(payload)
    return mac_tag
"""
    results = analyze_python_source(code)
    assert len(results) == 1
    res = results[0]
    assert res.target_variable == "mac_tag"
    assert res.tier == XTier.EPHEMERAL
    assert res.confidence == "MEDIUM"
    assert res.review_required is False
    assert "volatile memory scope" in res.evidence
