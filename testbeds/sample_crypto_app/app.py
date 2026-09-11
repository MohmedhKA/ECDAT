"""
Sample Microservices Application with Mixed Cryptographic Estates
Used as ground-truth testbed for ECDAT discovery and analysis.
"""

def gateway_tls_handshake(client_socket, client_hello):
    """Service 1: Ephemeral TLS session handshake (X25519/ECDH)"""
    session_key = cipher.encrypt(client_hello)
    client_socket.sendall(session_key)
    return True

def auth_token_cache(redis_client, user_id, user_claims):
    """Service 2: Short-term session token cached with TTL"""
    auth_token = cipher.encrypt(user_claims)
    redis.setex(f"session:{user_id}", 1800, auth_token)
    return auth_token

def payment_vault_record(db_session, card_pan):
    """Service 3: Operational cardholder data (relational DB)"""
    encrypted_pan = cipher.encrypt(card_pan)
    db.session.add(encrypted_pan)
    db.session.commit()
    return encrypted_pan

def compliance_audit_backup(s3_client, audit_log_data):
    """Service 4: Archival compliance backup (S3 cloud storage)"""
    encrypted_archive = cipher.encrypt(audit_log_data)
    s3.put_object(Bucket="compliance-vault", Key="audit_2026.enc", Body=encrypted_archive)
    return True

def ledger_block_signer(private_key, block_header):
    """Service 5: Block signature with fixed 64-byte buffer hazard"""
    sig_buffer = bytearray(64)  # Fixed buffer for classical ECDSA P-256
    signature = cipher.sign(private_key, block_header)
    return signature

def external_crm_dispatch(vendor_client, customer_record):
    """Service 6: Taint flows across module boundary to unanalyzed function"""
    token_blob = cipher.encrypt(customer_record)
    vendor_client.sync_data(token_blob)  # Unanalyzed external sink -> HUMAN_REVIEW
    return token_blob
