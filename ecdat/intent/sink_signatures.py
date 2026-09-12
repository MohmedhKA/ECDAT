"""
ECDAT DSIS Intent Sink Signatures:
Pattern catalogs mapping terminal sinks, method calls, headers, and variable naming conventions
to the 4-class functional security intent lattice.
"""

from typing import List, Dict, Any
from ecdat.models import IntentClass

# Ordered intent signature groups. Evaluated hierarchically:
# OPERATIONAL_UTILITY -> INTEGRITY_CHECKSUM -> AUTHENTICATION_SIGNATURE -> CONFIDENTIALITY_ENVELOPE
INTENT_SIGNATURE_CATALOG: List[Dict[str, Any]] = [
    {
        "intent": IntentClass.OPERATIONAL_UTILITY,
        "description": "Operational cache, HTTP ETag, in-memory hash table, or deduplication utility (0% quantum exploit risk)",
        "call_patterns": [
            "setheader('etag'", 'setheader("etag"', "headers['etag']", "headers[\"etag\"]",
            "set_header('etag'", 'set_header("etag"', "response.etag", "res.etag",
            "cache.set", "cache.add", "cache.get", "redis.setex", "redis.set",
            "memcached.set", "memcache.set", "hashmap.put", "map.set",
            "dict[", "cache_key", "dedup_key", "bloom_filter",
        ],
        "var_patterns": [
            "etag", "cache_key", "hash_key", "dedup", "map_key", "dict_key",
            "digest_key", "etag_val", "cache_val"
        ],
    },
    {
        "intent": IntentClass.INTEGRITY_CHECKSUM,
        "description": "File integrity verification, build checksum, or short-lived data validation",
        "call_patterns": [
            "verify_checksum", "compute_checksum", "sha256sum", "md5sum",
            "file_hash", "verify_file", "integrity_check", "build_hash",
            "package_hash", "artifact_hash", "git_hash", "commit_hash",
        ],
        "var_patterns": [
            "checksum", "file_hash", "build_hash", "artifact_checksum",
            "package_digest", "integrity_digest"
        ],
    },
    {
        "intent": IntentClass.AUTHENTICATION_SIGNATURE,
        "description": "Identity verification, authentication token, mTLS handshake, or digital signature",
        "call_patterns": [
            "jwt.sign", "jwt.verify", "crypto.sign", "crypto.verify",
            "sign_token", "verify_token", "authenticate", "verify_signature",
            "oauth", "saml", "auth_header", "bearer", "authorization",
            "client_cert", "mtls", "tls_handshake", "keystage_auth",
            "blindsignature", "blind_sign", "signblinded",
        ],
        "var_patterns": [
            "jwt", "auth_token", "id_token", "session_token", "access_token",
            "bearer_token", "signature", "signed_claim", "client_sig",
            "blind_sig", "auth_sig"
        ],
    },
    {
        "intent": IntentClass.CONFIDENTIALITY_ENVELOPE,
        "description": "Confidential data-at-rest encryption, relational/document database insertion, or secure transport",
        "call_patterns": [
            "session.add", "session.commit", "session.save", "db.session",
            "repository.save", "cursor.execute", "preparedstatement",
            "insert_one", "insert_many", "save_record", "db.query",
            "s3.put_object", "s3.upload_file", "blobclient.upload_blob",
            "bucket.blob", "cloud_storage", "open(", "write(",
            "cipher.update", "cipher.finalize", "createcipheriv", "encrypt(",
            "seal(", "box.encrypt",
        ],
        "var_patterns": [
            "ciphertext", "encrypted", "secret_payload", "vault_data",
            "cipher_bytes", "enc_record", "sealed_box", "encrypted_data"
        ],
    },
]
