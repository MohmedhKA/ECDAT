-- ECDAT Cryptographic Signature & Fingerprint Database Schema
-- Embedded SQLite relational engine for deterministic, zero-regex cryptographic discovery.

CREATE TABLE IF NOT EXISTS crypto_signatures (
    id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,           -- 'go', 'java', 'python', 'ruby', 'npm', 'cargo', 'generic'
    namespace TEXT NOT NULL,           -- e.g. 'crypto/des', 'javax.crypto.Cipher', 'hazmat.primitives', 'OpenSSL::Cipher'
    contract TEXT NOT NULL,            -- e.g. 'cipher.Block', 'cipher.AEAD', 'hash.Hash', 'crypto.Signer', 'CipherSpi'
    symbol TEXT NOT NULL,              -- e.g. 'NewCipher', 'getInstance', 'IDKey', 'new'
    normalized_alg TEXT NOT NULL,      -- e.g. 'DES', '3DES', 'AES', 'MD5', 'SHA-1', 'SHA-256', 'Argon2id', 'RSA-2048'
    primitive_type TEXT NOT NULL,      -- 'ENCRYPTION', 'HASH', 'SIGNATURE', 'KEY_EXCHANGE'
    key_size INTEGER,                  -- Standard key length in bits (or effective security bits)
    classical_security_level INTEGER,  -- Equivalent classical security bits (e.g. 56, 112, 128, 256)
    nist_quantum_security_level INTEGER, -- NIST PQC Level 0-5 (0 = broken/vulnerable, 5 = highest)
    default_risk TEXT NOT NULL,        -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'
    pqc_recommendation TEXT NOT NULL,  -- Post-quantum migration guidance
    cwe TEXT,                          -- e.g. 'CWE-327', 'CWE-328', 'CWE-326'
    description TEXT                   -- Human-readable description
);

CREATE TABLE IF NOT EXISTS crypto_fingerprints (
    fingerprint_hash TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    contract TEXT NOT NULL,
    param_shape TEXT,                  -- Parameter shape signature (e.g. 'k,iv,pt' or 'pwd,salt,iter,len')
    signature_id TEXT NOT NULL,
    FOREIGN KEY(signature_id) REFERENCES crypto_signatures(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS package_manifest_rules (
    ecosystem TEXT NOT NULL,           -- 'npm', 'go', 'cargo', 'pypi'
    package_name TEXT NOT NULL,        -- Package import / manifest identifier
    category TEXT NOT NULL,            -- 'POST_QUANTUM', 'CLASSICAL_ASYMMETRIC', 'BLOCKCHAIN_CORE', 'SYMMETRIC_OR_HASH'
    pqc_readiness TEXT NOT NULL,       -- 'MIGRATED_PQC', 'VULNERABLE_CLASSICAL', 'SAFE_SYMMETRIC', 'CLASSICAL_HYBRID'
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package_name)
);

CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Performance Indices for sub-millisecond lookups
CREATE INDEX IF NOT EXISTS idx_sig_eco_contract_sym ON crypto_signatures(ecosystem, contract, symbol);
CREATE INDEX IF NOT EXISTS idx_sig_eco_namespace ON crypto_signatures(ecosystem, namespace);
CREATE INDEX IF NOT EXISTS idx_sig_norm_alg ON crypto_signatures(normalized_alg);
CREATE INDEX IF NOT EXISTS idx_pkg_eco_name ON package_manifest_rules(ecosystem, package_name);
