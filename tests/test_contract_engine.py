"""
Unit Tests for ECDAT Autonomous Cryptographic Contract Engine:
Verifies SQLite signature database, multi-language contract visitors (Go, Java, Python, Ruby),
type-morphic parameter arity, and server TLS configuration scanner.
"""

import pytest
from pathlib import Path
from ecdat.models import PrimitiveType, XTier, EvidenceLevel
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.go_contracts import GoContractEngine
from ecdat.scanners.contracts.java_contracts import JavaContractEngine
from ecdat.scanners.contracts.python_contracts import PythonContractEngine
from ecdat.scanners.contracts.ruby_contracts import RubyContractEngine
from ecdat.scanners.type_morphism import TypeMorphismClassifier
from ecdat.scanners.config_scanner import ConfigScanner

def test_sqlite_signature_db():
    db = get_signature_db()

    # Go lookup
    aes_sig = db.lookup_namespace_symbol("go", "crypto/aes", "NewCipher")
    assert aes_sig is not None
    assert aes_sig["normalized_alg"] == "AES-256-GCM"
    assert aes_sig["primitive_type"] == "ENCRYPTION"

    des_sig = db.lookup_namespace_symbol("go", "crypto/des", "NewCipher")
    assert des_sig is not None
    assert des_sig["normalized_alg"] == "DES"
    assert des_sig["default_risk"] == "CRITICAL"
    assert des_sig["cwe"] == "CWE-327"

    # Java lookup
    j_sig = db.lookup_algorithm("AES")
    assert j_sig is not None
    assert "AES" in j_sig["normalized_alg"]

    # Package rule lookup
    pkg = db.lookup_package("npm", "@noble/post-quantum")
    assert pkg is not None
    assert pkg["pqc_readiness"] == "MIGRATED_PQC"

def test_go_contract_engine_ciphers_and_hashes(tmp_path):
    go_code = """
package main
import (
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"
    "crypto/md5"
    "crypto/sha256"
    "golang.org/x/crypto/argon2"
)
func demo() {
    k := []byte("0123456789abcdef0123456789abcdef")
    block, _ := aes.NewCipher(k)
    _, _ = cipher.NewGCM(block)
    _, _ = des.NewCipher([]byte("12345678"))
    _ = md5.New()
    _ = sha256.Sum256([]byte("hello"))
    _ = argon2.IDKey([]byte("password"), []byte("saltsalt"), 1, 64*1024, 4, 32)
}
"""
    f = tmp_path / "main.go"
    f.write_text(go_code, encoding="utf-8")

    engine = GoContractEngine()
    assets = engine.scan_file(f, tmp_path)

    algs = {a.algorithm for a in assets}
    assert "AES-256-GCM" in algs
    assert "AES-GCM" in algs
    assert "DES" in algs
    assert "MD5" in algs
    assert "SHA-256" in algs
    assert "Argon2id" in algs

    des_asset = next(a for a in assets if a.algorithm == "DES")
    assert des_asset.raw_properties.get("ecdat:risk_level") == "CRITICAL"
    assert des_asset.raw_properties.get("cwe") == "CWE-327"

def test_java_contract_engine_spi_and_quarantine(tmp_path):
    java_code = """
package com.example;
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class TestCrypto {
    public void test() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest md = MessageDigest.getInstance("MD5");
        // Dynamic unresolvable expression
        MessageDigest dynamicMd = MessageDigest.getInstance("M~D5".replace("~", ""));
    }
}
"""
    f = tmp_path / "TestCrypto.java"
    f.write_text(java_code, encoding="utf-8")

    engine = JavaContractEngine()
    assets = engine.scan_file(f, tmp_path)

    algs = {a.algorithm for a in assets}
    assert "AES-256" in algs
    assert "MD5" in algs
    assert "DYNAMIC_UNRESOLVED" in algs

    quarantined = next(a for a in assets if a.algorithm == "DYNAMIC_UNRESOLVED")
    assert quarantined.x_tier == XTier.HUMAN_REVIEW
    assert quarantined.evidence_level == EvidenceLevel.E0_UNCONFIRMED
    assert quarantined.raw_properties.get("ecdat:risk_level") == "MANUAL_REVIEW_REQUIRED"

def test_ruby_contract_engine(tmp_path):
    ruby_code = """
require 'openssl'
require 'bcrypt'

cipher = OpenSSL::Cipher.new('AES-256-GCM')
digest = OpenSSL::Digest.new('SHA256')
rsa = OpenSSL::PKey::RSA.generate(2048)
kdf = OpenSSL::KDF.pbkdf2_hmac('password', salt: 'salt', iterations: 1000, length: 32, hash: 'SHA256')
pwd = BCrypt::Password.create('password')
"""
    f = tmp_path / "crypto.rb"
    f.write_text(ruby_code, encoding="utf-8")

    engine = RubyContractEngine()
    assets = engine.scan_file(f, tmp_path)

    algs = {a.algorithm for a in assets}
    assert "AES-256-GCM" in algs
    assert "SHA-256" in algs
    assert "RSA-2048" in algs
    assert "PBKDF2-HMAC" in algs
    assert "Bcrypt" in algs

def test_type_morphic_classifier():
    # KDF shape
    kdf = TypeMorphismClassifier.classify_signature("customDerive", ["user_password", "user_salt", "10000", "key_len"])
    assert kdf is not None
    assert kdf["primitive_type"] == PrimitiveType.KEY_EXCHANGE
    assert kdf["inferred_algorithm"] == "GENERIC-KDF"

    # Symmetric cipher shape
    sym = TypeMorphismClassifier.classify_signature("envelopeEncrypt", ["secret_key", "iv_bytes", "payload_data", "aad"])
    assert sym is not None
    assert sym["primitive_type"] == PrimitiveType.ENCRYPTION
    assert sym["inferred_algorithm"] == "GENERIC-AEAD-CIPHER"

    # Signature shape
    sig = TypeMorphismClassifier.classify_signature("signMessage", ["privkey", "msg_digest"])
    assert sig is not None
    assert sig["primitive_type"] == PrimitiveType.SIGNATURE

def test_server_config_scanner(tmp_path):
    conf_content = """
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
    ssl_ciphers 'DES-CBC3-SHA:TLS_AES_256_GCM_SHA384';
    ssl_ecdh_curve X25519;
}
"""
    f = tmp_path / "nginx.conf"
    f.write_text(conf_content, encoding="utf-8")

    scanner = ConfigScanner()
    assets = scanner.scan_file(f, tmp_path)

    algs = {a.algorithm for a in assets}
    assert "TLSV1" in algs
    assert "TLSV1.2" in algs
    assert "TLSV1.3" in algs
    assert "DES-CBC3-SHA" in algs
    assert "TLS_AES_256_GCM_SHA384" in algs
    assert "X25519" in algs

    legacy_tls = next(a for a in assets if a.algorithm == "TLSV1")
    assert legacy_tls.raw_properties.get("ecdat:risk_level") == "HIGH"

    des_cipher = next(a for a in assets if a.algorithm == "DES-CBC3-SHA")
    assert des_cipher.raw_properties.get("ecdat:risk_level") == "CRITICAL"
