import pytest
from pathlib import Path
from ecdat.scanners.source_scanner import scan_java_file
from ecdat.models import PrimitiveType, XTier, EvidenceLevel, IntentClass

def test_scan_java_cryptoapi_bench_patterns(tmp_path):
    java_code = """
package test.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.KeyPairGenerator;

public class BenchmarkCryptoSample {
    public void testVulnerabilities() throws Exception {
        // Broken cipher: DES
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        
        // Broken hash: MD5
        MessageDigest md5Digest = MessageDigest.getInstance("MD5");
        
        // Broken hash: SHA-1
        MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
        
        // Broken cipher: Blowfish
        Cipher blowfishCipher = Cipher.getInstance("Blowfish");
        
        // Secure cipher control: AES
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Secure signature: SHA256withRSA
        Signature sig = Signature.getInstance("SHA256withRSA");
        
        // Key pair generation: RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    }
}
"""
    file_path = tmp_path / "BenchmarkCryptoSample.java"
    file_path.write_text(java_code, encoding="utf-8")

    assets = scan_java_file(file_path, tmp_path)
    assert len(assets) == 7

    # 1. DES check
    des_asset = next(a for a in assets if "DES" in a.algorithm and "3DES" not in a.algorithm)
    assert des_asset.algorithm == "DES-56"
    assert des_asset.key_size == 56
    assert des_asset.primitive_type == PrimitiveType.ENCRYPTION
    assert des_asset.evidence_level == EvidenceLevel.E1_STATIC_ARTIFACT

    # 2. MD5 check
    md5_asset = next(a for a in assets if a.algorithm == "MD5")
    assert md5_asset.primitive_type == PrimitiveType.HASH
    assert md5_asset.key_size == 128

    # 3. SHA-1 check
    sha1_asset = next(a for a in assets if a.algorithm == "SHA-1")
    assert sha1_asset.primitive_type == PrimitiveType.HASH

    # 4. Blowfish check
    bf_asset = next(a for a in assets if a.algorithm == "Blowfish-128")
    assert bf_asset.primitive_type == PrimitiveType.ENCRYPTION

    # 5. AES check
    aes_asset = next(a for a in assets if a.algorithm == "AES-256")
    assert aes_asset.primitive_type == PrimitiveType.ENCRYPTION

    # 6. Signature check
    sig_asset = next(a for a in assets if "RSA" in a.algorithm and a.primitive_type == PrimitiveType.SIGNATURE)
    assert sig_asset.primitive_type == PrimitiveType.SIGNATURE

    # 7. KeyPairGenerator RSA check
    kpg_asset = next(a for a in assets if a.algorithm == "RSA-2048" and a.primitive_type == PrimitiveType.SIGNATURE)
    assert kpg_asset.algorithm == "RSA-2048"
    assert kpg_asset.key_size == 2048
