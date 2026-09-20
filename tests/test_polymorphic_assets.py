from ecdat.models import (
    PostQuantumAsset,
    ClassicalAsymmetricAsset,
    EllipticCurveAsset,
    SymmetricAsset,
    UnknownOrOpaqueAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
)

def test_post_quantum_asset_mldsa():
    asset = PostQuantumAsset(
        asset_id="PQC-001",
        component_name="dilithium:ml-dsa-65",
        algorithm="ML-DSA-65",
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/dilithium.js",
        nist_level=3,
        pubkey_bytes=1952,
        sig_bytes=3309,
    )
    assert asset.is_pqc is True
    assert asset.is_classically_broken is False
    assert asset.z_reg_deadline == 2050
    assert asset.z_reg_phase == 0
    assert asset.security_bits == 192
    assert asset.network_flight_bytes == 1952 + 3309

def test_classical_asymmetric_rsa_2048():
    asset = ClassicalAsymmetricAsset(
        asset_id="ASYM-001",
        component_name="rsa:rsa-2048",
        algorithm="RSA-2048",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="src/rsa.js",
        modulus_bits=2048,
    )
    assert asset.is_pqc is False
    assert asset.is_classically_broken is False
    assert asset.z_reg_deadline == 2030
    assert asset.z_reg_phase == 3
    assert asset.security_bits == 112
    assert asset.network_flight_bytes == (2048 // 8) * 2

def test_classical_asymmetric_rsa_1024_broken():
    asset = ClassicalAsymmetricAsset(
        asset_id="ASYM-002",
        component_name="rsa:rsa-1024",
        algorithm="RSA-1024",
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/legacy.js",
        modulus_bits=1024,
    )
    assert asset.is_pqc is False
    assert asset.is_classically_broken is True
    assert asset.z_reg_deadline == 2026
    assert asset.z_reg_phase == 0

def test_elliptic_curve_ecdsa_p256():
    asset = EllipticCurveAsset(
        asset_id="ECC-001",
        component_name="wallet:ecdsa-p256",
        algorithm="ECDSA-P256",
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="wallet/admin.key",
        curve_bits=256,
        curve_name="secp256r1",
    )
    assert asset.is_pqc is False
    assert asset.is_classically_broken is False
    assert asset.z_reg_deadline == 2031  # OMB M-26-15 Phase 4!
    assert asset.z_reg_phase == 4
    assert asset.security_bits == 128
    assert asset.network_flight_bytes == (256 // 8) * 2

def test_symmetric_aes_256_gcm():
    asset = SymmetricAsset(
        asset_id="SYM-001",
        component_name="db:aes-256",
        algorithm="AES-256-GCM",
        primitive_type=PrimitiveType.ENCRYPTION,
        file_path="src/db.js",
        key_bits=256,
        cipher_mode="GCM",
    )
    assert asset.is_pqc is True  # 256 bits is Grover-safe
    assert asset.is_classically_broken is False
    assert asset.z_reg_deadline == 2050

def test_crypto_asset_factory_dispatch():
    from ecdat.scanners.factory import CryptoAssetFactory

    pqc = CryptoAssetFactory.create_asset(
        asset_prefix="SRC-JS",
        index=1,
        component_name="dilithium:sign",
        algorithm="ML-DSA-65",
        key_size=1952,
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="src/dilithium.js",
        line_number=40,
        tier=XTier.OPERATIONAL,
        has_shredding=False,
        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
        evidence_source="js_contract",
        matched_code="ml_dsa65.sign(sk, msg)",
        language="javascript",
    )
    assert isinstance(pqc, PostQuantumAsset)
    assert pqc.is_pqc is True
    assert pqc.is_classically_broken is False
    assert pqc.z_reg_deadline == 2050

    ecc = CryptoAssetFactory.create_asset(
        asset_prefix="SRC-THEIA",
        index=2,
        component_name="wallet:admin",
        algorithm="ECDSA-P256",
        key_size=256,
        primitive_type=PrimitiveType.SIGNATURE,
        file_path="wallet/admin.key",
        line_number=1,
        tier=XTier.OPERATIONAL,
        has_shredding=False,
        evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
        evidence_source="theia_bridge",
        matched_code="",
        language="asn1",
    )
    assert isinstance(ecc, EllipticCurveAsset)
    assert ecc.is_pqc is False
    assert ecc.is_classically_broken is False
    assert ecc.z_reg_deadline == 2031  # OMB M-26-15 Phase 4!

def test_ephemeral_rsa_blind_keygen(tmp_path):
    from ecdat.scanners.contracts.javascript_contracts import JavaScriptContractEngine
    from ecdat.mosca.engine import compute_mosca_score

    code = """
    // Chaum RSA-2048 Blind Signature Service (HNDL mitigation — in-memory only)
    class RsaBlindService {
        constructor() {
            this._keys = new Map();
        }
        async generateForElection(electionId) {
            forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keypair) => {
                this._keys.set(electionId, keypair);
            });
        }
        destroyForElection(electionId) {
            this._keys.delete(electionId);
        }
    }
    """
    f = tmp_path / "rsa-blind.service.js"
    f.write_text(code, encoding="utf-8")

    engine = JavaScriptContractEngine()
    assets = engine.scan_file(f, tmp_path)
    assert len(assets) == 1
    rsa_asset = assets[0]
    assert rsa_asset.algorithm == "RSA-2048"
    assert rsa_asset.x_tier == XTier.EPHEMERAL
    assert rsa_asset.has_crypto_shredding is True

    score = compute_mosca_score(rsa_asset, current_year=2026)
    assert score.risk_level == "LOW"
    assert score.y_max_years == 5.0
    assert score.r_q_score == 0.0

