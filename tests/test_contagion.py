import pytest
from pathlib import Path
from ecdat.models import CryptoAsset, PrimitiveType, XTier
from ecdat.contagion.engine import analyze_contagion, build_contagion_network

@pytest.fixture
def mock_microservice_repo(tmp_path):
    repo_dir = tmp_path / "microservices"
    repo_dir.mkdir()

    # 1. Common crypto provider (contains crypto primitive)
    common_crypto = repo_dir / "common_crypto.py"
    common_crypto.write_text("def encrypt_envelope(msg): return cipher.encrypt(msg)\n")

    # 2. Auth service depends on common_crypto
    auth_service = repo_dir / "auth_service.py"
    auth_service.write_text("import common_crypto\ndef login(): return common_crypto.encrypt_envelope('token')\n")

    # 3. Payment service depends on common_crypto
    payment_service = repo_dir / "payment_service.py"
    payment_service.write_text("import common_crypto\ndef charge(): return common_crypto.encrypt_envelope('card')\n")

    # 4. API Gateway depends on auth_service and payment_service
    gateway = repo_dir / "api_gateway.py"
    gateway.write_text("import auth_service\nimport payment_service\ndef route(): pass\n")

    # 5. Reporting service depends on payment_service
    reporting = repo_dir / "reporting_service.py"
    reporting.write_text("import payment_service\ndef report(): pass\n")

    # 6. Standalone utility (no crypto, no dependencies)
    utils = repo_dir / "string_utils.py"
    utils.write_text("def format_str(s): return s.strip()\n")

    file_paths = [
        str(common_crypto),
        str(auth_service),
        str(payment_service),
        str(gateway),
        str(reporting),
        str(utils),
    ]

    crypto_assets = [
        CryptoAsset(
            asset_id="asset-common-1",
            component_name="common_crypto",
            algorithm="RSA-2048",
            key_size=2048,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=str(common_crypto),
            x_tier=XTier.ARCHIVAL,
        )
    ]

    return file_paths, crypto_assets

def test_r0_contagion_superspreader_detection(mock_microservice_repo):
    file_paths, crypto_assets = mock_microservice_repo

    result = analyze_contagion(file_paths, crypto_assets, superspreader_threshold=2)

    assert result.total_nodes == 6
    assert result.total_edges >= 4

    # common_crypto should be identified as the top superspreader
    assert len(result.superspreaders) == 1
    sp = result.superspreaders[0]
    assert sp.node_id == "common_crypto"
    assert sp.has_crypto is True
    assert sp.is_superspreader is True
    # Downstream infected: auth_service, payment_service, api_gateway, reporting_service -> R0 = 4!
    assert sp.r0_score == 4
    assert set(sp.downstream_dependents) == {"auth_service", "payment_service", "api_gateway", "reporting_service"}
    assert "SUPERSPREADER" in sp.mitigation_impact
    assert "eliminates quantum risk across 4 downstream services" in sp.mitigation_impact

def test_d3_graph_json_export(mock_microservice_repo):
    file_paths, crypto_assets = mock_microservice_repo

    result = analyze_contagion(file_paths, crypto_assets)
    g_json = result.graph_json

    assert "nodes" in g_json
    assert "links" in g_json
    assert len(g_json["nodes"]) == 6

    # Verify superspreader node formatting for D3 visualization
    sp_node = next(n for n in g_json["nodes"] if n["id"] == "common_crypto")
    assert sp_node["group"] == "superspreader"
    assert sp_node["color"] == "#ef4444"  # Alert red
    assert sp_node["r0"] == 4
    assert sp_node["size"] >= 24

def test_pqc_immunization_anchor_polarity(mock_microservice_repo):
    file_paths, _ = mock_microservice_repo

    # Provide ML-DSA-65 post-quantum asset instead of RSA
    pqc_assets = [
        CryptoAsset(
            asset_id="asset-pqc-1",
            component_name="common_crypto",
            algorithm="ML-DSA-65",
            key_size=1952,
            primitive_type=PrimitiveType.SIGNATURE,
            file_path=file_paths[0],
            x_tier=XTier.EPHEMERAL,
        )
    ]

    result = analyze_contagion(file_paths, pqc_assets, superspreader_threshold=2)

    # common_crypto should NOT be in superspreaders (it does not spread risk)
    assert len(result.superspreaders) == 0
    # It SHOULD be in pqc_anchors
    assert len(result.pqc_anchors) == 1
    anchor = result.pqc_anchors[0]
    assert anchor.node_id == "common_crypto"
    assert anchor.is_superspreader is False
    assert anchor.is_pqc_anchor is True
    assert anchor.r0_score == 4
    assert "IMMUNIZATION ANCHOR" in anchor.mitigation_impact
    assert "Supplies post-quantum security to 4 downstream services" in anchor.mitigation_impact

    # Check graph JSON formatting
    anchor_json = next(n for n in result.graph_json["nodes"] if n["id"] == "common_crypto")
    assert anchor_json["group"] == "pqc_anchor"
    assert anchor_json["color"] == "#10b981"  # Emerald Green
    assert anchor_json["is_superspreader"] is False
    assert anchor_json["is_pqc_anchor"] is True
