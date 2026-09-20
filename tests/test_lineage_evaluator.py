"""
Unit Tests for ECDAT Father Marko Cryptographic Lineage & Call-Site Bifurcation Evaluator:
Verifies:
1. Zero-regex closed-world constant folding (.replace, +, .toUpperCase) -> CBOM.
2. Zero-regex open-world ingress classification (process.env, config, DB) -> Father Marko Lineage.
3. Strict bifurcation: .replace() in CBOM but NOT graph; process.env in graph but NOT CBOM.
4. Absolute zero-regex enforcement across new modules.
"""

from pathlib import Path
import pytest
from pygments.lexers import JavascriptLexer

from ecdat.scanners.contracts.evaluator import CallSiteEvaluator, StaticResolution, DynamicIngress
from ecdat.scanners.contracts.javascript_contracts import JavaScriptContractEngine
from ecdat.lineage.engine import analyze_crypto_lineage
from ecdat.lineage.models import LineageCategory, LineageSourceType


def tokenize_js(code_snippet: str):
    lexer = JavascriptLexer()
    raw = list(lexer.get_tokens_unprocessed(code_snippet))
    raw.sort(key=lambda t: t[0])
    return [(t[1], t[2], t[0]) for t in raw]


def test_evaluator_string_literal():
    tokens = tokenize_js("crypto.createCipheriv('aes-256-gcm', k, iv)")
    # Argument starts at token 4 (the string)
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, StaticResolution)
    assert res.value == "aes-256-gcm"
    assert res.is_static is True


def test_evaluator_replace_trick():
    """Tests the exact Project Marko case: 'A~ES'.replace('~', '') deterministically folds to 'AES'"""
    tokens = tokenize_js("crypto.createCipheriv('A~ES'.replace('~', ''), k, iv)")
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, StaticResolution)
    assert res.value == "AES"
    assert res.is_static is True


def test_evaluator_concatenation_and_case():
    tokens = tokenize_js("crypto.createCipheriv('aes-' + '256-' + 'gcm'.toUpperCase(), k, iv)")
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, StaticResolution)
    assert res.value == "aes-256-GCM"


def test_evaluator_process_env_dot():
    tokens = tokenize_js("crypto.createCipheriv(process.env.VOTE_CIPHER_SUITE, k, iv)")
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, DynamicIngress)
    assert res.source_type == "ENV"
    assert res.key_name == "VOTE_CIPHER_SUITE"
    assert res.is_static is False


def test_evaluator_process_env_bracket():
    tokens = tokenize_js("crypto.createCipheriv(process.env['CUSTOM_CRYPTO_MODE'], k, iv)")
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, DynamicIngress)
    assert res.source_type == "ENV"
    assert res.key_name == "CUSTOM_CRYPTO_MODE"


def test_evaluator_config_get():
    tokens = tokenize_js("crypto.createCipheriv(config.get('security.encryption.scheme'), k, iv)")
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, DynamicIngress)
    assert res.source_type == "CONFIG"
    assert res.key_name == "security.encryption.scheme"


def test_evaluator_database_row():
    tokens = tokenize_js("crypto.createCipheriv(row.algo_name, k, iv)")
    res, next_idx = CallSiteEvaluator.evaluate_argument_tokens(tokens, 4)
    assert isinstance(res, DynamicIngress)
    assert res.source_type == "DATABASE"
    assert res.key_name == "row.algo_name"


def test_strict_bifurcation_javascript_contracts(tmp_path):
    """
    Verifies that:
    - 'A~ES'.replace('~', '') produces a verified CryptoAsset for the CBOM.
    - process.env.VOTE_CIPHER does NOT produce a concrete CryptoAsset in the CBOM.
    """
    js_file = tmp_path / "crypto_service.js"
    js_file.write_text("""
    import crypto from 'crypto';

    function runCrypto(k, iv) {
        // Closed-world constant trick: Should go to CBOM
        const cipher1 = crypto.createCipheriv('A~ES-256-GCM'.replace('~', ''), k, iv);

        // Open-world external ingress: Should be excluded from concrete CBOM assets
        const cipher2 = crypto.createCipheriv(process.env.DYNAMIC_SUITE, k, iv);
    }
    """)

    engine = JavaScriptContractEngine()
    assets = engine.scan_file(js_file, tmp_path)

    # Only cipher1 should be present in assets!
    assert len(assets) == 1
    assert assets[0].algorithm == "AES-256-GCM"


def test_father_marko_lineage_graph_separation(tmp_path):
    """
    Verifies that:
    - process.env.DYNAMIC_SUITE creates an INGRESS node in Father Marko.
    - 'A~ES'.replace('~', '') does NOT create an INGRESS node in Father Marko.
    - Sinks (redisClient.set) create EGRESS nodes.
    """
    js_file = tmp_path / "vote_processor.js"
    js_file.write_text("""
    import crypto from 'crypto';
    import redis from 'redis';

    async function processVote(k, iv, data) {
        // Static trick: Suppressed from lineage graph
        const c1 = crypto.createCipheriv('A~ES'.replace('~', ''), k, iv);

        // Dynamic ingress: Must appear on Father Marko graph
        const c2 = crypto.createCipheriv(process.env.VOTE_DISPATCH_CIPHER, k, iv);

        // Egress Sink: Must appear on Father Marko graph
        await redisClient.set('vote:receipt:123', data, 'EX', 86400);
    }
    """)

    result = analyze_crypto_lineage(
        file_paths=[str(js_file)],
        target_dir=str(tmp_path)
    )

    # Ingress should contain VOTE_DISPATCH_CIPHER, but NO node for 'A~ES'
    ingress_keys = [n.details.get("key") for n in result.nodes if n.category == LineageCategory.INGRESS]
    assert "VOTE_DISPATCH_CIPHER" in ingress_keys
    assert len(ingress_keys) == 1  # Absolutely no node created for 'A~ES'

    # Egress should contain Redis cache
    egress_labels = [n.label for n in result.nodes if n.category == LineageCategory.EGRESS]
    assert any("Redis" in lbl for lbl in egress_labels)

    # Verify edges exist linking Ingress -> Nexus -> Egress
    assert len(result.edges) >= 2
    assert any(e.edge_type == "BINDS_PARAMETER" for e in result.edges)
    assert any(e.edge_type == "CIPHERTEXT_EGRESS" for e in result.edges)


def test_absolute_zero_regex_enforcement():
    """Verifies that the new modules do not import or use Python's re module."""
    base_dir = Path(__file__).parent.parent / "ecdat"
    files_to_check = [
        base_dir / "scanners" / "contracts" / "evaluator.py",
        base_dir / "lineage" / "models.py",
        base_dir / "lineage" / "engine.py",
    ]

    for fpath in files_to_check:
        assert fpath.exists(), f"File {fpath} must exist"
        content = fpath.read_text(encoding="utf-8")
        assert "import re" not in content, f"Zero regex violation: 'import re' found in {fpath}"
        assert "from re import" not in content, f"Zero regex violation: 'from re import' found in {fpath}"
        assert "re.compile" not in content, f"Zero regex violation: 're.compile' found in {fpath}"
        assert "re.search" not in content, f"Zero regex violation: 're.search' found in {fpath}"
        assert "re.match" not in content, f"Zero regex violation: 're.match' found in {fpath}"
