"""
Tests for ECDAT Live External Infrastructure & TLS Prober.
Strict Zero-Regex compliance: absolutely NO regular expressions.
"""

import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ecdat.models import CryptoAsset, EvidenceLevel, PrimitiveType, XTier
from ecdat.network.tls_prober import LiveTLSProber, TLSProbeError


def _generate_test_cert_der(
    key_type: str = "rsa",
    key_size: int = 2048,
    common_name: str = "api.evoting.com",
    sans: list[str] = None,
) -> bytes:
    """Helper to generate an in-memory X.509 certificate in DER format without external network."""
    if sans is None:
        sans = ["api.evoting.com", "backup.evoting.com"]

    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"Unsupported key_type: {key_type}")

    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    san_names = [x509.DNSName(s) for s in sans]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    )

    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_target_urls_and_ports():
    """Verify parse_target parses full URLs and assigns appropriate default or explicit ports."""
    prober = LiveTLSProber()

    # Full HTTPS URL with explicit port and path
    host, port = prober.parse_target("https://api.evoting.com:8443/v1")
    assert host == "api.evoting.com"
    assert port == 8443

    # Full HTTP URL with default port 80
    host, port = prober.parse_target("http://example.com")
    assert host == "example.com"
    assert port == 80

    # Full HTTPS URL with default port 443
    host, port = prober.parse_target("https://example.com")
    assert host == "example.com"
    assert port == 443

    # HTTP with explicit port and complex query/fragment
    host, port = prober.parse_target("http://example.com:8080/path?arg=1#frag")
    assert host == "example.com"
    assert port == 8080


def test_parse_target_hostnames_and_ipv4():
    """Verify parse_target parses plain hostnames, host:port, and IPv4 addresses without regex."""
    prober = LiveTLSProber()

    # Plain hostname (defaults to 443)
    host, port = prober.parse_target("example.com")
    assert host == "example.com"
    assert port == 443

    # Hostname with explicit port
    host, port = prober.parse_target("example.com:8443")
    assert host == "example.com"
    assert port == 8443

    # Leading and trailing whitespace
    host, port = prober.parse_target("   https://example.com:443/   ")
    assert host == "example.com"
    assert port == 443

    # Host with path and query without protocol prefix
    host, port = prober.parse_target("api.evoting.com:8443/v1?query=1#frag")
    assert host == "api.evoting.com"
    assert port == 8443

    host, port = prober.parse_target("api.evoting.com/v1?query=1#frag")
    assert host == "api.evoting.com"
    assert port == 443

    # IPv4 address
    host, port = prober.parse_target("127.0.0.1:9000")
    assert host == "127.0.0.1"
    assert port == 9000

    host, port = prober.parse_target("127.0.0.1")
    assert host == "127.0.0.1"
    assert port == 443


def test_parse_target_ipv6():
    """Verify parse_target parses bracketed and unbracketed IPv6 addresses without regex."""
    prober = LiveTLSProber()

    # Bracketed IPv6 with port
    host, port = prober.parse_target("[::1]:8443")
    assert host == "::1"
    assert port == 8443

    # Unbracketed IPv6 (multi-colon)
    host, port = prober.parse_target("::1")
    assert host == "::1"
    assert port == 443

    # Bracketed IPv6 without port
    host, port = prober.parse_target("[2001:db8::1]")
    assert host == "2001:db8::1"
    assert port == 443

    # Unbracketed IPv6
    host, port = prober.parse_target("2001:db8::1")
    assert host == "2001:db8::1"
    assert port == 443


def test_parse_target_invalid():
    """Verify parse_target raises ValueError on empty or blank input."""
    prober = LiveTLSProber()
    with pytest.raises(ValueError):
        prober.parse_target("")
    with pytest.raises(ValueError):
        prober.parse_target("   ")


def test_parse_certificate_rsa():
    """Verify RSA server certificate extraction produces standardized CryptoAsset."""
    prober = LiveTLSProber()
    der_bytes = _generate_test_cert_der("rsa", 2048, "api.evoting.com", ["api.evoting.com", "kiosk.evoting.com"])

    cert_asset = prober.parse_certificate(der_bytes, "api.evoting.com", 443)
    assert isinstance(cert_asset, CryptoAsset)
    assert cert_asset.primitive_type == PrimitiveType.SIGNATURE
    assert cert_asset.x_tier == XTier.OPERATIONAL
    assert cert_asset.evidence_level == EvidenceLevel.E3_CONFIG_CONFIRMED
    assert cert_asset.intent == "AUTHENTICATION_HANDSHAKE"
    assert cert_asset.key_size == 2048
    assert cert_asset.algorithm == "RSA-2048"
    assert cert_asset.raw_properties["subject_cn"] == "api.evoting.com"
    assert "kiosk.evoting.com" in cert_asset.raw_properties["sans"]
    assert cert_asset.raw_properties["quantum_risk"] in ("HIGH", "CRITICAL")


def test_parse_certificate_ecdsa():
    """Verify ECDSA server certificate extraction produces standardized CryptoAsset."""
    prober = LiveTLSProber()
    der_bytes = _generate_test_cert_der("ec", 256, "auth.evoting.com")

    cert_asset = prober.parse_certificate(der_bytes, "auth.evoting.com", 8443)
    assert isinstance(cert_asset, CryptoAsset)
    assert cert_asset.primitive_type == PrimitiveType.SIGNATURE
    assert cert_asset.x_tier == XTier.OPERATIONAL
    assert cert_asset.evidence_level == EvidenceLevel.E3_CONFIG_CONFIRMED
    assert cert_asset.intent == "AUTHENTICATION_HANDSHAKE"
    assert cert_asset.key_size == 256
    assert "ECDSA" in cert_asset.algorithm
    assert cert_asset.raw_properties["quantum_risk"] in ("HIGH", "CRITICAL")


def test_probe_endpoint_offline_simulated():
    """Verify probe_endpoint completes offline via mocked socket and SSL context returning 3 CryptoAssets."""
    prober = LiveTLSProber()
    der_cert = _generate_test_cert_der("rsa", 2048, "api.evoting.com")

    # Setup mock SSLSocket
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.getpeercert.return_value = der_cert

    # Context manager setup
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock
    mock_raw_sock.__exit__.return_value = False

    mock_ssl_ctx = MagicMock()
    mock_ssl_ctx.wrap_socket.return_value = mock_ssock

    with patch("socket.create_connection", return_value=mock_raw_sock) as mock_conn:
        with patch("ssl.create_default_context", return_value=mock_ssl_ctx):
            assets = prober.probe_endpoint("https://api.evoting.com:8443/v1", timeout=3.0)

    mock_conn.assert_called_once_with(("api.evoting.com", 8443), timeout=3.0)
    assert len(assets) == 3

    cert_asset, kex_asset, cipher_asset = assets

    # 1. Server Certificate
    assert cert_asset.primitive_type == PrimitiveType.SIGNATURE
    assert cert_asset.x_tier == XTier.OPERATIONAL
    assert cert_asset.evidence_level == EvidenceLevel.E3_CONFIG_CONFIRMED
    assert cert_asset.intent == "AUTHENTICATION_HANDSHAKE"
    assert cert_asset.algorithm == "RSA-2048"

    # 2. Key Exchange Mechanism
    assert kex_asset.primitive_type == PrimitiveType.KEY_EXCHANGE
    assert kex_asset.x_tier == XTier.TRANSIENT
    assert kex_asset.evidence_level == EvidenceLevel.E3_CONFIG_CONFIRMED
    assert kex_asset.intent == "CONFIDENTIALITY_IN_TRANSIT"
    assert kex_asset.raw_properties["quantum_risk"] in ("HIGH", "CRITICAL")
    assert kex_asset.raw_properties["hndl_vulnerable"] is True

    # 3. Bulk Encryption Cipher
    assert cipher_asset.primitive_type in (PrimitiveType.SYMMETRIC_CIPHER, PrimitiveType.ENCRYPTION)
    assert cipher_asset.x_tier == XTier.TRANSIENT
    assert cipher_asset.evidence_level == EvidenceLevel.E3_CONFIG_CONFIRMED
    assert cipher_asset.intent == "CONFIDENTIALITY_IN_TRANSIT"
    assert cipher_asset.key_size == 256
    assert cipher_asset.raw_properties["quantum_risk"] == "LOW"


def test_probe_endpoint_hybrid_pqc():
    """Verify hybrid Post-Quantum key exchange evaluation (e.g. X25519Kyber768Draft00 or secp256r1_mlkem768)."""
    prober = LiveTLSProber()
    der_cert = _generate_test_cert_der("rsa", 2048, "quantum.evoting.com")

    # Simulated hybrid PQC cipher / group negotiation
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.getpeercert.return_value = der_cert

    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False
    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock
    mock_raw_sock.__exit__.return_value = False
    mock_ssl_ctx = MagicMock()
    mock_ssl_ctx.wrap_socket.return_value = mock_ssock

    with patch("socket.create_connection", return_value=mock_raw_sock):
        with patch("ssl.create_default_context", return_value=mock_ssl_ctx):
            assets = prober.probe_endpoint(
                "quantum.evoting.com",
                timeout=3.0,
                kex_group_override="X25519Kyber768Draft00",
            )

    assert len(assets) == 3
    kex_asset = assets[1]
    assert kex_asset.primitive_type == PrimitiveType.KEY_EXCHANGE
    assert "KYBER" in kex_asset.algorithm.upper() or "PQC" in kex_asset.algorithm.upper()
    assert kex_asset.raw_properties["is_hybrid_pqc"] is True
    assert kex_asset.raw_properties["quantum_risk"] == "LOW"
    assert kex_asset.raw_properties["hndl_vulnerable"] is False


def test_probe_endpoint_connection_failure():
    """Verify graceful handling of connection timeout or refused connections."""
    prober = LiveTLSProber()

    with patch("socket.create_connection", side_effect=TimeoutError("Connection timed out")):
        with pytest.raises(TLSProbeError) as exc_info:
            prober.probe_endpoint("nonexistent.local:443", timeout=1.0)
        assert "nonexistent.local" in str(exc_info.value)
        assert exc_info.value.host == "nonexistent.local"
        assert exc_info.value.port == 443


def test_cli_probe_subcommand(tmp_path):
    """Verify probe CLI command and output JSON serialization."""
    import json
    from click.testing import CliRunner
    from ecdat.pipeline import cli, probe_live_tls_infrastructure

    der_cert = _generate_test_cert_der("rsa", 2048, "api.evoting.com")
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.getpeercert.return_value = der_cert
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock
    mock_raw_sock.__exit__.return_value = False

    mock_ssl_ctx = MagicMock()
    mock_ssl_ctx.wrap_socket.return_value = mock_ssock

    out_file = tmp_path / "probe_output.json"

    with patch("socket.create_connection", return_value=mock_raw_sock):
        with patch("ssl.create_default_context", return_value=mock_ssl_ctx):
            assets = probe_live_tls_infrastructure(
                "https://api.evoting.com:8443",
                timeout=2.0,
                output=str(out_file),
            )

    assert len(assets) == 3
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) == 3
    assert data[0]["primitive_type"] == "SIGNATURE"

    # Test via Click CLI Runner
    click_out = tmp_path / "click_probe.json"
    runner = CliRunner()
    with patch("socket.create_connection", return_value=mock_raw_sock):
        with patch("ssl.create_default_context", return_value=mock_ssl_ctx):
            result = runner.invoke(cli, ["probe", "https://api.evoting.com:8443", "-o", str(click_out)])

    assert result.exit_code == 0
    assert click_out.exists()
    with open(click_out, "r", encoding="utf-8") as f:
        click_data = json.load(f)
    assert len(click_data) == 3


def test_strict_zero_regex_compliance():
    """Verify neither tls_prober nor this test module imports or invokes regular expressions."""
    repo_root = Path(__file__).resolve().parent.parent
    prober_file = repo_root / "ecdat" / "network" / "tls_prober.py"
    test_file = Path(__file__).resolve()

    forbidden_mod = "r" + "e"
    forbidden_import = "import " + forbidden_mod
    forbidden_from = "from " + forbidden_mod + " import"
    forbidden_compile = forbidden_mod + ".compile"
    forbidden_search = forbidden_mod + ".search"
    forbidden_match = forbidden_mod + ".match"

    for target_path in [prober_file, test_file]:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()

        lines = [line.strip() for line in content.splitlines()]
        code_lines = [
            l for l in lines
            if not l.startswith("#")
            and not l.startswith("assert")
            and not l.startswith("forbidden_")
            and not l.startswith('"""')
            and not l.endswith('"""')
        ]

        for l in code_lines:
            assert l != forbidden_import and not l.startswith(forbidden_import + " "), (
                f"Zero-Regex violation in {target_path}: found '{forbidden_import}' in '{l}'"
            )
            assert not l.startswith(forbidden_from), (
                f"Zero-Regex violation in {target_path}: found '{forbidden_from}' in '{l}'"
            )
            assert forbidden_compile not in l, (
                f"Zero-Regex violation in {target_path}: found '{forbidden_compile}' in '{l}'"
            )
            assert forbidden_search not in l, (
                f"Zero-Regex violation in {target_path}: found '{forbidden_search}' in '{l}'"
            )
            assert forbidden_match not in l, (
                f"Zero-Regex violation in {target_path}: found '{forbidden_match}' in '{l}'"
            )

    # In prober_file specifically, ensure the forbidden module name is never imported anywhere
    with open(prober_file, "r", encoding="utf-8") as f:
        prober_content = f.read()
    assert forbidden_import not in prober_content
    assert forbidden_from not in prober_content
    assert forbidden_compile not in prober_content
    assert forbidden_search not in prober_content
    assert forbidden_match not in prober_content
