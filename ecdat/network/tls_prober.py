"""
ECDAT Live External Infrastructure & TLS Prober:
Connects to remote TLS endpoints, inspects active negotiated cryptographic parameters
(TLS version, cipher suite, peer certificates, and key exchange mechanisms),
and produces standardized CryptoAsset models with Post-Quantum (PQC/HNDL) risk evaluations.

Strict Zero-Regex Rule:
Uses urllib.parse, string methods, and parser state machines exclusively.
Regular expression modules are strictly forbidden.
"""

import socket
import ssl
import urllib.parse
from typing import List, Optional, Tuple, Any, Dict

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
    IntentClass,
    ExposureProfile,
    AgilityLevel,
)


class TLSProbeError(Exception):
    """Structured diagnostic error for TLS probe connection and handshake failures."""

    def __init__(
        self,
        message: str,
        host: str = "",
        port: int = 0,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.host = host
        self.port = port
        self.cause = cause


class LiveTLSProber:
    """
    Active TLS probe engine for live infrastructure, external gateways,
    and microservice ingress endpoints.
    """

    PQC_KEY_EXCHANGE_KEYWORDS = (
        "KYBER",
        "MLKEM",
        "ML-KEM",
        "HYBRID",
        "PQC",
        "FRODO",
        "NTRU",
        "BIKE",
        "HQC",
        "OQS",
    )

    @staticmethod
    def parse_target(target: str) -> Tuple[str, int]:
        """
        Parses endpoint string into (host, port) tuple.
        Handles full URLs (https://..., http://...), hostnames, host:port,
        IPv4, and bracketed or raw IPv6 addresses without regular expressions.
        """
        if not target or not target.strip():
            raise ValueError("Target endpoint cannot be empty")

        cleaned = target.strip()

        # Handle full URLs with scheme (e.g. https://api.evoting.com:8443/v1)
        if "://" in cleaned:
            parsed = urllib.parse.urlsplit(cleaned)
            scheme = parsed.scheme.lower() if parsed.scheme else "https"
            default_port = 80 if scheme == "http" else 443
            host = parsed.hostname or ""
            port = parsed.port or default_port
            return host, port

        # Strip path, query, and fragment parts from raw host strings
        for sep in ("#", "?", "/"):
            if sep in cleaned:
                cleaned = cleaned.split(sep, 1)[0]
        cleaned = cleaned.strip()

        if not cleaned:
            raise ValueError("Target endpoint contains no valid host")

        # Handle bracketed IPv6: [::1]:8443 or [2001:db8::1]
        if cleaned.startswith("["):
            bracket_end = cleaned.find("]")
            if bracket_end != -1:
                host = cleaned[1:bracket_end]
                remainder = cleaned[bracket_end + 1:]
                if remainder.startswith(":"):
                    port_str = remainder[1:]
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    port = 443
                return host, port

        # Handle raw unbracketed IPv6 (contains multiple colons)
        if cleaned.count(":") > 1:
            return cleaned, 443

        # Handle hostname:port or ipv4:port
        if ":" in cleaned:
            parts = cleaned.split(":", 1)
            host = parts[0]
            port = int(parts[1]) if parts[1].isdigit() else 443
            return host, port

        # Bare hostname or IPv4 address
        return cleaned, 443

    def parse_certificate(self, der_bytes: bytes, host: str, port: int) -> CryptoAsset:
        """
        Parses X.509 certificate DER bytes into a standardized CryptoAsset.
        """
        cert = x509.load_der_x509_certificate(der_bytes)

        # Extract Subject CN
        common_name = ""
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            common_name = str(cn_attrs[0].value)

        # Extract Subject Alternative Names (SANs)
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
            sans = [str(x) for x in dns_names] + [str(x) for x in ip_addrs]
        except x509.ExtensionNotFound:
            sans = []

        # Extract Issuer CN or string
        issuer_str = ""
        issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if issuer_attrs:
            issuer_str = str(issuer_attrs[0].value)
        else:
            try:
                issuer_str = cert.issuer.rfc4514_string()
            except Exception:
                issuer_str = "UNKNOWN"

        # Validity window
        try:
            not_before = cert.not_valid_before_utc.isoformat()
            not_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()

        # Public key and algorithm inspection
        pubkey = cert.public_key()
        algorithm = "UNKNOWN"
        key_size: Optional[int] = None
        quantum_risk = "HIGH"

        if isinstance(pubkey, rsa.RSAPublicKey):
            key_size = pubkey.key_size
            algorithm = f"RSA-{key_size}"
            if key_size < 2048:
                quantum_risk = "CRITICAL"
            else:
                quantum_risk = "CRITICAL"  # Classical RSA signatures are Shor-vulnerable (M-26-15 Phase 4)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_size = pubkey.curve.key_size
            curve_name = pubkey.curve.name.upper()
            algorithm = f"ECDSA-{curve_name}"
            quantum_risk = "CRITICAL"  # Classical ECDSA is Shor-vulnerable (M-26-15 Phase 4)
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            key_size = 256
            algorithm = "Ed25519"
            quantum_risk = "CRITICAL"
        elif isinstance(pubkey, ed448.Ed448PublicKey):
            key_size = 448
            algorithm = "Ed448"
            quantum_risk = "CRITICAL"
        elif isinstance(pubkey, dsa.DSAPublicKey):
            key_size = pubkey.key_size
            algorithm = f"DSA-{key_size}"
            quantum_risk = "CRITICAL"
        else:
            algorithm = type(pubkey).__name__
            key_size = getattr(pubkey, "key_size", None)
            quantum_risk = "HIGH"

        # Signature algorithm
        try:
            sig_algo = cert.signature_algorithm_oid._name
        except Exception:
            sig_algo = "unknown"

        raw_props: Dict[str, Any] = {
            "subject_cn": common_name,
            "sans": sans,
            "issuer": issuer_str,
            "not_before": not_before,
            "not_after": not_after,
            "signature_algorithm": sig_algo,
            "quantum_risk": quantum_risk,
            "pqc_status": "VULNERABLE_CLASSICAL",
            "omf_phase_deadline": 2031,
        }

        return CryptoAsset(
            asset_id=f"live-tls-cert:{host}:{port}",
            component_name=f"TLS-Certificate:{host}:{port}",
            algorithm=algorithm,
            key_size=key_size,
            primitive_type=PrimitiveType.SIGNATURE,
            file_path=f"https://{host}:{port}",
            line_number=0,
            x_tier=XTier.OPERATIONAL,
            x_confidence="HIGH",
            evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
            intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
            intent="AUTHENTICATION_HANDSHAKE",
            exposure_profile=ExposureProfile.PUBLIC,
            p_hndl=1.0,
            agility_level=AgilityLevel.CONFIGURABLE,
            raw_properties=raw_props,
        )

    def parse_key_exchange(
        self,
        tls_version: str,
        cipher_name: str,
        host: str,
        port: int,
        kex_group: Optional[str] = None,
    ) -> CryptoAsset:
        """
        Parses TLS Key Exchange mechanism and evaluates Harvest-Now-Decrypt-Later (HNDL) risk.
        """
        group_or_cipher = (kex_group or cipher_name or "").upper()

        # Check for Post-Quantum hybrid key exchange
        is_hybrid_pqc = False
        for kw in self.PQC_KEY_EXCHANGE_KEYWORDS:
            if kw in group_or_cipher:
                is_hybrid_pqc = True
                break

        if is_hybrid_pqc:
            kex_algorithm = kex_group or cipher_name
            quantum_risk = "LOW"
            pqc_status = "HYBRID_PQC"
            hndl_vulnerable = False
        else:
            c_upper = cipher_name.upper()
            if "ECDHE" in c_upper or tls_version == "TLSv1.3":
                kex_algorithm = "ECDHE-X25519" if not kex_group else f"ECDHE-{kex_group}"
            elif "DHE" in c_upper:
                kex_algorithm = "DHE"
            elif "RSA" in c_upper:
                kex_algorithm = "RSA-KEX"
            else:
                kex_algorithm = "ECDHE-P256"
            quantum_risk = "CRITICAL"  # Classical DH/ECDHE/RSA vulnerable to HNDL interception
            pqc_status = "VULNERABLE_CLASSICAL"
            hndl_vulnerable = True

        raw_props: Dict[str, Any] = {
            "tls_version": tls_version,
            "cipher_suite": cipher_name,
            "kex_group": kex_group or "negotiated",
            "is_hybrid_pqc": is_hybrid_pqc,
            "quantum_risk": quantum_risk,
            "hndl_vulnerable": hndl_vulnerable,
            "pqc_status": pqc_status,
            "omb_phase_deadline": 2030,
        }

        return CryptoAsset(
            asset_id=f"live-tls-kex:{host}:{port}",
            component_name=f"TLS-KeyExchange:{host}:{port}",
            algorithm=kex_algorithm,
            key_size=256,
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            file_path=f"https://{host}:{port}",
            line_number=0,
            x_tier=XTier.TRANSIENT,
            x_confidence="HIGH",
            evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            intent="CONFIDENTIALITY_IN_TRANSIT",
            exposure_profile=ExposureProfile.PUBLIC,
            p_hndl=1.0,
            agility_level=AgilityLevel.CONFIGURABLE,
            raw_properties=raw_props,
        )

    def parse_bulk_cipher(
        self,
        tls_version: str,
        cipher_name: str,
        secret_bits: int,
        host: str,
        port: int,
    ) -> CryptoAsset:
        """
        Parses symmetric bulk encryption cipher and evaluates Grover's algorithm exposure.
        """
        c_upper = cipher_name.upper()
        if "AES_256_GCM" in c_upper or "AES-256-GCM" in c_upper:
            cipher_alg = "AES-256-GCM"
            key_bits = 256
        elif "AES_128_GCM" in c_upper or "AES-128-GCM" in c_upper:
            cipher_alg = "AES-128-GCM"
            key_bits = 128
        elif "CHACHA20" in c_upper:
            cipher_alg = "CHACHA20-POLY1305"
            key_bits = 256
        elif "AES_128_CCM" in c_upper:
            cipher_alg = "AES-128-CCM"
            key_bits = 128
        elif "AES_256_CBC" in c_upper or "AES256" in c_upper:
            cipher_alg = "AES-256-CBC"
            key_bits = 256
        elif "AES_128_CBC" in c_upper or "AES128" in c_upper:
            cipher_alg = "AES-128-CBC"
            key_bits = 128
        else:
            cipher_alg = cipher_name
            key_bits = secret_bits if secret_bits else 128

        # Under Grover's quantum search algorithm, symmetric key strength is effectively halved
        if key_bits >= 256:
            quantum_risk = "LOW"
            pqc_status = "QUANTUM_RESISTANT"
        else:
            quantum_risk = "HIGH"  # 128-bit symmetric key reduced to 64 bits effective security
            pqc_status = "VULNERABLE_CLASSICAL"

        raw_props: Dict[str, Any] = {
            "tls_version": tls_version,
            "cipher_suite": cipher_name,
            "symmetric_bits": key_bits,
            "quantum_risk": quantum_risk,
            "pqc_status": pqc_status,
        }

        return CryptoAsset(
            asset_id=f"live-tls-cipher:{host}:{port}",
            component_name=f"TLS-BulkCipher:{host}:{port}",
            algorithm=cipher_alg,
            key_size=key_bits,
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            file_path=f"https://{host}:{port}",
            line_number=0,
            x_tier=XTier.TRANSIENT,
            x_confidence="HIGH",
            evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
            intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
            intent="CONFIDENTIALITY_IN_TRANSIT",
            exposure_profile=ExposureProfile.PUBLIC,
            p_hndl=1.0,
            agility_level=AgilityLevel.CONFIGURABLE,
            raw_properties=raw_props,
        )

    def probe_endpoint(
        self,
        target: str,
        timeout: float = 5.0,
        kex_group_override: Optional[str] = None,
    ) -> List[CryptoAsset]:
        """
        Connects via TCP socket to target, wraps with TLS context, extracts live
        handshake cryptographic parameters, and returns a 3-tuple list of CryptoAsset models:
        1. Server Certificate (SIGNATURE)
        2. Key Exchange Mechanism (KEY_EXCHANGE)
        3. Bulk Encryption Cipher (SYMMETRIC_CIPHER)
        """
        host, port = self.parse_target(target)

        # Prepare TLS client context with permissive certificate extraction
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Establish TCP connection and TLS handshake with timeout handling
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                server_hostname = host if not self._is_raw_ip(host) else None
                with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    tls_version = ssock.version() or "TLSv1.2"
                    cipher_info = ssock.cipher()
                    der_cert = ssock.getpeercert(binary_form=True)
        except (socket.error, ssl.SSLError, TimeoutError, OSError) as err:
            raise TLSProbeError(
                f"Failed to connect and probe TLS endpoint {host}:{port}: {err}",
                host=host,
                port=port,
                cause=err,
            ) from err

        cipher_name = cipher_info[0] if cipher_info else "UNKNOWN"
        secret_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 128

        # 1. Server Certificate Asset
        cert_asset = self.parse_certificate(der_cert, host, port)

        # 2. Key Exchange Asset
        kex_asset = self.parse_key_exchange(
            tls_version=tls_version,
            cipher_name=cipher_name,
            host=host,
            port=port,
            kex_group=kex_group_override,
        )

        # 3. Bulk Encryption Cipher Asset
        cipher_asset = self.parse_bulk_cipher(
            tls_version=tls_version,
            cipher_name=cipher_name,
            secret_bits=secret_bits,
            host=host,
            port=port,
        )

        return [cert_asset, kex_asset, cipher_asset]

    @staticmethod
    def _is_raw_ip(host: str) -> bool:
        """Determines if host is an IPv4 or IPv6 literal without regular expressions."""
        # IPv6 contains colons
        if ":" in host:
            return True
        # IPv4 has exactly 4 segments all numeric
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return True
        return False
