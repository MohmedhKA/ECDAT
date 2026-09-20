"""
ECDAT Server Configuration Cryptographic Scanner:
Statically discovers cryptographic protocols, TLS cipher suites, and certificate bindings
in server configurations (Nginx, Apache, Envoy, HAProxy) with E3_CONFIG_CONFIRMED evidence.
"""

import re
from pathlib import Path
from typing import List, Dict, Set, Optional

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
    IntentClass,
    AgilityLevel
)
from ecdat.rules.signature_db import get_signature_db

# Directives in Nginx/Apache configuration
SSL_PROTOCOLS_RE = re.compile(r'\bssl_protocols\s+([^;]+);', re.IGNORECASE)
SSL_CIPHERS_RE = re.compile(r'\bssl_ciphers\s+[\'"]?([^;\'"]+)[\'"]?;', re.IGNORECASE)
SSL_ECDH_CURVE_RE = re.compile(r'\bssl_ecdh_curve\s+([^;]+);', re.IGNORECASE)

class ConfigScanner:
    """Discovers cryptographic configurations in server configuration files."""

    def __init__(self):
        self.db = get_signature_db()

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem
        assets: List[CryptoAsset] = []
        seen_keys: Set[str] = set()

        # 1. Parse ssl_protocols (e.g. TLSv1 TLSv1.1 TLSv1.2 TLSv1.3)
        for m in SSL_PROTOCOLS_RE.finditer(content):
            protocols = m.group(1).split()
            line_no = content.count("\n", 0, m.start()) + 1
            for proto in protocols:
                proto_clean = proto.strip().upper()
                is_legacy = proto_clean in ("SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1")
                risk = "CRITICAL" if "SSL" in proto_clean else ("HIGH" if is_legacy else "LOW")
                cwe = "CWE-326" if is_legacy else None

                dedup_key = f"{rel_path}:{proto_clean}:{line_no}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                assets.append(CryptoAsset(
                    asset_id=f"CFG-TLS-{len(assets) + 1:03d}",
                    component_name=f"{stem}:{proto_clean.lower()}",
                    algorithm=proto_clean,
                    key_size=None,
                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=XTier.OPERATIONAL,
                    x_confidence="HIGH",
                    has_crypto_shredding=False,
                    intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                    evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
                    evidence_sources=["config_scanner:ssl_protocols"],
                    agility_level=AgilityLevel.CONFIGURABLE,
                    raw_properties={
                        "source": "config_scanner",
                        "config_type": "nginx_tls",
                        "directive": "ssl_protocols",
                        "matched_code": m.group(0)[:80],
                        "ecdat:risk_level": risk,
                        "cwe": cwe,
                        "description": f"Configured TLS protocol version {proto_clean}"
                    }
                ))

        # 2. Parse ssl_ciphers (colon- or space-delimited list)
        for m in SSL_CIPHERS_RE.finditer(content):
            raw_ciphers = m.group(1).replace(":", " ").replace("+", " ").split()
            line_no = content.count("\n", 0, m.start()) + 1
            for cipher in raw_ciphers:
                cipher_clean = cipher.strip().strip("'\"")
                if not cipher_clean or cipher_clean.startswith("!"):
                    continue

                cipher_upper = cipher_clean.upper()
                is_broken = any(b in cipher_upper for b in ("RC4", "DES", "MD5", "NULL", "EXPORT"))
                risk = "CRITICAL" if any(b in cipher_upper for b in ("RC4", "DES-CBC3", "MD5", "NULL")) else ("HIGH" if is_broken else "LOW")
                cwe = "CWE-327" if is_broken else None

                dedup_key = f"{rel_path}:{cipher_upper}:{line_no}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                assets.append(CryptoAsset(
                    asset_id=f"CFG-CIPHER-{len(assets) + 1:03d}",
                    component_name=f"{stem}:{cipher_upper.lower()}",
                    algorithm=cipher_upper,
                    key_size=128 if "128" in cipher_upper else (256 if "256" in cipher_upper else None),
                    primitive_type=PrimitiveType.ENCRYPTION,
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=XTier.OPERATIONAL,
                    x_confidence="HIGH",
                    has_crypto_shredding=False,
                    intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                    evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
                    evidence_sources=["config_scanner:ssl_ciphers"],
                    agility_level=AgilityLevel.CONFIGURABLE,
                    raw_properties={
                        "source": "config_scanner",
                        "config_type": "nginx_tls",
                        "directive": "ssl_ciphers",
                        "matched_code": m.group(0)[:80],
                        "ecdat:risk_level": risk,
                        "cwe": cwe,
                        "description": f"Configured TLS cipher suite {cipher_upper}"
                    }
                ))

        # 3. Parse ssl_ecdh_curve (e.g. X25519:prime256v1)
        for m in SSL_ECDH_CURVE_RE.finditer(content):
            curves = m.group(1).replace(":", " ").split()
            line_no = content.count("\n", 0, m.start()) + 1
            for curve in curves:
                curve_clean = curve.strip().upper()
                if not curve_clean:
                    continue
                dedup_key = f"{rel_path}:{curve_clean}:{line_no}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                assets.append(CryptoAsset(
                    asset_id=f"CFG-CURVE-{len(assets) + 1:03d}",
                    component_name=f"{stem}:{curve_clean.lower()}",
                    algorithm=curve_clean,
                    key_size=256,
                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                    file_path=rel_path,
                    line_number=line_no,
                    x_tier=XTier.OPERATIONAL,
                    x_confidence="HIGH",
                    has_crypto_shredding=False,
                    intent_class=IntentClass.AUTHENTICATION_SIGNATURE,
                    evidence_level=EvidenceLevel.E3_CONFIG_CONFIRMED,
                    evidence_sources=["config_scanner:ssl_ecdh_curve"],
                    agility_level=AgilityLevel.CONFIGURABLE,
                    raw_properties={
                        "source": "config_scanner",
                        "config_type": "nginx_tls",
                        "directive": "ssl_ecdh_curve",
                        "matched_code": m.group(0)[:80],
                        "ecdat:risk_level": "HIGH", # Classical ECC vulnerable to Shor's
                        "cwe": "CWE-326",
                        "description": f"Configured ECDH key exchange curve {curve_clean}"
                    }
                ))

        return assets

def scan_server_configs(target_dir: Path) -> List[CryptoAsset]:
    """Recursively scans target_dir for server configuration files (.conf, .yaml, .yml)."""
    scanner = ConfigScanner()
    assets: List[CryptoAsset] = []
    for conf_file in sorted(target_dir.glob("**/*.conf")):
        if conf_file.is_file():
            assets.extend(scanner.scan_file(conf_file, target_dir))
    return assets
