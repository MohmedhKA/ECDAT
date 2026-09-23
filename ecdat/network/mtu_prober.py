"""
ECDAT Active Path MTU & Transport Fragmentation Prober (Pillar 5):
Evaluates network route readiness for PQC size expansions (NIST FIPS 203/204).
Classifies routes into STANDARD (1500 B), FLEXIBLE (>=1500 B), and CONSTRAINED (<1280 B),
calculating exact TCP flight segments and middlebox packet drop risks.
"""

import os
import sys
import socket
import math
from pathlib import Path
from typing import Optional, Dict, Any

from ecdat.models import RouteProfile, PathMTUResult
from ecdat.constants import NIST_PRIMITIVE_SIZES

# Standard Header Overhead: 20 B IPv4 + 20 B TCP = 40 B (or 40 B IPv6 + 20 B TCP = 60 B)
TCP_IP_HEADER_OVERHEAD = 40

# PQC TLS 1.3 Key Exchange and Signature Flight Sizes (Bytes)
PQC_FLIGHT_SPECS: Dict[str, Dict[str, Any]] = {
    "ML-KEM-512": {
        "pubkey_bytes": 800,
        "ciphertext_bytes": 768,
        "flight_bytes": 800,
        "primitive": "KEM",
        "description": "NIST Level 1 Key Encapsulation",
    },
    "ML-KEM-768": {
        "pubkey_bytes": 1184,
        "ciphertext_bytes": 1088,
        "flight_bytes": 1184,
        "primitive": "KEM",
        "description": "NIST Level 3 Key Encapsulation",
    },
    "ML-KEM-1024": {
        "pubkey_bytes": 1568,
        "ciphertext_bytes": 1568,
        "flight_bytes": 1568,
        "primitive": "KEM",
        "description": "NIST Level 5 Key Encapsulation",
    },
    "X25519MLKEM768": {
        "pubkey_bytes": 1216,  # 32 B X25519 + 1184 B ML-KEM-768
        "ciphertext_bytes": 1120,
        "flight_bytes": 1216,
        "primitive": "HYBRID_KEM",
        "description": "ECDHE-ML-KEM-768 Hybrid Key Exchange",
    },
    "ML-DSA-44": {
        "pubkey_bytes": 1312,
        "signature_bytes": 2420,
        "flight_bytes": 3732,  # Pubkey + Signature in Handshake Cert
        "primitive": "SIGNATURE",
        "description": "NIST Level 2 Digital Signature",
    },
    "ML-DSA-65": {
        "pubkey_bytes": 1952,
        "signature_bytes": 3309,
        "flight_bytes": 5261,  # Certificate flight overhead
        "primitive": "SIGNATURE",
        "description": "NIST Level 3 Digital Signature",
    },
    "ML-DSA-87": {
        "pubkey_bytes": 2592,
        "signature_bytes": 4627,
        "flight_bytes": 7219,
        "primitive": "SIGNATURE",
        "description": "NIST Level 5 Digital Signature",
    },
    "SLH-DSA-128S": {
        "pubkey_bytes": 32,
        "signature_bytes": 7856,
        "flight_bytes": 7888,
        "primitive": "SIGNATURE",
        "description": "NIST Level 1 Stateless Hash Signature",
    },
}

def calculate_pqc_flight_estimates(mss: int, df_bit_strict: bool) -> Dict[str, Any]:
    """
    Computes packet fragmentation count and middlebox drop risk for each PQC suite
    given the route MSS.
    """
    estimates: Dict[str, Any] = {}

    for suite_name, spec in PQC_FLIGHT_SPECS.items():
        flight_len = spec["flight_bytes"]
        packet_count = math.ceil(flight_len / mss) if mss > 0 else 1
        fits_single_packet = (flight_len <= mss)

        warning: Optional[str] = None
        if not fits_single_packet:
            if df_bit_strict:
                warning = (
                    f"{suite_name} Flight ({flight_len} B) exceeds route MSS ({mss} B). "
                    f"Requires {packet_count} TCP segments with high middlebox drop risk."
                )
            else:
                warning = f"{suite_name} Flight ({flight_len} B) requires {packet_count} TCP segments."

        estimates[suite_name] = {
            "flight_bytes": flight_len,
            "packet_segments": packet_count,
            "fits_single_packet": fits_single_packet,
            "warning": warning,
            "primitive": spec["primitive"],
            "description": spec["description"],
        }

    return estimates

def _probe_interface_mtu() -> int:
    """Inspects Linux /sys/class/net interfaces or returns standard 1500 default."""
    try:
        sys_net = Path("/sys/class/net")
        if sys_net.exists():
            mtus = []
            for iface in sys_net.iterdir():
                if iface.name == "lo":
                    continue
                mtu_file = iface / "mtu"
                if mtu_file.exists():
                    try:
                        val = int(mtu_file.read_text().strip())
                        if val > 0:
                            mtus.append(val)
                    except Exception:
                        pass
            if mtus:
                # Return lowest non-loopback MTU on system (conservative bound)
                return min(mtus)
    except Exception:
        pass
    return 1500

IP_MTU_DISCOVER = 10
IP_PMTUDISC_DO = 2
IP_MTU = 14

def _probe_df_path_mtu(target_host: str, port: int = 53, timeout: float = 2.0) -> Optional[int]:
    """
    Performs unprivileged Path MTU Discovery (RFC 1191) using UDP SOCK_DGRAM
    with the IP Don't-Fragment (DF) bit set (IP_PMTUDISC_DO).
    Requires zero root privileges or raw socket capabilities (CAP_NET_RAW).
    Catches kernel errno.EMSGSIZE to detect bottleneck MTU limits.
    """
    if sys.platform != "linux":
        return None

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Set IP_MTU_DISCOVER to IP_PMTUDISC_DO (sets DF bit on all outgoing IP packets)
        if hasattr(socket, "IP_MTU_DISCOVER") and hasattr(socket, "IP_PMTUDISC_DO"):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
        else:
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)

        # Resolve IP
        target_ip = socket.gethostbyname(target_host)
        sock.connect((target_ip, port))

        # Probe candidate sizes: 1500 (Ethernet), 1420 (WireGuard/VPN), 1280 (IPv6 min)
        probe_sizes = [1500, 1420, 1280]
        detected_pmtu = None

        for target_mtu in probe_sizes:
            payload_len = target_mtu - 28  # 20 B IP + 8 B UDP
            try:
                sock.send(b"\x00" * payload_len)
                try:
                    learned = sock.getsockopt(socket.IPPROTO_IP, IP_MTU)
                    if 500 <= learned <= 9000:
                        detected_pmtu = learned
                        break
                except Exception:
                    detected_pmtu = target_mtu
                    break
            except OSError as e:
                import errno
                if e.errno == errno.EMSGSIZE:
                    continue
                else:
                    break

        return detected_pmtu
    except Exception:
        return None
    finally:
        if sock:
            sock.close()

def _probe_socket_mss(target_host: str, port: int = 443, timeout: float = 1.5) -> Optional[int]:
    """Attempts unprivileged TCP socket MSS inspection via TCP_MAXSEG (RFC 4821)."""
    try:
        with socket.create_connection((target_host, port), timeout=timeout) as sock:
            # TCP_MAXSEG socket option
            if hasattr(socket, "TCP_MAXSEG"):
                mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                if 500 <= mss <= 9000:
                    return mss
    except Exception:
        pass
    return None

def probe_network_mtu(
    target_host: Optional[str] = None,
    port: int = 443,
    override_profile: Optional[RouteProfile] = None,
    override_mtu: Optional[int] = None,
) -> PathMTUResult:
    """
    Probes path MTU or assigns route profile and computes PQC flight fragmentation estimates.
    """
    # 1. Manual Overrides
    if override_profile is not None:
        if override_profile == RouteProfile.CONSTRAINED:
            effective_mtu = override_mtu or 1240
            mss = effective_mtu - TCP_IP_HEADER_OVERHEAD
            df_strict = True
            drop_risk = "HIGH"
        elif override_profile == RouteProfile.FLEXIBLE:
            effective_mtu = override_mtu or 9000
            mss = effective_mtu - TCP_IP_HEADER_OVERHEAD
            df_strict = False
            drop_risk = "LOW"
        else:
            effective_mtu = override_mtu or 1500
            mss = effective_mtu - TCP_IP_HEADER_OVERHEAD
            df_strict = True
            drop_risk = "MEDIUM"

        return PathMTUResult(
            route_profile=override_profile,
            effective_mtu=effective_mtu,
            mss=mss,
            probing_method="configured_override",
            df_bit_strict=df_strict,
            middlebox_drop_risk=drop_risk,
            pqc_flight_estimates=calculate_pqc_flight_estimates(mss, df_strict),
        )

    # 2. Socket-based active probe (if target_host provided)
    if target_host:
        # First attempt real DF-bit PMTUD via unprivileged UDP socket
        probed_mtu = _probe_df_path_mtu(target_host, port=port if port != 443 else 53)
        probing_method = f"active_df_pmtud:{target_host}"

        if probed_mtu is None:
            # Fallback to TCP_MAXSEG inspection (RFC 4821)
            probed_mss = _probe_socket_mss(target_host, port=port)
            if probed_mss is not None:
                probed_mtu = probed_mss + TCP_IP_HEADER_OVERHEAD
                probing_method = f"socket_mss:{target_host}:{port}"

        if probed_mtu is not None:
            effective_mtu = probed_mtu
            effective_mss = effective_mtu - TCP_IP_HEADER_OVERHEAD
            if effective_mtu < 1280:
                profile = RouteProfile.CONSTRAINED
                drop_risk = "HIGH"
                df_strict = True
            elif effective_mtu >= 1500:
                profile = RouteProfile.STANDARD
                drop_risk = "MEDIUM"
                df_strict = True
            else:
                profile = RouteProfile.CONSTRAINED
                drop_risk = "HIGH"
                df_strict = True

            return PathMTUResult(
                route_profile=profile,
                effective_mtu=effective_mtu,
                mss=effective_mss,
                probing_method=probing_method,
                df_bit_strict=df_strict,
                middlebox_drop_risk=drop_risk,
                pqc_flight_estimates=calculate_pqc_flight_estimates(effective_mss, df_strict),
            )

    # 3. Local interface / CNI heuristic inspection
    detected_mtu = _probe_interface_mtu()
    if detected_mtu < 1280:
        profile = RouteProfile.CONSTRAINED
        drop_risk = "HIGH"
        df_strict = True
    elif detected_mtu > 1500:
        profile = RouteProfile.FLEXIBLE
        drop_risk = "LOW"
        df_strict = False
    else:
        profile = RouteProfile.STANDARD
        drop_risk = "MEDIUM"
        df_strict = True

    effective_mss = detected_mtu - TCP_IP_HEADER_OVERHEAD
    return PathMTUResult(
        route_profile=profile,
        effective_mtu=detected_mtu,
        mss=effective_mss,
        probing_method="interface_cni_heuristic",
        df_bit_strict=df_strict,
        middlebox_drop_risk=drop_risk,
        pqc_flight_estimates=calculate_pqc_flight_estimates(effective_mss, df_strict),
    )
