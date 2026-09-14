import pytest
from ecdat.models import RouteProfile
from ecdat.network.mtu_prober import probe_network_mtu, calculate_pqc_flight_estimates

def test_mtu_standard_profile_pqc_estimates():
    res = probe_network_mtu(override_profile=RouteProfile.STANDARD, override_mtu=1500)
    assert res.route_profile == RouteProfile.STANDARD
    assert res.effective_mtu == 1500
    assert res.mss == 1460
    assert res.df_bit_strict is True

    estimates = res.pqc_flight_estimates
    # ML-KEM-768 (1184 B) fits inside single 1460 B segment
    assert estimates["ML-KEM-768"]["fits_single_packet"] is True
    assert estimates["ML-KEM-768"]["packet_segments"] == 1
    assert estimates["ML-KEM-768"]["warning"] is None

    # ML-KEM-1024 (1568 B) exceeds 1460 B segment (requires 2 segments, warning emitted)
    assert estimates["ML-KEM-1024"]["fits_single_packet"] is False
    assert estimates["ML-KEM-1024"]["packet_segments"] == 2
    assert "exceeds route MSS" in estimates["ML-KEM-1024"]["warning"]

    # ML-DSA-65 (5261 B flight) requires 4 segments
    assert estimates["ML-DSA-65"]["packet_segments"] == 4
    assert estimates["ML-DSA-65"]["fits_single_packet"] is False

def test_mtu_constrained_profile():
    # Cellular / VPN tunnel with MTU 1200
    res = probe_network_mtu(override_profile=RouteProfile.CONSTRAINED, override_mtu=1200)
    assert res.route_profile == RouteProfile.CONSTRAINED
    assert res.effective_mtu == 1200
    assert res.mss == 1160
    assert res.middlebox_drop_risk == "HIGH"

    estimates = res.pqc_flight_estimates
    # ML-KEM-768 (1184 B) now exceeds 1160 B MSS
    assert estimates["ML-KEM-768"]["fits_single_packet"] is False
    assert estimates["ML-KEM-768"]["packet_segments"] == 2

    # ML-KEM-512 (800 B) still fits
    assert estimates["ML-KEM-512"]["fits_single_packet"] is True
    assert estimates["ML-KEM-512"]["packet_segments"] == 1

def test_mtu_flexible_profile():
    res = probe_network_mtu(override_profile=RouteProfile.FLEXIBLE, override_mtu=9000)
    assert res.route_profile == RouteProfile.FLEXIBLE
    assert res.effective_mtu == 9000
    assert res.df_bit_strict is False
    assert res.middlebox_drop_risk == "LOW"

    # In 9000 MTU jumbo frame, ML-KEM-1024 and ML-DSA-65 fit in single frame
    estimates = res.pqc_flight_estimates
    assert estimates["ML-KEM-1024"]["fits_single_packet"] is True
    assert estimates["ML-DSA-65"]["fits_single_packet"] is True

def test_default_probe_fallback():
    # Without overrides, probes local host or defaults safely
    res = probe_network_mtu()
    assert res.effective_mtu >= 1000
    assert res.mss == res.effective_mtu - 40
    assert res.route_profile in {RouteProfile.STANDARD, RouteProfile.FLEXIBLE, RouteProfile.CONSTRAINED}
    assert len(res.pqc_flight_estimates) >= 5
