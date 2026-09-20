"""
ECDAT Runtime Dynamic Observation Package.
"""

from ecdat.runtime.ebpf_observer import EBPFObserver, get_ebpf_observer

__all__ = ["EBPFObserver", "get_ebpf_observer"]
