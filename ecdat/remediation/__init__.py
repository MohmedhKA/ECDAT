"""
ECDAT Remediation Module:
Provides 1-Click Code Remediation Engine, Journal, and Patching Utilities.
Strictly zero-regex compliant.
"""

from ecdat.remediation.journal import RemediationJournal
from ecdat.remediation.engine import RemediationEngine, PatchResult

__all__ = [
    "RemediationJournal",
    "RemediationEngine",
    "PatchResult",
]
