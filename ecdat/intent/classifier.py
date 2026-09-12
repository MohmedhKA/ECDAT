"""
ECDAT DSIS Intent Classifier:
Implements Dual-Sink Semantic Intent Classification (DSIS) to determine the functional
security purpose of cryptographic operations and suppress false alarms on operational utilities.
"""

from typing import Optional, Tuple
from ecdat.models import IntentClass, PrimitiveType
from ecdat.intent.sink_signatures import INTENT_SIGNATURE_CATALOG

class IntentClassifier:
    """
    Classifies the functional security intent of a cryptographic primitive using
    terminal sinks, variable flow identifiers, and lexical context.
    """

    @classmethod
    def classify(
        cls,
        var_name: str,
        sink_call: Optional[str] = None,
        context_lines: Optional[str] = None,
        primitive_type: Optional[PrimitiveType] = None,
    ) -> Tuple[IntentClass, str]:
        var_lower = var_name.lower()
        sink_lower = (sink_call or "").lower()
        ctx_lower = (context_lines or "").lower()

        # Step 1: Terminal Sink Call Check (Highest confidence)
        if sink_lower:
            # Check Operational Utility sinks (ETags, caches)
            for pattern in INTENT_SIGNATURE_CATALOG[0]["call_patterns"]:
                if pattern in sink_lower:
                    return (
                        IntentClass.OPERATIONAL_UTILITY,
                        f"Operational utility detected: terminal sink matches '{pattern}' (0% quantum exploit risk).",
                    )
            # Check Authentication Signatures (JWTs, auth)
            for pattern in INTENT_SIGNATURE_CATALOG[2]["call_patterns"]:
                if pattern in sink_lower:
                    return (
                        IntentClass.AUTHENTICATION_SIGNATURE,
                        f"Authentication signature detected: sink matches '{pattern}'.",
                    )
            # Check Confidentiality Envelopes (DB persistence, cloud storage, cipher operations)
            for pattern in INTENT_SIGNATURE_CATALOG[3]["call_patterns"]:
                if pattern in sink_lower:
                    return (
                        IntentClass.CONFIDENTIALITY_ENVELOPE,
                        f"Confidentiality envelope detected: sink matches '{pattern}'.",
                    )
            # Check Integrity Checksums
            for pattern in INTENT_SIGNATURE_CATALOG[1]["call_patterns"]:
                if pattern in sink_lower:
                    return (
                        IntentClass.INTEGRITY_CHECKSUM,
                        f"Integrity checksum detected: sink matches '{pattern}'.",
                    )

        # Step 2: Variable Naming Check
        for entry in INTENT_SIGNATURE_CATALOG:
            for pattern in entry["var_patterns"]:
                if pattern in var_lower:
                    return (
                        entry["intent"],
                        f"{entry['intent'].value} detected: variable identifier contains '{pattern}'.",
                    )

        # Step 3: Context Lines Check (if sink wasn't matched above)
        if ctx_lower:
            for entry in INTENT_SIGNATURE_CATALOG:
                for pattern in entry["call_patterns"]:
                    if pattern in ctx_lower:
                        return (
                            entry["intent"],
                            f"{entry['intent'].value} detected: context contains '{pattern}'.",
                        )

        # Step 4: Heuristic fallback based on primitive type
        if primitive_type == PrimitiveType.SIGNATURE:
            return (
                IntentClass.AUTHENTICATION_SIGNATURE,
                "Defaulting to authentication signature based on primitive type SIGNATURE.",
            )
        elif primitive_type == PrimitiveType.HASH:
            return (
                IntentClass.INTEGRITY_CHECKSUM,
                "Defaulting to integrity checksum based on primitive type HASH.",
            )
        elif primitive_type in (PrimitiveType.ENCRYPTION, PrimitiveType.KEY_EXCHANGE):
            return (
                IntentClass.CONFIDENTIALITY_ENVELOPE,
                f"Defaulting to confidentiality envelope based on primitive type {primitive_type.value}.",
            )

        # Conservative fallback
        return (
            IntentClass.CONFIDENTIALITY_ENVELOPE,
            "Defaulting to confidentiality envelope (conservative defense-in-depth).",
        )

def classify_intent(
    var_name: str,
    sink_call: Optional[str] = None,
    context_lines: Optional[str] = None,
    primitive_type: Optional[PrimitiveType] = None,
) -> Tuple[IntentClass, str]:
    """Convenience functional wrapper for IntentClassifier.classify."""
    return IntentClassifier.classify(
        var_name=var_name,
        sink_call=sink_call,
        context_lines=context_lines,
        primitive_type=primitive_type,
    )
