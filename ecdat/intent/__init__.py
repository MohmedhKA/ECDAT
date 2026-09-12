"""
ECDAT Intent Classification Package:
Dual-Sink Semantic Intent Classification (DSIS) for post-quantum cryptographic risk analysis.
"""

from ecdat.intent.classifier import IntentClassifier, classify_intent
from ecdat.models import IntentClass

__all__ = ["IntentClassifier", "classify_intent", "IntentClass"]
