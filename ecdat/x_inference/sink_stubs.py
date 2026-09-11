"""
ECDAT Persistence Sink Signatures:
A curated library of known API sinks across relational databases, ORMs, cloud object storage,
caching engines, and ephemeral network/memory buffers.
"""

from typing import Optional, Tuple, Dict, List, Any
from ecdat.models import XTier

# Pre-annotated sink patterns: substring/pattern -> (XTier, confidence, description)
KNOWN_SINK_SIGNATURES: List[Dict[str, Any]] = [
    # ── 1. EPHEMERAL Sinks (~0 years) ──
    {
        "patterns": [".sendall", ".send", "socket", "SSLSocket", "stream.write", "transport.write", "channel.write"],
        "tier": XTier.EPHEMERAL,
        "confidence": "HIGH",
        "description": "Network socket transmission; transient volatile buffer zeroed on session close.",
    },
    {
        "patterns": ["sodium_memzero", "explicit_bzero", "Arrays.fill", "memset", "del "],
        "tier": XTier.EPHEMERAL,
        "confidence": "HIGH",
        "description": "Explicit memory zeroization/destruction call found in scope.",
    },

    # ── 2. SHORT-TERM Sinks (~1-2 years) ──
    {
        "patterns": ["redis.setex", "redis.set", "memcached.set", "cache.set", "session_cache"],
        "tier": XTier.SHORT_TERM,
        "confidence": "HIGH",
        "description": "Transient caching layer with TTL expiration.",
    },

    # ── 3. OPERATIONAL Sinks (~3-7 years, baseline 5 years) ──
    {
        "patterns": [
            "session.add", "session.commit", "session.save", "db.session",
            "repository.save", "repository.saveAndFlush",
            "cursor.execute", "PreparedStatement.executeUpdate",
            "insert_one", "insert_many", "save_record"
        ],
        "tier": XTier.OPERATIONAL,
        "confidence": "HIGH",
        "description": "Relational/document database persistence sink (active operational store).",
    },

    # ── 4. ARCHIVAL Sinks (~10+ years to permanent) ──
    {
        "patterns": [
            "s3.put_object", "s3.upload_file", "s3_client.put_object",
            "blobClient.upload_blob", "bucket.blob", "cloud_storage",
            "open(", "write(", "archive", "backup", "cold_storage"
        ],
        "tier": XTier.ARCHIVAL,
        "confidence": "HIGH",
        "description": "Long-term disk, file, or cloud object storage archive sink.",
    },
]

def match_sink_pattern(call_representation: str) -> Optional[Tuple[XTier, str, str]]:
    """
    Checks if a method invocation or syntax matches any known persistence sink.
    Returns (XTier, confidence, description) or None if unmatched.
    """
    call_lower = call_representation.lower()
    for entry in KNOWN_SINK_SIGNATURES:
        for pattern in entry["patterns"]:
            if pattern.lower() in call_lower:
                return entry["tier"], entry["confidence"], entry["description"]
    return None
