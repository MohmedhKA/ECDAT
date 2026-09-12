"""
ECDAT ORM & Model Lifespan Parser:
Extracts data secrecy lifespans from Prisma schemas (.prisma) and Python ORM models (Django, SQLAlchemy).
"""

import re
from typing import Dict, Tuple
from ecdat.models import XTier

PRISMA_MODEL_REGEX = re.compile(r"model\s+([a-zA-Z0-9_]+)\s*\{(.*?)\}", re.DOTALL)
PRISMA_COMMENT_RETENTION = re.compile(r"//\s*retention:\s*(\d+)\s*(days?|months?|years?)", re.IGNORECASE)

def parse_orm_schema_lifespan(content: str, filename: str = "schema.prisma") -> Dict[str, Tuple[XTier, float, str]]:
    """
    Parses ORM schema definitions and returns entity-to-lifespan mappings.
    """
    results: Dict[str, Tuple[XTier, float, str]] = {}

    for match in PRISMA_MODEL_REGEX.finditer(content):
        model_name = match.group(1)
        model_body = match.group(2)
        model_lower = model_name.lower()

        # Check comment retention
        retention_match = PRISMA_COMMENT_RETENTION.search(model_body)
        if retention_match:
            amount = int(retention_match.group(1))
            unit = retention_match.group(2).lower()
            years = amount if "year" in unit else round(amount / 12.0, 2) if "month" in unit else round(amount / 365.25, 2)
            tier = (
                XTier.EPHEMERAL if years <= 0.1 else
                XTier.SHORT_TERM if years <= 2.0 else
                XTier.OPERATIONAL if years <= 7.0 else
                XTier.ARCHIVAL
            )
            results[model_lower] = (tier, years, f"prisma_retention:{filename}:{model_name}")
            continue

        # Check TTL attributes or fields
        if any(attr in model_body.lower() for attr in ["expiresat", "validuntil", "expireafterseconds", "ttl"]):
            results[model_lower] = (
                XTier.SHORT_TERM,
                1.0,
                f"prisma_ttl_field:{filename}:{model_name}",
            )
            continue

        # Domain keywords
        if any(k in model_lower for k in ["patient", "medical", "ballot", "vote", "audit"]):
            results[model_lower] = (
                XTier.ARCHIVAL,
                10.0,
                f"prisma_archival_model:{filename}:{model_name}",
            )
        elif any(k in model_lower for k in ["session", "token", "otp", "nonce"]):
            results[model_lower] = (
                XTier.SHORT_TERM,
                1.0,
                f"prisma_ephemeral_model:{filename}:{model_name}",
            )

    return results
