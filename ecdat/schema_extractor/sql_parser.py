"""
ECDAT SQL DDL Lifespan Parser:
Extracts data retention policies, column-level TTL constraints, and archival classifications
directly from SQL DDL and migration statements.
"""

import re
from typing import Dict, Tuple
from ecdat.models import XTier

TABLE_REGEX = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"']?[a-zA-Z0-9_\-\.]+[`\"']?)\s*\((.*?)\);", re.DOTALL | re.IGNORECASE)
RETENTION_COMMENT_REGEX = re.compile(r"--\s*retention:\s*(\d+)\s*(days?|months?|years?)", re.IGNORECASE)
INLINE_COMMENT_REGEX = re.compile(r"COMMENT\s+['\"][^'\"]*retention:\s*(\d+)\s*(days?|months?|years?)", re.IGNORECASE)

# Lexical table categories
ARCHIVAL_TABLES = {"patient", "medical", "health", "tax", "audit", "legal", "archive", "ballot", "vote", "identity", "kyc"}
EPHEMERAL_TABLES = {"session", "token", "temp", "cache", "nonce", "otp", "captcha", "staging"}

def _parse_duration_to_years(amount: int, unit: str) -> float:
    unit_lower = unit.lower()
    if "day" in unit_lower:
        return round(amount / 365.25, 2)
    elif "month" in unit_lower:
        return round(amount / 12.0, 2)
    elif "year" in unit_lower:
        return float(amount)
    return 5.0

def parse_sql_ddl_lifespan(sql_content: str, filename: str = "schema.sql") -> Dict[str, Tuple[XTier, float, str]]:
    """
    Parses SQL DDL text and returns mapping of table/entity names to
    (XTier, effective_years, provenance_string).
    """
    results: Dict[str, Tuple[XTier, float, str]] = {}

    for match in TABLE_REGEX.finditer(sql_content):
        raw_table_name = match.group(1).strip("`\"' ")
        table_body = match.group(2)
        table_lower = raw_table_name.lower()

        # Check comment on the preceding line (before CREATE TABLE)
        preceding_text = sql_content[:match.start()].rstrip()
        preceding_lines = preceding_text.splitlines()
        preceding_comment = ""
        if preceding_lines:
            last_line = preceding_lines[-1].strip()
            if (last_line.startswith("--") or last_line.startswith("/*")) and ");" not in last_line:
                preceding_comment = last_line

        # Check trailing comment on the closing semicolon line
        trailing_text = sql_content[match.end():]
        trailing_comment = trailing_text.splitlines()[0] if trailing_text else ""

        # Check explicit retention comment inside or directly adjacent to table definition
        retention_match = (
            RETENTION_COMMENT_REGEX.search(table_body)
            or INLINE_COMMENT_REGEX.search(table_body)
            or RETENTION_COMMENT_REGEX.search(trailing_comment)
            or RETENTION_COMMENT_REGEX.search(preceding_comment)
            or INLINE_COMMENT_REGEX.search(trailing_comment)
        )
        if retention_match:
            amount = int(retention_match.group(1))
            unit = retention_match.group(2)
            years = _parse_duration_to_years(amount, unit)
            tier = (
                XTier.EPHEMERAL if years <= 0.1 else
                XTier.SHORT_TERM if years <= 2.0 else
                XTier.OPERATIONAL if years <= 7.0 else
                XTier.ARCHIVAL
            )
            provenance = f"sql_retention_comment:{filename}:{raw_table_name}:{amount}_{unit}"
            results[table_lower] = (tier, years, provenance)
            continue

        # Check for TTL / Expiry columns
        if any(col in table_body.lower() for col in ["expires_at", "valid_until", "ttl_timestamp", "expiry"]):
            results[table_lower] = (
                XTier.SHORT_TERM,
                1.0,
                f"sql_ttl_column:{filename}:{raw_table_name}",
            )
            continue

        # Check domain-specific table heuristics
        if any(arch in table_lower for arch in ARCHIVAL_TABLES):
            results[table_lower] = (
                XTier.ARCHIVAL,
                10.0,
                f"sql_archival_heuristic:{filename}:{raw_table_name}",
            )
        elif any(eph in table_lower for eph in EPHEMERAL_TABLES):
            results[table_lower] = (
                XTier.SHORT_TERM,
                1.0,
                f"sql_ephemeral_heuristic:{filename}:{raw_table_name}",
            )

    return results
