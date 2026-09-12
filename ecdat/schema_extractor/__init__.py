"""
ECDAT Schema Extractor:
Autonomous data secrecy lifespan (X_auto) derivation from SQL DDL,
ORM schemas (Prisma, Django, SQLAlchemy), and database retention annotations.
"""

from pathlib import Path
from typing import Dict, Tuple, Optional, Any, List
from ecdat.models import XTier
from ecdat.schema_extractor.sql_parser import parse_sql_ddl_lifespan
from ecdat.schema_extractor.orm_parser import parse_orm_schema_lifespan

def extract_schemas_lifespan(target_dir: str) -> Dict[str, Tuple[XTier, float, str]]:
    """
    Recursively scans target_dir for SQL migration files (.sql) and ORM models (.prisma, .py),
    extracting entity-level data secrecy lifespans (X_auto).
    Returns mapping: entity_name -> (XTier, effective_years, source_provenance).
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        return {}

    lifespan_map: Dict[str, Tuple[XTier, float, str]] = {}

    for fpath in target_path.glob("**/*"):
        if not fpath.is_file():
            continue
        suffix = fpath.suffix.lower()
        if suffix == ".sql":
            try:
                sql_content = fpath.read_text(encoding="utf-8", errors="replace")
                sql_results = parse_sql_ddl_lifespan(sql_content, fpath.name)
                lifespan_map.update(sql_results)
            except Exception:
                pass
        elif suffix == ".prisma" or (suffix == ".py" and "model" in fpath.name.lower()):
            try:
                orm_content = fpath.read_text(encoding="utf-8", errors="replace")
                orm_results = parse_orm_schema_lifespan(orm_content, fpath.name)
                lifespan_map.update(orm_results)
            except Exception:
                pass

    return lifespan_map
