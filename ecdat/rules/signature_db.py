"""
ECDAT Embedded Cryptographic Signature Database:
Zero-dependency, high-performance SQLite relational engine for deterministic
cryptographic primitive identification, parameter resolution, and PQC readiness scoring.
"""

import os
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, List
from functools import lru_cache

from ecdat.rules.seed_signatures import seed_database

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "crypto_signatures.db"
SCHEMA_SQL_PATH = Path(__file__).resolve().parent / "schema.sql"

class SignatureDatabase:
    """Thread-safe, embedded SQLite cryptographic signature and fingerprint store."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._ensure_initialized()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_initialized(self) -> None:
        """Initializes database schema and seeds default signatures if empty."""
        need_init = not self.db_path.exists() or self.db_path.stat().st_size == 0
        conn = self._get_connection()
        try:
            if need_init:
                if SCHEMA_SQL_PATH.exists():
                    schema_sql = SCHEMA_SQL_PATH.read_text(encoding="utf-8")
                    conn.executescript(schema_sql)
                seed_database(conn)
            else:
                # Ensure tables exist
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='crypto_signatures'")
                if not cur.fetchone():
                    if SCHEMA_SQL_PATH.exists():
                        conn.executescript(SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
                    seed_database(conn)
        finally:
            conn.close()

    def lookup_symbol(self, ecosystem: str, contract: str, symbol: str) -> Optional[Dict[str, Any]]:
        """Looks up a cryptographic signature by ecosystem, contract interface, and symbol."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM crypto_signatures 
                WHERE ecosystem = ? AND contract = ? AND symbol = ?
                LIMIT 1
            """, (ecosystem.lower(), contract, symbol))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def lookup_namespace_symbol(self, ecosystem: str, namespace: str, symbol: str) -> Optional[Dict[str, Any]]:
        """Looks up a cryptographic signature by ecosystem, package namespace, and symbol."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM crypto_signatures 
                WHERE ecosystem = ? AND (namespace = ? OR namespace LIKE ?) AND symbol = ?
                LIMIT 1
            """, (ecosystem.lower(), namespace, f"%{namespace}%", symbol))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def lookup_algorithm(self, alg_name: str) -> Optional[Dict[str, Any]]:
        """Looks up algorithm properties by normalized algorithm name (e.g. 'AES', 'DES', 'Argon2id')."""
        clean_name = alg_name.strip().upper()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM crypto_signatures 
                WHERE UPPER(normalized_alg) = ? OR UPPER(id) LIKE ?
                ORDER BY nist_quantum_security_level DESC
                LIMIT 1
            """, (clean_name, f"%.{clean_name.lower()}%"))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def lookup_package(self, ecosystem: str, package_name: str) -> Optional[Dict[str, Any]]:
        """Looks up third-party library package rules for manifests."""
        conn = self._get_connection()
        clean_pkg = package_name.strip().lower()
        try:
            cur = conn.cursor()
            # Exact match
            cur.execute("""
                SELECT * FROM package_manifest_rules 
                WHERE ecosystem = ? AND LOWER(package_name) = ?
                LIMIT 1
            """, (ecosystem.lower(), clean_pkg))
            row = cur.fetchone()
            if row:
                return dict(row)

            # Substring / namespace match (e.g. golang.org/x/crypto/argon2 matches golang.org/x/crypto)
            cur.execute("""
                SELECT * FROM package_manifest_rules 
                WHERE ecosystem = ? AND (? LIKE '%' || LOWER(package_name) || '%')
                ORDER BY LENGTH(package_name) DESC
                LIMIT 1
            """, (ecosystem.lower(), clean_pkg))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_all_package_rules(self, ecosystem: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all registered package manifest rules."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            if ecosystem:
                cur.execute("SELECT * FROM package_manifest_rules WHERE ecosystem = ?", (ecosystem.lower(),))
            else:
                cur.execute("SELECT * FROM package_manifest_rules")
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def register_signature(self, sig: Dict[str, Any]) -> None:
        """Dynamically registers or updates a cryptographic signature in the database."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO crypto_signatures (
                    id, ecosystem, namespace, contract, symbol, normalized_alg,
                    primitive_type, key_size, classical_security_level, nist_quantum_security_level,
                    default_risk, pqc_recommendation, cwe, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sig["id"], sig["ecosystem"].lower(), sig["namespace"], sig["contract"], sig["symbol"],
                sig["normalized_alg"], sig["primitive_type"], sig.get("key_size"),
                sig.get("classical_security_level"), sig.get("nist_quantum_security_level"),
                sig["default_risk"], sig["pqc_recommendation"], sig.get("cwe"), sig.get("description")
            ))
            conn.commit()
        finally:
            conn.close()


_GLOBAL_DB_INSTANCE: Optional[SignatureDatabase] = None

def get_signature_db() -> SignatureDatabase:
    """Returns a singleton SignatureDatabase instance."""
    global _GLOBAL_DB_INSTANCE
    if _GLOBAL_DB_INSTANCE is None:
        _GLOBAL_DB_INSTANCE = SignatureDatabase()
    return _GLOBAL_DB_INSTANCE
