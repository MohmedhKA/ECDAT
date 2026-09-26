"""
ECDAT Persistent SQLite Project Registry and Scan History.
Manages registered projects, scan frequencies, and historical audit logs.
"""

import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def get_default_db_path() -> Path:
    env_path = os.environ.get("ECDAT_DASHBOARD_DB")
    if env_path:
        p = Path(env_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    default_dir = Path.home() / ".ecdat"
    default_dir.mkdir(parents=True, exist_ok=True)
    return default_dir / "dashboard.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or get_default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target_dir TEXT NOT NULL,
                    output_dir TEXT NOT NULL,
                    scans_per_day INTEGER DEFAULT 1,
                    auto_scan INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_scanned TEXT,
                    status TEXT DEFAULT 'idle'
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    log TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                );
            """)
    finally:
        conn.close()


def slugify(text: str) -> str:
    slug = re.sub(r'[^a-zA-Z0-9_-]', '_', text.strip().lower())
    slug = re.sub(r'_+', '_', slug).strip('_')
    return slug or f"proj_{int(time.time())}"


def list_projects(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM projects ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_project(project_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def add_project(
    name: str,
    target_dir: str,
    output_dir: Optional[str] = None,
    scans_per_day: int = 1,
    auto_scan: int = 1,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    init_db(db_path)
    conn = get_connection(db_path)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    pid = slugify(name)
    target_path = Path(target_dir).resolve()
    
    if not output_dir:
        default_out = Path.home() / ".ecdat" / "scans" / pid
        default_out.mkdir(parents=True, exist_ok=True)
        out_path = default_out
    else:
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        
    try:
        with conn:
            conn.execute("""
                INSERT INTO projects (id, name, target_dir, output_dir, scans_per_day, auto_scan, created_at, last_scanned, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    target_dir=excluded.target_dir,
                    output_dir=excluded.output_dir,
                    scans_per_day=excluded.scans_per_day,
                    auto_scan=excluded.auto_scan
            """, (
                pid,
                name.strip(),
                str(target_path),
                str(out_path),
                max(1, int(scans_per_day)),
                1 if auto_scan else 0,
                now_iso,
                None,
                "idle"
            ))
        return get_project(pid, db_path) or {}
    finally:
        conn.close()


def update_project(project_id: str, db_path: Optional[Path] = None, **kwargs) -> Optional[Dict[str, Any]]:
    init_db(db_path)
    if not kwargs:
        return get_project(project_id, db_path)
    conn = get_connection(db_path)
    set_clauses = []
    values = []
    allowed = {"name", "target_dir", "output_dir", "scans_per_day", "auto_scan", "last_scanned", "status"}
    for k, v in kwargs.items():
        if k in allowed:
            set_clauses.append(f"{k} = ?")
            values.append(v)
    if not set_clauses:
        return get_project(project_id, db_path)
    values.append(project_id)
    try:
        with conn:
            conn.execute(f"UPDATE projects SET {', '.join(set_clauses)} WHERE id = ?", tuple(values))
        return get_project(project_id, db_path)
    finally:
        conn.close()


def delete_project(project_id: str, db_path: Optional[Path] = None) -> bool:
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM scan_history WHERE project_id = ?", (project_id,))
            cursor = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def record_scan_start(project_id: str, db_path: Optional[Path] = None) -> int:
    init_db(db_path)
    conn = get_connection(db_path)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO scan_history (project_id, started_at, status)
                VALUES (?, ?, 'running')
            """, (project_id, now_iso))
            conn.execute("UPDATE projects SET status = 'scanning' WHERE id = ?", (project_id,))
            return cursor.lastrowid or 0
    finally:
        conn.close()


def record_scan_finish(
    scan_id: int,
    status: str,
    exit_code: int,
    log: str,
    db_path: Optional[Path] = None
) -> None:
    init_db(db_path)
    conn = get_connection(db_path)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        with conn:
            conn.execute("""
                UPDATE scan_history
                SET finished_at = ?, status = ?, exit_code = ?, log = ?
                WHERE id = ?
            """, (now_iso, status, exit_code, log, scan_id))
            
            # Fetch project id for this scan
            cursor = conn.execute("SELECT project_id FROM scan_history WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row:
                pid = row["project_id"]
                conn.execute("""
                    UPDATE projects
                    SET last_scanned = ?, status = ?
                    WHERE id = ?
                """, (now_iso, "idle" if status == "success" else "error", pid))
    finally:
        conn.close()


def get_scan_history(
    project_id: Optional[str] = None,
    limit: int = 20,
    db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        if project_id:
            cursor.execute(
                "SELECT * FROM scan_history WHERE project_id = ? ORDER BY started_at DESC LIMIT ?",
                (project_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT ?",
                (limit,)
            )
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def seed_default_projects_if_empty(db_path: Optional[Path] = None) -> None:
    """Seeds existing scanned benchmarks if no projects are configured yet."""
    existing = list_projects(db_path)
    if existing:
        return

    candidates = [
        (
            "E-Voting Backend",
            "/home/mohmedh/personal/E-Voting-V2/backend",
            "/home/mohmedh/personal/ECDAT/testbeds/benchmarks/evoting_backend",
            2
        ),
        (
            "Sample Crypto Application",
            "/home/mohmedh/personal/ECDAT/testbeds/sample_crypto_app",
            "/home/mohmedh/personal/ECDAT/testbeds/sample_crypto_app/ecdat_output",
            1
        ),
    ]

    for name, target, out, spd in candidates:
        if Path(out).exists():
            add_project(name, target, out, scans_per_day=spd, auto_scan=1, db_path=db_path)
