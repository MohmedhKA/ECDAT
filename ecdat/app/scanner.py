"""
ECDAT Scan Subprocess Runner and Live Output Streamer.
Runs ecdat scan asynchronously, streams real-time stdout/stderr,
and updates database status upon completion.
"""

import sys
import time
import queue
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from ecdat.app import db

# Active scan tracker: project_id -> dict with status, logs, process
ACTIVE_SCANS: Dict[str, Dict[str, Any]] = {}
SCAN_LOCK = threading.Lock()


def get_scan_status(project_id: str) -> Dict[str, Any]:
    with SCAN_LOCK:
        if project_id in ACTIVE_SCANS:
            info = ACTIVE_SCANS[project_id]
            return {
                "active": True,
                "status": "scanning",
                "started_at": info.get("started_at"),
                "log_tail": list(info.get("recent_logs", []))[-25:],
                "lines_count": len(info.get("recent_logs", [])),
            }
    
    # Check DB status
    proj = db.get_project(project_id)
    if proj:
        return {
            "active": False,
            "status": proj.get("status", "idle"),
            "last_scanned": proj.get("last_scanned"),
            "log_tail": [],
            "lines_count": 0,
        }
    return {"active": False, "status": "unknown"}


def run_scan_worker(project_id: str, target_dir: str, output_dir: str, scan_id: int):
    recent_logs = []
    log_text_accum = []
    
    cmd = [
        sys.executable,
        "-m",
        "ecdat.pipeline",
        "scan",
        "--target",
        str(target_dir),
        "--out",
        str(output_dir),
        "--json",
        "--sarif",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        with SCAN_LOCK:
            if project_id in ACTIVE_SCANS:
                ACTIVE_SCANS[project_id]["proc"] = proc

        for line in iter(proc.stdout.readline, ""):
            cleaned = line.rstrip()
            if cleaned:
                with SCAN_LOCK:
                    recent_logs.append(cleaned)
                    if len(recent_logs) > 500:
                        recent_logs.pop(0)
                    log_text_accum.append(cleaned)
                    if project_id in ACTIVE_SCANS:
                        ACTIVE_SCANS[project_id]["recent_logs"] = recent_logs

        proc.stdout.close()
        exit_code = proc.wait()

        status = "success" if exit_code == 0 else "failed"
        full_log = "\n".join(log_text_accum)
        db.record_scan_finish(scan_id, status, exit_code, full_log)

    except Exception as exc:
        err_msg = f"Scan process encountered fatal exception: {str(exc)}"
        db.record_scan_finish(scan_id, "failed", 1, err_msg)
    finally:
        with SCAN_LOCK:
            ACTIVE_SCANS.pop(project_id, None)


def trigger_scan(project_id: str) -> Dict[str, Any]:
    with SCAN_LOCK:
        if project_id in ACTIVE_SCANS:
            return {
                "status": "already_running",
                "message": f"Scan for project '{project_id}' is already in progress.",
            }

    proj = db.get_project(project_id)
    if not proj:
        return {"status": "error", "message": f"Project '{project_id}' not found."}

    target_dir = proj["target_dir"]
    output_dir = proj["output_dir"]

    scan_id = db.record_scan_start(project_id)
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with SCAN_LOCK:
        ACTIVE_SCANS[project_id] = {
            "scan_id": scan_id,
            "started_at": started_at,
            "target_dir": target_dir,
            "output_dir": output_dir,
            "recent_logs": [f"Initializing ECDAT cryptographic scan for '{project_id}'..."],
            "proc": None,
        }

    thread = threading.Thread(
        target=run_scan_worker,
        args=(project_id, target_dir, output_dir, scan_id),
        daemon=True,
    )
    thread.start()

    return {
        "status": "started",
        "scan_id": scan_id,
        "message": f"Scan triggered for '{project_id}'.",
        "started_at": started_at,
    }
