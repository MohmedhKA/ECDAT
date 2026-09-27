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
    
    # Prefer repo venv python if available
    venv_py = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "python"
    py_bin = str(venv_py) if venv_py.exists() else sys.executable

    proj = db.get_project(project_id) or {}
    scan_libs = bool(proj.get("scan_libraries", 1))

    cmd = [
        py_bin,
        "-m",
        "ecdat.pipeline",
        "scan",
        "--target",
        str(target_dir),
        "--output",
        str(output_dir),
        "--format",
        "all",
    ]
    if not scan_libs:
        cmd.append("--no-scan-libraries")

    cmd_str = " ".join(cmd)
    print(f"\n[ECDAT-SCAN] Launching scan for project '{project_id}'...", flush=True)
    print(f"[ECDAT-SCAN] Command: {cmd_str}\n", flush=True)

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
                # Mirror to server console in real-time
                print(f"[{project_id}] {cleaned}", flush=True)
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

        if exit_code == 0:
            print(f"\n[ECDAT-SCAN SUCCESS] Scan for '{project_id}' completed successfully (exit code 0).\n", flush=True)
        else:
            print(f"\n" + "=" * 70, file=sys.stderr)
            print(f"[ECDAT-SCAN ERROR] Scan for project '{project_id}' FAILED with exit code {exit_code}!", file=sys.stderr)
            print(f"[ECDAT-SCAN ERROR] Target directory: {target_dir}", file=sys.stderr)
            print(f"[ECDAT-SCAN ERROR] Output directory: {output_dir}", file=sys.stderr)
            print(f"[ECDAT-SCAN ERROR] Full Log:\n{full_log}", file=sys.stderr)
            print("=" * 70 + "\n", file=sys.stderr, flush=True)

    except Exception as exc:
        err_msg = f"Scan process encountered fatal exception: {str(exc)}"
        print(f"\n[ECDAT-SCAN FATAL ERROR] {err_msg}\n", file=sys.stderr, flush=True)
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
