"""
ECDAT Background Auto-Scan Scheduler.
Monitors registered projects and automatically launches scans
according to the configured scans_per_day frequency.
"""

import time
import calendar
import threading
from typing import Optional

from ecdat.app import db, scanner

_SCHEDULER_THREAD: Optional[threading.Thread] = None
_RUNNING = False
_STOP_EVENT = threading.Event()


def parse_iso_time(iso_str: Optional[str]) -> Optional[float]:
    if not iso_str:
        return None
    try:
        # Expected format: 2026-09-25T17:28:47Z
        struct_time = time.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ")
        return calendar.timegm(struct_time)
    except Exception:
        return None


def scheduler_loop(interval_check_seconds: int = 20):
    while not _STOP_EVENT.is_set():
        try:
            projects = db.list_projects()
            now = time.time()

            for proj in projects:
                if not proj.get("auto_scan", 1):
                    continue

                pid = proj["id"]
                scans_per_day = max(1, proj.get("scans_per_day", 1))
                required_interval = 86400.0 / scans_per_day

                last_scanned_str = proj.get("last_scanned")
                last_time = parse_iso_time(last_scanned_str)

                # If never scanned or overdue
                if last_time is None or (now - last_time) >= required_interval:
                    status = scanner.get_scan_status(pid)
                    if not status.get("active"):
                        # Launch scheduled scan
                        scanner.trigger_scan(pid)

        except Exception as exc:
            pass  # Avoid crashing the background thread

        _STOP_EVENT.wait(interval_check_seconds)


def start_scheduler():
    global _SCHEDULER_THREAD, _RUNNING
    if _RUNNING:
        return
    _STOP_EVENT.clear()
    _RUNNING = True
    _SCHEDULER_THREAD = threading.Thread(target=scheduler_loop, daemon=True)
    _SCHEDULER_THREAD.start()


def stop_scheduler():
    global _RUNNING
    _STOP_EVENT.set()
    _RUNNING = False
