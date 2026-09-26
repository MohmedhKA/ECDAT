"""
Unit and Integration Tests for the ECDAT Standalone Dashboard Application.
Validates SQLite project persistence, scan scheduler/runner, data aggregation,
and Starlette API endpoints using zero-dependency ASGI call helper.
"""

import json
import asyncio
import tempfile
from pathlib import Path
import pytest

from ecdat.app import db, aggregator, scanner
from ecdat.app.main import app


def call_asgi(app, method="GET", path="/", headers=None, body=b""):
    """Zero-dependency ASGI invocation helper."""
    messages = []
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    async def run():
        await app(scope, receive, send)

    asyncio.run(run())

    status_code = 200
    headers_out = {}
    body_out = b""
    for msg in messages:
        if msg["type"] == "http.response.start":
            status_code = msg["status"]
            headers_out = {k.decode(): v.decode() for k, v in msg.get("headers", [])}
        elif msg["type"] == "http.response.body":
            body_out += msg.get("body", b"")

    class Response:
        def __init__(self, status, headers, body):
            self.status_code = status
            self.headers = headers
            self.content = body
            self.text = body.decode("utf-8", errors="replace")

        def json(self):
            return json.loads(self.text)

    return Response(status_code, headers_out, body_out)


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_dashboard.db"
    db.init_db(db_file)
    return db_file


def test_sqlite_project_crud(temp_db):
    # 1. Add project
    proj = db.add_project(
        name="Test Crypto App",
        target_dir="/tmp/test_target",
        output_dir="/tmp/test_output",
        scans_per_day=3,
        auto_scan=1,
        db_path=temp_db,
    )
    assert proj["id"] == "test_crypto_app"
    assert proj["scans_per_day"] == 3
    assert proj["auto_scan"] == 1

    # 2. List projects
    projects = db.list_projects(temp_db)
    assert len(projects) == 1
    assert projects[0]["name"] == "Test Crypto App"

    # 3. Update project
    updated = db.update_project("test_crypto_app", db_path=temp_db, scans_per_day=6)
    assert updated["scans_per_day"] == 6

    # 4. Scan history recording
    scan_id = db.record_scan_start("test_crypto_app", db_path=temp_db)
    assert scan_id > 0
    db.record_scan_finish(scan_id, "success", 0, "Scan completed with 0 errors.", db_path=temp_db)
    
    history = db.get_scan_history("test_crypto_app", limit=5, db_path=temp_db)
    assert len(history) == 1
    assert history[0]["status"] == "success"
    assert history[0]["exit_code"] == 0

    # 5. Delete project
    deleted = db.delete_project("test_crypto_app", db_path=temp_db)
    assert deleted is True
    assert len(db.list_projects(temp_db)) == 0


def test_aggregator_summary_and_tabs():
    sample_dir = Path(__file__).resolve().parent.parent / "testbeds" / "sample_crypto_app" / "ecdat_output"
    if not sample_dir.exists():
        pytest.skip("Sample crypto app scan directory not found")

    summary = aggregator.get_project_summary(str(sample_dir))
    assert "posture" in summary
    assert "mosca" in summary
    assert "contagion" in summary
    assert "pareto" in summary
    assert "cbom" in summary
    assert "proof" in summary

    assert summary["posture"]["total_assets"] > 0
    assert summary["mosca"]["mean_breach_probability"] >= 0
    assert summary["contagion"]["total_nodes"] > 0
    assert summary["proof"]["is_certified_clean"] is True

    # Test tab details
    tab_data = aggregator.get_tab_details(str(sample_dir), "mosca")
    assert tab_data["tab"] == "mosca"
    assert "results" in tab_data["mosca"]


def test_starlette_dashboard_api():
    # 1. Dashboard page
    resp = call_asgi(app, method="GET", path="/dashboard")
    assert resp.status_code == 200
    assert "ECDAT" in resp.text
    assert "waterfall-grid" in resp.text or "nav-tabs-bar" in resp.text

    # 2. List projects API
    resp = call_asgi(app, method="GET", path="/api/projects")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert isinstance(data["projects"], list)

    # 3. Create project API
    with tempfile.TemporaryDirectory() as tmp_dir:
        req_body = json.dumps({
            "name": "Integration Test Service",
            "target_dir": tmp_dir,
            "scans_per_day": 2,
            "auto_scan": 1
        }).encode("utf-8")
        resp = call_asgi(app, method="POST", path="/api/projects", headers={"Content-Type": "application/json"}, body=req_body)
        assert resp.status_code == 200
        proj_data = resp.json()["project"]
        pid = proj_data["id"]
        assert pid == "integration_test_service"

        # 4. Tab details API
        tab_resp = call_asgi(app, method="GET", path=f"/api/project/{pid}/tab/home")
        assert tab_resp.status_code == 200
        assert "summary" in tab_resp.json()

        # 5. Delete project
        del_resp = call_asgi(app, method="DELETE", path=f"/api/project/{pid}")
        assert del_resp.status_code == 200
