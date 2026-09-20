"""
Tests for ECDAT Multi-Project Fleet Dashboard Server:
Verifies:
1. Fleet project discovery and metadata extraction.
2. Starlette ASGI application routing:
   - GET / (serves primary report.html with fleet selector)
   - GET /project/{name} (serves specific report.html)
   - GET /fleet (serves multi-project fleet scorecard)
   - GET /api/fleet (returns fleet summary JSON)
3. Strict zero-regex rule enforcement.
"""

import json
import asyncio
from pathlib import Path
import pytest

from ecdat.dashboard.server import create_fleet_app, find_scanned_projects


def call_asgi(app, method="GET", path="/", headers=None, body=b""):
    """Zero-dependency ASGI test client."""
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


def create_mock_report_dir(base_dir: Path, name: str, asset_count: int = 5):
    pdir = base_dir / name
    pdir.mkdir(parents=True, exist_ok=True)

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "bom-ref": f"ASSET-{i:03d}",
                "name": f"comp_{i}",
                "cryptoProperties": {
                    "assetType": "asymmetricKey" if i % 2 == 0 else "symmetricKey",
                    "algorithmProperties": {
                        "name": "RSA-2048" if i % 2 == 0 else "AES-256-GCM"
                    }
                }
            }
            for i in range(asset_count)
        ]
    }
    (pdir / "enriched_cbom.json").write_text(json.dumps(cbom), encoding="utf-8")
    (pdir / "cbom_root.hex").write_text("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", encoding="utf-8")

    report_html = f"""<!DOCTYPE html>
    <html>
    <head><title>ECDAT Report - {name}</title></head>
    <body>
        <header class="border-b border-slate-800/80 bg-slate-950/90">
            <h1>ECDAT | Cryptographic Discovery & Attestation Report</h1>
            <p>Target: <strong>{name}</strong></p>
        </header>
        <main>
            <div id="tab-pane-cbom">Asset Count: {asset_count}</div>
        </main>
    </body>
    </html>"""
    (pdir / "report.html").write_text(report_html, encoding="utf-8")
    return pdir


def test_find_scanned_projects(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "proj_alpha", asset_count=3)
    create_mock_report_dir(reports_root, "proj_beta", asset_count=8)

    projects = find_scanned_projects(reports_dir=reports_root)
    assert len(projects) == 2
    names = [p["name"] for p in projects]
    assert "proj_alpha" in names
    assert "proj_beta" in names


def test_fleet_api_endpoint(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "evoting", asset_count=15)

    app = create_fleet_app(reports_dir=reports_root)
    response = call_asgi(app, "GET", "/api/fleet")
    assert response.status_code == 200
    data = response.json()
    assert "projects" in data
    assert len(data["projects"]) == 1
    assert data["projects"][0]["name"] == "evoting"
    assert data["projects"][0]["asset_count"] == 15
    assert "fleet_summary" in data
    assert data["fleet_summary"]["total_projects"] == 1
    assert data["fleet_summary"]["total_assets"] == 15


def test_project_html_serving_with_injected_selector(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "masc", asset_count=160)
    create_mock_report_dir(reports_root, "evoting", asset_count=15)

    app = create_fleet_app(reports_dir=reports_root)

    # Root route should serve primary project report with injected fleet selector
    resp_root = call_asgi(app, "GET", "/")
    assert resp_root.status_code == 200
    assert "fleet-project-select" in resp_root.text

    # Explicit project route
    resp_proj = call_asgi(app, "GET", "/project/masc")
    assert resp_proj.status_code == 200
    assert "ECDAT Report - masc" in resp_proj.text
    assert "fleet-project-select" in resp_proj.text


def test_fleet_overview_scorecard_page(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "proj_a", asset_count=10)
    create_mock_report_dir(reports_root, "proj_b", asset_count=20)

    app = create_fleet_app(reports_dir=reports_root)
    resp_fleet = call_asgi(app, "GET", "/fleet")
    assert resp_fleet.status_code == 200
    assert "Fleet Cryptographic Posture Scorecard" in resp_fleet.text
    assert "proj_a" in resp_fleet.text
    assert "proj_b" in resp_fleet.text



def test_project_data_and_version_endpoints(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "proj_live", asset_count=12)

    app = create_fleet_app(reports_dir=reports_root)

    # Version endpoint
    resp_ver = call_asgi(app, "GET", "/api/project/proj_live/version")
    assert resp_ver.status_code == 200
    vdata = resp_ver.json()
    assert vdata["name"] == "proj_live"
    assert vdata["asset_count"] == 12
    assert "mtime" in vdata
    assert "last_scanned" in vdata
    assert "readiness_pct" in vdata

    # Data endpoint
    resp_data = call_asgi(app, "GET", "/api/project/proj_live/data")
    assert resp_data.status_code == 200
    pdata = resp_data.json()
    assert pdata["project_name"] == "proj_live"
    assert "modules_status" in pdata
    assert "enriched_cbom" in pdata
    assert pdata["modules_status"]["cbom"] is True
    assert pdata["modules_status"]["pareto"] is False  # not created in mock

    # Nonexistent project
    resp_404 = call_asgi(app, "GET", "/api/project/does_not_exist/version")
    assert resp_404.status_code == 404


def test_project_export_endpoint(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "proj_export", asset_count=6)

    app = create_fleet_app(reports_dir=reports_root)
    resp = call_asgi(app, "GET", "/api/project/proj_export/export")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "proj_export_report.html" in resp.headers.get("content-disposition", "")
    assert "<!DOCTYPE html>" in resp.text


def test_dynamic_hydration_with_module_status(tmp_path):
    reports_root = tmp_path / "reports"
    create_mock_report_dir(reports_root, "proj_hydrated", asset_count=4)

    app = create_fleet_app(reports_dir=reports_root)
    resp = call_asgi(app, "GET", "/project/proj_hydrated")
    assert resp.status_code == 200
    assert "ECDAT_MODULE_STATUS" in resp.text
    assert "downloadStandaloneReport()" in resp.text
    assert "checkServerFreshness()" in resp.text


def test_api_scan_endpoint(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    sample_target = str(repo_root / "testbeds" / "sample_crypto_app")
    reports_root = tmp_path / "reports"

    app = create_fleet_app(reports_dir=reports_root)

    # Valid scan request
    body = json.dumps({"target": sample_target, "name": "sample_scan"}).encode("utf-8")
    resp = call_asgi(app, "POST", "/api/scan", headers={"Content-Type": "application/json"}, body=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["project"] == "sample_scan"
    assert data["total_assets"] >= 1

    # Invalid path
    bad_body = json.dumps({"target": "/nonexistent/path/xyz123"}).encode("utf-8")
    resp_bad = call_asgi(app, "POST", "/api/scan", headers={"Content-Type": "application/json"}, body=bad_body)
    assert resp_bad.status_code == 400


def test_api_remediation_preview_and_protection(tmp_path):
    reports_root = tmp_path / "reports"
    app = create_fleet_app(reports_dir=reports_root)

    # 1. Preview on a temporary test file
    test_file = tmp_path / "crypto_service.js"
    test_file.write_text("const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);\n", encoding="utf-8")

    preview_body = json.dumps({"file_path": str(test_file), "rule": "REPLACE_CBC_GCM"}).encode("utf-8")
    resp_preview = call_asgi(app, "POST", "/api/remediation/preview", headers={"Content-Type": "application/json"}, body=preview_body)
    assert resp_preview.status_code == 200
    pdata = resp_preview.json()
    assert pdata["status"] == "success"
    assert pdata["has_changes"] is True
    assert "aes-256-gcm" in pdata["diff"]
    assert pdata["is_protected"] is False

    # 2. Protection guard against E-Voting repository
    evoting_mock = tmp_path / "evoting_backend" / "test.js"
    evoting_mock.parent.mkdir(parents=True, exist_ok=True)
    evoting_mock.write_text("const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);\n", encoding="utf-8")

    apply_body = json.dumps({"file_path": str(evoting_mock)}).encode("utf-8")
    resp_guard = call_asgi(app, "POST", "/api/remediation/apply", headers={"Content-Type": "application/json"}, body=apply_body)
    assert resp_guard.status_code == 403
    assert "PROTECTED REPOSITORY" in resp_guard.json()["error"]


def test_fleet_targets_endpoint(tmp_path):
    reports_root = tmp_path / "reports"
    app = create_fleet_app(reports_dir=reports_root)
    response = call_asgi(app, "GET", "/api/fleet/targets")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "targets" in data
    assert "evoting_backend" in data["targets"]


def test_zero_regex_compliance():
    from pathlib import Path
    for fname in ["server.py", "hydrator.py", "fleet.py"]:
        fpath = Path(f"ecdat/dashboard/{fname}")
        if fpath.exists():
            content = fpath.read_text(encoding="utf-8")
            assert "import re" not in content, f"Zero-regex violated in {fname}"
            assert "from re import" not in content, f"Zero-regex violated in {fname}"
            assert "re." not in content, f"Zero-regex violated in {fname}"

