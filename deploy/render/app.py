"""
ECDAT Single-Project Public Demo Server (CryptoAPI-Bench on Render)
Standalone Starlette/Uvicorn server hosting the interactive ECDAT dashboard
restricted exclusively to CryptoAPI-Bench:
- Disables project switching and fleet view
- Disables live scanning and remediation mutation APIs
- Serves complete D3 contagion graphs, asset inventories, Mosca simulations,
  Pareto optimization curves, and in-toto DSSE attestation packages
- Zero external build dependencies beyond Starlette and Uvicorn
"""

import os
import sys
import json
import time
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent.parent
SCANS_DIR = BASE_DIR / "scans"
PROJECT_NAME = "cryptoapi-bench"
PROJECT_DIR = SCANS_DIR / PROJECT_NAME

# Ensure repo root is on sys.path if running from within repo
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Load hydrator dynamically without executing ecdat.__init__ (to avoid heavy deps)
def get_hydrator():
    candidate_paths = [
        REPO_ROOT / "ecdat" / "dashboard" / "hydrator.py",
        BASE_DIR / "hydrator.py"
    ]
    for p in candidate_paths:
        if p.exists():
            try:
                spec = importlib.util.spec_from_file_location("ecdat_hydrator", p)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    return mod
            except Exception:
                pass
    return None

_hydrator = get_hydrator()

def load_cached_data() -> Dict[str, Any]:
    """Load pre-computed assessment artifacts from the scan folder."""
    if _hydrator and hasattr(_hydrator, "load_project_data"):
        try:
            return _hydrator.load_project_data(PROJECT_DIR)
        except Exception:
            pass

    # Fallback loader directly from json files
    cbom_file = PROJECT_DIR / "enriched_cbom.json"
    cbom_data = {}
    if cbom_file.exists():
        try:
            cbom_data = json.loads(cbom_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

    return {
        "project_name": PROJECT_NAME,
        "directory": str(PROJECT_DIR),
        "mtime": cbom_file.stat().st_mtime if cbom_file.exists() else time.time(),
        "last_scanned": time.strftime("%Y-%m-%d %H:%M:%S"),
        "merkle_root": "0x0",
        "enriched_cbom": cbom_data,
        "assets_data": [],
        "modules_status": {}
    }

DEMO_NAV_WIDGET = """
<!-- ECDAT Public Demo Project Badge -->
<div class="flex items-center gap-2 flex-wrap">
    <div class="flex items-center bg-slate-900/95 border border-cyan-500/40 rounded-lg px-3 py-1 text-xs font-mono shadow-sm">
        <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse mr-2"></span>
        <span class="text-cyan-400 font-bold mr-1.5">Project:</span>
        <span class="text-white font-semibold">cryptoapi-bench</span>
        <span class="ml-2.5 px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-mono uppercase tracking-wide">Public Demo</span>
    </div>
</div>
"""

def inject_demo_navigation(html_content: str) -> str:
    """Inject the demo navigation badge into report.html / dynamic dashboard."""
    if "<!-- FLEET_NAVIGATION_SLOT_START -->" in html_content and "<!-- FLEET_NAVIGATION_SLOT_END -->" in html_content:
        s_idx = html_content.find("<!-- FLEET_NAVIGATION_SLOT_START -->")
        e_tag = "<!-- FLEET_NAVIGATION_SLOT_END -->"
        e_idx = html_content.find(e_tag) + len(e_tag)
        html_content = html_content[:s_idx] + DEMO_NAV_WIDGET + html_content[e_idx:]
    elif "<!-- FLEET_NAVIGATION_SLOT -->" in html_content:
        html_content = html_content.replace("<!-- FLEET_NAVIGATION_SLOT -->", DEMO_NAV_WIDGET, 1)
    elif "<!-- Header Quick Actions & Merkle Root Chip -->" in html_content:
        html_content = html_content.replace(
            "<!-- Header Quick Actions & Merkle Root Chip -->",
            DEMO_NAV_WIDGET + "\n<!-- Header Quick Actions & Merkle Root Chip -->",
            1
        )
    elif "<header" in html_content and "</header>" in html_content:
        idx = html_content.find("</header>")
        html_content = html_content[:idx] + DEMO_NAV_WIDGET + html_content[idx:]

    # Resolve logo placeholder if present
    logo_file = REPO_ROOT / "ecdat" / "dashboard" / "assets" / "logo_b64.txt"
    if "__ECDAT_LOGO_B64__" in html_content and logo_file.exists():
        html_content = html_content.replace("__ECDAT_LOGO_B64__", logo_file.read_text(encoding="utf-8").strip())

    return html_content

def render_dashboard_html() -> str:
    """Renders the dashboard HTML using dynamic hydration or pre-compiled report."""
    if _hydrator and hasattr(_hydrator, "render_dynamic_project_dashboard"):
        try:
            pdata = load_cached_data()
            projects = [{"name": PROJECT_NAME, "asset_count": len(pdata.get("assets_data", []))}]
            raw_html = _hydrator.render_dynamic_project_dashboard(PROJECT_DIR, PROJECT_NAME, projects)
            return inject_demo_navigation(raw_html)
        except Exception:
            pass

    # Fallback to pre-compiled report.html
    report_file = PROJECT_DIR / "report.html"
    if report_file.exists():
        raw_html = report_file.read_text(encoding="utf-8", errors="replace")
        return inject_demo_navigation(raw_html)

    return f"<h3>ECDAT Demo: Scan data for '{PROJECT_NAME}' not found.</h3>"

# Route Handlers
async def root_handler(request):
    html = render_dashboard_html()
    return HTMLResponse(html)

async def project_handler(request):
    proj_name = request.path_params.get("name", "")
    if proj_name.lower() == PROJECT_NAME.lower():
        html = render_dashboard_html()
        return HTMLResponse(html)
    return RedirectResponse(url="/")

async def fleet_redirect_handler(request):
    return RedirectResponse(url="/")

async def api_project_data_handler(request):
    pdata = load_cached_data()
    payload = {
        "status": "success",
        "project": PROJECT_NAME,
        "project_name": PROJECT_NAME,
        "data": pdata
    }
    payload.update(pdata)
    return JSONResponse(payload)

async def api_project_version_handler(request):
    pdata = load_cached_data()
    return JSONResponse({
        "status": "success",
        "name": PROJECT_NAME,
        "project": PROJECT_NAME,
        "mtime": pdata.get("mtime", time.time()),
        "last_scanned": pdata.get("last_scanned", "Unknown"),
        "asset_count": len(pdata.get("assets_data", [])),
        "readiness_pct": 51
    })

async def api_project_export_handler(request):
    report_file = PROJECT_DIR / "report.html"
    if report_file.exists():
        content = report_file.read_text(encoding="utf-8", errors="replace")
    else:
        content = render_dashboard_html()
    return Response(
        content=content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{PROJECT_NAME}_report.html"'}
    )

async def api_fleet_handler(request):
    pdata = load_cached_data()
    total_assets = len(pdata.get("assets_data", []))
    return JSONResponse({
        "status": "success",
        "fleet_summary": {
            "total_projects": 1,
            "total_assets": total_assets,
            "total_critical_risks": 142,
            "total_high_risks": 0,
            "overall_readiness_pct": 51
        },
        "projects": [
            {
                "name": PROJECT_NAME,
                "directory": str(PROJECT_DIR),
                "asset_count": total_assets,
                "critical_count": 142,
                "high_count": 0,
                "readiness_pct": 51,
                "last_scanned": pdata.get("last_scanned", "Unknown")
            }
        ]
    })

async def api_fleet_targets_handler(request):
    return JSONResponse({
        "status": "success",
        "targets": {
            PROJECT_NAME: {
                "name": PROJECT_NAME,
                "target_dir": "benchmarks/CryptoAPI-Bench",
                "asset_count": 289
            }
        }
    })

async def api_scan_disabled_handler(request):
    return JSONResponse(
        {
            "status": "disabled",
            "error": "Scanning is disabled on this public demo instance. To scan custom codebases, run ECDAT locally via 'ecdat scan <target>'."
        },
        status_code=403
    )

async def api_remediation_disabled_handler(request):
    return JSONResponse(
        {
            "status": "disabled",
            "error": "Code remediation is disabled on this public demo instance."
        },
        status_code=403
    )

async def health_check_handler(request):
    return JSONResponse({
        "status": "healthy",
        "service": "ECDAT Public Demo",
        "project": PROJECT_NAME
    })

# Starlette Application Setup
routes = [
    Route("/", endpoint=root_handler, methods=["GET"]),
    Route("/project/{name}", endpoint=project_handler, methods=["GET"]),
    Route("/fleet", endpoint=fleet_redirect_handler, methods=["GET"]),
    Route("/health", endpoint=health_check_handler, methods=["GET"]),
    Route("/api/fleet", endpoint=api_fleet_handler, methods=["GET"]),
    Route("/api/fleet/targets", endpoint=api_fleet_targets_handler, methods=["GET"]),
    Route("/api/project/{name}/data", endpoint=api_project_data_handler, methods=["GET"]),
    Route("/api/project/{name}/version", endpoint=api_project_version_handler, methods=["GET"]),
    Route("/api/project/{name}/export", endpoint=api_project_export_handler, methods=["GET"]),
    Route("/api/scan", endpoint=api_scan_disabled_handler, methods=["POST"]),
    Route("/api/remediation/preview", endpoint=api_remediation_disabled_handler, methods=["POST"]),
    Route("/api/remediation/apply", endpoint=api_remediation_disabled_handler, methods=["POST"]),
    Route("/api/remediation/undo", endpoint=api_remediation_disabled_handler, methods=["POST"]),
    Route("/api/remediation/redo", endpoint=api_remediation_disabled_handler, methods=["POST"]),
]

app = Starlette(debug=False, routes=routes)

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    print(f"\n[*] ECDAT Public Demo Server: http://{host}:{port}")
    print(f"[*] Locked Project: {PROJECT_NAME}\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
