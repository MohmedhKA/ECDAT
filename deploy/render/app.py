"""
ECDAT Standalone Web Dashboard Application — Public Demo (CryptoAPI-Bench on Render)
Serves the exact interactive ECDAT Enterprise Post-Quantum Security Dashboard:
- All 11 interactive tabs: Overview, Mosca Horizon, Contagion Graph, Lineage Provenance,
  Pareto Portfolio, CBOM Inventory, Buffer & Agility, Supply Chain, Proofs & DSSE,
  Shadow Crypto, and CISO Briefing.
- Locked exclusively to CryptoAPI-Bench (no project switching or scan triggering).
- Zero external build dependencies beyond Starlette and Uvicorn.
"""

import os
import sys
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent.parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
DATA_DIR = BASE_DIR / "data" / "cryptoapi-bench"

# Fallback paths if running from repo root
if not STATIC_DIR.exists() and (REPO_ROOT / "ecdat" / "app" / "static").exists():
    STATIC_DIR = REPO_ROOT / "ecdat" / "app" / "static"
if not TEMPLATES_DIR.exists() and (REPO_ROOT / "ecdat" / "app" / "templates").exists():
    TEMPLATES_DIR = REPO_ROOT / "ecdat" / "app" / "templates"
if not DATA_DIR.exists() and (BASE_DIR / "scans" / "cryptoapi-bench").exists():
    DATA_DIR = BASE_DIR / "scans" / "cryptoapi-bench"

# Import aggregator (local copy or from ecdat.app)
try:
    from deploy.render import aggregator
except ImportError:
    try:
        import aggregator
    except ImportError:
        from ecdat.app import aggregator

PROJECT_ID = "cryptoapi-bench"
PROJECT_NAME = "CryptoAPI-Bench"


def get_cached_project():
    """Generates the locked project record dynamically from pre-computed scan outputs."""
    summary = aggregator.get_project_summary(str(DATA_DIR))
    posture = summary.get("posture", {})
    return {
        "id": PROJECT_ID,
        "name": PROJECT_NAME,
        "target_dir": "benchmarks/CryptoAPI-Bench",
        "output_dir": str(DATA_DIR),
        "created_at": "2026-09-28T00:00:00Z",
        "last_scanned": "2026-09-28 15:00:00",
        "status": "idle",
        "readiness_score": posture.get("readiness_score", 51),
        "total_assets": posture.get("total_assets", 289),
        "critical_count": posture.get("critical_count", 142),
        "high_count": posture.get("high_count", 0),
    }


async def root_handler(request):
    return RedirectResponse(url="/dashboard", status_code=302)


async def dashboard_page_handler(request):
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


async def api_list_projects(request):
    proj = get_cached_project()
    return JSONResponse({"status": "success", "projects": [proj]})


async def api_project_summary(request):
    pid = request.path_params.get("project_id")
    proj = get_cached_project()
    summary = aggregator.get_project_summary(str(DATA_DIR))
    return JSONResponse({"status": "success", "project": proj, "summary": summary})


async def api_project_tab_details(request):
    pid = request.path_params.get("project_id")
    tab = request.path_params.get("tab_name", "home")
    proj = get_cached_project()
    tab_data = aggregator.get_tab_details(str(DATA_DIR), tab)
    tab_data["project"] = proj
    return JSONResponse(tab_data)


async def api_export_report(request):
    report_path = DATA_DIR / "report.html"
    if not report_path.exists():
        return HTMLResponse("<h3>Report not found for this project.</h3>", status_code=404)
    return FileResponse(str(report_path), media_type="text/html")


async def api_scan_status(request):
    return JSONResponse({
        "active": False,
        "status": "idle",
        "log_tail": ["[Public Demo] Static live-demo instance. Full re-scans disabled."]
    })


async def api_disabled_action(request):
    return JSONResponse(
        {
            "status": "error",
            "message": "This operation is disabled on the public demo instance."
        },
        status_code=403
    )


async def health_check_handler(request):
    return JSONResponse({
        "status": "healthy",
        "service": "ECDAT Public Demo",
        "project": PROJECT_ID
    })


routes = [
    Route("/", root_handler, methods=["GET"]),
    Route("/dashboard", dashboard_page_handler, methods=["GET"]),
    Route("/health", health_check_handler, methods=["GET"]),
    Route("/api/projects", api_list_projects, methods=["GET"]),
    Route("/api/projects", api_disabled_action, methods=["POST"]),
    Route("/api/project/{project_id}", api_disabled_action, methods=["DELETE"]),
    Route("/api/project/{project_id}/scan", api_disabled_action, methods=["POST"]),
    Route("/api/project/{project_id}/scan-status", api_scan_status, methods=["GET"]),
    Route("/api/project/{project_id}/summary", api_project_summary, methods=["GET"]),
    Route("/api/project/{project_id}/tab/{tab_name}", api_project_tab_details, methods=["GET"]),
    Route("/api/project/{project_id}/export", api_export_report, methods=["GET"]),
    Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
]

app = Starlette(debug=False, routes=routes)

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    print(f"\n[*] ECDAT Enterprise Security Dashboard (Demo): http://{host}:{port}/dashboard")
    print(f"[*] Locked Project: {PROJECT_NAME}\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
