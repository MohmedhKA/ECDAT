"""
ECDAT Standalone Web Dashboard Application.
Starlette ASGI Server providing REST APIs, project persistence,
auto-scheduled scans, and static asset serving for the modern dashboard.
"""

import json
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

from ecdat.app import db, scanner, scheduler, aggregator

APP_DIR = Path(__file__).parent.resolve()
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"


@asynccontextmanager
async def lifespan(app: Starlette):
    db.init_db()
    db.seed_default_projects_if_empty()
    scheduler.start_scheduler()
    yield
    scheduler.stop_scheduler()


async def root_handler(request):
    return RedirectResponse(url="/dashboard", status_code=302)


async def dashboard_page_handler(request):
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


async def api_list_projects(request):
    projects = db.list_projects()
    enriched = []
    for p in projects:
        item = dict(p)
        out_dir = Path(p["output_dir"])
        if out_dir.exists() and (out_dir / "enriched_cbom.json").exists():
            summary = aggregator.get_project_summary(str(out_dir))
            item["readiness_score"] = summary["posture"]["readiness_score"]
            item["total_assets"] = summary["posture"]["total_assets"]
            item["critical_count"] = summary["posture"]["critical_count"]
            item["high_count"] = summary["posture"]["high_count"]
        else:
            item["readiness_score"] = None
            item["total_assets"] = 0
            item["critical_count"] = 0
            item["high_count"] = 0
        enriched.append(item)
    return JSONResponse({"status": "success", "projects": enriched})


async def api_create_project(request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON body"}, status_code=400)

    name = body.get("name", "").strip()
    target_dir = body.get("target_dir", "").strip()
    output_dir = body.get("output_dir")
    scans_per_day = int(body.get("scans_per_day", 1))
    auto_scan = int(body.get("auto_scan", 1))

    if not name or not target_dir:
        return JSONResponse({"status": "error", "message": "name and target_dir are required."}, status_code=400)

    project = db.add_project(
        name=name,
        target_dir=target_dir,
        output_dir=output_dir,
        scans_per_day=scans_per_day,
        auto_scan=auto_scan,
    )
    return JSONResponse({"status": "success", "project": project})


async def api_delete_project(request):
    pid = request.path_params.get("project_id")
    deleted = db.delete_project(pid)
    if deleted:
        return JSONResponse({"status": "success", "message": f"Project '{pid}' deleted."})
    return JSONResponse({"status": "error", "message": "Project not found."}, status_code=404)


async def api_trigger_scan(request):
    pid = request.path_params.get("project_id")
    result = scanner.trigger_scan(pid)
    return JSONResponse(result)


async def api_scan_status(request):
    pid = request.path_params.get("project_id")
    status = scanner.get_scan_status(pid)
    return JSONResponse(status)


async def api_project_summary(request):
    pid = request.path_params.get("project_id")
    proj = db.get_project(pid)
    if not proj:
        return JSONResponse({"status": "error", "message": "Project not found."}, status_code=404)

    out_dir = proj["output_dir"]
    summary = aggregator.get_project_summary(out_dir)
    return JSONResponse({"status": "success", "project": proj, "summary": summary})


async def api_project_tab_details(request):
    pid = request.path_params.get("project_id")
    tab = request.path_params.get("tab_name", "home")
    proj = db.get_project(pid)
    if not proj:
        return JSONResponse({"status": "error", "message": "Project not found."}, status_code=404)

    out_dir = proj["output_dir"]
    tab_data = aggregator.get_tab_details(out_dir, tab)
    tab_data["project"] = proj
    return JSONResponse(tab_data)


async def api_export_report(request):
    pid = request.path_params.get("project_id")
    proj = db.get_project(pid)
    if not proj:
        return HTMLResponse("<h3>Project not found</h3>", status_code=404)

    report_path = Path(proj["output_dir"]) / "report.html"
    if not report_path.exists():
        return HTMLResponse("<h3>Standalone report.html has not been generated for this project yet. Please run a scan.</h3>", status_code=404)

    return FileResponse(str(report_path), media_type="text/html")


routes = [
    Route("/", root_handler, methods=["GET"]),
    Route("/dashboard", dashboard_page_handler, methods=["GET"]),
    Route("/api/projects", api_list_projects, methods=["GET"]),
    Route("/api/projects", api_create_project, methods=["POST"]),
    Route("/api/project/{project_id}", api_delete_project, methods=["DELETE"]),
    Route("/api/project/{project_id}/scan", api_trigger_scan, methods=["POST"]),
    Route("/api/project/{project_id}/scan-status", api_scan_status, methods=["GET"]),
    Route("/api/project/{project_id}/summary", api_project_summary, methods=["GET"]),
    Route("/api/project/{project_id}/tab/{tab_name}", api_project_tab_details, methods=["GET"]),
    Route("/api/project/{project_id}/export", api_export_report, methods=["GET"]),
    Mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static"),
]

app = Starlette(debug=True, routes=routes, lifespan=lifespan)
