"""
ECDAT Multi-Project Fleet Dashboard Server:
Asynchronous Starlette/Uvicorn server providing:
1. Fleet-wide project discovery and metadata aggregation.
2. Direct serving of rich, interactive report.html dashboards with a live project switcher.
3. Fleet Overview scorecard comparing quantum risk across multiple microservices.
4. REST APIs for fleet metrics, historical burn-down curves, and on-demand scan triggering.
Strictly zero-regex: Operates exclusively on string methods, paths, and dictionary structures.
"""

import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

# Default candidate directories where scan outputs typically reside
DEFAULT_SEARCH_PATHS = [
    "testbeds/benchmarks/evoting_backend",
    "testbeds/benchmarks/reports",
    "scans",
    "."
]


def find_scanned_projects(reports_dir: Optional[Path] = None, base_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Discovers all scanned project directories containing report.html or enriched_cbom.json.
    Extracts asset counts, quantum risk metrics, and Merkle roots with zero regex.
    """
    projects = []
    seen_paths = set()
    root_dir = Path(base_dir or Path.cwd()).resolve()

    candidate_roots = []
    if reports_dir:
        candidate_roots.append(Path(reports_dir).resolve())
    else:
        for p in DEFAULT_SEARCH_PATHS:
            cand = root_dir / p
            if cand.exists():
                candidate_roots.append(cand.resolve())

    for search_root in candidate_roots:
        if not search_root.exists():
            continue

        # Check if the search_root itself is a scan output directory
        candidates_to_check = [search_root]
        # Check subdirectories
        if search_root.is_dir():
            try:
                for child in search_root.iterdir():
                    if child.is_dir():
                        candidates_to_check.append(child)
            except Exception:
                pass

        for pdir in candidates_to_check:
            abs_pdir = pdir.resolve()
            if abs_pdir in seen_paths:
                continue

            report_file = abs_pdir / "report.html"
            cbom_file = abs_pdir / "enriched_cbom.json"

            if report_file.exists() or cbom_file.exists():
                seen_paths.add(abs_pdir)
                proj_name = abs_pdir.name

                asset_count = 0
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = 0
                merkle_root = ""
                last_scanned = ""

                # Read enriched_cbom.json if present
                if cbom_file.exists():
                    try:
                        cbom_data = json.loads(cbom_file.read_text(encoding="utf-8", errors="replace"))
                        comps = cbom_data.get("components", [])
                        asset_count = len(comps)

                        for c in comps:
                            props = c.get("cryptoProperties", {})
                            risk = props.get("ecdat:risk_level", "").upper()
                            if not risk:
                                # fallback to raw properties
                                risk = c.get("raw_properties", {}).get("ecdat:risk_level", "").upper()
                            if "CRITICAL" in risk:
                                critical_count += 1
                            elif "HIGH" in risk:
                                high_count += 1
                            elif "MEDIUM" in risk:
                                medium_count += 1
                            else:
                                low_count += 1
                    except Exception:
                        pass

                # Read Merkle root if present
                root_file = abs_pdir / "cbom_root.hex"
                if root_file.exists():
                    try:
                        merkle_root = root_file.read_text(encoding="utf-8", errors="replace").strip()
                    except Exception:
                        pass

                # Calculate last modified timestamp
                try:
                    target_stat_file = report_file if report_file.exists() else cbom_file
                    mtime = target_stat_file.stat().st_mtime
                    last_scanned = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
                except Exception:
                    last_scanned = "Unknown"

                # Calculate Post-Quantum Readiness Index (%)
                # Assets that are not Critical or High are considered quantum-ready / safe
                readiness_pct = 100
                if asset_count > 0:
                    vulnerable = critical_count + high_count
                    readiness_pct = max(0, round(((asset_count - vulnerable) / asset_count) * 100))

                projects.append({
                    "name": proj_name,
                    "directory": str(abs_pdir),
                    "report_path": str(report_file) if report_file.exists() else None,
                    "has_report": report_file.exists(),
                    "asset_count": asset_count,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "medium_count": medium_count,
                    "low_count": low_count,
                    "readiness_pct": readiness_pct,
                    "merkle_root": merkle_root,
                    "last_scanned": last_scanned
                })

    # Sort projects with evoting_backend first if present, then alphabetical
    projects.sort(key=lambda p: (0 if "evoting" in p["name"].lower() else 1, p["name"].lower()))
    return projects


def inject_fleet_navigation(html_content: str, current_project: str, all_projects: List[Dict[str, Any]]) -> str:
    """
    Injects the Fleet Project Switcher bar and navigation controls into report.html
    without altering its existing D3 scripts, CSS, or visualizations.
    """
    # Build Project Switcher Dropdown Options
    options_html = []
    for p in all_projects:
        selected_attr = ' selected="selected"' if p["name"] == current_project else ""
        options_html.append(
            f'<option value="{p["name"]}"{selected_attr}>{p["name"]} ({p["asset_count"]} assets)</option>'
        )
    options_str = "\n".join(options_html)

    # Injected Fleet Switcher Widget
    fleet_widget = f"""
    <!-- ECDAT Fleet Navigation Widget (Injected) -->
    <div class="flex items-center gap-2 flex-wrap">
        <div class="flex items-center bg-slate-900/95 border border-cyan-500/40 rounded-lg px-2.5 py-1 text-xs font-mono shadow-sm">
            <span class="text-cyan-400 font-bold flex items-center gap-1.5 mr-2">
                <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                Fleet:
            </span>
            <select id="fleet-project-select" onchange="window.location.href='/project/' + this.value" class="bg-slate-950 border border-slate-700 text-cyan-200 rounded px-2 py-0.5 text-xs font-mono focus:border-cyan-400 focus:outline-none cursor-pointer">
                {options_str}
            </select>
        </div>
        <a href="/fleet" class="bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white px-2.5 py-1 rounded-lg text-xs font-mono border border-slate-700 flex items-center gap-1.5 transition shadow-sm" title="View Organization Multi-Project Scorecard">
            <svg class="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>
            <span>Fleet View</span>
        </a>
        <button id="btn-scan-now" onclick="triggerCurrentProjectScan()" class="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold px-3 py-1 rounded-lg text-xs font-mono flex items-center gap-1.5 transition shadow-md shadow-cyan-900/30 ring-1 ring-cyan-400/50" title="Trigger immediate re-scan of this codebase">
            <svg class="w-3.5 h-3.5 text-slate-950" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
            <span>Scan Now</span>
        </button>
        <button onclick="openScanModal()" class="bg-gradient-to-r from-emerald-600 to-teal-700 hover:from-emerald-500 hover:to-teal-600 text-white px-2.5 py-1 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition shadow-sm" title="Scan a new codebase">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
            <span>+ Scan Target</span>
        </button>
    </div>
    """

    # Modal for On-Demand Scan Trigger
    modal_html = """
    <!-- Scan Target In-Page Modal -->
    <div id="scan-target-modal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="glass-panel rounded-2xl border border-cyan-500/40 bg-slate-950 p-6 max-w-lg w-full shadow-2xl space-y-4 font-mono text-xs">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">Trigger Cryptographic Scan</h3>
                </div>
                <button onclick="closeScanModal()" class="text-slate-400 hover:text-white text-base">&times;</button>
            </div>
            <div class="space-y-3">
                <div>
                    <label class="text-slate-400 block mb-1">Target Codebase Path / URL:</label>
                    <input type="text" id="scan-target-input" placeholder="/home/user/project or https://api.endpoint.com" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-400 focus:outline-none text-xs" />
                </div>
                <div>
                    <label class="text-slate-400 block mb-1">Project Identifier (Optional):</label>
                    <input type="text" id="scan-name-input" placeholder="my_microservice" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-400 focus:outline-none text-xs" />
                </div>
            </div>
            <div id="scan-status-message" class="text-[11px] text-slate-400"></div>
            <div class="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button onclick="closeScanModal()" class="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700">Cancel</button>
                <button onclick="executeScanTrigger()" id="btn-submit-scan" class="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold">Start Discovery</button>
            </div>
        </div>
    </div>
    <script>
    function openScanModal() { document.getElementById('scan-target-modal').classList.remove('hidden'); }
    function closeScanModal() { document.getElementById('scan-target-modal').classList.add('hidden'); }
    async function executeScanTrigger() {
        const target = document.getElementById('scan-target-input').value.trim();
        const name = document.getElementById('scan-name-input').value.trim();
        const statusEl = document.getElementById('scan-status-message');
        const btn = document.getElementById('btn-submit-scan');
        if (!target) { statusEl.innerHTML = '<span class="text-rose-400">Please enter a valid directory path or URL.</span>'; return; }
        btn.disabled = true;
        btn.innerText = 'Scanning...';
        statusEl.innerHTML = '<span class="text-cyan-400 animate-pulse">Running AST and cryptographic discovery pipeline...</span>';
        try {
            const resp = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, name: name })
            });
            const data = await resp.json();
            if (resp.ok) {
                statusEl.innerHTML = '<span class="text-emerald-400">Scan Complete! Reloading dashboard...</span>';
                setTimeout(() => { window.location.href = '/project/' + (data.project || name || 'latest'); }, 800);
            } else {
                statusEl.innerHTML = '<span class="text-rose-400">Error: ' + (data.error || 'Scan failed') + '</span>';
                btn.disabled = false;
                btn.innerText = 'Start Discovery';
            }
        } catch (e) {
            statusEl.innerHTML = '<span class="text-rose-400">Network error: ' + e.message + '</span>';
            btn.disabled = false;
            btn.innerText = 'Start Discovery';
        }
    }
    </script>
    """

    # Inject into the executive header toolbar
    if "<!-- FLEET_NAVIGATION_SLOT_START -->" in html_content and "<!-- FLEET_NAVIGATION_SLOT_END -->" in html_content:
        s_idx = html_content.find("<!-- FLEET_NAVIGATION_SLOT_START -->")
        e_tag = "<!-- FLEET_NAVIGATION_SLOT_END -->"
        e_idx = html_content.find(e_tag) + len(e_tag)
        html_content = html_content[:s_idx] + fleet_widget + html_content[e_idx:]
    elif "<!-- FLEET_NAVIGATION_SLOT -->" in html_content:
        html_content = html_content.replace(
            "<!-- FLEET_NAVIGATION_SLOT -->",
            fleet_widget,
            1
        )
    elif "<!-- Header Quick Actions & Merkle Root Chip -->" in html_content:
        html_content = html_content.replace(
            "<!-- Header Quick Actions & Merkle Root Chip -->",
            fleet_widget + "\n<!-- Header Quick Actions & Merkle Root Chip -->",
            1
        )
    elif "<header" in html_content and "</header>" in html_content:
        # Fallback: place before closing header
        idx = html_content.find("</header>")
        html_content = html_content[:idx] + fleet_widget + html_content[idx:]

    # Also ensure logo placeholder is populated if present
    logo_file = Path(__file__).parent / "assets" / "logo_b64.txt"
    if "__ECDAT_LOGO_B64__" in html_content and logo_file.exists():
        html_content = html_content.replace("__ECDAT_LOGO_B64__", logo_file.read_text(encoding="utf-8").strip())

    # Inject modal before closing body
    if "</body>" in html_content:
        idx_body = html_content.rfind("</body>")
        html_content = html_content[:idx_body] + modal_html + html_content[idx_body:]
    else:
        html_content += modal_html

    return html_content


def render_fleet_scorecard_html(projects: List[Dict[str, Any]]) -> str:
    """
    Renders the Organization-Wide Fleet Cryptographic Posture Scorecard
    using the exact same visual design, glassmorphism, fonts, and dark palette as report.html.
    """
    total_projects = len(projects)
    total_assets = sum(p["asset_count"] for p in projects)
    total_critical = sum(p["critical_count"] for p in projects)
    total_high = sum(p["high_count"] for p in projects)
    overall_readiness = max(0, round(((total_assets - (total_critical + total_high)) / max(1, total_assets)) * 100))

    logo_file = Path(__file__).parent / "assets" / "logo_b64.txt"
    logo_b64 = logo_file.read_text(encoding="utf-8").strip() if logo_file.exists() else ""

    # Build Project Table Rows
    rows_html = []
    for p in projects:
        crit_badge = f'<span class="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800 font-bold">{p["critical_count"]}</span>' if p["critical_count"] > 0 else '<span class="text-slate-500 font-mono">0</span>'
        high_badge = f'<span class="px-2 py-0.5 rounded bg-orange-950/80 text-orange-300 border border-orange-800">{p["high_count"]}</span>' if p["high_count"] > 0 else '<span class="text-slate-500 font-mono">0</span>'
        
        # Color bar for readiness
        pct = p["readiness_pct"]
        bar_color = "bg-emerald-400" if pct >= 70 else ("bg-yellow-400" if pct >= 40 else "bg-rose-400")

        rows_html.append(f"""
        <tr class="hover:bg-slate-900/60 transition border-b border-slate-800/60">
            <td class="py-3.5 px-4 font-bold text-white font-mono flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span>{p["name"]}</span>
            </td>
            <td class="py-3.5 px-4 font-mono text-cyan-300 font-bold text-sm">{p["asset_count"]}</td>
            <td class="py-3.5 px-4">{crit_badge}</td>
            <td class="py-3.5 px-4">{high_badge}</td>
            <td class="py-3.5 px-4">
                <div class="flex items-center gap-2">
                    <div class="w-24 bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div class="{bar_color} h-2 rounded-full" style="width: {pct}%"></div>
                    </div>
                    <span class="font-mono text-xs font-bold text-slate-300">{pct}%</span>
                </div>
            </td>
            <td class="py-3.5 px-4 font-mono text-slate-400 text-[11px] truncate max-w-xs">{p["last_scanned"]}</td>
            <td class="py-3.5 px-4 text-right">
                <a href="/project/{p["name"]}" class="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 font-mono text-xs font-semibold inline-flex items-center gap-1 transition">
                    <span>View Dashboard</span>
                    <span>&rarr;</span>
                </a>
            </td>
        </tr>
        """)
    rows_str = "\n".join(rows_html)

    # Return complete standalone HTML using the exact report styling
    return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECDAT | Organization Fleet Cryptographic Posture Scorecard</title>
    <link rel="icon" type="image/png" href="data:image/png;base64,{logo_b64}">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; background-color: #020617; color: #f8fafc; }}
        .glass-panel {{ background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); }}
        .glass-card {{ background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(51, 65, 85, 0.6); }}
    </style>
</head>
<body class="min-h-screen flex flex-col antialiased">
    <!-- Header identical to report.html -->
    <header class="border-b border-slate-800/80 bg-slate-950/90 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-[1720px] mx-auto px-4 sm:px-8 xl:px-12 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div class="flex items-center space-x-3.5">
                <img src="data:image/png;base64,{logo_b64}" class="w-10 h-10 rounded-xl object-cover shadow-lg shadow-cyan-500/30 border border-cyan-400/40 ring-1 ring-white/10 flex-shrink-0" alt="ECDAT Logo" />
                <div>
                    <div class="flex items-center gap-2.5">
                        <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                            ECDAT
                            <span class="text-xs text-slate-400 font-normal">| Multi-Project Fleet Posture Scorecard</span>
                        </h1>
                        <span class="px-2 py-0.5 text-[11px] font-semibold rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/70 font-mono">
                            FIPS 203/204/205
                        </span>
                        <span class="px-2 py-0.5 text-[11px] font-semibold rounded bg-slate-900 text-slate-300 border border-slate-700 font-mono">
                            OMB M-26-15 Fleet Audit
                        </span>
                    </div>
                    <p class="text-xs text-slate-400 mt-0.5 font-mono">
                        Consolidated Post-Quantum Readiness across {total_projects} microservices and repositories.
                    </p>
                </div>
            </div>

            <div class="flex items-center gap-2.5">
                <button onclick="document.getElementById('scan-target-modal').classList.remove('hidden')" class="bg-gradient-to-r from-emerald-600 to-teal-700 hover:from-emerald-500 hover:to-teal-600 text-white px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                    <span>+ Scan New Target</span>
                </button>
            </div>
        </div>
    </header>

    <main class="max-w-[1720px] mx-auto px-4 sm:px-8 xl:px-12 py-6 flex-grow w-full space-y-6">
        <!-- Fleet KPI Summary Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
            <div class="glass-card rounded-xl p-4">
                <div class="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">Scanned Projects</div>
                <div class="text-2xl font-black text-white font-mono mt-1">{total_projects}</div>
                <div class="text-[11px] text-slate-400 mt-0.5 font-mono">Active Codebases in Fleet</div>
            </div>
            <div class="glass-card rounded-xl p-4">
                <div class="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">Total Discovered Assets</div>
                <div class="text-2xl font-black text-emerald-300 font-mono mt-1">{total_assets}</div>
                <div class="text-[11px] text-slate-400 mt-0.5 font-mono">AST, Certs &amp; Sinks</div>
            </div>
            <div class="glass-card rounded-xl p-4 border-rose-900/50 bg-rose-950/20">
                <div class="text-[10px] font-mono text-rose-400 uppercase tracking-wider">Critical Quantum Risks</div>
                <div class="text-2xl font-black text-rose-300 font-mono mt-1">{total_critical}</div>
                <div class="text-[11px] text-rose-400/80 mt-0.5 font-mono">CRQC Vulnerable Primitives</div>
            </div>
            <div class="glass-card rounded-xl p-4">
                <div class="text-[10px] font-mono text-yellow-400 uppercase tracking-wider">High Risk Primitives</div>
                <div class="text-2xl font-black text-yellow-300 font-mono mt-1">{total_high}</div>
                <div class="text-[11px] text-slate-400 mt-0.5 font-mono">Migration Budget Required</div>
            </div>
            <div class="glass-card rounded-xl p-4 border-emerald-900/50 bg-emerald-950/20">
                <div class="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">Fleet Readiness Score</div>
                <div class="text-2xl font-black text-emerald-300 font-mono mt-1">{overall_readiness}%</div>
                <div class="text-[11px] text-emerald-400/80 mt-0.5 font-mono">NIST FIPS Safe Margin</div>
            </div>
        </div>

        <!-- Fleet Project Comparison Table -->
        <div class="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
            <div class="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
                <div>
                    <h3 class="text-sm font-bold text-white font-mono">Fleet Cryptographic Posture Scorecard</h3>
                    <p class="text-xs text-slate-400 font-mono mt-0.5">Discovered projects, asset inventory, and individual quantum security compliance.</p>
                </div>
                <div class="text-xs font-mono text-slate-400">
                    <span class="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-emerald-400">Live Monitored</span>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs">
                    <thead class="bg-slate-950/90 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                        <tr>
                            <th class="py-3 px-4">Project Name</th>
                            <th class="py-3 px-4">Assets</th>
                            <th class="py-3 px-4">Critical Risks</th>
                            <th class="py-3 px-4">High Risks</th>
                            <th class="py-3 px-4">Quantum Readiness</th>
                            <th class="py-3 px-4">Last Scanned</th>
                            <th class="py-3 px-4 text-right">Dashboard</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/60">
                        {rows_str}
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <!-- Scan Modal -->
    <div id="scan-target-modal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="glass-panel rounded-2xl border border-cyan-500/40 bg-slate-950 p-6 max-w-lg w-full shadow-2xl space-y-4 font-mono text-xs">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">Trigger Cryptographic Scan</h3>
                </div>
                <button onclick="document.getElementById('scan-target-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-base">&times;</button>
            </div>
            <div class="space-y-3">
                <div>
                    <label class="text-slate-400 block mb-1">Target Codebase Path:</label>
                    <input type="text" id="scan-target-input" placeholder="/home/mohmedh/personal/E-Voting-V2/backend" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-400 focus:outline-none text-xs" />
                </div>
                <div>
                    <label class="text-slate-400 block mb-1">Project Identifier (Optional):</label>
                    <input type="text" id="scan-name-input" placeholder="evoting_backend" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:border-cyan-400 focus:outline-none text-xs" />
                </div>
            </div>
            <div id="scan-status-message" class="text-[11px] text-slate-400"></div>
            <div class="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button onclick="document.getElementById('scan-target-modal').classList.add('hidden')" class="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700">Cancel</button>
                <button onclick="executeScanTrigger()" id="btn-submit-scan" class="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold">Start Discovery</button>
            </div>
        </div>
    </div>

    <script>
    async function executeScanTrigger() {{
        const target = document.getElementById('scan-target-input').value.trim();
        const name = document.getElementById('scan-name-input').value.trim();
        const statusEl = document.getElementById('scan-status-message');
        const btn = document.getElementById('btn-submit-scan');
        if (!target) {{ statusEl.innerHTML = '<span class="text-rose-400">Please enter a valid directory path.</span>'; return; }}
        btn.disabled = true;
        btn.innerText = 'Scanning...';
        statusEl.innerHTML = '<span class="text-cyan-400 animate-pulse">Running AST and cryptographic discovery pipeline...</span>';
        try {{
            const resp = await fetch('/api/scan', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ target: target, name: name }})
            }});
            const data = await resp.json();
            if (resp.ok) {{
                statusEl.innerHTML = '<span class="text-emerald-400">Scan Complete! Reloading dashboard...</span>';
                setTimeout(() => {{ window.location.href = '/project/' + (data.project || name || 'latest'); }}, 800);
            }} else {{
                statusEl.innerHTML = '<span class="text-rose-400">Error: ' + (data.error || 'Scan failed') + '</span>';
                btn.disabled = false;
                btn.innerText = 'Start Discovery';
            }}
        }} catch (e) {{
            statusEl.innerHTML = '<span class="text-rose-400">Network error: ' + e.message + '</span>';
            btn.disabled = false;
            btn.innerText = 'Start Discovery';
        }}
    }}
    </script>
</body>
</html>
"""


def create_fleet_app(reports_dir: Optional[Path] = None, base_dir: Optional[Path] = None) -> Starlette:
    """
    Creates and configures the Starlette ASGI application for the Fleet Dashboard Server.
    """
    app_base_dir = Path(base_dir or Path.cwd()).resolve()

    async def root_handler(request):
        projects = find_scanned_projects(reports_dir=reports_dir, base_dir=app_base_dir)
        if not projects:
            return HTMLResponse(render_fleet_scorecard_html([]))

        # Primary project: first project in list
        primary = projects[0]
        if primary.get("report_path") and Path(primary["report_path"]).exists():
            html_content = Path(primary["report_path"]).read_text(encoding="utf-8", errors="replace")
            enriched_html = inject_fleet_navigation(html_content, primary["name"], projects)
            return HTMLResponse(enriched_html)
        return RedirectResponse("/fleet")

    async def project_handler(request):
        proj_name = request.path_params["name"]
        projects = find_scanned_projects(reports_dir=reports_dir, base_dir=app_base_dir)
        matching = [p for p in projects if p["name"] == proj_name]

        if matching and matching[0].get("report_path") and Path(matching[0]["report_path"]).exists():
            html_content = Path(matching[0]["report_path"]).read_text(encoding="utf-8", errors="replace")
            enriched_html = inject_fleet_navigation(html_content, proj_name, projects)
            return HTMLResponse(enriched_html)

        return HTMLResponse(f"<h3>Project '{proj_name}' not found or has no report.html. <a href='/fleet'>Return to Fleet</a></h3>", status_code=404)

    async def fleet_page_handler(request):
        projects = find_scanned_projects(reports_dir=reports_dir, base_dir=app_base_dir)
        return HTMLResponse(render_fleet_scorecard_html(projects))

    async def api_fleet_handler(request):
        projects = find_scanned_projects(reports_dir=reports_dir, base_dir=app_base_dir)
        total_assets = sum(p["asset_count"] for p in projects)
        total_critical = sum(p["critical_count"] for p in projects)
        total_high = sum(p["high_count"] for p in projects)

        return JSONResponse({
            "status": "success",
            "fleet_summary": {
                "total_projects": len(projects),
                "total_assets": total_assets,
                "total_critical_risks": total_critical,
                "total_high_risks": total_high,
                "overall_readiness_pct": max(0, round(((total_assets - (total_critical + total_high)) / max(1, total_assets)) * 100))
            },
            "projects": projects
        })

    async def api_scan_handler(request):
        try:
            body = await request.json()
            target_path = body.get("target", "").strip()
            custom_name = body.get("name", "").strip() or Path(target_path).name or "scan_output"

            projects = find_scanned_projects(reports_dir=reports_dir, base_dir=app_base_dir)
            matching = [p for p in projects if p["name"] == target_path or p["name"] == custom_name]

            # If target_path is not an existing filesystem path, check if it matches a known project
            if (not target_path or not Path(target_path).exists()) and matching:
                target_path = matching[0]["directory"]
                custom_name = matching[0]["name"]

            if not target_path or not Path(target_path).exists():
                return JSONResponse({"status": "error", "error": f"Target path '{target_path}' does not exist."}, status_code=400)

            # If existing project with an established report directory, refresh in-place
            if matching and matching[0].get("report_path"):
                out_dir = Path(matching[0]["report_path"]).parent
            else:
                out_dir = app_base_dir / "scans" / custom_name
            out_dir.mkdir(parents=True, exist_ok=True)

            # Run pipeline asynchronously using standard pipeline logic
            from ecdat.pipeline import run_pipeline
            res = run_pipeline(target=target_path, output_dir=str(out_dir))

            return JSONResponse({
                "status": "success",
                "project": custom_name,
                "output_dir": str(out_dir),
                "total_assets": len(res.assets) if hasattr(res, "assets") else 0
            })
        except Exception as e:
            return JSONResponse({"status": "error", "error": str(e)}, status_code=500)

    routes = [
        Route("/", endpoint=root_handler, methods=["GET"]),
        Route("/project/{name}", endpoint=project_handler, methods=["GET"]),
        Route("/fleet", endpoint=fleet_page_handler, methods=["GET"]),
        Route("/api/fleet", endpoint=api_fleet_handler, methods=["GET"]),
        Route("/api/scan", endpoint=api_scan_handler, methods=["POST"]),
    ]

    return Starlette(debug=False, routes=routes)


def start_server(host: str = "127.0.0.1", port: int = 8080, reports_dir: Optional[str] = None):
    """
    Entry point to run the ECDAT Fleet Dashboard Server using uvicorn.
    """
    import uvicorn
    p_reports = Path(reports_dir) if reports_dir else None
    app = create_fleet_app(reports_dir=p_reports)
    print(f"\n[*] Starting ECDAT Multi-Project Fleet Dashboard on http://{host}:{port}")
    print(f"[*] Fleet Scorecard: http://{host}:{port}/fleet\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
