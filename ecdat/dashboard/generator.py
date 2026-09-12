"""
ECDAT Visual Interactive Report & Dashboard Generator:
Generates an executive-grade, standalone HTML5/JS report ('report.html') featuring:
1. Academic & defense-grade mathematical typography with KaTeX (LaTeX math rendering for $Y_{\\max}$, $X_{\\text{eff}}$, $Z_{\\text{reg}}$, $R_0$).
2. D3.js force-directed bubble graph with $R_0$ contagion coloring, search, and hub-and-spoke file inspector.
3. Mosca $Y_{\\max}$ timeline and Gantt schedule against OMB M-26-15, NIST SP 800-131A, and GRI 2025 regulatory horizons.
4. Comprehensive CBOM inventory with exact file paths, line numbers, and persistence sinks.
5. Buffer agility hazard inspector with side-by-side remediation code diffs and byte expansion calculations.
6. Live in-browser Web Cryptography SHA-256 Merkle selective proof verification sandbox.
7. Dedicated Third-Party Dependency Supply Chain (SBOM) tab auditing manifest packages (npm, Go, Cargo, PyPI).
8. Native client-side exports for CycloneDX 1.6 CBOM and executive CISO report (rendered with marked.js).
"""

import json
import html
from typing import List, Dict, Tuple, Any, Optional
from pathlib import Path

from ecdat.models import CryptoAsset, MoscaScore
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.agility.buffer_audit import BufferHazard
from ecdat.contagion.engine import ContagionGraphResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECDAT — Cryptographic Discovery & Attestation Report</title>
    <!-- Tailwind CSS (CDN) -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- D3.js v7 (CDN) -->
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <!-- KaTeX for Academic Mathematical Formula Rendering -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/contrib/auto-render.min.js"></script>
    <!-- Marked.js for Structured Markdown Briefing Rendering -->
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        slate: {
                            850: '#111827',
                            900: '#0b0f19',
                            950: '#060911',
                        },
                        defense: {
                            dark: '#070a13',
                            panel: '#0d1322',
                            card: '#121a2d',
                            border: 'rgba(255, 255, 255, 0.08)',
                            cyan: '#38bdf8',
                            critical: '#ef4444',
                            warning: '#f59e0b',
                            success: '#10b981',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        
        :root {
            --bg-base: #060911;
            --surface-panel: #0d1322;
            --surface-card: #121a2d;
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-bright: rgba(56, 189, 248, 0.3);
        }

        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-base);
            color: #e2e8f0;
            letter-spacing: -0.01em;
            overflow-x: hidden;
        }

        code, pre, .font-mono {
            font-family: 'JetBrains Mono', monospace;
        }

        .glass-panel {
            background: rgba(13, 19, 34, 0.85);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-subtle);
        }

        .glass-card-interactive {
            background: rgba(18, 26, 45, 0.75);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .glass-card-interactive:hover {
            border-color: rgba(56, 189, 248, 0.35);
            transform: translateY(-2px);
            box-shadow: 0 12px 28px -6px rgba(0, 0, 0, 0.65);
        }

        .tab-btn {
            position: relative;
            transition: all 0.15s ease;
            white-space: nowrap;
        }

        .tab-btn.tab-active {
            color: #38bdf8;
            font-weight: 700;
        }

        .tab-btn.tab-active::after {
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            right: 0;
            height: 2px;
            background: #38bdf8;
            box-shadow: 0 -2px 10px rgba(56, 189, 248, 0.7);
        }

        /* Superspreader Orbital Radar Ring */
        .radar-pulse {
            animation: radar-sweep 2.4s cubic-bezier(0.2, 0.8, 0.2, 1) infinite;
        }
        @keyframes radar-sweep {
            0% { r: 16px; stroke-opacity: 0.9; stroke-width: 2px; }
            50% { r: 28px; stroke-opacity: 0.3; stroke-width: 4px; }
            100% { r: 36px; stroke-opacity: 0; stroke-width: 1px; }
        }

        .katex {
            font-size: 1.05em !important;
            text-rendering: geometricPrecision;
        }
        .katex-display {
            margin: 0.5em 0 !important;
        }

        .diff-added {
            background-color: rgba(16, 185, 129, 0.15);
            border-left: 3px solid #10b981;
            color: #a7f3d0;
        }
        .diff-removed {
            background-color: rgba(239, 68, 68, 0.15);
            border-left: 3px solid #ef4444;
            color: #fecaca;
        }

        /* CISO Markdown Formatted Table Styling */
        #ciso-markdown-preview table {
            width: 100%;
            border-collapse: collapse;
            margin: 1.25rem 0;
            font-size: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            overflow-x: auto;
            display: block;
        }
        #ciso-markdown-preview th {
            background-color: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.12);
            padding: 0.5rem 0.75rem;
            text-align: left;
            color: #38bdf8;
            font-weight: 700;
            text-transform: uppercase;
        }
        #ciso-markdown-preview td {
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 0.5rem 0.75rem;
            color: #cbd5e1;
        }
        #ciso-markdown-preview tr:hover {
            background-color: rgba(30, 41, 59, 0.5);
        }
        #ciso-markdown-preview h1 { font-size: 1.25rem; font-weight: 800; color: #38bdf8; margin: 1.5rem 0 0.75rem 0; }
        #ciso-markdown-preview h2 { font-size: 1.1rem; font-weight: 700; color: #f8fafc; margin: 1.25rem 0 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.25rem; }
        #ciso-markdown-preview h3 { font-size: 0.95rem; font-weight: 600; color: #93c5fd; margin: 1rem 0 0.25rem 0; }
        #ciso-markdown-preview blockquote { border-left: 3px solid #38bdf8; padding-left: 1rem; color: #94a3b8; font-style: italic; margin: 1rem 0; background: rgba(56, 189, 248, 0.05); padding-top: 0.5rem; padding-bottom: 0.5rem; border-radius: 0 0.5rem 0.5rem 0; }

        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(11, 15, 25, 0.6);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(71, 85, 105, 0.5);
            border-radius: 9999px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(100, 116, 139, 0.8);
        }
    </style>
</head>
<body class="min-h-screen flex flex-col antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
    <!-- Top Defense-Grade Executive Bar -->
    <header class="border-b border-slate-800/80 bg-slate-950/90 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-6 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div class="flex items-center space-x-3.5">
                <div class="w-10 h-10 rounded-lg bg-gradient-to-tr from-cyan-600 via-blue-700 to-indigo-800 flex items-center justify-center font-black text-white text-lg shadow-lg shadow-cyan-900/40 ring-1 ring-white/20">
                    E
                </div>
                <div>
                    <div class="flex items-center gap-2.5">
                        <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                            ECDAT
                            <span class="text-xs text-slate-400 font-normal">| Cryptographic Discovery & Attestation Report</span>
                        </h1>
                        <span class="px-2 py-0.5 text-[11px] font-semibold rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/70 font-mono">
                            FIPS 203/204/205
                        </span>
                        <span class="px-2 py-0.5 text-[11px] font-semibold rounded bg-slate-900 text-slate-300 border border-slate-700 font-mono">
                            OMB M-26-15
                        </span>
                    </div>
                    <p class="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                        <span>Target: <strong class="font-mono text-slate-200">__PROJECT_NAME__</strong></span>
                        <span>&bull;</span>
                        <span class="font-mono text-cyan-400/90">Theorem: $Y_{\\max} = (Z_{\\text{reg}} - 2026) - X_{\\text{eff}}$</span>
                    </p>
                </div>
            </div>

            <!-- Header Quick Actions & Merkle Root Chip -->
            <div class="flex items-center flex-wrap gap-2.5">
                <!-- Committed Root Chip -->
                <div class="flex items-center bg-slate-900/90 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs font-mono shadow-inner">
                    <span class="text-slate-400 mr-2 flex items-center">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 inline-block mr-1.5 animate-pulse"></span>
                        Merkle Root:
                    </span>
                    <span class="text-cyan-300 font-semibold cursor-pointer select-all" onclick="copyRootHex()" title="Click to copy full 32-byte hex">
                        0x__MERKLE_ROOT_SHORT__
                    </span>
                    <button onclick="copyRootHex()" class="ml-2 text-slate-400 hover:text-white p-0.5 rounded transition" title="Copy 32-Byte Merkle Root">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                    </button>
                </div>

                <!-- Export Actions -->
                <button onclick="exportCbomJson()" class="bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition shadow-sm">
                    <svg class="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                    CBOM JSON
                </button>
                <button onclick="exportCisoReportMd()" class="bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition shadow-sm">
                    <svg class="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    CISO Briefing (.md)
                </button>
            </div>
        </div>
    </header>

    <!-- Executive Health Scorecard (Stat Grid with Precise Mathematical Notation) -->
    <section class="max-w-7xl mx-auto px-6 pt-5 w-full">
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
            <!-- 1. Total Assets -->
            <div onclick="switchTab('cbom'); clearCbomFilter();" class="glass-card-interactive rounded-xl p-3.5 cursor-pointer">
                <div class="flex items-center justify-between">
                    <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Assets</p>
                    <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
                </div>
                <div class="mt-2 flex items-baseline">
                    <span class="text-2xl font-black text-white font-mono">__TOTAL_ASSETS__</span>
                    <span class="ml-1.5 text-[11px] text-slate-400 font-mono">Discovered</span>
                </div>
                <div class="mt-1 text-[11px] text-slate-500 font-mono truncate">Code AST + Certs</div>
            </div>

            <!-- 2. Critical Risk (LaTeX: Y_max <= 1y) -->
            <div onclick="switchTab('cbom'); setCbomRiskFilter('CRITICAL');" class="glass-card-interactive rounded-xl p-3.5 border-red-900/50 bg-red-950/20 cursor-pointer">
                <div class="flex items-center justify-between">
                    <p class="text-[11px] font-bold text-red-400 uppercase tracking-wider">Critical Risk</p>
                    <span class="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
                </div>
                <div class="mt-2 flex items-baseline">
                    <span class="text-2xl font-black text-red-400 font-mono">__CRITICAL_COUNT__</span>
                    <span class="ml-1.5 text-xs text-red-300 font-medium">$Y_{\\max} \\le 1\\text{y}$</span>
                </div>
                <div class="mt-1 text-[11px] text-red-300/70 font-mono truncate">HNDL Window Expired</div>
            </div>

            <!-- 3. High Risk (LaTeX: 1 < Y_max <= 3y) -->
            <div onclick="switchTab('cbom'); setCbomRiskFilter('HIGH');" class="glass-card-interactive rounded-xl p-3.5 border-amber-900/50 bg-amber-950/20 cursor-pointer">
                <div class="flex items-center justify-between">
                    <p class="text-[11px] font-bold text-amber-400 uppercase tracking-wider">High Risk</p>
                    <span class="w-2 h-2 rounded-full bg-amber-500"></span>
                </div>
                <div class="mt-2 flex items-baseline">
                    <span class="text-2xl font-black text-amber-400 font-mono">__HIGH_COUNT__</span>
                    <span class="ml-1.5 text-xs text-amber-300 font-medium">$1 < Y_{\\max} \\le 3\\text{y}$</span>
                </div>
                <div class="mt-1 text-[11px] text-amber-300/70 font-mono truncate">Migration Deadline</div>
            </div>

            <!-- 4. R0 Superspreaders (LaTeX: R_0 >= 2) -->
            <div onclick="switchTab('contagion');" class="glass-card-interactive rounded-xl p-3.5 border-purple-900/50 bg-purple-950/20 cursor-pointer">
                <div class="flex items-center justify-between">
                    <p class="text-[11px] font-bold text-purple-400 uppercase tracking-wider">Superspreaders</p>
                    <span class="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
                </div>
                <div class="mt-2 flex items-baseline">
                    <span class="text-2xl font-black text-purple-300 font-mono">__SUPERSPREADER_COUNT__</span>
                    <span class="ml-1.5 text-xs text-purple-300 font-medium">$R_0 \\ge 2$</span>
                </div>
                <div class="mt-1 text-[11px] text-purple-300/70 font-mono truncate">High Fan-out Roots</div>
            </div>

            <!-- 5. Buffer Hazards (LaTeX: Delta B > 0) -->
            <div onclick="switchTab('buffer');" class="glass-card-interactive rounded-xl p-3.5 border-rose-900/50 bg-rose-950/20 cursor-pointer">
                <div class="flex items-center justify-between">
                    <p class="text-[11px] font-bold text-rose-400 uppercase tracking-wider">Buffer Hazards</p>
                    <span class="w-2 h-2 rounded-full bg-rose-500"></span>
                </div>
                <div class="mt-2 flex items-baseline">
                    <span class="text-2xl font-black text-rose-400 font-mono">__HAZARDS_COUNT__</span>
                    <span class="ml-1.5 text-xs text-rose-300 font-medium">$\\Delta B_{\\text{overflow}} > 0$</span>
                </div>
                <div class="mt-1 text-[11px] text-rose-300/70 font-mono truncate">ML-DSA Incompatible</div>
            </div>

            <!-- 6. Quantum Agility Index -->
            <div class="glass-card-interactive rounded-xl p-3.5 border-slate-700/60">
                <div class="flex items-center justify-between">
                    <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Agility Index</p>
                    <span class="text-[10px] font-mono text-cyan-400 font-bold">Q-SCORE</span>
                </div>
                <div class="mt-2 flex items-baseline">
                    <span class="text-2xl font-black text-cyan-300 font-mono">__READINESS_SCORE__</span>
                    <span class="ml-1 text-[11px] text-slate-400 font-mono">/ 100</span>
                </div>
                <div class="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div class="bg-gradient-to-r from-red-500 via-amber-400 to-emerald-400 h-1.5 rounded-full" style="width: __READINESS_SCORE__%;"></div>
                </div>
            </div>
        </div>
    </section>

    <!-- Tab Navigation Bar -->
    <nav class="max-w-7xl mx-auto px-6 mt-6 w-full border-b border-slate-800">
        <div class="flex space-x-1 sm:space-x-3 overflow-x-auto text-xs font-semibold text-slate-400 pb-px">
            <button onclick="switchTab('contagion')" id="tab-btn-contagion" class="tab-btn tab-active pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="18" cy="5" r="3" stroke-width="2"/><circle cx="6" cy="12" r="3" stroke-width="2"/><circle cx="18" cy="19" r="3" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.59 13.51l6.83 3.98m-.01-10.98l-6.82 3.98"/></svg>
                <span>Cryptographic Contagion Graph ($R_0$)</span>
            </button>
            <button onclick="switchTab('mosca')" id="tab-btn-mosca" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6l4 2"/></svg>
                <span>Mosca $Y_{\\max}$ Schedule</span>
            </button>
            <button onclick="switchTab('cbom')" id="tab-btn-cbom" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                <span>CBOM Inventory & Trace</span>
            </button>
            <button onclick="switchTab('buffer')" id="tab-btn-buffer" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-rose-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                <span>Buffer Agility Hazards (__HAZARDS_COUNT__)</span>
            </button>
            <button onclick="switchTab('supplychain')" id="tab-btn-supplychain" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-purple-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
                <span>Supply Chain SBOM (__DEPS_COUNT__)</span>
            </button>
            <button onclick="switchTab('proof')" id="tab-btn-proof" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-teal-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                <span>Attestation Sandbox</span>
            </button>
            <button onclick="switchTab('unknowns')" id="tab-btn-unknowns" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-orange-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                <span>Unknowns Ledger (__UNKNOWNS_COUNT__)</span>
            </button>
            <button onclick="switchTab('ciso')" id="tab-btn-ciso" class="tab-btn pb-3 px-3 flex items-center gap-2 hover:text-slate-200">
                <svg class="w-4 h-4 text-blue-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                <span>Executive CISO Report</span>
            </button>
        </div>
    </nav>

    <!-- Main Content Container -->
    <main class="max-w-7xl mx-auto px-6 py-6 w-full flex-grow">

        <!-- ================= TAB 1: CONTAGION GRAPH ================= -->
        <div id="tab-pane-contagion" class="space-y-4">

            <!-- Tab 1 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Cryptographic Contagion &amp; Dependency Risk Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        Visualizes how cryptographic algorithms and dependencies propagate through your codebase. A single vulnerable classical key or library can "infect" multiple downstream microservices and business workflows.
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-slate-300">Basic Reproduction Number ($R_0$):</strong> Counts downstream dependent services reachable from each component.</span>
                        <span>&bull; <strong class="text-rose-400">Superspreaders ($R_0 \\ge 2$):</strong> High-leverage classical hubs. Migrating one superspreader immunizes all its downstream dependents.</span>
                        <span>&bull; <strong class="text-emerald-400">PQC Anchors:</strong> Post-quantum components providing forward quantum security to consumers.</span>
                    </div>
                </div>
            </div>

            <div class="p-4 rounded-xl glass-panel border border-slate-700/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h3 class="text-sm font-bold text-white flex items-center gap-2">
                        <span>Cryptographic Contagion Graph &bull; Dependency Risk Propagation</span>
                    </h3>
                    <p class="text-xs text-slate-300 mt-1">
                        Directed propagation with oriented contagion vectors:
                        $$\\mathcal{R}_0(v) = \\text{deg}_{\\text{out}}(v) \\times \\sum_{u \\in \\text{Children}(v)} \\text{BlastWeight}(u) \\quad \\left(\\mathcal{R}_0 \\ge 2 \\implies \\text{Superspreader}\\right)$$
                    </p>
                </div>
                <div class="flex items-center gap-2 flex-wrap">
                    <input type="text" id="graph-search" placeholder="Search node name..." oninput="filterGraphNodes(this.value)" class="bg-slate-900 text-xs px-3 py-1.5 rounded-lg border border-slate-700 focus:outline-none focus:border-cyan-400 w-36 font-mono text-slate-200" />
                    <button onclick="toggleGraphLabels()" id="graph-labels-btn" class="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 border border-slate-700 hover:text-white transition flex items-center gap-1.5" title="Cycle Label Density (Smart / Key Hubs / All)">
                        <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h10M7 12h10m-7 5h7"/></svg>
                        <span id="label-mode-text">Labels: Smart</span>
                    </button>
                    <button onclick="zoomGraphIn()" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:text-white transition" title="Zoom In">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                    </button>
                    <button onclick="zoomGraphOut()" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:text-white transition" title="Zoom Out">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4"/></svg>
                    </button>
                    <button onclick="fitGraphToView()" class="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 hover:text-white transition flex items-center gap-1.5" title="Fit to View">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"/></svg>
                        <span>Fit View</span>
                    </button>
                </div>
            </div>

            <div class="glass-panel rounded-2xl p-3 border border-slate-800 relative overflow-hidden">
                <!-- Updated Accurate Graph Legend -->
                <div class="absolute top-4 left-4 z-10 bg-slate-950/90 backdrop-blur-md border border-slate-800 rounded-xl p-3 text-[11px] font-mono space-y-1.5 shadow-xl max-w-xs">
                    <div class="text-slate-400 font-bold uppercase tracking-wider text-[10px] mb-1 flex items-center justify-between">
                        <span>Graph Legend</span>
                        <span id="graph-stats" class="text-[9px] text-cyan-400 font-normal"></span>
                    </div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-[#ef4444] inline-block ring-2 ring-red-400/50"></span> <span>Superspreader ($R_0 \\ge 2$)</span></div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-[#10b981] inline-block ring-2 ring-emerald-400/40"></span> <span>PQC Immunization Anchor</span></div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-[#06b6d4] inline-block"></span> <span>Safe Symmetric / Hash</span></div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-[#f97316] inline-block"></span> <span>Direct Crypto Source</span></div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-[#3b82f6] inline-block"></span> <span>Intermediary Router</span></div>
                    <div class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full bg-[#64748b] inline-block"></span> <span>Consumer Module</span></div>
                </div>
                <svg id="contagion-svg" class="w-full h-[600px] bg-[#080c16] rounded-xl cursor-grab active:cursor-grabbing"></svg>
            </div>
        </div>

        <!-- ================= TAB 2: MOSCA SCHEDULE ================= -->
        <div id="tab-pane-mosca" class="hidden space-y-5">

            <!-- Tab 2 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Mosca's Structural Theorem &amp; Migration Budget Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        Formulated by Dr. Michele Mosca, this theorem models the temporal countdown before classical encrypted data is exposed to Harvest Now, Decrypt Later (HNDL) quantum attacks.
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-slate-300">Data Lifespan ($X_{\\text{eff}}$):</strong> Required years of confidentiality inferred from persistence sinks (memory, cache, DB, disk, archive).</span>
                        <span>&bull; <strong class="text-rose-400">Migration Budget ($Y_{\\max}$):</strong> Years left to migrate before exposure: $Y_{\\max} = \\max(0, (Z_{\\text{reg}} - 2026) - X_{\\text{eff}})$.</span>
                        <span>&bull; <strong class="text-amber-400">Risk Urgency:</strong> $Y_{\\max} \\le 1\\text{y}$ (CRITICAL, Immediate Migration) &bull; $Y_{\\max} \\le 3\\text{y}$ (HIGH) &bull; $Y_{\\max} > 3\\text{y}$ (MEDIUM/LOW).</span>
                    </div>
                </div>
            </div>

            <div class="p-5 rounded-2xl glass-panel border border-cyan-900/40 bg-slate-900/60 space-y-3">
                <div class="flex items-center justify-between">
                    <h3 class="text-sm font-bold text-cyan-300 flex items-center gap-2">
                        <span>Mosca's Structural Theorem: Temporal Quantum Risk Formulation</span>
                    </h3>
                    <span class="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">
                        NIST IR 8547 / OMB M-26-15
                    </span>
                </div>
                <div class="text-xs text-slate-200 leading-relaxed grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800/80">
                        <div class="text-slate-400 font-semibold mb-1 text-[11px] uppercase tracking-wider font-mono">Governing Inequality</div>
                        <div class="text-center py-2 text-cyan-200">
                            $$X_{\\text{eff}} + Y > Z_{\\text{reg}} \\implies \\text{Adversarial Decryption Window (HNDL)}$$
                        </div>
                        <p class="text-[11px] text-slate-400">
                            If data confidentiality lifespan ($X$) plus migration lead time ($Y$) exceeds the regulatory or physical quantum arrival horizon ($Z$), captured ciphertext is vulnerable to retrospective Harvest Now, Decrypt Later attacks.
                        </p>
                    </div>
                    <div class="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800/80">
                        <div class="text-slate-400 font-semibold mb-1 text-[11px] uppercase tracking-wider font-mono">Migration Budget Formulation</div>
                        <div class="text-center py-2 text-rose-300 font-bold">
                            $$Y_{\\max} = \\max\\left(0, (Z_{\\text{reg}} - 2026) - X_{\\text{eff}}\\right)$$
                        </div>
                        <p class="text-[11px] text-slate-400">
                            $Y_{\\max}$ defines the hard temporal threshold before security compromise occurs. Assets with $Y_{\\max} \\le 1\\text{y}$ require immediate remediation.
                        </p>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span class="text-[10px] font-mono text-cyan-400 block font-bold">2026 BASELINE</span>
                    <span class="text-xs text-slate-300">ECDAT Assessment Origin</span>
                </div>
                <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span class="text-[10px] font-mono text-amber-400 block font-bold">2030 REGULATORY</span>
                    <span class="text-xs text-slate-300">OMB M-26-15 PK Deprecation</span>
                </div>
                <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span class="text-[10px] font-mono text-rose-400 block font-bold">2033 PROBABILISTIC</span>
                    <span class="text-xs text-slate-300">GRI 2025 CRQC 50% Threshold</span>
                </div>
                <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                    <span class="text-[10px] font-mono text-purple-400 block font-bold">2035 ABSOLUTE CUTOFF</span>
                    <span class="text-xs text-slate-300">NIST SP 800-131A Mandatory</span>
                </div>
            </div>

            <div class="glass-panel rounded-2xl p-5 border border-slate-800 space-y-4">
                <div class="flex items-center justify-between pb-3 border-b border-slate-800">
                    <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                        Asset Lifespan ($X_{\\text{eff}}$) & Remaining Migration Budget ($Y_{\\max}$)
                    </h4>
                    <span class="text-[11px] text-slate-400 font-mono">Sorted by Urgency ($Y_{\\max}$ ascending)</span>
                </div>
                <div id="gantt-chart-container" class="space-y-3 font-mono text-xs overflow-hidden">
                    <!-- Populated dynamically via JS -->
                </div>
            </div>
        </div>

        <!-- ================= TAB 3: CBOM INVENTORY ================= -->
        <div id="tab-pane-cbom" class="hidden space-y-4">

            <!-- Tab 3 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Cryptographic Bill of Materials (CBOM) Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        An exhaustive, machine-readable inventory (CycloneDX 1.6 standard) of every cryptographic asset in the codebase—including algorithms, keys, certificates, and persistence sinks.
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-slate-300">Regulatory Mandate:</strong> OMB M-22-18 and NIST IR 8547 require verified CBOM inventories to justify PQC transition funding.</span>
                        <span>&bull; <strong class="text-cyan-300">File &amp; Sink Traceability:</strong> Every asset records exact file location, line number, and data destination (DB, cache, memory, socket).</span>
                        <span>&bull; <strong class="text-slate-300">Quick Search:</strong> Press <kbd class="px-1 py-0.2 rounded bg-slate-800 border border-slate-700 text-cyan-300">/</kbd> to filter or click "Inspect" to view full component details in the slide-over drawer.</span>
                    </div>
                </div>
            </div>

            <div class="p-4 rounded-xl glass-panel border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div class="flex items-center flex-wrap gap-2 text-xs font-mono">
                    <button onclick="filterCbomTable('ALL')" id="filter-btn-ALL" class="px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold transition">
                        ALL (__TOTAL_ASSETS__)
                    </button>
                    <button onclick="filterCbomTable('CRITICAL')" id="filter-btn-CRITICAL" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-red-300 transition">
                        CRITICAL ($Y_{\\max} \\le 1\\text{y}$) (__CRITICAL_COUNT__)
                    </button>
                    <button onclick="filterCbomTable('HIGH')" id="filter-btn-HIGH" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-amber-300 transition">
                        HIGH ($Y_{\\max} \\le 3\\text{y}$) (__HIGH_COUNT__)
                    </button>
                    <button onclick="filterCbomTable('MEDIUM')" id="filter-btn-MEDIUM" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-yellow-300 transition">
                        MEDIUM (__MEDIUM_COUNT__)
                    </button>
                    <button onclick="filterCbomTable('LOW')" id="filter-btn-LOW" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-emerald-300 transition">
                        LOW (__LOW_COUNT__)
                    </button>
                    <button onclick="toggleSuppressOperational()" id="btn-suppress-op" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-cyan-300 flex items-center gap-1.5 transition ml-1">
                        <svg class="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/></svg>
                        <span>Suppress Operational Utility</span>
                        <span id="suppress-op-count" class="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-cyan-400 font-bold font-mono">0</span>
                    </button>
                </div>

                <div class="relative min-w-[260px]">
                    <span class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-slate-500 text-xs">
                        <kbd class="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400">/</kbd>
                    </span>
                    <input type="text" id="cbom-search" placeholder="Filter by path, line, algorithm, sink..." oninput="onCbomSearch(this.value)" class="bg-slate-900 text-xs pl-9 pr-4 py-2 rounded-lg border border-slate-700 focus:outline-none focus:border-cyan-400 w-full font-mono text-slate-200 placeholder-slate-500 shadow-inner" />
                </div>
            </div>

            <div class="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                            <tr>
                                <th class="py-3 px-4">Asset ID & Component</th>
                                <th class="py-3 px-4">Algorithm & Primitive</th>
                                <th class="py-3 px-4">File Location & Line</th>
                                <th class="py-3 px-4">Persistence Sink / Evidence</th>
                                <th class="py-3 px-4">Lifespan ($X_{\\text{eff}}$)</th>
                                <th class="py-3 px-4">Mosca Budget ($Y_{\\max}$)</th>
                                <th class="py-3 px-4">NIST PQC Migration Target</th>
                                <th class="py-3 px-4 text-center">Inspect</th>
                            </tr>
                        </thead>
                        <tbody id="cbom-table-body" class="divide-y divide-slate-800/60 font-mono">
                            <!-- Populated dynamically via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB 4: BUFFER AGILITY HAZARDS ================= -->
        <div id="tab-pane-buffer" class="hidden space-y-5">

            <!-- Tab 4 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Buffer Agility &amp; Memory Deficit Audit Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        Post-quantum cryptography requires dramatically larger memory footprints. For example, NIST FIPS 204 ML-DSA-65 signatures are 3,309 bytes, compared to 64 bytes for classical ECDSA-P256 (+5,070% expansion).
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-rose-400">Memory Deficit Hazard:</strong> Fixed-size buffers (e.g. <code>byte[64]</code>) cause immediate truncation, memory corruptions, or silent failures when PQC is enabled.</span>
                        <span>&bull; <strong class="text-emerald-400">Remediation Diffs:</strong> Drop-in dynamic allocation diffs are generated automatically below to replace hardcoded arrays with agile buffers.</span>
                        <span>&bull; <strong class="text-slate-300">Target Standards:</strong> FIPS 203 ML-KEM (encapsulation), FIPS 204 ML-DSA (signatures), FIPS 205 SLH-DSA (stateless hash).</span>
                    </div>
                </div>
            </div>

            <div class="p-5 rounded-2xl glass-panel border border-rose-900/40 bg-slate-900/60 space-y-3">
                <div class="flex items-center justify-between">
                    <h3 class="text-sm font-bold text-rose-300 flex items-center gap-2">
                        <span>Static Buffer Agility Audit: Classical vs. Post-Quantum Memory Requirements</span>
                    </h3>
                    <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-950 border border-rose-800 text-rose-300 font-mono">
                        Memory Deficit Hazard
                    </span>
                </div>
                <p class="text-xs text-slate-300 leading-relaxed">
                    Post-quantum signatures (such as NIST FIPS 204 ML-DSA-65) produce outputs exceeding 3,000 bytes, compared to 64 bytes for classical ECDSA-P256. Code allocating fixed-size bytearrays without dynamic sizing triggers immediate truncation or memory corruption:
                    $$\\Delta B_{\\text{deficit}} = \\text{Required}_{\\text{PQC}} - \\text{Allocated}_{\\text{Classical}} = 3309\\text{ B} - 64\\text{ B} = +3245\\text{ B} \\quad (+5070\\% \\text{ expansion})$$
                </p>
            </div>

            <!-- Dynamic Remediation Diff & Buffer Agility Status Card Container -->
            <div id="buffer-remediation-cards" class="space-y-4">
                <!-- Populated dynamically via JS: Remediation Diffs for detected hazards or Zero-Deficit Agility Confirmation -->
            </div>

            <!-- Detected Hazards Table -->
            <div class="glass-panel rounded-2xl border border-slate-800 overflow-hidden">
                <div class="p-4 border-b border-slate-800">
                    <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Detected Hardcoded Buffer Allocations</h4>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs font-mono">
                        <thead class="bg-slate-950/80 border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                            <tr>
                                <th class="py-3 px-4">Variable Name</th>
                                <th class="py-3 px-4">Source File & Line</th>
                                <th class="py-3 px-4">Allocated Bytes</th>
                                <th class="py-3 px-4">Required PQC Bytes</th>
                                <th class="py-3 px-4">Buffer Deficit</th>
                                <th class="py-3 px-4">Severity</th>
                            </tr>
                        </thead>
                        <tbody id="hazards-table-body" class="divide-y divide-slate-800/60">
                            <!-- Populated dynamically via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB 5: DEPENDENCY SUPPLY CHAIN SBOM ================= -->
        <div id="tab-pane-supplychain" class="hidden space-y-4">

            <!-- Tab 5 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Cryptographic Supply Chain (SBOM) Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        Discovers and audits all third-party cryptographic dependencies declared in manifests across npm (package.json), Go (go.mod), Rust (Cargo.toml), and Python (requirements.txt).
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-slate-300">Upstream Exposure:</strong> Over 80% of modern application cryptography is imported. Classical dependencies silently undermine your post-quantum perimeter.</span>
                        <span>&bull; <strong class="text-emerald-400">Posture Classification:</strong> Identifies whether libraries are Migrated PQC, Quantum Agility Enablers, Safe Symmetric, or require immediate replacement.</span>
                        <span>&bull; <strong class="text-cyan-300">Clean AST Separation:</strong> Manifest packages are tracked in this dedicated SBOM table without cluttering your core internal codebase AST graphs.</span>
                    </div>
                </div>
            </div>

            <div class="p-4 rounded-xl glass-panel border border-slate-800 flex items-center justify-between">
                <div>
                    <h3 class="text-sm font-bold text-white flex items-center gap-2">
                        <span>Third-Party Cryptographic Supply Chain (SBOM)</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                            Manifest Audited
                        </span>
                    </h3>
                    <p class="text-xs text-slate-400 mt-0.5">
                        Audits declared third-party crypto packages in manifests (npm, Go, Cargo, PyPI) without polluting code AST graphs.
                    </p>
                </div>
            </div>
            <div class="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs font-mono">
                        <thead class="bg-slate-950/80 border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider">
                            <tr>
                                <th class="py-3 px-4">Package Name</th>
                                <th class="py-3 px-4">Ecosystem</th>
                                <th class="py-3 px-4">Version</th>
                                <th class="py-3 px-4">Manifest Path</th>
                                <th class="py-3 px-4">Crypto Category</th>
                                <th class="py-3 px-4">Post-Quantum Posture</th>
                                <th class="py-3 px-4">Actionable Guidance</th>
                            </tr>
                        </thead>
                        <tbody id="supplychain-table-body" class="divide-y divide-slate-800/60">
                            <!-- Populated dynamically via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB 6: MERKLE ZERO-KNOWLEDGE PROOF ATTESTATION ================= -->
        <div id="tab-pane-proof" class="hidden space-y-5">

            <!-- Tab 6 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Zero-Knowledge Attestation Sandbox Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        Enables mathematical proof to auditors, regulators, or clients that a cryptographic asset exists in the baseline without disclosing source code paths, internal architecture, or key material.
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-slate-300">Merkle Root:</strong> The 32-byte root hash commits the entire cryptographic state immutably.</span>
                        <span>&bull; <strong class="text-emerald-400">Client-Side Verification:</strong> Computes the SHA-256 sibling authentication ladder directly in your browser using the W3C WebCrypto API.</span>
                        <span>&bull; <strong class="text-rose-400">Tamper Testing:</strong> Click "Test Tamper Resistance" to simulate an adversarial 1-byte alteration and observe instant rejection.</span>
                    </div>
                </div>
            </div>

            <div class="p-5 rounded-2xl glass-panel border border-emerald-900/40 bg-slate-900/60 space-y-3">
                <div class="flex items-center justify-between">
                    <h3 class="text-sm font-bold text-emerald-300 flex items-center gap-2">
                        <span>Zero-Knowledge Merkle Selective Disclosure Attestation Sandbox</span>
                    </h3>
                    <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-300 font-mono">
                        W3C WebCrypto API SHA-256
                    </span>
                </div>
                <p class="text-xs text-slate-300 leading-relaxed">
                    Verify that an individual cryptographic asset exists within the enterprise baseline without disclosing source code paths or proprietary architecture:
                    $$H_{\\text{leaf}} = \\text{SHA256}\\left(\\text{AssetID} \\parallel \\text{Algorithm} \\parallel X_{\\text{tier}} \\parallel \\text{Salt}\\right)$$
                </p>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-12 gap-5">
                <div class="lg:col-span-5 glass-panel rounded-2xl p-5 border border-slate-800 space-y-4">
                    <label class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono block">Select Asset Proof Package</label>
                    <select id="proof-asset-select" onchange="onSelectProofPackage(this.value)" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:border-cyan-400 focus:outline-none">
                        <!-- Populated via JS -->
                    </select>

                    <div class="p-3.5 rounded-xl bg-slate-950 border border-slate-800/80 font-mono text-xs space-y-2 text-slate-300">
                        <div class="text-[11px] text-slate-400 font-bold uppercase tracking-wider">Committed Merkle Root</div>
                        <div class="text-xs text-emerald-400 break-all select-all font-bold">
                            0x__MERKLE_ROOT__
                        </div>
                    </div>

                    <div class="flex gap-2">
                        <button onclick="runClientSideProofVerification(false)" class="flex-1 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold py-2.5 px-4 rounded-xl text-xs font-mono transition shadow-lg shadow-emerald-900/30">
                            Verify Proof in Browser
                        </button>
                        <button onclick="runClientSideProofVerification(true)" class="bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 py-2.5 px-3 rounded-xl text-xs font-mono transition" title="Simulate 1-byte adversary tamper">
                            Test Tamper Resistance
                        </button>
                    </div>
                </div>

                <div class="lg:col-span-7 glass-panel rounded-2xl p-5 border border-slate-800 space-y-3">
                    <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                        <span class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Cryptographic Verification Ladder</span>
                        <span id="proof-status-tag" class="text-xs px-3 py-1 rounded-full font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">READY</span>
                    </div>
                    <div id="proof-steps-container" class="space-y-2 font-mono text-xs max-h-[360px] overflow-y-auto">
                        <div class="text-slate-500 p-4 text-center">Select an asset proof package and click "Verify Proof in Browser".</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ================= TAB 7: UNKNOWNS LEDGER ================= -->
        <div id="tab-pane-unknowns" class="hidden space-y-4">

            <!-- Tab 7 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-orange-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Auditable Unknowns Ledger &amp; Perimeter Boundary Honesty</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        Traditional scanners claim false 100% security coverage by silently ignoring files they cannot parse. ECDAT practices <strong>Boundary Honesty</strong> by declaring all excluded third-party paths, uninspected binary files, and encrypted keystores.
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-orange-300">Auditable Honesty:</strong> Auditors know exactly what was scanned and what technical limitations constrained coverage.</span>
                        <span>&bull; <strong class="text-slate-300">Binary Boundaries:</strong> Compiled native libraries (.so, .dll) require eBPF runtime profiling or binary disassemblers.</span>
                        <span>&bull; <strong class="text-cyan-300">Credential Boundaries:</strong> Encrypted keystores (.p12, .jks) require decryption passwords to inspect certificates.</span>
                    </div>
                </div>
            </div>

            <div class="p-4 rounded-xl glass-panel border border-slate-800 flex items-center justify-between">
                <div>
                    <h3 class="text-sm font-bold text-white">Auditable Unknowns Ledger (<span class="font-mono text-orange-400">__UNKNOWNS_COUNT__</span> entries logged)</h3>
                    <p class="text-xs text-slate-400 mt-0.5">Explicit declarations of scanning perimeter exclusions and format limitations.</p>
                </div>
                <div class="text-xs font-mono text-slate-400">
                    <span class="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-orange-400">Perimeter Defense-in-Depth</span>
                </div>
            </div>

            <div class="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                            <tr>
                                <th class="py-3 px-4">Item Path / Identifier</th>
                                <th class="py-3 px-4">Category</th>
                                <th class="py-3 px-4">Perimeter Limitation / Reason</th>
                                <th class="py-3 px-4">Recommended Auditor Action</th>
                            </tr>
                        </thead>
                        <tbody id="unknowns-table-body" class="divide-y divide-slate-800/60 font-mono">
                            <!-- Populated dynamically via JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB 8: EXECUTIVE CISO REPORT ================= -->
        <div id="tab-pane-ciso" class="hidden space-y-4">

            <!-- Tab 7 Info Banner -->
            <div class="p-4 rounded-xl glass-panel border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 to-slate-900/50 flex items-start gap-3.5 shadow-lg">
                <div class="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                </div>
                <div class="flex-grow text-xs space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 uppercase tracking-wider text-[11px] font-mono">Executive CISO Migration Briefing Guide</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Tab Guide</span>
                    </div>
                    <p class="text-slate-300 leading-relaxed text-[11px]">
                        A formal, C-level executive briefing synthesizing technical findings into business risk metrics, data confidentiality exposure windows (HNDL), and actionable NIST FIPS migration roadmaps.
                    </p>
                    <div class="pt-1 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                        <span>&bull; <strong class="text-slate-300">Executive Synthesis:</strong> Structured for CISOs, Board Risk Committees, and compliance officers under OMB M-26-15.</span>
                        <span>&bull; <strong class="text-cyan-300">Export Ready:</strong> Use "Copy Markdown" or "Download .md" to integrate directly into your organization's GRC or reporting portals.</span>
                        <span>&bull; <strong class="text-slate-300">Hybrid Recommendations:</strong> Recommends RFC 9180 composite pairings (e.g. classical + ML-DSA-65) for dual-verification safety.</span>
                    </div>
                </div>
            </div>

            <div class="p-4 rounded-xl glass-panel border border-slate-800 flex items-center justify-between">
                <div>
                    <h3 class="text-sm font-bold text-white">Executive CISO Migration Briefing</h3>
                    <p class="text-xs text-slate-400 mt-0.5">Formal executive briefing rendered directly from Markdown.</p>
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="copyCisoReportMarkdown()" class="bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 transition">
                        Copy Markdown
                    </button>
                    <button onclick="exportCisoReportMd()" class="bg-cyan-600 hover:bg-cyan-500 text-white px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 transition font-semibold">
                        Download .md
                    </button>
                </div>
            </div>
            <div class="glass-panel rounded-2xl p-6 border border-slate-800 overflow-x-auto">
                <div id="ciso-markdown-preview" class="text-xs leading-relaxed font-sans text-slate-300">
                    <!-- Populated via marked.js -->
                </div>
            </div>
        </div>

    </main>

    <!-- Slide-Over Asset Detail Drawer -->
    <div id="asset-drawer-backdrop" onclick="closeAssetDrawer()" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 opacity-0 pointer-events-none transition-opacity duration-200"></div>
    <div id="asset-drawer" class="fixed right-0 top-0 bottom-0 w-full sm:w-[500px] bg-slate-950 border-l border-slate-800 z-50 p-6 flex flex-col transform translate-x-full transition-transform duration-200 ease-out shadow-2xl overflow-y-auto">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
                <span id="drawer-asset-id" class="text-xs font-bold font-mono text-cyan-400 block">ASSET-001</span>
                <h3 id="drawer-title" class="text-base font-bold text-white mt-0.5">Component Details</h3>
            </div>
            <button onclick="closeAssetDrawer()" class="p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-700 transition">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>

        <div class="py-5 space-y-4 flex-grow text-xs">
            <div class="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 font-mono space-y-1.5">
                <span class="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Source Code Location</span>
                <div class="text-cyan-300 font-semibold flex items-center gap-1.5">
                    <svg class="w-4 h-4 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    <span id="drawer-file-path" class="break-all">source.py:42</span>
                </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 font-mono space-y-1.5">
                <span class="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Persistence Sink & Dataflow Evidence</span>
                <div id="drawer-sink-call" class="text-amber-300 bg-black/40 p-2 rounded border border-slate-800 break-all">
                    db.session.add(...)
                </div>
                <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                    <span>Lifespan Tier: <strong id="drawer-tier" class="text-slate-200">OPERATIONAL</strong></span>
                    <span>Confidence: <strong id="drawer-confidence" class="text-slate-200">0.90</strong></span>
                </div>
            </div>

            <div class="p-4 rounded-xl bg-slate-900/90 border border-cyan-900/50 font-mono space-y-2">
                <span class="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">Mosca Risk Formulation Proof</span>
                <div class="text-slate-300 text-xs py-1">
                    $$Y_{\\max} = (Z_{\\text{reg}} - 2026) - X_{\\text{eff}}$$
                </div>
                <div id="drawer-mosca-calc" class="text-xs text-rose-300 bg-black/40 p-2.5 rounded border border-slate-800">
                </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 font-mono space-y-2">
                <span class="text-[10px] text-emerald-400 font-bold uppercase tracking-wider block">NIST Post-Quantum Replacement</span>
                <div>
                    <div class="text-[11px] text-slate-400">Standalone Standard:</div>
                    <div id="drawer-pqc-target" class="text-emerald-300 font-bold">ML-DSA-65 (FIPS 204)</div>
                </div>
                <div>
                    <div class="text-[11px] text-slate-400">RFC 9180 Hybrid Pairing:</div>
                    <div id="drawer-hybrid-target" class="text-cyan-300 font-semibold">ECDSA-P256 + ML-DSA-65</div>
                </div>
                <div class="text-[11px] text-slate-400 pt-1 leading-relaxed" id="drawer-guidance">
                    Migrate signatures to composite dual-verification standard.
                </div>
            </div>
        </div>

        <div class="pt-4 border-t border-slate-800 flex items-center justify-between">
            <span id="drawer-risk-pill" class="text-xs px-3 py-1 rounded-full font-mono font-bold bg-red-950 text-red-300 border border-red-800">
                CRITICAL
            </span>
            <button onclick="copyDrawerAssetJson()" class="bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono transition">
                Copy JSON
            </button>
        </div>
    </div>

    <!-- Toast Notification Container -->
    <div id="toast-container" class="fixed bottom-6 right-6 z-50 space-y-2 pointer-events-none"></div>

    <!-- Embedded Datasets and Client-Side Engine -->
    <script>
        const ASSETS_DATA = __ASSETS_JSON__;
        const GRAPH_DATA = __GRAPH_JSON__;
        const HAZARDS_DATA = __HAZARDS_JSON__;
        const PROOFS_DATA = __PROOFS_JSON__;
        const DEPS_DATA = __DEPS_JSON__;
        const UNKNOWNS_DATA = __UNKNOWNS_JSON__;
        const MERKLE_ROOT_HEX = "__MERKLE_ROOT__";
        const CISO_MD_TEXT = __CISO_MD__;

        let activeCbomFilter = 'ALL';
        let suppressOperationalUtility = false;
        let currentDrawerAsset = null;

        function triggerKaTeX() {
            if (typeof renderMathInElement === 'function') {
                renderMathInElement(document.body, {
                    delimiters: [
                        {left: '$$', right: '$$', display: true},
                        {left: '$', right: '$', display: false}
                    ],
                    throwOnError: false
                });
            }
        }

        function showToast(msg, isError = false) {
            const container = document.getElementById('toast-container');
            if (!container) return;
            const toast = document.createElement('div');
            toast.className = `px-4 py-2.5 rounded-xl border text-xs font-mono shadow-2xl flex items-center gap-2 transform transition-all duration-200 ${
                isError 
                    ? 'bg-rose-950 text-rose-200 border-rose-800' 
                    : 'bg-slate-900 text-cyan-300 border-cyan-800/80'
            }`;
            const iconSvg = isError
                ? '<svg class="w-4 h-4 text-rose-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
                : '<svg class="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
            toast.innerHTML = `<span class="flex-shrink-0">${iconSvg}</span> <span>${msg}</span>`;
            container.appendChild(toast);
            setTimeout(() => {
                toast.classList.add('opacity-0', 'translate-y-2');
                setTimeout(() => toast.remove(), 250);
            }, 2600);
        }

        function switchTab(tabId) {
            const tabs = ['contagion', 'mosca', 'cbom', 'buffer', 'supplychain', 'proof', 'unknowns', 'ciso'];
            tabs.forEach(t => {
                const btn = document.getElementById(`tab-btn-${t}`);
                const pane = document.getElementById(`tab-pane-${t}`);
                if (btn && pane) {
                    if (t === tabId) {
                        btn.classList.add('tab-active');
                        pane.classList.remove('hidden');
                    } else {
                        btn.classList.remove('tab-active');
                        pane.classList.add('hidden');
                    }
                }
            });
            if (tabId === 'mosca') renderGanttChart();
            if (tabId === 'supplychain') renderSupplyChainTable();
            if (tabId === 'unknowns') renderUnknownsTable();
            if (tabId === 'ciso') renderCisoMarkdown();
            setTimeout(triggerKaTeX, 60);
        }

        function copyRootHex() {
            navigator.clipboard.writeText(MERKLE_ROOT_HEX);
            showToast("Copied 32-byte Merkle root hex to clipboard!");
        }

        function exportCbomJson() {
            const blob = new Blob([JSON.stringify({
                bomFormat: "CycloneDX",
                specVersion: "1.6",
                assets: ASSETS_DATA,
                dependencies: DEPS_DATA,
                merkleRoot: MERKLE_ROOT_HEX
            }, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cbom_attested_${MERKLE_ROOT_HEX.slice(0, 8)}.json`;
            a.click();
            showToast("Exported CycloneDX 1.6 CBOM JSON!");
        }

        function exportCisoReportMd() {
            const blob = new Blob([CISO_MD_TEXT], { type: "text/markdown" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ciso_migration_report.md`;
            a.click();
            showToast("Downloaded CISO Migration Briefing (.md)!");
        }

        function copyCisoReportMarkdown() {
            navigator.clipboard.writeText(CISO_MD_TEXT);
            showToast("Copied CISO Markdown report to clipboard!");
        }

        function openAssetDrawer(assetId) {
            const asset = ASSETS_DATA.find(a => a.asset_id === assetId);
            if (!asset) return;
            currentDrawerAsset = asset;

            document.getElementById('drawer-asset-id').innerText = asset.asset_id;
            document.getElementById('drawer-title').innerText = `${asset.component} (${asset.algorithm})`;
            document.getElementById('drawer-file-path').innerText = `${asset.file_path} : line ${asset.line_number}`;
            document.getElementById('drawer-sink-call').innerText = asset.evidence || 'Direct Cryptographic Primitive Call';
            document.getElementById('drawer-tier').innerText = `${asset.x_tier} (${asset.x_years}y retention)`;
            document.getElementById('drawer-confidence').innerText = Number(asset.confidence || 1.0).toFixed(2);
            document.getElementById('drawer-pqc-target').innerText = asset.recommended_pqc || 'ML-KEM-768';
            document.getElementById('drawer-hybrid-target').innerText = asset.recommended_hybrid || 'Hybrid Pairing';
            document.getElementById('drawer-guidance').innerText = asset.guidance || 'Deploy NIST FIPS 203/204 standardized replacement.';

            const calcTerm = (asset.z_reg_year - 2026) - asset.x_years;
            document.getElementById('drawer-mosca-calc').innerHTML = `
                $$Y_{\\\\max} = (${asset.z_reg_year} - 2026) - ${asset.x_years} = ${calcTerm} \\\\implies \\\\mathbf{${asset.y_max_years}\\\\text{ years budget remaining}}$$
            `;

            const pill = document.getElementById('drawer-risk-pill');
            pill.innerText = `${asset.risk_level} RISK (Ymax: ${asset.y_max_years}y)`;
            pill.className = `text-xs px-3 py-1 rounded-full font-mono font-bold border ${
                asset.risk_level === 'CRITICAL' ? 'bg-red-950 text-red-300 border-red-800' :
                asset.risk_level === 'HIGH' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                asset.risk_level === 'MEDIUM' ? 'bg-yellow-950 text-yellow-300 border-yellow-800' :
                'bg-emerald-950 text-emerald-300 border-emerald-800'
            }`;

            const backdrop = document.getElementById('asset-drawer-backdrop');
            const drawer = document.getElementById('asset-drawer');
            backdrop.classList.remove('opacity-0', 'pointer-events-none');
            backdrop.classList.add('opacity-100');
            drawer.classList.remove('translate-x-full');

            setTimeout(triggerKaTeX, 40);
        }

        function closeAssetDrawer() {
            const backdrop = document.getElementById('asset-drawer-backdrop');
            const drawer = document.getElementById('asset-drawer');
            backdrop.classList.remove('opacity-100');
            backdrop.classList.add('opacity-0', 'pointer-events-none');
            drawer.classList.add('translate-x-full');
        }

        function copyDrawerAssetJson() {
            if (currentDrawerAsset) {
                navigator.clipboard.writeText(JSON.stringify(currentDrawerAsset, null, 2));
                showToast(`Copied JSON metadata for ${currentDrawerAsset.asset_id}!`);
            }
        }

        function renderCbomRows(assets) {
            const tbody = document.getElementById('cbom-table-body');
            if (!tbody) return;
            tbody.innerHTML = '';

            if (assets.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="p-8 text-center text-slate-500 font-mono">No cryptographic assets match the current filter criteria.</td></tr>`;
                return;
            }

            const evColors = {
                'E0_UNCONFIRMED': 'bg-slate-800 text-slate-400 border-slate-700',
                'E1_STATIC_ARTIFACT': 'bg-blue-950/80 text-blue-300 border-blue-800',
                'E2_REACHABLE_PATH': 'bg-cyan-950/80 text-cyan-300 border-cyan-800',
                'E3_CONFIG_CONFIRMED': 'bg-emerald-950/80 text-emerald-300 border-emerald-800',
                'E4_RUNTIME_OBSERVED': 'bg-purple-950/80 text-purple-300 border-purple-800',
                'E5_CORRELATED_SIGNED': 'bg-amber-950/80 text-amber-300 border-amber-800',
            };

            const intentBadges = {
                'OPERATIONAL_UTILITY': '<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-slate-800 text-slate-400 border border-slate-700" title="Operational Utility (ETag/Cache)">OP_UTIL</span>',
                'AUTHENTICATION_SIGNATURE': '<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-blue-950/80 text-blue-300 border border-blue-800" title="Authentication Signature">AUTH</span>',
                'INTEGRITY_CHECKSUM': '<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-teal-950/80 text-teal-300 border border-teal-800" title="Integrity Checksum">INTEG</span>',
                'CONFIDENTIALITY_ENVELOPE': '<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-950/80 text-purple-300 border border-purple-800" title="Confidentiality Envelope">CONF</span>',
            };

            assets.forEach(a => {
                const tr = document.createElement('tr');
                tr.className = "hover:bg-slate-900/70 transition-colors border-b border-slate-800/60";

                const evCode = a.evidence_level ? a.evidence_level.split('_')[0] : 'E1';
                const evClass = evColors[a.evidence_level] || 'bg-slate-800 text-slate-400 border-slate-700';
                const evBadge = `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold border ${evClass}" title="Evidence Level: ${a.evidence_level || 'E1'}">${evCode}</span>`;
                const intentBadge = intentBadges[a.intent_class] || intentBadges['CONFIDENTIALITY_ENVELOPE'];

                const riskBadge = a.intent_class === 'OPERATIONAL_UTILITY'
                    ? `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700 whitespace-nowrap">$R_Q = 0.0$ SUPPRESSED</span>`
                    : a.risk_level === 'CRITICAL'
                    ? `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-red-950/80 text-red-300 border border-red-800 whitespace-nowrap">$Y_{\\max} = ${a.y_max_years}\\text{y}$ CRITICAL</span>`
                    : a.risk_level === 'HIGH'
                    ? `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800 whitespace-nowrap">$Y_{\\max} = ${a.y_max_years}\\text{y}$ HIGH</span>`
                    : a.risk_level === 'MEDIUM'
                    ? `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-yellow-950/80 text-yellow-300 border border-yellow-800 whitespace-nowrap">$Y_{\\max} = ${a.y_max_years}\\text{y}$ MEDIUM</span>`
                    : `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800 whitespace-nowrap">$Y_{\\max} = ${a.y_max_years}\\text{y}$ LOW</span>`;

                tr.innerHTML = `
                    <td class="py-3 px-4">
                        <div class="flex items-center gap-1.5">
                            <span class="font-bold text-cyan-300">${a.asset_id}</span>
                            ${evBadge}
                            ${intentBadge}
                        </div>
                        <div class="text-[11px] text-slate-400 max-w-[160px] truncate" title="${a.component}">${a.component}</div>
                    </td>
                    <td class="py-3 px-4">
                        <span class="text-white font-semibold">${a.algorithm}</span>
                        <div class="text-[11px] text-slate-500">${a.primitive} (${a.key_size} bit)</div>
                    </td>
                    <td class="py-3 px-4 font-mono text-slate-300">
                        <div class="text-cyan-400 font-semibold max-w-[200px] truncate" title="${a.file_path}">${a.file_path}</div>
                        <div class="text-[10px] text-slate-500">line ${a.line_number}</div>
                    </td>
                    <td class="py-3 px-4">
                        <code class="text-[11px] bg-black/40 px-2 py-1 rounded text-amber-300 border border-slate-800/80 block max-w-[180px] truncate" title="${a.evidence}">${a.evidence}</code>
                    </td>
                    <td class="py-3 px-4 whitespace-nowrap">
                        <div class="text-slate-300">$X_{\\text{eff}} = ${a.x_years}\\text{y}$</div>
                        <div class="text-[10px] text-slate-500">${a.x_tier} &bull; $P_{\\text{HNDL}}: ${a.p_hndl !== undefined ? a.p_hndl : 1.0}$</div>
                    </td>
                    <td class="py-3 px-4">
                        ${riskBadge}
                    </td>
                    <td class="py-3 px-4 font-mono">
                        <div class="text-emerald-400 font-semibold max-w-[180px] truncate" title="${a.recommended_pqc}">${a.recommended_pqc}</div>
                        <div class="text-[10px] text-slate-500 max-w-[180px] truncate" title="${a.recommended_hybrid}">${a.recommended_hybrid}</div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <button onclick="openAssetDrawer('${a.asset_id}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-[11px] transition">
                            Inspect
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            setTimeout(triggerKaTeX, 40);
        }

        function toggleSuppressOperational() {
            suppressOperationalUtility = !suppressOperationalUtility;
            const btn = document.getElementById('btn-suppress-op');
            if (btn) {
                if (suppressOperationalUtility) {
                    btn.className = "px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 flex items-center gap-1.5 transition font-semibold ml-1";
                } else {
                    btn.className = "px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-cyan-300 flex items-center gap-1.5 transition ml-1";
                }
            }
            const query = (document.getElementById('cbom-search').value || '').toLowerCase();
            applyCbomFilterAndSearch(query);
            showToast(suppressOperationalUtility ? "Suppressed operational utility assets (ETags/Caches) from CBOM" : "Showing all assets including operational utility");
        }

        function updateOperationalSuppressionCount() {
            const opCount = ASSETS_DATA.filter(a => a.intent_class === 'OPERATIONAL_UTILITY').length;
            const counter = document.getElementById('suppress-op-count');
            if (counter) counter.innerText = opCount;
        }

        function renderUnknownsTable() {
            const tbody = document.getElementById('unknowns-table-body');
            if (!tbody) return;
            tbody.innerHTML = '';
            if (UNKNOWNS_DATA.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="p-8 text-center text-slate-500 font-mono">No scanning boundary unknowns or excluded files declared. Full perimeter audited.</td></tr>`;
                return;
            }
            UNKNOWNS_DATA.forEach(u => {
                const tr = document.createElement('tr');
                tr.className = "hover:bg-slate-900/70 transition-colors border-b border-slate-800/60";
                const catBadge = u.category === 'EXCLUDED_DIR'
                    ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">EXCLUDED_DIR</span>'
                    : u.category === 'UNINSPECTED_BINARY'
                    ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">UNINSPECTED_BINARY</span>'
                    : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-800">ENCRYPTED_KEYSTORE</span>';

                tr.innerHTML = `
                    <td class="py-3 px-4 font-mono text-cyan-400 max-w-[280px] truncate" title="${u.item_path}">${u.item_path}</td>
                    <td class="py-3 px-4">${catBadge}</td>
                    <td class="py-3 px-4 text-slate-300 text-xs">${u.reason}</td>
                    <td class="py-3 px-4 text-emerald-400 text-xs font-mono">${u.recommended_action}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        function filterCbomTable(severity) {
            activeCbomFilter = severity;
            ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(lvl => {
                const btn = document.getElementById(`filter-btn-${lvl}`);
                if (btn) {
                    if (lvl === severity) {
                        btn.className = "px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold transition";
                    } else {
                        btn.className = "px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200 transition";
                    }
                }
            });

            const query = (document.getElementById('cbom-search').value || '').toLowerCase();
            applyCbomFilterAndSearch(query);
        }

        function clearCbomFilter() {
            filterCbomTable('ALL');
        }

        function setCbomRiskFilter(severity) {
            filterCbomTable(severity);
        }

        function onCbomSearch(query) {
            applyCbomFilterAndSearch(query.toLowerCase());
        }

        function applyCbomFilterAndSearch(query) {
            const filtered = ASSETS_DATA.filter(a => {
                const matchSeverity = activeCbomFilter === 'ALL' || a.risk_level === activeCbomFilter;
                const matchSuppress = !suppressOperationalUtility || a.intent_class !== 'OPERATIONAL_UTILITY';
                const matchQuery = !query || 
                    a.asset_id.toLowerCase().includes(query) ||
                    a.component.toLowerCase().includes(query) ||
                    a.file_path.toLowerCase().includes(query) ||
                    a.algorithm.toLowerCase().includes(query) ||
                    (a.evidence && a.evidence.toLowerCase().includes(query)) ||
                    (a.intent_class && a.intent_class.toLowerCase().includes(query)) ||
                    (a.evidence_level && a.evidence_level.toLowerCase().includes(query)) ||
                    a.recommended_pqc.toLowerCase().includes(query);
                return matchSeverity && matchSuppress && matchQuery;
            });
            renderCbomRows(filtered);
        }

        function renderGanttChart() {
            const container = document.getElementById('gantt-chart-container');
            if (!container) return;
            container.innerHTML = '';

            const sorted = [...ASSETS_DATA].sort((a, b) => a.y_max_years - b.y_max_years);
            const totalYearsSpan = 14;

            sorted.forEach(a => {
                const xYears = Math.min(a.x_years, 14);
                const yMax = Math.max(0, a.y_max_years);

                const xPercent = (xYears / totalYearsSpan) * 100;
                const yMaxPercent = (yMax / totalYearsSpan) * 100;

                const row = document.createElement('div');
                row.className = "p-3 rounded-xl bg-slate-900/90 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition";
                row.onclick = () => openAssetDrawer(a.asset_id);

                row.innerHTML = `
                    <div class="flex items-center justify-between text-xs mb-2">
                        <div class="flex items-center gap-2 max-w-[70%]">
                            <span class="font-bold text-cyan-300 flex-shrink-0">${a.asset_id}</span>
                            <span class="text-slate-400 truncate">(${a.component} &bull; ${a.algorithm})</span>
                            <span class="text-[10px] text-slate-500 font-mono truncate hidden sm:inline">${a.file_path}:${a.line_number}</span>
                        </div>
                        <div class="flex items-center gap-3 flex-shrink-0">
                            <span class="text-slate-300">$X_{\\\\text{eff}} = ${a.x_years}\\\\text{y}$</span>
                            <span class="font-bold ${a.risk_level === 'CRITICAL' ? 'text-rose-400' : a.risk_level === 'HIGH' ? 'text-amber-400' : 'text-emerald-400'}">
                                $Y_{\\\\max} = ${a.y_max_years}\\\\text{y}$ (${a.risk_level})
                            </span>
                        </div>
                    </div>
                    <div class="w-full bg-slate-950 h-5 rounded-md relative flex items-center overflow-hidden border border-slate-800">
                        <div class="h-full bg-cyan-700/70 border-r border-cyan-400/50 flex items-center justify-center text-[10px] font-bold text-white" style="width: ${Math.max(4, xPercent)}%;">
                            ${xYears}y
                        </div>
                        <div class="h-full ${a.risk_level === 'CRITICAL' ? 'bg-red-800/80' : a.risk_level === 'HIGH' ? 'bg-amber-800/80' : 'bg-emerald-800/80'} border-r border-white/20 flex items-center justify-center text-[10px] font-bold text-white" style="width: ${Math.max(4, yMaxPercent)}%;">
                            ${yMax}y budget
                        </div>
                        <div class="absolute left-[28.5%] top-0 bottom-0 w-[1px] bg-amber-400/60" title="2030 OMB M-26-15"></div>
                        <div class="absolute left-[50%] top-0 bottom-0 w-[1px] bg-rose-400/60" title="2033 GRI CRQC Arrival"></div>
                        <div class="absolute left-[64.2%] top-0 bottom-0 w-[1px] bg-purple-400/60" title="2035 NIST Deprecation"></div>
                    </div>
                `;
                container.appendChild(row);
            });

            setTimeout(triggerKaTeX, 40);
        }

        function initHazardsTable() {
            const cardsContainer = document.getElementById('buffer-remediation-cards');
            const tbody = document.getElementById('hazards-table-body');
            if (!tbody) return;
            tbody.innerHTML = '';

            if (HAZARDS_DATA.length === 0) {
                if (cardsContainer) {
                    cardsContainer.innerHTML = `
                        <div class="p-6 rounded-2xl glass-panel border border-emerald-800/40 bg-slate-900/60 space-y-4">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center gap-3">
                                    <span class="w-8 h-8 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400 flex items-center justify-center">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                                    </span>
                                    <div>
                                        <h4 class="text-sm font-bold text-emerald-300 font-mono">Full Buffer Agility Confirmed &bull; Zero Memory Deficits</h4>
                                        <p class="text-xs text-slate-400 mt-0.5">No hardcoded fixed allocations (e.g. 64B ECDSA or 256B RSA bytearrays) detected in cryptographic call sites.</p>
                                    </div>
                                </div>
                                <span class="text-[10px] px-2.5 py-1 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-300 font-mono font-bold">
                                    0 HAZARDS DETECTED
                                </span>
                            </div>
                            <div class="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-2">
                                <div class="text-slate-400 text-[11px]">Recommended Cryptographic Agility Pattern for Post-Quantum Migration:</div>
                                <div class="text-slate-500"># Use dynamically sized byte containers or runtime length queries rather than fixed-length bytearrays</div>
                                <div class="text-cyan-300">sig_buffer = bytearray(crypto_provider.get_signature_size()) <span class="text-slate-500"># Dynamically expands to 3,309 B for ML-DSA-65</span></div>
                            </div>
                        </div>
                    `;
                }
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="p-8 text-center text-slate-400 font-mono">
                            <div class="text-emerald-400 font-bold mb-1 flex items-center justify-center gap-1.5">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                                <span>Full Memory Agility Confirmed</span>
                            </div>
                            <div class="text-xs text-slate-500">All cryptographic operations in this estate use dynamic buffers or high-level library abstractions. No fixed buffer truncation risks found.</div>
                        </td>
                    </tr>
                `;
                return;
            }

            if (cardsContainer) {
                let diffHtml = '';
                HAZARDS_DATA.forEach(h => {
                    const deficit = h.required - h.allocated;
                    const pct = Math.round((deficit / h.allocated) * 100);
                    diffHtml += `
                        <div class="glass-panel rounded-2xl p-5 border border-slate-800 space-y-3">
                            <div class="flex items-center justify-between">
                                <span class="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                                    Remediation Diff &bull; <span class="text-cyan-300">${h.file}</span> (Line ${h.line})
                                </span>
                                <span class="text-[11px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono">
                                    ${h.severity} DEFICIT (+${deficit} B / +${pct}%)
                                </span>
                            </div>
                            <div class="rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs overflow-hidden shadow-inner">
                                <div class="p-2.5 bg-slate-900/90 border-b border-slate-800 text-[11px] text-slate-400 flex justify-between items-center">
                                    <span>--- a/${h.file} (Classical Fixed Buffer: ${h.allocated} Bytes)</span>
                                    <span>+++ b/${h.file} (NIST FIPS 204 ML-DSA Buffer: ${h.required} Bytes)</span>
                                </div>
                                <div class="p-4 space-y-1 font-mono text-xs">
                                    <div class="text-slate-500">@@ -${Math.max(1, h.line - 1)},2 +${Math.max(1, h.line - 1)},3 @@</div>
                                    <div class="text-slate-400"># Variable: ${h.variable} at line ${h.line}</div>
                                    <div class="diff-removed px-2 py-1 rounded font-bold">-    ${h.variable} = bytearray(${h.allocated})  # Fixed classical buffer too small for PQC</div>
                                    <div class="diff-added px-2 py-1 rounded font-bold">+    # ECDAT Mitigation: Allocate minimum ${h.required} B for NIST FIPS 204 ML-DSA-65</div>
                                    <div class="diff-added px-2 py-1 rounded font-bold">+    ${h.variable} = bytearray(${h.required})</div>
                                </div>
                            </div>
                        </div>
                    `;
                });
                cardsContainer.innerHTML = diffHtml;
            }

            HAZARDS_DATA.forEach(h => {
                const tr = document.createElement('tr');
                tr.className = "hover:bg-slate-900/60 transition border-b border-slate-800/60";
                const deficit = h.required - h.allocated;
                tr.innerHTML = `
                    <td class="py-3 px-4 font-bold text-rose-400">${h.variable}</td>
                    <td class="py-3 px-4 text-slate-300 font-semibold max-w-[240px] truncate" title="${h.file_path}">${h.file_path} : line ${h.line}</td>
                    <td class="py-3 px-4 text-slate-400">${h.allocated} Bytes</td>
                    <td class="py-3 px-4 text-emerald-400 font-bold">${h.required} Bytes (ML-DSA-65)</td>
                    <td class="py-3 px-4 text-rose-300 font-bold">+${deficit} B deficit (+${Math.round(deficit / h.allocated * 100)}%)</td>
                    <td class="py-3 px-4">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-800">${h.severity}</span>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }

        function renderSupplyChainTable() {
            const tbody = document.getElementById('supplychain-table-body');
            if (!tbody) return;
            tbody.innerHTML = '';
            if (!DEPS_DATA || DEPS_DATA.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-500">No third-party cryptographic package dependencies detected in manifests.</td></tr>`;
                return;
            }
            DEPS_DATA.forEach(d => {
                const tr = document.createElement('tr');
                tr.className = "hover:bg-slate-900/60 transition border-b border-slate-800/60";
                const postureBadge = d.pqc_readiness === 'MIGRATED_PQC'
                    ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">MIGRATED PQC</span>`
                    : d.pqc_readiness === 'VULNERABLE_CLASSICAL'
                    ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-800">VULNERABLE CLASSICAL</span>`
                    : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">SAFE / SYMMETRIC</span>`;

                tr.innerHTML = `
                    <td class="py-3 px-4 font-bold text-white">${d.package_name}</td>
                    <td class="py-3 px-4 text-cyan-400 uppercase font-semibold">${d.ecosystem}</td>
                    <td class="py-3 px-4 text-slate-300">${d.version}</td>
                    <td class="py-3 px-4 text-slate-400 max-w-[180px] truncate" title="${d.manifest_path}">${d.manifest_path}</td>
                    <td class="py-3 px-4 text-slate-300">${d.category}</td>
                    <td class="py-3 px-4">${postureBadge}</td>
                    <td class="py-3 px-4 text-[11px] text-slate-300 max-w-[280px] truncate" title="${d.recommendation}">${d.recommendation}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        function initProofSelector() {
            const select = document.getElementById('proof-asset-select');
            if (!select) return;
            select.innerHTML = '';
            PROOFS_DATA.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.asset_id;
                const compName = p.component_name || (p.sanitized_asset && p.sanitized_asset.component_name) || "asset";
                const alg = p.algorithm || (p.sanitized_asset && p.sanitized_asset.algorithm) || "CRYPTO";
                opt.innerText = `${p.asset_id} - ${compName} (${alg})`;
                select.appendChild(opt);
            });
            if (PROOFS_DATA.length > 0) {
                select.value = PROOFS_DATA[0].asset_id;
                runClientSideProofVerification(false);
            }
        }

        function onSelectProofPackage(assetId) {
            runClientSideProofVerification(false);
        }

        function hexToBytes(hex) {
            const clean = (hex || "").trim();
            const bytes = new Uint8Array(clean.length / 2);
            for (let i = 0; i < clean.length; i += 2) {
                bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
            }
            return bytes;
        }

        function bytesToHex(bytes) {
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function hashRawBytes(u8array) {
            const hashBuffer = await crypto.subtle.digest('SHA-256', u8array);
            return bytesToHex(new Uint8Array(hashBuffer));
        }

        async function hashNodePair(leftHex, rightHex) {
            const left = hexToBytes(leftHex);
            const right = hexToBytes(rightHex);
            const combined = new Uint8Array(64);
            combined.set(left, 0);
            combined.set(right, 32);
            return await hashRawBytes(combined);
        }

        async function runClientSideProofVerification(simulateTamper = false) {
            const assetId = document.getElementById('proof-asset-select').value;
            const pkg = PROOFS_DATA.find(p => p.asset_id === assetId);
            const stepsContainer = document.getElementById('proof-steps-container');
            const statusTag = document.getElementById('proof-status-tag');

            if (!pkg) return;

            statusTag.innerText = "VERIFYING...";
            statusTag.className = "text-xs px-3 py-1 rounded-full font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 animate-pulse";

            try {
                const baseHash = pkg.leaf_hash || "00".repeat(32);
                let currentHash = simulateTamper ? ("deadbeef" + baseHash.slice(8)) : baseHash;

                let stepsHtml = `
                    <div class="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                        <div class="flex justify-between items-center">
                            <span class="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">1. Selective Disclosure Leaf Commitment</span>
                            <span class="text-[10px] font-mono text-slate-400">${pkg.algorithm} &bull; ${pkg.x_tier} &bull; ${pkg.risk_level}</span>
                        </div>
                        <div class="text-slate-400 text-[11px] font-mono truncate">Canonical: id:${pkg.asset_id} | comp:${pkg.component_name} | alg:${pkg.algorithm}</div>
                        <div class="text-emerald-400 font-bold break-all font-mono text-xs">${currentHash}</div>
                        ${simulateTamper ? '<div class="text-rose-400 text-[10px] font-mono font-bold flex items-center gap-1.5"><svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><span>SIMULATED LEAF TAMPER INJECTED (Hash altered to 0xdeadbeef...)</span></div>' : ''}
                    </div>
                `;

                const pathList = pkg.sibling_path || pkg.authentication_path || [];
                let stepIdx = 2;
                for (const step of pathList) {
                    const sibling = step.hash || step.sibling_hash;
                    const pos = (step.position || step.direction || 'right').toLowerCase();
                    const leftHex = pos === 'left' ? sibling : currentHash;
                    const rightHex = pos === 'left' ? currentHash : sibling;
                    currentHash = await hashNodePair(leftHex, rightHex);

                    stepsHtml += `
                        <div class="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                            <div class="flex justify-between items-center">
                                <span class="text-[10px] text-slate-400 font-bold uppercase tracking-wider">${stepIdx}. Authentication Ladder Node</span>
                                <span class="text-[10px] font-mono text-cyan-400">Sibling (${pos})</span>
                            </div>
                            <div class="text-slate-500 text-[10px] font-mono truncate">Sibling: ${sibling}</div>
                            <div class="text-cyan-300 font-bold break-all font-mono text-xs">${currentHash}</div>
                        </div>
                    `;
                    stepIdx++;
                }

                const expectedRoot = pkg.expected_root || MERKLE_ROOT_HEX;
                const isValid = currentHash.toLowerCase() === expectedRoot.toLowerCase();

                if (isValid) {
                    statusTag.innerText = "VERIFIED (VALID PROOF)";
                    statusTag.className = "text-xs px-3 py-1 rounded-full font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 shadow-lg shadow-emerald-950/50";
                    stepsHtml += `
                        <div class="p-4 bg-emerald-950/40 rounded-xl border border-emerald-800 text-emerald-300 font-mono text-xs space-y-1">
                            <div class="font-bold flex items-center gap-2">
                                <span class="text-emerald-400 flex-shrink-0"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg></span>
                                <span>MATHEMATICAL ATTESTATION SUCCESS</span>
                            </div>
                            <div class="text-slate-300 text-[11px] leading-relaxed">
                                Computed root matches committed Merkle root <span class="text-emerald-300 font-bold break-all">0x${expectedRoot}</span>. Zero-knowledge selective disclosure confirmed: this cryptographic asset is mathematically proven to exist in the published inventory without exposing internal source paths or key material.
                            </div>
                        </div>
                    `;
                } else {
                    statusTag.innerText = "TAMPERED / INVALID";
                    statusTag.className = "text-xs px-3 py-1 rounded-full font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800 shadow-lg shadow-rose-950/50";
                    stepsHtml += `
                        <div class="p-4 bg-rose-950/40 rounded-xl border border-rose-800 text-rose-300 font-mono text-xs space-y-1">
                            <div class="font-bold flex items-center gap-2">
                                <span class="text-rose-400 flex-shrink-0"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg></span>
                                <span>TAMPER DETECTED: CRYPTOGRAPHIC PROOF REJECTED</span>
                            </div>
                            <div class="text-slate-300 text-[11px] leading-relaxed">
                                Computed root (<span class="text-rose-400 break-all font-bold">0x${currentHash}</span>) does not match committed root (<span class="text-cyan-300 break-all font-bold">0x${expectedRoot}</span>). The audit trail has detected altered leaf properties or invalid sibling authentication steps.
                            </div>
                        </div>
                    `;
                }

                stepsContainer.innerHTML = stepsHtml;

            } catch (err) {
                statusTag.innerText = "PARSING ERROR";
                statusTag.className = "text-xs px-3 py-1 rounded-full font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800";
                stepsContainer.innerHTML = `<div class="p-4 bg-red-950/40 rounded-xl border border-red-800 text-red-300 font-mono text-xs">Error: ${err.message}</div>`;
            }
        }

        // ==========================================================
        // DEDICATED CONTAGION GRAPH MANAGEMENT ENGINE
        // ==========================================================
        class ContagionGraphEngine {
            constructor() {
                this.simulation = null;
                this.svg = null;
                this.svgGroup = null;
                this.zoom = null;
                this.nodes = [];
                this.links = [];
                this.width = 1000;
                this.height = 560;
                this.neighborMap = new Map();
                this.nodeElements = null;
                this.linkElements = null;
                this.labelElements = null;
                this.labelMode = 'smart'; // 'smart' | 'hubs' | 'all'
            }

            init() {
                this.svg = d3.select("#contagion-svg");
                if (!this.svg.node()) return;
                const container = document.getElementById('contagion-svg');
                this.width = (container && container.clientWidth) ? container.clientWidth : 1000;
                this.height = 560;

                this.svg.selectAll("*").remove();

                this.zoom = d3.zoom()
                    .scaleExtent([0.2, 3.5])
                    .on("zoom", (e) => {
                        if (this.svgGroup) {
                            this.svgGroup.attr("transform", e.transform);
                        }
                    });
                this.svg.call(this.zoom);

                this.svgGroup = this.svg.append("g");

                const defs = this.svg.append("defs");
                const pattern = defs.append("pattern")
                    .attr("id", "dot-grid")
                    .attr("width", 24)
                    .attr("height", 24)
                    .attr("patternUnits", "userSpaceOnUse");
                pattern.append("circle")
                    .attr("cx", 2)
                    .attr("cy", 2)
                    .attr("r", 1)
                    .attr("fill", "rgba(255, 255, 255, 0.08)");

                defs.append("marker")
                    .attr("id", "arrowhead")
                    .attr("viewBox", "0 -5 10 10")
                    .attr("refX", 22)
                    .attr("refY", 0)
                    .attr("markerWidth", 6)
                    .attr("markerHeight", 6)
                    .attr("orient", "auto")
                    .append("path")
                    .attr("d", "M0,-4L8,0L0,4")
                    .attr("fill", "rgba(56, 189, 248, 0.75)");

                this.svgGroup.append("rect")
                    .attr("width", this.width * 4)
                    .attr("height", this.height * 4)
                    .attr("x", -this.width * 1.5)
                    .attr("y", -this.height * 1.5)
                    .attr("fill", "url(#dot-grid)");

                if (!GRAPH_DATA || !GRAPH_DATA.nodes || GRAPH_DATA.nodes.length === 0) {
                    this.svgGroup.append("text")
                        .attr("x", this.width / 2)
                        .attr("y", this.height / 2 - 12)
                        .attr("text-anchor", "middle")
                        .attr("fill", "#94a3b8")
                        .attr("font-family", "JetBrains Mono")
                        .attr("font-size", "14px")
                        .attr("font-weight", "bold")
                        .text("Isolated Cryptographic Estate");
                    this.svgGroup.append("text")
                        .attr("x", this.width / 2)
                        .attr("y", this.height / 2 + 14)
                        .attr("text-anchor", "middle")
                        .attr("fill", "#64748b")
                        .attr("font-family", "JetBrains Mono")
                        .attr("font-size", "11px")
                        .text("No inter-service infection propagation paths detected.");
                    return;
                }

                this.nodes = GRAPH_DATA.nodes.map(d => ({ ...d }));
                this.links = GRAPH_DATA.links.map(d => ({ ...d }));

                // 1. Calculate degrees and build neighbor map
                const degrees = {};
                this.nodes.forEach(n => {
                    degrees[n.id] = 0;
                    this.neighborMap.set(n.id, new Set([n.id]));
                });
                this.links.forEach(l => {
                    const s = typeof l.source === 'object' ? l.source.id : l.source;
                    const t = typeof l.target === 'object' ? l.target.id : l.target;
                    degrees[s] = (degrees[s] || 0) + 1;
                    degrees[t] = (degrees[t] || 0) + 1;
                    if (this.neighborMap.has(s)) this.neighborMap.get(s).add(t);
                    if (this.neighborMap.has(t)) this.neighborMap.get(t).add(s);
                });
                this.nodes.forEach(n => {
                    n.degree = degrees[n.id] || 0;
                });

                // Update stats counter in legend
                const statsElem = document.getElementById('graph-stats');
                if (statsElem) {
                    const spCount = this.nodes.filter(n => n.is_superspreader).length;
                    statsElem.innerText = `${this.nodes.length} nodes \u2022 ${this.links.length} links \u2022 ${spCount} superspreaders`;
                }

                // 2. Deterministic expansive multi-orbit initialization centered at canvas center
                const cx = this.width / 2;
                const cy = this.height / 2;
                this.nodes.forEach((n, i) => {
                    let orbitR = 240;
                    if (n.is_superspreader) {
                        orbitR = 100 + (i % 3) * 50;
                    } else if (n.is_pqc_anchor || n.has_crypto) {
                        orbitR = 230 + (i % 5) * 45;
                    } else if (n.degree === 0) {
                        orbitR = 430 + (i % 8) * 35;
                    } else {
                        orbitR = 320 + (i % 6) * 40;
                    }
                    const angle = i * 2.39996; // Golden angle (~137.5 deg)
                    n.x = cx + orbitR * Math.cos(angle);
                    n.y = cy + orbitR * Math.sin(angle);
                });

                // 3. Expansive, anti-clumping physics simulation
                // Decreased link stiffness (0.18) & elongated distance (160-220px)
                // Strong wide-area repulsion (-420 to -650) to prevent inward attraction
                // Minimal center drift (0.012) and broad collision buffer (r + 42)
                this.simulation = d3.forceSimulation(this.nodes)
                    .alphaDecay(0.028)
                    .velocityDecay(0.38)
                    .force("link", d3.forceLink(this.links).id(d => d.id).distance(d => {
                        const sSp = d.source && d.source.is_superspreader;
                        const tSp = d.target && d.target.is_superspreader;
                        return (sSp || tSp) ? 220 : 160;
                    }).strength(0.18))
                    .force("charge", d3.forceManyBody().strength(d => d.is_superspreader ? -650 : -420).distanceMax(750).distanceMin(25))
                    .force("x", d3.forceX(cx).strength(d => (d.degree === 0 ? 0.025 : 0.012)))
                    .force("y", d3.forceY(cy).strength(d => (d.degree === 0 ? 0.025 : 0.012)))
                    .force("collision", d3.forceCollide().radius(d => {
                        const r = this.getNodeRadius(d);
                        return r + 42;
                    }).iterations(4));

                // 4. Render links
                this.linkElements = this.svgGroup.append("g")
                    .attr("stroke", "rgba(56, 189, 248, 0.35)")
                    .attr("stroke-width", 1.5)
                    .selectAll("line")
                    .data(this.links)
                    .join("line")
                    .attr("marker-end", "url(#arrowhead)");

                // 5. Render nodes
                this.nodeElements = this.svgGroup.append("g")
                    .selectAll("g")
                    .data(this.nodes)
                    .join("g")
                    .call(d3.drag()
                        .on("start", (event, d) => this.dragstarted(event, d))
                        .on("drag", (event, d) => this.dragged(event, d))
                        .on("end", (event, d) => this.dragended(event, d)))
                    .on("click", (e, d) => {
                        if (d.asset_id) openAssetDrawer(d.asset_id);
                    })
                    .on("mouseenter", (e, d) => this.highlightNeighbors(d))
                    .on("mouseleave", () => this.clearHighlights());

                // Radar pulse for superspreaders
                this.nodeElements.filter(d => d.is_superspreader)
                    .append("circle")
                    .attr("class", "radar-pulse")
                    .attr("fill", "none")
                    .attr("stroke", "#ef4444")
                    .attr("stroke-width", 2);

                // Dashed ring for PQC anchors
                this.nodeElements.filter(d => d.is_pqc_anchor)
                    .append("circle")
                    .attr("r", 24)
                    .attr("fill", "none")
                    .attr("stroke", "#10b981")
                    .attr("stroke-width", 1.5)
                    .attr("stroke-dasharray", "3,2");

                // Base node circle with accurate engine color
                this.nodeElements.append("circle")
                    .attr("r", d => this.getNodeRadius(d))
                    .attr("fill", d => this.getNodeColor(d))
                    .attr("stroke", d => {
                        if (d.is_superspreader) return "#fca5a5";
                        if (d.is_pqc_anchor) return "#6ee7b7";
                        return "rgba(255, 255, 255, 0.45)";
                    })
                    .attr("stroke-width", d => d.is_superspreader ? 2.5 : 1.5);

                // Centered text labels beneath node circle with dark outline halo to prevent collision
                this.labelElements = this.nodeElements.append("text")
                    .attr("class", "graph-node-label")
                    .text(d => this.formatLabel(d, false))
                    .attr("text-anchor", "middle")
                    .attr("x", 0)
                    .attr("y", d => this.getNodeRadius(d) + 14)
                    .attr("fill", "#cbd5e1")
                    .attr("font-size", "10px")
                    .attr("font-family", "JetBrains Mono, monospace")
                    .style("paint-order", "stroke fill")
                    .style("stroke", "#030712")
                    .style("stroke-width", "3.5px")
                    .style("stroke-linejoin", "round")
                    .style("pointer-events", "none");

                // Tooltip title
                this.nodeElements.append("title")
                    .text(d => {
                        const r0 = d.r0 || 0;
                        const role = d.is_superspreader ? 'Superspreader (R0 >= 2)' : (d.is_pqc_anchor ? 'PQC Immunization Anchor' : (d.group || d.type || 'module'));
                        return `${d.id}\nRole: ${role}\nR0 Blast Radius: ${r0}\nImpact: ${d.impact || 'N/A'}`;
                    });

                // Apply initial label density mode
                this.applyLabelMode();

                // Simulation tick
                this.simulation.on("tick", () => {
                    this.linkElements
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);

                    this.nodeElements
                        .attr("transform", d => `translate(${d.x},${d.y})`);
                });

                // Initial fit to view after simulation relaxes slightly
                setTimeout(() => {
                    this.fitToView();
                }, 450);
            }

            formatLabel(d, isExpanded = false) {
                let text = d.label || d.id || '';
                // If it's a file path, extract the basename for clean display
                if (text.includes('/')) {
                    const segments = text.split('/');
                    text = segments[segments.length - 1];
                }
                if (isExpanded) return text;
                return text.length > 14 ? text.slice(0, 13) + '…' : text;
            }

            applyLabelMode() {
                if (!this.labelElements) return;
                const mode = this.labelMode;
                this.labelElements.style("display", d => {
                    if (mode === 'all') return "block";
                    if (mode === 'hubs') {
                        return (d.is_superspreader || d.is_pqc_anchor || (d.r0 && d.r0 > 0)) ? "block" : "none";
                    }
                    // 'smart' mode: show superspreaders, anchors, crypto nodes, or multi-degree nodes
                    return (d.is_superspreader || d.is_pqc_anchor || d.has_crypto || d.degree >= 2) ? "block" : "none";
                });

                const modeBtnText = document.getElementById('label-mode-text');
                if (modeBtnText) {
                    if (mode === 'smart') modeBtnText.innerText = "Labels: Smart";
                    else if (mode === 'hubs') modeBtnText.innerText = "Labels: Hubs Only";
                    else if (mode === 'all') modeBtnText.innerText = "Labels: All";
                }
            }

            cycleLabelMode() {
                if (this.labelMode === 'smart') this.labelMode = 'hubs';
                else if (this.labelMode === 'hubs') this.labelMode = 'all';
                else this.labelMode = 'smart';
                this.applyLabelMode();
            }

            getNodeColor(d) {
                if (d.color) return d.color;
                if (d.is_superspreader) return "#ef4444";
                if (d.is_pqc_anchor) return "#10b981";
                if (d.group === "safe_symmetric") return "#06b6d4";
                if (d.has_crypto) return "#f97316";
                if (d.r0 > 0 || d.group === "intermediary") return "#3b82f6";
                return "#64748b";
            }

            getNodeRadius(d) {
                if (d.radius) return d.radius;
                if (d.is_superspreader) return 22;
                if (d.is_pqc_anchor) return 18;
                if (d.has_crypto) return 15;
                if (d.r0 > 0) return 13;
                return 9;
            }

            highlightNeighbors(targetNode) {
                const neighbors = this.neighborMap.get(targetNode.id) || new Set([targetNode.id]);
                if (this.nodeElements) {
                    this.nodeElements.transition().duration(120)
                        .style("opacity", n => neighbors.has(n.id) ? 1.0 : 0.12);
                }
                if (this.linkElements) {
                    this.linkElements.transition().duration(120)
                        .style("opacity", l => {
                            const s = typeof l.source === 'object' ? l.source.id : l.source;
                            const t = typeof l.target === 'object' ? l.target.id : l.target;
                            return (s === targetNode.id || t === targetNode.id) ? 1.0 : 0.08;
                        })
                        .attr("stroke", l => {
                            const s = typeof l.source === 'object' ? l.source.id : l.source;
                            const t = typeof l.target === 'object' ? l.target.id : l.target;
                            return (s === targetNode.id || t === targetNode.id) ? "#38bdf8" : "rgba(56, 189, 248, 0.25)";
                        })
                        .attr("stroke-width", l => {
                            const s = typeof l.source === 'object' ? l.source.id : l.source;
                            const t = typeof l.target === 'object' ? l.target.id : l.target;
                            return (s === targetNode.id || t === targetNode.id) ? 2.5 : 1.2;
                        });
                }
                // Dynamically expand labels for hovered node and direct neighbors with bright highlight
                if (this.labelElements) {
                    const self = this;
                    this.labelElements.each(function(d) {
                        const elem = d3.select(this);
                        if (d.id === targetNode.id) {
                            elem.style("display", "block")
                                .style("opacity", 1.0)
                                .attr("fill", "#ffffff")
                                .attr("font-size", "12px")
                                .attr("font-weight", "bold")
                                .text(self.formatLabel(d, true));
                        } else if (neighbors.has(d.id)) {
                            elem.style("display", "block")
                                .style("opacity", 1.0)
                                .attr("fill", "#38bdf8")
                                .attr("font-size", "11px")
                                .attr("font-weight", "600")
                                .text(self.formatLabel(d, true));
                        } else {
                            elem.style("opacity", 0.08);
                        }
                    });
                }
            }

            clearHighlights() {
                if (this.nodeElements) {
                    this.nodeElements.transition().duration(150).style("opacity", 1.0);
                }
                if (this.linkElements) {
                    this.linkElements.transition().duration(150)
                        .style("opacity", 0.6)
                        .attr("stroke", "rgba(56, 189, 248, 0.35)")
                        .attr("stroke-width", 1.5);
                }
                // Restore default truncated labels and active mode visibility
                if (this.labelElements) {
                    const self = this;
                    this.labelElements
                        .style("opacity", 1.0)
                        .attr("fill", "#cbd5e1")
                        .attr("font-size", "10px")
                        .attr("font-weight", "normal")
                        .text(d => self.formatLabel(d, false));
                    this.applyLabelMode();
                }
            }

            dragstarted(event, d) {
                if (!event.active && this.simulation) this.simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            dragended(event, d) {
                if (!event.active && this.simulation) this.simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            fitToView() {
                if (!this.nodes || this.nodes.length === 0 || !this.svg || !this.svgGroup || !this.zoom) return;
                let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
                this.nodes.forEach(d => {
                    const x = d.x || this.width / 2;
                    const y = d.y || this.height / 2;
                    if (x < minX) minX = x;
                    if (x > maxX) maxX = x;
                    if (y < minY) minY = y;
                    if (y > maxY) maxY = y;
                });
                const dx = maxX - minX || 100;
                const dy = maxY - minY || 100;
                const x = (minX + maxX) / 2;
                const y = (minY + maxY) / 2;
                const padding = 70;
                const scale = Math.max(0.25, Math.min(1.5, 0.88 / Math.max((dx + padding) / this.width, (dy + padding) / this.height)));
                const translate = [this.width / 2 - scale * x, this.height / 2 - scale * y];
                this.svg.transition().duration(650).call(
                    this.zoom.transform,
                    d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
                );
            }

            zoomIn() {
                if (this.svg && this.zoom) {
                    this.svg.transition().duration(250).call(this.zoom.scaleBy, 1.3);
                }
            }

            zoomOut() {
                if (this.svg && this.zoom) {
                    this.svg.transition().duration(250).call(this.zoom.scaleBy, 0.7);
                }
            }

            filterNodes(query) {
                const q = query.toLowerCase().trim();
                if (!this.nodeElements) return;
                this.nodeElements.each(function(d) {
                    if (!d) return;
                    const match = !q || (d.id && d.id.toLowerCase().includes(q)) || (d.label && d.label.toLowerCase().includes(q));
                    d3.select(this).style("opacity", match ? 1.0 : 0.12);
                });
            }
        }

        const graphManager = new ContagionGraphEngine();

        function initContagionGraph() {
            graphManager.init();
        }

        function toggleGraphLabels() {
            graphManager.cycleLabelMode();
        }

        function zoomGraphIn() {
            graphManager.zoomIn();
        }

        function zoomGraphOut() {
            graphManager.zoomOut();
        }

        function fitGraphToView() {
            graphManager.fitToView();
        }

        function resetGraphZoom() {
            graphManager.fitToView();
        }

        function filterGraphNodes(query) {
            graphManager.filterNodes(query);
        }

        function renderCisoMarkdown() {
            const preview = document.getElementById('ciso-markdown-preview');
            if (!preview) return;
            if (window.marked && typeof window.marked.parse === 'function') {
                preview.innerHTML = marked.parse(CISO_MD_TEXT);
            } else {
                preview.innerText = CISO_MD_TEXT;
            }
            setTimeout(triggerKaTeX, 50);
        }

        window.addEventListener('keydown', (e) => {
            if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
                e.preventDefault();
                switchTab('cbom');
                const search = document.getElementById('cbom-search');
                if (search) search.focus();
            } else if (e.key === 'Escape') {
                closeAssetDrawer();
            }
        });

        window.addEventListener('DOMContentLoaded', () => {
            try { initContagionGraph(); } catch (e) { console.error("Error in graph:", e); }
            try { initProofSelector(); } catch (e) { console.error("Error in proof selector:", e); }
            try { initHazardsTable(); } catch (e) { console.error("Error in hazards table:", e); }
            try { renderSupplyChainTable(); } catch (e) { console.error("Error in supply chain:", e); }
            try { renderCbomRows(ASSETS_DATA); } catch (e) { console.error("Error in CBOM rows:", e); }
            try { updateOperationalSuppressionCount(); } catch (e) {}
            try { renderUnknownsTable(); } catch (e) {}
            try { triggerKaTeX(); } catch (e) {}
            setTimeout(triggerKaTeX, 350);
            setTimeout(triggerKaTeX, 1200);
        });
    </script>
</body>
</html>
"""

def generate_html_dashboard(
    assessments: List[Tuple[CryptoAsset, MoscaScore, MigrationRecommendation]],
    buffer_hazards: List[BufferHazard],
    merkle_root_hex: str,
    contagion_result: ContagionGraphResult,
    proof_packages: List[Dict[str, Any]],
    project_name: str = "Enterprise Cryptographic Estate",
    ciso_report_md: Optional[str] = None,
    manifest_dependencies: Optional[List[Any]] = None,
    unknowns_ledger: Optional[List[Any]] = None,
) -> str:
    """
    Generates a single, self-contained HTML5 report ('report.html') featuring KaTeX LaTeX rendering,
    hub-and-spoke file traceability, defense-grade UI aesthetics, marked.js CISO tables,
    and third-party dependency supply chain auditing.
    """
    total_assets = len(assessments)
    critical_count = sum(1 for _, s, _ in assessments if s.risk_level == "CRITICAL")
    high_count = sum(1 for _, s, _ in assessments if s.risk_level == "HIGH")
    medium_count = sum(1 for _, s, _ in assessments if s.risk_level == "MEDIUM")
    low_count = sum(1 for _, s, _ in assessments if s.risk_level == "LOW")
    superspreader_count = len(contagion_result.superspreaders)

    penalty = (critical_count * 12) + (high_count * 6) + (len(buffer_hazards) * 8)
    readiness_score = max(5, min(100, 100 - penalty))

    assets_data = []
    for asset, score, rec in assessments:
        evidence = (
            asset.raw_properties.get("sink")
            or asset.raw_properties.get("evidence")
            or asset.raw_properties.get("subject")
            or "Direct Cryptographic Material"
        )
        assets_data.append({
            "asset_id": asset.asset_id,
            "component": asset.component_name,
            "file_path": asset.file_path,
            "line_number": asset.line_number,
            "algorithm": asset.algorithm,
            "key_size": asset.key_size,
            "primitive": asset.primitive_type.value,
            "x_tier": asset.x_tier.value,
            "x_years": score.x_years_effective,
            "z_reg_year": score.z_regulatory_year,
            "y_max_years": score.y_max_years,
            "risk_level": score.risk_level,
            "hndl_vulnerable": score.x_years_effective > 0,
            "recommended_hybrid": rec.recommended_hybrid,
            "recommended_pqc": rec.recommended_pqc_standalone,
            "target_standard": rec.target_standard,
            "security_level": rec.security_level,
            "confidence": asset.x_confidence,
            "evidence": evidence,
            "guidance": rec.implementation_guidance,
            "raw_properties": asset.raw_properties,
            "intent_class": asset.intent_class.value if hasattr(asset.intent_class, "value") else str(asset.intent_class),
            "evidence_level": asset.evidence_level.value if hasattr(asset.evidence_level, "value") else str(asset.evidence_level),
            "agility_level": asset.agility_level.value if hasattr(asset.agility_level, "value") else int(asset.agility_level),
            "exposure_profile": asset.exposure_profile.value if hasattr(asset.exposure_profile, "value") else str(asset.exposure_profile),
            "p_hndl": getattr(score, "p_hndl", 1.0),
            "r_q_score": getattr(score, "r_q_score", 0.0),
            "agility_factor": getattr(score, "agility_factor", 0.0),
        })

    hazards_data = []
    for h in buffer_hazards:
        hazards_data.append({
            "variable": h.variable_name,
            "file": Path(h.file_path).name if hasattr(h, "file_path") and h.file_path else "source",
            "file_path": getattr(h, "file_path", "source"),
            "line": h.line_number,
            "allocated": h.allocated_bytes,
            "required": h.required_bytes_pqc,
            "severity": h.severity,
            "description": h.message,
        })

    deps_data = []
    if manifest_dependencies:
        for d in manifest_dependencies:
            if hasattr(d, "model_dump"):
                deps_data.append(d.model_dump())
            elif hasattr(d, "dict"):
                deps_data.append(d.dict())
            elif isinstance(d, dict):
                deps_data.append(d)

    unknowns_data = []
    if unknowns_ledger:
        for u in unknowns_ledger:
            if hasattr(u, "model_dump"):
                unknowns_data.append(u.model_dump())
            elif hasattr(u, "dict"):
                unknowns_data.append(u.dict())
            elif isinstance(u, dict):
                unknowns_data.append(u)

    assets_json_str = json.dumps(assets_data)
    hazards_json_str = json.dumps(hazards_data)
    graph_json_str = json.dumps(contagion_result.graph_json)
    proof_packages_json_str = json.dumps(proof_packages)
    deps_json_str = json.dumps(deps_data)
    unknowns_json_str = json.dumps(unknowns_data)
    ciso_md_escaped = json.dumps(ciso_report_md or "")
    merkle_short = f"{merkle_root_hex[:8]}...{merkle_root_hex[-8:]}" if len(merkle_root_hex) >= 16 else merkle_root_hex

    report_html = (
        HTML_TEMPLATE
        .replace("__ASSETS_JSON__", assets_json_str)
        .replace("__GRAPH_JSON__", graph_json_str)
        .replace("__HAZARDS_JSON__", hazards_json_str)
        .replace("__PROOFS_JSON__", proof_packages_json_str)
        .replace("__DEPS_JSON__", deps_json_str)
        .replace("__UNKNOWNS_JSON__", unknowns_json_str)
        .replace("__MERKLE_ROOT__", merkle_root_hex)
        .replace("__MERKLE_ROOT_SHORT__", merkle_short)
        .replace("__PROJECT_NAME__", html.escape(project_name))
        .replace("__TOTAL_ASSETS__", str(total_assets))
        .replace("__CRITICAL_COUNT__", str(critical_count))
        .replace("__HIGH_COUNT__", str(high_count))
        .replace("__MEDIUM_COUNT__", str(medium_count))
        .replace("__LOW_COUNT__", str(low_count))
        .replace("__SUPERSPREADER_COUNT__", str(superspreader_count))
        .replace("__HAZARDS_COUNT__", str(len(buffer_hazards)))
        .replace("__DEPS_COUNT__", str(len(deps_data)))
        .replace("__UNKNOWNS_COUNT__", str(len(unknowns_data)))
        .replace("__READINESS_SCORE__", str(readiness_score))
        .replace("__CISO_MD__", ciso_md_escaped)
    )

    return report_html

generate_html_report = generate_html_dashboard

