/**
 * ECDAT Dashboard — Contagion Propagation & Blast Radius Tab
 * Implements interactive D3 force-directed blast radius graph visualization,
 * node drag & zoom, superspreader radar rings, downstream infection path highlighter,
 * node centrality ranking table, and slide-out Micro Variable Data-Level Contagion Drawer.
 */
(function() {
    window.renderContagionTab = function(container, data) {
        if (!container) return;

        const summary = (data && data.summary) || {};
        const contagionSummary = summary.contagion || {};
        const rawContagion = (data && data.contagion) || {};
        const lineageData = (data && data.lineage) || {};

        // Parse nodes and links
        let rawNodes = [];
        let rawLinks = [];

        if (!Array.isArray(rawContagion.nodes) || rawContagion.nodes.length === 0) {
            container.innerHTML = `
                <div class="tab-pane active" style="animation: fadeIn 0.2s ease;">
                    <div style="background: var(--bg-card); border: 1px solid rgba(244, 63, 94, 0.3); border-radius: var(--radius-md); padding: 3.5rem 2rem; text-align: center; margin: 2rem 0; box-shadow: var(--shadow-sm);">
                        <div style="color: var(--sev-critical); margin-bottom: 1.25rem; display: flex; justify-content: center;">
                            ${window.getIcon ? window.getIcon('alertTriangle', 48) : ''}
                        </div>
                        <h3 style="font-size: 1.3rem; font-weight: 800; color: var(--text-primary); margin-bottom: 0.6rem;">
                            No Contagion Dependency Graph Available
                        </h3>
                        <p style="font-size: 0.88rem; color: var(--text-secondary); max-width: 580px; margin: 0 auto 1.75rem auto; line-height: 1.6;">
                            No blast radius contagion graph has been computed for this project (<code>contagion_graph.json</code> not found).
                            Fabricated dependency topologies are disabled to prevent inaccurate blast radius assessments.
                        </p>
                        <div style="display: flex; justify-content: center; gap: 1rem;">
                            <button class="btn btn-primary" onclick="if (window.triggerScan) window.triggerScan();" style="font-size: 0.85rem; padding: 0.6rem 1.2rem; display: inline-flex; align-items: center; gap: 0.5rem;">
                                ${window.getIcon ? window.getIcon('zap', 15) : ''} Trigger Cryptographic Scan
                            </button>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        rawNodes = JSON.parse(JSON.stringify(rawContagion.nodes));
        rawLinks = JSON.parse(JSON.stringify(rawContagion.links || []));

        // Variable Flow Data (from lineage_graph.json)
        let varFlowData = lineageData.variable_flow || (lineageData.lineage_data && lineageData.lineage_data.variable_flow) || null;
        if (!varFlowData || !Array.isArray(varFlowData.flows)) {
            varFlowData = {
                has_flows: false,
                modules: [],
                flows: [],
                stats: { total_flows: 0, modules_count: 0 }
            };
        }

        // Build adjacency graph for fast downstream traversal
        const forwardAdj = new Map();
        const backwardAdj = new Map();

        rawNodes.forEach(n => {
            forwardAdj.set(n.id, new Set());
            backwardAdj.set(n.id, new Set());
        });

        rawLinks.forEach(l => {
            const s = typeof l.source === 'object' ? l.source.id : l.source;
            const t = typeof l.target === 'object' ? l.target.id : l.target;
            if (forwardAdj.has(s)) forwardAdj.get(s).add(t);
            if (backwardAdj.has(t)) backwardAdj.get(t).add(s);
        });

        // Compute blast radius per node using BFS
        function computeBlastRadius(startNodeId) {
            const visited = new Set();
            const queue = [startNodeId];
            visited.add(startNodeId);

            while (queue.length > 0) {
                const curr = queue.shift();
                const neighbors = forwardAdj.get(curr) || new Set();
                neighbors.forEach(next => {
                    if (!visited.has(next)) {
                        visited.add(next);
                        queue.push(next);
                    }
                });
            }
            return visited;
        }

        const totalNodesCount = Math.max(1, rawNodes.length);
        rawNodes.forEach(node => {
            const reachable = computeBlastRadius(node.id);
            node.blast_count = reachable.size;
            node.downstream_count = reachable.size - 1;
            node.blast_pct = parseFloat(((node.blast_count / totalNodesCount) * 100).toFixed(1));
            
            if (node.is_pqc_anchor) {
                node.render_color = '#00f5a0';
                node.risk_tier = 'PQC ANCHOR';
            } else if (node.is_superspreader) {
                node.render_color = '#f43f5e';
                node.risk_tier = 'SUPERSPREADER';
            } else if (node.has_crypto) {
                node.render_color = '#f59e0b';
                node.risk_tier = 'HIGH RISK';
            } else {
                node.render_color = '#38bdf8';
                node.risk_tier = 'CONSUMER';
            }
        });

        // Sort ranking: highest blast radius first
        const rankedNodes = [...rawNodes].sort((a, b) => b.blast_pct - a.blast_pct || b.r0 - a.r0);

        // State
        const graphState = {
            selectedNodeId: null,
            blastSet: new Set(),
            searchQuery: '',
            filterType: 'ALL',
            varFlowDrawerOpen: false,
            activeVarFlowModule: 'ALL'
        };

        const totalFlowsCount = (varFlowData && varFlowData.flows) ? varFlowData.flows.length : 0;

        // Render HTML Container
        container.innerHTML = `
            <div class="tab-pane active" style="display: flex; flex-direction: column; gap: 1.5rem; animation: fadeIn 0.2s ease;">
                
                <!-- Tab Header Banner -->
                <div class="tab-header-banner" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem 1.5rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; box-shadow: var(--shadow-sm);">
                    <div class="tab-title-wrap">
                        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
                            <span style="display: inline-flex; color: var(--accent-cyan);">${window.getIcon ? window.getIcon('network', 22) : ''}</span>
                            <h2 style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em; margin: 0;">Contagion Propagation &amp; Blast Radius</h2>
                            <span class="card-badge badge-critical" id="contagion-status-badge">R₀ REPRODUCTION DETECTED</span>
                        </div>
                        <p style="font-size: 0.82rem; color: var(--text-secondary); margin: 0;">
                            Epidemiological infection modeling of cryptographic vulnerabilities across dependencies and microservices. Identify superspreader hubs that propagate classical risk transitively through the estate.
                        </p>
                    </div>

                    <!-- Clean Banner Badge -->
                    <div style="display: flex; align-items: center; gap: 0.6rem;">
                        <span class="card-badge badge-pqc" style="font-size: 0.72rem; padding: 0.35rem 0.75rem; font-family: var(--font-mono);">
                            EPIDEMIOLOGICAL MODEL &bull; ZERO-MVCC TOPOLOGY
                        </span>
                    </div>
                </div>

                <!-- KPI Metric Cards Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem;">
                    
                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Topology Nodes</span>
                            <span style="color: var(--text-muted); display: inline-flex;">${window.getIcon ? window.getIcon('globe', 16) : ''}</span>
                        </div>
                        <div class="stat-val" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: var(--text-primary);">
                            ${rawNodes.length}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary);">
                            Discovered modules and services
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Dependency Edges</span>
                            <span style="color: #0284c7; display: inline-flex;">${window.getIcon ? window.getIcon('link', 16) : ''}</span>
                        </div>
                        <div class="stat-val" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: #0284c7;">
                            ${rawLinks.length}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary);">
                            Directed data &amp; invocation links
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Primary Hotspot (Max R₀)</span>
                            <span style="color: var(--sev-critical); display: inline-flex;">${window.getIcon ? window.getIcon('alertTriangle', 16) : ''}</span>
                        </div>
                        <div class="stat-val text-critical" style="font-size: 1.5rem; margin: 0.35rem 0 0.1rem 0; word-break: break-all;">
                            ${contagionSummary.max_degree_node || (rankedNodes[0] && rankedNodes[0].label) || 'N/A'}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--sev-critical); font-weight: 600;">
                            R₀ = ${contagionSummary.max_degree || (rankedNodes[0] && rankedNodes[0].r0) || 0} immediate dependents
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">PQC Anchors Installed</span>
                            <span style="color: var(--pqc-emerald); display: inline-flex;">${window.getIcon ? window.getIcon('shieldCheck', 16) : ''}</span>
                        </div>
                        <div class="stat-val text-emerald" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0;">
                            ${rawNodes.filter(n => n.is_pqc_anchor).length}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--pqc-emerald);">
                            Post-quantum trust roots active
                        </div>
                    </div>

                </div>

                <!-- Graph Canvas & Interactive Simulator Area -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem 1.5rem; display: flex; flex-direction: column; gap: 0.85rem; position: relative; box-shadow: var(--shadow-sm);">
                    
                    <!-- Graph Header with Action Toolbar -->
                    <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem;">
                        <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
                            <span style="font-size: 0.88rem; font-weight: 700; color: var(--text-primary);">Interactive Blast Radius Graph</span>
                            <span style="font-size: 0.72rem; color: var(--text-muted);">(Hover node to inspect connections &bull; Drag to reposition &bull; Scroll to zoom &bull; Click to pin blast)</span>
                        </div>

                        <!-- Graph Actions Toolbar: Micro Variable Flow Drawer + Zoom + Reset -->
                        <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                            <!-- Micro Variable Flow Drawer Toggle Button (Sleek placement right on graph toolbar) -->
                            <button id="var-flow-toggle-btn" class="btn btn-secondary" style="font-size: 0.75rem; border-color: #0284c7; color: #0284c7; display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.35rem 0.75rem; background: #ffffff; box-shadow: var(--shadow-sm);" title="Toggle Micro Variable Data Flow Drawer">
                                ${window.getIcon ? window.getIcon('layers', 14) : ''}
                                <span class="font-bold">Micro Variable Flow</span>
                                <span id="var-flow-badge-count" class="card-badge badge-pqc" style="font-size: 0.65rem; padding: 1px 6px;">${totalFlowsCount} Flows</span>
                            </button>

                            <div style="display: inline-flex; align-items: center; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); overflow: hidden; background: #ffffff;">
                                <button class="btn" id="graph-zoom-in" title="Zoom In" style="padding: 0.35rem 0.6rem; border: none; border-right: 1px solid var(--border-subtle); background: transparent; font-size: 0.8rem; cursor: pointer; color: var(--text-primary);">${window.getIcon ? window.getIcon('plus', 13) : '+'}</button>
                                <button class="btn" id="graph-zoom-out" title="Zoom Out" style="padding: 0.35rem 0.6rem; border: none; border-right: 1px solid var(--border-subtle); background: transparent; font-size: 0.8rem; cursor: pointer; color: var(--text-primary);">${window.getIcon ? window.getIcon('minus', 13) : '-'}</button>
                                <button class="btn" id="graph-zoom-reset" title="Reset View" style="padding: 0.35rem 0.65rem; border: none; background: transparent; font-size: 0.72rem; cursor: pointer; color: var(--text-primary); display: inline-flex; align-items: center; gap: 0.25rem;">
                                    ${window.getIcon ? window.getIcon('refresh', 12) : ''}
                                    <span>Reset</span>
                                </button>
                            </div>

                            <button class="btn btn-emerald" id="graph-clear-blast" style="font-size: 0.72rem; padding: 0.35rem 0.65rem; display: none;">
                                <span style="display: inline-flex; align-items: center; gap: 0.3rem;">
                                    ${window.getIcon ? window.getIcon('x', 12) : ''}
                                    <span>Clear Simulator</span>
                                </span>
                            </button>
                        </div>
                    </div>

                    <!-- Legend -->
                    <div style="display: flex; align-items: center; justify-content: flex-end; gap: 1.25rem; font-size: 0.7rem; padding-top: 0.35rem; border-top: 1px solid var(--border-subtle);">
                        <div style="display: flex; align-items: center; gap: 0.35rem;">
                            <span style="display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: #f43f5e; box-shadow: 0 0 6px #f43f5e;"></span>
                            <span style="color: var(--text-secondary);">Superspreader (Critical)</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.35rem;">
                            <span style="display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: #f59e0b;"></span>
                            <span style="color: var(--text-secondary);">Crypto Source (High)</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.35rem;">
                            <span style="display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: #10b981; box-shadow: 0 0 6px #10b981;"></span>
                            <span style="color: var(--text-secondary);">PQC Anchor</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.35rem;">
                            <span style="display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: #64748b;"></span>
                            <span style="color: var(--text-secondary);">Consumer Node</span>
                        </div>
                    </div>

                    <!-- Graph Container with Slide-Out Variable Flow Drawer -->
                    <div id="contagion-d3-canvas-wrapper" style="width: 100%; height: 600px; background: #f8fafc; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); position: relative; overflow: hidden;">
                        <svg id="contagion-svg" width="100%" height="100%" style="display: block; cursor: grab;"></svg>

                        <!-- Floating Blast Radius HUD Overlay -->
                        <div id="blast-radius-hud" style="position: absolute; top: 1rem; left: 1rem; max-width: 340px; background: #ffffff; border: 1px solid var(--sev-critical); border-radius: var(--radius-md); padding: 1rem; box-shadow: var(--shadow-lg); display: none; z-index: 10; animation: fadeIn 0.2s ease;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                                <div style="display: flex; align-items: center; gap: 0.4rem; color: #f43f5e; font-weight: 800; font-size: 0.78rem;">
                                    <span style="display: inline-flex;">${window.getIcon ? window.getIcon('alertTriangle', 14) : ''}</span>
                                    <span>BLAST RADIUS ACTIVE</span>
                                </div>
                                <button id="close-hud-btn" style="background: none; border: none; color: var(--text-muted); cursor: pointer; display: inline-flex; align-items: center;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
                            </div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); margin-bottom: 0.25rem;">Patient Zero Vector:</div>
                            <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); font-size: 0.88rem; margin-bottom: 0.5rem;" id="hud-node-name">
                                common_crypto
                            </div>
                            <div style="display: flex; gap: 0.5rem; margin-bottom: 0.6rem;">
                                <div style="background: var(--bg-sunken); padding: 0.4rem 0.6rem; border-radius: 4px; flex: 1;">
                                    <div style="font-size: 0.65rem; color: var(--text-muted);">Impacted Nodes</div>
                                    <div class="mono font-bold text-critical" id="hud-impact-count" style="font-size: 1.1rem;">4</div>
                                </div>
                                <div style="background: var(--bg-sunken); padding: 0.4rem 0.6rem; border-radius: 4px; flex: 1;">
                                    <div style="font-size: 0.65rem; color: var(--text-muted);">Estate Exposure</div>
                                    <div class="mono font-bold text-critical" id="hud-impact-pct" style="font-size: 1.1rem;">36.4%</div>
                                </div>
                            </div>
                            <div style="font-size: 0.68rem; color: var(--text-secondary); line-height: 1.4; border-top: 1px solid var(--border-subtle); padding-top: 0.5rem;">
                                Downstream infection compromises all services consuming this module's unshielded cryptographic tokens or signatures.
                            </div>
                            <!-- Micro Variable Flow Action Button in HUD -->
                            <button id="hud-var-flow-btn" class="btn btn-secondary" style="margin-top: 0.65rem; width: 100%; font-size: 0.72rem; border-color: #0284c7; color: #0284c7; display: flex; align-items: center; justify-content: center; gap: 0.35rem;">
                                ${window.getIcon ? window.getIcon('layers', 13) : ''}
                                <span>Inspect Micro Variable Flow</span>
                            </button>
                        </div>

                        <!-- Micro Variable Flow Drawer (Slide-out from right) -->
                        <div id="variable-flow-drawer" class="variable-flow-drawer" style="position: absolute; top: 0; right: 0; bottom: 0; width: 680px; max-width: 95%; background: rgba(255, 255, 255, 0.98); backdrop-filter: blur(16px); border-left: 1px solid var(--border-strong); box-shadow: var(--shadow-xl); z-index: 30; transform: translateX(100%); transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); display: flex; flex-direction: column; overflow: hidden;">
                            <!-- Drawer Header -->
                            <div style="padding: 1rem 1.25rem; border-bottom: 1px solid var(--border-subtle); background: var(--bg-sunken); display: flex; align-items: flex-start; justify-content: space-between; gap: 0.75rem; flex-shrink: 0;">
                                <div>
                                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #0284c7; box-shadow: 0 0 6px #0284c7;"></span>
                                        <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin: 0; font-family: var(--font-mono);">Micro Data-Level Contagion</h4>
                                        <span class="card-badge badge-pqc" style="font-size: 0.65rem;">Variable Flow</span>
                                    </div>
                                    <p style="font-size: 0.72rem; color: var(--text-secondary); margin: 0.3rem 0 0 0; font-family: var(--font-mono);">
                                        Ingress &bull; Parameters &rarr; Cryptographic Nexus &rarr; Persistence Sinks
                                    </p>
                                </div>
                                <button id="var-flow-close-btn" style="background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.25rem; padding: 0.2rem; line-height: 1;" title="Close Drawer">&times;</button>
                            </div>

                            <!-- Module Filter Bar -->
                            <div style="padding: 0.65rem 1.25rem; background: #ffffff; border-bottom: 1px solid var(--border-subtle); display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; flex-shrink: 0;">
                                <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-secondary);">
                                    <span>Filter Module:</span>
                                    <select id="var-flow-module-select" style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 0.25rem 0.5rem; font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-primary); outline: none; max-width: 260px;">
                                        <option value="ALL">All Modules</option>
                                    </select>
                                </div>
                                <span id="var-flow-filtered-count" style="font-size: 0.72rem; font-family: var(--font-mono); color: var(--text-muted);"></span>
                            </div>

                            <!-- Drawer Content List -->
                            <div id="variable-flow-list" style="flex: 1; overflow-y: auto; padding: 1rem 1.25rem; display: flex; flex-direction: column; gap: 0.85rem;">
                                <!-- Populated dynamically by renderVariableFlowDrawer -->
                            </div>
                        </div>

                    </div>

                </div>

                <!-- Node Centrality and Propagation Ranking Table -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; box-shadow: var(--shadow-sm);">
                    
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 1rem;">
                        <div>
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <span style="display: inline-flex; color: var(--text-muted);">${window.getIcon ? window.getIcon('barChart', 16) : ''}</span>
                                <h3 style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin: 0;">Centrality &amp; Blast Propagation Ranking</h3>
                            </div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">
                                Ranked by cumulative transitive blast radius across downstream architectural dependencies.
                            </div>
                        </div>

                        <!-- Search and Filter -->
                        <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
                            <input type="text" id="contagion-search" placeholder="Search node or file..." style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); color: var(--text-primary); padding: 0.35rem 0.65rem; border-radius: var(--radius-sm); font-size: 0.78rem; font-family: var(--font-mono); outline: none; width: 180px;">
                            
                            <select id="contagion-filter-select" style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); color: var(--text-primary); padding: 0.35rem 0.65rem; border-radius: var(--radius-sm); font-size: 0.78rem; font-family: var(--font-mono); outline: none;">
                                <option value="ALL">All Nodes</option>
                                <option value="SUPERSPREADER">Superspreaders</option>
                                <option value="HIGH">High Risk</option>
                                <option value="PQC">PQC Anchors</option>
                            </select>
                        </div>
                    </div>

                    <!-- Ranking Table -->
                    <div style="overflow-x: auto; width: 100%;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-strong); color: var(--text-muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em;">
                                    <th style="padding: 0.65rem 0.85rem; width: 50px;">Rank</th>
                                    <th style="padding: 0.65rem 0.85rem;">Node Identifier</th>
                                    <th style="padding: 0.65rem 0.85rem;">Source File / Path</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Reproduction R₀</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: right;">Downstream Impact</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Blast Radius %</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Risk Classification</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Simulation</th>
                                </tr>
                            </thead>
                            <tbody id="contagion-table-body">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>

                </div>

            </div>
        `;

        // Calculate degree topology
        const inDegrees = {};
        const outDegrees = {};
        rawNodes.forEach(n => {
            inDegrees[n.id] = 0;
            outDegrees[n.id] = 0;
        });

        rawLinks.forEach(l => {
            const s = typeof l.source === 'object' ? l.source.id : l.source;
            const t = typeof l.target === 'object' ? l.target.id : l.target;
            outDegrees[s] = (outDegrees[s] || 0) + 1;
            inDegrees[t] = (inDegrees[t] || 0) + 1;
        });

        rawNodes.forEach(n => {
            n.inDegree = inDegrees[n.id] || 0;
            n.outDegree = outDegrees[n.id] || 0;
            n.degree = n.inDegree + n.outDegree;
        });

        // Sizing function ensuring compact, elegant, non-overlapping nodes
        function getNodeRadius(d) {
            if (!d) return 9;
            if (d.is_superspreader) return 20;
            if (d.is_pqc_anchor) return 17;
            if (d.has_crypto) return 14;
            if (d.r0 > 0 || (d.degree && d.degree > 1)) return 11;
            return 9;
        }

        // ================= DETERMINISTIC STRATIFIED FLOW TOPOLOGY =================
        const svgEl = d3.select("#contagion-svg");
        const containerWrapper = document.getElementById("contagion-d3-canvas-wrapper");
        const width = containerWrapper ? containerWrapper.clientWidth : 1000;
        const height = containerWrapper ? containerWrapper.clientHeight : 600;

        svgEl.selectAll("*").remove();

        const defs = svgEl.append("defs");

        // Standard directed arrow marker (pointing precisely to node perimeter)
        defs.append("marker")
            .attr("id", "arrow-std")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 7)
            .attr("refY", 0)
            .attr("markerWidth", 5)
            .attr("markerHeight", 5)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-3.5L7,0L0,3.5Z")
            .attr("fill", "#64748b");

        // Active blast / superspreader infection arrow (crimson)
        defs.append("marker")
            .attr("id", "arrow-blast")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 7)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-3.5L7,0L0,3.5Z")
            .attr("fill", "#f43f5e");

        // Downstream hover connection arrow (emerald)
        defs.append("marker")
            .attr("id", "arrow-downstream")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 7)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-3.5L7,0L0,3.5Z")
            .attr("fill", "#10b981");

        // Upstream hover connection arrow (sky blue)
        defs.append("marker")
            .attr("id", "arrow-upstream")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 7)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-3.5L7,0L0,3.5Z")
            .attr("fill", "#0284c7");

        // Background subtle grid pattern
        const gridPattern = defs.append("pattern")
            .attr("id", "contagion-grid")
            .attr("width", 28)
            .attr("height", 28)
            .attr("patternUnits", "userSpaceOnUse");

        gridPattern.append("circle")
            .attr("cx", 2)
            .attr("cy", 2)
            .attr("r", 1)
            .attr("fill", "rgba(0, 0, 0, 0.06)");

        const g = svgEl.append("g");

        g.append("rect")
            .attr("x", -4000)
            .attr("y", -4000)
            .attr("width", 8000)
            .attr("height", 8000)
            .attr("fill", "url(#contagion-grid)");

        // Zoom Behavior
        const zoom = d3.zoom()
            .scaleExtent([0.15, 3.5])
            .on("zoom", (e) => {
                g.attr("transform", e.transform);
            });

        svgEl.call(zoom);

        // Deterministic Stratified Flow Assignment (Rank/Tier Computation)
        const nodesData = rawNodes.map(d => Object.assign({}, d));
        const linksData = rawLinks.map(d => Object.assign({}, d));

        // Build adjacency maps for instant hover connection highlighting
        const neighborMap = new Map();
        const upstreamMap = new Map();
        const downstreamMap = new Map();

        nodesData.forEach(n => {
            neighborMap.set(n.id, new Set([n.id]));
            upstreamMap.set(n.id, new Set());
            downstreamMap.set(n.id, new Set());

            if (n.is_superspreader || (n.id && n.id.includes('-ca')) || (n.inDegree === 0 && n.outDegree > 0)) {
                n.flowTier = 0;
            } else if (n.is_pqc_anchor || n.has_crypto) {
                n.flowTier = 1;
            } else if (n.outDegree > 0 && n.inDegree > 0) {
                n.flowTier = 2;
            } else if (n.degree > 0) {
                n.flowTier = 3;
            } else {
                n.flowTier = 4; // Isolated
            }
        });

        linksData.forEach(l => {
            const sId = typeof l.source === 'object' ? l.source.id : l.source;
            const tId = typeof l.target === 'object' ? l.target.id : l.target;
            if (neighborMap.has(sId)) neighborMap.get(sId).add(tId);
            if (neighborMap.has(tId)) neighborMap.get(tId).add(sId);
            if (downstreamMap.has(sId)) downstreamMap.get(sId).add(tId);
            if (upstreamMap.has(tId)) upstreamMap.get(tId).add(sId);
        });

        // Refine flow tier via forward BFS along links
        for (let iter = 0; iter < 3; iter++) {
            linksData.forEach(l => {
                const sId = typeof l.source === 'object' ? l.source.id : l.source;
                const tId = typeof l.target === 'object' ? l.target.id : l.target;
                const sNode = nodesData.find(n => n.id === sId);
                const tNode = nodesData.find(n => n.id === tId);
                if (sNode && tNode && tNode.flowTier <= sNode.flowTier && sNode.flowTier < 3) {
                    tNode.flowTier = sNode.flowTier + 1;
                }
            });
        }

        // Compute Deterministic Stable Coordinates with ample spacing
        const tiers = [0, 1, 2, 3, 4];
        const tierNodesMap = {};
        tiers.forEach(t => { tierNodesMap[t] = []; });
        nodesData.forEach(n => {
            const t = n.flowTier in tierNodesMap ? n.flowTier : 3;
            tierNodesMap[t].push(n);
        });

        const colWidth = 350;
        const padX = 130;

        tiers.forEach(t => {
            const group = tierNodesMap[t];
            group.sort((a, b) => {
                if (a.is_superspreader !== b.is_superspreader) return a.is_superspreader ? -1 : 1;
                if (a.is_pqc_anchor !== b.is_pqc_anchor) return a.is_pqc_anchor ? -1 : 1;
                return (b.degree || 0) - (a.degree || 0);
            });

            const useSubCols = group.length > 8;
            const subColOffset = 95;
            const vertSpacing = useSubCols ? 62 : Math.max(54, Math.min(84, (height - 130) / Math.max(1, group.length)));
            const startY = 70;

            group.forEach((n, idx) => {
                if (useSubCols) {
                    const sub = idx % 2;
                    const row = Math.floor(idx / 2);
                    n.x = padX + t * colWidth + (sub === 1 ? subColOffset : -subColOffset / 2);
                    n.y = startY + row * vertSpacing;
                } else {
                    n.x = padX + t * colWidth;
                    n.y = startY + idx * vertSpacing;
                }
            });
        });

        // Resolve link references to node objects
        const nodeLookup = new Map(nodesData.map(n => [n.id, n]));
        linksData.forEach(l => {
            if (typeof l.source !== 'object') l.source = nodeLookup.get(l.source) || { id: l.source, x: 0, y: 0 };
            if (typeof l.target !== 'object') l.target = nodeLookup.get(l.target) || { id: l.target, x: 0, y: 0 };
        });

        // Precision Perimeter-to-Perimeter Cubic Bézier Path Generator
        function computeLinkPath(d) {
            const s = typeof d.source === 'object' ? d.source : null;
            const t = typeof d.target === 'object' ? d.target : null;
            if (!s || !t) return "";

            const sRadius = getNodeRadius(s);
            const tRadius = getNodeRadius(t);

            if (t.x > s.x) {
                // Forward flow: starts right boundary of s, ends left boundary of t
                const startX = s.x + sRadius;
                const startY = s.y;
                const endX = t.x - tRadius;
                const endY = t.y;
                const dx = Math.max(30, (endX - startX) * 0.45);
                return `M ${startX} ${startY} C ${startX + dx} ${startY}, ${endX - dx} ${endY}, ${endX} ${endY}`;
            } else if (t.x < s.x) {
                // Backward / feedback flow: loops gracefully from left boundary of s to right boundary of t
                const startX = s.x - sRadius;
                const startY = s.y;
                const endX = t.x + tRadius;
                const endY = t.y;
                const dy = (s.y >= t.y) ? -45 : 45;
                return `M ${startX} ${startY} C ${startX - 50} ${startY + dy}, ${endX + 50} ${endY + dy}, ${endX} ${endY}`;
            } else {
                // Same column (s.x === t.x): loops out to the right
                const startX = s.x + sRadius;
                const startY = s.y;
                const endX = t.x + tRadius;
                const endY = t.y;
                const loop = 45;
                return `M ${startX} ${startY} C ${startX + loop} ${startY}, ${endX + loop} ${endY}, ${endX} ${endY}`;
            }
        }

        // Render Directed Flow Links
        const link = g.append("g")
            .attr("class", "links")
            .selectAll("path")
            .data(linksData)
            .enter()
            .append("path")
            .attr("fill", "none")
            .attr("stroke", d => {
                const s = d.source;
                if (s && s.is_superspreader) return "rgba(244, 63, 94, 0.55)";
                if (s && s.is_pqc_anchor) return "rgba(16, 185, 129, 0.55)";
                return "#94a3b8";
            })
            .attr("stroke-opacity", 0.65)
            .attr("stroke-width", d => {
                const s = d.source;
                return (s && s.is_superspreader) ? 2.0 : 1.3;
            })
            .attr("marker-end", "url(#arrow-std)")
            .attr("d", d => computeLinkPath(d));

        // Render Node Group Elements with Drag Support & Connection Hover Highlighting
        const node = g.append("g")
            .attr("class", "nodes")
            .selectAll("g")
            .data(nodesData)
            .enter()
            .append("g")
            .attr("transform", d => `translate(${d.x},${d.y})`)
            .style("cursor", "pointer")
            .call(d3.drag()
                .on("drag", function(event, d) {
                    d.x = event.x;
                    d.y = event.y;
                    d3.select(this).attr("transform", `translate(${d.x},${d.y})`);
                    link.attr("d", l => computeLinkPath(l));
                })
            );

        // Node visual elements (compact, scaled radii)
        node.each(function(d) {
            const el = d3.select(this);
            const r = getNodeRadius(d);

            if (d.is_superspreader) {
                el.append("circle")
                    .attr("class", "node-outer-ring")
                    .attr("r", r + 6)
                    .attr("fill", "none")
                    .attr("stroke", "#f43f5e")
                    .attr("stroke-width", 1.5)
                    .attr("stroke-dasharray", "3,2")
                    .attr("opacity", 0.7);
            } else if (d.is_pqc_anchor) {
                el.append("circle")
                    .attr("class", "node-outer-ring")
                    .attr("r", r + 5)
                    .attr("fill", "none")
                    .attr("stroke", "#00f5a0")
                    .attr("stroke-width", 1.5)
                    .attr("stroke-dasharray", "3,2")
                    .attr("opacity", 0.8);
            }

            el.append("circle")
                .attr("class", "node-base-circle")
                .attr("r", r)
                .attr("fill", d.render_color || "#38bdf8")
                .attr("stroke", "#ffffff")
                .attr("stroke-width", 2.2)
                .style("filter", d.is_superspreader ? "drop-shadow(0px 0px 6px rgba(244,63,94,0.5))" : (d.is_pqc_anchor ? "drop-shadow(0px 0px 6px rgba(16,185,129,0.5))" : "none"));

            el.append("text")
                .attr("class", "node-inner-text")
                .attr("text-anchor", "middle")
                .attr("dy", 3.5)
                .attr("fill", "#ffffff")
                .attr("font-size", r >= 14 ? "9px" : "8px")
                .attr("font-weight", "bold")
                .attr("font-family", "var(--font-mono)")
                .text(d.r0 !== undefined && d.r0 > 0 ? d.r0 : (d.has_crypto ? '★' : ''));

            el.append("text")
                .attr("class", "node-label")
                .attr("text-anchor", "middle")
                .attr("dy", r + 13)
                .attr("fill", "#0f172a")
                .attr("font-size", "10px")
                .attr("font-weight", (d.is_superspreader || d.is_pqc_anchor) ? "800" : "600")
                .attr("font-family", "var(--font-mono)")
                .style("paint-order", "stroke fill")
                .style("stroke", "#ffffff")
                .style("stroke-width", "3px")
                .style("stroke-linejoin", "round")
                .style("pointer-events", "none")
                .text(d.label || d.id);
        });

        // Hover Connection Highlighting (Lineage Provenance Style)
        function highlightNodeConnections(targetNode) {
            const neighbors = neighborMap.get(targetNode.id) || new Set([targetNode.id]);
            const upstream = upstreamMap.get(targetNode.id) || new Set();
            const downstream = downstreamMap.get(targetNode.id) || new Set();

            // 1. Highlight Nodes
            node.transition().duration(120)
                .style("opacity", n => neighbors.has(n.id) ? 1.0 : 0.08);

            node.each(function(n) {
                const el = d3.select(this);
                const isTarget = n.id === targetNode.id;
                const isUp = upstream.has(n.id);
                const isDown = downstream.has(n.id);

                if (isTarget) {
                    el.attr("transform", `translate(${n.x},${n.y}) scale(1.2)`);
                    el.select(".node-base-circle")
                        .attr("stroke", "#0f172a")
                        .attr("stroke-width", 3.2);
                } else if (isDown) {
                    el.attr("transform", `translate(${n.x},${n.y}) scale(1.1)`);
                    el.select(".node-base-circle")
                        .attr("stroke", targetNode.is_superspreader ? "#f43f5e" : "#10b981")
                        .attr("stroke-width", 2.6);
                } else if (isUp) {
                    el.attr("transform", `translate(${n.x},${n.y}) scale(1.1)`);
                    el.select(".node-base-circle")
                        .attr("stroke", "#0284c7")
                        .attr("stroke-width", 2.6);
                } else {
                    el.attr("transform", `translate(${n.x},${n.y}) scale(1.0)`);
                }
            });

            // 2. Highlight Links
            link.transition().duration(120)
                .style("opacity", l => {
                    const sId = typeof l.source === 'object' ? l.source.id : l.source;
                    const tId = typeof l.target === 'object' ? l.target.id : l.target;
                    return (sId === targetNode.id || tId === targetNode.id) ? 1.0 : 0.03;
                })
                .attr("stroke", l => {
                    const sId = typeof l.source === 'object' ? l.source.id : l.source;
                    const tId = typeof l.target === 'object' ? l.target.id : l.target;
                    if (sId === targetNode.id) {
                        return targetNode.is_superspreader ? "#f43f5e" : "#10b981";
                    }
                    if (tId === targetNode.id) {
                        return "#0284c7";
                    }
                    return "#cbd5e1";
                })
                .attr("stroke-width", l => {
                    const sId = typeof l.source === 'object' ? l.source.id : l.source;
                    const tId = typeof l.target === 'object' ? l.target.id : l.target;
                    return (sId === targetNode.id || tId === targetNode.id) ? 3.0 : 1.0;
                })
                .attr("marker-end", l => {
                    const sId = typeof l.source === 'object' ? l.source.id : l.source;
                    const tId = typeof l.target === 'object' ? l.target.id : l.target;
                    if (sId === targetNode.id) {
                        return targetNode.is_superspreader ? "url(#arrow-blast)" : "url(#arrow-downstream)";
                    }
                    if (tId === targetNode.id) {
                        return "url(#arrow-upstream)";
                    }
                    return "url(#arrow-std)";
                });

            // 3. Highlight Node Labels
            node.selectAll(".node-label").style("opacity", n => neighbors.has(n.id) ? 1.0 : 0.04);
        }

        function clearNodeHighlights() {
            // If blast simulation is pinned, retain simulation
            if (graphState.selectedNodeId) {
                triggerBlastSimulation(graphState.selectedNodeId);
                return;
            }

            node.transition().duration(150)
                .style("opacity", 1.0)
                .attr("transform", d => `translate(${d.x},${d.y}) scale(1.0)`);

            node.selectAll(".node-base-circle")
                .attr("stroke", "#ffffff")
                .attr("stroke-width", 2.2);

            link.transition().duration(150)
                .style("opacity", 0.65)
                .attr("stroke", d => {
                    const s = d.source;
                    if (s && s.is_superspreader) return "rgba(244, 63, 94, 0.55)";
                    if (s && s.is_pqc_anchor) return "rgba(16, 185, 129, 0.55)";
                    return "#94a3b8";
                })
                .attr("stroke-width", d => {
                    const s = d.source;
                    return (s && s.is_superspreader) ? 2.0 : 1.3;
                })
                .attr("marker-end", "url(#arrow-std)");

            node.selectAll(".node-label").style("opacity", 1.0);
        }

        // Attach Mouse Events: Hover to Highlight Connections, Click to Pin Blast Details
        node.on("mouseenter", (event, d) => {
            highlightNodeConnections(d);
        })
        .on("mouseleave", () => {
            clearNodeHighlights();
        })
        .on("click", (event, d) => {
            event.stopPropagation();
            triggerBlastSimulation(d.id);
        });

        // Click canvas to clear simulation
        svgEl.on("click", () => {
            clearBlastSimulation();
        });

        // Fit to View Auto-Centering and Scaling
        function fitToView() {
            if (!nodesData || nodesData.length === 0 || !svgEl || !g || !zoom) return;
            let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
            let count = 0;
            nodesData.forEach(d => {
                const x = d.x;
                const y = d.y;
                if (x !== undefined && y !== undefined) {
                    if (x < minX) minX = x;
                    if (x > maxX) maxX = x;
                    if (y < minY) minY = y;
                    if (y > maxY) maxY = y;
                    count++;
                }
            });

            if (count === 0) {
                minX = 40; maxX = width - 40; minY = 40; maxY = height - 40;
            }

            const dx = Math.max(100, maxX - minX);
            const dy = Math.max(100, maxY - minY);
            const midX = (minX + maxX) / 2;
            const midY = (minY + maxY) / 2;

            const padding = 80;
            const scale = Math.max(0.35, Math.min(1.2, 0.88 / Math.max((dx + padding) / width, (dy + padding) / height)));
            const translate = [width / 2 - scale * midX, height / 2 - scale * midY];

            svgEl.transition()
                .duration(400)
                .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
        }

        setTimeout(() => fitToView(), 100);

        // Highlight Blast Radius Function (Click / Pinned Mode)
        function triggerBlastSimulation(selectedId) {
            graphState.selectedNodeId = selectedId;
            const targetNode = rawNodes.find(n => n.id === selectedId);
            if (!targetNode) return;

            const blastSet = computeBlastRadius(selectedId);
            graphState.blastSet = blastSet;

            // Highlight nodes
            node.transition().duration(200)
                .style("opacity", d => blastSet.has(d.id) ? 1.0 : 0.15);

            // Highlight links with high-contrast active stroke
            link.transition().duration(200)
                .style("opacity", d => {
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return (blastSet.has(s) && blastSet.has(t)) ? 1.0 : 0.15;
                })
                .attr("stroke", d => {
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return (blastSet.has(s) && blastSet.has(t)) ? "#f43f5e" : "#cbd5e1";
                })
                .attr("stroke-opacity", d => {
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return (blastSet.has(s) && blastSet.has(t)) ? 1.0 : 0.25;
                })
                .attr("stroke-width", d => {
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return (blastSet.has(s) && blastSet.has(t)) ? 2.5 : 1.25;
                })
                .attr("marker-end", d => {
                    const s = typeof d.source === 'object' ? d.source.id : d.source;
                    const t = typeof d.target === 'object' ? d.target.id : d.target;
                    return (blastSet.has(s) && blastSet.has(t)) ? "url(#arrow-blast)" : "url(#arrow-std)";
                });

            // Update floating HUD
            const hud = document.getElementById("blast-radius-hud");
            const hudName = document.getElementById("hud-node-name");
            const hudCount = document.getElementById("hud-impact-count");
            const hudPct = document.getElementById("hud-impact-pct");
            const clearBtn = document.getElementById("graph-clear-blast");
            const hudVarFlowBtn = document.getElementById("hud-var-flow-btn");

            if (hud) hud.style.display = "block";
            if (hudName) hudName.textContent = targetNode.label || targetNode.id;
            if (hudCount) hudCount.textContent = blastSet.size;
            if (hudPct) hudPct.textContent = `${((blastSet.size / totalNodesCount) * 100).toFixed(1)}%`;
            if (clearBtn) clearBtn.style.display = "inline-flex";

            // Configure HUD variable flow button
            if (hudVarFlowBtn) {
                const targetMod = targetNode.file_path || targetNode.id;
                hudVarFlowBtn.onclick = (e) => {
                    e.stopPropagation();
                    toggleVariableFlowDrawer(true);
                    filterVariableFlowByModule(targetMod);
                };
            }

            renderRankingTable();
        }

        // Reset Blast Simulation
        function clearBlastSimulation() {
            graphState.selectedNodeId = null;
            graphState.blastSet.clear();

            node.transition().duration(200).style("opacity", 1.0);
            link.transition().duration(200)
                .style("opacity", 1.0)
                .attr("stroke", d => {
                    const s = d.source;
                    if (s && s.is_superspreader) return "rgba(244, 63, 94, 0.55)";
                    if (s && s.is_pqc_anchor) return "rgba(16, 185, 129, 0.55)";
                    return "#94a3b8";
                })
                .attr("stroke-opacity", 0.65)
                .attr("stroke-width", d => {
                    const s = d.source;
                    return (s && s.is_superspreader) ? 2.0 : 1.3;
                })
                .attr("marker-end", "url(#arrow-std)");

            const hud = document.getElementById("blast-radius-hud");
            const clearBtn = document.getElementById("graph-clear-blast");
            if (hud) hud.style.display = "none";
            if (clearBtn) clearBtn.style.display = "none";

            renderRankingTable();
        }

        // ================= MICRO VARIABLE FLOW DRAWER LOGIC =================
        function toggleVariableFlowDrawer(forceState) {
            const drawer = document.getElementById('variable-flow-drawer');
            const toggleBtn = document.getElementById('var-flow-toggle-btn');
            if (!drawer) return;

            if (forceState !== undefined) {
                graphState.varFlowDrawerOpen = forceState;
            } else {
                graphState.varFlowDrawerOpen = !graphState.varFlowDrawerOpen;
            }

            if (graphState.varFlowDrawerOpen) {
                drawer.style.transform = 'translateX(0)';
                if (toggleBtn) {
                    toggleBtn.innerHTML = `
                        ${window.getIcon ? window.getIcon('x', 14) : ''}
                        <span class="font-bold">Close Drawer</span>
                    `;
                }
                renderVariableFlowDrawer(graphState.activeVarFlowModule);
            } else {
                drawer.style.transform = 'translateX(100%)';
                if (toggleBtn) {
                    toggleBtn.innerHTML = `
                        ${window.getIcon ? window.getIcon('layers', 14) : ''}
                        <span class="font-bold">Micro Variable Flow</span>
                        <span id="var-flow-badge-count" class="card-badge badge-pqc" style="font-size: 0.65rem; padding: 1px 6px;">${totalFlowsCount} Flows</span>
                    `;
                }
            }
        }

        function filterVariableFlowByModule(moduleName) {
            renderVariableFlowDrawer(moduleName);
        }

        function renderVariableFlowDrawer(filterModule = 'ALL') {
            graphState.activeVarFlowModule = filterModule;
            const container = document.getElementById('variable-flow-list');
            const select = document.getElementById('var-flow-module-select');
            const filteredCount = document.getElementById('var-flow-filtered-count');
            if (!container) return;

            const allFlows = (varFlowData && varFlowData.flows) ? varFlowData.flows : [];

            // Populate select if needed
            if (select && select.options.length <= 1) {
                const modules = (varFlowData && varFlowData.modules) ? varFlowData.modules : [];
                modules.forEach(m => {
                    const opt = document.createElement('option');
                    opt.value = m;
                    const shortName = m.split('/').pop();
                    opt.textContent = shortName;
                    select.appendChild(opt);
                });
            }
            if (select) select.value = filterModule;

            const filtered = (filterModule === 'ALL') ? allFlows : allFlows.filter(f => f.module && (f.module === filterModule || f.module.includes(filterModule) || filterModule.includes(f.module)));

            if (filteredCount) {
                filteredCount.textContent = `Showing ${filtered.length} of ${allFlows.length} flows`;
            }

            if (filtered.length === 0) {
                container.innerHTML = `
                    <div style="padding: 2.5rem 1.5rem; border-radius: var(--radius-md); background: var(--bg-sunken); border: 1px solid var(--border-subtle); text-align: center; margin-top: 2rem;">
                        <div style="width: 44px; height: 44px; margin: 0 auto 0.75rem auto; border-radius: var(--radius-sm); background: #dcfce7; border: 1px solid #16a34a; color: #16a34a; display: flex; align-items: center; justify-content: center;">
                            ${window.getIcon ? window.getIcon('shieldCheck', 24) : ''}
                        </div>
                        <h4 style="font-size: 0.92rem; font-weight: 700; color: var(--text-primary); margin: 0 0 0.4rem 0; font-family: var(--font-mono);">Zero Dynamic Variable Contagion</h4>
                        <p style="font-size: 0.75rem; color: var(--text-secondary); line-height: 1.5; max-width: 380px; margin: 0 auto;">
                            All cryptographic invocations in this module operate on closed-world statically bound literals. Zero unverified runtime variables or unconfined storage sinks detected.
                        </p>
                    </div>
                `;
                return;
            }

            let html = '';
            filtered.forEach((flow) => {
                const inp = flow.input;
                const nex = flow.nexus;
                const sinks = flow.sinks || [];

                const inputBadge = inp ? (inp.badge || inp.source_type) : 'STATIC';
                const inputBadgeColor = inp ? (inp.source_type === 'ENV' ? 'background: #e0f2fe; color: #0284c7; border: 1px solid #0284c7;' : (inp.source_type === 'CONFIG' ? 'background: #fef3c7; color: #d97706; border: 1px solid #d97706;' : 'background: #f3e8ff; color: #7c3aed; border: 1px solid #7c3aed;')) : 'background: #f1f5f9; color: #64748b; border: 1px solid #cbd5e1;';
                const inputLabel = inp ? inp.label : 'Hardcoded Constant';
                const inputSub = inp && inp.fallback ? `default: "${inp.fallback}"` : (inp ? inp.source_type : 'Closed-World AST');

                const sinkBadge = sinks.length > 0 ? (sinks[0].source_type || 'EGRESS') : 'VOLATILE';
                const sinkBadgeColor = sinks.length > 0 ? 'background: #dcfce7; color: #16a34a; border: 1px solid #16a34a;' : 'background: #f1f5f9; color: #64748b; border: 1px solid #cbd5e1;';
                const sinkLabel = sinks.length > 0 ? sinks[0].label : 'In-Memory / Volatile Only';
                const sinkSub = sinks.length > 0 ? (sinks[0].storage || sinks[0].retention || '') : 'Zero persistence exposure';

                const modName = flow.module ? flow.module.split('/').pop() : 'AST';

                html += `
                    <div class="variable-flow-card" style="padding: 1rem; border-radius: var(--radius-md); background: #ffffff; border: 1px solid var(--border-subtle); box-shadow: var(--shadow-sm); transition: all 0.2s ease; cursor: pointer;"
                         data-module="${flow.module || ''}"
                         onmouseenter="this.style.borderColor='#0284c7'; this.style.boxShadow='var(--shadow-md)';"
                         onmouseleave="this.style.borderColor='var(--border-subtle)'; this.style.boxShadow='var(--shadow-sm)';">
                        
                        <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.72rem; font-family: var(--font-mono); padding-bottom: 0.5rem; margin-bottom: 0.65rem; border-bottom: 1px solid var(--border-subtle);">
                            <span style="display: flex; align-items: center; gap: 0.4rem; color: var(--text-primary); font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 440px;">
                                <span style="color: #0284c7; display: inline-flex;">${window.getIcon ? window.getIcon('fileText', 13) : ''}</span>
                                <span>${flow.module || 'Unknown'}</span>
                            </span>
                            <span class="card-badge badge-low" style="font-size: 0.65rem; font-weight: 700;">L${nex.line || '?'}</span>
                        </div>

                        <div style="display: grid; grid-template-columns: 1fr auto 1.15fr auto 1fr; gap: 0.6rem; align-items: center;">
                            
                            <!-- Subcard 1: Input Parameter -->
                            <div class="flow-subcard" style="padding: 0.65rem 0.75rem; border-radius: var(--radius-sm); background: var(--bg-sunken); border: 1px solid var(--border-subtle); min-width: 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.68rem; font-family: var(--font-mono); margin-bottom: 0.25rem;">
                                    <span style="padding: 1px 5px; border-radius: 4px; font-weight: 700; font-size: 0.62rem; ${inputBadgeColor}">${inputBadge}</span>
                                    <span style="color: var(--text-muted); font-size: 0.62rem; text-transform: uppercase; font-weight: 700;">Input</span>
                                </div>
                                <div style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 700; color: #0284c7; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${inputLabel}">
                                    ${inputLabel}
                                </div>
                                <div style="font-size: 0.68rem; color: var(--text-secondary); font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 0.2rem;" title="${inputSub}">
                                    ${inputSub}
                                </div>
                            </div>

                            <!-- Flow Arrow 1 -->
                            <div style="display: flex; justify-content: center; align-items: center; color: #0284c7;">
                                ${window.getIcon ? window.getIcon('arrowRight', 14) : '&rarr;'}
                            </div>

                            <!-- Subcard 2: Crypto Invocation -->
                            <div class="flow-subcard" style="padding: 0.65rem 0.75rem; border-radius: var(--radius-sm); background: var(--bg-sunken); border: 1px solid var(--border-subtle); min-width: 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.68rem; font-family: var(--font-mono); margin-bottom: 0.25rem;">
                                    <span class="card-badge badge-high" style="font-size: 0.62rem; padding: 1px 5px;">CRYPTO CALL</span>
                                    <span style="color: var(--text-muted); font-size: 0.62rem; text-transform: uppercase; font-weight: 700;">Nexus</span>
                                </div>
                                <div style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 700; color: #d97706; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${nex.call || nex.label}">
                                    ${nex.call || nex.label}
                                </div>
                                <div style="font-size: 0.68rem; color: var(--text-secondary); font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 0.2rem;" title="${modName}:L${nex.line || '?'}">
                                    ${modName}:L${nex.line || '?'}
                                </div>
                            </div>

                            <!-- Flow Arrow 2 -->
                            <div style="display: flex; justify-content: center; align-items: center; color: #16a34a;">
                                ${window.getIcon ? window.getIcon('arrowRight', 14) : '&rarr;'}
                            </div>

                            <!-- Subcard 3: Persistence Sink -->
                            <div class="flow-subcard" style="padding: 0.65rem 0.75rem; border-radius: var(--radius-sm); background: var(--bg-sunken); border: 1px solid var(--border-subtle); min-width: 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.68rem; font-family: var(--font-mono); margin-bottom: 0.25rem;">
                                    <span style="padding: 1px 5px; border-radius: 4px; font-weight: 700; font-size: 0.62rem; ${sinkBadgeColor}">${sinkBadge}</span>
                                    <span style="color: var(--text-muted); font-size: 0.62rem; text-transform: uppercase; font-weight: 700;">Persistence</span>
                                </div>
                                <div style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 700; color: #16a34a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${sinkLabel}">
                                    ${sinkLabel}
                                </div>
                                <div style="font-size: 0.68rem; color: var(--text-secondary); font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 0.2rem;" title="${sinkSub}">
                                    ${sinkSub}
                                </div>
                            </div>

                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // Wire Drawer Buttons
        const varFlowToggleBtn = document.getElementById('var-flow-toggle-btn');
        if (varFlowToggleBtn) {
            varFlowToggleBtn.onclick = () => toggleVariableFlowDrawer();
        }

        const varFlowCloseBtn = document.getElementById('var-flow-close-btn');
        if (varFlowCloseBtn) {
            varFlowCloseBtn.onclick = () => toggleVariableFlowDrawer(false);
        }

        const varFlowModuleSelect = document.getElementById('var-flow-module-select');
        if (varFlowModuleSelect) {
            varFlowModuleSelect.onchange = (e) => filterVariableFlowByModule(e.target.value);
        }

        // ================= CONTROLS & TABLE RENDERING =================
        const zoomInBtn = document.getElementById("graph-zoom-in");
        const zoomOutBtn = document.getElementById("graph-zoom-out");
        const zoomResetBtn = document.getElementById("graph-zoom-reset");
        const clearBlastBtn = document.getElementById("graph-clear-blast");
        const closeHudBtn = document.getElementById("close-hud-btn");

        if (zoomInBtn) zoomInBtn.onclick = () => svgEl.transition().duration(250).call(zoom.scaleBy, 1.25);
        if (zoomOutBtn) zoomOutBtn.onclick = () => svgEl.transition().duration(250).call(zoom.scaleBy, 0.8);
        if (zoomResetBtn) zoomResetBtn.onclick = () => fitToView();
        if (clearBlastBtn) clearBlastBtn.onclick = () => clearBlastSimulation();
        if (closeHudBtn) closeHudBtn.onclick = () => clearBlastSimulation();

        // Render Ranking Table
        function renderRankingTable() {
            const tbody = document.getElementById("contagion-table-body");
            if (!tbody) return;

            let filtered = rankedNodes;

            if (graphState.filterType === 'SUPERSPREADER') {
                filtered = filtered.filter(n => n.is_superspreader);
            } else if (graphState.filterType === 'HIGH') {
                filtered = filtered.filter(n => n.has_crypto && !n.is_superspreader);
            } else if (graphState.filterType === 'PQC') {
                filtered = filtered.filter(n => n.is_pqc_anchor);
            }

            if (graphState.searchQuery) {
                const q = graphState.searchQuery.toLowerCase();
                filtered = filtered.filter(n => 
                    (n.label && n.label.toLowerCase().includes(q)) ||
                    (n.id && n.id.toLowerCase().includes(q)) ||
                    (n.file_path && n.file_path.toLowerCase().includes(q))
                );
            }

            if (filtered.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8" style="padding: 2rem; text-align: center; color: var(--text-muted); font-family: var(--font-mono);">
                            No network nodes match the selected criteria.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = filtered.map((n, idx) => {
                const isSelected = graphState.selectedNodeId === n.id;
                const isBlastImpacted = graphState.blastSet.has(n.id);
                
                let rowBg = '';
                if (isSelected) {
                    rowBg = 'background: rgba(244, 63, 94, 0.1); border-left: 3px solid #f43f5e;';
                } else if (isBlastImpacted) {
                    rowBg = 'background: rgba(245, 158, 11, 0.05);';
                }

                let badgeClass = 'badge-low';
                if (n.is_superspreader) badgeClass = 'badge-critical';
                else if (n.is_pqc_anchor) badgeClass = 'badge-pqc';
                else if (n.has_crypto) badgeClass = 'badge-high';

                return `
                    <tr style="border-bottom: 1px solid var(--border-subtle); ${rowBg} transition: background 0.15s ease;" onmouseover="this.style.background='rgba(0,0,0,0.02)'" onmouseout="this.style.background='transparent'">
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); color: var(--text-muted);">
                            #${idx + 1}
                        </td>
                        <td style="padding: 0.75rem 0.85rem;">
                            <div style="font-weight: 700; font-family: var(--font-mono); color: ${n.render_color || 'var(--text-primary)'}; font-size: 0.82rem;">
                                ${n.label || n.id}
                            </div>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-secondary); max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            ${n.file_path || '.'}
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center; font-family: var(--font-mono); font-weight: 700; color: ${n.r0 > 1 ? 'var(--sev-critical)' : 'var(--text-primary)'};">
                            ${n.r0}
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: right; font-family: var(--font-mono); font-weight: 600; color: var(--text-primary);">
                            ${n.blast_count} nodes (${n.downstream_count} downstream)
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center;">
                            <div style="display: flex; align-items: center; justify-content: center; gap: 0.4rem;">
                                <div style="width: 50px; height: 5px; background: var(--bg-sunken); border-radius: 999px; overflow: hidden;">
                                    <div style="width: ${n.blast_pct}%; height: 100%; background: ${n.blast_pct > 30 ? 'var(--sev-critical)' : (n.blast_pct > 15 ? 'var(--sev-high)' : '#0284c7')}; border-radius: 999px;"></div>
                                </div>
                                <span style="font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700; color: ${n.blast_pct > 30 ? 'var(--sev-critical)' : 'var(--text-primary)'};">
                                    ${n.blast_pct}%
                                </span>
                            </div>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center;">
                            <span class="card-badge ${badgeClass}" style="font-size: 0.68rem;">${n.risk_tier}</span>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center;">
                            <button class="btn btn-secondary blast-simulate-btn" data-id="${n.id}" style="padding: 0.25rem 0.55rem; font-size: 0.7rem; border-color: rgba(244, 63, 94, 0.4);">
                                <span style="display: inline-flex; align-items: center; gap: 0.3rem;">
                                    ${window.getIcon ? window.getIcon('crosshair', 12) : ''}
                                    <span>Simulate</span>
                                </span>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');

            const simBtns = tbody.querySelectorAll('.blast-simulate-btn');
            simBtns.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const id = e.target.closest('button').getAttribute('data-id');
                    triggerBlastSimulation(id);
                    const targetNode = nodesData.find(d => d.id === id);
                    if (targetNode && targetNode.x && targetNode.y) {
                        svgEl.transition().duration(500).call(
                            zoom.transform,
                            d3.zoomIdentity.translate(width / 2 - targetNode.x, height / 2 - targetNode.y).scale(1.2)
                        );
                    }
                });
            });
        }

        const searchInput = document.getElementById("contagion-search");
        if (searchInput) {
            searchInput.addEventListener("input", (e) => {
                graphState.searchQuery = e.target.value.trim();
                renderRankingTable();
            });
        }

        const filterSelect = document.getElementById("contagion-filter-select");
        if (filterSelect) {
            filterSelect.addEventListener("change", (e) => {
                graphState.filterType = e.target.value;
                renderRankingTable();
            });
        }

        renderRankingTable();
    };
})();
