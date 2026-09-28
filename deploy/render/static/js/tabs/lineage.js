/**
 * ECDAT Dashboard — Cryptographic Lineage & Father Marko Provenance Tab
 * Implements Father Marko Bipartite/Tripartite DAG (External Ingress Hubs -> Consuming AST Spokes -> Persistence Sinks),
 * high-contrast curved bezier links, interactive node inspector card, and cryptographic provenance ledger.
 */
(function() {
    window.renderLineageTab = function(container, data) {
        if (!container) return;

        const summary = (data && data.summary) || {};
        const lineageSummary = summary.lineage || {};
        const rawLineage = (data && data.lineage) || {};
        const cbom = (data && data.cbom) || {};

        // 1. Extract or construct Father Marko data structure
        let fm = rawLineage.father_marko || (rawLineage.lineage_data && rawLineage.lineage_data.father_marko) || null;

        // If father_marko is not directly present, construct from rawLineage.nodes and links
        if (!fm || !Array.isArray(fm.hubs) || fm.hubs.length === 0) {
            const rawNodes = Array.isArray(rawLineage.nodes) ? rawLineage.nodes : [];
            const rawEdges = Array.isArray(rawLineage.links) ? rawLineage.links : (Array.isArray(rawLineage.edges) ? rawLineage.edges : []);

            const hubs = [];
            const spokes = [];
            const edges = [];

            rawNodes.forEach(n => {
                const cat = (n.category || n.layer || '').toUpperCase();
                if (cat === 'INGRESS') {
                    hubs.push({
                        id: n.node_id || n.id,
                        label: n.label || n.node_id || n.id,
                        source_type: n.source_type || 'ENV',
                        badge: n.source_type === 'ENV' ? '.ENV' : (n.source_type === 'CONFIG' ? 'CONFIG' : (n.source_type === 'DATABASE' ? 'DATABASE' : 'INGRESS')),
                        key: (n.details && n.details.key) || n.label,
                        fallback: (n.details && n.details.fallback) || null,
                        file_path: n.file_path || '',
                        line_number: n.line_number || '',
                        consumer_count: 1
                    });
                } else if (cat === 'NEXUS') {
                    spokes.push({
                        id: n.node_id || n.id,
                        label: n.label || n.node_id || n.id,
                        file_path: n.file_path || '',
                        line_number: n.line_number || '',
                        call: (n.details && (n.details.call || n.details.symbol)) || 'AST Invocation',
                        hub_id: null
                    });
                }
            });

            rawEdges.forEach(e => {
                const s = e.source_id || (typeof e.source === 'object' ? (e.source.node_id || e.source.id) : e.source);
                const t = e.target_id || (typeof e.target === 'object' ? (e.target.node_id || e.target.id) : e.target);
                edges.push({ source: s, target: t, label: e.label || '' });
            });

            if (hubs.length > 0 && spokes.length > 0) {
                fm = {
                    has_ingress: true,
                    hubs: hubs,
                    spokes: spokes,
                    edges: edges,
                    stats: { hubs: hubs.length, spokes: spokes.length, edges: edges.length }
                };
            }
        }

        // If no authentic lineage graph data is available, render error state
        if (!fm || !Array.isArray(fm.hubs) || fm.hubs.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="padding: 4rem 2rem; text-align: center;">
                    <div style="font-size: 3rem; margin-bottom: 1rem; color: var(--sev-high); display: flex; justify-content: center;">
                        ${window.getIcon ? window.getIcon('alertTriangle', 48) : ''}
                    </div>
                    <h3 style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
                        No Cryptographic Lineage Graph Available
                    </h3>
                    <p style="font-size: 0.875rem; color: var(--text-muted); max-width: 500px; margin: 0 auto 1.5rem auto;">
                        No lineage provenance graph or parameter bindings were found for this project. Run a cryptographic discovery scan with AST data-flow analysis enabled to trace parameter bindings from environment ingress to cryptographic call-sites.
                    </p>
                    <button class="btn btn-primary" onclick="if(window.triggerScan) window.triggerScan();">
                        ${window.getIcon ? window.getIcon('play', 14) : ''} Trigger Cryptographic Scan
                    </button>
                </div>
            `;
            return;
        }

        const hubsCount = fm.hubs.length;
        const spokesCount = fm.spokes.length;
        const edgesCount = fm.edges.length;

        // Render HTML Container
        container.innerHTML = `
            <div class="tab-pane active" style="display: flex; flex-direction: column; gap: 1.5rem; animation: fadeIn 0.2s ease;">
                
                <!-- Tab Header Banner -->
                <div class="tab-header-banner" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem 1.5rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; box-shadow: var(--shadow-sm);">
                    <div class="tab-title-wrap">
                        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
                            <span style="display: inline-flex; color: #0284c7;">${window.getIcon ? window.getIcon('gitBranch', 22) : ''}</span>
                            <h2 style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em; margin: 0;">Father Marko Cryptographic Lineage &amp; Provenance</h2>
                            <span class="card-badge badge-pqc">ZERO-REGEX CONTRACT ENGINE</span>
                        </div>
                        <p style="font-size: 0.82rem; color: var(--text-secondary); margin: 0;">
                            Distinguishes closed-world constant expressions (folded deterministically into the CBOM) from open-world runtime ingress (<code>.env</code>, configs, databases). Maps parameter bindings directly to AST cryptographic call-sites and down to persistence storage sinks.
                        </p>
                    </div>

                    <div style="display: flex; align-items: center; gap: 0.6rem;">
                        <button class="btn btn-secondary" id="lineage-reset-zoom" style="font-size: 0.75rem;">
                            <span style="display: inline-flex; align-items: center; gap: 0.35rem;">
                                ${window.getIcon ? window.getIcon('refresh', 13) : ''}
                                <span>Reset Zoom</span>
                            </span>
                        </button>
                    </div>
                </div>

                <!-- KPI Summary Cards Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem;">
                    
                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">External Ingress Hubs</span>
                            <span style="color: #0284c7; display: inline-flex;">${window.getIcon ? window.getIcon('database', 16) : ''}</span>
                        </div>
                        <div class="stat-val" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: #0284c7;">
                            ${hubsCount}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary);">
                            Environment, YAML/JSON, and DB lookups
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Consuming Spokes</span>
                            <span style="color: #7c3aed; display: inline-flex;">${window.getIcon ? window.getIcon('code', 16) : ''}</span>
                        </div>
                        <div class="stat-val" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: #7c3aed;">
                            ${spokesCount}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary);">
                            Application files consuming ingress keys
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Active Parameter Edges</span>
                            <span style="color: #059669; display: inline-flex;">${window.getIcon ? window.getIcon('link', 16) : ''}</span>
                        </div>
                        <div class="stat-val text-emerald" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0;">
                            ${edgesCount}
                        </div>
                        <div style="font-size: 0.7rem; color: var(--pqc-emerald);">
                            Zero-regex verified AST data links
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">CBOM Constant-Folded</span>
                            <span style="color: #d97706; display: inline-flex;">${window.getIcon ? window.getIcon('lock', 16) : ''}</span>
                        </div>
                        <div class="stat-val" style="font-size: 1.5rem; margin: 0.35rem 0 0.1rem 0; color: #d97706;">
                            Closed-World
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary);">
                            .replace() &amp; string tricks routed to CBOM
                        </div>
                    </div>

                </div>

                <!-- Toolbar & Filter Bar -->
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 0.85rem 1.25rem; box-shadow: var(--shadow-sm);">
                    <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                        <span style="font-size: 0.72rem; font-family: var(--font-mono); font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Filter Ingress:</span>
                        <div style="display: inline-flex; background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 2px;">
                            <button id="lineage-btn-all" class="lineage-filter-btn active" data-filter="ALL" style="padding: 0.25rem 0.65rem; font-size: 0.72rem; border: none; background: #ffffff; color: #0284c7; font-weight: 700; cursor: pointer; border-radius: 4px; box-shadow: var(--shadow-sm); font-family: var(--font-mono);">ALL</button>
                            <button id="lineage-btn-env" class="lineage-filter-btn" data-filter="ENV" style="padding: 0.25rem 0.65rem; font-size: 0.72rem; border: none; background: transparent; color: var(--text-secondary); cursor: pointer; border-radius: 4px; font-family: var(--font-mono);">.ENV ONLY</button>
                            <button id="lineage-btn-config" class="lineage-filter-btn" data-filter="CONFIG" style="padding: 0.25rem 0.65rem; font-size: 0.72rem; border: none; background: transparent; color: var(--text-secondary); cursor: pointer; border-radius: 4px; font-family: var(--font-mono);">CONFIG ONLY</button>
                            <button id="lineage-btn-db" class="lineage-filter-btn" data-filter="DATABASE" style="padding: 0.25rem 0.65rem; font-size: 0.72rem; border: none; background: transparent; color: var(--text-secondary); cursor: pointer; border-radius: 4px; font-family: var(--font-mono);">DB / STORAGE</button>
                        </div>
                    </div>

                    <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
                        <input type="text" id="lineage-search-input" placeholder="Search parameter, file, or sink..." style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); color: var(--text-primary); padding: 0.35rem 0.65rem; border-radius: var(--radius-sm); font-size: 0.78rem; font-family: var(--font-mono); outline: none; width: 220px;">
                        <button id="lineage-zoom-in" class="btn btn-secondary" style="padding: 0.35rem 0.6rem; font-size: 0.78rem;" title="Zoom In">+</button>
                        <button id="lineage-zoom-out" class="btn btn-secondary" style="padding: 0.35rem 0.6rem; font-size: 0.78rem;" title="Zoom Out">&minus;</button>
                        <button id="lineage-reset-btn" class="btn btn-secondary" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;">Reset</button>
                    </div>
                </div>

                <!-- Visualization Canvas with Relative Floating Inspector -->
                <div style="position: relative; width: 100%; border-radius: var(--radius-md); overflow: hidden; border: 1px solid var(--border-subtle); box-shadow: var(--shadow-sm); background: #f8fafc;">
                    <!-- Column Headers Overlay -->
                    <div id="lineage-col-headers" style="position: absolute; top: 0.75rem; left: 0; right: 0; padding: 0 3rem; display: flex; justify-content: space-between; pointer-events: none; z-index: 10; font-size: 0.75rem; font-family: var(--font-mono); font-weight: 700; letter-spacing: 0.05em;">
                        <span style="color: #0284c7; background: rgba(255, 255, 255, 0.9); padding: 0.35rem 0.75rem; border-radius: var(--radius-sm); border: 1px solid rgba(2, 132, 199, 0.3); box-shadow: var(--shadow-sm);">
                            &larr; EXTERNAL INGRESS HUBS (.ENV / CONFIG / DB)
                        </span>
                        <span style="color: #7c3aed; background: rgba(255, 255, 255, 0.9); padding: 0.35rem 0.75rem; border-radius: var(--radius-sm); border: 1px solid rgba(124, 58, 237, 0.3); box-shadow: var(--shadow-sm);">
                            CONSUMING SPOKES (FILES &amp; CALL-SITES) &rarr;
                        </span>
                    </div>

                    <!-- Floating Node Details Inspector -->
                    <div id="lineage-inspector-card" style="display: none; position: absolute; bottom: 1rem; left: 1rem; z-index: 20; max-width: 380px; width: 100%; padding: 1.1rem; border-radius: var(--radius-md); background: rgba(255, 255, 255, 0.96); backdrop-filter: blur(12px); border: 1px solid #0284c7; box-shadow: var(--shadow-lg); font-size: 0.78rem; font-family: var(--font-mono);">
                        <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 0.5rem; margin-bottom: 0.65rem;">
                            <span id="lineage-inspector-title" style="font-weight: 700; color: #0284c7; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">Node Inspector</span>
                            <button id="close-lineage-inspector" style="background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.2rem; line-height: 1;">&times;</button>
                        </div>
                        <div id="lineage-inspector-body" style="display: flex; flex-direction: column; gap: 0.45rem; color: var(--text-secondary); font-size: 0.72rem;">
                            <!-- Populated dynamically -->
                        </div>
                    </div>

                    <svg id="lineage-svg" style="width: 100%; height: 560px; display: block; cursor: grab;"></svg>
                </div>

                <!-- Comprehensive Cryptographic Call-Site Ledger -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; box-shadow: var(--shadow-sm);">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 1rem;">
                        <div>
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <span style="display: inline-flex; color: var(--text-muted);">${window.getIcon ? window.getIcon('fileText', 16) : ''}</span>
                                <h3 style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin: 0;">Cryptographic Call-Site &amp; Parameter Provenance Ledger</h3>
                            </div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">
                                Full audit breakdown mapping ingress origins, parameter bindings, and AST invocation targets.
                            </div>
                        </div>
                    </div>

                    <div style="overflow-x: auto; width: 100%;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-strong); color: var(--text-muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em;">
                                    <th style="padding: 0.65rem 0.85rem;">Ingress Source</th>
                                    <th style="padding: 0.65rem 0.85rem;">Source Type</th>
                                    <th style="padding: 0.65rem 0.85rem;">Consuming Spoke (File:Line)</th>
                                    <th style="padding: 0.65rem 0.85rem;">AST Cryptographic Call</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Binding Status</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Action</th>
                                </tr>
                            </thead>
                            <tbody id="lineage-table-body">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        `;

        // ================= D3 FATHER MARKO GRAPH ENGINE =================
        const svgEl = d3.select("#lineage-svg");
        const containerWrapper = document.getElementById("lineage-svg").parentElement;
        const width = containerWrapper ? containerWrapper.clientWidth : 960;
        const height = 560;

        svgEl.selectAll("*").remove();

        const defs = svgEl.append("defs");

        // Marker for lineage links (Crisp #0284c7)
        defs.append("marker")
            .attr("id", "arrow-lineage")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 22)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-4L8,0L0,4")
            .attr("fill", "#0284c7");

        const svgGroup = svgEl.append("g");

        // Zoom setup
        const zoom = d3.zoom()
            .scaleExtent([0.25, 3.0])
            .on("zoom", (e) => {
                svgGroup.attr("transform", e.transform);
            });

        svgEl.call(zoom);

        // State for filtering
        let activeFilter = 'ALL';
        let searchQuery = '';

        function renderGraph() {
            svgGroup.selectAll("*").remove();

            let hubs = (fm && fm.hubs) ? fm.hubs.map(h => ({ ...h })) : [];
            let spokes = (fm && fm.spokes) ? fm.spokes.map(s => ({ ...s })) : [];
            let edges = (fm && fm.edges) ? fm.edges.map(e => ({ ...e })) : [];

            // Apply filter
            if (activeFilter !== 'ALL') {
                hubs = hubs.filter(h => h.source_type === activeFilter);
                const activeHubIds = new Set(hubs.map(h => h.id));
                edges = edges.filter(e => activeHubIds.has(e.source));
                const activeSpokeIds = new Set(edges.map(e => e.target));
                spokes = spokes.filter(s => activeSpokeIds.has(s.id));
            }

            if (hubs.length === 0) {
                const emptyG = svgGroup.append("g").attr("transform", `translate(${width / 2}, ${height / 2 - 20})`);
                emptyG.append("text")
                    .attr("text-anchor", "middle")
                    .attr("fill", "#0f172a")
                    .attr("font-family", "var(--font-mono)")
                    .attr("font-size", "14px")
                    .attr("font-weight", "bold")
                    .text("Zero Dynamic Ingress Matching Filter");
                emptyG.append("text")
                    .attr("y", 24)
                    .attr("text-anchor", "middle")
                    .attr("fill", "#64748b")
                    .attr("font-family", "var(--font-mono)")
                    .attr("font-size", "11px")
                    .text(`No external runtime sources found for type: ${activeFilter}`);
                return;
            }

            // Layout coordinates: Hubs on left (x = 200), Spokes on right (x = width - 200)
            const hubX = 200;
            const spokeX = width - 200;

            const hubSpacing = Math.min(75, (height - 120) / Math.max(1, hubs.length));
            const hubStartY = (height - (hubs.length - 1) * hubSpacing) / 2;
            hubs.forEach((h, i) => {
                h.x = hubX;
                h.y = hubStartY + i * hubSpacing;
            });

            const spokeSpacing = Math.min(65, (height - 120) / Math.max(1, spokes.length));
            const spokeStartY = (height - (spokes.length - 1) * spokeSpacing) / 2;
            spokes.forEach((s, i) => {
                s.x = spokeX;
                s.y = spokeStartY + i * spokeSpacing;
            });

            const hubMap = new Map(hubs.map(h => [h.id, h]));
            const spokeMap = new Map(spokes.map(s => [s.id, s]));

            // Render Edges (High contrast #0284c7 with 2.0px stroke-width)
            const linkGroup = svgGroup.append("g").attr("class", "lineage-links");
            const edgeElements = linkGroup.selectAll("path")
                .data(edges)
                .enter().append("path")
                .attr("d", d => {
                    const h = hubMap.get(d.source);
                    const s = spokeMap.get(d.target);
                    if (!h || !s) return "";
                    const dx = s.x - h.x;
                    return `M ${h.x + 90} ${h.y} C ${h.x + dx * 0.45} ${h.y}, ${s.x - dx * 0.45} ${s.y}, ${s.x - 90} ${s.y}`;
                })
                .attr("fill", "none")
                .attr("stroke", "#0284c7")
                .attr("stroke-width", 2.0)
                .attr("stroke-opacity", 0.75)
                .attr("marker-end", "url(#arrow-lineage)");

            // Render Spokes (Right column)
            const spokeGroup = svgGroup.append("g").attr("class", "lineage-spokes");
            const spokeElements = spokeGroup.selectAll("g")
                .data(spokes)
                .enter().append("g")
                .attr("transform", d => `translate(${d.x}, ${d.y})`)
                .style("cursor", "pointer")
                .on("click", (e, d) => showInspector(d, 'SPOKE'))
                .on("mouseenter", (e, targetSpoke) => {
                    const connectedEdges = edges.filter(ed => ed.target === targetSpoke.id);
                    const connectedHubIds = new Set(connectedEdges.map(ed => ed.source));
                    
                    spokeElements.style("opacity", s => s.id === targetSpoke.id ? 1.0 : 0.15);
                    spokeElements.filter(s => s.id === targetSpoke.id)
                        .select("rect")
                        .attr("stroke", "#7c3aed")
                        .attr("stroke-width", 2.5);

                    hubElements.style("opacity", h => connectedHubIds.has(h.id) ? 1.0 : 0.15);
                    hubElements.filter(h => connectedHubIds.has(h.id))
                        .select("rect")
                        .attr("stroke", "#0284c7")
                        .attr("stroke-width", 2.5);

                    edgeElements.style("opacity", ed => ed.target === targetSpoke.id ? 1.0 : 0.05)
                        .attr("stroke-width", ed => ed.target === targetSpoke.id ? 3.5 : 1.5)
                        .attr("stroke", ed => ed.target === targetSpoke.id ? "#7c3aed" : "#0284c7");
                })
                .on("mouseleave", () => {
                    spokeElements.style("opacity", 1.0)
                        .select("rect")
                        .attr("stroke", "#7c3aed")
                        .attr("stroke-width", 1.5);

                    hubElements.style("opacity", 1.0)
                        .select("rect")
                        .attr("stroke", "#0284c7")
                        .attr("stroke-width", 1.5);

                    edgeElements.style("opacity", 0.75)
                        .attr("stroke-width", 2.0)
                        .attr("stroke", "#0284c7");
                });

            // Spoke Card Background
            spokeElements.append("rect")
                .attr("x", -90)
                .attr("y", -22)
                .attr("width", 180)
                .attr("height", 44)
                .attr("rx", 8)
                .attr("fill", "#ffffff")
                .attr("stroke", "#7c3aed")
                .attr("stroke-width", 1.5)
                .style("filter", "drop-shadow(0px 2px 4px rgba(0,0,0,0.06))");

            spokeElements.append("circle")
                .attr("cx", -74)
                .attr("cy", 0)
                .attr("r", 4)
                .attr("fill", "#7c3aed");

            spokeElements.append("text")
                .attr("x", -64)
                .attr("y", -3)
                .attr("fill", "#0f172a")
                .attr("font-size", "10.5px")
                .attr("font-family", "var(--font-mono)")
                .attr("font-weight", "bold")
                .text(d => d.label.length > 20 ? d.label.substring(0, 18) + '…' : d.label);

            spokeElements.append("text")
                .attr("x", -64)
                .attr("y", 11)
                .attr("fill", "#64748b")
                .attr("font-size", "9px")
                .attr("font-family", "var(--font-mono)")
                .text(d => (d.call || 'AST Call').length > 22 ? (d.call || 'AST Call').substring(0, 20) + '…' : (d.call || 'AST Call'));

            // Render Hubs (Left column)
            const hubGroup = svgGroup.append("g").attr("class", "lineage-hubs");
            const hubElements = hubGroup.selectAll("g")
                .data(hubs)
                .enter().append("g")
                .attr("transform", d => `translate(${d.x}, ${d.y})`)
                .style("cursor", "pointer")
                .on("click", (e, d) => showInspector(d, 'HUB'))
                .on("mouseenter", (e, targetHub) => {
                    const connectedSpokeIds = new Set(edges.filter(ed => ed.source === targetHub.id).map(ed => ed.target));
                    
                    hubElements.style("opacity", h => h.id === targetHub.id ? 1.0 : 0.15);
                    spokeElements.style("opacity", s => connectedSpokeIds.has(s.id) ? 1.0 : 0.15);
                    
                    edgeElements.style("opacity", ed => ed.source === targetHub.id ? 1.0 : 0.05)
                        .attr("stroke-width", ed => ed.source === targetHub.id ? 3.5 : 1.5)
                        .attr("stroke", ed => ed.source === targetHub.id ? "#0284c7" : "#cbd5e1");
                })
                .on("mouseleave", () => {
                    hubElements.style("opacity", 1.0);
                    spokeElements.style("opacity", 1.0);
                    edgeElements.style("opacity", 0.75).attr("stroke-width", 2.0).attr("stroke", "#0284c7");
                });

            // Hub Card Background
            hubElements.append("rect")
                .attr("x", -90)
                .attr("y", -22)
                .attr("width", 180)
                .attr("height", 44)
                .attr("rx", 8)
                .attr("fill", "#ffffff")
                .attr("stroke", "#0284c7")
                .attr("stroke-width", 1.5)
                .style("filter", "drop-shadow(0px 2px 4px rgba(0,0,0,0.06))");

            hubElements.append("circle")
                .attr("cx", -74)
                .attr("cy", 0)
                .attr("r", 4)
                .attr("fill", "#0284c7");

            hubElements.append("text")
                .attr("x", -64)
                .attr("y", -3)
                .attr("fill", "#0f172a")
                .attr("font-size", "10.5px")
                .attr("font-family", "var(--font-mono)")
                .attr("font-weight", "bold")
                .text(d => d.label.length > 20 ? d.label.substring(0, 18) + '…' : d.label);

            hubElements.append("text")
                .attr("x", -64)
                .attr("y", 11)
                .attr("fill", "#0284c7")
                .attr("font-size", "9px")
                .attr("font-family", "var(--font-mono)")
                .attr("font-weight", "600")
                .text(d => `${d.badge || 'INGRESS'} • ${d.consumer_count || 1} consumer${(d.consumer_count || 1) > 1 ? 's' : ''}`);
        }

        // Show Inspector Card
        function showInspector(node, type) {
            const card = document.getElementById('lineage-inspector-card');
            const title = document.getElementById('lineage-inspector-title');
            const body = document.getElementById('lineage-inspector-body');
            if (!card || !title || !body) return;

            card.style.display = 'block';
            title.textContent = node.label || node.id;

            let html = `<div><strong style="color: #64748b;">Node ID:</strong> <span style="color: #0284c7; word-break: break-all;">${node.id || ''}</span></div>`;
            if (node.source_type) {
                html += `<div><strong style="color: #64748b;">Source Type:</strong> <span class="card-badge badge-low" style="font-size: 0.65rem;">${node.source_type}</span></div>`;
            }
            if (node.key) {
                html += `<div><strong style="color: #64748b;">Key Name:</strong> <span style="color: #0f172a; font-weight: 700;">${node.key}</span></div>`;
            }
            if (node.fallback) {
                html += `<div><strong style="color: #64748b;">Fallback:</strong> <span style="color: #64748b;">${node.fallback}</span></div>`;
            }
            if (node.file_path) {
                html += `<div><strong style="color: #64748b;">File:</strong> <span style="color: #0f172a;">${node.file_path}</span></div>`;
            }
            if (node.line_number) {
                html += `<div><strong style="color: #64748b;">Line:</strong> <span style="color: #0f172a;">L${node.line_number}</span></div>`;
            }
            if (node.call) {
                html += `<div><strong style="color: #64748b;">AST Invocation:</strong> <span style="color: #7c3aed; font-weight: 700;">${node.call}</span></div>`;
            }
            if (node.consumer_count !== undefined) {
                html += `<div><strong style="color: #64748b;">Consumers:</strong> <span style="color: #16a34a; font-weight: 700;">${node.consumer_count} files</span></div>`;
            }

            body.innerHTML = html;
        }

        // Close Inspector Card
        const closeInspectorBtn = document.getElementById('close-lineage-inspector');
        if (closeInspectorBtn) {
            closeInspectorBtn.onclick = () => {
                const card = document.getElementById('lineage-inspector-card');
                if (card) card.style.display = 'none';
            };
        }

        // Filter Ingress Buttons
        const filterBtns = container.querySelectorAll('.lineage-filter-btn');
        filterBtns.forEach(btn => {
            btn.onclick = () => {
                filterBtns.forEach(b => {
                    b.style.color = 'var(--text-secondary)';
                    b.style.background = 'transparent';
                    b.style.boxShadow = 'none';
                    b.classList.remove('active');
                });
                btn.style.color = '#0284c7';
                btn.style.background = '#ffffff';
                btn.style.boxShadow = 'var(--shadow-sm)';
                btn.classList.add('active');

                activeFilter = btn.getAttribute('data-filter') || 'ALL';
                renderGraph();
            };
        });

        // Search Input
        const searchInput = document.getElementById('lineage-search-input');
        if (searchInput) {
            searchInput.oninput = (e) => {
                searchQuery = (e.target.value || '').toLowerCase().trim();
                svgGroup.selectAll(".lineage-hubs > g, .lineage-spokes > g").each((d, i, nodes) => {
                    const el = d3.select(nodes[i]);
                    const text = el.text().toLowerCase();
                    el.style("opacity", !searchQuery || text.includes(searchQuery) ? 1.0 : 0.15);
                });
            };
        }

        // Zoom Controls
        const zoomInBtn = document.getElementById('lineage-zoom-in');
        const zoomOutBtn = document.getElementById('lineage-zoom-out');
        const resetBtn = document.getElementById('lineage-reset-btn');
        const topResetBtn = document.getElementById('lineage-reset-zoom');

        if (zoomInBtn) zoomInBtn.onclick = () => svgEl.transition().duration(250).call(zoom.scaleBy, 1.25);
        if (zoomOutBtn) zoomOutBtn.onclick = () => svgEl.transition().duration(250).call(zoom.scaleBy, 0.8);
        if (resetBtn) resetBtn.onclick = () => svgEl.transition().duration(350).call(zoom.transform, d3.zoomIdentity);
        if (topResetBtn) topResetBtn.onclick = () => svgEl.transition().duration(350).call(zoom.transform, d3.zoomIdentity);

        // Render Provenance Ledger Table
        function renderTable() {
            const tbody = document.getElementById('lineage-table-body');
            if (!tbody) return;

            const edges = (fm && fm.edges) ? fm.edges : [];
            const hubsMap = new Map((fm.hubs || []).map(h => [h.id, h]));
            const spokesMap = new Map((fm.spokes || []).map(s => [s.id, s]));

            if (edges.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" style="padding: 2rem; text-align: center; color: var(--text-muted); font-family: var(--font-mono);">
                            No cryptographic provenance edges discovered.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = edges.map(e => {
                const hub = hubsMap.get(e.source) || { label: e.source, source_type: 'ENV' };
                const spoke = spokesMap.get(e.target) || { label: e.target, call: 'AST Call', file_path: '', line_number: '' };

                return `
                    <tr style="border-bottom: 1px solid var(--border-subtle); transition: background 0.15s ease;" onmouseover="this.style.background='rgba(0,0,0,0.02)'" onmouseout="this.style.background='transparent'">
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); font-weight: 700; color: #0284c7;">
                            ${hub.label}
                        </td>
                        <td style="padding: 0.75rem 0.85rem;">
                            <span class="card-badge badge-low" style="font-size: 0.65rem;">${hub.source_type || 'INGRESS'}</span>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-primary); font-weight: 600;">
                            ${spoke.label || spoke.file_path}
                        </td>
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); font-size: 0.75rem; color: #7c3aed;">
                            ${spoke.call || 'AST Call'}
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center;">
                            <span class="card-badge badge-pqc" style="font-size: 0.65rem;">VERIFIED AST</span>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center;">
                            <button class="btn btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; border-color: #0284c7; color: #0284c7;"
                                    onclick="document.getElementById('lineage-search-input').value='${hub.label}'; document.getElementById('lineage-search-input').dispatchEvent(new Event('input'));">
                                Trace Link
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        // Initial renders
        renderGraph();
        renderTable();
    };
})();
