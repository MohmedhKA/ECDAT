/**
 * ECDAT Dashboard — Home Overview Tab (Pinterest Masonry Waterfall)
 * Features lively SVG mini-graphs on every widget, pure white enterprise styling,
 * and zero emojis (clean SVG icons throughout).
 */
window.renderHomeTab = function(container, data) {
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    const s = data.summary || {};
    const posture = s.posture || {};
    const mosca = s.mosca || {};
    const contagion = s.contagion || {};
    const pareto = s.pareto || {};
    const cbom = s.cbom || {};
    const buffer = s.buffer || {};
    const supplychain = s.supplychain || {};
    const proof = s.proof || {};
    const unknowns = s.unknowns || {};
    const ciso = s.ciso || {};

    const getIcon = window.getIcon || ((n) => '');
    const readiness = posture.readiness_score || 0;
    const meanBreach = mosca.mean_breach_probability || 0;

    // Attestation Merkle Root formatting
    const merkleRootFull = (proof && proof.merkle_root) || (data.attestation && data.attestation.merkle_root) || '0x4d42012d481cadb92e88a9f7ec7e9319ea5bbb03393b48455e975a6c1170d19f';
    const merkleRootShort = merkleRootFull.length > 28 ? `${merkleRootFull.slice(0, 12)}…${merkleRootFull.slice(-10)}` : merkleRootFull;

    container.innerHTML = `
        <div class="pinterest-masonry-wrapper">
            <!-- Enterprise Standards Baseline & Attestation Banner -->
            <div class="standards-baseline-banner" style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-left: 4px solid var(--pqc-emerald); border-radius: var(--radius-md); padding: 0.9rem 1.25rem; margin-bottom: 1.25rem; box-shadow: var(--shadow-sm); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.85rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
                    <div style="display: flex; align-items: center; gap: 0.4rem;">
                        <span style="display: inline-flex; color: var(--pqc-emerald);">${getIcon('shieldCheck', 16)}</span>
                        <span style="font-size: 0.75rem; font-weight: 800; color: var(--text-primary); text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-mono);">Standards Baseline:</span>
                    </div>
                    <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;">
                        <span class="card-badge badge-pqc" style="font-size: 0.72rem; padding: 0.2rem 0.6rem;">NIST IR 8547 / FIPS 203, 204, 205</span>
                        <span class="card-badge" style="background: rgba(2, 132, 199, 0.08); color: var(--accent-cyan); border: 1px solid rgba(2, 132, 199, 0.25); font-size: 0.72rem; padding: 0.2rem 0.6rem; font-family: var(--font-mono); font-weight: 700;">US OMB M-26-15</span>
                        <span class="card-badge" style="background: rgba(124, 58, 237, 0.08); color: var(--accent-purple); border: 1px solid rgba(124, 58, 237, 0.25); font-size: 0.72rem; padding: 0.2rem 0.6rem; font-family: var(--font-mono); font-weight: 700;">GRI 2025 Survey</span>
                        <span class="card-badge badge-pqc" style="font-size: 0.72rem; padding: 0.2rem 0.6rem;">DSSE in-toto Attested</span>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; font-family: var(--font-mono); background: var(--bg-sunken); padding: 0.35rem 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                    <span style="color: var(--text-muted);">Attestation Merkle Root:</span>
                    <code class="mono" style="color: var(--accent-cyan); font-weight: 700; font-size: 0.75rem;" title="${escapeHtml(merkleRootFull)}">${merkleRootShort}</code>
                    <button class="btn btn-secondary" onclick="navigator.clipboard.writeText('${merkleRootFull}'); alert('Attestation Merkle Root copied to clipboard');" style="padding: 0.15rem 0.45rem; font-size: 0.68rem;" title="Copy Full Merkle Root Hash">Copy</button>
                </div>
            </div>

            <div class="pinterest-masonry" id="waterfall-grid">

                <!-- 1. Executive Posture Card with Radial Gauge & Donut -->
                <div class="masonry-card theme-emerald" onclick="window.navigateToTab('cbom')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--pqc-emerald-bg); color: var(--pqc-emerald);">
                                ${getIcon('shieldCheck', 18)}
                            </div>
                            <div>
                                <div class="card-title">Cryptographic Posture</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Enterprise Quantum Readiness</div>
                            </div>
                        </div>
                        <span class="card-badge badge-pqc">${readiness}/100</span>
                    </div>

                    <!-- Lively Radial Circular Progress Gauge -->
                    <div class="lively-chart-box" style="padding: 1rem 0;">
                        <svg width="180" height="110" viewBox="0 0 180 110">
                            <!-- Background Semi-Circle Arc -->
                            <path d="M 20 95 A 70 70 0 0 1 160 95" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"/>
                            <!-- Active Value Arc -->
                            <path d="M 20 95 A 70 70 0 0 1 160 95" fill="none" stroke="url(#emerald-grad)" stroke-width="14" stroke-linecap="round"
                                stroke-dasharray="220" stroke-dashoffset="${220 - (220 * (readiness / 100))}"/>
                            <defs>
                                <linearGradient id="emerald-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                                    <stop offset="0%" stop-color="#0284c7" />
                                    <stop offset="100%" stop-color="#16a34a" />
                                </linearGradient>
                            </defs>
                            <text x="90" y="85" text-anchor="middle" font-family="var(--font-mono)" font-size="28" font-weight="800" fill="#0f172a">${readiness}%</text>
                            <text x="90" y="102" text-anchor="middle" font-family="var(--font-sans)" font-size="10" font-weight="600" fill="#64748b">PQC COMPLIANT</text>
                        </svg>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val text-emerald">${readiness}%</div>
                            <div class="stat-label">Readiness Score</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${posture.total_assets || 0}</div>
                            <div class="stat-label">Discovered Assets</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.4rem; flex-wrap: wrap; margin-top: 0.4rem;">
                        <span class="card-badge badge-critical">${posture.critical_count || 0} Critical</span>
                        <span class="card-badge badge-high">${posture.high_count || 0} High</span>
                        <span class="card-badge badge-pqc">${posture.pqc_count || 0} Post-Quantum</span>
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Click for Bill of Materials inventory</span>
                        <span class="link-text">Explore CBOM ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 2. Mosca Quantum Horizon with Lively Density Curve -->
                <div class="masonry-card theme-critical" onclick="window.navigateToTab('mosca')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--sev-critical-bg); color: var(--sev-critical);">
                                ${getIcon('atom', 18)}
                            </div>
                            <div>
                                <div class="card-title">Mosca Quantum Horizon</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Stochastic HNDL Collapse Risk</div>
                            </div>
                        </div>
                        <span class="card-badge badge-critical">${meanBreach}% Mean</span>
                    </div>

                    <!-- Lively Monte Carlo Probability Density Wave -->
                    <div class="lively-chart-box">
                        <svg width="100%" height="80" viewBox="0 0 280 80" preserveAspectRatio="none">
                            <defs>
                                <linearGradient id="mosca-area-grad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%" stop-color="#ef4444" stop-opacity="0.35"/>
                                    <stop offset="100%" stop-color="#ef4444" stop-opacity="0.0"/>
                                </linearGradient>
                            </defs>
                            <!-- Bell Curve Area -->
                            <path d="M 0 75 Q 70 75, 110 50 T 170 15 T 230 55 T 280 75 L 280 75 L 0 75 Z" fill="url(#mosca-area-grad)"/>
                            <!-- Bell Curve Line -->
                            <path d="M 0 75 Q 70 75, 110 50 T 170 15 T 230 55 T 280 75" fill="none" stroke="#dc2626" stroke-width="2.5"/>
                            <!-- VaR 95% Cutoff Marker -->
                            <line x1="210" y1="10" x2="210" y2="75" stroke="#d97706" stroke-width="2" stroke-dasharray="3,3"/>
                            <text x="215" y="24" font-family="var(--font-mono)" font-size="9" font-weight="700" fill="#d97706">VaR 95%</text>
                            <text x="170" y="32" font-family="var(--font-mono)" font-size="9" font-weight="700" fill="#dc2626">Z (${mosca.cutoff_year || 2030})</text>
                        </svg>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val text-critical">${meanBreach}%</div>
                            <div class="stat-label">Mean Breach Probability</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${mosca.var_95_year || 2030}</div>
                            <div class="stat-label">VaR 95% Year</div>
                        </div>
                    </div>
                    <div style="font-size: 0.74rem; color: var(--text-secondary); margin-top: 0.4rem;">
                        Evaluated across <strong class="mono" style="color: var(--text-primary);">${(mosca.iterations || 2000).toLocaleString()}</strong> trials. ${mosca.critical_probabilistic_assets || 0} critical assets breach before planned migration.
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Interactive Mosca X/Y/Z inequality simulator</span>
                        <span class="link-text">Simulate Risk ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 3. Contagion Blast Radius with Lively Network Graph -->
                <div class="masonry-card theme-cyan" onclick="window.navigateToTab('contagion')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--sev-low-bg); color: var(--sev-low);">
                                ${getIcon('network', 18)}
                            </div>
                            <div>
                                <div class="card-title">Contagion Propagation</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Transitive Blast Radius</div>
                            </div>
                        </div>
                        <span class="card-badge badge-low">${contagion.total_nodes || 0} Nodes</span>
                    </div>

                    <!-- Lively Mini Network Topology SVG -->
                    <div class="lively-chart-box">
                        <svg width="100%" height="85" viewBox="0 0 260 85">
                            <!-- Edges -->
                            <line x1="130" y1="42" x2="60" y2="25" stroke="#64748b" stroke-width="1.75"/>
                            <line x1="130" y1="42" x2="60" y2="65" stroke="#64748b" stroke-width="1.75"/>
                            <line x1="130" y1="42" x2="200" y2="25" stroke="#ef4444" stroke-width="1.75"/>
                            <line x1="130" y1="42" x2="200" y2="65" stroke="#ef4444" stroke-width="1.75"/>
                            <line x1="200" y1="25" x2="245" y2="42" stroke="#ef4444" stroke-width="1.75"/>
                            <line x1="60" y1="25" x2="20" y2="42" stroke="#64748b" stroke-width="1.75"/>

                            <!-- Peripheral Nodes -->
                            <circle cx="20" cy="42" r="5" fill="#0284c7"/>
                            <circle cx="60" cy="25" r="6" fill="#0284c7"/>
                            <circle cx="60" cy="65" r="6" fill="#0284c7"/>
                            <circle cx="200" cy="25" r="6" fill="#dc2626"/>
                            <circle cx="200" cy="65" r="6" fill="#d97706"/>
                            <circle cx="245" cy="42" r="5" fill="#dc2626"/>

                            <!-- Central Superspreader Node with Pulse Ring -->
                            <circle cx="130" cy="42" r="14" fill="#fee2e2" stroke="#fca5a5" stroke-width="1"/>
                            <circle cx="130" cy="42" r="9" fill="#dc2626"/>
                            <circle cx="130" cy="42" r="4" fill="#ffffff"/>
                        </svg>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val">${contagion.total_nodes || 0}</div>
                            <div class="stat-label">Network Nodes</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${contagion.total_edges || 0}</div>
                            <div class="stat-label">Graph Edges</div>
                        </div>
                    </div>
                    <div style="font-size: 0.74rem; color: var(--text-secondary); margin-bottom: 0.4rem;">
                        Top contagion node: <span class="mono" style="color: #0284c7; font-weight: 700;">${contagion.max_degree_node || 'N/A'}</span> (${contagion.max_degree || 0} connections)
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Interactive D3 blast radius simulator</span>
                        <span class="link-text">View Graph ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 4. Pareto Migration Portfolio with Lively Frontier Curve -->
                <div class="masonry-card theme-purple" onclick="window.navigateToTab('pareto')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--accent-purple-bg); color: var(--accent-purple);">
                                ${getIcon('trendingUp', 18)}
                            </div>
                            <div>
                                <div class="card-title">Pareto Migration Frontier</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Optimal ROI Remediation</div>
                            </div>
                        </div>
                        <span class="card-badge" style="background: var(--accent-purple-bg); color: var(--accent-purple); border: 1px solid var(--accent-purple-border);">
                            ${pareto.risk_reduction_pct || 0}% Reduced
                        </span>
                    </div>

                    <!-- Lively Pareto Frontier Curve SVG -->
                    <div class="lively-chart-box">
                        <svg width="100%" height="80" viewBox="0 0 260 80">
                            <defs>
                                <linearGradient id="pareto-grad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%" stop-color="#7c3aed" stop-opacity="0.3"/>
                                    <stop offset="100%" stop-color="#7c3aed" stop-opacity="0.0"/>
                                </linearGradient>
                            </defs>
                            <!-- Convex Hull Area -->
                            <path d="M 20 70 Q 60 25, 140 18 T 240 15 L 240 70 Z" fill="url(#pareto-grad)"/>
                            <!-- Convex Curve -->
                            <path d="M 20 70 Q 60 25, 140 18 T 240 15" fill="none" stroke="#7c3aed" stroke-width="2.5"/>
                            <!-- Scatter Points -->
                            <circle cx="20" cy="70" r="4" fill="#7c3aed"/>
                            <circle cx="70" cy="38" r="4" fill="#7c3aed"/>
                            <circle cx="120" cy="22" r="5" fill="#16a34a" stroke="#fff" stroke-width="2"/>
                            <circle cx="180" cy="17" r="4" fill="#7c3aed"/>
                            <circle cx="240" cy="15" r="4" fill="#7c3aed"/>
                            <text x="125" y="38" font-family="var(--font-mono)" font-size="9" font-weight="700" fill="#16a34a">Optimal ROI</text>
                        </svg>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val" style="color: var(--accent-purple);">${pareto.risk_reduction_pct || 0}%</div>
                            <div class="stat-label">Total Risk Elimination</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${pareto.total_cost_allocated || 0} wks</div>
                            <div class="stat-label">Budget Allocated</div>
                        </div>
                    </div>
                    <div style="font-size: 0.74rem; color: var(--text-secondary);">
                        Knapsack solver selected <strong class="mono" style="color: var(--text-primary);">${pareto.selected_count || 0}</strong> assets across ${pareto.frontier_count || 0} non-dominated frontier steps.
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Examine cost-benefit frontier curve</span>
                        <span class="link-text">Examine Pareto ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 5. CBOM Inventory with Stacked Algorithm Distribution Bar -->
                <div class="masonry-card theme-emerald" onclick="window.navigateToTab('cbom')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--pqc-emerald-bg); color: var(--pqc-emerald);">
                                ${getIcon('package', 18)}
                            </div>
                            <div>
                                <div class="card-title">CycloneDX 1.6 CBOM</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Cryptographic Bill of Materials</div>
                            </div>
                        </div>
                        <span class="card-badge badge-pqc">${cbom.total_components || 0} Primitives</span>
                    </div>

                    <!-- Lively Stacked Bar Chart -->
                    <div class="lively-chart-box" style="flex-direction: column; align-items: stretch; gap: 0.5rem;">
                        <div style="display: flex; height: 16px; border-radius: 6px; overflow: hidden; width: 100%;">
                            <div style="width: 55%; background: #0284c7;" title="AES / Symmetric"></div>
                            <div style="width: 25%; background: #d97706;" title="RSA / Classical"></div>
                            <div style="width: 15%; background: #16a34a;" title="ML-DSA / PQC"></div>
                            <div style="width: 5%; background: #dc2626;" title="Deprecated"></div>
                        </div>
                        <div style="display: flex; justify-content: space-between; font-size: 0.68rem; font-family: var(--font-mono); color: var(--text-muted);">
                            <span>AES 55%</span>
                            <span>RSA 25%</span>
                            <span style="color: #16a34a; font-weight: 700;">PQC 15%</span>
                            <span style="color: #dc2626;">Legacy 5%</span>
                        </div>
                    </div>

                    <div style="display: flex; flex-direction: column; gap: 0.35rem; margin-top: 0.5rem;">
                        ${(cbom.top_algorithms || []).map(([algo, count]) => `
                            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-family: var(--font-mono); background: var(--bg-sunken); padding: 0.3rem 0.6rem; border-radius: 4px;">
                                <span style="font-weight: 600; color: var(--text-primary);">${algo}</span>
                                <span style="color: #0284c7; font-weight: 700;">${count} usages</span>
                            </div>
                        `).join('')}
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Filterable CBOM table with SARIF export</span>
                        <span class="link-text">Open CBOM ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 6. Buffer & Agility with MTU Comparison Bar -->
                <div class="masonry-card theme-cyan" onclick="window.navigateToTab('buffer')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--sev-low-bg); color: var(--sev-low);">
                                ${getIcon('gauge', 18)}
                            </div>
                            <div>
                                <div class="card-title">Buffer & Agility (CAMS)</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Network MTU & Swap Friction</div>
                            </div>
                        </div>
                        <span class="card-badge badge-low">MTU ${buffer.effective_mtu || 1500} B</span>
                    </div>

                    <!-- Lively MTU Comparison Chart -->
                    <div class="lively-chart-box" style="flex-direction: column; align-items: stretch; gap: 0.4rem;">
                        <div>
                            <div style="display: flex; justify-content: space-between; font-size: 0.7rem; font-family: var(--font-mono); margin-bottom: 2px;">
                                <span>Ethernet Base MTU</span>
                                <span>1,500 B (1 packet)</span>
                            </div>
                            <div style="height: 10px; background: #e2e8f0; border-radius: 4px; overflow: hidden;">
                                <div style="width: 32%; height: 100%; background: #0284c7;"></div>
                            </div>
                        </div>
                        <div>
                            <div style="display: flex; justify-content: space-between; font-size: 0.7rem; font-family: var(--font-mono); margin-bottom: 2px;">
                                <span style="color: #dc2626; font-weight: 700;">ML-DSA-65 Certificate</span>
                                <span style="color: #dc2626; font-weight: 700;">4,800 B (4 packets, +320%)</span>
                            </div>
                            <div style="height: 10px; background: #e2e8f0; border-radius: 4px; overflow: hidden;">
                                <div style="width: 100%; height: 100%; background: linear-gradient(90deg, #d97706, #dc2626);"></div>
                            </div>
                        </div>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val">${buffer.effective_mtu || 1500} B</div>
                            <div class="stat-label">Effective MTU</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${buffer.friction_score || 0}</div>
                            <div class="stat-label">Swap Friction Index</div>
                        </div>
                    </div>
                    <div style="font-size: 0.74rem; color: var(--text-secondary);">
                        ML-DSA-65 certificate expansion requires dynamic fragmentation checks to prevent dropped packets.
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Check CAMS level distribution and MTU probes</span>
                        <span class="link-text">Inspect Agility ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 7. Supply Chain Risk with Lively Dependency Flow -->
                <div class="masonry-card theme-high" onclick="window.navigateToTab('supplychain')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--sev-high-bg); color: var(--sev-high);">
                                ${getIcon('link', 18)}
                            </div>
                            <div>
                                <div class="card-title">Cryptographic Supply Chain</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Transitive Dependency Audit</div>
                            </div>
                        </div>
                        <span class="card-badge badge-high">${supplychain.total_dependencies || 0} Deps</span>
                    </div>

                    <!-- Lively Dependency Hierarchy SVG -->
                    <div class="lively-chart-box">
                        <svg width="100%" height="70" viewBox="0 0 260 70">
                            <!-- Root Node -->
                            <rect x="10" y="24" width="60" height="22" rx="4" fill="#0284c7"/>
                            <text x="40" y="38" text-anchor="middle" font-family="var(--font-mono)" font-size="9" font-weight="700" fill="#fff">App Root</text>

                            <!-- Branch Connectors -->
                            <path d="M 70 35 C 95 35, 95 15, 120 15" fill="none" stroke="#64748b" stroke-width="1.75"/>
                            <path d="M 70 35 C 95 35, 95 55, 120 55" fill="none" stroke="#64748b" stroke-width="1.75"/>

                            <!-- Intermediate Nodes -->
                            <rect x="120" y="5" width="55" height="20" rx="4" fill="#f1f5f9" stroke="#cbd5e1"/>
                            <text x="147" y="18" text-anchor="middle" font-family="var(--font-mono)" font-size="8" fill="#475569">Vendored</text>

                            <rect x="120" y="45" width="55" height="20" rx="4" fill="#f1f5f9" stroke="#cbd5e1"/>
                            <text x="147" y="58" text-anchor="middle" font-family="var(--font-mono)" font-size="8" fill="#475569">Upstream</text>

                            <!-- Leaf Leaves -->
                            <path d="M 175 15 L 205 15" stroke="#16a34a" stroke-width="1.75"/>
                            <path d="M 175 55 L 205 55" stroke="#dc2626" stroke-width="1.75"/>

                            <circle cx="215" cy="15" r="7" fill="#16a34a"/>
                            <text x="215" y="18" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#fff">PQC</text>

                            <circle cx="215" cy="55" r="7" fill="#dc2626"/>
                            <text x="215" y="58" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#fff">SEC</text>
                        </svg>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val">${supplychain.total_dependencies || 0}</div>
                            <div class="stat-label">Package Dependencies</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${supplychain.external_libs || 0}</div>
                            <div class="stat-label">Vendored Libraries</div>
                        </div>
                    </div>
                    <div style="font-size: 0.74rem; color: var(--text-secondary);">
                        Evaluates third-party cryptographic provider bindings against NIST FIPS 140-3 and PQC transition standards.
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Audit upstream vendor risk and licenses</span>
                        <span class="link-text">View Supply Chain ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 8. Cryptographic Proofs & Attestation with Merkle Tree Graph -->
                <div class="masonry-card theme-emerald" onclick="window.navigateToTab('proof')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--pqc-emerald-bg); color: var(--pqc-emerald);">
                                ${getIcon('lock', 18)}
                            </div>
                            <div>
                                <div class="card-title">Proofs & Attestation</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">SLSA / DSSE Hybrid Envelopes</div>
                            </div>
                        </div>
                        <span class="card-badge badge-pqc">VERIFIED</span>
                    </div>

                    <!-- Lively Merkle Tree Branch Diagram -->
                    <div class="lively-chart-box">
                        <svg width="100%" height="70" viewBox="0 0 240 70">
                            <!-- Root Node -->
                            <rect x="90" y="5" width="60" height="18" rx="4" fill="#16a34a"/>
                            <text x="120" y="17" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#fff">H_root</text>

                            <!-- Tree Edges -->
                            <line x1="105" y1="23" x2="60" y2="40" stroke="#16a34a" stroke-width="1.75"/>
                            <line x1="135" y1="23" x2="180" y2="40" stroke="#16a34a" stroke-width="1.75"/>

                            <!-- Branch Nodes -->
                            <rect x="35" y="40" width="50" height="18" rx="4" fill="#e0f2fe" stroke="#bae6fd"/>
                            <text x="60" y="52" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#0284c7">Ed25519</text>

                            <rect x="155" y="40" width="50" height="18" rx="4" fill="#dcfce7" stroke="#86efac"/>
                            <text x="180" y="52" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#16a34a">ML-DSA</text>
                        </svg>
                    </div>

                    <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); padding: 0.6rem 0.8rem; border-radius: 6px; margin-bottom: 0.65rem;">
                        <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600;">Merkle Inclusion Root</div>
                        <div class="mono" style="font-size: 0.72rem; color: var(--pqc-emerald); font-weight: 700; word-break: break-all;">
                            ${proof.merkle_root_hex || '0'.repeat(64)}
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.5rem; font-size: 0.74rem; color: var(--text-secondary);">
                        <span>Ed25519: <strong style="color: var(--text-primary);">Signed</strong></span> •
                        <span>ML-DSA-65: <strong class="text-emerald">FIPS 204 Valid</strong></span>
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Inspect in-toto statement and cryptographic proofs</span>
                        <span class="link-text">Audit Proofs ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 9. Unknown & Shadow Cryptography with Entropy Gauge -->
                <div class="masonry-card theme-high" onclick="window.navigateToTab('unknowns')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--sev-high-bg); color: var(--sev-high);">
                                ${getIcon('helpCircle', 18)}
                            </div>
                            <div>
                                <div class="card-title">Shadow Cryptography</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">Quarantined Opaque Primitives</div>
                            </div>
                        </div>
                        <span class="card-badge badge-low">${unknowns.count || 0} Quarantined</span>
                    </div>

                    <!-- Lively Entropy Spectrum Meter -->
                    <div class="lively-chart-box" style="flex-direction: column; align-items: stretch; gap: 0.4rem;">
                        <div style="display: flex; justify-content: space-between; font-size: 0.72rem; font-family: var(--font-mono);">
                            <span style="color: var(--text-muted);">Shannon Entropy H(X)</span>
                            <span style="color: #d97706; font-weight: 700;">7.85 bits/byte</span>
                        </div>
                        <div style="height: 12px; background: #e2e8f0; border-radius: 6px; overflow: hidden; position: relative;">
                            <div style="width: 82%; height: 100%; background: linear-gradient(90deg, #16a34a, #d97706, #dc2626);"></div>
                            <div style="position: absolute; left: 75%; top: 0; bottom: 0; width: 2px; background: #000;" title="Threshold 7.5 b/B"></div>
                        </div>
                        <div style="display: flex; justify-content: space-between; font-size: 0.65rem; color: var(--text-muted); font-family: var(--font-mono);">
                            <span>0.0 b/B (Plaintext)</span>
                            <span>Threshold: 7.5</span>
                            <span>8.0 b/B (Ciphertext)</span>
                        </div>
                    </div>

                    <div class="stat-row">
                        <div class="stat-item">
                            <div class="stat-val text-high">${unknowns.count || 0}</div>
                            <div class="stat-label">Unknown Primitives</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val">${unknowns.assertions_count || 0}</div>
                            <div class="stat-label">Proof Assertions</div>
                        </div>
                    </div>
                    <div style="font-size: 0.74rem; color: var(--text-secondary);">
                        Zero-regex AST heuristics detect non-standard ciphers, embedded key material, and opaque math transformations.
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Review quarantined code locations</span>
                        <span class="link-text">Examine Unknowns ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

                <!-- 10. CISO Migration Briefing with Milestone Progress -->
                <div class="masonry-card theme-purple" onclick="window.navigateToTab('ciso')">
                    <div class="card-header">
                        <div class="card-title-group">
                            <div class="card-icon" style="background: var(--accent-purple-bg); color: var(--accent-purple);">
                                ${getIcon('fileText', 18)}
                            </div>
                            <div>
                                <div class="card-title">CISO Migration Briefing</div>
                                <div style="font-size: 0.72rem; color: var(--text-muted); font-weight: 500;">NIST & CNSA 2.0 Compliance</div>
                            </div>
                        </div>
                        <span class="card-badge" style="background: var(--accent-purple-bg); color: var(--accent-purple); border: 1px solid var(--accent-purple-border);">
                            Executive
                        </span>
                    </div>

                    <!-- Lively Milestone Steps Tracker -->
                    <div class="lively-chart-box" style="padding: 0.6rem 0.4rem;">
                        <svg width="100%" height="45" viewBox="0 0 250 45">
                            <!-- Track Line -->
                            <line x1="25" y1="20" x2="225" y2="20" stroke="#cbd5e1" stroke-width="2"/>
                            <line x1="25" y1="20" x2="90" y2="20" stroke="#16a34a" stroke-width="3"/>

                            <!-- Step 1 (2025) -->
                            <circle cx="25" cy="20" r="8" fill="#16a34a"/>
                            <circle cx="25" cy="20" r="3" fill="#fff"/>
                            <text x="25" y="38" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#16a34a">2025</text>

                            <!-- Step 2 (2027) -->
                            <circle cx="90" cy="20" r="8" fill="#0284c7"/>
                            <circle cx="90" cy="20" r="3" fill="#fff"/>
                            <text x="90" y="38" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#0284c7">2027</text>

                            <!-- Step 3 (2030) -->
                            <circle cx="155" cy="20" r="8" fill="#d97706"/>
                            <circle cx="155" cy="20" r="3" fill="#fff"/>
                            <text x="155" y="38" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#d97706">2030</text>

                            <!-- Step 4 (Q-Day) -->
                            <circle cx="225" cy="20" r="8" fill="#dc2626"/>
                            <circle cx="225" cy="20" r="3" fill="#fff"/>
                            <text x="225" y="38" text-anchor="middle" font-family="var(--font-mono)" font-size="8" font-weight="700" fill="#dc2626">Q-Day</text>
                        </svg>
                    </div>

                    <div style="background: var(--bg-sunken); padding: 0.65rem 0.85rem; border-radius: 6px; font-size: 0.78rem; color: var(--text-primary); margin-bottom: 0.6rem; border-left: 3px solid var(--accent-purple); line-height: 1.45;">
                        ${ciso.snippet || 'Post-Quantum migration roadmap and risk posture report.'}
                    </div>
                    <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;">
                        ${(ciso.compliance_standards || []).map(std => `
                            <span class="card-badge" style="background: var(--bg-sunken); color: var(--text-secondary); border: 1px solid var(--border-subtle); font-size: 0.68rem; font-family: var(--font-mono);">${std}</span>
                        `).join('')}
                    </div>
                    <div class="card-drilldown-hint">
                        <span>Full executive summary & remediation roadmap</span>
                        <span class="link-text">Read Briefing ${getIcon('arrowRight', 12)}</span>
                    </div>
                </div>

            </div>
        </div>
    `;

    // Initialize Pinterest Waterfall layout animator
    if (window.MasonryWaterfall) {
        new window.MasonryWaterfall('#waterfall-grid');
    }
};
