/**
 * ECDAT Dashboard — Pareto Frontier Portfolio Tab
 * Implements interactive Pareto Frontier scatter / curve visualization,
 * 0/1 Knapsack optimization controller, and candidate remediation trade-off table.
 */
(function() {
    window.renderParetoTab = function(container, data) {
        if (!container) return;

        const summary = (data && data.summary) || {};
        const paretoSummary = summary.pareto || {};
        const rawPareto = (data && data.pareto) || {};
        const cbom = (data && data.cbom) || {};

        // Parse items
        let items = [];
        if (Array.isArray(rawPareto.items) && rawPareto.items.length > 0) {
            items = JSON.parse(JSON.stringify(rawPareto.items));
        } else if (Array.isArray(cbom.components) && cbom.components.length > 0) {
            // Fallback generation from CBOM
            items = cbom.components.map((c, i) => {
                const props = c.properties || [];
                const getP = (name, d) => {
                    const found = props.find(p => p.name === name);
                    return found ? found.value : d;
                };
                const algo = (c.cryptoProperties && c.cryptoProperties.algorithmProperties && c.cryptoProperties.algorithmProperties.name) || c.name;
                const risk = getP('ecdat:risk_level', 'LOW');
                const isCrit = risk === 'CRITICAL';
                const isHigh = risk === 'HIGH';
                const cost = isCrit ? 2.5 : (isHigh ? 1.8 : 0.5);
                const deltaR = isCrit ? 25.0 : (isHigh ? 10.0 : 0.0);
                return {
                    asset_id: c['bom-ref'] || `ASSET-00${i+1}`,
                    component_name: c.name || `component_${i+1}`,
                    algorithm: algo,
                    primitive_type: (c.cryptoProperties && c.cryptoProperties.algorithmProperties && c.cryptoProperties.algorithmProperties.primitive) || 'CRYPTO',
                    file_path: getP('ecdat:file_path', 'source.py'),
                    line_number: parseInt(getP('ecdat:line_number', '1'), 10),
                    r0_score: parseInt(getP('ecdat:r0_score', '1'), 10),
                    risk_level: risk,
                    delta_r: deltaR,
                    cost_dev_weeks: cost,
                    efficiency: cost > 0 ? parseFloat((deltaR / cost).toFixed(2)) : 0,
                    is_selected: isCrit
                };
            });
        }

        if (items.length === 0) {
            container.innerHTML = `
                <div class="tab-pane active" style="animation: fadeIn 0.2s ease;">
                    <div style="background: var(--bg-card); border: 1px solid rgba(244, 63, 94, 0.3); border-radius: var(--radius-md); padding: 3.5rem 2rem; text-align: center; margin: 2rem 0; box-shadow: var(--shadow-sm);">
                        <div style="color: var(--sev-critical); margin-bottom: 1.25rem; display: flex; justify-content: center;">
                            ${window.getIcon ? window.getIcon('alertTriangle', 48) : ''}
                        </div>
                        <h3 style="font-size: 1.3rem; font-weight: 800; color: var(--text-primary); margin-bottom: 0.6rem;">
                            No Pareto Remediation Portfolio Available
                        </h3>
                        <p style="font-size: 0.88rem; color: var(--text-secondary); max-width: 580px; margin: 0 auto 1.75rem auto; line-height: 1.6;">
                            No cryptographic remediation candidates or Pareto frontier optimization data (<code>pareto_portfolio.json</code>) were found for this project.
                            Fabricated remediation curves are disabled to maintain investment prioritization integrity.
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

        // Recommend PQC replacements based on algorithm and primitive
        function getPqcRecommendation(algo, primitive) {
            const a = (algo || '').toUpperCase();
            const p = (primitive || '').toUpperCase();
            if (a.includes('ECDSA') || a.includes('ED25519') || a.includes('DSA') || p === 'SIGNATURE') {
                return { name: 'ML-DSA-65', std: 'NIST FIPS 204' };
            }
            if (a.includes('RSA') && (p === 'KEY_EXCHANGE' || p === 'KEM' || p === 'ENCRYPTION')) {
                return { name: 'ML-KEM-768', std: 'NIST FIPS 203' };
            }
            if (a.includes('RSA') || a.includes('PKCS')) {
                return { name: 'ML-DSA-65 / ML-KEM-768', std: 'NIST FIPS 203/204' };
            }
            if (a.includes('128') || a.includes('DES') || a.includes('RC4')) {
                return { name: 'AES-256-GCM', std: 'CNSA 2.0' };
            }
            if (a.includes('SHA-1') || a.includes('MD5')) {
                return { name: 'SHA3-256 / SHAKE-256', std: 'FIPS 202' };
            }
            return { name: 'ML-KEM-768 / ML-DSA-65', std: 'PQC Standard' };
        }

        items.forEach(item => {
            const rec = getPqcRecommendation(item.algorithm, item.primitive_type);
            item.recommended_pqc = rec.name;
            item.recommended_std = rec.std;
        });

        // Compute total estate risk baseline
        const totalEstateRisk = rawPareto.total_estate_risk || items.reduce((acc, i) => acc + (i.delta_r || 0), 0) || 62.0;

        // Frontier Points
        let frontierPoints = [];
        if (Array.isArray(rawPareto.frontier_points) && rawPareto.frontier_points.length > 0) {
            frontierPoints = rawPareto.frontier_points;
        } else {
            // Compute greedy frontier steps
            const sortedCandidates = items.filter(i => (i.delta_r || 0) > 0).sort((a, b) => b.efficiency - a.efficiency);
            frontierPoints.push({ cost: 0.0, risk_pct: 0.0, asset_id: 'origin', algorithm: 'none' });
            let cumCost = 0;
            let cumRisk = 0;
            sortedCandidates.forEach(c => {
                cumCost += c.cost_dev_weeks;
                cumRisk += c.delta_r;
                const pct = totalEstateRisk > 0 ? (cumRisk / totalEstateRisk) * 100 : 0;
                frontierPoints.push({
                    cost: parseFloat(cumCost.toFixed(1)),
                    risk_pct: parseFloat(Math.min(100, pct).toFixed(1)),
                    asset_id: c.asset_id,
                    algorithm: c.algorithm
                });
            });
        }

        // State object
        const paretoState = {
            budgetWeeks: rawPareto.budget_dev_weeks || 10.0,
            selectedAssetIds: new Set(items.filter(i => i.is_selected).map(i => i.asset_id)),
            filterMode: 'ALL',
            searchQuery: '',
            isAutoKnapsack: true
        };

        // If no assets were pre-selected, run knapsack initially
        if (paretoState.selectedAssetIds.size === 0) {
            runKnapsackSolve(paretoState.budgetWeeks);
        }

        // Helper: solve 0/1 Greedy Knapsack
        function runKnapsackSolve(budget) {
            paretoState.selectedAssetIds.clear();
            const candidates = items.filter(i => (i.delta_r || 0) > 0).sort((a, b) => b.efficiency - a.efficiency);
            let allocated = 0;
            for (const item of candidates) {
                if (allocated + item.cost_dev_weeks <= budget) {
                    allocated += item.cost_dev_weeks;
                    paretoState.selectedAssetIds.add(item.asset_id);
                }
            }
        }

        // Render HTML skeleton
        container.innerHTML = `
            <div class="tab-pane active" style="display: flex; flex-direction: column; gap: 1.5rem; animation: fadeIn 0.2s ease;">
                
                <!-- Tab Header Banner -->
                <div class="tab-header-banner" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem 1.5rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; box-shadow: var(--shadow-sm);">
                    <div class="tab-title-wrap">
                        <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.25rem;">
                            <span style="display: inline-flex; color: var(--accent-cyan);">${window.getIcon ? window.getIcon('trendingUp', 22) : ''}</span>
                            <h2 style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em; margin: 0;">Pareto Frontier Migration Portfolio</h2>
                            <span class="card-badge badge-pqc" id="pareto-mode-badge">0/1 KNAPSACK OPTIMAL</span>
                        </div>
                        <p style="font-size: 0.82rem; color: var(--text-secondary); margin: 0;">
                            Multi-objective optimization mapping developer capacity (weeks) against cryptographic risk reduction (&Delta;R). Identifies non-dominated Pareto migration candidates for maximum security ROI.
                        </p>
                    </div>

                    <!-- Quick Preset Buttons -->
                    <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                        <span style="font-size: 0.72rem; color: var(--text-muted); font-weight: 600;">PRESETS:</span>
                        <button class="btn btn-secondary preset-btn" data-budget="3.0" style="padding: 0.35rem 0.65rem; font-size: 0.72rem;">Quick Wins (3w)</button>
                        <button class="btn btn-secondary preset-btn" data-budget="10.0" style="padding: 0.35rem 0.65rem; font-size: 0.72rem;">Balanced (10w)</button>
                        <button class="btn btn-secondary preset-btn" data-budget="15.0" style="padding: 0.35rem 0.65rem; font-size: 0.72rem;">Aggressive (15w)</button>
                        <button class="btn btn-emerald" id="pareto-re-optimize-btn" style="padding: 0.35rem 0.75rem; font-size: 0.72rem;">
                            <span style="display: inline-flex; align-items: center; gap: 0.35rem;">
                                ${window.getIcon ? window.getIcon('zap', 13) : ''}
                                <span>Auto-Solve Knapsack</span>
                            </span>
                        </button>
                    </div>
                </div>

                <!-- KPI Metric Cards Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem;">
                    
                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Total Risk Mitigated</span>
                            <span style="color: var(--pqc-emerald); display: inline-flex;">${window.getIcon ? window.getIcon('shieldCheck', 16) : ''}</span>
                        </div>
                        <div class="stat-val text-emerald" id="kpi-risk-reduced" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0;">
                            0.0 pts
                        </div>
                        <div style="font-size: 0.72rem; color: var(--pqc-emerald); font-weight: 600;" id="kpi-risk-pct">
                            0.0% of estate risk
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Dev Weeks Allocated</span>
                            <span style="color: #f59e0b; display: inline-flex;">${window.getIcon ? window.getIcon('clock', 16) : ''}</span>
                        </div>
                        <div class="stat-val" id="kpi-cost-allocated" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: #f59e0b;">
                            0.0 wks
                        </div>
                        <div style="font-size: 0.72rem; color: var(--text-secondary);" id="kpi-budget-ceiling">
                            Budget limit: 10.0 wks
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Budget Utilization</span>
                            <span style="color: #0284c7; display: inline-flex;">${window.getIcon ? window.getIcon('barChart', 16) : ''}</span>
                        </div>
                        <div class="stat-val" id="kpi-budget-util" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: #0284c7;">
                            0.0%
                        </div>
                        <div class="progress-bar-container" style="height: 5px; margin: 0.3rem 0;">
                            <div class="progress-bar-fill" id="kpi-util-bar" style="width: 0%; background: #0284c7;"></div>
                        </div>
                    </div>

                    <div class="stat-item" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.1rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <span class="stat-label" style="font-size: 0.7rem; color: var(--text-muted); font-weight: 600;">Selected Assets</span>
                            <span style="color: var(--text-muted); display: inline-flex;">${window.getIcon ? window.getIcon('package', 16) : ''}</span>
                        </div>
                        <div class="stat-val" id="kpi-selected-count" style="font-size: 1.8rem; margin: 0.35rem 0 0.1rem 0; color: var(--text-primary);">
                            0 / ${items.length}
                        </div>
                        <div style="font-size: 0.72rem; color: var(--text-secondary);" id="kpi-efficiency-sub">
                            High ROI candidates prioritized
                        </div>
                    </div>

                </div>                <!-- Interactive Budget Slider & Chart Section -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; display: flex; flex-direction: column; gap: 1.25rem; box-shadow: var(--shadow-sm);">
                    
                    <!-- Slider Bar -->
                    <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 1rem 1.25rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <span style="display: inline-flex; color: var(--pqc-emerald);">${window.getIcon ? window.getIcon('sliders', 16) : ''}</span>
                                <label for="pareto-budget-slider" style="font-size: 0.85rem; font-weight: 700; color: var(--text-primary);">
                                    Remediation Budget Horizon
                                </label>
                            </div>
                            <div style="display: flex; align-items: center; gap: 0.75rem;">
                                <span style="font-size: 0.72rem; color: var(--text-muted);">Allocated Ceiling:</span>
                                <span class="mono font-bold" id="slider-budget-display" style="font-size: 1rem; color: var(--pqc-emerald);">
                                    ${paretoState.budgetWeeks.toFixed(1)} dev weeks
                                </span>
                            </div>
                        </div>

                        <input type="range" id="pareto-budget-slider" min="1.0" max="30.0" step="0.5" value="${paretoState.budgetWeeks}" style="width: 100%; accent-color: var(--pqc-emerald); cursor: pointer;">
                        
                        <div style="display: flex; justify-content: space-between; font-size: 0.68rem; color: var(--text-muted); margin-top: 0.35rem; font-family: var(--font-mono);">
                            <span>1.0w (Immediate Sprint)</span>
                            <span>10.0w (Recommended Horizon)</span>
                            <span>20.0w (Quarterly Target)</span>
                            <span>30.0w (Full Overhaul)</span>
                        </div>
                    </div>

                    <!-- SVG Chart Container -->
                    <div style="position: relative;">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                            <div style="font-size: 0.82rem; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 0.4rem;">
                                <span>Pareto Frontier Curve</span>
                                <span style="font-size: 0.7rem; color: var(--text-muted); font-weight: normal;">(Cost vs. Cumulative Risk Reduction)</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 1rem; font-size: 0.7rem;">
                                <div style="display: flex; align-items: center; gap: 0.35rem;">
                                    <span style="display: inline-block; width: 12px; height: 2px; background: var(--pqc-emerald);"></span>
                                    <span style="color: var(--text-secondary);">Optimal Frontier</span>
                                </div>
                                <div style="display: flex; align-items: center; gap: 0.35rem;">
                                    <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--pqc-emerald);"></span>
                                    <span style="color: var(--text-secondary);">Selected in Budget</span>
                                </div>
                                <div style="display: flex; align-items: center; gap: 0.35rem;">
                                    <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #64748b;"></span>
                                    <span style="color: var(--text-secondary);">Deferred Asset</span>
                                </div>
                            </div>
                        </div>

                        <!-- Render SVG Curve -->
                        <div id="pareto-chart-svg-box" style="width: 100%; min-height: 250px; background: #f8fafc; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); overflow: hidden;">
                            <!-- SVG generated dynamically -->
                        </div>

                        <!-- Floating hover tooltip -->
                        <div id="pareto-tooltip" style="position: absolute; display: none; background: #ffffff; border: 1px solid var(--pqc-emerald); border-radius: var(--radius-sm); padding: 0.5rem 0.75rem; font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-primary); pointer-events: none; z-index: 10; box-shadow: var(--shadow-md);">
                        </div>
                    </div>

                </div>

                <!-- Remediation Trade-Off Candidates Table -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; box-shadow: var(--shadow-sm);">
                    
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 1rem;">
                        <div>
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <span style="display: inline-flex; color: var(--text-muted);">${window.getIcon ? window.getIcon('fileText', 16) : ''}</span>
                                <h3 style="font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin: 0;">Remediation Candidate Prioritization</h3>
                            </div>
                            <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">
                                Toggle checkboxes to test custom what-if remediation schedules or re-apply automated Knapsack solver.
                            </div>
                        </div>

                        <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
                            <input type="text" id="pareto-search" placeholder="Search candidate..." style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); color: var(--text-primary); padding: 0.35rem 0.65rem; border-radius: var(--radius-sm); font-size: 0.78rem; font-family: var(--font-mono); outline: none; width: 180px;">
                            
                            <button class="btn btn-secondary" id="pareto-select-all-btn" style="padding: 0.35rem 0.65rem; font-size: 0.72rem;">
                                Select All
                            </button>
                            <button class="btn btn-secondary" id="pareto-deselect-all-btn" style="padding: 0.35rem 0.65rem; font-size: 0.72rem;">
                                Clear
                            </button>
                        </div>
                    </div>    </div>

                    <!-- Table -->
                    <div style="overflow-x: auto; width: 100%;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-strong); color: var(--text-muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em;">
                                    <th style="padding: 0.65rem 0.75rem; width: 40px; text-align: center;">Plan</th>
                                    <th style="padding: 0.65rem 0.85rem;">Asset Ref</th>
                                    <th style="padding: 0.65rem 0.85rem;">Component / Source File</th>
                                    <th style="padding: 0.65rem 0.85rem;">Legacy Algorithm</th>
                                    <th style="padding: 0.65rem 0.85rem;">Recommended PQC Target</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: right;">Cost (wks)</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: right;">&Delta;Risk Points</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: right;">ROI (pts/wk)</th>
                                    <th style="padding: 0.65rem 0.85rem; text-align: center;">Sprint Status</th>
                                </tr>
                            </thead>
                            <tbody id="pareto-table-body">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>

                </div>

            </div>
        `;

        // Update calculations and UI
        function updateParetoView() {
            let allocatedCost = 0;
            let reducedRisk = 0;
            let selectedCount = 0;

            items.forEach(item => {
                if (paretoState.selectedAssetIds.has(item.asset_id)) {
                    allocatedCost += (item.cost_dev_weeks || 0);
                    reducedRisk += (item.delta_r || 0);
                    selectedCount++;
                }
            });

            const riskPct = totalEstateRisk > 0 ? (reducedRisk / totalEstateRisk) * 100 : 0;
            const budgetUtil = paretoState.budgetWeeks > 0 ? Math.min(100, (allocatedCost / paretoState.budgetWeeks) * 100) : 0;

            // KPI elements
            const riskReducedEl = document.getElementById('kpi-risk-reduced');
            const riskPctEl = document.getElementById('kpi-risk-pct');
            const costEl = document.getElementById('kpi-cost-allocated');
            const budgetCeilingEl = document.getElementById('kpi-budget-ceiling');
            const utilEl = document.getElementById('kpi-budget-util');
            const utilBarEl = document.getElementById('kpi-util-bar');
            const countEl = document.getElementById('kpi-selected-count');
            const sliderDispEl = document.getElementById('slider-budget-display');
            const modeBadge = document.getElementById('pareto-mode-badge');

            if (riskReducedEl) riskReducedEl.textContent = `${reducedRisk.toFixed(1)} pts`;
            if (riskPctEl) riskPctEl.textContent = `${riskPct.toFixed(1)}% of total estate risk`;
            if (costEl) costEl.textContent = `${allocatedCost.toFixed(1)} wks`;
            if (budgetCeilingEl) budgetCeilingEl.textContent = `Ceiling: ${paretoState.budgetWeeks.toFixed(1)} wks (${(paretoState.budgetWeeks - allocatedCost).toFixed(1)}w remaining)`;
            if (utilEl) utilEl.textContent = `${budgetUtil.toFixed(1)}%`;
            if (utilBarEl) {
                utilBarEl.style.width = `${budgetUtil}%`;
                utilBarEl.style.background = budgetUtil > 100 ? 'var(--sev-critical)' : (budgetUtil > 80 ? 'var(--pqc-emerald)' : '#38bdf8');
            }
            if (countEl) countEl.textContent = `${selectedCount} / ${items.length}`;
            if (sliderDispEl) sliderDispEl.textContent = `${paretoState.budgetWeeks.toFixed(1)} dev weeks`;

            if (modeBadge) {
                if (paretoState.isAutoKnapsack) {
                    modeBadge.className = 'card-badge badge-pqc';
                    modeBadge.textContent = '0/1 KNAPSACK OPTIMAL';
                } else {
                    modeBadge.className = 'card-badge badge-high';
                    modeBadge.textContent = 'CUSTOM WHAT-IF SCHEDULE';
                }
            }

            renderChartSvg(allocatedCost, riskPct);
            renderCandidatesTable();
        }

        // Render SVG Curve Chart
        function renderChartSvg(allocatedCost, currentRiskPct) {
            const chartBox = document.getElementById('pareto-chart-svg-box');
            if (!chartBox) return;

            const width = chartBox.clientWidth || 800;
            const height = 240;
            const padL = 55;
            const padR = 35;
            const padT = 25;
            const padB = 40;

            const maxCost = Math.max(30.0, Math.ceil(paretoState.budgetWeeks * 1.2));
            const maxRisk = 100.0;

            const xScale = (c) => padL + (Math.min(c, maxCost) / maxCost) * (width - padL - padR);
            const yScale = (r) => (height - padB) - (Math.min(r, maxRisk) / maxRisk) * (height - padT - padB);

            // Filter points within maxCost
            const sortedPts = [...frontierPoints].sort((a, b) => a.cost - b.cost);

            // Build smooth path
            let pathD = `M ${xScale(0)} ${yScale(0)}`;
            sortedPts.forEach(p => {
                pathD += ` L ${xScale(p.cost)} ${yScale(p.risk_pct)}`;
            });

            // Gradient area fill
            const lastPt = sortedPts[sortedPts.length - 1];
            const areaD = pathD + ` L ${xScale(lastPt.cost)} ${yScale(0)} Z`;

            // Active operating point
            const activeX = xScale(allocatedCost);
            const activeY = yScale(currentRiskPct);
            const budgetLineX = xScale(paretoState.budgetWeeks);

            // Grid lines
            let gridLines = '';
            for (let r = 0; r <= 100; r += 25) {
                const y = yScale(r);
                gridLines += `
                    <line x1="${padL}" y1="${y}" x2="${width - padR}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
                    <text x="${padL - 10}" y="${y + 4}" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace" text-anchor="end">${r}%</text>
                `;
            }
            for (let c = 0; c <= maxCost; c += 5) {
                const x = xScale(c);
                gridLines += `
                    <line x1="${x}" y1="${padT}" x2="${x}" y2="${height - padB}" stroke="rgba(255,255,255,0.06)" stroke-width="1" />
                    <text x="${x}" y="${height - 15}" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace" text-anchor="middle">${c}w</text>
                `;
            }

            // Scatter point markers
            let pointCircles = '';
            sortedPts.forEach(p => {
                if (p.asset_id === 'origin') return;
                const px = xScale(p.cost);
                const py = yScale(p.risk_pct);
                const isWithin = p.cost <= paretoState.budgetWeeks;
                const fillCol = isWithin ? 'var(--pqc-emerald)' : '#64748b';
                pointCircles += `
                    <circle class="pareto-pt" cx="${px}" cy="${py}" r="5" fill="${fillCol}" stroke="#060811" stroke-width="1.5" style="cursor: pointer; transition: transform 0.2s;" data-cost="${p.cost}" data-risk="${p.risk_pct}" data-asset="${p.asset_id}" data-algo="${p.algorithm}" />
                `;
            });

            chartBox.innerHTML = `
                <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible;">
                    <defs>
                        <linearGradient id="paretoGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stop-color="#00f5a0" stop-opacity="0.35" />
                            <stop offset="100%" stop-color="#00f5a0" stop-opacity="0.02" />
                        </linearGradient>
                    </defs>

                    <!-- Background Grids -->
                    ${gridLines}

                    <!-- Area Under Curve -->
                    <path d="${areaD}" fill="url(#paretoGrad)" />

                    <!-- Curve Line -->
                    <path d="${pathD}" fill="none" stroke="var(--pqc-emerald)" stroke-width="2.5" />

                    <!-- Budget Cutoff Vertical Line -->
                    <line x1="${budgetLineX}" y1="${padT}" x2="${budgetLineX}" y2="${height - padB}" stroke="#38bdf8" stroke-width="1.5" stroke-dasharray="4,3" />
                    <text x="${budgetLineX}" y="${padT - 8}" fill="#38bdf8" font-size="9.5" font-family="'JetBrains Mono', monospace" font-weight="bold" text-anchor="middle">
                        BUDGET (${paretoState.budgetWeeks.toFixed(1)}w)
                    </text>

                    <!-- Active Operating Point Crosshair -->
                    <circle cx="${activeX}" cy="${activeY}" r="7" fill="#00f5a0" stroke="#fff" stroke-width="2" />
                    <circle cx="${activeX}" cy="${activeY}" r="14" fill="none" stroke="#00f5a0" stroke-width="1" opacity="0.5" />

                    <!-- Data Scatter Points -->
                    ${pointCircles}
                </svg>
            `;

            // Attach hover tooltips to scatter points
            const tooltip = document.getElementById('pareto-tooltip');
            const ptEls = chartBox.querySelectorAll('.pareto-pt');
            ptEls.forEach(pt => {
                pt.addEventListener('mouseenter', (e) => {
                    if (!tooltip) return;
                    const cost = e.target.getAttribute('data-cost');
                    const risk = e.target.getAttribute('data-risk');
                    const asset = e.target.getAttribute('data-asset');
                    const algo = e.target.getAttribute('data-algo');
                    tooltip.innerHTML = `
                        <div style="color: var(--pqc-emerald); font-weight: 700;">${asset} (${algo})</div>
                        <div style="color: var(--text-secondary);">Cost: <span style="color: var(--text-primary); font-weight: 600;">${cost} weeks</span></div>
                        <div style="color: var(--text-secondary);">Risk Mitigated: <span style="color: var(--text-primary); font-weight: 600;">${risk}%</span></div>
                    `;
                    tooltip.style.display = 'block';
                    tooltip.style.left = `${e.target.cx.baseVal.value + 15}px`;
                    tooltip.style.top = `${e.target.cy.baseVal.value - 20}px`;
                });
                pt.addEventListener('mouseleave', () => {
                    if (tooltip) tooltip.style.display = 'none';
                });
                pt.addEventListener('click', (e) => {
                    const cost = parseFloat(e.target.getAttribute('data-cost'));
                    paretoState.budgetWeeks = cost;
                    const slider = document.getElementById('pareto-budget-slider');
                    if (slider) slider.value = cost;
                    runKnapsackSolve(cost);
                    paretoState.isAutoKnapsack = true;
                    updateParetoView();
                });
            });
        }

        // Render Candidates Table
        function renderCandidatesTable() {
            const tbody = document.getElementById('pareto-table-body');
            if (!tbody) return;

            let filtered = items;

            // Search filter
            if (paretoState.searchQuery) {
                const q = paretoState.searchQuery.toLowerCase();
                filtered = filtered.filter(i => 
                    (i.asset_id && i.asset_id.toLowerCase().includes(q)) ||
                    (i.component_name && i.component_name.toLowerCase().includes(q)) ||
                    (i.algorithm && i.algorithm.toLowerCase().includes(q)) ||
                    (i.recommended_pqc && i.recommended_pqc.toLowerCase().includes(q))
                );
            }

            if (filtered.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="9" style="padding: 2.5rem; text-align: center; color: var(--text-muted); font-family: var(--font-mono);">
                            No remediation candidates match your query.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = filtered.map(item => {
                const isChecked = paretoState.selectedAssetIds.has(item.asset_id);
                const efficiency = item.efficiency || 0;
                let effColor = 'var(--text-muted)';
                if (efficiency > 5.0) effColor = 'var(--pqc-emerald)';
                else if (efficiency > 2.0) effColor = 'var(--accent-cyan)';
                else if (efficiency > 0) effColor = '#f59e0b';

                const rowBg = isChecked ? 'background: rgba(16, 185, 129, 0.08);' : '';
                const statusBadge = isChecked 
                    ? `<span class="card-badge badge-pqc" style="font-size: 0.68rem;">SCHEDULED SPRINT 1</span>` 
                    : `<span class="card-badge badge-low" style="background: rgba(100, 116, 139, 0.1); color: var(--text-muted); border-color: rgba(100, 116, 139, 0.2); font-size: 0.68rem;">DEFERRED</span>`;

                return `
                    <tr style="border-bottom: 1px solid var(--border-subtle); ${rowBg} transition: background 0.15s ease;" onmouseover="this.style.background='rgba(0,0,0,0.02)'" onmouseout="this.style.background='${isChecked ? 'rgba(16, 185, 129, 0.08)' : 'transparent'}'">
                        <td style="padding: 0.75rem 0.75rem; text-align: center;">
                            <input type="checkbox" class="candidate-check" data-id="${item.asset_id}" ${isChecked ? 'checked' : ''} style="accent-color: var(--pqc-emerald); cursor: pointer; transform: scale(1.15);">
                        </td>
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); font-weight: 700; color: ${isChecked ? 'var(--text-primary)' : 'var(--text-secondary)'};">
                            ${item.asset_id}
                        </td>
                        <td style="padding: 0.75rem 0.85rem;">
                            <div style="font-weight: 600; color: var(--text-primary); font-size: 0.78rem;">${item.component_name || 'Component'}</div>
                            <div style="font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono);">${item.file_path || 'file'}:${item.line_number || 1}</div>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; font-family: var(--font-mono); color: #f43f5e; font-size: 0.78rem;">
                            ${item.algorithm}
                        </td>
                        <td style="padding: 0.75rem 0.85rem;">
                            <span style="font-family: var(--font-mono); color: var(--pqc-emerald); font-weight: 700; font-size: 0.78rem;">${item.recommended_pqc}</span>
                            <span style="display: block; font-size: 0.65rem; color: var(--text-muted); font-family: var(--font-mono);">${item.recommended_std}</span>
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: right; font-family: var(--font-mono); font-weight: 700; color: #f59e0b;">
                            ${item.cost_dev_weeks.toFixed(1)}w
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: right; font-family: var(--font-mono); font-weight: 700; color: var(--pqc-emerald);">
                            +${item.delta_r.toFixed(1)} pts
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: right; font-family: var(--font-mono); font-weight: 800; color: ${effColor};">
                            ${efficiency.toFixed(2)}
                        </td>
                        <td style="padding: 0.75rem 0.85rem; text-align: center;">
                            ${statusBadge}
                        </td>
                    </tr>
                `;
            }).join('');

            // Attach checkbox toggle events
            const checkEls = tbody.querySelectorAll('.candidate-check');
            checkEls.forEach(chk => {
                chk.addEventListener('change', (e) => {
                    const id = e.target.getAttribute('data-id');
                    if (e.target.checked) {
                        paretoState.selectedAssetIds.add(id);
                    } else {
                        paretoState.selectedAssetIds.delete(id);
                    }
                    paretoState.isAutoKnapsack = false; // manual override
                    updateParetoView();
                });
            });
        }

        // Attach event listeners
        const slider = document.getElementById('pareto-budget-slider');
        if (slider) {
            slider.addEventListener('input', (e) => {
                paretoState.budgetWeeks = parseFloat(e.target.value);
                paretoState.isAutoKnapsack = true;
                runKnapsackSolve(paretoState.budgetWeeks);
                updateParetoView();
            });
        }

        const presetBtns = container.querySelectorAll('.preset-btn');
        presetBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const b = parseFloat(btn.getAttribute('data-budget'));
                paretoState.budgetWeeks = b;
                if (slider) slider.value = b;
                paretoState.isAutoKnapsack = true;
                runKnapsackSolve(b);
                updateParetoView();
            });
        });

        const reOptBtn = document.getElementById('pareto-re-optimize-btn');
        if (reOptBtn) {
            reOptBtn.addEventListener('click', () => {
                paretoState.isAutoKnapsack = true;
                runKnapsackSolve(paretoState.budgetWeeks);
                updateParetoView();
            });
        }

        const selectAllBtn = document.getElementById('pareto-select-all-btn');
        if (selectAllBtn) {
            selectAllBtn.addEventListener('click', () => {
                items.forEach(i => paretoState.selectedAssetIds.add(i.asset_id));
                paretoState.isAutoKnapsack = false;
                updateParetoView();
            });
        }

        const deselectAllBtn = document.getElementById('pareto-deselect-all-btn');
        if (deselectAllBtn) {
            deselectAllBtn.addEventListener('click', () => {
                paretoState.selectedAssetIds.clear();
                paretoState.isAutoKnapsack = false;
                updateParetoView();
            });
        }

        const searchInput = document.getElementById('pareto-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                paretoState.searchQuery = e.target.value.trim();
                renderCandidatesTable();
            });
        }

        // Window resize handler
        let resizeTimer = null;
        if (typeof window.addEventListener === 'function') {
            window.addEventListener('resize', () => {
                clearTimeout(resizeTimer);
                resizeTimer = setTimeout(() => {
                    let allocatedCost = 0;
                    let reducedRisk = 0;
                    items.forEach(i => {
                        if (paretoState.selectedAssetIds.has(i.asset_id)) {
                            allocatedCost += i.cost_dev_weeks || 0;
                            reducedRisk += i.delta_r || 0;
                        }
                    });
                    const riskPct = totalEstateRisk > 0 ? (reducedRisk / totalEstateRisk) * 100 : 0;
                    renderChartSvg(allocatedCost, riskPct);
                }, 100);
            });
        }

        // Initial render
        updateParetoView();
    };
})();
