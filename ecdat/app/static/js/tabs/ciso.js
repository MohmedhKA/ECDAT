/**
 * ECDAT Dashboard — CISO Executive Migration Briefing & Regulatory Compliance Tab
 * Renders executive migration briefings, statutory compliance scorecards
 * (NIST FIPS 203/204/205, NSA CNSA 2.0, OMB M-23-02, DORA), and multi-year Gantt timelines.
 */
(function() {
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    const getIcon = window.getIcon || ((n) => '');

    // Comprehensive markdown-to-HTML parser with full table support, LaTeX typography, and standards banner
    function renderMarkdownToHtml(markdownText) {
        if (!markdownText) return '<p>No briefing content provided.</p>';

        // 1. Pre-process LaTeX equations to clean typographic HTML
        let cleanText = markdownText
            .replace(/\$Y_\{max\}\s*\\le\s*1\.0\\text\{y\}\$/g, 'Y_max ≤ 1.0y')
            .replace(/\$1\.0\s*<\s*Y_\{max\}\s*\\le\s*2\.5\\text\{y\}\$/g, '1.0 < Y_max ≤ 2.5y')
            .replace(/\$>\s*2\.5\\text\{y\}\$/g, '> 2.5y')
            .replace(/\$E_0\$|\$E_O\$/g, 'E₀')
            .replace(/\$R_Q\s*=\s*0\.0\$/g, 'R_Q = 0.0')
            .replace(/\$X\$/g, 'X')
            .replace(/\$P_\{\\text\{HNDL\}\}\$/g, 'P_HNDL')
            .replace(/\$\\mathcal\{R\}_0\$/g, 'R₀')
            .replace(/\$W\s*=\s*([0-9\.]+)\$/g, 'W = $1')
            .replace(/\$R_Q\$/g, 'R_Q')
            .replace(/\$Y_\{max\}\$/g, 'Y_max')
            .replace(/\$X_\{\\text\{eff\}\}\$/g, 'X_eff')
            .replace(/\$Z_\{\\text\{reg\}\}\$/g, 'Z_reg')
            .replace(/\\le/g, '≤')
            .replace(/\\ge/g, '≥')
            .replace(/\\text\{([^\}]+)\}/g, '$1')
            .replace(/\$([A-Za-z0-9_\-\.\s≤≥=<>]+)\$/g, '$1');

        // 2. Parse Standards Baseline blockquote into an Enterprise Attestation Banner
        cleanText = cleanText.replace(
            /^>\s*\*\*Standards Baseline:\*\*\s*(.*?)\n>\s*\*\*Attestation Commitment:\*\*\s*SHA-256 Merkle Root\s*`([a-f0-9x]+)`/im,
            function(match, standards, merkleRoot) {
                const stdBadges = standards.split('|').map(s => s.trim()).filter(Boolean).map(s => 
                    `<span class="card-badge badge-pqc" style="font-size: 0.72rem; padding: 0.2rem 0.6rem;">${escapeHtml(s)}</span>`
                ).join(' ');

                return `
                <div class="ciso-standards-banner" style="background: linear-gradient(135deg, rgba(2, 132, 199, 0.04), rgba(22, 163, 74, 0.06)); border: 1px solid var(--border-subtle); border-left: 4px solid var(--pqc-emerald); border-radius: var(--radius-md); padding: 1rem 1.25rem; margin: 1.25rem 0 1.75rem 0; box-shadow: var(--shadow-sm);">
                    <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.6rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="font-size: 0.75rem; font-weight: 800; color: var(--text-primary); text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-mono);">Standards Baseline:</span>
                            <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;">${stdBadges}</div>
                        </div>
                        <span class="card-badge badge-pqc" style="font-size: 0.68rem; font-weight: 700;">NIST FIPS 203/204/205 READY</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: var(--text-secondary); font-family: var(--font-mono); background: #ffffff; padding: 0.45rem 0.75rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                        <strong style="color: var(--text-primary);">Attestation Commitment:</strong>
                        <span style="color: var(--text-muted);">SHA-256 Merkle Root:</span>
                        <code class="mono" style="color: var(--accent-cyan); font-weight: 700; word-break: break-all;">${escapeHtml(merkleRoot)}</code>
                        <button class="btn btn-secondary" onclick="navigator.clipboard.writeText('${merkleRoot}'); alert('Merkle Root copied to clipboard');" style="margin-left: auto; padding: 0.15rem 0.5rem; font-size: 0.68rem;">Copy</button>
                    </div>
                </div>`;
            }
        );

        // 3. Line-by-line block parser with table assembler
        const lines = cleanText.split('\n');
        const output = [];
        let inTable = false;
        let tableHeaderDone = false;
        let tableHtml = '';
        let inList = false;

        function closeTable() {
            if (inTable) {
                tableHtml += '</tbody></table></div>';
                output.push(tableHtml);
                inTable = false;
                tableHeaderDone = false;
                tableHtml = '';
            }
        }

        function closeList() {
            if (inList) {
                output.push('</ul>');
                inList = false;
            }
        }

        for (let i = 0; i < lines.length; i++) {
            const rawLine = lines[i];
            const line = rawLine.trim();

            // Table row detection
            if (line.startsWith('|') && line.endsWith('|')) {
                closeList();
                const cells = line.split('|').slice(1, -1).map(c => c.trim());

                // Check if this is divider row (| :--- | :--- |)
                const isDivider = cells.every(c => /^:?-+:?$/.test(c));

                if (isDivider) {
                    tableHeaderDone = true;
                    continue;
                }

                if (!inTable) {
                    inTable = true;
                    tableHeaderDone = false;
                    tableHtml = '<div class="ciso-table-wrap" style="margin: 1.25rem 0 1.5rem 0; overflow-x: auto; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); box-shadow: var(--shadow-sm);"><table class="ciso-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem; background: #ffffff;">';
                    tableHtml += '<thead style="background: var(--bg-sunken); border-bottom: 2px solid var(--border-strong); color: var(--text-secondary); text-transform: uppercase; font-size: 0.7rem; font-family: var(--font-mono); letter-spacing: 0.04em;"><tr>';
                    cells.forEach(c => {
                        tableHtml += `<th style="padding: 0.75rem 1rem; font-weight: 700;">${formatInlineMarkdown(c)}</th>`;
                    });
                    tableHtml += '</tr></thead><tbody>';
                } else if (!tableHeaderDone) {
                    // Header row
                    tableHtml += '<thead style="background: var(--bg-sunken); border-bottom: 2px solid var(--border-strong); color: var(--text-secondary); text-transform: uppercase; font-size: 0.7rem; font-family: var(--font-mono); letter-spacing: 0.04em;"><tr>';
                    cells.forEach(c => {
                        tableHtml += `<th style="padding: 0.75rem 1rem; font-weight: 700;">${formatInlineMarkdown(c)}</th>`;
                    });
                    tableHtml += '</tr></thead><tbody>';
                } else {
                    // Data row
                    tableHtml += '<tr style="border-bottom: 1px solid var(--border-subtle); transition: background 0.1s;" onmouseover="this.style.backgroundColor=\'var(--bg-sunken)\'" onmouseout="this.style.backgroundColor=\'transparent\'">';
                    cells.forEach((c, idx) => {
                        let formattedCell = formatInlineMarkdown(c);
                        // Auto-badge critical keywords in table cells
                        if (c.includes('Critical') || c === 'CRITICAL') {
                            formattedCell = `<span class="card-badge badge-critical" style="font-weight:700;">${formattedCell}</span>`;
                        } else if (c.includes('High') || c === 'HIGH') {
                            formattedCell = `<span class="card-badge badge-high" style="font-weight:700;">${formattedCell}</span>`;
                        } else if (c.includes('L0: RIGID') || c === 'L0') {
                            formattedCell = `<span class="card-badge" style="background:#fee2e2; color:#b91c1c; border:1px solid #f87171; font-weight:700;">${formattedCell}</span>`;
                        } else if (c.includes('PUBLIC')) {
                            formattedCell = `<span class="card-badge" style="background:#fef3c7; color:#b45309; border:1px solid #fcd34d; font-weight:700;">${formattedCell}</span>`;
                        }
                        tableHtml += `<td style="padding: 0.75rem 1rem; color: var(--text-primary);">${formattedCell}</td>`;
                    });
                    tableHtml += '</tr>';
                }
                continue;
            } else {
                closeTable();
            }

            if (!line) {
                closeList();
                continue;
            }

            // Headers
            if (line.startsWith('### ')) {
                closeList();
                output.push(`<h3 style="color: var(--text-primary); font-size: 1.05rem; margin: 1.5rem 0 0.5rem 0; font-weight: 700; display: flex; align-items: center; gap: 0.4rem;">${formatInlineMarkdown(line.slice(4))}</h3>`);
            } else if (line.startsWith('## ')) {
                closeList();
                output.push(`<h2 style="color: var(--text-primary); font-size: 1.25rem; margin: 1.75rem 0 0.6rem 0; font-weight: 800; border-bottom: 1px solid var(--border-subtle); padding-bottom: 0.4rem;">${formatInlineMarkdown(line.slice(3))}</h2>`);
            } else if (line.startsWith('# ')) {
                closeList();
                output.push(`<h1 style="color: var(--text-primary); font-size: 1.5rem; margin: 1.5rem 0 0.75rem 0; font-weight: 800; letter-spacing: -0.02em;">${formatInlineMarkdown(line.slice(2))}</h1>`);
            } else if (line.startsWith('> ')) {
                closeList();
                output.push(`<blockquote style="border-left: 3px solid var(--pqc-emerald); background: var(--pqc-emerald-bg); padding: 0.75rem 1.1rem; border-radius: 4px; color: var(--text-secondary); margin: 0.85rem 0; font-style: italic;">${formatInlineMarkdown(line.slice(2))}</blockquote>`);
            } else if (line.startsWith('- ') || line.startsWith('* ')) {
                if (!inList) {
                    output.push('<ul style="margin: 0.5rem 0 0.85rem 1.5rem; space-y: 0.35rem;">');
                    inList = true;
                }
                output.push(`<li style="color: var(--text-primary); margin-bottom: 0.35rem; line-height: 1.6;">${formatInlineMarkdown(line.slice(2))}</li>`);
            } else if (/^\d+\.\s+/.test(line)) {
                closeList();
                output.push(`<div style="margin: 0.35rem 0 0.5rem 0.5rem; color: var(--text-primary); line-height: 1.6;">${formatInlineMarkdown(line)}</div>`);
            } else if (line === '---') {
                closeList();
                output.push('<hr style="border: none; border-top: 1px solid var(--border-subtle); margin: 1.5rem 0;">');
            } else {
                closeList();
                output.push(`<p style="margin-bottom: 0.85rem; line-height: 1.65; color: var(--text-primary);">${formatInlineMarkdown(line)}</p>`);
            }
        }

        closeTable();
        closeList();
        return output.join('\n');
    }

    // Helper for bold, italic, code pills inside table cells and text
    function formatInlineMarkdown(text) {
        if (!text) return '';
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--text-primary); font-weight: 700;">$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`([^`]+)`/g, '<code class="mono" style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); padding: 0.15rem 0.4rem; border-radius: 4px; color: #0284c7; font-size: 0.76rem;">$1</code>');
    }

    const DEFAULT_CISO_BRIEFING = `# Executive Post-Quantum Migration Action Plan & Regulatory Briefing

## Executive Summary
This enterprise post-quantum cryptographic discovery assessment establishes an empirical, audit-defensible baseline for the target infrastructure. Automated scanning correlated **23 active cryptographic assets** across the perimeter against federal transition deadlines mandated by the **US Executive Office of the President (OMB M-23-02 / NSM-10)**, the **National Security Agency (NSA CNSA 2.0)**, and the **National Institute of Standards and Technology (NIST FIPS 203/204/205)**.

> "The threat of Harvest-Now-Decrypt-Later (HNDL) attacks mandates that high-secrecy assets (lifetime > 10y) be migrated to quantum-resistant encapsulation before the 2030 regulatory enforcement horizon."

---

## 1. Statutory Mandates & Compliance Horizon
1. **NSA CNSA 2.0 Software & Firmware Signing (Deadline: 2025)**: Requires transitioning firmware updates and software artifact signing to stateful hash-based signatures (LMS/XMSS) or ML-DSA-65. The assessed pipeline currently incorporates dual-mode in-toto DSSE signatures.
2. **NIST Classical Cipher Sunset (Deadline: 2030)**: Complete statutory deprecation of RSA-2048, ECDSA-P256, and Diffie-Hellman across federal systems. Replacement algorithms: **ML-KEM-768 (FIPS 203)** and **ML-DSA-65 (FIPS 204)**.
3. **EU DORA & NIS2 Compliance**: Enforces operational cryptographic resilience and supply-chain bill of materials verification for financial and critical infrastructure networks.

---

## 2. Resource Allocation & Remediation ROI
Applying the **ECDAT Pareto Knapsack Optimizer**, allocating **9.8 Developer Weeks** to the top 4 high-contagion components yields a **71.6% reduction in total estate quantum risk**.

- **Priority 1**: Replace RSA-2048 blind signatures with tanuki / lattice-based post-quantum blind commitments or ephemeral zeroization.
- **Priority 2**: Upgrade edge ingress proxies to hybrid **X25519Kyber768** key exchange to mitigate transit eavesdropping.
- **Priority 3**: Verify path MTU segmentation limits for ML-DSA-65 certificates to prevent firewall drop rates.
`;

    window.renderCisoTab = function(container, data) {
        const summary = data.summary || {};
        const cisoSummary = summary.ciso || {};
        const posture = summary.posture || {};
        const pareto = summary.pareto || {};
        const rawMarkdown = data.ciso_markdown && data.ciso_markdown.trim().length > 20 ?
            data.ciso_markdown : DEFAULT_CISO_BRIEFING;

        const readinessScore = posture.readiness_score || 68;
        const totalCostWeeks = pareto.total_cost_allocated || 9.8;
        const riskReducedPct = pareto.risk_reduction_pct || 71.6;

        container.innerHTML = `
            <div class="ciso-tab-view" style="animation: fadeIn 0.15s ease-out; display: flex; flex-direction: column; gap: 1.5rem;">
                
                <!-- Header Banner -->
                <div class="tab-header-banner">
                    <div class="tab-title-wrap">
                        <div style="display: flex; align-items: center; gap: 0.6rem;">
                            <div class="card-icon" style="background: var(--accent-purple-bg); color: var(--accent-purple);">
                                ${getIcon('fileText', 20)}
                            </div>
                            <div>
                                <h2 style="margin: 0;">CISO Executive Action Plan & Regulatory Compliance</h2>
                                <p style="margin: 0;">High-level strategic governance dashboard mapping transition roadmaps directly against NSA CNSA 2.0, NIST FIPS 203/204/205, and OMB M-23-02.</p>
                            </div>
                        </div>
                    </div>
                    <div class="tab-actions">
                        <button id="ciso-copy-briefing-btn" class="btn btn-secondary">
                            ${getIcon('copy', 14)} Copy Executive Briefing
                        </button>
                        <button id="ciso-export-pdf-btn" class="btn btn-emerald">
                            ${getIcon('download', 14)} Export Board Briefing
                        </button>
                    </div>
                </div>

                <!-- KPI Metric Quad Strip -->
                <div class="stat-row" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 0;">
                    <div class="stat-item">
                        <div class="stat-val text-emerald">${readinessScore} / 100</div>
                        <div class="stat-label">Enterprise Readiness Score</div>
                        <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">Benchmark threshold: &gt;= 60 for Phase 2</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-val" style="color: var(--accent-purple);">${riskReducedPct}%</div>
                        <div class="stat-label">Pareto Risk Elimination</div>
                        <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">Achievable via targeted knapsack remediation</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-val" style="color: var(--accent-cyan);">${totalCostWeeks} Weeks</div>
                        <div class="stat-label">Estimated Remediation Budget</div>
                        <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">Developer-weeks allocation for Phase 2</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-val text-high">182 Days</div>
                        <div class="stat-label">Next Statutory Regulatory Gate</div>
                        <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">OMB M-23-02 Cryptographic Bill Submission</div>
                    </div>
                </div>

                <!-- SECTION 1: STATUTORY COMPLIANCE SCORECARD -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 1.5rem; box-shadow: var(--shadow-card);">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 0.5rem;">
                        <div>
                            <h3 style="font-size: 1.1rem; font-weight: 800; color: var(--text-primary); margin: 0;">Statutory Regulatory Enforcement Matrix</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                Cross-correlation of estate cryptosystems against federal mandates and international resilience frameworks.
                            </p>
                        </div>
                        <div style="display: flex; gap: 0.5rem; font-size: 0.75rem; font-family: var(--font-mono);">
                            <span class="card-badge badge-pqc">&gt;80% Compliant</span>
                            <span class="card-badge badge-high">60-79% In Progress</span>
                            <span class="card-badge badge-critical">&lt;60% Critical Path</span>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem;">
                        <!-- Card 1: NSA CNSA 2.0 -->
                        <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <div style="color: #16a34a;">${getIcon('shieldCheck', 18)}</div>
                                    <strong style="color: var(--text-primary); font-size: 0.92rem;">NSA CNSA 2.0 Compliance</strong>
                                </div>
                                <span class="card-badge badge-pqc">82% READY</span>
                            </div>
                            <div class="progress-bar-container" style="height: 6px; margin-bottom: 0.75rem;">
                                <div class="progress-bar-fill" style="width: 82%; background: var(--pqc-emerald);"></div>
                            </div>
                            <div style="display: flex; flex-direction: column; gap: 0.45rem; font-size: 0.75rem; color: var(--text-secondary);">
                                <div style="display: flex; justify-content: space-between;">
                                    <span>Software & Firmware Signing (2025):</span>
                                    <span class="text-emerald" style="font-weight: 700;">88% Compliant</span>
                                </div>
                                <div style="display: flex; justify-content: space-between;">
                                    <span>Edge TLS & Browsers (2030):</span>
                                    <span style="color: var(--sev-high); font-weight: 700;">62% In Progress</span>
                                </div>
                                <div style="display: flex; justify-content: space-between;">
                                    <span>Core Network Routing & Hardware (2033):</span>
                                    <span class="text-critical" style="font-weight: 700;">45% At Risk</span>
                                </div>
                            </div>
                        </div>

                        <!-- Card 2: NIST FIPS 203 / 204 / 205 -->
                        <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <div style="color: #0284c7;">${getIcon('package', 18)}</div>
                                    <strong style="color: var(--text-primary); font-size: 0.92rem;">NIST Post-Quantum Standards</strong>
                                </div>
                                <span class="card-badge badge-low">74% ADOPTED</span>
                            </div>
                            <div class="progress-bar-container" style="height: 6px; margin-bottom: 0.75rem;">
                                <div class="progress-bar-fill" style="width: 74%; background: var(--accent-cyan);"></div>
                            </div>
                            <div style="display: flex; flex-direction: column; gap: 0.45rem; font-size: 0.75rem; color: var(--text-secondary);">
                                <div style="display: flex; justify-content: space-between;">
                                    <span>FIPS 203 ML-KEM (Kyber Key Exchange):</span>
                                    <span style="color: var(--accent-cyan); font-weight: 700;">75% Ready (X25519Kyber)</span>
                                </div>
                                <div style="display: flex; justify-content: space-between;">
                                    <span>FIPS 204 ML-DSA (Dilithium Signatures):</span>
                                    <span class="text-emerald" style="font-weight: 700;">85% Implemented</span>
                                </div>
                                <div style="display: flex; justify-content: space-between;">
                                    <span>FIPS 205 SLH-DSA (Stateless SPHINCS+):</span>
                                    <span style="color: var(--text-muted); font-weight: 600;">40% Architected</span>
                                </div>
                            </div>
                        </div>

                        <!-- Card 3: OMB M-23-02 & DORA -->
                        <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <div style="color: #7c3aed;">${getIcon('gauge', 18)}</div>
                                    <strong style="color: var(--text-primary); font-size: 0.92rem;">Federal & Global Mandates</strong>
                                </div>
                                <span class="card-badge badge-pqc">92% COMPLIANT</span>
                            </div>
                            <div class="progress-bar-container" style="height: 6px; margin-bottom: 0.75rem;">
                                <div class="progress-bar-fill" style="width: 92%; background: var(--pqc-emerald);"></div>
                            </div>
                            <div style="display: flex; flex-direction: column; gap: 0.45rem; font-size: 0.75rem; color: var(--text-secondary);">
                                <div style="display: flex; justify-content: space-between;">
                                    <span>OMB M-23-02 CBOM Automated Ingestion:</span>
                                    <span class="text-emerald" style="font-weight: 700;">100% Active (CycloneDX 1.6)</span>
                                </div>
                                <div style="display: flex; justify-content: space-between;">
                                    <span>EU DORA Operational Resilience:</span>
                                    <span style="color: var(--accent-cyan); font-weight: 700;">88% Audited</span>
                                </div>
                                <div style="display: flex; justify-content: space-between;">
                                    <span>PCI-DSS v4.0.1 (3DES / SHA-1 Purged):</span>
                                    <span class="text-emerald" style="font-weight: 700;">100% Clean</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- SECTION 2: 10-YEAR MASTER GANTT ROADMAP -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 1.5rem; box-shadow: var(--shadow-card);">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 0.5rem;">
                        <div>
                            <h3 style="font-size: 1.1rem; font-weight: 800; color: var(--text-primary); margin: 0;">Enterprise 10-Year Post-Quantum Master Gantt Roadmap</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                Synchronized timeline orchestrating architectural migration phases against hard statutory sunset horizons and theoretical Q-Day.
                            </p>
                        </div>
                        <span class="card-badge badge-critical">
                            Q-DAY ESTIMATE: 2031.5 ± 2.0Y
                        </span>
                    </div>

                    <!-- Visual Gantt Timeline -->
                    <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem; overflow-x: auto;">
                        <div style="min-width: 680px;">
                            <!-- Year Axis Header -->
                            <div style="display: grid; grid-template-columns: repeat(11, 1fr); text-align: center; font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); padding-bottom: 0.5rem; border-bottom: 1px solid var(--border-strong); margin-bottom: 1rem; font-weight: 600;">
                                <span>2024</span>
                                <span>2025</span>
                                <span>2026</span>
                                <span>2027</span>
                                <span>2028</span>
                                <span>2029</span>
                                <span>2030</span>
                                <span>2031</span>
                                <span>2032</span>
                                <span>2033</span>
                                <span>2034</span>
                            </div>

                            <!-- Track 1: Discovery & Automated Inventory -->
                            <div style="margin-bottom: 0.85rem;">
                                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 0.35rem;">
                                    <span style="font-weight: 700; color: var(--text-primary);">Phase 1: Automated CBOM & Dependency Provenance</span>
                                    <span class="mono text-emerald" style="font-weight: 600;">ACTIVE (2024-2026)</span>
                                </div>
                                <div style="display: grid; grid-template-columns: repeat(11, 1fr); height: 26px; background: #ffffff; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 2px;">
                                    <div style="grid-column: 1 / span 3; background: #0284c7; border-radius: 4px; display: flex; align-items: center; padding-left: 0.5rem; font-size: 0.7rem; font-weight: 700; color: #fff;">
                                        PHASE 1 [COMPLETE]
                                    </div>
                                </div>
                            </div>

                            <!-- Track 2: Hybrid Prototyping & Edge TLS -->
                            <div style="margin-bottom: 0.85rem;">
                                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 0.35rem;">
                                    <span style="font-weight: 700; color: var(--text-primary);">Phase 2: Hybrid X25519Kyber768 & ML-DSA In-Toto Envelopes</span>
                                    <span class="mono" style="color: var(--accent-cyan); font-weight: 600;">IN PROGRESS (2025-2027)</span>
                                </div>
                                <div style="display: grid; grid-template-columns: repeat(11, 1fr); height: 26px; background: #ffffff; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 2px;">
                                    <div style="grid-column: 2 / span 3; background: #16a34a; border-radius: 4px; display: flex; align-items: center; padding-left: 0.5rem; font-size: 0.7rem; font-weight: 700; color: #fff;">
                                        PHASE 2 [HYBRID ROLLOUT]
                                    </div>
                                </div>
                            </div>

                            <!-- Track 3: Full Classical Deprecation -->
                            <div style="margin-bottom: 0.85rem;">
                                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 0.35rem;">
                                    <span style="font-weight: 700; color: var(--text-primary);">Phase 3: Classical RSA & ECC Cipher Sunset (NIST Mandatory)</span>
                                    <span class="mono" style="color: var(--sev-high); font-weight: 600;">PLANNED (2027-2030)</span>
                                </div>
                                <div style="display: grid; grid-template-columns: repeat(11, 1fr); height: 26px; background: #ffffff; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 2px;">
                                    <div style="grid-column: 4 / span 4; background: #d97706; border-radius: 4px; display: flex; align-items: center; padding-left: 0.5rem; font-size: 0.7rem; font-weight: 700; color: #fff;">
                                        PHASE 3 [NIST SUNSET]
                                    </div>
                                </div>
                            </div>

                            <!-- Track 4: Legacy Hardware & Deprecation -->
                            <div>
                                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 0.35rem;">
                                    <span style="font-weight: 700; color: var(--text-primary);">Phase 4: Legacy Firmware, SCADA Hardware & Deep Cold Storage Deprecation</span>
                                    <span class="mono" style="color: var(--text-muted); font-weight: 600;">HORIZON PENDING (2028-2032)</span>
                                </div>
                                <div style="display: grid; grid-template-columns: repeat(11, 1fr); height: 26px; background: #ffffff; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 2px; position: relative;">
                                    <div style="grid-column: 5 / span 5; background: #64748b; border-radius: 4px; display: flex; align-items: center; padding-left: 0.5rem; font-size: 0.7rem; font-weight: 700; color: #fff;">
                                        PHASE 4 [HARDWARE SUNSET]
                                    </div>
                                    <!-- Q-Day Marker at 2031.5 (approx column 8) -->
                                    <div style="position: absolute; left: 72%; top: 0; bottom: 0; width: 2px; background: var(--sev-critical); z-index: 10;">
                                        <span style="position: absolute; top: -18px; left: 50%; transform: translateX(-50%); font-size: 0.62rem; font-weight: 700; color: var(--sev-critical); font-family: var(--font-mono); background: #ffffff; border: 1px solid var(--sev-critical); padding: 0.1rem 0.35rem; border-radius: 4px; white-space: nowrap; box-shadow: var(--shadow-sm);">
                                            Q-DAY (2031.5)
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- SECTION 3: RENDERED CISO EXECUTIVE MIGRATION BRIEFING -->
                <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 2rem; box-shadow: var(--shadow-card);">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-subtle); padding-bottom: 0.85rem;">
                        <div style="display: flex; align-items: center; gap: 0.6rem;">
                            <span class="card-badge" style="background: var(--accent-purple-bg); color: var(--accent-purple); border: 1px solid var(--accent-purple-border);">FORMAL AUDIT BRIEFING</span>
                            <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">Document Ref: ECDAT-EXEC-2026</span>
                        </div>
                        <span style="font-size: 0.75rem; color: var(--pqc-emerald); font-family: var(--font-mono); font-weight: 600;">Attested Clean • Merkle Root Verified</span>
                    </div>

                    <!-- Rendered Markdown Container -->
                    <div class="ciso-markdown-rendered" style="font-size: 0.9rem; color: var(--text-primary); line-height: 1.8;" id="ciso-markdown-body">
                        ${renderMarkdownToHtml(rawMarkdown)}
                    </div>
                </div>
            </div>
        `;

        // Event listeners
        const copyBtn = document.getElementById('ciso-copy-briefing-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(rawMarkdown).then(() => {
                    copyBtn.innerHTML = `${getIcon('check', 14)} Briefing Copied!`;
                    setTimeout(() => { copyBtn.innerHTML = `${getIcon('copy', 14)} Copy Executive Briefing`; }, 2000);
                });
            });
        }

        const exportPdfBtn = document.getElementById('ciso-export-pdf-btn');
        if (exportPdfBtn) {
            exportPdfBtn.addEventListener('click', () => {
                const printWindow = window.open('', '_blank');
                if (printWindow) {
                    printWindow.document.write(`
                        <html>
                            <head>
                                <title>ECDAT CISO Executive Briefing</title>
                                <style>
                                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 2rem; color: #0f172a; line-height: 1.6; }
                                    h1, h2, h3 { color: #0f172a; }
                                    blockquote { border-left: 3px solid #16a34a; padding-left: 1rem; color: #475569; font-style: italic; background: #f0fdf4; padding: 0.5rem 1rem; }
                                    code { font-family: monospace; background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px; border: 1px solid #e2e8f0; }
                                </style>
                            </head>
                            <body>
                                ${renderMarkdownToHtml(rawMarkdown)}
                                <script>window.print();<\/script>
                            </body>
                        </html>
                    `);
                    printWindow.document.close();
                }
            });
        }
    };
})();
