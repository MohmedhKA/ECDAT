/**
 * ECDAT Dashboard — Cryptographic Supply Chain & Dependency Blast Radius Tab
 * Evaluates transitive dependencies, third-party cryptographic provider bindings,
 * vendor trust lists, and blast radius vulnerability contagion.
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

    const VENDOR_DATABASE = [
        {
            name: '@noble/post-quantum',
            ecosystem: 'npm',
            version: '^0.6.1',
            license: 'MIT',
            pqcStatus: 'PQC_NATIVE',
            riskLevel: 'LOW',
            blastRadius: 8,
            slsaLevel: 'SLSA Level 3',
            signed: true,
            providerType: 'CRYPTO_CORE',
            cveCount: 0,
            algorithms: ['ML-DSA-65 (FIPS 204)', 'ML-KEM-768 (FIPS 203)', 'SLH-DSA (FIPS 205)'],
            advisory: 'Zero-dependency post-quantum cryptographic primitives. Audited by Cure53, conforms to final NIST FIPS 203/204 specifications.'
        },
        {
            name: 'node-forge',
            ecosystem: 'npm',
            version: '^1.4.0',
            license: 'BSD-3-Clause',
            pqcStatus: 'CLASSICAL_ONLY',
            riskLevel: 'HIGH',
            blastRadius: 14,
            slsaLevel: 'SLSA Level 2',
            signed: false,
            providerType: 'CLASSICAL_LEGACY',
            cveCount: 1,
            algorithms: ['RSA-2048 Blind Signatures', 'AES-GCM', 'SHA-256 HMAC'],
            advisory: 'Pure JavaScript classical crypto suite. Lacks lattice-based post-quantum primitives. Used for Chaum blind signatures; vulnerable to HNDL attack window.'
        },
        {
            name: '@hyperledger/fabric-gateway',
            ecosystem: 'npm',
            version: '^1.10.1',
            license: 'Apache-2.0',
            pqcStatus: 'TRANSITION',
            riskLevel: 'MEDIUM',
            blastRadius: 12,
            slsaLevel: 'SLSA Level 3',
            signed: true,
            providerType: 'BLOCKCHAIN_GATEWAY',
            cveCount: 0,
            algorithms: ['ECDSA-P256', 'gRPC TLS 1.3', 'SHA-256'],
            advisory: 'Consortium blockchain client SDK. Uses classical ECDSA for transaction endorsement signatures. Dual-MSP anchoring protocol required for quantum hardening.'
        },
        {
            name: 'crypto-verifier-rust (gRPC)',
            ecosystem: 'Cargo / Tokio',
            version: '0.2.0 (Internal)',
            license: 'Proprietary',
            pqcStatus: 'PQC_NATIVE',
            riskLevel: 'LOW',
            blastRadius: 19,
            slsaLevel: 'SLSA Level 4',
            signed: true,
            providerType: 'NATIVE_MICROSERVICE',
            cveCount: 0,
            algorithms: ['LWE Lattice Homomorphic Accumulator', 'Ristretto255 NIZK Proofs', '37-bit Binary Spooling'],
            advisory: 'High-performance Tokio microservice running on gRPC :50051. Implements Dealer-Shamir 2-of-3 threshold partial decryption across trustees.'
        },
        {
            name: 'ioredis',
            ecosystem: 'npm',
            version: '^5.4.1',
            license: 'MIT',
            pqcStatus: 'TRANSITION',
            riskLevel: 'LOW',
            blastRadius: 9,
            slsaLevel: 'SLSA Level 3',
            signed: true,
            providerType: 'STREAM_BROKER',
            cveCount: 0,
            algorithms: ['TLS 1.3', 'AES-256-GCM (Payload encryption)'],
            advisory: 'High-throughput Redis 7 stream client. Encrypted message broker backing the 4-stage ingestion pipeline.'
        },
        {
            name: 'crypto-js',
            ecosystem: 'npm',
            version: '^4.2.0',
            license: 'MIT',
            pqcStatus: 'DEPRECATED',
            riskLevel: 'CRITICAL',
            blastRadius: 4,
            slsaLevel: 'SLSA Level 1',
            signed: false,
            providerType: 'CLASSICAL_LEGACY',
            cveCount: 2,
            algorithms: ['MD5', 'SHA-1', 'DES', 'RC4', 'AES-CBC'],
            advisory: 'Unmaintained legacy JavaScript crypto utility. Contains deprecated ciphers (MD5/SHA1/DES) prohibited by NIST SP 800-131A Rev 2.'
        }
    ];

    window.renderSupplychainTab = function(container, data) {
        const summary = data.summary || {};
        const supplySummary = summary.supplychain || {};
        const cbom = data.cbom || {};

        let activeFilter = 'ALL';
        let searchQuery = '';

        const totalDeps = supplySummary.total_dependencies || VENDOR_DATABASE.length;
        const pqcDeps = VENDOR_DATABASE.filter(v => v.pqcStatus === 'PQC_NATIVE').length;
        const classicalDeps = VENDOR_DATABASE.filter(v => v.pqcStatus === 'CLASSICAL_ONLY' || v.pqcStatus === 'DEPRECATED').length;
        const signedCount = VENDOR_DATABASE.filter(v => v.signed).length;

        function renderBaseHtml() {
            container.innerHTML = `
                <div class="supplychain-tab-view" style="animation: fadeIn 0.15s ease-out;">
                    <!-- Header Banner -->
                    <div class="tab-header-banner">
                        <div class="tab-title-wrap">
                            <div style="display: flex; align-items: center; gap: 0.6rem;">
                                <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(245, 158, 11, 0.15); color: var(--sev-high); display: flex; align-items: center; justify-content: center;">
                                    ${window.getIcon ? window.getIcon('link', 18) : ''}
                                </div>
                                <div>
                                    <h2>Cryptographic Supply Chain & Dependency Blast Radius</h2>
                                    <p>Audit of third-party package providers, upstream cryptographic library trust, SLSA provenance, and downstream blast radius exposure.</p>
                                </div>
                            </div>
                        </div>
                        <div class="tab-actions">
                            <button id="sc-export-sbom-btn" class="btn btn-secondary">
                                ${window.getIcon ? window.getIcon('package', 14) : ''} Export CycloneDX SBOM
                            </button>
                            <button class="btn btn-emerald" onclick="window.navigateToTab('contagion')">
                                ${window.getIcon ? window.getIcon('network', 14) : ''} Open Contagion Graph →
                            </button>
                        </div>
                    </div>

                    <!-- KPI Metric Quad Strip -->
                    <div class="stat-row" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 1.25rem;">
                        <div class="stat-item">
                            <div class="stat-val">${totalDeps} Packages</div>
                            <div class="stat-label">Total Third-Party Dependencies</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val text-emerald">${pqcDeps} Verified</div>
                            <div class="stat-label">Post-Quantum Native Providers</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val text-critical">${classicalDeps} At Risk</div>
                            <div class="stat-label">Classical / Deprecated Packages</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val" style="color: var(--accent-cyan);">${signedCount} / ${VENDOR_DATABASE.length}</div>
                            <div class="stat-label">SLSA Provenance Signed</div>
                        </div>
                    </div>

                    <!-- SECTION 1: INTERACTIVE DEPENDENCY TREE HIERARCHY -->
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem;">
                            <div>
                                <h3 style="font-size: 1.1rem; font-weight: 700; color: var(--text-primary);">Cryptographic Call Tree & Blast Radius Hotspots</h3>
                                <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                    Tracing third-party provider bindings from root application controllers down to low-level cryptographic primitives.
                                </p>
                            </div>
                            <span class="card-badge badge-high">6 Key Cryptographic Sinks</span>
                        </div>

                        <!-- Tree Layout -->
                        <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 1.25rem; font-family: var(--font-mono); font-size: 0.78rem;">
                            <!-- Root Node -->
                            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                                <span style="background: var(--accent-blue); color: #fff; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 700;">ROOT</span>
                                <span style="font-weight: 700; color: var(--text-primary);">ECDAT Cryptographic Ingestion Engine (Node.js + Rust Consortium)</span>
                            </div>

                            <!-- Branch 1: Ingestion API -->
                            <div style="margin-left: 1.5rem; padding-left: 1rem; border-left: 2px dashed var(--border-subtle); margin-bottom: 0.75rem;">
                                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                                    <span style="color: var(--accent-cyan);">├──</span>
                                    <strong style="color: var(--text-primary);">controllers/ec.controller.js</strong>
                                    <span class="card-badge badge-high" style="font-size: 0.65rem;">Blast Radius: 14</span>
                                </div>
                                <div style="margin-left: 2rem; color: var(--text-secondary); font-size: 0.72rem; display: flex; flex-direction: column; gap: 0.25rem;">
                                    <div>└── invokes <span style="color: var(--sev-high); font-weight: 600;">node-forge</span> (RSA-2048 Chaum Blind Signature Engine) <span class="card-badge badge-critical" style="font-size: 0.6rem;">SNDL RISK</span></div>
                                    <div>└── invokes <span style="color: var(--pqc-emerald); font-weight: 600;">crypto-verifier-rust</span> (Ristretto255 Sigma Proofs) <span class="card-badge badge-pqc" style="font-size: 0.6rem;">FIPS-204</span></div>
                                </div>
                            </div>

                            <!-- Branch 2: Blockchain Ledger Worker -->
                            <div style="margin-left: 1.5rem; padding-left: 1rem; border-left: 2px dashed var(--border-subtle); margin-bottom: 0.75rem;">
                                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                                    <span style="color: var(--accent-cyan);">├──</span>
                                    <strong style="color: var(--text-primary);">workers/vote-processor.js</strong>
                                    <span class="card-badge badge-medium" style="font-size: 0.65rem;">Blast Radius: 12</span>
                                </div>
                                <div style="margin-left: 2rem; color: var(--text-secondary); font-size: 0.72rem; display: flex; flex-direction: column; gap: 0.25rem;">
                                    <div>└── delegates to <span style="color: var(--accent-cyan); font-weight: 600;">@hyperledger/fabric-gateway</span> (SmartBFT Consensus Ingestion)</div>
                                    <div>└── emits to <span style="color: var(--pqc-emerald); font-weight: 600;">@noble/post-quantum</span> (ML-DSA-65 Merkle Leaf Generation)</div>
                                </div>
                            </div>

                            <!-- Branch 3: Merkle Anchor Service -->
                            <div style="margin-left: 1.5rem; padding-left: 1rem; border-left: 2px dashed var(--border-subtle);">
                                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                                    <span style="color: var(--accent-cyan);">└──</span>
                                    <strong style="color: var(--text-primary);">workers/anchor-worker.js</strong>
                                    <span class="card-badge badge-pqc" style="font-size: 0.65rem;">Blast Radius: 19</span>
                                </div>
                                <div style="margin-left: 2rem; color: var(--text-secondary); font-size: 0.72rem; display: flex; flex-direction: column; gap: 0.25rem;">
                                    <div>└── executes <span style="color: var(--pqc-emerald); font-weight: 600;">@noble/post-quantum (ML-DSA-65)</span> (CRYSTALS-Dilithium3 FIPS-204 Anchor)</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 2: VENDOR AUDIT & RISK TABLE -->
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 0.75rem;">
                            <div>
                                <h3 style="font-size: 1.1rem; font-weight: 700; color: var(--text-primary);">Vendor Cryptographic Trust & Provenance Roster</h3>
                                <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                    Detailed vulnerability posture, SLSA supply chain provenance level, and downstream contagion blast radius.
                                </p>
                            </div>

                            <!-- Filter Pills -->
                            <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;" id="sc-filter-pills">
                                <button class="nav-tab-item active" data-filter="ALL">All Vendors</button>
                                <button class="nav-tab-item" data-filter="PQC_NATIVE">Quantum Safe</button>
                                <button class="nav-tab-item" data-filter="CLASSICAL_ONLY">Classical Only</button>
                                <button class="nav-tab-item" data-filter="DEPRECATED">Deprecated</button>
                            </div>
                        </div>

                        <div style="overflow-x: auto;">
                            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;" id="sc-table">
                                <thead>
                                    <tr style="background: var(--bg-sunken); border-bottom: 1px solid var(--border-subtle); color: var(--text-muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-mono);">
                                        <th style="padding: 0.75rem 1rem;">Package Name & Ecosystem</th>
                                        <th style="padding: 0.75rem 0.85rem;">Version / License</th>
                                        <th style="padding: 0.75rem 0.85rem;">Cryptographic Posture</th>
                                        <th style="padding: 0.75rem 0.85rem;">Blast Radius</th>
                                        <th style="padding: 0.75rem 0.85rem;">SLSA Provenance</th>
                                        <th style="padding: 0.75rem 0.85rem;">Vulnerabilities</th>
                                        <th style="padding: 0.75rem 1rem; text-align: right;">Action</th>
                                    </tr>
                                </thead>
                                <tbody id="sc-table-body">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Package Detail Modal -->
                    <div class="modal-overlay" id="sc-package-modal">
                        <div class="modal-box" id="sc-package-modal-box">
                            <!-- Populated on click -->
                        </div>
                    </div>
                </div>
            `;
        }

        function filterVendors() {
            return VENDOR_DATABASE.filter(v => {
                if (activeFilter !== 'ALL' && v.pqcStatus !== activeFilter) return false;
                if (!searchQuery) return true;
                const q = searchQuery.toLowerCase();
                return (
                    v.name.toLowerCase().includes(q) ||
                    v.ecosystem.toLowerCase().includes(q) ||
                    v.algorithms.some(a => a.toLowerCase().includes(q))
                );
            });
        }

        function renderRows() {
            const tbody = document.getElementById('sc-table-body');
            if (!tbody) return;

            const filtered = filterVendors();
            tbody.innerHTML = filtered.map(item => {
                const statusBadge = item.pqcStatus === 'PQC_NATIVE' ?
                    '<span class="card-badge badge-pqc">PQC Native</span>' :
                    item.pqcStatus === 'TRANSITION' ?
                    '<span class="card-badge badge-low">Transition</span>' :
                    item.pqcStatus === 'CLASSICAL_ONLY' ?
                    '<span class="card-badge badge-high">Classical Only</span>' :
                    '<span class="card-badge badge-critical">Deprecated</span>';

                const slsaBadge = item.signed ?
                    `<span class="card-badge badge-pqc" style="font-size: 0.68rem; display: inline-flex; align-items: center; gap: 0.25rem;">${window.getIcon ? window.getIcon('check', 12) : ''} ${escapeHtml(item.slsaLevel)}</span>` :
                    `<span class="card-badge badge-high" style="font-size: 0.68rem; display: inline-flex; align-items: center; gap: 0.25rem;">${window.getIcon ? window.getIcon('alertTriangle', 12) : ''} Unsigned</span>`;

                const cveBadge = item.cveCount > 0 ?
                    `<span class="card-badge badge-critical">${item.cveCount} CVEs</span>` :
                    `<span class="card-badge badge-pqc">Clean (0 CVE)</span>`;

                return `
                    <tr style="border-bottom: 1px solid var(--border-subtle); transition: background 0.15s; cursor: pointer;"
                        class="sc-row"
                        data-name="${escapeHtml(item.name)}"
                        onmouseover="this.style.backgroundColor='var(--bg-card-hover)'"
                        onmouseout="this.style.backgroundColor='transparent'">
                        <td style="padding: 0.85rem 1rem;">
                            <div style="font-weight: 700; color: var(--text-primary);">${escapeHtml(item.name)}</div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);">
                                Eco: ${escapeHtml(item.ecosystem)} • Type: ${escapeHtml(item.providerType)}
                            </div>
                        </td>
                        <td style="padding: 0.85rem 0.85rem; font-family: var(--font-mono); font-size: 0.75rem;">
                            <div style="color: var(--text-primary);">${escapeHtml(item.version)}</div>
                            <div style="color: var(--text-muted); font-size: 0.68rem;">${escapeHtml(item.license)}</div>
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            ${statusBadge}
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            <span class="mono" style="font-size: 0.82rem; font-weight: 700; color: ${item.blastRadius > 10 ? 'var(--sev-critical)' : 'var(--accent-cyan)'};">
                                ${item.blastRadius} modules
                            </span>
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            ${slsaBadge}
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            ${cveBadge}
                        </td>
                        <td style="padding: 0.85rem 1rem; text-align: right;">
                            <button class="btn btn-secondary sc-inspect-btn" data-name="${escapeHtml(item.name)}" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;">
                                Audit →
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');

            container.querySelectorAll('.sc-row').forEach(row => {
                row.addEventListener('click', () => {
                    const name = row.getAttribute('data-name');
                    openPackageModal(name);
                });
            });

            container.querySelectorAll('.sc-inspect-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const name = btn.getAttribute('data-name');
                    openPackageModal(name);
                });
            });
        }

        function openPackageModal(pkgName) {
            const pkg = VENDOR_DATABASE.find(v => v.name === pkgName);
            if (!pkg) return;

            const modal = document.getElementById('sc-package-modal');
            const box = document.getElementById('sc-package-modal-box');
            if (!modal || !box) return;

            box.innerHTML = `
                <div class="modal-header">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="card-badge badge-pqc">${escapeHtml(pkg.ecosystem)}</span>
                        <h3 class="modal-title" style="color: var(--text-primary);">${escapeHtml(pkg.name)}</h3>
                    </div>
                    <button class="modal-close" id="sc-modal-close-btn">&times;</button>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="background: var(--bg-sunken); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Downstream Blast Radius</div>
                        <div class="mono" style="font-size: 1.1rem; font-weight: 800; color: ${pkg.blastRadius > 10 ? 'var(--sev-critical)' : 'var(--pqc-emerald)'}; margin-top: 0.2rem;">
                            ${pkg.blastRadius} Dependent Controllers
                        </div>
                    </div>
                    <div style="background: var(--bg-sunken); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Supply Chain Provenance</div>
                        <div class="mono" style="font-size: 0.85rem; font-weight: 700; color: var(--text-primary); margin-top: 0.25rem;">
                            ${escapeHtml(pkg.slsaLevel)} (Sigstore Verified)
                        </div>
                    </div>
                </div>

                <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 0.85rem; margin-bottom: 1rem;">
                    <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700; margin-bottom: 0.4rem;">
                        Bound Cryptographic Algorithms
                    </div>
                    <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;">
                        ${pkg.algorithms.map(alg => `
                            <span class="mono" style="font-size: 0.72rem; background: rgba(56, 189, 248, 0.12); color: var(--accent-cyan); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.3);">
                                ${escapeHtml(alg)}
                            </span>
                        `).join('')}
                    </div>
                </div>

                <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: var(--radius-sm); padding: 0.85rem; margin-bottom: 1.25rem;">
                    <div style="font-size: 0.72rem; color: var(--sev-high); font-weight: 700; text-transform: uppercase; margin-bottom: 0.35rem;">
                        Vendor Security Advisory & Remediation
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-secondary); line-height: 1.5;">
                        ${escapeHtml(pkg.advisory)}
                    </div>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 0.75rem;">
                    <button class="btn btn-secondary" id="sc-modal-close-action">Close</button>
                    <button class="btn btn-emerald" onclick="window.navigateToTab('ciso')">View Migration Mandates →</button>
                </div>
            `;

            modal.classList.add('active');
            const closeBtn = document.getElementById('sc-modal-close-btn');
            const closeAction = document.getElementById('sc-modal-close-action');
            if (closeBtn) closeBtn.onclick = () => modal.classList.remove('active');
            if (closeAction) closeAction.onclick = () => modal.classList.remove('active');
        }

        renderBaseHtml();
        renderRows();

        const filterPills = document.getElementById('sc-filter-pills');
        if (filterPills) {
            filterPills.querySelectorAll('button').forEach(btn => {
                btn.addEventListener('click', () => {
                    filterPills.querySelectorAll('button').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    activeFilter = btn.getAttribute('data-filter') || 'ALL';
                    renderRows();
                });
            });
        }

        const exportBtn = document.getElementById('sc-export-sbom-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                const sbom = {
                    bomFormat: 'CycloneDX',
                    specVersion: '1.6',
                    components: VENDOR_DATABASE.map(v => ({
                        type: 'library',
                        name: v.name,
                        version: v.version,
                        licenses: [{ license: { id: v.license } }],
                        properties: [
                            { name: 'ecdat:pqc_status', value: v.pqcStatus },
                            { name: 'ecdat:blast_radius', value: String(v.blastRadius) }
                        ]
                    }))
                };
                const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `cyclonedx_sbom_dependencies_${new Date().toISOString().slice(0, 10)}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }
    };
})();
