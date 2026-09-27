/**
 * ECDAT Dashboard — Cryptographic Supply Chain & Dependency Blast Radius Tab
 * Evaluates transitive dependencies, third-party cryptographic provider bindings,
 * vendor trust lists, and blast radius vulnerability contagion.
 * Zero-Fabrication: Strictly renders live, project-specific dependencies discovered
 * from project manifests (pom.xml, package.json, requirements.txt, go.mod, Cargo.toml).
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

    window.renderSupplychainTab = function(container, data) {
        const rawDeps = data.manifest_dependencies || (data.cbom && data.cbom.dependencies) || [];
        
        // Normalize dependencies from scan artifacts
        const dependencies = rawDeps.map((d, idx) => {
            const pkgName = d.package_name || d.name || `dependency-${idx}`;
            const eco = (d.ecosystem || 'unknown').toLowerCase();
            const ver = d.version || 'managed';
            const manifest = d.manifest_path || 'manifest';
            const cat = d.category || 'UNKNOWN';
            const readiness = d.pqc_readiness || 'UNKNOWN';
            const scope = d.scope || 'PRODUCTION';
            const cveId = d.cve_id || null;
            const cveSeverity = d.cve_severity || null;
            const cveSummary = d.cve_summary || null;
            const advisoryUrl = d.advisory_url || (cveId ? `https://nvd.nist.gov/vuln/detail/${cveId}` : null);

            let pqcStatus = 'TRANSITION';
            let riskLevel = 'LOW';
            if (readiness === 'MIGRATED_PQC' || cat === 'POST_QUANTUM') {
                pqcStatus = 'PQC_NATIVE';
                riskLevel = 'LOW';
            } else if (readiness === 'VULNERABLE_CLASSICAL' || cat === 'CLASSICAL_ASYMMETRIC') {
                pqcStatus = 'CLASSICAL_ONLY';
                riskLevel = 'HIGH';
            } else if (readiness === 'SAFE_SYMMETRIC' || cat === 'SYMMETRIC_OR_HASH') {
                pqcStatus = 'TRANSITION';
                riskLevel = 'LOW';
            } else if (cat === 'BLOCKCHAIN_CORE') {
                pqcStatus = 'TRANSITION';
                riskLevel = 'MEDIUM';
            }

            return {
                id: `dep-${idx}`,
                name: pkgName,
                ecosystem: eco,
                version: ver,
                license: d.license || 'Declared in Manifest',
                pqcStatus: pqcStatus,
                category: cat,
                pqcReadiness: readiness,
                riskLevel: riskLevel,
                scope: scope,
                cveId: cveId,
                cveSeverity: cveSeverity,
                cveSummary: cveSummary,
                advisoryUrl: advisoryUrl,
                blastRadius: d.blast_radius || (cat === 'CLASSICAL_ASYMMETRIC' ? 8 : 3),
                manifestPath: manifest,
                signed: eco === 'cargo' || eco === 'npm' || eco === 'maven',
                slsaLevel: 'Package Manager Index',
                cveCount: cveId ? 1 : 0,
                description: d.description || 'Cryptographic library dependency declared in project manifest.',
                advisory: d.recommendation || 'Audit dependency usage against cryptographic migration standards.',
                algorithms: [cat.replace(/_/g, ' ')]
            };
        });

        let activeFilter = 'ALL';
        let activeScope = 'ALL';
        let activeCveFilter = 'ALL';
        let searchQuery = '';

        // If no dependencies were found in the project
        if (dependencies.length === 0) {
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
                                    <p>Audit of third-party package providers, upstream cryptographic library trust, and package manifest exposure.</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Honest Empty State -->
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 3.5rem 1.5rem; text-align: center; box-shadow: var(--shadow-sm); margin-top: 1.5rem;">
                        <div style="width: 52px; height: 52px; border-radius: 12px; background: rgba(2, 132, 199, 0.1); color: var(--accent-cyan); display: inline-flex; align-items: center; justify-content: center; margin-bottom: 1.25rem;">
                            ${window.getIcon ? window.getIcon('package', 26) : ''}
                        </div>
                        <h3 style="font-size: 1.2rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
                            No Third-Party Cryptographic Packages Discovered
                        </h3>
                        <p style="font-size: 0.85rem; color: var(--text-secondary); max-width: 620px; margin: 0 auto 1.5rem auto; line-height: 1.5;">
                            No cryptographic library dependencies were detected in package manifests (<code class="mono">pom.xml</code>, <code class="mono">package.json</code>, <code class="mono">requirements.txt</code>, <code class="mono">go.mod</code>, <code class="mono">Cargo.toml</code>) for the selected project. Either this repository strictly utilizes internal first-party algorithms, or manifest scanning was excluded during the discovery run.
                        </p>
                        <div style="display: flex; justify-content: center; gap: 0.75rem;">
                            <button class="btn btn-emerald" onclick="window.triggerProjectScan()">
                                ${window.getIcon ? window.getIcon('play', 14) : ''} Run Cryptographic Scan
                            </button>
                            <button class="btn btn-secondary" onclick="window.navigateToTab('cbom')">
                                View First-Party CBOM Assets →
                            </button>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        const totalDeps = dependencies.length;
        const pqcDeps = dependencies.filter(v => v.pqcStatus === 'PQC_NATIVE').length;
        const classicalDeps = dependencies.filter(v => v.pqcStatus === 'CLASSICAL_ONLY' || v.pqcStatus === 'DEPRECATED').length;
        const transitionDeps = dependencies.filter(v => v.pqcStatus === 'TRANSITION').length;
        const cveDeps = dependencies.filter(v => Boolean(v.cveId)).length;
        const prodDeps = dependencies.filter(v => v.scope === 'PRODUCTION').length;
        const testDeps = dependencies.filter(v => v.scope === 'TEST_FIXTURE').length;

        // Group dependencies by manifest file for dynamic tree
        const manifestGroups = {};
        dependencies.forEach(d => {
            const m = d.manifestPath || 'Root Manifest';
            if (!manifestGroups[m]) manifestGroups[m] = [];
            manifestGroups[m].push(d);
        });

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
                                    <p>Authentic audit of third-party package providers discovered in project manifests, upstream library trust, live CVE intelligence, and downstream blast radius exposure.</p>
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

                    <!-- KPI Metric Strip -->
                    <div class="stat-row" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 1.25rem;">
                        <div class="stat-item">
                            <div class="stat-val">${totalDeps} Packages</div>
                            <div class="stat-label">Manifest Dependencies (${prodDeps} Prod / ${testDeps} Test)</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val ${cveDeps > 0 ? 'text-critical' : 'text-emerald'}">${cveDeps} Known CVEs</div>
                            <div class="stat-label">Real-Time OSV / NVD Vulnerabilities</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val text-critical">${classicalDeps} At Risk</div>
                            <div class="stat-label">Classical Asymmetric (HNDL Risk)</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val text-emerald">${pqcDeps} Verified</div>
                            <div class="stat-label">Post-Quantum Native Packages</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-val" style="color: var(--accent-cyan);">${transitionDeps} Transition</div>
                            <div class="stat-label">Symmetric / Hybrid Dependencies</div>
                        </div>
                    </div>

                    <!-- SECTION 1: DYNAMIC DEPENDENCY MANIFEST HIERARCHY -->
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem;">
                            <div>
                                <h3 style="font-size: 1.1rem; font-weight: 700; color: var(--text-primary);">Manifest Call Tree & Discovered Package Bindings</h3>
                                <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                    Real cryptographic dependency trees reconstructed directly from project manifests across the repository.
                                </p>
                            </div>
                            <span class="card-badge badge-pqc">${Object.keys(manifestGroups).length} Manifest Files</span>
                        </div>

                        <!-- Dynamic Tree Layout -->
                        <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 1.25rem; font-family: var(--font-mono); font-size: 0.78rem;">
                            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                                <span style="background: var(--accent-blue); color: #fff; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 700;">ROOT</span>
                                <span style="font-weight: 700; color: var(--text-primary);">Target Codebase Repository</span>
                            </div>

                            ${Object.entries(manifestGroups).map(([manifestFile, depsInManifest], mIdx, mArr) => {
                                const isLastManifest = mIdx === mArr.length - 1;
                                return `
                                    <div style="margin-left: 1.5rem; padding-left: 1rem; border-left: 2px dashed var(--border-subtle); margin-bottom: ${isLastManifest ? '0' : '0.85rem'};">
                                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                                            <span style="color: var(--accent-cyan);">${isLastManifest ? '└──' : '├──'}</span>
                                            <strong style="color: var(--text-primary);">${escapeHtml(manifestFile)}</strong>
                                            <span class="card-badge badge-low" style="font-size: 0.65rem;">${depsInManifest.length} crypto packages</span>
                                        </div>
                                        <div style="margin-left: 2rem; color: var(--text-secondary); font-size: 0.72rem; display: flex; flex-direction: column; gap: 0.35rem;">
                                            ${depsInManifest.map((dep, dIdx, dArr) => {
                                                const isLastDep = dIdx === dArr.length - 1;
                                                const badgeClass = dep.pqcStatus === 'PQC_NATIVE' ? 'badge-pqc' :
                                                                  dep.pqcStatus === 'CLASSICAL_ONLY' ? 'badge-critical' : 'badge-low';
                                                return `
                                                    <div style="display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;">
                                                        <span style="color: var(--text-muted);">${isLastDep ? '└──' : '├──'}</span>
                                                        <span style="font-weight: 600; color: ${dep.riskLevel === 'HIGH' ? 'var(--sev-critical)' : 'var(--text-primary)'};">${escapeHtml(dep.name)}</span>
                                                        <span style="color: var(--text-muted); font-size: 0.68rem;">(${escapeHtml(dep.version)})</span>
                                                        <span class="card-badge ${badgeClass}" style="font-size: 0.6rem;">${escapeHtml(dep.category)}</span>
                                                        <span class="scope-pill ${dep.scope === 'PRODUCTION' ? 'scope-prod' : 'scope-test'}" style="font-size: 0.55rem; padding: 0.1rem 0.35rem;">${dep.scope === 'PRODUCTION' ? 'PROD' : 'TEST'}</span>
                                                        ${dep.cveId ? `<span class="card-badge badge-critical" style="font-size: 0.58rem; padding: 0.1rem 0.35rem;">${escapeHtml(dep.cveId)}</span>` : ''}
                                                    </div>
                                                `;
                                            }).join('')}
                                        </div>
                                    </div>
                                ` ;
                            }).join('')}
                        </div>
                    </div>

                    <!-- SECTION 2: VENDOR AUDIT & RISK TABLE -->
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.5rem; box-shadow: var(--shadow-sm);">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 0.75rem;">
                            <div>
                                <h3 style="font-size: 1.1rem; font-weight: 700; color: var(--text-primary);">Third-Party Cryptographic Dependency Roster</h3>
                                <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                    Discovered manifest dependencies, ecosystem classification, scope boundary, real-time CVE vulnerabilities, and migration actions.
                                </p>
                            </div>

                            <!-- Filter Controls -->
                            <div style="display: flex; flex-direction: column; gap: 0.5rem; align-items: flex-end;">
                                <!-- PQC Readiness Pills -->
                                <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;" id="sc-filter-pills">
                                    <button class="nav-tab-item active" data-filter="ALL">All Dependencies (${dependencies.length})</button>
                                    <button class="nav-tab-item" data-filter="PQC_NATIVE">Quantum Safe (${pqcDeps})</button>
                                    <button class="nav-tab-item" data-filter="CLASSICAL_ONLY">Classical Only (${classicalDeps})</button>
                                    <button class="nav-tab-item" data-filter="TRANSITION">Symmetric / Hybrid (${transitionDeps})</button>
                                </div>
                                <!-- Scope & CVE Filters -->
                                <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;" id="sc-subfilter-pills">
                                    <span style="font-size: 0.72rem; color: var(--text-muted); align-self: center; margin-right: 0.2rem;">Scope:</span>
                                    <button class="btn btn-secondary active sc-scope-btn" data-scope="ALL" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">All Scopes</button>
                                    <button class="btn btn-secondary sc-scope-btn" data-scope="PRODUCTION" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">Production (${prodDeps})</button>
                                    <button class="btn btn-secondary sc-scope-btn" data-scope="TEST_FIXTURE" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">Test Fixtures (${testDeps})</button>
                                    <span style="font-size: 0.72rem; color: var(--text-muted); align-self: center; margin-left: 0.4rem; margin-right: 0.2rem;">CVE:</span>
                                    <button class="btn btn-secondary active sc-cve-btn" data-cve="ALL" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;">All</button>
                                    <button class="btn btn-secondary sc-cve-btn" data-cve="VULNERABLE" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; color: var(--sev-critical);">Has CVE (${cveDeps})</button>
                                    <button class="btn btn-secondary sc-cve-btn" data-cve="CLEAN" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; color: var(--sev-low);">Clean / None (${totalDeps - cveDeps})</button>
                                </div>
                            </div>
                        </div>

                        <div style="overflow-x: auto;">
                            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.8rem;" id="sc-table">
                                <thead>
                                    <tr style="background: var(--bg-sunken); border-bottom: 1px solid var(--border-subtle); color: var(--text-muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-mono);">
                                        <th style="padding: 0.75rem 1rem;">Package Name & Ecosystem</th>
                                        <th style="padding: 0.75rem 0.75rem;">Scope</th>
                                        <th style="padding: 0.75rem 0.85rem;">Known Vulnerability (CVE)</th>
                                        <th style="padding: 0.75rem 0.85rem;">Version / Manifest</th>
                                        <th style="padding: 0.75rem 0.85rem;">Cryptographic Category</th>
                                        <th style="padding: 0.75rem 0.85rem;">PQC Readiness</th>
                                        <th style="padding: 0.75rem 0.85rem;">Risk Assessment</th>
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

        function filterDependencies() {
            return dependencies.filter(v => {
                if (activeFilter !== 'ALL' && v.pqcStatus !== activeFilter) return false;
                if (activeScope !== 'ALL' && v.scope !== activeScope) return false;
                if (activeCveFilter === 'VULNERABLE' && !v.cveId) return false;
                if (activeCveFilter === 'CLEAN' && v.cveId) return false;
                if (!searchQuery) return true;
                const q = searchQuery.toLowerCase();
                return (
                    v.name.toLowerCase().includes(q) ||
                    v.ecosystem.toLowerCase().includes(q) ||
                    v.manifestPath.toLowerCase().includes(q) ||
                    (v.cveId && v.cveId.toLowerCase().includes(q))
                );
            });
        }

        function renderRows() {
            const tbody = document.getElementById('sc-table-body');
            if (!tbody) return;

            const filtered = filterDependencies();
            if (filtered.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8" style="padding: 2.5rem; text-align: center; color: var(--text-muted);">
                            No third-party packages match the selected scope and vulnerability filters.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = filtered.map(item => {
                const statusBadge = item.pqcStatus === 'PQC_NATIVE' ?
                    '<span class="card-badge badge-pqc">PQC Native</span>' :
                    item.pqcStatus === 'TRANSITION' ?
                    '<span class="card-badge badge-low">Safe Symmetric / Hybrid</span>' :
                    '<span class="card-badge badge-critical">Classical Asymmetric (HNDL)</span>';

                const riskBadge = item.riskLevel === 'HIGH' ?
                    '<span class="card-badge badge-critical">High Risk</span>' :
                    '<span class="card-badge badge-low">Low Risk</span>';

                const scopeBadge = item.scope === 'PRODUCTION' ?
                    '<span class="scope-pill scope-prod" style="font-size: 0.65rem;">PRODUCTION</span>' :
                    '<span class="scope-pill scope-test" style="font-size: 0.65rem;">TEST FIXTURE</span>';

                const cveCell = item.cveId ? `
                    <div style="display: flex; flex-direction: column; gap: 0.2rem;">
                        <a href="${escapeHtml(item.advisoryUrl || '#')}" target="_blank" rel="noopener noreferrer" class="cwe-pill-badge" style="background: rgba(239, 68, 68, 0.12); color: var(--sev-critical); border-color: rgba(239, 68, 68, 0.35); text-decoration: none; display: inline-flex; align-items: center; gap: 0.3rem;" title="${escapeHtml(item.cveSummary || '')} (${escapeHtml(item.cveSeverity || 'HIGH')})">
                            <strong>${escapeHtml(item.cveId)}</strong> ↗
                        </a>
                        <div style="font-size: 0.65rem; color: var(--sev-critical); font-family: var(--font-mono);">${escapeHtml(item.cveSeverity || 'HIGH')} SEVERITY</div>
                    </div>
                ` : `
                    <span class="card-badge badge-pqc" style="background: rgba(16, 185, 129, 0.08); color: var(--sev-low); border: 1px solid rgba(16, 185, 129, 0.25); font-weight: 600;">None</span>
                `;

                return `
                    <tr style="border-bottom: 1px solid var(--border-subtle); transition: background 0.15s; cursor: pointer;"
                        class="sc-row"
                        data-name="${escapeHtml(item.name)}"
                        onmouseover="this.style.backgroundColor='var(--bg-card-hover)'"
                        onmouseout="this.style.backgroundColor='transparent'">
                        <td style="padding: 0.85rem 1rem;">
                            <div style="font-weight: 700; color: var(--text-primary);">${escapeHtml(item.name)}</div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);">
                                Ecosystem: ${escapeHtml(item.ecosystem)}
                            </div>
                        </td>
                        <td style="padding: 0.85rem 0.75rem;">
                            ${scopeBadge}
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            ${cveCell}
                        </td>
                        <td style="padding: 0.85rem 0.85rem; font-family: var(--font-mono); font-size: 0.75rem;">
                            <div style="color: var(--text-primary);">${escapeHtml(item.version)}</div>
                            <div style="color: var(--text-muted); font-size: 0.68rem;" title="${escapeHtml(item.manifestPath)}">
                                ${escapeHtml(item.manifestPath)}
                            </div>
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            <span class="mono" style="font-size: 0.75rem; color: var(--accent-cyan);">${escapeHtml(item.category)}</span>
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            ${statusBadge}
                        </td>
                        <td style="padding: 0.85rem 0.85rem;">
                            ${riskBadge}
                        </td>
                        <td style="padding: 0.85rem 1rem; text-align: right;">
                            <button class="btn btn-secondary sc-inspect-btn" data-name="${escapeHtml(item.name)}" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;">
                                Inspect →
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
            const pkg = dependencies.find(v => v.name === pkgName);
            if (!pkg) return;

            const modal = document.getElementById('sc-package-modal');
            const box = document.getElementById('sc-package-modal-box');
            if (!modal || !box) return;

            const cveSnippet = pkg.cveId ? `
                <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: var(--radius-sm); padding: 0.85rem; margin-bottom: 1rem;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
                        <span style="font-size: 0.72rem; color: var(--sev-critical); font-weight: 700; text-transform: uppercase;">Known Vulnerability Advisory (${escapeHtml(pkg.cveSeverity || 'HIGH')})</span>
                        <a href="${escapeHtml(pkg.advisoryUrl || '#')}" target="_blank" rel="noopener noreferrer" style="color: var(--sev-critical); font-weight: 700; font-size: 0.75rem; text-decoration: none;">
                            ${escapeHtml(pkg.cveId)} ↗
                        </a>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.45;">
                        ${escapeHtml(pkg.cveSummary || 'Vulnerability detected in third-party library via OSV public advisory catalog.')}
                    </div>
                </div>
            ` : `
                <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-sm); padding: 0.6rem 0.85rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between;">
                    <span style="font-size: 0.72rem; color: var(--sev-low); font-weight: 700;">Vulnerability Status</span>
                    <span class="card-badge badge-pqc" style="font-size: 0.68rem;">None (No Known CVE in OSV)</span>
                </div>
            `;

            box.innerHTML = `
                <div class="modal-header">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="card-badge badge-pqc">${escapeHtml(pkg.ecosystem)}</span>
                        <span class="scope-pill ${pkg.scope === 'PRODUCTION' ? 'scope-prod' : 'scope-test'}" style="font-size: 0.65rem;">${escapeHtml(pkg.scope)}</span>
                        <h3 class="modal-title" style="color: var(--text-primary);">${escapeHtml(pkg.name)}</h3>
                    </div>
                    <button class="modal-close" id="sc-modal-close-btn">&times;</button>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="background: var(--bg-sunken); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Manifest Path</div>
                        <div class="mono" style="font-size: 0.85rem; font-weight: 700; color: var(--text-primary); margin-top: 0.2rem; word-break: break-all;">
                            ${escapeHtml(pkg.manifestPath)}
                        </div>
                    </div>
                    <div style="background: var(--bg-sunken); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Declared Version</div>
                        <div class="mono" style="font-size: 0.85rem; font-weight: 700; color: var(--accent-cyan); margin-top: 0.25rem;">
                            ${escapeHtml(pkg.version)}
                        </div>
                    </div>
                </div>

                ${cveSnippet}

                <div style="background: var(--bg-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 0.85rem; margin-bottom: 1rem;">
                    <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700; margin-bottom: 0.4rem;">
                        Package Description & Role
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.45;">
                        ${escapeHtml(pkg.description)}
                    </div>
                </div>

                <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: var(--radius-sm); padding: 0.85rem; margin-bottom: 1.25rem;">
                    <div style="font-size: 0.72rem; color: var(--sev-high); font-weight: 700; text-transform: uppercase; margin-bottom: 0.35rem;">
                        Statutory Migration Recommendation
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.5;">
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

        const subfilterPills = document.getElementById('sc-subfilter-pills');
        if (subfilterPills) {
            subfilterPills.querySelectorAll('.sc-scope-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    subfilterPills.querySelectorAll('.sc-scope-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    activeScope = btn.getAttribute('data-scope') || 'ALL';
                    renderRows();
                });
            });

            subfilterPills.querySelectorAll('.sc-cve-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    subfilterPills.querySelectorAll('.sc-cve-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    activeCveFilter = btn.getAttribute('data-cve') || 'ALL';
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
                    components: dependencies.map(v => ({
                        type: 'library',
                        name: v.name,
                        version: v.version,
                        licenses: [{ license: { id: v.license } }],
                        properties: [
                            { name: 'ecdat:ecosystem', value: v.ecosystem },
                            { name: 'ecdat:manifest_path', value: v.manifestPath },
                            { name: 'ecdat:pqc_status', value: v.pqcStatus },
                            { name: 'ecdat:category', value: v.category },
                            { name: 'ecdat:scope', value: v.scope },
                            { name: 'ecdat:cve_id', value: v.cveId || 'None' }
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
