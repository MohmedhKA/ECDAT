/**
 * ECDAT Dashboard — Master Client Application
 * Handles SPA navigation, project switching, live scan polling, and dynamic tab rendering.
 */
(function() {
    const state = {
        projects: [],
        currentProjectId: null,
        currentTab: 'home',
        tabData: {},
        isScanning: false,
        scanPollInterval: null,
    };

    const TABS = [
        { id: 'home', name: 'Overview', icon: 'home' },
        { id: 'mosca', name: 'Mosca Horizon', icon: 'atom' },
        { id: 'contagion', name: 'Contagion Graph', icon: 'network' },
        { id: 'lineage', name: 'Lineage Provenance', icon: 'gitBranch' },
        { id: 'pareto', name: 'Pareto Portfolio', icon: 'trendingUp' },
        { id: 'cbom', name: 'CBOM Inventory', icon: 'package' },
        { id: 'buffer', name: 'Buffer & Agility', icon: 'gauge' },
        { id: 'supplychain', name: 'Supply Chain', icon: 'link' },
        { id: 'proof', name: 'Proofs & DSSE', icon: 'lock' },
        { id: 'unknowns', name: 'Shadow Crypto', icon: 'helpCircle' },
        { id: 'ciso', name: 'CISO Briefing', icon: 'fileText' },
    ];

    window.navigateToTab = function(tabId) {
        window.location.hash = `#/${tabId}`;
    };

    async function fetchProjects() {
        try {
            const res = await fetch('/api/projects');
            const data = await res.json();
            state.projects = data.projects || [];
            
            const selectEl = document.getElementById('project-selector');
            if (!selectEl) return;
            selectEl.innerHTML = '';

            if (state.projects.length === 0) {
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = 'No Projects Configured';
                selectEl.appendChild(opt);
                renderEmptyState();
                return;
            }

            state.projects.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.id;
                opt.textContent = p.name;
                if (p.id === state.currentProjectId) {
                    opt.selected = true;
                }
                selectEl.appendChild(opt);
            });

            // Add divider and "+ Add Project" action
            const addOpt = document.createElement('option');
            addOpt.value = '__add_new__';
            addOpt.textContent = '+ Add New Project...';
            selectEl.appendChild(addOpt);

            if (!state.currentProjectId && state.projects.length > 0) {
                state.currentProjectId = state.projects[0].id;
                selectEl.value = state.currentProjectId;
            }

            await loadCurrentProjectData();
        } catch (err) {
            console.error('Failed to fetch projects:', err);
        }
    }

    async function loadCurrentProjectData() {
        if (!state.currentProjectId) return;
        const mainContainer = document.getElementById('tab-content-container');
        if (!mainContainer) return;

        try {
            // Fetch both summary and specific tab payload
            const res = await fetch(`/api/project/${state.currentProjectId}/tab/${state.currentTab}`);
            if (!res.ok) throw new Error(`HTTP error ${res.status}`);
            const payload = await res.json();
            state.tabData = payload;

            // Update top banner details
            const currentProj = state.projects.find(p => p.id === state.currentProjectId);
            const statusEl = document.getElementById('project-scan-status');
            if (statusEl && currentProj) {
                statusEl.textContent = currentProj.last_scanned ? `Last scanned: ${currentProj.last_scanned}` : 'Not scanned yet';
            }

            renderCurrentTab();
        } catch (err) {
            console.error('Failed to load project data:', err);
            mainContainer.innerHTML = `
                <div style="background: var(--bg-card); border: 1px solid var(--sev-critical); padding: 2rem; border-radius: var(--radius-md); text-align: center; box-shadow: var(--shadow-sm);">
                    <div style="display: inline-flex; align-items: center; justify-content: center; width: 48px; height: 48px; border-radius: 50%; background: #fee2e2; color: var(--sev-critical); margin-bottom: 0.75rem;">
                        ${window.getIcon ? window.getIcon('alertCircle', 24) : ''}
                    </div>
                    <h3 style="color: var(--text-primary); margin-bottom: 0.5rem; font-weight: 700;">Failed to load data for project</h3>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1.25rem;">${err.message}</p>
                    <button class="btn btn-emerald" onclick="window.triggerProjectScan()">
                        <span style="display: inline-flex; align-items: center; gap: 0.4rem;">
                            ${window.getIcon ? window.getIcon('zap', 14) : ''}
                            <span>Trigger First Scan Now</span>
                        </span>
                    </button>
                </div>
            `;
        }
    }

    function renderTabsBar() {
        const bar = document.getElementById('nav-tabs-bar');
        if (!bar) return;
        bar.innerHTML = '';

        TABS.forEach(tab => {
            const a = document.createElement('a');
            a.className = `nav-tab-item ${tab.id === state.currentTab ? 'active' : ''}`;
            a.href = `#/${tab.id}`;
            const iconSvg = window.getIcon ? window.getIcon(tab.icon, 15, 'tab-svg-icon') : '';
            a.innerHTML = `<span style="display: inline-flex; align-items: center;">${iconSvg}</span> <span>${tab.name}</span>`;
            bar.appendChild(a);
        });
    }

    function renderCurrentTab() {
        const container = document.getElementById('tab-content-container');
        if (!container) return;

        renderTabsBar();

        const rendererMap = {
            'home': window.renderHomeTab,
            'mosca': window.renderMoscaTab,
            'contagion': window.renderContagionTab,
            'lineage': window.renderLineageTab,
            'pareto': window.renderParetoTab,
            'cbom': window.renderCbomTab,
            'buffer': window.renderBufferTab,
            'supplychain': window.renderSupplychainTab,
            'proof': window.renderProofTab,
            'unknowns': window.renderUnknownsTab,
            'ciso': window.renderCisoTab,
        };

        const renderer = rendererMap[state.currentTab] || window.renderHomeTab;
        if (typeof renderer === 'function') {
            renderer(container, state.tabData);
        } else {
            container.innerHTML = `
                <div style="padding: 4rem; text-align: center; color: var(--text-secondary);">
                    <div style="display: inline-flex; align-items: center; justify-content: center; width: 44px; height: 44px; border-radius: 50%; background: var(--bg-card); border: 1px solid var(--border-subtle); color: var(--accent-cyan); margin-bottom: 1rem;">
                        <span class="spin" style="display: inline-flex;">${window.getIcon ? window.getIcon('refresh', 20) : ''}</span>
                    </div>
                    <h3 style="color: var(--text-primary); font-size: 1.1rem; font-weight: 700; margin-bottom: 0.25rem;">Tab module loading...</h3>
                    <p style="font-size: 0.82rem; color: var(--text-muted);">Rendering interactive cryptographic models...</p>
                </div>
            `;
        }
    }

    function renderEmptyState() {
        const container = document.getElementById('tab-content-container');
        if (!container) return;
        container.innerHTML = `
            <div style="max-width: 620px; margin: 4rem auto; background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 2.5rem; text-align: center; box-shadow: var(--shadow-md);">
                <div style="width: 56px; height: 56px; background: rgba(16, 185, 129, 0.1); color: var(--pqc-emerald); border-radius: 14px; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 1.25rem;">
                    ${window.getIcon ? window.getIcon('shield', 30) : ''}
                </div>
                <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--text-primary); margin-bottom: 0.5rem; letter-spacing: -0.02em;">Welcome to ECDAT Security Suite</h2>
                <p style="color: var(--text-secondary); font-size: 0.88rem; line-height: 1.6; margin-bottom: 1.75rem;">
                    To initiate automated Post-Quantum Cryptographic discovery and continuous risk monitoring, register your target codebase repository or directory below.
                </p>
                <button class="btn btn-emerald" style="padding: 0.75rem 1.5rem; font-size: 0.9rem;" onclick="window.openNewProjectModal()">
                    <span style="display: inline-flex; align-items: center; gap: 0.45rem;">
                        ${window.getIcon ? window.getIcon('plus', 16) : ''}
                        <span>Register Target Codebase</span>
                    </span>
                </button>
            </div>
        `;
    }

    // Hash routing
    function handleHashChange() {
        const hash = window.location.hash.replace(/^#\/?/, '').trim();
        const tab = hash || 'home';
        if (state.currentTab !== tab) {
            state.currentTab = tab;
            loadCurrentProjectData();
        }
    }

    // Modal management
    window.openNewProjectModal = function() {
        const modal = document.getElementById('new-project-modal');
        if (modal) modal.classList.add('active');
    };

    window.closeNewProjectModal = function() {
        const modal = document.getElementById('new-project-modal');
        if (modal) modal.classList.remove('active');
    };

    window.handleProjectSelectChange = function(selectEl) {
        if (selectEl.value === '__add_new__') {
            selectEl.value = state.currentProjectId || '';
            window.openNewProjectModal();
            return;
        }
        state.currentProjectId = selectEl.value;
        loadCurrentProjectData();
    };

    window.submitNewProject = async function(event) {
        event.preventDefault();
        const nameInput = document.getElementById('proj-name-input');
        const targetInput = document.getElementById('proj-target-input');
        const scansInput = document.getElementById('proj-scans-input');
        const autoScanCheckbox = document.getElementById('proj-autoscan-input');

        const name = nameInput.value.trim();
        const target_dir = targetInput.value.trim();
        const scans_per_day = parseInt(scansInput.value, 10) || 1;
        const auto_scan = autoScanCheckbox ? (autoScanCheckbox.checked ? 1 : 0) : 1;

        if (!name || !target_dir) {
            alert('Please provide both Project Name and Target Directory.');
            return;
        }

        try {
            const res = await fetch('/api/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, target_dir, scans_per_day, auto_scan }),
            });
            const result = await res.json();
            if (!res.ok) throw new Error(result.message || 'Failed to create project');

            window.closeNewProjectModal();
            state.currentProjectId = result.project.id;
            
            // Re-fetch project list and trigger first scan
            await fetchProjects();
            await window.triggerProjectScan();
        } catch (err) {
            alert('Error creating project: ' + err.message);
        }
    };

    // Live Scan runner
    window.triggerProjectScan = async function() {
        if (!state.currentProjectId) return;
        const drawer = document.getElementById('live-scan-drawer');
        const logBox = document.getElementById('live-scan-log');
        
        if (drawer) drawer.classList.add('active');
        if (logBox) logBox.textContent = `Triggering ECDAT cryptographic discovery scan for ${state.currentProjectId}...\n`;

        try {
            const res = await fetch(`/api/project/${state.currentProjectId}/scan`, { method: 'POST' });
            const data = await res.json();

            // Start polling scan progress
            clearInterval(state.scanPollInterval);
            state.scanPollInterval = setInterval(async () => {
                const pollRes = await fetch(`/api/project/${state.currentProjectId}/scan-status`);
                const statusData = await pollRes.json();

                if (logBox && statusData.log_tail) {
                    logBox.textContent = statusData.log_tail.join('\n');
                    logBox.scrollTop = logBox.scrollHeight;
                }

                if (!statusData.active) {
                    clearInterval(state.scanPollInterval);
                    if (logBox) logBox.textContent += '\n\n[OK] Scan completed successfully. Refreshing dashboard metrics...';
                    setTimeout(() => {
                        if (drawer) drawer.classList.remove('active');
                        fetchProjects();
                    }, 1200);
                }
            }, 1000);

        } catch (err) {
            if (logBox) logBox.textContent += `\nError triggering scan: ${err.message}`;
        }
    };

    // Export standalone report
    window.exportStandaloneReport = function() {
        if (!state.currentProjectId) return;
        window.open(`/api/project/${state.currentProjectId}/export`, '_blank');
    };

    // App Initialization
    window.addEventListener('DOMContentLoaded', () => {
        window.addEventListener('hashchange', handleHashChange);
        handleHashChange();
        fetchProjects();
    });
})();
