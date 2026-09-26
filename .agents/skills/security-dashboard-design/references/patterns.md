# Reference patterns for security dashboard design

Starting points, not mandates — adapt every value here to the specific brief.

## 1. Color tokens

A severity scale is the one place strong, saturated color is functional. Keep it identical across light and dark themes so meaning never shifts; only the neutrals and surfaces change.

**Severity scale (use in both themes):**
```
--sev-critical:    #C4362D   /* desaturated red, not neon */
--sev-high:        #D97B2B   /* amber-orange */
--sev-medium:      #C9A227   /* muted gold, not yellow-on-white */
--sev-low:         #4A7A8C   /* slate blue */
--sev-info:        #6B7280   /* neutral grey */
```

**Light theme:**
```
--bg-page:      #F5F6F8   /* cool off-white, not pure #FFF */
--bg-surface:   #FFFFFF
--bg-sunken:    #EDEFF3   /* tables, code blocks */
--border:       #DCE0E6
--text-primary: #1A1D23
--text-muted:   #5B6270
--accent:       #2F5EA8   /* one considered blue, used sparingly */
```

**Dark theme (a real dark theme, not a terminal):**
```
--bg-page:      #14171C   /* deep charcoal/navy, never pure #000 */
--bg-surface:   #1B1F26
--bg-sunken:    #101317
--border:       #2A2F38
--text-primary: #E7E9ED
--text-muted:   #9AA1AC
--accent:       #6E9BE0   /* lifted for dark contrast, still restrained */
```

Rules of use: the severity colors never appear except to mark actual severity (a status pill, a queue count, a chart series keyed to severity). The accent never appears more than once or twice per screen outside of links. Everything else is neutrals.

## 2. Widget catalog, by job

Pick the job first, then pull only the widgets that job actually needs — a real tool doesn't cram every possible module onto one screen.

**SOC analyst / live triage**
- Alert queue: severity, rule/detection name, asset, first-seen, status, assignee — table or list, sortable, this is the main surface
- Open incidents / active cases with status (new, investigating, contained, closed)
- MTTD / MTTR trend (mean time to detect / respond) over the last N days
- Log ingestion health: volume by source, any pipeline gaps or lag
- Analyst workload: cases per assignee, unassigned count

**CISO / leadership posture summary**
- Overall risk or compliance posture score (e.g. against CIS Controls, SOC 2, a custom baseline) with trend
- Open critical/high findings by business unit or asset group
- Top attack techniques observed, mapped to MITRE ATT&CK tactics
- Patch/remediation SLA compliance
- Incidents this period vs. last period

**Vulnerability management**
- CVE counts by severity, with counts that are actually clickable/filterable, not static
- Mean time to remediate by severity
- Assets overdue for patching, sorted by exposure
- Newly disclosed CVEs affecting known assets (watchlist)

**Identity / access risk**
- Anomalous login attempts (impossible travel, new device, off-hours) with real-looking entries
- Privileged account activity
- MFA/coverage gaps
- Access reviews pending

**Incident detail (a drill-down target, not a top-level dashboard)**
- Full timeline of events for the case
- Affected assets/accounts
- Analyst notes and actions taken
- Related alerts and IOCs

A geo/world map of source IPs or login attempts is legitimate when the data genuinely benefits from geography — but treat it as one module among several, styled in the same restrained palette as everything else (a clean dot-density or choropleth), not a full-bleed radar-sweep centerpiece. It's the single most overused "cyber" cliché in stock dashboard mockups, so it has to earn its place with real data, not just be included because the topic is security.

## 3. Click-through navigation: hash routing + real new tabs

The pattern: one self-contained HTML file, a router keyed off `location.hash`, and links that open their target hash in a new tab. This gives every module a real, deep-linkable detail view without needing multiple hosted files.

```html
<!-- Dashboard card -->
<a class="module-card" href="#/view/alerts" target="_blank" rel="noopener">
  <h3>Open alerts</h3>
  <p class="metric">312 <span class="metric-unit">unassigned of 1,284</span></p>
</a>
```

```js
// Views: 'summary' (the dashboard) plus one per module, e.g. 'view/alerts'
function renderApp() {
  const hash = location.hash.replace(/^#\/?/, ''); // '' or 'view/alerts'
  const root = document.getElementById('app');

  if (!hash || hash === 'dashboard') {
    root.innerHTML = renderDashboard();
  } else if (hash.startsWith('view/')) {
    const section = hash.slice('view/'.length);
    root.innerHTML = renderDetailView(section); // full table, filters, etc.
  } else {
    root.innerHTML = renderDashboard();
  }
}

window.addEventListener('hashchange', renderApp);
window.addEventListener('DOMContentLoaded', renderApp);
```

Why `target="_blank"` on a same-page hash link works: the browser treats `yourfile.html#/view/alerts` as a distinct URL from `yourfile.html`, so opening it with `target="_blank"` genuinely opens a new tab at that address, loads the same file fresh, and your router renders the detail view because that's what the hash says on load. The analyst ends up with the dashboard in one tab and the drill-down in another, exactly like clicking into an alert in a real SIEM — and the detail view is bookmarkable/shareable since it's a real URL.

If the environment you're building in can't spawn a real new tab (some sandboxed previews block `window.open`/`target="_blank"`), drop `target="_blank"` and let the same router swap the view in place instead. It's a smaller win than a real new tab, but the routing logic and the detail views themselves don't change — say plainly that you made this adjustment rather than letting the click silently do nothing.

Each detail view should feel like its own screen: a back link to the dashboard, a real title, and the fuller data the summary card didn't have room for (see the widget catalog above for what belongs in each one).
