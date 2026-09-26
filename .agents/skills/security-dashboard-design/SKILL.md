---
name: security-dashboard-design
description: Design and build modern, human-crafted web dashboards for SIEM, SOC, threat intelligence, incident response, vulnerability management, identity/access risk, or any other cybersecurity operations interface. Steers hard away from two failure modes at once — the "hacker movie" cliché (matrix green-on-black, neon terminal glow, skulls and padlocks) and generic "AI slop" dashboard defaults (dark-mode-only, identical rounded gradient cards, meaningless stat tiles) — in favor of calm, dense, functional layouts like real enterprise security products. Covers the click-a-card-to-drill-into-a-detail-view interaction pattern. Use this whenever someone asks to design, mock up, redesign, or build a security dashboard, a SOC/SIEM console, a threat-monitoring UI, an incident-response screen, a vulnerability-management view, or any admin/ops dashboard where they ask for a "modern" or "not AI-generated" look — even if they never say "SIEM" or "SOC" outright.
---

# Security Dashboard Design

You're not mocking up a movie hacker's screen and you're not generating a generic admin template. You're designing the thing a real security analyst stares at for eight hours a shift, using it to decide what to look at next. That job — fast triage, correct priority, no noise — is what should drive every visual decision here, not "security = dark + green + scary."

Read `references/patterns.md` before you start building. It has a starter color system, a catalog of real SOC/SIEM widgets to ground the layout in, and a concrete code pattern for the click-through navigation this skill is built around. Come back to it while you work rather than trying to hold it all in your head.

If this session has the `frontend-design` skill available, read it too — it covers typography, motion, copy, and self-critique in more depth than is worth repeating here. This skill is the security-specific delta on top of it.

## The two failure modes, and why both are wrong

**Failure mode 1 — "hacker" pastiche.** Black background, neon green monospace text, a matrix-rain effect, a giant glowing padlock or skull icon, red alarm-strobe everywhere. This is set-dressing from movies, not how anyone who actually does this job wants to work. It's exhausting to read for a full shift, it uses color for atmosphere instead of meaning (so real alerts stop standing out), and it signals "this was designed by someone who's never used a SOC tool" faster than anything else.

**Failure mode 2 — templated AI-dashboard defaults.** Because this skill exists partly to counter this: without a strong steer, a generated security dashboard tends to land on identical rounded cards with soft drop shadows, a purple-to-blue gradient somewhere, four meaningless-looking stat tiles up top ("1,284" with a tiny up-arrow and no unit), a bright acid accent color used decoratively rather than to mean something, and a world map with pulsing dots because "cyber" implies a world map. This is the same tell as any other AI-generated interface — it just happens to also *look* more legitimate here because dashboards are already card-and-chart heavy, so the genericness hides better. Don't let that fool you into skipping the same scrutiny you'd apply anywhere else.

The fix for both is the same: design from the actual content and the actual job, the way you would for any other real product.

## Ground it in what the screen is actually for

Before laying anything out, decide (or ask, if it's not given): which job is this? A SOC analyst's live triage queue, a CISO's weekly posture summary, a vulnerability-management backlog, an identity/access risk view, an incident's own timeline — these are different products with different information needs, not the same dashboard with a different title. Pick real, specific content for the primary use case and build with it throughout, the same way you would ground any other design in its subject matter. `references/patterns.md` has a catalog of real widgets organized by job to help you pick.

A few things that are true of this domain specifically and should shape the design:

- **Severity is the organizing principle, not decoration.** Critical/high/medium/low (or your SIEM's equivalent scale) needs to be instantly scannable at a glance across the whole screen — that's the core job of a triage UI. This is the one place a strong, consistent color-coding system is functional rather than decorative, precisely because it's used sparingly and consistently. See the color section below.
- **It's read for hours, not glanced at once.** Favor a calm, low-fatigue palette and real information density over a flashy hero moment. This is an operations tool, not a landing page — the "hero" section pattern from general web design doesn't apply here the way it would to a marketing site.
- **Numbers need units and context.** "1,284" alone is the classic AI-dashboard tell. "1,284 open alerts · 312 unassigned" tells an analyst something. Every metric on the screen should answer "so what do I do about this" for the person reading it, not just look like a stat.
- **Most of what's on screen is real or realistic log/event/asset data.** Write plausible entries (hostnames, CVE IDs, source IPs in documentation ranges, rule names) rather than "Item 1 / Item 2" placeholders — placeholder content reads as templated as fast as placeholder design does.

## Color: a functional severity system, not a vibe

Don't reach for neon-on-black by default, and don't reach for a single decorative accent color either — build a small, deliberate palette where color is doing a specific job:

1. **A calm neutral base** for backgrounds, cards, and chrome — light or dark, both are legitimate (see below), but either way it should be a considered neutral (warm or cool grey, off-white, deep charcoal or navy), never pure `#000`/`#FFF` and never the reflexive AI-slop cream-plus-terracotta or near-black-plus-acid-green combos called out in `frontend-design`.
2. **One brand/interactive accent** for links, active states, and primary actions — used sparingly, not painted across every card border.
3. **A short, fixed severity scale** (critical → informational) reserved *only* for actual severity signaling — never reuse these hues for anything decorative, or they stop meaning anything. Keep them slightly desaturated rather than neon; a legible, printable red reads as more serious and more professional than a glowing one.

Concrete starter values for both a light and a dark version of this system are in `references/patterns.md` — use them as a starting point, not a mandate; make the specific choice for your brief.

**On dark mode specifically:** dark UIs are genuinely good for screens people stare at for a long shift, so don't avoid dark mode — avoid *only* offering the hacker-terminal version of it. A well-made dark theme (think a modern IDE or a tool like Linear or Grafana's newer themes: deep charcoal or navy, not black; muted rather than neon accents; real contrast ratios) is a completely different object from "green text on black," even though both are technically "dark mode." If you're only building one theme, a light or dim neutral theme is often the safer default for something that needs to read as "modern enterprise software" rather than "terminal" — but let the brief decide.

## Typography and layout

Dense, data-heavy screens live or die on type. Use a clean, highly legible sans-serif for UI text and labels, and reserve a monospace face for what's actually monospaced data — IPs, hashes, log lines, IDs — not for every small label the way generic dashboards do reflexively. Keep a real type scale with clear weight differences between a metric, its label, and a section heading, rather than relying on size alone.

Favor a structured grid over a wall of identical rounded cards. Real triage tools mix table/list views (for the alert queue, the log stream, the case list) with a smaller number of chart or gauge modules (for trends and posture scores) — mixing density is itself a signal of a considered layout rather than a templated one. Give every module a single job; a card that's trying to show a trend, a count, and a status all at once usually needs to be split in two.

## The interaction: click a module, get its full detail view

The requirement to make a card or section navigate to a focused view with clear detail on just that topic is a real, common SOC-tool pattern (an analyst clicks an alert to get the full case; clicks the vuln-count tile to get the filtered CVE list) — build it as a real drill-down, not just a bigger version of the same summary card.

The detail view for a section should generally include what the summary card couldn't fit: a filterable table or list, a longer time range, related items, and whatever specific fields matter for that data type (full alert metadata, an asset's patch history, a case's timeline). Design it as its own considered screen, not an afterthought.

For how to actually wire up "click → opens in a new tab showing that view," see the navigation pattern and code sample in `references/patterns.md`. The short version: build the dashboard as one page with hash-based routing (`#/alerts`, `#/vulnerabilities`, etc.), and make each module's link open its hash in a new tab — that gives a genuine new-tab, deep-linkable detail view while staying inside a single self-contained file. If your environment can't spawn real new tabs (e.g. a constrained preview), the same routing still works as an in-place view switch; just say so rather than silently downgrading the requirement.

## Before you ship it, check yourself against both failure modes

Look at the finished screen and ask:

- If I removed the title, would a security analyst recognize this as a real tool for their job, or does it read as a generic "cyber" mockup?
- Is there a single default accent color painted decoratively across borders, icons, and buttons — or is color only appearing where it means something?
- Does every number on screen have a unit and enough context to act on, or are there floating stat tiles?
- Is dark mode (if used) a considered dark theme, or is it secretly just "black background, green text" with extra steps?
- Did I build one memorable, well-considered layout decision, or did I reach for the identical-rounded-card grid by default?
- Does clicking through actually lead somewhere more useful, or is the "detail view" just the summary card again at a bigger size?

If any answer is the bad one, that's the thing to fix before calling it done — not a note to leave for later.
