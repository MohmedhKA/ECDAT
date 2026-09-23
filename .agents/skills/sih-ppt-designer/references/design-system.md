# Design System — Visual DNA of an SIH Slide

Read this before laying out any slide. It describes what was *consistent* across teams, years, and slide types — treat it as the template. Anything not mentioned here (exact icon choice, exact color hue, exact diagram wording) is a creative decision for the specific idea, not a rule.

## Why the slides look the way they do

SIH idea-submission decks are judged as static documents, not narrated presentations. A reviewer opens a PDF and skims. There is no one in the room to say "and here's why this matters." So the slide has to do that work itself: every section is labeled, every point is color-coded to its category, every claim is quantified where possible, and the whole slide reads almost like an infographic poster rather than a bullet-point outline. Keep this in mind whenever you're tempted to simplify toward a sparser, more minimalist pitch-deck look — that would actually read as *less* professional in this specific context, because it would look under-filled next to real submissions.

## Header (every slide, all four types)

- **Team emblem**, top-left: a small (~0.8-1") circle or thin-outlined oval containing the team's logo/icon and often the team name beneath or beside it.
- **Slide title**, top-center: bold serif font, ALL CAPS, large (32-40pt), e.g. "FEASIBILITY AND VIABILITY", "TECHNICAL APPROACH", "IMPACT AND BENEFITS". On slide 2 the title is the idea/project name instead of a generic label.
- **Hackathon logo**, top-right: the official hackathon emblem (brain/bulb icon + event name and year), small, consistent placement across every slide.

## Footer (every slide, non-negotiable)

- A **full-width, solid-color bar** (commonly a strong blue) pinned to the very bottom of the slide, roughly 4-5% of slide height.
- White text inside it: left side reads something like "@SIH Idea submission- Template" (or a team/event-specific variant), right side is the page number.
- **Deliberately keep this**, even though it looks like the kind of "decorative accent bar spanning the slide width" the general pptx skill's design guidance warns against. That warning exists to stop *arbitrary* AI-generated decoration; this bar is the opposite — it's the one fixed, mandated element every real SIH submission carries, and its absence is what would look wrong here.

## Body layout

- **2 to 4 columns**, sometimes an asymmetric split (e.g. narrower diagram column beside a wider text column). Content blocks are packed close together — noticeably less whitespace than a typical minimalist pitch deck, because the slide has to be self-sufficient without narration.
- Content lives inside **rounded-rectangle cards or pills**: a colored or bold header line at the top of the card, then a short paragraph or a small bullet list beneath.
- List markers vary by section: diamond (❖) or checkmark (✅) bullets for benefit/feature lists, hollow-circle or plain bullets for narrative lists, numbered or ➤-arrow bullets for ordered/sequential items (like a named list of solution components).

## Color-coding — the single most important convention

Each slide chooses **3 to 5 pastel category colors** and assigns one color per conceptual bucket:

- In a Feasibility slide: Technical / Financial / Operational / Social each get their own color.
- In an Impact slide: each stakeholder group (or each impact category) gets its own color.
- In an Idea slide: sometimes the "Innovation and Uniqueness" grid gives each differentiator its own color purely for visual variety, without a deeper taxonomy.

The same bucket keeps the **same color everywhere it appears on that slide** — header pill, card fill, any connecting lines. A common four-color set that recurs often: soft blue, soft teal/green, soft orange/peach, soft lavender/purple — but pick colors that fit the specific idea's domain (e.g. earthy greens for an environmental idea, warm oranges for agriculture) rather than defaulting to that exact set every time.

Backgrounds are white or near-white throughout. These are print/scan-friendly poster slides, not a dark "premium" theme — don't reach for dark backgrounds here even though that's common general pitch-deck advice.

## Icons

- Every benefit/feature/impact bullet gets a small, flat, colorful icon next to it that reinforces its specific meaning — an upward chart for growth, coins for revenue/savings, a shield for trust/security, a handshake for partnership, a gear for operations, and so on. Icons are illustrative flat-style, not photographic or 3D, with consistent stroke weight across a slide.
- Build icons the way the pptx skill's gotchas describe (react-icons rendered to SVG, rasterized with sharp, inserted as base64 PNG) — pick icons that map to the specific point being made, not generic filler icons.

## Diagrams

Three recurring diagram shapes, chosen by what they're illustrating:

1. **Box-and-arrow flowchart** — the default for any process, pipeline, or system architecture. Plain rounded or rectangular boxes in 2-3 tones, connected by thin directional arrows, laid out top-to-bottom or left-to-right. Used constantly in Technical Approach (data pipeline, system architecture, user journey) and sometimes in the Idea slide's Proposed Solution (especially for hardware/IoT prototypes, where the flow mirrors the physical build-test-deploy sequence).
2. **Donut / segmented diagram** — a central label (the core platform or idea) with 4-6 labeled segments radiating around it, each naming one capability or feature. Used when a solution is best described as a bundle of interlocking capabilities rather than a linear process.
3. **Hub-and-spoke diagram** — a central node (e.g. "Benefits of the Solution") with a handful of labeled boxes around it, one per stakeholder group. Used specifically for stakeholder-segmented impact breakdowns.

## Photos

Real photographs — working prototypes, field visits, user-testing or evaluation sessions, award ceremonies — appear whenever a team has tangible proof of work, most often in Technical Approach and Feasibility. They function as credibility evidence, not decoration, so **always include them if the user has real photos to offer**, captioned plainly, positioned next to the text they support (e.g. a defect close-up photo beside the sentence describing that defect type).

## Charts & tables

- Bar and pie/donut charts for financial projections and market share, with values labeled directly on or beside the chart rather than left to a legend alone.
- Tables for any structured comparison with 2-3 columns: Existing-vs-Proposed approach, Challenges-vs-Strategies, or a TAM/SAM/SOM market-sizing breakdown. Clean thin gridlines, a bold/colored header row.

## Typography

- Slide title: bold serif (Times New Roman-safe font), ALL CAPS, 32-40pt, centered.
- Section/card headers: bold sans-serif (Calibri/Arial-safe), 14-18pt, colored to match that section's category.
- Body text: sans-serif, 10-12pt given how dense these slides are, always left-aligned — never centered paragraphs.
- Inside running paragraphs (problem statements, solution overviews), bold **and** a color (often red, or the section's category color) is used on the 4-8 most important phrases so a skimming reviewer catches the differentiators without reading every word. This is different from the bold-lead-phrase bullet formula (see `writing-style.md`) — here it's inline emphasis within full sentences, not a fragment-per-bullet structure.

## Spacing

- Keep margins tighter than typical pitch-deck advice — roughly 0.3-0.4" from slide edges rather than 0.5"+, because the header/footer bands already consume vertical space and the content needs to stay dense.
- 0.15-0.25" gaps between cards within the same column; slightly more (0.3") between distinct column groups.
- Still avoid true overlaps or sub-0.1" gaps — dense is fine, cramped-to-the-point-of-illegible is not. Run the pptx skill's visual QA pass (render to images, inspect every slide) before calling it done.
