---
name: sih-ppt-designer
description: "Use whenever the user wants to design, draft, fill in, or restyle a Smart India Hackathon (SIH) idea-submission PowerPoint: the four core content slides (Idea, Technical Approach, Feasibility and Viability, Impact and Benefits). Trigger for SIH, \"Smart India Hackathon\", \"idea submission PPT/template\", a hackathon deck on the official SIH format, or \"build my hackathon slides\", \"make this look like an SIH deck\", \"draft the feasibility slide for my SIH idea\" — even without the word \"SIH\", if the four-slide structure, team logo, hackathon logo, and footer bar are described. Encodes the visual design system (colors, layout, icons, diagrams, mandatory header/footer) and the content structure and bold-lead-phrase wording style found across real competitive SIH decks, so output reads like an authentic submission, not a generic pitch deck. Pairs with the pptx skill for the actual .pptx file mechanics."
---

# SIH Idea-Submission PPT Designer

## What this is for

The Smart India Hackathon idea-submission PPT is not a spoken pitch deck — it's reviewed as a static document by a panel skimming dozens of PDFs, with no presenter narrating it. That single fact explains almost everything about how these slides look: they are dense, self-explanatory information posters, not the sparse "one idea per slide, huge font" style a startup pitch deck would use. Every design and wording choice in this skill exists to make a slide fully legible and persuasive on its own, in a few seconds of skimming.

This skill was built by studying real SIH submission decks across several teams and hackathon cycles (a tourism platform, a fabric-defect inspection system, a farmer advisory app, a waste-to-energy unit, a VR therapy tool, and a campus energy platform, among others) and extracting what was *common* across all of them versus what was *team-specific*. The common parts — layout skeleton, header/footer, color-coding logic, bold-lead-phrase wording, the instinct to quantify every claim — are the actual template. The team-specific parts (colors chosen, exact diagram shape, which stakeholders get called out) are creative choices this skill helps you make well, not rules to copy verbatim.

## The four slides this skill covers

| # | Slide title (as it appears on the deck) | Reference file |
|---|---|---|
| 2 | The idea's own name/title (e.g. project name) — NOT the literal word "Idea" | `references/slide-idea.md` |
| 3 | TECHNICAL APPROACH | `references/slide-technical-approach.md` |
| 4 | FEASIBILITY AND VIABILITY | `references/slide-feasibility-viability.md` |
| 5 | IMPACT AND BENEFITS | `references/slide-impact-benefits.md` |

Only slide 2's title is idea-specific; slides 3-5 always carry those exact fixed section titles. This skill does not have visual evidence for a title/cover slide or a closing references slide, so don't invent a design for those — ask the user for the official SIH template file if those are needed, or keep them to plain, standard conventions (team name, problem statement ID, theme/category, organization for the cover; a simple citation list for references).

## Workflow

1. **Gather the idea.** You need, at minimum: the problem being solved, the proposed solution, the core technology/approach, who benefits and how, and any traction the team already has (prototype, award, pilot data, mentor contact). If the user hasn't supplied these, ask — batch the questions instead of trickling them one at a time. Never invent numbers (market size, cost savings, revenue) — ask the user for their figures, or clearly mark a number as an illustrative placeholder if they want a draft before they have real data.

2. **Decide the Idea-slide's shape.** Read `references/slide-idea.md` — it has two structural variants (problem/solution-grid vs. process-flow-with-photos) and tells you how to pick based on whether the idea centers on a physical prototype/hardware or a pure software/service flow.

3. **Draft content for each slide** following the section-by-section structure in that slide's reference file, and write every bullet using the bold-lead-phrase formula in `references/writing-style.md`. Draft content before worrying about exact pixel layout — get the words right first.

4. **Apply the visual design system** in `references/design-system.md`: header/footer, color-coding per category, card/pill containers, icon usage, diagram styles, typography. Pick one 3-5 color category palette for the whole deck and reuse it consistently slide to slide (e.g. if Technical Feasibility is blue on slide 4, technical content elsewhere in the deck can echo that blue too).

5. **Build the .pptx.** This skill is about *what the deck should say and look like*; the pptx skill (`pptx` in this environment) is about *how to mechanically build and validate the file* — the pptxgenjs gotchas, icon rendering via react-icons + sharp, chart-building, and the required QA pass. Use both together. One deliberate override of the general pptx skill's advice: its "Avoid" list forbids full-width header/footer bars as an AI-slop signal — ignore that specifically for the bottom footer bar described in `references/design-system.md`. That bar is the mandated SIH template convention, present on every real submission, not decorative filler.

6. **QA against this skill, not just the pptx skill's generic checklist.** Beyond text overflow and alignment, check: every bullet follows the bold-lead-phrase pattern, every category has a consistent color across its cards, the footer and both logos are present on every slide, and every claim that could carry a number does.

## Quick-reference cheat sheet

If you only remember one page, remember this:

- **Header:** team emblem (circle/oval, top-left) · bold serif ALL-CAPS title, centered · hackathon logo (top-right).
- **Footer:** full-width solid-color bar, bottom-pinned, white text — "@SIH Idea submission- Template" + page number. Non-negotiable, on every slide.
- **Layout:** 2-4 packed columns, colored rounded-rectangle cards, very little empty whitespace compared to a normal pitch deck.
- **Color-coding:** each slide picks 3-5 pastel category colors; the same category keeps the same color everywhere on that slide.
- **Wording:** `**Bold lead phrase** : explanation` or `**Bold lead phrase** → explanation` — pick one separator, use it consistently. Active verbs (Boosts, Reduces, Ensures, Empowers). Quantify everything you can.
- **Diagrams:** box-and-arrow flowcharts for any process/architecture; donut/segmented diagrams for a set of features orbiting one core idea; hub-and-spoke for stakeholder-based impact.
- **Credibility:** real photos, award mentions, mentor contacts, and demo/prototype links are always worth including when the user has them — reviewers weight demonstrated traction heavily.
- **Paragraphs vs. bullets:** the one or two "problem statement" / "solution overview" intro blocks per slide get 2-4 sentence prose; everything downstream (innovation points, benefits, strategies) drops to bold-lead-phrase bullet fragments.

## Reference files

- `references/design-system.md` — colors, header/footer, cards, icons, diagram styles, typography, spacing. Read before building anything visual.
- `references/writing-style.md` — the bold-lead-phrase formula, verb choices, quantification habit, paragraph-vs-bullet rule, with real examples. Read before drafting any text.
- `references/slide-idea.md` — content structure for slide 2 (the idea/solution slide), including the two structural variants.
- `references/slide-technical-approach.md` — content structure for slide 3.
- `references/slide-feasibility-viability.md` — content structure for slide 4, including the near-universal 4-quadrant feasibility split and challenges/strategies pairing.
- `references/slide-impact-benefits.md` — content structure for slide 5, including stakeholder-segmented benefits and the business-model block.

Each is written to stand alone — read the one you need for the slide you're building, you don't need all six loaded at once unless you're building the full deck.
