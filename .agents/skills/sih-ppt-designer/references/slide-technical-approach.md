# Slide 3 — Technical Approach

Fixed title: "TECHNICAL APPROACH."

This slide answers one question for the reviewer: *does this team actually know how to build what they're proposing?* Everything on it should read as evidence of real technical grounding, not aspirational hand-waving — specific tools, a specific pipeline, a specific architecture diagram, and (when available) specific proof the team has already built part of it.

## Core sections

1. **Methodology and Process** — an ordered list (hollow-circle or numbered bullets) of 5-7 pipeline stages in their natural sequence. The recurring shape of this sequence: data/requirements collection → preprocessing/integration → core model or system development → verification/security/testing → real-time or interactive delivery → scaling/improvement. Each stage is a bold-lead-phrase bullet (stage name, then a one-line description of what happens at that stage). This section is almost always plain text/bullets, not a diagram.

2. **Technology Stack** — shown as a **grid of real product/brand logos**, not a text list of categories. If the idea has physical hardware, split into a Hardware column (cameras, boards, sensors, motor drivers — usually with small product photos or icons) and a Software column (languages, frameworks, cloud platforms, ML libraries). Naming the actual tools (Python, React, MongoDB, AWS, TensorFlow, PyTorch, etc.) rather than generic categories is part of the credibility signal here.

3. **System architecture / user-flow diagram** — a box-and-arrow flowchart (see `design-system.md`) showing the real data or user journey through the system end to end: something like User Input/Authentication → Central Server or Processing Layer → Core Platform Modules → Recommendation/Calculation Engine → Output. This is usually the single largest visual element on the slide and is often positioned as its own column so it reads at a glance, separate from the bulleted methodology text.

4. **Credibility elements** (include whenever the user has them, they matter a lot on this slide specifically):
   - Achievement badges — named awards or competition placements, stated directly rather than folded into other text.
   - Real photos — field visits, prototype-build photos, testing sessions with real equipment or real users.
   - A clickable link to a demo/explanation video or working-prototype folder, usually set inside its own small highlighted box so it doesn't get lost among the diagrams.
   - For teams working on multiple models or a layered technical strategy (e.g. a lightweight edge model plus a heavier cloud-validation model plus a fallback model), a small dedicated callout box explaining that trade-off decision in 2-4 bold-lead-phrase bullets — this shows engineering judgment, not just a feature list.

## Wording notes specific to this slide

- The Methodology and Process bullets are the one place on this whole slide type where the bold-lead-phrase pattern applies to *technical stage names* rather than benefits — "Data Collection & Integration: Gather destination, transport, accommodation... from government portals, IoT, geo-location, and user inputs" is the right register: specific about *what data* and *what sources*, not just "collect data."
- Avoid vague technology claims ("uses AI," "cloud-based") without naming the specific technique or platform — every real deck examined names actual frameworks, actual model families, actual cloud providers.

## Ask the user, if you don't already know

- What's the actual tech stack — specific languages, frameworks, cloud services, and (if hardware) specific components?
- What are the 5-7 real stages this system goes through from data/input to final output?
- Does a working prototype, demo video, or field test already exist? (If yes, always surface it — it's one of the strongest credibility signals on this slide.)
- Is there a specific technical trade-off or layered strategy worth calling out (e.g. edge vs. cloud processing, a fallback for low-connectivity conditions)?
