# SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
### Solution Plan

---

## 1. What the problem statement is actually asking for

Breaking the PS description into discrete, testable requirements:

| # | PS requirement (verbatim ask) | What this means concretely |
|---|---|---|
| i | Identify & catalogue cryptographic artefacts — algorithms, keys, certificates, protocols, libraries, hardware modules, cloud services — across internal/external apps, products, infrastructure | A **scanner layer** that produces a complete inventory |
| ii | Comprehensive quantum risk assessment; identify systems prone to quantum attacks; highlight risk to sensitive data | A **risk-scoring engine** |
| iii | Classify artefacts by type, lifetime, business criticality; apply Mosca's algorithm (data lifetime + migration time vs. CRQC arrival) | The risk engine must be **temporal**, not just a static "RSA=bad" flag |
| iv | Recommend suitable PQC/hybrid alternatives based on risk profile, latency, cost | A **recommendation engine**, not just a report |
| Deliverable | CBOM analytics tool scanning source repos, binaries, libraries, container images → report in standardised formats → interactive GUI | **Scan → Classify → Recommend → Report → Visualise**, end to end |

Four requirements, four engines, one pipeline. That's the shape of the whole plan below.

---

## 2. Architecture

```
┌───────────────────────────────────────────────────────────┐
│ LAYER 5 — Dashboard (web GUI)                              │
│ Risk heat-map · inventory table · Mosca timeline view      │
└───────────────────────────▲─────────────────────────────────┘
                            │ reads
┌───────────────────────────┴─────────────────────────────────┐
│ LAYER 4 — Reporting                                         │
│ CBOM export (CycloneDX/ECMA-424 JSON) · PDF/HTML summary    │
└───────────────────────────▲─────────────────────────────────┘
                            │ consumes
┌───────────────────────────┴─────────────────────────────────┐
│ LAYER 3 — Recommendation Engine                              │
│ classical → PQC/hybrid mapping, latency & cost trade-offs   │
└───────────────────────────▲─────────────────────────────────┘
                            │ consumes
┌───────────────────────────┴─────────────────────────────────┐
│ LAYER 2 — Risk Engine (Mosca's X+Y>Z)                        │
│ quantum-vulnerability × business-criticality × urgency      │
└───────────────────────────▲─────────────────────────────────┘
                            │ consumes CBOM
┌───────────────────────────┴─────────────────────────────────┐
│ LAYER 1 — Discovery / Scanners                               │
│ source code · certificates · containers · (binaries, later) │
└───────────────────────────────────────────────────────────┘
```

**Design decision that shapes everything else:** the artefact schema is **not invented**. It's the real, standardised **Cryptography Bill of Materials (CBOM)** — a capability of **CycloneDX**, an OWASP project now formally standardised as **Ecma International ECMA-424** (current spec version 1.7, Oct 2025). CycloneDX and SPDX are the two BOM formats named under US Executive Order 14028. CBOM extends the standard `component` object with a `crypto-asset` type and a `cryptoProperties` block covering four asset types — `algorithm`, `certificate`, `relatedCryptoMaterial`, `protocol` — with fields that already include `classicalSecurityLevel`, `nistQuantumSecurityLevel`, `confidenceLevels`, `scanner`, and `detectionContext` (file path, line numbers, symbols). [CycloneDX CBOM capability page](https://cyclonedx.org/capabilities/cbom/) · [full schema, IBM/CBOM](https://github.com/IBM/CBOM)

This matters for the plan in a very concrete way: **the "produce a report in standardised formats" deliverable is satisfied by generating valid CBOM JSON — a spec that already exists and is already what enterprise tooling expects.** We're not asking a judge to trust a bespoke format.

---

## 3. Layer 1 — Discovery

We are **not** building a crypto static-analysis engine from zero. IBM Research has open-sourced exactly this under **CBOMkit** (Apache-2.0):

- **CBOMkit-hyperion** — SonarQube plugin, detects crypto assets in source code, emits CBOM
- **CBOMkit-theia** — detects crypto assets in container images and directories
- **CBOMkit-coeus** — CBOM viewer with statistics
- **CBOMkit-action** — GitHub Action for CI/CD-integrated scanning

Source: [github.com/IBM/CBOM](https://github.com/IBM/CBOM)

**The honest, feasible plan:** integrate/extend hyperion + theia for the parts they already cover, and put original engineering effort into the parts they *don't* — which is exactly Layers 2–3. A team that reinvents a source-code crypto scanner from scratch in a hackathon window is worse off than one that wires into a maintained, spec-compliant open tool and spends the saved time on the risk model. This is also a stronger judging story: "we know the ecosystem and didn't reinvent the wheel" beats "we wrote our own regex scanner" on a security-tooling problem statement specifically.

What still needs custom work in Layer 1:
- **Certificates:** X.509 parsing (public key algorithm, key size, signature algorithm, validity window) — straightforward with a standard crypto library, not covered by hyperion/theia directly.
- **Cloud service configs:** the PS explicitly names "cloud services" as an artefact type; hyperion/theia don't cover this. Scope: read-only scan of a small set of common config surfaces (e.g., TLS cipher policy on a load balancer, KMS key algorithm) rather than a general cloud crawler.
- **Binaries:** the hardest, most specialised item in the PS list (symbol-table / linked-library detection is tractable; disassembly-level constant scanning for hand-rolled crypto is a research problem on its own). This is scoped to Roadmap, not MVP — see §6.

---

## 4. Layer 2 — Risk Engine (the actual differentiator)

This is where the real engineering effort belongs, because it's the layer nothing off-the-shelf gives you.

**Mosca's inequality** (Michele Mosca, 2015 — this is the exact framework the PS names): if

> **X** (years the data must stay confidential) **+ Y** (years needed to migrate) **> Z** (years until a cryptographically-relevant quantum computer, or an equivalent hard deadline)

...then the asset is at risk *today*, not someday — because by the time Z arrives, migration won't have finished in time to protect data whose secrecy window runs past Z.

**The design choice that makes this defensible rather than speculative:** don't try to pin Z to "when will a quantum computer exist" — that's genuinely, unavoidably contested among experts, and asserting a specific year would be exactly the kind of unsupported claim we're trying to avoid. Instead, **anchor Z to a real regulatory deadline**, which is a fact, not a forecast:

- **NIST IR 8547** ("Transition to Post-Quantum Cryptography Standards," initial public draft, Nov 2024): RSA, ECDSA, ECDH, DH at ~112-bit strength (RSA-2048, P-256) are **deprecated after 2030**, **disallowed after 2035**. Even higher-strength classical (RSA-3072, P-384) is disallowed by 2035. AES-128/192/256 and SHA-2/3 are *not* on this schedule — symmetric crypto is only quadratically weakened by Grover's algorithm, not broken.
- As of mid-2026 this has real teeth: **Executive Order 14412** treats the 2030 date as a compliance deadline for federal high-value/high-impact systems, and **OMB M-26-15** directs agencies to align migration plans with IR 8547, with 2035 as the full-migration date.
- For a more aggressive Z, national-security-adjacent deployments can use **NSA CNSA 2.0**, which sets required dates of **2030–2033** for most categories.

Sources: [NIST IR 8547 tracker/summary](https://www.encryptionconsulting.com/education-center/nist-ir-8547-sp-800-131a-algorithm-transitions/) · [PQC Mandate Tracker](https://pqcmandates.com/mandate/nist-ir-8547) · [NIST IR 8547 ipd, original PDF](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)

Making Z a configurable regulatory anchor rather than a guessed date is itself a legitimate design decision worth stating explicitly in the pitch — it's more defensible under judge questioning than any specific "quantum computers arrive in 20XX" claim would be.

**X (data lifetime)** and **Y (migration time)** are inherently org-specific — no tool can know these with certainty. The honest approach: ship sensible default tiers (X: ephemeral <1 day / short-term <1yr / long-term 10yr+ / permanent; Y: cert rotation = weeks, embedded/firmware = months–years, custom protocol re-engineering = 1yr+) and let the artefact's own metadata (cert validity period, a config tag) override the default where available. State this as a known limitation, not a solved problem — a judge who asks "how do you know Y for an arbitrary system" deserves "we default, and we let you override" rather than an invented precision.

**Output of this layer:** each CBOM `crypto-asset` gets a composite score from {quantum-vulnerability class (populated into the CBOM's own `nistQuantumSecurityLevel` field, 0 = not quantum-safe, 1–5 = NIST category) × business criticality tag × Mosca's X+Y-vs-Z verdict} → a risk tier (Critical/High/Medium/Low).

---

## 5. Layer 3 — Recommendation Engine

Maps each flagged classical algorithm to its standardised replacement, with real trade-off data rather than a bare "use ML-KEM" instruction:

| Detected | Recommend | Why / trade-off |
|---|---|---|
| RSA/ECDH key exchange | **ML-KEM (FIPS 203)**, deployed today as hybrid **X25519MLKEM768** | Real production deployment: Chrome (default), Firefox 132+, Cloudflare edge, BoringSSL, OpenSSL 3.5 (Apr 2025) all support this exact hybrid group. Measured overhead: **~1,088 bytes** added to ClientHello, **~10–20ms** median latency — cite this instead of a vague "some overhead" |
| RSA/ECDSA signatures | **ML-DSA (FIPS 204)** — pick 44/65/87 by target NIST category | Direct parameter-set-to-category mapping, straight from the FIPS 204 spec |
| Long-lived roots / firmware / boot signing | **SLH-DSA (FIPS 205)** | Hash-based only, most conservative security assumption, at the cost of larger signatures — the right call for 20-year firmware lifetimes, wrong call for high-frequency signing |
| General guidance | **Hybrid over pure-PQC during the transition window** | IR 8547 itself keeps this door open: well-designed classical+PQC hybrids remain permitted even after the 2035 disallowance date, as long as the hybrid doesn't weaken the PQC component |

Sources: [FIPS 203/204/205 finalization, Aug 2024](https://evertrust.io/blog/hybrid-post-quantum-certificates/) · [X25519MLKEM768 deployment status](https://www.postquantumsecurity.org/publications/X25519+MLKEM768.html) · [handshake overhead measurements](https://arxiv.org/pdf/2603.06969)

Context worth having in your back pocket for judges: a 2026 internet-scale measurement study found **50.7% of scanned domains remain fully classically vulnerable**, with the other 49.3% only *partially* ready via hybrid key exchange — this is not a hypothetical problem. ([source](https://arxiv.org/pdf/2606.16473))

---

## 6. Scope: MVP vs. Stretch vs. Roadmap

Being explicit about this is what makes the plan *feasible* instead of a wish list.

**MVP — build this, demo this:**
- Source scanning integrated with CBOMkit-hyperion for 2–3 languages your team actually knows well
- Custom X.509 certificate scanner
- Valid CBOM JSON export (real schema compliance, checkable with the public `ajv` validator against IBM's published schema)
- The Mosca's risk engine (§4) — this is the genuine, judgeable, hard-to-copy contribution
- The recommendation engine (§5)
- A working dashboard: risk heat-map + inventory table + drill-down to file/line (the CBOM schema's own `detectionContext` gives you this for free)

**Stretch — if time allows:**
- CBOMkit-theia integration for container image scanning
- CBOMkit-action-style CI/CD hook
- More source languages

**Roadmap — say this out loud, don't pretend it's done:**
- Full binary/firmware-level detection (disassembly + constant scanning)
- Cloud-service config crawling beyond a fixed sample set
- Auto-generated migration patches (recommend → apply, not just recommend)

A judge who hears "here's what's built, here's what's next, here's why we drew the line there" trusts the team more than one who claims full PS coverage and can't back it up under a follow-up question.

---

## 7. The validation story: your own system as the test case

Instead of demoing against a toy repo, run ECDAT against the real e-voting system already built (Hyperledger Fabric v3.0.0 / SmartBFT, ephemeral RSA-2048 Chaum blind signatures for voter anonymity, ML-DSA-65/FIPS 204 for Merkle batch ledger anchoring, LWE-based homomorphic tallying — now confirmed at **NIST Security Level 3**). This genuinely is a real, substantial, mixed-crypto-estate codebase, and using it as the flagship demo is honest — every part of that description is something already established and verified in this conversation, nothing new is being claimed here.

The specific thing this demonstrates well: ECDAT should correctly flag the RSA-2048 layer as *quantum-vulnerable by algorithm class* — but the Mosca's engine should also correctly recognise it as **low urgency** (X ≈ 0: keys are ephemeral and destroyed at election close, so there's no long-lived ciphertext to harvest), while the ML-DSA-65 and LWE layers register as already-migrated. A generic team's tool that just flags "RSA = bad, migrate now" would get this wrong. Showing your tool get it *right* — on a real system, not a synthetic example — is the actual differentiator, and it's one no amount of benchmark-number-polishing can substitute for.

One caution worth stating plainly: don't put specific throughput/latency numbers for the e-voting system itself into the submission unless they come from a benchmark you run fresh and can reproduce live if asked. That's not a hypothetical risk — it's exactly the issue this conversation already worked through once.

---

## 8. Work breakdown — what's actually yours

| Component | Who | Why |
|---|---|---|
| Risk Engine (Mosca's, §4) | **You** | This is cryptographic risk modelling — directly your research area, not something a generalist teammate can credibly own |
| Recommendation Engine (§5) | **You**, possibly + 1 | Needs someone who can correctly reason about FIPS 203/204/205 parameter selection, not just look up a table |
| e-voting validation integration (§7) | **You** | You're the only one who knows that codebase |
| Scanner integration (hyperion/theia wiring) | Teammate(s) | Systems/integration work, not crypto-specialist work |
| Dashboard (§ Layer 5) | Teammate(s) | Standard frontend work — React + a charting library, consuming the CBOM JSON your engines already produce |
| CBOM/reporting plumbing | Shared | Schema is fixed by the standard; this is mostly serialization work |

This split means your personal time goes entirely into the two layers that are genuinely hard to fake and genuinely yours — not into rebuilding a scanner IBM already open-sourced.

---

## 9. Sources referenced in this plan

- CycloneDX / CBOM capability: https://cyclonedx.org/capabilities/cbom/
- CBOM schema & IBM open tooling (CBOMkit): https://github.com/IBM/CBOM
- NIST IR 8547 (2030 deprecation / 2035 disallowance): https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
- NIST IR 8547 federal compliance status (EO 14412, OMB M-26-15): https://pqcmandates.com/mandate/nist-ir-8547
- FIPS 203/204/205 finalization and current hybrid TLS deployment: https://evertrust.io/blog/hybrid-post-quantum-certificates/
- X25519MLKEM768 real-world deployment: https://www.postquantumsecurity.org/publications/X25519+MLKEM768.html
- Hybrid handshake overhead measurements: https://arxiv.org/pdf/2603.06969
- 2026 internet PQC-readiness measurement study: https://arxiv.org/pdf/2606.16473
