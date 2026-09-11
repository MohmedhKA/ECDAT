# ECDAT — Cross-Verified Competitive Analysis & Final Solution Plan
### For Mohmedh + coding agent — SIH26164

**How to read this document:** every claim is tagged with where it came from. `[C51]`/`[C52]`/`[GEM]`/`[PPX]` = one of your four uploaded reports (Claude-1, Claude-2, Gemini, Perplexity). `[VERIFIED: <url>]` = I independently checked this myself this session, source given. `[UNVERIFIED]` = stated in a report, I could not confirm it, treat as a claim, not a fact, until someone checks it. Nothing in the "Final Design" section rests on an `[UNVERIFIED]` claim alone.

---

## 1. The direct answer to your question

You asked the right question before writing any code: **does something like this already exist, or is there a reason it hasn't been built?** The honest answer, after checking: **it already exists, and it's well-funded.** This isn't a limitation blocking the idea — it's competition you need to know about before you pitch "novel."

Specifically: **SandboxAQ's AQtive Guard already does the thing all four reports present as ECDAT's headline novel contribution** — dynamic, runtime discovery of cryptography via instrumentation, not just static source scanning. Its "Application Analyzer... hooks into running processes to log all calls to crypto libraries (instrumenting applications at runtime)" `[VERIFIED: postquantum.com/post-quantum/cryptographic-inventory-vendors]`, alongside a Network Analyzer and Filesystem Analyzer for the other two surfaces (traffic, binaries/at-rest files) `[VERIFIED: sandboxaq.com/solutions/security/discover]`. This isn't a lab prototype: SandboxAQ (an Alphabet spin-off) has deployed it at SoftBank since April 2024, lists Vodafone Business and Mount Sinai Health System as customers, reached FedRAMP Ready status in December 2025, and **signed a five-year contract with the U.S. Department of War CIO in December 2025** to run this exact workflow across DoW systems `[VERIFIED: securitystack.app/products/aqtive-guard]`.

Separately, **IBM has both a commercial product (Quantum Safe Explorer, launched October 2023) and a March-2025 IBM Research paper (Cryptoscope) that already do rigorous static discovery** with published, peer-reviewed accuracy numbers `[VERIFIED: arxiv.org/pdf/2503.19531]`. And the specific "solve the dynamic/reflection blind spot via runtime instrumentation" idea that all four of your reports present as ECDAT's novel contribution has **published academic prior art going back to 2021** — CRYLogger (IEEE S&P 2021, JCA runtime instrumentation) and CRYScanner (2021, static+dynamic hybrid) are both cited and discussed in the Cryptoscope paper's own related-work section `[VERIFIED: same, §5.1]`. None of your four reports found or cited any of this.

That's the real finding of this exercise. It's not bad news — it's exactly the diligence you asked for, and it changes what "absolute solution" should mean: not "build a cleverer scanner than everyone else" (you can't out-engineer a company with a DoW contract and Google money in a hackathon timeline), but **find the specific place your unique position actually gives you an edge.** Section 4 below is that.

---

## 2. What the existing competitive landscape actually looks like

None of the four reports did this part — they all jumped to "how do we build X" without first asking "who already builds X." Here's what's actually out there, sourced:

| Player | What it actually does | Real limitation (sourced) |
|---|---|---|
| **SandboxAQ AQtive Guard** | 3-analyzer discovery (network/application-runtime/filesystem), policy enforcement (FIPS-140, PCI-DSS), SOC2 + ISO27001 + FedRAMP Ready, $-serious enterprise deployment | Runtime instrumentation has real overhead/stability cost — vendors themselves note it's often restricted to test environments, not full production `[VERIFIED: postquantum.com/post-quantum/cryptographic-inventory-vendors]`. Academically assessed as unable to build a semantically *complete* crypto asset — presence-only, not full operational semantics `[VERIFIED: arxiv.org/pdf/2503.19531, §5.1]` |
| **IBM Quantum Safe Explorer / Guardium Cryptography Manager** | Static source scanning → CBOM, plus a broader Guardium suite for network-level crypto-agile remediation without code changes `[VERIFIED: ibm.com/quantum/quantum-safe]` | Explorer's own docs describe it as providing "**a static view**" `[VERIFIED: ibm.com/docs/.../quantum-safe-explorer-overview]` — the dynamic gap the reports describe is real *for this specific product*, just not for the vendor's full suite or for their competitor (AQtive Guard) |
| **IBM Research — Cryptoscope** (not yet a shipped product, March 2025 paper) | Full data/control-flow slicing → *semantically complete* crypto assets (mode, padding, IV source, key derivation — not just "AES is present"). Benchmarked: 92% exact-match recall / 98% with partial matches, 97% precision, ~1,650 lines/sec, and **outperforms CogniCrypt, CryptoGuard, SonarQube, FindSecBugs** on the CamBench benchmark `[VERIFIED: arxiv.org/pdf/2503.19531]` | Static only, single-repo scope (doesn't cross into dependency libraries), Java-proven with Python/Go/C planned — and it's IBM Research, i.e. this *is* roughly the ceiling of what's achievable on pure static analysis right now |
| **CBOMkit** (hyperion/theia/coeus/action) | IBM donated this to the **Post-Quantum Cryptography Alliance (PQCA)**, a Linux Foundation project, in 2024 `[VERIFIED: researcher.ibm.com/blog/cryptographic-cbom-linux-foundation]` — now at `github.com/PQCA/cbomkit`, not `github.com/IBM/CBOM` (correction to what I told you earlier this session). Actively developed — Go support added, a new "CBOMkit Pipeline" for dependency-level detection in progress `[VERIFIED: linkedin.com/company/post-quantum-cryptography-alliance]` | Founding members include actual co-authors of Kyber/Dilithium/Falcon/SPHINCS+ `[VERIFIED: linuxfoundation.org/press/...]` — this is not a gap you can out-cryptography |
| **InfoSecGlobal AgileScan / AgileSec Analytics** | Certificate/key/library discovery | Same semantic-completeness gap as AQtive Guard, per the same academic assessment `[VERIFIED: arxiv.org/pdf/2503.19531, §5.1]` |

**Bottom line for your pitch:** "we do dynamic discovery" is not a differentiator — three different organizations already ship it. "We do *semantically complete* discovery" is IBM Research's current frontier, not a hackathon-beatable target. Don't lead with either.

---

## 3. What checked out vs. what didn't, across your four reports

You asked me to point out where things came from and whether they hold up. Report by report:

**Perplexity `[PPX]` — most reliable of the four.** Real, resolvable footnotes: direct links to NIST FIPS PDFs, the actual whitehouse.gov OMB M-26-15 PDF, IETF datatracker, USENIX Security, IACR ePrint. I independently checked several of its central claims (OMB M-26-15's existence/contents, IBM Quantum Safe Explorer's real static-only limitation, AQtive Guard's real capabilities, PQCA's stewardship of CBOMkit) and every one held up. It's also the only one of the four that even mentions AQtive Guard and IBM Quantum Safe Explorer by name as prior art, though it still doesn't draw the "this undermines our novelty claim" conclusion.

**Claude-1 `[C51]` and Claude-2 `[C52]` — architecturally sound, citation-unverifiable.** Both correctly identify PQCA's stewardship of CBOMkit (which I confirmed) — a good sign they're not pulling facts from nowhere. But `[C51]`'s citations are bare `[web:N]` tags with no bibliography attached, so none of its specific numbers (overhead percentages, timing tables) are independently checkable from the document itself. `[C51]` also names two CBOMkit modules — "themis" (policy engine) and "mnemosyne" (centralized store) — that I found **no corroborating evidence for** anywhere in PQCA's own materials; treat these as unverified, possibly invented, until you find them yourself. `[C52]` has a real (if thin) source list mixing solid academic citations (arXiv, IACR ePrint) with some lower-authority domains I can't vouch for (shattered.io, netguardia.com).

**Gemini `[GEM]` — real citation list, but with a serious quality problem.** It has actual URLs, which is good. But mixed into that list are sources with **zero topical relevance**: a blog post about building carbon credit markets, a Chinese-language cybersecurity-acronym glossary, a federal AI-governance-policy PDF, a Scribd document about blockchain disrupting brokers. That's not a minor blemish — it means whatever produced this list didn't check relevance before citing, which should lower your trust in the *rest* of its citations too, even the ones that look fine on their face. Don't hand this specific report to a judge as evidence of anything without re-verifying the individual claim first.

**Shared blind spot, all four:** none surfaced AQtive Guard's *existing* dynamic instrumentation, none surfaced Cryptoscope, none surfaced the CRYLogger/CRYScanner academic lineage going back to 2021 — despite all of this being centrally relevant to a report specifically about "what would make dynamic discovery novel." That's a research-scope gap, not a factual error, but it's the one that matters most for your original question.

**On the deeply technical claims none of us can casually verify:** the specific side-channel attack numbers (Cortex-M4 key recovery in ~30 seconds, SLH-DSA "26,000x slower than ECDSA"), the precise sub-2%-overhead figures, and most exact byte-size/timing table entries are individually plausible (the general shape — PQC signatures are much bigger and often slower, lattice implementations have real side-channel history — is well-established) but I did not verify each number against its underlying paper. Where a specific figure matters for a judge-facing claim, pull the primary source yourself before stating it as fact — same standard we've held all session.

---

## 4. Where a real, defensible edge actually exists

Given the landscape above, here's what survives scrutiny as *genuinely* differentiated — not because a report said so, but because I could not find an existing tool, commercial or academic, that does it:

### 4.1 CBOM confidentiality architecture — the strongest candidate
All four reports independently converged on the same real problem: a complete CBOM is a targeting map for Harvest-Now-Decrypt-Later adversaries — "here is every RSA-2048 endpoint, exact file and line" is exactly what an attacker positioning for 2030+ wants. I could not find **any** existing commercial tool (AQtive Guard, IBM Quantum Safe Explorer, InfoSecGlobal) that treats the inventory itself as a protected asset rather than a report to hand to whoever asks. This is the one place all four reports agree on the *problem* and I found zero prior art on the *solution*.

Practical version (per `[C52]`'s more conservative framing, which I trust over `[C51]`/`[GEM]`'s heavier ZK-first approach — building a working zk-SNARK circuit over arbitrary CBOM predicates in a hackathon window is not realistic, and `[C52]` says so directly): differential-privacy / risk-tiered redaction as the default export control (implementable in weeks, real libraries exist), confidential-computing storage underneath it if time allows, ZK-attestation named explicitly as a roadmap item, not a promise.

### 4.2 Real temporal Mosca scoring, not binary flagging
Every competitor above appears to do **posture/policy scoring** — "this algorithm is/isn't compliant." None of the marketing or technical material I found describes genuine per-asset **X (data lifetime) + Y (migration time) vs. Z (deadline)** modeling. Build this for real, anchored to the actual regulatory dates — which just moved, importantly:

**Update to what I told you earlier this session:** OMB M-26-15, "Execution of the Migration to Post-Quantum Cryptography," was issued **June 24, 2026** — two days after Executive Order 14412 (June 22, 2026) `[VERIFIED: whitehouse.gov/wp-content/uploads/2026/06/M-26-15-...pdf]`. It sets a concrete five-phase civilian timeline: Phase 1 discovery (2026–2027), Phase 2 pilots (2027–2028), Phase 3 prioritized/key-establishment migration (2028–2030), Phase 4 signature migration (2031), Phase 5 full migration (2035) — and **every covered agency must name the specific automated discovery tools it will use in a migration plan due October 2026** `[VERIFIED: tychon.io/what-omb-m-26-15-means-for-federal-migration]`. National-security systems run on a separate CNSA 2.0 track completing by 2033 `[VERIFIED: openssl-corporation.org/blog/post-quantum-cryptography-now-has-deadlines]`. This is a better, more current, more concrete "Z" than the 2030/2035 dates I gave you before — use the actual phase your target artefact falls into, not just one blanket deadline.

### 4.3 Consensus/BFT-aware discovery — the part that's actually yours
Every one of the four reports independently flagged the same landmine: swapping ECDSA/Ed25519 for ML-DSA in a consensus protocol multiplies signature size ~13–50x (depending which classical baseline you compare against), which can blow through gossip-protocol message budgets, desync view-change timeouts, or silently change liveness assumptions in BFT systems `[C51][C52][GEM][PPX] — all four, independently converged]`. None of the enterprise tools above are built for this — they're TLS/PKI/application-crypto tools, not blockchain-consensus tools. **You've actually run a real Hyperledger Fabric SmartBFT deployment and hit this class of problem for real.** That's not a claim a competitor can casually match — it's a track record.

### 4.4 Validated on a real, already-verified system
Not a "novel subsystem" — a fact. Your e-voting platform mixes an ephemeral classical layer (RSA-2048 Chaum blinding), an already-migrated NIST-standard PQC layer (ML-DSA-65/FIPS 204 Merkle anchoring), and a from-scratch LWE homomorphic layer whose security level you and I already independently fought over and settled at NIST Level 3 this session. Running ECDAT against it and having it correctly rank the ephemeral RSA layer as low-urgency (nothing to harvest — keys die same-day) while everything else reads as already-compliant is a demo no competitor tool vendor can reproduce, because none of them built the target system.

---

## 5. What NOT to lead with (and why)

- **"We solve the dynamic/reflection blind spot"** — three real vendors already do this; leading with it invites a judge who knows the space to ask "have you used AQtive Guard?"
- **Elaborate binary-analysis tiering as the headline** — sound engineering, not differentiated; every serious competitor does some version of symbol-table-then-constants-then-disassembly triage.
- **Any specific unverified benchmark number** (side-channel timings, exact overhead percentages) as a stated fact in submission material — same rule as last time: don't put a number in front of a panel that you can't reproduce if asked.

## 6. What TO lead with

1. CBOM confidentiality (§4.1) — genuinely unaddressed white space, all four reports agree it's a real problem, I found no existing solution.
2. Real temporal Mosca engine anchored to the actual OMB M-26-15 phase schedule (§4.2) — current, sourced, more concrete than "quantum computers arrive someday."
3. Consensus/BFT-specific discovery and migration guidance (§4.3) — the one piece of this that's genuinely yours, backed by a system you actually built.
4. Validation on that real system (§4.4) — a fact, not a pitch.
5. Everything from the earlier plan (discovery via CBOMkit/PQCA integration, FIPS 203/204/205 recommendation engine, standard CBOM/CycloneDX output) stays as the *foundation* — necessary, table-stakes, honestly presented as "built on the same standard everyone else uses," not as the innovation.

---

## 7. Blind spots even the existing tools miss (not just gaps — errors in how the standard math is applied)

Everything below survived a second pass specifically hunting for "what would an existing player still be getting wrong." Tagged by source: `[CITED]` = a real, checkable published source; `[SYNTHESIS]` = my own reasoning, not directly published anywhere I found, offered as reasoning rather than fact.

**A. `[CITED]` Z is used as a fixed date; Mosca's own collaborators present it as a probability distribution.** Global Risk Institute's own annual surveys give probability bands, not dates (2022: ~50% chance of CRQC-breaks-RSA-2048 by 2037; 2023: <1% within 5 years; 2025: 28–49% within 10 years) — https://globalriskinstitute.org/publication/quantum-threat-timeline/, explainer at https://www.encryptionconsulting.com/understanding-mosca-theorem/. A methodological critique of the survey itself (annual opinion-poll methodology can't track fast-moving hardware progress, and it doesn't separate RSA from ECC timelines) — https://postquantum.com/security-pqc/quantum-threat-timeline-report-2025/. Every tool found, including this plan's earlier draft, collapses this to one fixed date. Fix: carry Z as a distribution, keep "regulatory Z" (NIST IR 8547 / OMB M-26-15, a policy choice) separate from "physical Z" (CRQC arrival, a genuine forecast), per algorithm family.

**B. `[CITED]` Mosca's inequality treats risk as binary; it's actually a graduated economic decision for the adversary.** Blanco-Romero et al., "On the Practical Feasibility of Harvest-Now, Decrypt-Later Attacks," Universidad Carlos III de Madrid, March 2026 — https://arxiv.org/pdf/2603.01091. States this as a direct critique of Mosca's framework and a prior extension of it, then builds an adversary cost model: storage is economically trivial (~$1–11B/year to archive 1–10% of global encrypted traffic; drops further with tape media), so real risk should weight by how *cheap* an asset is for an adversary to target and eventually decrypt, not just whether X+Y>Z holds.

**C. `[CITED]` "Forward secrecy: true" is not the safety signal a CBOM treats it as — blast radius per compromised key depends on protocol *feature usage*, not protocol *name*.** Same paper: TLS 1.3's `KeyUpdate` derives every later epoch from the one before via one HKDF step with no new randomness, so one broken ephemeral key cascades to everything downstream in that connection (and further, into resumed 0-RTT/PSK sessions). SSH's native rekeying instead forces an independent quantum computation per rekey — their measured example: 37 independent Shor-algorithm runs needed for a 5MB SSH session vs. 1 for the TLS 1.3/QUIC equivalent, because the IETF drafts that would fix this for TLS/QUIC (`draft-ietf-tls-extended-key-update`, `draft-ietf-quic-extended-key-update`) are still Work in Progress. A CBOM entry needs 0-RTT status, ticket lifetime, and extended-key-update deployment to actually represent this — no schema found (including all four research reports' proposed extensions) captures it.

**D. `[SYNTHESIS]` Nobody attempts automated inference of X — every tool treats it as manually-tagged metadata.** See §8 below for the proposed fix (storage-persistence heuristic + local model).

**E. `[SYNTHESIS]` CBOM has no concept of "these components must migrate as a coordinated unit."** Corroborated indirectly by finding C: TLS 1.3/QUIC being architecturally "locked" until a new mechanism deploys on both ends is exactly a coordinated-migration constraint. Same shape as the consensus/BFT landmine from the earlier plan, but it's a general property of CBOM's per-component data model, not a blockchain-specific quirk.

## 8. The deeper problem with X+Y>Z itself, and how to actually determine X and Y

**The core issue `[SYNTHESIS]`:** X+Y>Z is a *necessary* check — it tells you whether there's theoretically enough time — and every tool, including earlier drafts of this plan, treats it as a *sufficient* decision procedure. It doesn't say whether X and Y are measurements or levers you control, carries no confidence on any input, and produces a flag, not a recommendation. Three concrete failure modes:

1. **X is also a lever, not just Z's counterpart.** Every treatment implicitly assumes only Y is actionable ("migrate faster"). Data minimization, retention limits, and crypto-shredding (destroying the key so ciphertext becomes permanently unreadable once its retention window ends) shrink X directly, often faster and cheaper than a full migration — and this is absent from how the inequality gets used everywhere, including in this plan until now.
2. **The actionable output isn't the flag, it's the gap.** Invert the formula: `Y_max = Z − X` is the real deadline; separately estimate `Y_current` at present resourcing. If `Y_current > Y_max`, the gap is what needs closing — via more resourcing, shrinking X instead, an interim weaker mitigation, or reprioritization. "At risk: yes" is not a recommendation on its own.
3. **Y estimated per-asset in isolation ignores shared capacity.** In a real portfolio, assets compete for the same HSM budget, engineering time, and testing cycles — Y for asset #3,999 in a migration queue isn't the same number as Y for asset #1. This makes Layer 2 a scheduling/portfolio problem stacked on top of the inequality, not N independent instances of it.

**Determining X — layered, each tier carrying a visible confidence level, never a bare score:**
1. Explicit metadata (compliance tag, data-classification label) if it exists — highest confidence.
2. **Storage-persistence heuristic (automatable, no AI needed):** does this key/ciphertext ever reach a persistent write (ledger append, archival DB, backup) or does it only ever live in memory and get explicitly zeroed? Checkable via ordinary taint/dataflow analysis — the same category of technique Cryptoscope already applies well, for a different purpose (crypto-primitive semantics rather than data lifetime).
3. Regulatory/sectoral defaults as fallback prior (healthcare retention norms, financial audit periods, jurisdiction-specific election-data rules).
4. Explicitly flagged for human review when confidence from 1–3 is low — not silently guessed.

**Why a local, fine-tuned model belongs here specifically (and why not cloud):** sending a cryptographic inventory to an external API to get X-classifications recreates the exact "CBOM is a targeting map" confidentiality problem this plan already identifies as the strongest genuine white-space gap (§4.1). Proposed architecture: dataflow tracing (tier 2) does the primary work with no model involved; a small, local, fine-tuned classifier acts as a secondary signal, trained on variable/function names, comments, and adjacent code context (e.g. `purgeElectionKeys`, `archival_ledger_write`, `GDPR_retention_days`) to catch what pure dataflow tracing misses — narrow domain, small output space (a tier plus a confidence value), a realistic fine-tuning target rather than a large general-purpose model. Output is always a suggestion with confidence, feeding the same human-review queue as tier 4, never presented as authoritative.

---

## 9. Sources referenced in this document

- SandboxAQ AQtive Guard capabilities: https://www.sandboxaq.com/solutions/security/discover · https://postquantum.com/post-quantum/cryptographic-inventory-vendors/ · https://securitystack.app/products/aqtive-guard
- IBM Quantum Safe Explorer (static-view limitation, launch date): https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x?topic=quantum-safe-explorer-overview · https://www.ibm.com/quantum/quantum-safe
- Cryptoscope (IBM Research, benchmark results, related-work/prior-art review): https://arxiv.org/pdf/2503.19531
- CBOMkit donated to PQCA/Linux Foundation: https://researcher.ibm.com/blog/cryptographic-cbom-linux-foundation · https://www.linuxfoundation.org/press/announcing-the-post-quantum-cryptography-alliance-pqca
- OMB M-26-15 (primary source + phased timeline): https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf · https://tychon.io/what-omb-m-26-15-means-for-federal-migration/ · https://openssl-corporation.org/blog/post-quantum-cryptography-now-has-deadlines.html
