# SIH26164 — ECDAT Presentation Story & Voiceover Script

> **Target Duration:** 5 to 7 Minutes  
> **Audience:** Smart India Hackathon 2026 Evaluation Panel / Technical Jury  
> **Key Objective:** Deliver a clear, grounded narrative proving that ECDAT solves real enterprise post-quantum cryptographic risk using official standards (ECMA-424 CBOM, NIST IR 8547, OMB M-26-15), novel Merkle-tree CBOM confidentiality, automated taint-based multi-tier X-inference, and a phased implementation roadmap with honest validation plans.

---

## Presentation Delivery Principles

1. **Speak with grounded confidence**: You are presenting an engineering system built on finalized NIST FIPS standards and Linux Foundation tooling — not a concept.
2. **Never read slides verbatim**: The slides provide structural proof (especially the implementation flowchart); your voice delivers the storyline, technical reasoning, and competitive edge.
3. **Use the "Challenge vs. Engineered Resolution" cadence**: Introduce a concrete enterprise problem, explain why current tools fall short, and demonstrate how ECDAT resolves it.

---

## Slide 1: Title Page & Opening Hook

* **Visual on Screen:** Slide 1 — ECDAT Title, Problem Statement ID SIH26164, Theme, Category, Team
* **Estimated Time:** 15 to 20 seconds
* **Pacing:** Crisp, steady, professional.

### Spoken Script

"Respected evaluators, greetings. We are Team [Your Team Name], presenting our solution for Problem Statement SIH26164: **ECDAT — the Enterprise Cryptographic Discovery and Analysis Tool**, under the Blockchain and Cybersecurity theme.

Every enterprise today runs on public-key cryptography: RSA, elliptic curves, Diffie-Hellman. But regulatory clocks have started ticking. Today, we will walk you through how ECDAT transforms post-quantum migration from an overwhelming blind spot into an automated, mathematically grounded, and tamper-evident engineering roadmap."

---

## Slide 2: Idea Title — Problem, Solution & Innovations

* **Visual on Screen:** Slide 2 — 4 Metric Stat Cards, Problem Statement, Proposed Solution, How It Addresses, Innovation & Uniqueness
* **Estimated Time:** 90 to 100 seconds
* **Pacing:** Narrative-driven, engaging. Call out the top numbers first to anchor credibility.

### Spoken Script

"Let us examine the reality facing every Chief Information Security Officer today.

Notice the four key figures on screen:
* **50.7%** of scanned internet domains in 2026 remain vulnerable to classical cryptanalysis — more than half of the internet is not ready.
* **2030 and 2035** are the hard deadlines set by NIST IR 8547 and US OMB M-26-15, which require civilian and critical agencies to complete automated discovery and deploy hybrid-ready tooling.
* ECDAT introduces a **4-tier automated X-inference classification** — we will explain what this means shortly, but it solves the industry's biggest discovery blind spot.
* And **32 bytes** — that is all ECDAT exposes during an external audit: a single Merkle root hash, not your internal codebase map.

When leadership asks: 'Where does our quantum-vulnerable cryptography live, which services will break first, and what must we migrate before 2030?' — most security teams have no answer.

**Our solution is ECDAT**: an automated 5-layer platform that discovers cryptographic assets across code, certificates, containers, and cloud configs, models temporal risk using Mosca's theorem with our novel extensions, and generates standards-compliant Cryptography Bills of Materials under ECMA-424.

What makes ECDAT novel?
1. **Privacy-Preserving CBOM via Merkle Commitments**: Conventional tools generate full plaintext inventories that expose sensitive internal file paths during audits. ECDAT publishes only a 32-byte Merkle root. Auditors verify specific compliance claims via selective inclusion proofs — without accessing internal code paths.
2. **Actionable Mosca Metric (Y_max = Z minus X)**: Existing tools output a binary yes/no flag. ECDAT computes Y_max — the exact years engineering teams have left for each specific asset — and detects crypto-shredding levers to shrink X.
3. **Multi-Tier X-Inference**: Instead of a naive binary 'RAM or Database', ECDAT classifies data lifespan into four tiers — EPHEMERAL, OPERATIONAL, ARCHIVAL, and HUMAN_REVIEW — using call-graph-aware taint tracing.
4. **Regulatory-Physical Dual-Z Model**: Evaluates both the OMB M-26-15 regulatory deadline and the GRI 2025 probabilistic CRQC arrival distribution — because compliance risk and technical cryptographic risk are not the same number."

---

## Slide 3: Technical Approach — Implementation Flowchart & Tech Stack

* **Visual on Screen:** Slide 3 — Full 5-Stage Implementation Flowchart, Technologies Panel, Implementation Scope & Validation Plan Panel
* **Estimated Time:** 100 to 120 seconds
* **Pacing:** Technical, authoritative, walking the visual pipeline.

### Spoken Script

"Slide 3 shows our complete Methodology and Implementation Flowchart, illustrating how raw infrastructure data becomes a verified cryptographic risk report.

Let us trace the five stages left to right:

1. **Inputs (Scan Surfaces)**: ECDAT scans four enterprise vectors: source code repositories in Java, Go, Python, and C/C++; X.509 certificates and TLS keystores; OCI container image layers; and cloud infrastructure TLS policies.

2. **Phase 1 (Discovery Engine)**: We integrate the Linux Foundation's open-source PQCA CBOMkit — specifically Hyperion for SonarQube AST parsing and Theia for container inspection. This extracts every crypto invocation, algorithm name, key length, and provider into a normalized Cryptographic Asset Graph.

3. **Phase 2 (Dual Risk Engine)**:
   - Track A — 4-Tier X-Inference: This solves the industry-wide blind spot of guessing how long data stays sensitive. ECDAT runs taint dataflow analysis, tracing whether ciphertexts reach persistent storage sinks — databases, disk writes, S3 buckets — or remain ephemeral in memory. Based on this, we classify each asset into one of four tiers: EPHEMERAL for in-memory data zeroed after use; OPERATIONAL for database records with active rotation policies; ARCHIVAL for long-lived audit logs, medical or financial records; and HUMAN_REVIEW for ambiguous cross-function flows where ECDAT flags confidence below threshold for manual inspection.
   - Track B — Dual-Z Temporal Engine: Computes Y_max = Z minus X using both regulatory deadlines from OMB M-26-15 and physical quantum arrival probabilities from the Global Risk Institute.
   - R0 Contagion Graph: Identifies high-impact shared libraries that, if migrated first, resolve risk across the most downstream services.

4. **Phase 3 & 4 (PQC & Attestation)**: Maps each primitive to finalized NIST standards — FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA — with hybrid-first pairing guidance (X25519+ML-KEM for key exchange, ECDSA+ML-DSA for signatures). Then builds the SHA-256 Merkle tree commitment from all asset records.

5. **Outputs**: Produces ECMA-424 / CycloneDX CBOM JSON, privacy-preserving selective inclusion proofs, an interactive CISO risk dashboard with Y_max timelines and a Gantt view, and a CBOM diff report tracking before-and-after migration deltas.

At the bottom, notice our phased implementation roadmap: Phase 1 delivers the core AST scanner and 4-tier X-classifier. Phase 2 adds the Merkle module, container scanning, and CISO dashboard. Phase 3 adds inter-procedural call-graph taint analysis for cross-function persistence detection, with pre-annotated stubs for JDBC, SQLAlchemy, and the AWS SDK. Our validation plan uses open-source Java and Python codebases with known cryptographic estates as ground truth — so we can measure detection recall and HUMAN_REVIEW escalation rates honestly."

---

## Slide 4: Feasibility and Viability

* **Visual on Screen:** Slide 4 — Feasibility Pillars, Challenges & Engineered Strategies Table
* **Estimated Time:** 60 to 75 seconds
* **Pacing:** Objective, candid, problem-solving tone.

### Spoken Script

"Feasibility is about engineering realism and clear boundaries.

* **Technically**, building on PQCA CBOMkit and the CycloneDX standard means we build on battle-tested AST parsers rather than writing fragile regular expressions from scratch.
* **Operationally**, ECMA-424 output plugs directly into existing CI/CD and SBOM pipelines — SonarQube, GitHub Actions, no custom integration required.
* **Economically**, portfolio optimization lets CISOs allocate migration budget along a Markowitz efficient frontier, maximizing risk reduction per rupee spent.

Look at our Challenges and Strategies table:
* Row 1: Exposing sensitive internal architecture in plain-text audit reports. Our Merkle commitment architecture solves this — only the 32-byte root is disclosed publicly.
* Row 2: Ambiguous data lifespan. Our 4-tier taint analysis assigns a confidence-weighted tier to each asset; low-confidence cases are escalated to the HUMAN_REVIEW tier rather than silently guessed.
* Row 3: Inter-procedural taint tracing — when a ciphertext is passed into a third-party library call, a purely local static analysis cannot know what that function does internally. We solve this with pre-annotated API stubs for common persistence frameworks, and automatic HUMAN_REVIEW escalation for unresolved external sinks with an explicit confidence score.
* Row 4: Compiled binary analysis without debug symbols. Fast symbol-table scanning covers the MVP tier; Ghidra headless decompilation is an explicitly scoped enterprise roadmap tier.

A team that openly acknowledges real technical bottlenecks — and engineers documented fallbacks — is a team ready for production."

---

## Slide 5: Impact and Benefits

* **Visual on Screen:** Slide 5 — Target Audience Impact, Broader National Benefits
* **Estimated Time:** 50 to 60 seconds
* **Pacing:** Highlighting concrete, multi-stakeholder value.

### Spoken Script

"Who benefits from ECDAT, and what is the tangible impact?

* **For CISOs**: Replaces subjective audit checklists with an actionable, ranked migration backlog. The efficient-frontier model maximizes risk reduction per allocated budget.
* **For Compliance and Audit Teams**: Automated CBOM exports satisfy NIST IR 8547, OMB M-26-15, and CNSA 2.0 requirements with verifiable mathematical proof — not manual questionnaire responses.
* **For Software Engineering Teams**: Taint-based X-inference filters out thousands of ephemeral low-risk keys, pinpointing only the critical persistent-data call sites that genuinely require migration effort.
* **For Critical Infrastructure and Regulated Sectors**: Financial institutions, healthcare systems, and government agencies protect long-lived citizen data against HNDL exploitation well ahead of the 2030/2035 regulatory deadlines.
* **For DevSecOps Communities**: The CBOM export pipeline integrates directly into CI/CD workflows, automating PQC compliance checks on every code merge.

On a national level, ECDAT establishes a verifiable, proactive post-quantum migration framework — converting the regulatory mandate into an engineering-grade action plan rather than a compliance checkbox."

---

## Slide 6: Research Foundations & Conclusion

* **Visual on Screen:** Slide 6 — Standards & Mandates, Peer-Reviewed Literature, Validation Approach
* **Estimated Time:** 30 to 40 seconds
* **Pacing:** Decisive, authoritative closing.

### Spoken Script

"In summary, ECDAT is grounded in authoritative, peer-reviewed science:
* NIST's finalized FIPS 203, 204, and 205 standards and NIST IR 8547.
* White House Executive Order 14412 and OMB M-26-15 issued June 2026.
* The CycloneDX / ECMA-424 international CBOM standard.
* March 2026 research from IBM Research on Cryptoscope (CamBench: 92% recall, 97% precision) and Blanco-Romero et al. on HNDL attack economics.

Our validation plan uses open-source enterprise codebases with known cryptographic profiles as verifiable ground truth — so every claim about detection accuracy is independently measurable.

Thank you. We are ready for your questions."

---

## Rapid-Fire Q&A Preparation for Judges

### Q1: "Why use PQCA CBOMkit instead of building your own AST scanner?"

**Answer:**
"The Linux Foundation's Post-Quantum Cryptography Alliance — co-founded by the original Kyber and Dilithium authors — maintains CBOMkit as the open industry baseline. It already achieves 92% recall at 97% precision on the CamBench benchmark per IBM Research's March 2025 paper. Building a competing AST scanner from scratch would consume most of our engineering budget for a problem that is already solved. Our real contributions are what CBOMkit does not do: multi-tier X-inference via taint analysis, the dual-Z Mosca planning engine, and Merkle-tree CBOM confidentiality."

---

### Q2: "What is your novel contribution if CBOMkit and SandboxAQ already exist?"

**Answer:**
"Three specific, defensible innovations:
1. Privacy-Preserving Audit Architecture: Existing tools expose full plaintext inventories to auditors. We introduce a Merkle commitment scheme — auditors verify specific compliance claims without seeing the full codebase cryptographic map.
2. Automated Multi-Tier X-Inference: Existing tools require manual metadata tagging. We use taint and call-graph analysis to assign one of four data-lifespan tiers — EPHEMERAL, OPERATIONAL, ARCHIVAL, or HUMAN_REVIEW — to each asset automatically.
3. Dual-Z Mosca Extension: We separate the regulatory compliance deadline from the physical CRQC probability distribution, treating Z as a distribution rather than a point estimate, and compute per-asset Y_max budgets rather than an organizational yes/no flag."

---

### Q3: "How does the Merkle tree commitment actually work for an auditor?"

**Answer:**
"Each discovered crypto asset — service name, file path hash, algorithm, key size, risk tier, timestamp — is serialized and hashed with SHA-256 to produce a leaf node. Leaf pairs are hashed together to form parent nodes, continuing up to a single 32-byte Merkle root. This root is published to an immutable timestamped log.

When an auditor asks 'Has payment-service migrated from RSA-2048?', ECDAT reveals only the leaf data for that specific asset plus log2(N) sibling hashes along the path to the root. The auditor recomputes the path and verifies it matches the committed root. They receive cryptographic certainty about that component's status without ever seeing any other asset in the inventory.

This is a practical privacy architecture — not something auditors currently mandate, but a genuine technical contribution that prevents CBOM audit reports from becoming attack-planning maps."

---

### Q4: "How does your 4-tier X-inference handle data that flows across function boundaries — for example, a key passed to a function that then stores it?"

**Answer:**
"This is a genuine limitation of static taint analysis — and we document it honestly rather than hiding it.

If a key is passed to storeKey(key) and the body of storeKey is in a third-party library whose source we cannot read, a purely intra-procedural taint trace cannot follow it. ECDAT addresses this in three ways:

First, for well-known persistence APIs — JDBC, SQLAlchemy, JPA repositories, Redis client, S3 SDK — we ship pre-annotated stubs that mark those function calls as ARCHIVAL sinks without needing to inspect their internals.

Second, for application-internal functions where source code is available, ECDAT performs inter-procedural call-graph traversal: it follows the call into the function body and checks whether the parameter eventually reaches a persistence sink.

Third, for external function calls that are neither in our stub library nor have available source, ECDAT assigns the HUMAN_REVIEW tier with a confidence score and a flag: 'data flows into unanalyzed external function — manual review required.'

The key point is that ECDAT is transparent about what it cannot resolve automatically rather than making silent worst-case guesses."

---

### Q5: "What are the known limitations of Mosca's inequality, and why does ECDAT not just use it as-is?"

**Answer:**
"Mosca's original inequality — X + Y greater than Z means you are at risk — has several well-documented limitations that our research surfaced:

1. Z is treated as a point estimate, not a distribution. The quantum arrival year is probabilistic, not fixed. GRI 2025 estimates a 28 to 49 percent chance of a Cryptanalytically Relevant Quantum Computer within 10 years. Using a single year misrepresents the actual risk profile.

2. Mosca outputs a binary yes/no. It tells you whether you are at risk, not which assets to fix first or how many years remain for each. ECDAT's Y_max = Z minus X converts this into a per-asset engineering budget.

3. X is hard to measure. Mosca assumes organizations know their data retention windows. In practice, they do not — which is exactly what our 4-tier X-inference addresses.

4. Y is systematically underestimated. Migration time in real enterprises includes discovery time — which organizations often have not started — procurement cycles, regulatory approval, testing, and deployment. Mosca does not capture these sequencing constraints.

5. Mosca does not distinguish HNDL urgency by data type. Public TLS handshakes may already be harvested. Encrypted at-rest databases are only harvestable if an adversary gains storage access. This is a different threat model that requires different X estimates.

ECDAT's dual-Z approach — evaluating regulatory-Z from OMB M-26-15 separately from physical-Z from GRI 2025 — directly addresses the first limitation. The multi-tier X classification addresses the third."
