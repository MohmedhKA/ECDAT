# ECDAT — MY-Plan-V2.md
### The Absolute Master Plan: Evidence-Centered Cryptographic Discovery, Attestation & Transition
**Date:** 2026-09-11
**Status:** Master innovation blueprint — ready for SIH 2026 national round preparation
**Provenance:** Synthesized from 14 independent research reports (6 AI models × 2 phases + 1 fact-check audit + 1 master architecture), cross-verified against primary vendor documentation, NIST publications, arXiv papers, and open-source repositories.

---

## SOURCE TAG PROTOCOL

Every claim carries a provenance tag:
- `[VERIFIED]` — Independently confirmed against a primary published source (NIST FIPS, OMB memo, vendor docs, GitHub repo).
- `[CITED]` — From a named published paper or standard, link given.
- `[CONSENSUS-6/6]` — All 6 independent research models agreed on this point.
- `[CONSENSUS-4+/6]` — 4 or more of 6 models converged on this point.
- `[SYNTHESIS]` — Original reasoning from first principles; treat as an argument, not a fact.
- `[ALREADY-BUILT]` — Exists in the current ECDAT codebase (`/home/mohmedh/personal/ECDAT/ecdat/`).

**Rule:** If a number goes in front of an SIH judge, it must have a `[VERIFIED]` or `[CITED]` tag. No exceptions.

---

## PART 0 — WHAT WE ALREADY HAVE (THE FOUNDATION)

Before planning what to build, here is what ECDAT already does that **zero** existing commercial or open-source tools replicate in combination:

| Existing Module | What It Does | Status |
|---|---|---|
| **Polyglot AST Source Scanner** | Regex + AST pattern matching across JS, Go, Rust, Python to discover crypto call sites with line numbers. | `[ALREADY-BUILT]` |
| **Theia Filesystem Bridge** | Integrates `cbomkit-theia` for X.509 certificate and key-file discovery on disk/containers. | `[ALREADY-BUILT]` |
| **Manifest Supply-Chain Scanner** | Parses `package.json`, `go.mod`, `Cargo.toml`, `requirements.txt` for crypto dependencies. | `[ALREADY-BUILT]` |
| **X-Inference Engine** | Forward taint-style heuristic slicing: infers data lifespan tier (`EPHEMERAL` → `ARCHIVAL`) from code flow sinks (socket writes, DB inserts, cloud uploads). | `[ALREADY-BUILT]` |
| **Mosca Inequality Engine** | Deterministic $Y_{\max} = Z_{\text{reg}} - X$ with 5-phase OMB M-26-15 schedule + GRI 2025 probabilistic distributions. | `[ALREADY-BUILT]` |
| **Contagion $R_0$ Graph Engine** | Epidemiological blast-radius modeling: directed dependency graph, superspreader detection ($R_0 \ge 2$), PQC immunization anchors. | `[ALREADY-BUILT]` |
| **Buffer Hazard Auditor** | Detects hard-coded byte-array allocations that would overflow under PQC signature/key expansion (64 B → 3,309 B). | `[ALREADY-BUILT]` |
| **Merkle Audit Tree** | SHA-256 Merkle commitments over CBOM assets with selective-disclosure proofs and browser-based WebCrypto verification. | `[ALREADY-BUILT]` |
| **Interactive HTML Report** | 7-tab dashboard: Contagion Graph, Mosca Schedule, CBOM Inventory, Buffer Hazards, Supply Chain, Attestation Sandbox, CISO Report. | `[ALREADY-BUILT]` |
| **Enriched CycloneDX 1.6 CBOM** | Standard CBOM output with `ecdat:x_tier`, `ecdat:y_max_years`, `ecdat:risk_level` property extensions. | `[ALREADY-BUILT]` |
| **CISO Migration Report** | Executive Markdown briefing with per-asset timelines, remediation recommendations, and regulatory phase mapping. | `[ALREADY-BUILT]` |

**Key Insight:** The basic pipeline (`scan → CBOM → risk score → dashboard → recommend`) is already **commoditized** — even an open-source hackathon tool called `QuantumShield` on GitHub implements it with 95 tests. `[VERIFIED]` Our existing $R_0$ contagion graph, X-inference taint analysis, and buffer hazard auditing already differentiate us from all known competitors. But to win SIH nationally and outperform commercial tools (IBM, SandboxAQ, Keyfactor), we must build where **everyone** fails.

---

## PART 1 — THE SIX UNANIMOUS MARKET FAILURES

All 6 independent research models and the fact-check audit converge on six structural failures that **no existing tool** — commercial or open-source — solves:

### Failure 1: The Static vs. Dynamic Reconciliation Chasm `[CONSENSUS-6/6]`

**The Problem:** Static AST scanners (IBM Explorer, CBOMkit-Hyperion, our source scanner) detect what crypto *could* run. Dynamic tracers (SandboxAQ's JVM hooks) detect what crypto *does* run. Nobody unifies these two views.

- A library might contain DES code that is never called → false alarm from static scan.
- A runtime failover path might activate RSA-1024 during disaster recovery, but it's never triggered in normal testing → invisible to dynamic tracing.
- **Result:** Organizations cannot distinguish real threats from dead code, wasting months on remediation of unreachable vulnerabilities.

**Quantitative Evidence:**
- SandboxAQ's JVM bytecode rewriting introduces 3%–8% CPU overhead and crash risks. `[VERIFIED]` (vendor-acknowledged limitation to staging/test environments)
- IBM Explorer is explicitly documented as providing "a static view" only. `[VERIFIED]`

### Failure 2: Shallow / Broken Mosca's Inequality `[CONSENSUS-6/6]`

**The Problem:** Vendors reduce Mosca's Inequality ($X + Y > Z$) to a marketing buzzword, using a single global scalar for data lifetime $X$. But:
- Session tokens expire in minutes ($X \approx 0$) → zero quantum risk.
- Medical records must be protected for 50+ years ($X \ge 50$) → extreme quantum risk.
- Migration time $Y$ varies by code complexity, not a global constant.
- Whether an adversary can intercept the data at all ($P_{\text{HNDL}}$) is never considered.

### Failure 3: The "Expensive Spreadsheet" Remediation Chasm `[CONSENSUS-6/6]`

**The Problem:** Scanners produce 50 MB CycloneDX JSON dumps with no line-of-code lineage, no automated code-fix recipes, and no round-trip to ticketing systems. Developers receive a spreadsheet they cannot act on.

**Quantitative Evidence:**
- Best-in-class commercial tool recall is only 0.7628 on a 1,368 test corpus; 13 of 14 tools refuse to publish per-detector accuracy. `[CITED]` PQC Discovery Index evaluation (caution: index itself has vendor conflicts — Qtonic Quantum Corp runs both the index site and ranks its own product #1 `[VERIFIED]`)

### Failure 4: Context Blindness & Alert Fatigue ("Primitive Flooding") `[CONSENSUS-6/6]`

**The Problem:** SHA-256 used for cache ETag generation gets the same `CRITICAL` severity as SHA-256 protecting database encryption keys. Scanners evaluate crypto in mathematical isolation without understanding **functional intent**.

**Quantitative Claim:** Intent classification can eliminate >90–95% of false-positive primitive alerts. `[SYNTHESIS]` — supported by Gemini Spark's DSIS model

### Failure 5: Transport-Layer Blindness to PQC Size Expansion `[CONSENSUS-6/6]`

**The Problem:** Tools recommend ML-KEM-1024 or ML-DSA-65 based on bit-security alone, ignoring that:
- ML-DSA-65 signature: **3,309 bytes** (vs ECDSA P-256: 64 bytes = **51.7× expansion**) `[VERIFIED]` NIST FIPS 204 Table 2
- ML-KEM-1024 public key: **1,568 bytes** (exceeds 1,500-byte Ethernet MTU) `[VERIFIED]` NIST FIPS 203
- Composite TLS handshake (cert chain + ML-KEM + ML-DSA) can exceed **7 KB**, requiring ≥5 TCP segments on 1,500 MTU path.
- Middleboxes, firewalls, and load balancers frequently drop fragmented packets or timeout on reassembly.

### Failure 6: The "Complete Inventory" Lie & Audit Untrustworthiness `[CONSENSUS-6/6]`

**The Problem:** Marketing claims 100% automated coverage. Reality:
- OMB M-23-02 mandates *annual manual inventories* because automated tools **structurally cannot** find everything. `[VERIFIED]`
- CISA concedes only **3 of 9** required inventory data items can be gathered via automated tooling. `[VERIFIED]`
- 12 of 14 commercial tools emit plain, unsigned JSON CBOMs with zero tamper-evidence. `[CITED]` Sonnet 5(2) evaluation
- Enterprise Windows estates hold **80,000–500,000** certificates. `[CITED]` NIST NCCoE study

---

## PART 2 — THE SEVEN INNOVATION PILLARS

Based on the cross-verified research consensus, the following seven innovations are what ECDAT must build to outperform every existing tool. They are ordered by **implementation priority** (build-sequence dependencies).

---

### PILLAR 1: Dual-Sink Semantic Intent Classification (DSIS-Lite) `[CONSENSUS-5/6]`

**What:** Forward taint slicing from crypto output to its terminal sink to classify the **functional intent** of every cryptographic operation.

**Four Intent Classes (Security Lattice):**
| Class | Quantum Risk | Example Sinks | Alert Action |
|---|---|---|---|
| `OPERATIONAL_UTILITY` | **None (0%)** | HTTP `ETag` headers, in-memory hash-map keys, cache deduplication checksums, Git tree IDs | **Suppress** |
| `INTEGRITY_CHECKSUM` | **Low** | File integrity verification (non-archival), CI/CD build hashes | **Info** |
| `AUTHENTICATION_SIGNATURE` | **High** | JWT signing, mTLS certificate validation, code signing | **Alert** |
| `CONFIDENTIALITY_ENVELOPE` | **Critical** | Database column encryption, network socket TLS, cloud storage encryption | **Critical Alert** |

**The Mathematical Formulation (DSIS Forward Taint):**
$$\text{Intent}(f_{\text{crypto}}) = \begin{cases} \text{OPERATIONAL\_UTILITY} & \text{if } S_f(v_{\text{out}}) \cap \mathcal{S}_{\text{Op}} \neq \emptyset \land S_f(v_{\text{out}}) \cap (\mathcal{S}_{\text{Conf}} \cup \mathcal{S}_{\text{Auth}}) = \emptyset \\ \text{CONFIDENTIALITY\_ENVELOPE} & \text{if } S_f(v_{\text{out}}) \cap \mathcal{S}_{\text{Conf}} \neq \emptyset \\ \text{AUTHENTICATION\_SIGNATURE} & \text{if } S_f(v_{\text{out}}) \cap \mathcal{S}_{\text{Auth}} \neq \emptyset \end{cases}$$

Where $S_f(v_{\text{out}})$ is the set of terminal sinks reachable from the crypto output value $v_{\text{out}}$, and $\mathcal{S}_{\text{Op}}, \mathcal{S}_{\text{Conf}}, \mathcal{S}_{\text{Auth}}$ are the signature sets for operational, confidentiality, and authentication sinks.

**Why This Wins:**
- Immediately reduces alert fatigue by 90–95% in real codebases. `[SYNTHESIS]`
- No existing tool — commercial or academic — performs intent classification. `[CONSENSUS-6/6]`
- Builds directly on our existing X-inference forward taint engine. `[ALREADY-BUILT]`

**How to Build:**
- Extend `ecdat/x_inference/engine.py` with a new `IntentClassifier` that maps terminal sink types to the 4-class lattice.
- Define sink signature maps per language (JS: `res.setHeader('ETag', ...)` → `OPERATIONAL_UTILITY`; `db.query('INSERT ...', encrypted_col)` → `CONFIDENTIALITY_ENVELOPE`).
- The classifier runs alongside X-tier inference; both share the same forward-trace walk.

**Feasibility:** ★★★★★ (directly extends existing infrastructure)

---

### PILLAR 2: Evidence-Centered State Taxonomy (E0–E5) `[CONSENSUS-4+/6]`

**What:** Replace flat `CryptoAsset` records with a **6-level evidence state machine** tracking how much proof we have that a cryptographic primitive is real, reachable, and active.

**State Definitions:**
| Level | Name | Evidence Source | Meaning |
|---|---|---|---|
| `E0` | Unconfirmed Hypothesis | Raw regex/string match | Might be a comment, log message, or variable name |
| `E1` | Static Artifact | AST parse confirms API call | Confirmed crypto API invocation in source code |
| `E2` | Reachable Path | Call-graph analysis | Confirmed reachable from application entry point |
| `E3` | Configuration-Confirmed | Deployment config/env analysis | Config enables this algorithm (not disabled/overridden) |
| `E4` | Runtime-Observed | eBPF uprobe or log correlation | Actually executed in a live process |
| `E5` | Correlated & Signed | Multi-source agreement + signature | Static + config + runtime agree; attestation signed |

**Critical Design Rules:**
1. `not_observed_during_coverage_window ≠ absent`. When dynamic tracing fails to see a statically detected primitive, tag it as `E2-DORMANT`, never silently drop it.
2. The **Unknowns Ledger** tracks everything at E0–E1 that couldn't be promoted, giving auditors honest coverage boundaries.
3. Confidence and risk are **orthogonal axes** — low E-level raises *investigation priority*, not *vulnerability severity*.

**Why This Wins:**
- Solves the static/dynamic reconciliation chasm (Failure #1) with a clean, auditable state machine.
- No competitor has this — IBM Explorer is purely static (E0–E2 at best); SandboxAQ is purely dynamic (E4 only). `[CONSENSUS-6/6]`

**How to Build:**
- Add `EvidenceLevel` enum to `ecdat/models.py` (E0–E5 + DORMANT).
- Extend `CryptoAsset` with `evidence_level`, `evidence_sources: List[str]`, `coverage_window`, and `promotion_history`.
- Refactor `pipeline.py` to set initial evidence levels based on detection source (regex → E0, AST → E1, call-graph → E2, theia cert → E3).
- **Phase 2 addition:** eBPF uprobes feed E4 promotions (aspirational — pitch as roadmap).

**Feasibility:** ★★★★★ (model/schema change, no new dependencies)

---

### PILLAR 3: Autonomous Data-Lifetime Extraction from Schema & Code ($X_{\text{auto}}$) `[CONSENSUS-5/6]`

**What:** Automatically extract the data lifespan $X$ from database schemas, ORM models, and deployment configurations instead of relying on manual lookup tables.

**Three Extraction Sources:**

**Source A — SQL DDL / Migration Scripts** (Flyway, Liquibase, Prisma, raw SQL):
- Parse `CREATE TABLE` for column comments containing retention hints (`-- retention: 7 years`).
- Detect TTL indices (MongoDB `expireAfterSeconds`, Redis `EXPIRE`, DynamoDB TTL).
- Map table names to data classification heuristics (`patient_records` → archival; `session_tokens` → ephemeral).

**Source B — ORM / Application Models:**
- Parse Prisma schemas, Hibernate `@Column` annotations, Django model field types.
- Detect `@Temporal`, `@TTL`, `@RetentionPeriod` annotations.
- Infer from field types: `session_id VARCHAR` → SHORT_TERM; `medical_record_id UUID` → ARCHIVAL.

**Source C — Deployment Manifests (Kubernetes, Docker Compose):**
- Parse Ingress/Service definitions to determine network exposure ($P_{\text{HNDL}}$).
- `type: LoadBalancer` or Ingress with public domain → $P_{\text{HNDL}} = 1.0$ (internet-exposed, harvestable).
- `type: ClusterIP` with no Ingress → $P_{\text{HNDL}} = 0.05$ (internal mesh, minimal harvest risk).
- Air-gapped / no network binding → $P_{\text{HNDL}} = 0.0$.

**Enriched Mosca Formula:**
$$R_Q = \max\left(0,\; (X_{\text{auto}} + Y_{\text{code}}) - Z_{\text{reg}}\right) \times P_{\text{HNDL}} \times (1 - A_{\text{CAMS}})$$

Where:
- $X_{\text{auto}}$: Automatically extracted data lifetime (years)
- $Y_{\text{code}}$: Migration effort derived from code structural complexity:
  $$Y_{\text{code}} = Y_{\text{base}} \times \left(1 + \alpha \log(\text{FanIn}) + \beta \frac{\text{CyclomaticComplexity}}{10} + \gamma \cdot \text{HardcodedPenalty}\right)$$
  `[SYNTHESIS]` — $\alpha, \beta, \gamma$ are tunable weights calibrated against real migration case studies.
- $Z_{\text{reg}}$: Regulatory deprecation year from OMB M-26-15 Phase schedule `[VERIFIED]`
- $P_{\text{HNDL}}$: Adversarial interception probability from deployment manifest
- $A_{\text{CAMS}}$: Cryptographic Agility Maturity Score (0.0–1.0) — see Pillar 4

**Why This Wins:**
- Replaces arbitrary manual $X$ inputs with programmatic ground truth.
- The $P_{\text{HNDL}}$ network exposure factor means an air-gapped internal cache using MD5 correctly gets **zero** quantum risk, while the same MD5 protecting internet-facing patient records gets **critical** risk.
- No competitor does any of this — all use single global scalars. `[CONSENSUS-6/6]`

**Feasibility:** ★★★★☆ (schema parsing is well-understood; K8s manifest parsing is straightforward)

---

### PILLAR 4: Cryptographic Agility Maturity Score (CAMS) `[CONSENSUS-4+/6]`

**What:** Measure how easy or hard it would be to swap out a cryptographic algorithm in each code location. This directly feeds $Y_{\text{code}}$ (migration effort) and $A_{\text{CAMS}}$ (agility discount).

**4-Level Maturity Scale:**
| Level | Name | Pattern | $Y$ Multiplier | $A_{\text{CAMS}}$ |
|---|---|---|---|---|
| 0 | **Rigid / Hardcoded** | `Cipher.getInstance("AES/CBC/PKCS5Padding")` string literal | 1.0 (baseline) | 0.0 |
| 1 | **Configurable** | Algorithm loaded from `config.yaml` or environment variable | 0.7 | 0.3 |
| 2 | **Provider / Factory** | Abstracted behind factory class or DI container | 0.4 | 0.6 |
| 3 | **Runtime Agile** | Crypto-agile facade with policy-driven runtime selection (like Tink KeysetHandle) | 0.15 | 0.85 |

**Detection Method:**
- At AST level, check if the algorithm string is a literal (Level 0), a variable resolved from config (Level 1), injected via factory/DI (Level 2), or routed through a strategy/policy pattern (Level 3).
- Output as `agility_level` on each `CryptoAsset`.

**Why This Wins:**
- A Level 3 codebase needs almost no migration engineering — just update the policy config. The risk formula correctly reflects this reality.
- No existing tool evaluates code-level agility. `[CONSENSUS-4+/6]`

**Feasibility:** ★★★★☆ (AST pattern matching for DI/factory patterns is deterministic)

---

### PILLAR 5: Active Path MTU & Fragmentation Probe `[CONSENSUS-6/6]`

**What:** Before recommending a PQC algorithm, actively test whether the network path between services can handle the expanded packet sizes.

**Route Profile Classification:**
| Profile | Path MTU | Fragment Handling | Recommendation Constraint |
|---|---|---|---|
| `STANDARD` | 1,500 B | Strict DF-bit; fragments dropped by middlebox | Limit to ML-KEM-768 (1,184 B pubkey). Avoid ML-KEM-1024 (1,568 B > MTU). |
| `FLEXIBLE` | 1,500 B | Reassembly confirmed working | ML-KEM-1024 OK; warn about multi-segment ML-DSA-65 certs. |
| `CONSTRAINED` | < 1,280 B | VPN/satellite/cellular tunnels | Restrict to ML-KEM-512 or hybrid X25519 + ML-KEM-768 with certificate compression (RFC 8879). |

**Implementation:**
- Python raw socket sends ICMP/TCP probe packets with DF (Don't Fragment) bit set at various payload sizes (1,280 / 1,400 / 1,500 / 2,000 bytes).
- Records ICMP "Fragmentation Needed" responses or timeouts.
- Generates a `PathProfile` per network route.
- The recommendation engine filters PQC candidates against the PathProfile.

**Handshake Expansion Calculator:**
$$\text{TLS Flight Size} = L_{\text{cert\_chain}} + L_{\text{PQC\_sig}} + L_{\text{PQC\_pubkey}} + L_{\text{TLS\_headers}}$$
- Example: ML-DSA-65 cert (1,952 + 3,309) + ML-KEM-768 (1,184) + headers (~200) = **6,645 bytes** → requires ≥5 TCP segments on 1,500 MTU path. `[VERIFIED]` NIST FIPS 203/204

**Why This Wins:**
- No commercial tool tests network readiness for PQC. All recommend algorithms based purely on bit-security. `[CONSENSUS-6/6]`
- A live demo showing "your network would **drop** this PQC handshake" is devastating in a hackathon pitch.

**Feasibility:** ★★★★☆ (standard PMTUD technique; Python `scapy` or raw sockets)

---

### PILLAR 6: Signed Evidence Provenance & Unknowns Ledger `[CONSENSUS-5/6]`

**What:** Cryptographically sign every CBOM output and explicitly declare what the scanner **could not inspect** (the Unknowns Ledger).

**Two Components:**

**A. Signed CBOM Attestation:**
- Wrap the CycloneDX 1.6 CBOM in an SLSA/in-toto attestation envelope.
- Sign using Ed25519 (speed) + ML-DSA-65 (PQC-resistant) hybrid scheme.
- Include: tool version, scan timestamp, repository commit hash, scanner configuration, evidence levels, and a hash chain back to the previous scan.
- **Auditors can verify:** "This exact scan configuration, at this exact commit, produced these exact findings."

**B. Unknowns Ledger:**
- Explicitly list what the scanner **did not** or **could not** inspect:
  - Directories excluded by filter rules.
  - Binary files without symbol tables.
  - Encrypted archives.
  - Third-party vendor black-box services.
  - Network segments not reachable by the MTU prober.
- Each entry carries a `reason` and `recommended_action` (e.g., "Request vendor CBOM" or "Schedule manual audit").

**Negative Proof Envelope:**
$$\text{NegativeProof}(\text{scope}) = \{\text{repo\_commit}, \text{binary\_digest}, \text{entry\_points}: N, \text{requests\_observed}: M, \text{claim}: \text{"No reachable RSA signing found"}\}$$

**Why This Wins:**
- Transforms ECDAT from "a scanner" into "an authoritative audit authority."
- 12 of 14 commercial tools produce unsigned, trivially modifiable JSON. `[CITED]`
- Our existing Merkle proof infrastructure provides the cryptographic foundation. `[ALREADY-BUILT]`

**Feasibility:** ★★★★★ (JSON envelope formatting + Ed25519/ML-DSA signing we already use in E-Voting-V2)

---

### PILLAR 7: Pareto Migration Portfolio Optimizer `[CONSENSUS-4+/6]`

**What:** Instead of a flat severity-sorted list, optimize the remediation backlog as a **resource-constrained portfolio** that maximizes risk reduction per unit of engineering effort.

**Mathematical Formulation:**
$$\max_{S \subseteq \mathcal{A}} \sum_{i \in S} \Delta R_i \quad \text{subject to} \quad \sum_{i \in S} C_i \le B$$

Where:
- $\Delta R_i = R_0(i) \times P_{\text{compromise}}(i)$ — blast-radius-weighted risk reduction if asset $i$ is migrated
- $C_i = Y_{\text{code}}(i)$ — engineering cost to migrate asset $i$ (from CAMS level)
- $B$ — total engineering sprint budget (developer-weeks)
- $R_0(i)$ — contagion blast radius from our existing graph `[ALREADY-BUILT]`

**Output:** A ranked "fix these first" list showing the **Pareto frontier** — the set of migrations that achieve the maximum risk reduction for a given engineering budget.

**Visualization:**
- Scatter plot: X-axis = engineering effort, Y-axis = risk reduction.
- Pareto-optimal fixes are highlighted on the efficient frontier.
- Below-frontier fixes are grayed out as suboptimal.

**Why This Wins:**
- Replaces "fix everything marked CRITICAL" (which overwhelms teams) with "fix these 5 things this sprint for 73% total risk reduction."
- Directly leverages our existing $R_0$ contagion engine. `[ALREADY-BUILT]`
- No existing tool does portfolio optimization — all use flat severity ranking. `[CONSENSUS-4+/6]`

**Feasibility:** ★★★★☆ (fractional knapsack / greedy algorithm over dependency graph)

---

## PART 3 — THREE-PHASE IMPLEMENTATION ROADMAP

### Phase 1: "The Demo Killer" (Week 1–2) — Core Differentiation
> Goal: Build the features that make the 3-minute SIH pitch impossible to ignore.

| # | Task | Builds On | Output |
|---|---|---|---|
| 1.1 | Implement DSIS Intent Classifier (Pillar 1) | `x_inference/engine.py` | 4-class intent labels on every asset; 90%+ alert reduction demo |
| 1.2 | Add E0–E5 Evidence State Taxonomy (Pillar 2) | `models.py`, `pipeline.py` | Evidence-level badges in dashboard; Unknowns Ledger tab |
| 1.3 | Schema-based $X_{\text{auto}}$ extractor (Pillar 3 — SQL/ORM only) | `mosca/engine.py`, new `schema_extractor.py` | Automatic data-lifetime from Prisma/SQL/MongoDB schemas |
| 1.4 | K8s/Docker manifest $P_{\text{HNDL}}$ parser (Pillar 3) | `scanners/`, new `exposure_scanner.py` | Network exposure risk labels: `PUBLIC` / `INTERNAL` / `AIRGAPPED` |
| 1.5 | Update Mosca formula to $R_Q$ with $P_{\text{HNDL}}$ | `mosca/engine.py` | Context-aware risk that correctly zeroes out air-gapped assets |

### Phase 2: "The Competitive Moat" (Week 3–4) — What Nobody Else Has
> Goal: Build features that are technically hard to replicate and create defensible IP.

| # | Task | Builds On | Output |
|---|---|---|---|
| 2.1 | CAMS Agility Level detector (Pillar 4) | `scanners/source_scanner.py` | 4-level agility maturity per crypto call site |
| 2.2 | Active Path MTU Prober (Pillar 5) | New `network/mtu_prober.py` | Route profiles (`STANDARD` / `FLEXIBLE` / `CONSTRAINED`) |
| 2.3 | MTU-aware recommendation filter | `agility/recommender.py` | "ML-KEM-1024 BLOCKED: path MTU 1,500 < pubkey 1,568" |
| 2.4 | Signed CBOM + Unknowns Ledger (Pillar 6) | `merkle/`, `pipeline.py` | SLSA/in-toto attestation envelope + Ed25519/ML-DSA hybrid signature |
| 2.5 | CycloneDX Discussion #966 attestation fields | `pipeline.py` CBOM output | Native `reachabilityProof`, `dataLifetime`, `runtimeExecutionStatus` |

### Phase 3: "The Executive Knockout" (Week 5–6) — Optimization & Polish
> Goal: Turn raw data into executive-level decision intelligence.

| # | Task | Builds On | Output |
|---|---|---|---|
| 3.1 | Pareto Migration Portfolio Optimizer (Pillar 7) | `contagion/engine.py`, `mosca/engine.py` | Efficient frontier scatter plot in dashboard |
| 3.2 | Stochastic Mosca upgrade (Monte Carlo) | `mosca/engine.py` | $P(X+Y>Z)$ probability distributions instead of scalar |
| 3.3 | Negative Proof Envelope generator | `report.py`, `pipeline.py` | Audit-defensible "not found" claims with exact scope |
| 3.4 | Dashboard overhaul: new tabs for MTU, Pareto, Evidence | `dashboard/generator.py` | Interactive Path MTU results, Pareto frontier chart, E0–E5 heatmap |
| 3.5 | End-to-end demo on E-Voting-V2 | All modules | Live scan demonstrating all 7 pillars on our own blockchain system |

---

## PART 4 — COMPETITIVE MOAT ANALYSIS

### What Makes ECDAT Impossible to Copy Quickly

| Innovation | Technical Barrier to Replication | Time for Competitor to Match |
|---|---|---|
| **DSIS Intent Classification** | Requires language-specific sink signature databases and forward taint analysis — can't be done with regex | 3–6 months for a well-staffed team |
| **E0–E5 Evidence Taxonomy** | Fundamental data-model redesign; competitors would need to rewrite their core asset schema | 6–12 months (architectural) |
| **$X_{\text{auto}}$ Schema Extraction** | Requires polyglot database/ORM parser ecosystem; no shortcut via API wrapping | 2–4 months |
| **$P_{\text{HNDL}}$ Network Exposure** | Requires K8s API parsing + deployment manifest understanding | 1–2 months (moderate) |
| **Active MTU Probing** | Requires raw socket programming, PMTUD protocol knowledge, and middlebox behavioral modeling | 3–6 months |
| **SLSA/in-toto Signed Provenance** | Requires cryptographic signing infrastructure and attestation schema design | 2–3 months |
| **Pareto Portfolio Optimizer** | Requires combining blast-radius graph theory with knapsack optimization | 2–3 months |

**Combined moat:** A competitor would need 12–18 months to replicate all 7 pillars working together as a coherent system.

---

## PART 5 — SIH 2026 DEMO STRATEGY

### The 3-Minute Killer Pitch Narrative

**Hook (30 seconds):**
> "Every quantum-safe scanner on the market — IBM, SandboxAQ, Keyfactor — produces the same thing: an expensive spreadsheet. They find crypto. They cannot tell you if it matters, if the network can handle the fix, or what to fix first. We built ECDAT to answer the questions they can't."

**Demo Beat 1 — Intent Classification (45 seconds):**
> Live scan of E-Voting-V2 backend. Show 14+ detected crypto assets. Toggle DSIS filter: multiple assets reclassified as `OPERATIONAL_UTILITY` (cache hashes, ETag checksums). Only the genuine `CONFIDENTIALITY_ENVELOPE` or `AUTHENTICATION_SIGNATURE` threats remain. "We just eliminated the false alarms that IBM Explorer would show you."

**Demo Beat 2 — Autonomous Risk Context (45 seconds):**
> Show $X_{\text{auto}}$ pulling data lifetime from database schemas: `session_tokens` → 0 years (ephemeral), `ballot_records` → 25 years (archival). Show $P_{\text{HNDL}}$ from Docker Compose: backend service bound to public port → $P_{\text{HNDL}} = 1.0$. Redis on internal network → $P_{\text{HNDL}} = 0.05$. "The same RSA-2048 key gets two completely different risk scores because we understand context."

**Demo Beat 3 — Network Reality Check (30 seconds):**
> Run MTU prober against demo network. Show: "ML-KEM-1024 BLOCKED on this path — public key (1,568 B) exceeds detected MTU (1,500 B). Recommending ML-KEM-768 (1,184 B) instead." "No other tool in the world checks this."

**Demo Beat 4 — Fix Prioritization (30 seconds):**
> Show Pareto frontier: "Of these real threats, fixing the superspreader ($R_0 = 4.2$) alone reduces system-wide quantum risk by 47%. This is your Sprint 1."

**Closing (15 seconds):**
> "ECDAT doesn't just find crypto. It understands what it's protecting, proves whether the network can handle the replacement, and tells you exactly what to fix first. That's what a quantum migration engine looks like."

---

## PART 6 — EVALUATION RUBRIC (SELF-ASSESSMENT)

### Direct Scoring Criteria (1–5 Scale)

| Criterion | Weight | What Score 5 Looks Like |
|---|---|---|
| **Discovery Accuracy** | 0.15 | ≥90% recall on CamBench-equivalent benchmark with published metrics |
| **Alert Signal-to-Noise** | 0.20 | Intent classification eliminates >80% of operational/non-security alerts |
| **Mosca Risk Fidelity** | 0.15 | Per-asset $X$ from schema, $P_{\text{HNDL}}$ from deployment, $Y$ from code complexity |
| **Remediation Actionability** | 0.15 | Pareto-optimized fix list with effort estimates and blast-radius impact |
| **Network Readiness Validation** | 0.15 | Active MTU probing with algorithm-specific feasibility verdicts |
| **Audit Integrity** | 0.10 | Cryptographically signed CBOM + Unknowns Ledger + Negative Proofs |
| **Dashboard & UX** | 0.10 | Interactive graph, hover highlighting, tabbed exploration, info banners |

### Pairwise Comparison Matrix (ECDAT vs. Market)

| Dimension | IBM Explorer | SandboxAQ | Keyfactor | CBOMkit | QuantumShield | **ECDAT v2** |
|---|---|---|---|---|---|---|
| Intent Classification | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ DSIS** |
| Evidence States (E0–E5) | Partial (E1–E2) | Partial (E4) | ✗ | E1 only | ✗ | **✓ Full E0–E5** |
| Schema-derived $X$ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ Auto** |
| Network $P_{\text{HNDL}}$ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ K8s/Docker** |
| Active MTU Probing | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ PMTUD** |
| Contagion $R_0$ Graph | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ Built** |
| Buffer Hazard Audit | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ Built** |
| Signed CBOM | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ SLSA** |
| Portfolio Optimization | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ Pareto** |
| Unknowns Ledger | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ Explicit** |

---

## PART 7 — WHAT WE DELIBERATELY DO NOT BUILD (YAGNI)

These are ideas from the research that are technically interesting but **not feasible or necessary for SIH 2026**:

| Excluded Feature | Why Not | Pitch As |
|---|---|---|
| eBPF uprobes on `libcrypto.so` | Requires Linux kernel programming expertise, BCC/libbpf toolchain, and root access on target systems. | Future roadmap item for enterprise version |
| SMT/Z3 verified automated code repair | Active academic research frontier. | "Future vision" slide |
| GNN-based stripped binary analysis | Requires custom ML training corpora and decompilation pipelines. | Research collaboration opportunity |
| eBPF TC/XDP handshake padding injection | Risks breaking live network traffic. Unsafe to demo. | Conceptual diagram in pitch |
| Full OpenLineage/Apache Atlas integration | Enterprise-only tools that judges won't have running. | Schema parsing is the achievable proxy |
| Neo4j/KùzuDB graph database | Our in-memory NetworkX graph is sufficient for hackathon scale. | Scale-out architecture diagram |

---

## PART 8 — ACADEMIC GROUNDING

### Key References for Judge Q&A Defense

1. **IBM Research Cryptoscope** (arXiv:2503.19531, Mar 2025): AST backward slicing from crypto sinks. 92% recall, 97% precision on CamBench. `[CITED]`
2. **Näther & Hirsch** (arXiv:2608.04857, Aug 2026): F1 = 0.75 across 10 production services (57,610 files, 370 crypto assets, 6 CVEs, 52 PQC candidates). `[CITED]`
3. **NIST IR 8547**: Transition to Post-Quantum Cryptography Standards (Nov 2024). `[VERIFIED]`
4. **NIST FIPS 203/204/205**: ML-KEM, ML-DSA, SLH-DSA parameter tables. `[VERIFIED]`
5. **OMB M-26-15**: Federal PQC Transition Executive Memorandum (June 2026). `[VERIFIED]`
6. **OMB M-23-02**: Federal inventory mandate — annual manual inventories required. `[VERIFIED]`
7. **CISA ACDI Strategy**: Automated Cryptographic Discovery & Inventory — only 3/9 items automatable. `[VERIFIED]`
8. **CycloneDX Discussion #966**: Maintainers discussing data-lifetime and intended-use for CBOM 2.0 / CDXA. `[VERIFIED]`
9. **Global Risk Institute 2025**: CRQC arrival probability distributions (7%–18% by 2030, 28%–49% by 2035). `[VERIFIED]`
10. **Blanco-Romero et al.**: TLS vs SSH Shor-attack blast radius (37 independent runs for SSH vs 1 for TLS 1.3). `[CITED]`

---

## PART 9 — FACT-CHECK WARNINGS

### Sources to NEVER Cite as Independent `[VERIFIED]`

- **Qtonic Quantum Corp / PQC Discovery Index (`pqc-index.org`):** Vendor-operated "benchmark" that ranks its own product (QScout Pulse Gold) #1 with 9.42/10 while giving IBM 36.4/100 and SandboxAQ 28.6/100 (ranked 202nd/300). This is a marketing funnel disguised as an independent evaluation.

### Hallucinated Tools from Research Models `[VERIFIED]`

The following tools were cited in individual research reports but **do not exist** on the public web:
- Qinsight Atlas, QuantumGenie, Spice Labs Surveyor/Topographer, QuProtect R3 (from Perplexity report)
- PQStation QVision, QryptoCyber (from ChatGPT report)

**Rule:** Never reference these in any pitch, paper, or slide.

---

## PART 10 — THE ONE-LINE POSITIONING

> **ECDAT is not "another CBOM scanner."**
> **ECDAT is an Autonomous Cryptographic Posture Intelligence & Verified Migration Engine.**

It doesn't just find crypto. It understands what the crypto is protecting, how long that data lives, whether the network can handle the replacement, and what to fix first — then proves its own claims with signed evidence.

That is the gap. That is the innovation. That is what wins SIH 2026.

---

## APPENDIX A — MODULE INTEGRATION ARCHITECTURE

```
   ┌────────────────────────────────────────────────────────┐
   │                  DISCOVERY SENSORS                     │
   │  ┌───────────────┐ ┌───────────────┐ ┌──────────────┐  │
   │  │  AST Scanners │ │ Config Parsers│ │Schema Extract│  │
   │  │  [BUILT]      │ │ [BUILT]       │ │ [NEW-P1]     │  │
   │  └───────┬───────┘ └───────┬───────┘ └──────┬───────┘  │
   └──────────┼─────────────────┼────────────────┼──────────┘
              │                 │                │
              ▼                 ▼                ▼
   ┌────────────────────────────────────────────────────────┐
   │        EVIDENCE-CENTERED GRAPH ENGINE [NEW-P1]         │
   │  Node State Machine: E0 ──► E1 ──► E2 ──► E3 ──► E5   │
   │  DSIS Intent Classifier: OP_UTIL | INTEG | AUTH | CONF │
   │  Unknowns Ledger: tracks unresolvable E0/E1 assets     │
   └──────────┬──────────────────────────────────┬──────────┘
              │                                  │
              ▼                                  ▼
   ┌───────────────────────────┐    ┌──────────────────────────┐
   │   ENRICHED MOSCA ENGINE   │    │  ACTIVE NETWORK PROBER   │
   │   [UPGRADE-P1/P3]        │    │  [NEW-P2]                │
   │ X_auto from schemas       │    │  DF-bit PMTUD probing    │
   │ P_HNDL from K8s/Docker   │    │  Profiles: STD/FLEX/CON  │
   │ Y_code from CAMS+AST     │    │                          │
   │ Monte Carlo P(X+Y>Z)     │    │                          │
   └──────────┬────────────────┘    └────────────┬─────────────┘
              │                                  │
              └───────────────┬──────────────────┘
                              ▼
   ┌────────────────────────────────────────────────────────┐
   │  PARETO PORTFOLIO OPTIMIZER [NEW-P3]                   │
   │  - Algorithm selection filtered by MTU PathProfile     │
   │  - Remediation ranked by Max ΔRisk / Effort            │
   │  - Sprint planning with engineering budget constraint   │
   └──────────────────────────┬─────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
   ┌───────────────────────────┐ ┌─────────────────────────────┐
   │ CYCLONEDX CBOM + #966    │ │ SIGNED EVIDENCE PROVENANCE   │
   │ [UPGRADE-P2]             │ │ [NEW-P2]                     │
   │ reachabilityProof        │ │ Ed25519 + ML-DSA hybrid sig  │
   │ dataLifetime             │ │ SLSA/in-toto envelope        │
   │ runtimeExecutionStatus   │ │ Negative Proof Envelopes     │
   │ adversarialExposure      │ │ Unknowns Ledger export       │
   └───────────────────────────┘ └─────────────────────────────┘
```

**Legend:** `[BUILT]` = existing, `[NEW-Pn]` = new in Phase n, `[UPGRADE-Pn]` = enhanced in Phase n

---

## APPENDIX B — STOCHASTIC MOSCA MATHEMATICAL SPECIFICATION

### Current Implementation (Deterministic) `[ALREADY-BUILT]`
$$Y_{\max} = (Z_{\text{reg}} - \text{CurrentYear}) - X_{\text{tier}}$$

### Upgraded Implementation (Stochastic) `[SYNTHESIS]`

Model all three Mosca variables as continuous probability distributions:
$$X \sim \mathcal{D}_X, \quad Y \sim \text{LogNormal}(\mu_Y, \sigma_Y^2), \quad Z \sim \text{Weibull}(\lambda_Z, k_Z)$$

Where:
- $X$ is derived from schema extraction (discrete tiers mapped to distribution priors)
- $Y \sim \text{LogNormal}$ because migration timelines are right-skewed (most take ~baseline, some take much longer)
- $Z \sim \text{Weibull}$ because quantum computer arrival follows a hazard-rate model (increasing probability over time)

The quantum compromise probability is:
$$P_{\text{compromise}} = P(X + Y > Z) = \int_0^\infty \int_0^\infty \int_0^{x+y} f_X(x) \cdot f_Y(y) \cdot f_Z(z) \, dz \, dy \, dx$$

Evaluated via **10,000-iteration Monte Carlo simulation** (computationally cheap, runs in <100ms).

### Final Risk Score Per Asset
$$R_Q(i) = P_{\text{compromise}}(i) \times P_{\text{HNDL}}(i) \times (1 - A_{\text{CAMS}}(i)) \times R_0(i)$$

Where $R_0(i)$ is the contagion blast radius from our dependency graph. `[ALREADY-BUILT]`

---

*End of MY-Plan-V2.md*
