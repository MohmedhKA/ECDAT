# ECDAT — MY-Plan.md
### Synthesized Master Plan: Cross-Verified + Research Model Corrections + Innovative Extensions
**Last updated:** 2026-09-01  
**Status:** Working document — idea-phase complete, build-phase TBD

---

## HOW TO READ THIS FILE

Every claim carries a source tag:
- `[VERIFIED]` = independently confirmed against a checkable source
- `[CITED]` = from a named published paper, link given
- `[SYNTHESIS]` = reasoning from first principles, not yet published anywhere — treat as an argument, not a fact
- `[CORRECTED]` = a specific error from an earlier draft, now fixed

If a number goes in front of a judge, it must have a `[VERIFIED]` or `[CITED]` tag. No exceptions.

---

## PART 1 — FACTUAL CORRECTIONS (Apply Before Anything Else)

These are errors that were in earlier drafts and the presentation script. Fix these before the idea goes anywhere near a reviewer.

### Correction 1 — The signature size comparison number `[CORRECTED]`
**Wrong (used in earlier pitch line #4):** "ML-DSA-65 signatures are 13x larger than ECDSA"  
**Why it's wrong:** 13x is correct only when comparing against RSA-2048 (256 bytes → 3,309 bytes ≈ 12.9x). Against ECDSA P-256, the comparison is 64 bytes → 3,309 bytes = **51.7x larger**.  
**Fix:** Always specify the baseline. Use the table below:

| Algorithm | Signature Size | vs ECDSA P-256 (64 B) | vs RSA-2048 (256 B) |
|---|---|---|---|
| ECDSA P-256 | 64 bytes | baseline | 0.25x |
| RSA-2048 | 256 bytes | 4x | baseline |
| ML-DSA-44 (Level 2) | 2,420 bytes | 37.8x | 9.5x |
| ML-DSA-65 (Level 3) | 3,309 bytes | **51.7x** | **12.9x** |
| ML-DSA-87 (Level 5) | 4,627 bytes | 72.3x | 18.1x |
| SLH-DSA-128f | 17,088 bytes | 267x | 66.7x |

`[CITED]` NIST FIPS 204 Table 2 (parameters), Table 1 (SLH-DSA sizes in FIPS 205)

---

### Correction 2 — Validation Framing: Ground-Truth Open-Source Benchmarks `[CORRECTED]`
**Wrong:** Claiming ECDAT is "validated on a live production system" before blind testing runs.  
**Why it's wrong:** ECDAT is a new discovery tool. Claiming automated derivation against a previously built project where ground truth was set by human design is premature. A security judge will immediately ask for blind test results or test harness output.  
**Fix:** Frame validation around open-source benchmarks and public cryptographic repositories:

> "Validation is designed around open-source enterprise Java and Python microservices with known cryptographic estates (e.g. CamBench suite, Apache Commons Crypto, Spring Security reference architectures). The ground truth for each cryptographic call site is established by manual security audit, and ECDAT's detection accuracy, false positive rate, and X-tier assignments are measured quantitatively against that baseline."

This is scientifically honest, verifiable, and withstands scrutiny.

---

### Correction 3 — "Differential privacy" is not what the two-tier CBOM design does `[CORRECTED]`
**Wrong:** Calling the aggregated compliance export "differential privacy"  
**Why it's wrong:** Differential privacy requires a formal noise parameter (epsilon ε), a privacy budget, and a mechanism that adds calibrated random noise to outputs. What the two-tier design actually does is k-anonymity-style aggregation (grouping and counting without revealing individuals). These are different things. A judge who knows DP will ask "what's your epsilon?" and there isn't one.  
**Additional problem with the aggregation itself:** When a bucket has count = 1 ("payment-service: 1 critical asset"), that asset is identified with certainty. Aggregation only hides when there's enough in a bucket to disappear into.  
**Fix:**  
- Call it what it is: **risk-tiered aggregation**  
- Add a **minimum bucket-size rule**: if a service-level group has fewer than k assets in a risk tier (suggested k = 3), fold it into a coarser grouping (e.g., business-unit level) or redact the count entirely  
- If you want actual DP, the Python `diffprivlib` library (IBM Research, open source) adds genuine Laplace/Gaussian mechanisms and outputs a real epsilon — this is a day of work, not a research problem, and if you build it you can say "epsilon = 2.0" to a judge and mean it

---

### Correction 4 — X-inference runs on source code, not on CBOM output `[CORRECTED]`
**Wrong:** "Component 1 post-processes the CBOM JSON to infer X"  
**Why it's wrong:** The CBOM is what taint analysis *produces*, not what it *runs on*. Taint analysis runs on the source code, AST, and call graphs. The CBOM then records the X_tier field as an output of that analysis.  
**Fix:** Taint/dataflow analysis runs alongside CBOMkit-hyperion during the Layer 1 scan, on the source code. The resulting X_tier and confidence fields are written into the CBOM as additional properties at generation time, not added retroactively.

---

### Correction 5 — TLS blast-radius schema loses real information `[CORRECTED]`
**Wrong:** `"hndlBlastRadius": "CASCADE"` as a string label  
**Why it's wrong:** This throws away the numerical content from Blanco-Romero et al. — their measurement was 37 independent Shor-algorithm runs for an SSH session vs. 1 for TLS 1.3/QUIC. The category is a summary; the number is the data.  
**Fix — extended protocol schema for CBOM:**

```json
{
  "cryptoProperties": {
    "assetType": "protocol",
    "protocolProperties": {
      "name": "TLS",
      "version": "1.3",
      "sessionRisk": {
        "zeroRTTEnabled": true,
        "ticketLifetimeSeconds": 86400,
        "extendedKeyUpdateDeployed": false,
        "hndlBlastRadiusCategory": "CASCADE",
        "hndlIndependentQuantumComputationsRequired": 1,
        "hndlNote": "KeyUpdate derives each epoch from prior via HKDF — one broken key cascades downstream. Fix pending: draft-ietf-tls-extended-key-update (WIP as of 2026)."
      }
    }
  }
}
```
`[CITED]` Blanco-Romero et al., arxiv.org/pdf/2603.01091, §4.3 (37 vs 1 computation comparison)

---

### Correction 6 — Component 1 "2 days" is optimistic `[CORRECTED]`
**Wrong:** Implying taint/dataflow analysis that works across arbitrary codebases is a two-day task  
**Right:** Two days gets you a single-language, single-framework, narrow-pattern prototype. Cross-function taint tracking with indirect calls, multiple persistence APIs, and language-specific edge cases is real engineering that takes weeks for production quality.  
**Fix — honest scope statement:** In the hackathon window, the X-inference prototype handles Python and Java, checks for direct file write / DB insert / archival stream calls within the same module as the crypto invocation, and flags everything else as `confidence: LOW, reviewRequired: true`. That's the honest boundary. Name it as a prototype, not a complete system.

---

## PART 2 — THE COMPETITIVE LANDSCAPE (What Already Exists — Know This Cold)

Do NOT pitch "we solve X" without knowing which of these competitors already does it.

| Competitor | What It Does | Its Real Limitation |
|---|---|---|
| **SandboxAQ AQtive Guard** | Runtime instrumentation (hooks into running processes), network analyzer, filesystem analyzer. DoW 5-year contract (Dec 2025). FedRAMP Ready. | Runtime instrumentation has real overhead/stability cost — often restricted to test environments. Academically assessed as "presence-only" not semantically complete (Cryptoscope §5.1) `[VERIFIED]` |
| **IBM Quantum Safe Explorer** | Static source scanning → CBOM. IBM's docs describe it as providing "a static view." `[VERIFIED]` | Dynamic/runtime gap is real for this specific product. Does not compute Mosca scoring. Does not treat CBOM as a protected asset. |
| **IBM Cryptoscope (Research, Mar 2025)** | Full data/control-flow slicing → semantically complete crypto assets. 92% exact recall, 97% precision on CamBench. `[VERIFIED: arxiv.org/pdf/2503.19531]` | Static only, single-repo, Java-primary. Not yet a shipped product. This is the ceiling of current static analysis. |
| **CBOMkit (now PQCA/Linux Foundation)** | Open-source scanner (hyperion for source, theia for containers). `[VERIFIED]` | Foundation tool — we build on top of it, not against it. Correct repo: `github.com/PQCA/cbomkit` not `github.com/IBM/CBOM` |
| **InfoSecGlobal AgileScan** | Certificate/key/library discovery | Same semantic-completeness gap as AQtive Guard per Cryptoscope §5.1 `[VERIFIED]` |

**The one confirmed white space across all of the above:** None of them treat the CBOM as a protected asset. All of them generate the inventory and hand it over as a plain file.

---

## PART 3 — THE REAL DIFFERENTIATORS (What ECDAT Claims)

In order of defensibility. Lead with #1.

### Differentiator 1: CBOM Confidentiality via Merkle Commitment `[SYNTHESIS + innovation]`

**The Problem (confirmed, no existing solution found):**  
A complete CBOM is a targeting map — "RSA-2048 at payment-service/src/sign.py:142" is exactly what an HNDL-positioned adversary wants. Every existing commercial tool generates this file and hands it to whoever asks. `[VERIFIED: no existing tool addresses this]`

**The Solution — Merkle Commitment Scheme (Privacy-Preserving Attestation):**  
This architecture uses cryptographic commitment schemes (Merkle trees) widely proven in Certificate Transparency logs (RFC 6962) and verifiable data registries:

How it works:
1. Hash each crypto-asset record into a leaf node: `Leaf = SHA256(component_id || file_path_hash || algorithm || key_size || x_tier || compliance_status || salt)`
2. Build a Merkle tree over all leaves
3. Publish only the **32-byte Merkle root** — reveals nothing about individual assets or sensitive internal file paths
4. Answer compliance questions with **selective Merkle inclusion proofs** — an auditor asking "is payment-service compliant?" receives a proof for that single leaf plus log2(N) sibling hashes, not the rest of the inventory
5. For aggregate claims ("95% of critical assets are compliant"), use statistical sampling verification — auditor requests a random sample of proofs, verifying mathematical inclusion against the committed root without needing the full internal tree

**What this gives you that no other tool has:**  
- **Tamper-evidence:** The root is committed at a point in time. Nobody can retroactively claim "we were compliant all along" after a breach — the commitment either matches or it doesn't.  
- **Zero inventory exposure to external auditors:** Regulatory compliance can be proven without handing over an attack blueprint of the internal cryptographic estate.  
- **Practical reality check:** While standard compliance auditors today still ask for CSV/PDF exports, this architecture prepares enterprises for zero-knowledge and privacy-preserving compliance mandates, eliminating the audit-side leak vector.

**This replaces the naive two-tier aggregation design** from earlier drafts. It solves the confidentiality problem mathematically without leaking when a bucket has count = 1.

`[CITED sources]`
- Merkle commitment scheme: Merkle (1987) — standard cryptographic primitive, not novel per se
- Risk-limiting audits applied to ballot tallying: Stark et al., multiple papers 2008–2020, implemented in real US elections
- Application to CBOM compliance: `[SYNTHESIS]` — no published prior art found

---

### Differentiator 2: Mosca Engine as Planning Tool, Not Flag `[SYNTHESIS + corrects existing tools]`

**What every existing tool does:** Binary flag — "X + Y > Z → at risk: yes/no"  
**Why Mosca's original theorem alone is insufficient (Known Limitations):**
1. **Z is treated as a deterministic point estimate:** The arrival of a Cryptanalytically Relevant Quantum Computer (CRQC) is probabilistic, not fixed. Collapsing it to a single year creates false precision.
2. **Binary output provides no engineering actionability:** Stating an asset is "at risk" does not inform a CISO whether they have 6 months or 8 years, nor which asset to schedule first.
3. **Assumes X and Y are independent:** In reality, migration effort Y depends heavily on how many assets have long retention X and how deeply coupled the cryptographic primitives are across services.
4. **X is assumed to be known:** Mosca assumes organizations know the secrecy lifespan X of their data. In practice, enterprise teams have zero automated visibility into data lifespan.
5. **Ignores operational levers like crypto-shredding:** You can shrink X without re-encrypting petabytes of data simply by enforcing key destruction schedules.
6. **Ignores shared resource constraints:** 4,000 assets cannot all be migrated simultaneously; engineering bandwidth, HSM throughput, and regression testing create queuing delays.

**ECDAT's Mathematical Formulation:**
- **Actionable Metric:** `Y_max = Z − X` (the maximum permissible engineering budget before HNDL vulnerability occurs).
- **Dual-Z Architecture:**
  - `Z_regulatory`: Mandatory compliance deadline under OMB M-26-15 (Phase 3 key exchange by 2030, Phase 4 signatures by 2031, Phase 5 full by 2035) and NIST IR 8547.
  - `Z_physical`: Probabilistic distribution from the Global Risk Institute (GRI) 2025 Quantum Threat Timeline (28–49% probability of CRQC within 10 years).
- **Crypto-Shredding Lever:** Flags where key lifecycle automation collapses effective data lifespan X from ARCHIVAL to EPHEMERAL.

**Output format for a CBOM risk entry:**
```json
{
  "moscaScore": {
    "X_tier": "OPERATIONAL",
    "X_years_estimated": 5,
    "X_confidence": "HIGH",
    "X_lever_available": "crypto_shredding_viable",
    "Y_current_estimate_years": 1.5,
    "Y_max": 3.5,
    "Z_regulatory_phase": 3,
    "Z_regulatory_deadline": "2030",
    "Z_physical_probability_10yr": "28-49%",
    "risk_flag": "HIGH",
    "planning_note": "Y_current (1.5yr) < Y_max (3.5yr) — on track at current resourcing; crypto-shredding can reduce X to 0.5yr"
  }
}
```

---

### Differentiator 3: 4-Tier Automated X-Inference via Call-Graph Taint Analysis `[SYNTHESIS]`

**What every existing tool does:** X is either manually tagged in spreadsheets or ignored entirely.  
**What ECDAT does differently:** Infers X automatically from source code ASTs, call graphs, and persistence sink analysis, classifying each asset into four distinct tiers with explicit confidence scores.

#### The 4-Tier Data Lifespan Model (Not a simplistic binary assumption):
1. **`EPHEMERAL` (~0 years / in-memory only):**
   - Cryptographic material exists solely in volatile memory and is explicitly zeroed or destroyed upon session close.
   - Examples: TLS 1.3 ephemeral ECDH / X25519 handshakes, ephemeral HMAC session nonces, memory-only RAM caches.
   - HNDL impact: Zero retrospective vulnerability if session keys are destroyed.
2. **`SHORT_TERM` (~1–2 years):**
   - Credentials, session tokens, rotating API keys, OAuth refresh tokens, Redis caches with short TTLs.
   - HNDL impact: Low; data value naturally expires before quantum hardware arrival.
3. **`OPERATIONAL` (~3–7 years, typical baseline 5 years):**
   - Standard relational database records (PostgreSQL, MySQL, Oracle), active customer profiles, enterprise ERP/CRM records, standard statutory business records under GDPR / corporate limitation statutes.
   - HNDL impact: Moderate-to-High; must be migrated before 2030 to prevent decrypt-later exposure.
4. **`ARCHIVAL` (~10+ years to permanent):**
   - Long-term encrypted backups, medical records (HIPAA 6–10+ years), financial transaction logs (SOX 7–10 years), tax archives, national citizen registries, root certificate authority private keys.
   - HNDL impact: Critical; adversaries can capture ciphertext today and crack it in 2035 with catastrophic impact.
5. **`HUMAN_REVIEW` (Flagged ambiguity):**
   - Assigned when static analysis detects ciphertext flowing into unanalyzed external libraries or ambiguous sinks. Never silently guesses; assigns confidence score and links exact code site.

#### Handling Inter-Procedural Data Flow (Addressing the Cross-Function Persistence Limitation):
A classic challenge in static analysis is: *what if function A encrypts data and passes the ciphertext to function B, and function B writes it to a database?*
- **Intra-procedural analysis alone fails:** It loses the taint tag once the variable crosses the function boundary.
- **ECDAT's 3-Layer Inter-Procedural Resolution:**
  1. **Internal Call-Graph Traversal:** For code within the scanned repository, ECDAT builds a whole-program call graph using Tree-sitter and Sonar AST representations, propagating taint tags across internal function parameters and return values.
  2. **Pre-Annotated Persistence API Stubs:** For third-party frameworks and external libraries where source code is unavailable, ECDAT ships pre-annotated sink signatures:
     - ORM & Database Sinks (`session.add()`, `repository.save()`, `PreparedStatement.executeUpdate()`, `pymongo.insert_one()`) → tagged **OPERATIONAL (5yr)** or **ARCHIVAL (10yr)** based on table metadata.
     - Cloud Storage Sinks (`s3.put_object()`, `blobClient.upload()`, `gcs.bucket.upload()`) → tagged **ARCHIVAL (10yr)**.
     - Cache & Memory Sinks (`redis.setex(..., ttl)`, `memcached.set()`) → tagged **SHORT_TERM (1–2yr)**.
     - Key Destruction / Zeroization calls (`Arrays.fill(key, (byte)0)`, `sodium_memzero()`) → tagged **EPHEMERAL (0yr)**.
  3. **Fallback to HUMAN_REVIEW:** If ciphertext flows into an opaque third-party black-box method not present in our stub library, ECDAT flags: `X_tier: "HUMAN_REVIEW"`, `confidence: "LOW"`, pointing to `file:line` with reason *"Taint escaped into unanalyzed external call"*.

**Why local analysis only:** All AST parsing, taint tracing, and tier classification execute locally inside the customer's CI/CD or air-gapped environment. No codebase or inventory data is ever transmitted to external cloud LLMs.

---

### Differentiator 4: Hybrid-First Migration Guidance & Crypto-Agility Engine `[SYNTHESIS + Standards Alignment]`

**What existing discovery tools do:**  
Commercial scanners flag an algorithm as "vulnerable" and output a generic recommendation (e.g. "replace RSA with ML-KEM"). They do not account for backward compatibility, protocol negotiation constraints, or memory buffer overflow risks.

**The real problem in enterprise migrations:**  
1. **Pure PQC is risky for immediate drop-in:** International regulatory authorities (NIST, German BSI, French ANSSI) mandate **hybrid schemes** during the transition period to guard against zero-day cryptanalytic breaks in newly standardized lattice schemes.
2. **Fixed-buffer memory overflows:** Legacy C/C++, Java, and Go code often allocate fixed byte arrays for keys and signatures (e.g., `byte sig[64]` for ECDSA). Attempting to write an ML-DSA-65 signature (3,309 bytes) causes silent buffer overflows or serialization failures.
3. **Cryptographic Agility Score:** Most codebases tightly couple cryptographic algorithm calls to application logic rather than using abstract crypto provider interfaces.

**The ECDAT Agility & Hybrid Engine:**  
- **Dual-Algorithm Pairing:** Recommends standardized hybrid combinations:
  - Key Encapsulation: `X25519MLKEM768` (per IETF draft-ietf-tls-ecdhe-mlkem / RFC 9180)
  - Digital Signatures: Dual composite signatures (`ECDSA-P256 + ML-DSA-65` per IETF composite draft)
- **Static Buffer Audit:** Scans variable allocations adjacent to crypto call sites to flag fixed-size buffer hazards before engineers attempt algorithm replacement.
- **Crypto-Agility Metric:** Assigns an Agility Rating (0–100) based on whether cryptography is isolated behind abstraction layers (e.g., JCA/JCE providers, OpenSSL EVP interfaces) versus hard-coded primitive instantiations.

---

### Differentiator 5: Epidemiological Contagion Modeling for Dependency Risk `[SYNTHESIS, novel framing]`

**The insight:** Current per-asset risk scoring treats every asset independently. But CBOM risk propagates like disease through a contact network. One vulnerable shared library "infects" every downstream service that imports it.

**What to build:**  
- Overlay the CBOM on the existing SBOM dependency graph (most orgs already have one)
- Compute an **R0-equivalent** for each vulnerable component: how many downstream components are exposed if this one is left unmigrated
- Apply **superspreader identification**: in real dependency graphs, a small number of widely-imported vulnerable configs account for most total exposure — find those first
- Output: "Migrating this one shared auth library eliminates critical exposure in 47 downstream services" is a fundamentally different (and more useful) insight than "this library is itself high-risk"

**The pitch to a CISO:** A flat risk-ranked list gives you 4,000 line items. This gives you 12 superspreaders that each have an R0 > 10. Fix those 12 and your total exposure drops by 80%.

`[SYNTHESIS]` — framing is novel; the underlying graph analysis is standard dependency analysis applied with an epidemiological lens.

---

### Differentiator 6: Efficient Frontier for Migration Budget `[SYNTHESIS, from finance]`

**The insight:** The question a CISO actually asks is not "what's the priority list" — it's "given my engineering budget for the next quarter, which combination of migrations reduces my total quantum risk by the most?"

**That is the Markowitz portfolio optimization problem, exactly.**  
- Each asset has: `cost_to_migrate` (engineering hours) and `risk_reduction_if_migrated` (calculated from Mosca score)  
- Feed into a portfolio optimizer  
- Output: an **efficient frontier curve** — at each budget level, the achievable risk reduction and the specific set of assets to migrate to reach it  
- Marginal value of the next hour of engineering time is visible directly from the curve slope

**Why this matters:** This is the shape of the actual CFO/CISO conversation. "Here's our migration budget for H1. Here's what we can accomplish with it, and here's the marginal value of adding $200K more." A flat priority list doesn't answer that question. An efficient frontier does.

---

## PART 4 — THE X-INFERENCE PIPELINE TECHNICAL DETAIL

This is the most novel automated component and deserves the most precision.

### Taint analysis — what "persistent write" means in practice:

**Python (Tier 2 prototype scope):**
- Persistent: `open(path, 'wb').write(ciphertext)`, `db.execute(INSERT ...)`, `s3.put_object(Body=ciphertext)`, `shutil.copy`, `pickle.dump`, `json.dump` to file handle
- Ephemeral: ciphertext only passed to network socket (TLS send), returned from function without write, explicit `del` or `zeros(len(ciphertext))`
- Flag as `reviewRequired`: cross-function boundary without clear terminal sink in same module

**Java (Tier 2 prototype scope):**
- Persistent: `FileOutputStream`, `ObjectOutputStream`, `PreparedStatement.setBytes`, `S3Client.putObject`, `RedisTemplate.opsForValue().set`
- Ephemeral: `SSLSocket.getOutputStream().write`, in-memory `ByteArray` destroyed in same scope, `Arrays.fill(key, (byte)0)` pattern

**Confidence levels — be explicit in CBOM output:**
```json
"X_inference": {
  "tier_used": 2,
  "method": "dataflow_persistence_trace",
  "result": "EPHEMERAL",
  "confidence": "MEDIUM",
  "evidence": "No persistent write sink found within module scope. Key zeroed at line 87.",
  "review_required": false,
  "prototype_scope_note": "Analysis covers direct calls within same module only. Cross-module persistence not checked in v0.1."
}
```

---

## PART 5 — WHAT NOT TO LEAD WITH (AND WHY)

These are not bad ideas — they're just not differentiated from what already exists:

| Don't Lead With | Why |
|---|---|
| "We solve the dynamic/reflection blind spot" | SandboxAQ AQtive Guard already does runtime instrumentation `[VERIFIED]` |
| "We built a binary analysis pipeline" | Every competitor does symbol-table → constants → disassembly triage. Say symbol-table-only for MVP, name Ghidra for roadmap. |
| "Our tool is validated on proprietary production estates" | Premature without published blind test harness. Current honest framing: "benchmarked against open-source enterprise reference architectures with known ground truth" |
| Any unverified benchmark number | If a judge asks to reproduce it and you can't, the whole pitch collapses |

---

## PART 6 — THE PITCH ORDER (What to Lead With)

**Opening:** "Every existing tool generates a cryptographic inventory — and hands it over as a plain file. That file is a targeting map for the exact attack the tool is supposed to prevent. ECDAT is the first tool that treats its own output as a protected asset."

**Then, in order:**

1. **Merkle Commitment CBOM** — genuinely unaddressed white space, no prior art found, tamper-evident by design
2. **Mosca as planning tool (Y_max = Z − X)** — deeper than any competitor's binary flag, anchored to OMB M-26-15 phase schedule and GRI 2025 distribution
3. **4-Tier X-inference automation** — eliminates manual tagging; classifies EPHEMERAL, SHORT_TERM, OPERATIONAL, ARCHIVAL, and HUMAN_REVIEW
4. **Hybrid-First & Crypto-Agility Guidance** — maps standardized hybrid pairs (RFC 9180) and detects fixed-buffer overflow hazards
5. **Epidemiological R0 superspreader prioritization** — reframes the CISO conversation from list to network
6. **Efficient frontier for migration budget** — reframes the CFO conversation from priority to optimization

**Everything else** (CBOMkit/PQCA integration, FIPS 203/204/205 recommendation mapping, ECMA-424 CBOM output) is the **foundation**, presented honestly as "we built on the same open standards the industry uses."

---

## PART 7 — BUILD ORDER FOR HACKATHON TIMELINE

Listed in order of impact-per-day. Stop when time runs out.

### Priority 1 (1 day): Mosca Engine — Correct Form
- Y_max = Z − X output instead of binary flag
- Z_regulatory from OMB M-26-15 phase lookup table
- Z_physical as range from Global Risk Institute 2025 survey
- X as four-tier with confidence field
- X lever (crypto-shredding option) flagged when applicable

### Priority 2 (1 day): Merkle Commitment Exporter
- Hash each CBOM asset record → SHA-256 leaf
- Build Merkle tree, publish root
- Generate inclusion proof for any single leaf
- Output: `cbom_root.hex`, `proof_<assetId>.json`
- This is the demo-able differentiator — show it working in the presentation

### Priority 3 (1-2 days): 4-Tier X-Inference Prototype (Python, AST + Taint)
- Single module, direct persistence trace (DB/Disk/RAM)
- Four output tiers (EPHEMERAL, SHORT_TERM, OPERATIONAL, ARCHIVAL) + confidence + review flag
- Inter-procedural stub matcher for JPA, SQLAlchemy, S3 SDK
- Integrate as a CBOMkit-hyperion post-processor

### Priority 4 (1-2 days): Hybrid-First Recommendation & Agility Engine
- Input: CBOM asset inventory
- Map primitives to FIPS 203/204/205 + hybrid pairings (X25519MLKEM768, composite signatures)
- Buffer-overflow check: static scan for fixed-size byte buffers near crypto call sites

### Priority 5 (if time): R0/Superspreader Graph Analysis
- Overlay CBOM on dependency graph
- Compute downstream exposure per vulnerable component
- Identify top-K superspreaders

### Not in hackathon scope, name as roadmap:
- ZK-SNARK proofs over CBOM predicates
- Full DP with formal epsilon guarantee (doable, just takes more than a day)
- Disassembly-level binary analysis (Ghidra headless)
- Efficient frontier optimizer (portfolio math is a day's work, but integration needs the rest to be solid first)
- Dynamic runtime instrumentation (eBPF, JVM agent) — real engineering, months of work

---

## PART 8 — SOURCES

All claims in this document should be traceable to one of these:

- NIST IR 8547: https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
- NIST FIPS 203 (ML-KEM): https://doi.org/10.6028/NIST.FIPS.203
- NIST FIPS 204 (ML-DSA): https://doi.org/10.6028/NIST.FIPS.204
- NIST FIPS 205 (SLH-DSA): https://doi.org/10.6028/NIST.FIPS.205
- OMB M-26-15: https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf
- Executive Order 14412: https://www.whitehouse.gov/presidential-actions/2026/06/executive-order-14412/
- IBM Cryptoscope paper: https://arxiv.org/pdf/2503.19531
- Blanco-Romero et al. HNDL feasibility (2026): https://arxiv.org/pdf/2603.01091
- Global Risk Institute Quantum Threat Timeline (2025): https://globalriskinstitute.org/publication/quantum-threat-timeline/
- SandboxAQ AQtive Guard: https://www.sandboxaq.com/solutions/security/discover
- CBOMkit / PQCA: https://github.com/PQCA/cbomkit
- CycloneDX CBOM / ECMA-424: https://cyclonedx.org/capabilities/cbom/
- Risk-limiting audits (Stark): https://www.stat.berkeley.edu/~stark/Preprints/gentle12.pdf
- IETF TLS extended key update draft: https://datatracker.ietf.org/doc/draft-ietf-tls-extended-key-update/
- IBM diffprivlib (for actual DP if needed): https://github.com/IBM/differential-privacy-library
