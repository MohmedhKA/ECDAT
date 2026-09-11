# ECDAT: Innovative Research-to-Design Report
## Reverse-engineering proven research solutions to build a more trustworthy enterprise cryptographic discovery platform

**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
**Prepared for:** MohmedhKA and project team
**Purpose:** Convert fact-checked market weaknesses and relevant research into an implementable, differentiated ECDAT architecture.

> **Research discipline:** This report separates verified research results from proposed ECDAT ideas. A research result is not automatically a production guarantee, and a proposed feature must be validated through benchmarks on ECDAT's own test corpus.

---

## 1. Executive Direction

ECDAT should not compete by claiming to scan more file types than IBM, SandboxAQ, or Keyfactor. The defensible opportunity is to create a **Crypto Evidence and Decision Fabric** that answers four questions simultaneously:

1. **What cryptography could exist?** — source, binaries, libraries, firmware, containers, configurations, certificates, keys, cloud and hardware metadata.
2. **What cryptography actually executed or negotiated?** — runtime events and network observations with controlled instrumentation.
3. **How certain are we?** — evidence provenance, confidence, reachability, negative evidence, and explicit unknowns.
4. **What should the organization do first, and can the fix be verified?** — data-lifetime-aware Mosca/HNDL risk, business impact, migration graph, pull requests, policy changes, and post-fix proof.

The central innovation is a **dual-state, evidence-backed CBOM**:

- **Potential state:** statically inferred capabilities and possible crypto paths.
- **Observed state:** cryptographic operations actually seen during selected runtime/network coverage.
- **Reconciled state:** a machine-readable conclusion containing evidence, confidence, coverage boundaries, and drift status.

This directly addresses the market's structural problem: existing products commonly produce either a rich static inventory or a dynamic trace, but enterprises need the relationship between the two.

---

## 2. Fact-Checked Problem Register

The attached fact-checked market report identifies the following problems. They should become explicit ECDAT requirements rather than informal design concerns [file:66].

| ID | Fact-checked problem | Design consequence for ECDAT |
|---|---|---|
| P1 | Static analysis provides potential usage, not guaranteed production usage. IBM explicitly describes Explorer as a static view [file:66]. | Every finding must label `potential`, `observed`, `inferred`, or `confirmed` state. |
| P2 | Runtime instrumentation can introduce overhead or stability risk and is often constrained to test environments [file:66]. | Use a tiered sensor model: passive network observation first, low-overhead host probes second, opt-in application instrumentation last. |
| P3 | String matching and incomplete symbol resolution generate false positives and missed findings. Cryptoscope research targets this limitation [file:66]. | Use compiler/data/control-flow analysis and preserve unresolved evidence instead of silently dropping it. |
| P4 | No automated tool can honestly guarantee complete coverage across black-box vendors, OT, SaaS, legacy and embedded systems. Policy bodies require manual supplementation [file:66]. | Report coverage and unknowns as first-class assets. Never display a misleading 100% completeness score. |
| P5 | Primitive-level alerts create fatigue because they ignore data lifetime and business impact [file:66]. | Compute risk per cryptographic use and data flow, not only per algorithm name. |
| P6 | Mosca's inequality is often simplified into generic severity labels [file:66]. | Store X, Y, Z, uncertainty distributions and attack exposure per asset. Recalculate when assumptions change. |
| P7 | Static CBOM snapshots do not adequately represent drift, history or forensic queries [file:66]. | Maintain append-only observations and a temporal inventory with diff, replay and drift detection. |
| P8 | Remediation is often disconnected from real tickets, pull requests, configuration rollout and verification [file:66]. | Build a closed-loop control plane: recommend → approve → change → rescan → prove. |
| P9 | Benchmark accuracy and evidence quality are rarely disclosed by vendors; conflicted benchmarks must not be presented as independent [file:66]. | ECDAT must publish its detector-level precision/recall, corpus, version, blind spots and signed results. |
| P10 | Oversized PQC handshakes create packet/MTU and interoperability risks [file:66]. | Add protocol-level migration simulation and negotiated-path testing, not just algorithm replacement suggestions. |

---

## 3. Research Solutions Worth Reverse-Engineering

### 3.1 Cryptoscope: semantic cryptographic asset reconstruction

The IBM Research **Cryptoscope** paper is the strongest direct answer to primitive string-matching limitations. It uses cryptographic domain knowledge and compiler techniques to parse source code, analyze control flow and data flow, and construct a queryable inventory of complete cryptographic operations rather than disconnected API hits [web:69].

Its asset view can include the operation, API, key material, nonce, random source and related data. On the reported benchmark, it achieved approximately 92% exact asset recall, approximately 97% precision, and approximately 98% recall when partial matches were accepted; it detected 11 of 15 CamBench weaknesses [web:69].

**Reverse-engineer for ECDAT:**
- Construct an intermediate representation called `CryptoFlowIR`.
- Represent each operation as a semantic tuple:
  `operation → algorithm → mode/parameters → key source → nonce/IV source → randomness source → input data class → output sink`.
- Resolve aliases, wrappers and factory methods through call-graph and data-flow analysis.
- Assign a finding only after classifying whether the operation is a capability, reachable path, or exercised operation.
- Preserve unresolved calls with an explanation such as `unknown-wrapper` or `native-boundary`.

**Why it matters:** ECDAT can show *why* it believes a use is risky, not merely that a string such as `RSA` appeared in a file.

### 3.2 CRYLogger and CRYScanner: runtime observation plus offline rules

CRYLogger is an open-source dynamic analysis approach that logs parameters passed to cryptographic APIs and checks them offline against cryptographic rules [web:70]. CRYScanner combines an online logger with an offline checker based on CrySL/CogniCrypt-style domain rules [web:69].

**Reverse-engineer for ECDAT:**
- Keep runtime collection separate from interpretation.
- Runtime agent emits privacy-minimized events, never raw plaintext, keys or sensitive payloads.
- Offline analyzer evaluates algorithm, key size, mode, provider, protocol context and parameter constraints.
- Rule packs are versioned and independently testable.
- A runtime observation should carry process identity, library/provider, timestamp, deployment identity, trace ID, and a cryptographic hash of the event payload.

**Important limitation to solve:** Dynamic analysis observes only executed paths. ECDAT must therefore never treat “not observed” as “not present.” It should say: `not observed during coverage window`.

### 3.3 Runtime verification research: low-risk observability

Runtime-verification work studies dynamic API monitoring as an alternative to invasive testing instrumentation [web:77]. This supports a tiered ECDAT collection strategy rather than assuming every application can tolerate agents.

**Reverse-engineer for ECDAT:**
- Linux: eBPF uprobes for supported crypto-library entry points.
- Java: optional bytecode agent in staging/test environments.
- Windows: optional ETW/CNG telemetry where organizational policy permits.
- Network: passive TLS/SSH/IKE/QUIC metadata extraction from SPAN/TAP or host socket context.
- Application-specific adapters for OpenSSL, BoringSSL, Go TLS, Java JCA, .NET CNG, Python OpenSSL bindings and PKCS#11.

Each sensor reports its visibility class:
- `direct-observed`: exact algorithm/provider/path observed.
- `protocol-observed`: negotiated protocol and suite observed, implementation details partial.
- `library-observed`: library call observed, parameters incomplete.
- `opaque`: crypto likely present but unsupported/black-box.
- `unknown`: insufficient evidence.

### 3.4 Reachability analysis from SBOM/VEX research

Recent SBOM research found that function-call analysis can prune 61.9% of false vulnerability alarms caused by unreachable code [web:84]. It also shows that VEX is a communication format, not an analysis engine; a VEX assertion needs evidence behind it [web:84].

**Reverse-engineer for ECDAT:**
- Add a CBOM analogue of VEX called **Crypto Evidence Exchange (CEX)**.
- For each artifact, record `reachable`, `unreachable`, `conditionally-reachable`, `observed`, or `unknown`.
- Require a justification and evidence reference for every suppression.
- Do not suppress a finding solely because a dependency is “probably unused.”
- Apply an evidence floor: uncertainty can reduce confidence, but cannot erase high-consequence assets without proof.

Example:
```json
{
  "artifact": "RSA-2048 signing operation",
  "status": "conditionally-reachable",
  "reachabilityEvidence": {
    "entryPoint": "POST /legacy/sign",
    "callPathHash": "sha256:...",
    "condition": "feature_flag=legacy-signing"
  },
  "runtimeStatus": "not_observed",
  "suppression": null
}
```

### 3.5 Mosca and decision-theoretic migration research

Mosca's model states that an asset is temporally exposed when:

\[
X + Y > Z
\]

where `X` is required confidentiality or trust lifetime, `Y` is migration time, and `Z` is the anticipated time until a cryptographically relevant quantum computer [web:73][web:75]. Recent work emphasizes uncertainty, HNDL exposure windows and the cost of waiting rather than treating `Z` as a certain date [web:73][web:76].

**Reverse-engineer for ECDAT:**
- Replace one global date with a probability distribution for `Z`.
- Calculate `X` by data class, retention policy, legal hold, archival period, certificate validity, firmware-support horizon and signature-verification lifetime.
- Calculate `Y` from actual dependency and deployment graphs, testing queues, vendor lead time, hardware replacement time and change windows.
- Add attacker access probability: intercepted network data, database exfiltration likelihood, public signature exposure, or isolated internal data.
- Produce probability of temporal failure, not only High/Medium/Low.

A useful risk quantity is:

\[
P(\text{failure}) = P(X + Y > Z) \times E(\text{impact}) \times P(\text{attacker access})
\]

The expression is a proposed prioritization heuristic, not a universal scientific law. ECDAT should expose the assumptions and allow risk owners to replace them.

### 3.6 CycloneDX CBOM discussions: standard gaps as design opportunities

The fact-checked report identifies an active CycloneDX discussion concerning intended use, migration status and a framework-agnostic risk object for future CBOM/CDXA work [file:66]. This indicates that the standard inventory format is evolving and does not yet express all temporal-risk and evidence semantics required by ECDAT.

**Reverse-engineer for ECDAT:**
- Export standard CycloneDX CBOM for interoperability.
- Add a separate signed ECDAT Evidence Manifest rather than corrupting or prematurely extending the standard.
- Maintain a lossless internal model, with deterministic down-conversion to CycloneDX.
- Version every schema and provide migration tooling.

### 3.7 eBPF and kernel-level observability

Recent runtime-visibility implementations demonstrate eBPF probes and uprobes against common TLS libraries, while explicitly refusing to claim universal decryption or visibility [web:90][web:96]. This is the right model for ECDAT: low-overhead observation with an explicit visibility boundary.

**Reverse-engineer for ECDAT:**
- Probe function entry/exit, process identity, socket identity and provider metadata.
- Capture algorithm identifiers and parameter sizes where safe.
- Hash or redact key identifiers and never capture key bytes.
- Use ring buffers and sampling to control overhead.
- Include sensor health and dropped-event counts in every scan report.

---

## 4. Proposed ECDAT Architecture: Crypto Evidence and Decision Fabric

### 4.1 High-level architecture

```text
                 ┌──────────────────────────────────────────┐
                 │              ECDAT Control Plane          │
                 │  Projects · Policies · Tenants · RBAC     │
                 └────────────────────┬─────────────────────┘
                                      │
┌─────────────────────────────────────▼─────────────────────────────────────┐
│                         Collection Gateway                                 │
│ GitHub/GitLab · filesystems · binaries · containers · firmware · cloud      │
│ EDR/NDR · SPAN/TAP · eBPF · JVM/.NET test agents · PKCS#11/KMS connectors   │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │ signed observations
                 ┌────────────────────▼────────────────────┐
                 │       Evidence Normalization Layer       │
                 │ CryptoFlowIR · entity resolution ·       │
                 │ source mapping · deduplication            │
                 └────────────────────┬────────────────────┘
                                      │
        ┌─────────────────────────────▼─────────────────────────────┐
        │                    Evidence Graph                           │
        │ application → component → crypto operation → data →         │
        │ key/certificate → protocol → asset owner → business service │
        └───────────────┬─────────────────────────────┬─────────────┘
                        │                             │
          ┌─────────────▼─────────────┐   ┌───────────▼──────────────┐
          │ Risk & Decision Engine     │   │ Policy & Recommendation   │
          │ Mosca distributions       │   │ PQC/hybrid candidates     │
          │ HNDL exposure              │   │ latency/MTU/cost checks   │
          │ blast radius               │   │ migration dependency graph│
          └─────────────┬─────────────┘   └───────────┬──────────────┘
                        │                             │
                 ┌──────▼────────────────────────────▼──────┐
                 │ Verification and Remediation Control Loop │
                 │ PR · ticket · config change · approval    │
                 │ re-scan · runtime proof · signed closure  │
                 └────────────────────┬───────────────────────┘
                                      │
                 ┌────────────────────▼───────────────────────┐
                 │ UI, APIs, CycloneDX CBOM, CEX, audit export │
                 └────────────────────────────────────────────┘
```

### 4.2 Core internal entities

ECDAT should model more than `algorithm = RSA`. The minimum internal graph should contain:

- **Application/service:** repository, binary, container, firmware, deployment, owner, environment.
- **Crypto operation:** encrypt, decrypt, sign, verify, key generation, derivation, encapsulation or decapsulation.
- **Primitive:** algorithm, mode, padding, curve/parameter set, key size, provider and version.
- **Material:** key reference, certificate, trust anchor, nonce/IV, randomness source; never raw secret material.
- **Data flow:** source classification, destination, confidentiality lifetime, integrity value and exposure channel.
- **Protocol event:** TLS/SSH/IKE/QUIC version, offered suite, negotiated suite, fallback and peer metadata.
- **Evidence:** source span, binary offset, symbol, call path, runtime event, packet metadata, connector record, timestamp and sensor version.
- **Decision:** risk computation, assumptions, recommendation, approval, change and verification result.

### 4.3 Evidence confidence model

Do not use one unexplained confidence number. Use a vector:

```text
confidence = {
  detector_confidence,
  reachability_confidence,
  runtime_coverage,
  entity_resolution_confidence,
  data_classification_confidence,
  freshness,
  evidence_integrity
}
```

A final dashboard score may be derived from this vector, but analysts must be able to inspect every component.

### 4.4 Evidence levels

| Level | Meaning | Example |
|---|---|---|
| E0 | Unconfirmed hypothesis | String `RSA` found in documentation. |
| E1 | Static artifact | RSA API or linked symbol found in source/binary. |
| E2 | Reachable path | Call graph reaches the operation from a deployment entry point. |
| E3 | Configuration-confirmed | TLS or provider configuration enables the operation. |
| E4 | Runtime-observed | Operation or negotiation observed in a controlled or production window. |
| E5 | Correlated and independently verified | Static, configuration and runtime evidence agree; signed records available. |

The system must distinguish **absence of evidence** from **evidence of absence**.

---

## 5. Innovative Features That Could Exceed Existing Products

### 5.1 Crypto Twin: a digital twin of cryptographic behavior

Create a temporal “Crypto Twin” for every service. It stores:

- what the service could use;
- what configuration permits;
- what traffic negotiated;
- what operations executed;
- which data classes flowed through them;
- how each state changed over time.

The key view is not a static inventory table but a contradiction detector:

```text
Static:      TLS 1.3 + ML-KEM hybrid enabled
Configured:   TLS 1.2 fallback permitted at load balancer
Observed:     23% of connections negotiated classical TLS 1.2
Conclusion:   PQC capability exists, but production protection is not PQC-enforced
```

### 5.2 Unknowns ledger and coverage proof

Every scanner should output an **Unknowns Ledger**:

- unsupported binary format;
- stripped symbols;
- statically unreachable but dynamically untested code;
- vendor-managed SaaS boundary;
- encrypted or inaccessible container layer;
- unsupported hardware security module;
- dropped runtime events;
- network segments not observed.

For each unknown, ECDAT should provide a next-best collection action and expected uncertainty reduction. This turns incompleteness into a managed work queue instead of hiding it.

### 5.3 Cryptographic evidence notarization

For each scan and runtime batch:

1. Canonicalize the observation.
2. Hash the canonical representation.
3. Sign it using an organization-controlled signing key.
4. Chain it to the previous observation batch.
5. Store the manifest in an append-only object store or transparency log.
6. Export a verifier CLI that works offline.

Use a hybrid signature during transition if desired: classical Ed25519/ECDSA for current compatibility plus ML-DSA for long-term evidence integrity. ECDAT should never claim that signing the CBOM protects the underlying enterprise secrets; the purpose is audit provenance and tamper evidence.

### 5.4 Active coverage planner

Dynamic scans fail when they exercise only happy paths. Build an **Active Crypto Coverage Planner** that identifies unobserved cryptographic paths and proposes safe test stimuli:

- invoke rarely used API routes in a staging environment;
- exercise certificate renewal and revocation workflows;
- test disaster-recovery and backup restore paths;
- trigger feature flags in an isolated clone;
- perform TLS negotiation probes against each supported client profile;
- inspect scheduled jobs and batch pipelines.

The planner should prioritize paths by temporal risk and business impact, not coverage percentage alone.

### 5.5 Negative proof instead of simplistic absence

A high-value result is not “no RSA found.” It is:

```text
No reachable RSA signing operation found in:
- source commit abc123;
- binary hash sha256:...;
- container digest sha256:...;
- 14 declared production entry points;
- 4.2 million observed requests;
- 3 certificate-renewal workflows.
Unknown: vendor HSM operation outside telemetry boundary.
```

This is much more defensible for an auditor and more useful to an engineering team.

### 5.6 Data-lifetime inference with human confirmation

ECDAT can infer data classes using labels, database schema, API routes, retention policies, classification tags, legal holds and repository metadata. It must not silently decide that a field is “secret for 30 years.” Instead:

- infer a range and explain the sources;
- ask the asset owner to confirm or correct it;
- record the decision as signed governance evidence;
- propagate the classification along the data-flow graph.

### 5.7 Migration digital simulation

Before recommending an algorithm, simulate:

- handshake and certificate size;
- packet fragmentation and MTU;
- CPU and memory cost;
- latency percentile impact;
- library/provider compatibility;
- hardware support;
- certificate-chain size;
- fallback behavior;
- rollback path;
- operational change windows.

The result should be an experiment report, not a generic “use ML-KEM/ML-DSA” recommendation.

### 5.8 Constraint-aware hybrid recommendation engine

Represent migration as an optimization problem:

```text
minimize  risk + migration_cost + latency_penalty + interoperability_penalty
subject to:
  required_security_level satisfied
  data lifetime protected
  provider/library supported
  packet and certificate limits satisfied
  hardware and compliance constraints satisfied
  rollback available
```

Candidate outputs may include classical, PQC, hybrid or compensating-control options. The engine must show rejected candidates and the reason for rejection.

### 5.9 Remediation proof objects

A remediation is not closed when a ticket becomes “Done.” Close it only when:

- source/configuration change is linked to a commit;
- binary/container digest changed as expected;
- deployment inventory confirms rollout;
- runtime/network observation confirms the intended algorithm;
- no prohibited fallback was observed during the validation window;
- the result is signed and added to the evidence chain.

This turns ECDAT from a report generator into a verification system.

### 5.10 Federated discovery for privacy-sensitive enterprises

Many organizations cannot upload source code, telemetry or certificates to a vendor cloud. Design ECDAT with:

- local scanning agents;
- local evidence stores;
- metadata-only federation;
- zero-knowledge-style aggregate reporting where practical;
- customer-controlled keys;
- offline verifier and export.

Only normalized metadata and evidence references need to leave the protected environment.

---

## 6. Proposed ECDAT Risk Engine

### 6.1 Asset-level temporal model

For each crypto operation `a`, calculate:

- `X(a)`: confidentiality or trust lifetime.
- `Y(a)`: realistic migration duration.
- `Z`: CRQC arrival distribution, not a single date.
- `A(a)`: probability that an attacker can obtain ciphertext, signatures or protocol transcripts.
- `I(a)`: business impact if confidentiality or authenticity fails.
- `C(a)`: confidence in the evidence.
- `F(a)`: fallback and downgrade exposure.

Define a transparent prioritization score:

\[
R(a) = P(X(a) + Y(a) > Z) \times A(a) \times I(a) \times F(a) \times C_{min}(a)
\]

`C_min` should not increase risk merely because a scanner is uncertain. Instead, uncertainty should produce a separate **investigation priority**:

\[
U(a) = (1 - C_{min}(a)) \times I(a) \times P(X(a)+Y(a)>Z)
\]

This prevents uncertainty from being ignored while avoiding the dangerous practice of turning a weak signal into a confirmed vulnerability.

### 6.2 Example

Assume a healthcare record has a 25-year confidentiality requirement, migration is estimated at 6–10 years, and the organization uses a conservative CRQC arrival distribution centered around 2035. A high-impact RSA encryption path has `X + Y = 31–35 years`, so the temporal condition is likely true. ECDAT should prioritize discovery of where the records travel, whether ciphertext is externally exposed, the current certificate/key lifecycle and the feasibility of hybrid replacement — not simply label every RSA reference as critical. Mosca’s rule and its interpretation are supported by recent research [web:73][web:75].

### 6.3 Risk categories

| Category | Question answered |
|---|---|
| Quantum confidentiality | Can harvested ciphertext become readable within its required lifetime? |
| Quantum authenticity | Can signatures or identity proofs become forgeable before trust expires? |
| Operational | Can the migration cause outages, MTU failures or performance regressions? |
| Supply-chain | Is the algorithm embedded in an upstream library, image, firmware or vendor appliance? |
| Evidence | How much of the conclusion is observed versus inferred? |
| Governance | Is an owner, deadline, exception and verification plan recorded? |

---

## 7. Recommended ECDAT Module Design

### Module A — Ingestion and connectors

- GitHub/GitLab/Bitbucket repositories.
- Local directories, binaries and firmware images.
- Docker/OCI images and package registries.
- Kubernetes manifests and service mesh configuration.
- TLS/SSH/IKE/QUIC endpoint probes.
- SPAN/TAP network metadata.
- Linux eBPF host sensor.
- Optional Java/.NET test instrumentation.
- Cloud KMS, certificate managers and HSM metadata.
- Manual/vendor questionnaire for opaque systems.

### Module B — Static semantic analyzer

- Tree-sitter or compiler front ends for source parsing.
- LLVM/Capstone/Ghidra-style binary analysis adapters.
- Symbol and string recovery.
- Call graph, data-flow and taint propagation.
- CryptoFlowIR extraction.
- Library/provider/version identification.
- Reachability and parameter resolution.

### Module C — Runtime and protocol observers

- eBPF uprobes for supported Linux crypto libraries.
- JVM/.NET agents for controlled environments.
- Passive protocol metadata analyzer.
- Active handshake compatibility tester.
- Sensor-health and coverage accounting.

### Module D — Evidence graph and temporal store

- Graph database for relationships.
- Relational store for normalized assets and decisions.
- Object store for raw signed manifests.
- Append-only event log for history.
- Search index for investigations.

### Module E — Risk and recommendation engine

- Mosca/HNDL temporal model.
- Business-impact and data-lifetime model.
- Protocol/MTU/performance simulator.
- PQC/hybrid candidate catalog.
- Dependency-aware migration planner.
- Confidence and unknowns analysis.

### Module F — Remediation and verification

- GitHub/GitLab pull requests.
- Jira/ServiceNow tickets.
- Kubernetes/TLS configuration proposals.
- Certificate and key lifecycle integrations.
- Pre-change simulation.
- Post-change runtime verification.
- Signed remediation proof.

### Module G — GUI and reporting

Primary screens:

1. Executive PQC readiness and temporal exposure.
2. Cryptographic asset graph.
3. Static-versus-observed reconciliation.
4. Unknowns ledger and coverage map.
5. Migration roadmap and dependency bottlenecks.
6. Protocol performance and MTU simulation.
7. Evidence-chain verifier.
8. Remediation queue and proof-of-closure.

---

## 8. Minimum Viable Product and Innovation Roadmap

### Phase 1 — defensible MVP

- GitHub repository scanner for Python, JavaScript/TypeScript, Go and C.
- Container and filesystem scanner.
- CycloneDX CBOM export.
- CryptoFlowIR for a focused set of operations.
- Reachability-aware findings.
- Per-asset Mosca calculation with editable X/Y/Z.
- Interactive graph and risk dashboard.
- Signed scan manifest.
- Published detector test corpus and precision/recall results.

### Phase 2 — evidence superiority

- eBPF observer for OpenSSL, BoringSSL, Go TLS and common socket paths.
- TLS/SSH active negotiation tester.
- Static/runtime reconciliation and drift detection.
- Unknowns ledger.
- CEX evidence format.
- Historical diff and audit replay.

### Phase 3 — enterprise actionability

- GitHub PR and Jira/ServiceNow integration.
- Data classification connectors.
- Cloud KMS/HSM/certificate inventory.
- Migration dependency graph.
- Protocol and performance simulation.
- Post-remediation proof objects.

### Phase 4 — research-grade differentiation

- Active coverage planner.
- Federated/privacy-preserving inventory.
- Signed transparency log.
- Hardware/firmware cryptographic extraction.
- ML-assisted wrapper and alias discovery with deterministic evidence requirements.
- Multi-objective migration optimization.

---

## 9. Evaluation Plan: How ECDAT Must Prove Its Claims

ECDAT should avoid the same evidentiary weakness found in the market: unsupported completeness claims. Create a public, versioned benchmark suite containing:

- direct API calls;
- aliases and wrapper functions;
- reflection/dynamic dispatch;
- dead code;
- reachable but rarely exercised paths;
- native-library boundaries;
- stripped binaries;
- container layers;
- TLS configuration and fallback cases;
- certificates and key references;
- hybrid/PQC algorithms;
- intentional false positives.

Measure separately:

| Metric | Definition |
|---|---|
| Exact asset recall | Complete operation and related material correctly recovered. |
| Partial asset recall | Operation identified but one or more related elements missing. |
| Precision | Reported findings that are valid in context. |
| Reachability accuracy | Correct reachable/unreachable/conditional classification. |
| Runtime coverage | Executed paths and protocol sessions represented. |
| Drift detection latency | Real change to verified alert, end to end. |
| Evidence completeness | Findings with reproducible source/runtime evidence. |
| Remediation closure rate | Findings verified closed after approved changes. |
| Sensor overhead | CPU, memory, latency and event-loss impact. |

Cryptoscope demonstrates the value of semantic analysis through its reported 92% exact asset recall and 97% precision, while SBOM reachability research demonstrates why function-level context can significantly reduce false alarms [web:69][web:84]. ECDAT should reproduce such evaluations on its own corpus rather than copy their numbers as a product claim.

---

## 10. What ECDAT Should Not Claim

Avoid these statements:

- “ECDAT discovers every cryptographic asset.”
- “No other tool performs dynamic discovery.”
- “Our risk score predicts the exact date of Q-Day.”
- “A static absence proves that an algorithm is not used.”
- “PQC migration is complete when the code scanner is clean.”
- “AI guarantees accurate cryptographic classification.”

Use defensible alternatives:

- “ECDAT reports observed coverage, inferred coverage and known unknowns.”
- “ECDAT reconciles static, configuration, runtime and protocol evidence.”
- “ECDAT evaluates temporal exposure under explicit CRQC assumptions.”
- “ECDAT provides evidence-backed recommendations with verification status.”
- “ECDAT publishes detector-level evaluation results and limitations.”

---

## 11. Final Design Thesis

The next generation of cryptographic discovery should not be a larger list of algorithms. It should be an **evidence system for cryptographic decisions**.

The winning ECDAT architecture is therefore:

> **semantic static analysis + low-overhead runtime observation + protocol telemetry + temporal risk modeling + explicit unknowns + signed evidence + verified remediation**.

Existing research has already shown that semantic data/control-flow analysis can outperform simple pattern matching [web:69], dynamic logging can reveal actual API parameters [web:70], runtime verification can complement static analysis [web:77], reachability can substantially reduce noise [web:84], and Mosca’s inequality provides a temporal basis for prioritization [web:73][web:75]. ECDAT’s innovation is to combine these into one auditable lifecycle rather than shipping another disconnected scanner.

The strongest differentiator is not a proprietary algorithm. It is the ability to answer, for every high-risk asset:

```text
Here is what we found.
Here is the evidence and its age.
Here is what we could not observe.
Here is why the data is at risk in time.
Here is the least-disruptive migration option.
Here is the exact change made.
Here is proof that production now behaves as intended.
```

That is the gap between a CBOM report and an enterprise cryptographic control system.

---

## Sources

- IBM Research, “Cryptoscope: Analyzing cryptographic usages in modern software,” arXiv:2503.19531 [web:69].
- CRYLOGGER, “Detecting Crypto Misuses Dynamically” [web:70].
- CRYScanner, “Finding cryptographic libraries misuse” [web:68].
- Runtime Verification of Crypto APIs: An Empirical Study [web:77].
- “A Reality Check on SBOM-based Vulnerability Management,” arXiv:2511.20313 [web:84].
- “The cost of waiting: a decision-theoretic synthesis of early versus late post-quantum migration” [web:73].
- “Towards a Unified Quantum Risk Assessment” [web:75].
- Attached fact-checked ECDAT market report [file:66].
- CycloneDX CBOM standard and evolution materials [web:51].
