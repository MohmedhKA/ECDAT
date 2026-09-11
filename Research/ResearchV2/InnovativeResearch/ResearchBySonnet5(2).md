# ECDAT 2.0: Research-Based and Novel Architecture
## Designing an Enterprise Cryptographic Discovery, Quantum-Risk, and Migration Intelligence Platform

**Prepared for:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
**Purpose:** Convert the fact-checked market gaps into an implementable, research-grounded, and differentiated system design.

---

## 1. Direct Answer

The strongest route for ECDAT is not to build another static scanner or another CBOM dashboard. The innovation should be an **evidence-fusing cryptographic digital twin**: a system that combines static code and binary analysis, runtime observations, network handshakes, certificate/key inventories, cloud/KMS metadata, and human-provided business context into one versioned graph.

The system should report not only that an algorithm exists, but also:

- whether the algorithm is actually reachable and executed;
- which data, identities, protocols, and business services depend on it;
- how much evidence supports that conclusion;
- how long the protected data must remain confidential;
- how long migration is likely to take;
- what failure or compatibility risks a proposed PQC/hybrid replacement creates;
- and whether a generated recommendation was actually implemented and verified.

This design directly addresses the confirmed weaknesses in the fact-checked report: static/dynamic separation, false positives, incomplete coverage, shallow Mosca scoring, missing evidence integrity, alert fatigue, and the remediation gap [file:66].

---

## 2. Research Findings to Reverse Engineer

### 2.1 Cryptoscope: semantic cryptographic views

IBM Research's Cryptoscope is the most useful source-analysis design to borrow. It moves beyond disconnected API matches and constructs a view of the complete cryptographic operation, including the operation, API, keys, nonces, random sources, and related data. The paper reports 92% exact-match recall and 97% precision on its evaluated corpus, with 98% recall when partial matches are included [web:100].

**Reverse-engineer for ECDAT:**

- Build an intermediate representation of cryptographic operations rather than storing isolated findings.
- Represent each operation as a structured tuple:
  `operation → implementation → parameters → key source → nonce/IV → random source → data-flow origin → data-flow destination`.
- Run data-flow and control-flow slicing around crypto sinks and sources.
- Preserve exact source locations and the path used to infer each relationship.
- Use confidence levels for exact, partial, inferred, and unobserved relationships.

**Why this matters:** A finding such as `RSA-2048 detected in OpenSSL` is weak. A finding such as `customer-record export → RSA-OAEP key wrapping → OpenSSL 3.0.8 → key loaded from Vault path X → consumed by service Y` is actionable.

### 2.2 CRYLOGGER and CRYScanner: runtime evidence

CRYLOGGER demonstrates a practical dynamic approach: instrument cryptographic API calls, log parameters during execution, and check them offline against rules. It was evaluated on 1,780 Android applications and detected crypto misuses dynamically [web:98][web:101]. CRYScanner extends the idea toward cryptographic library misuse and demonstrates the value of dynamic analysis alongside static analysis [web:68].

**Reverse-engineer for ECDAT:**

- Instrument Java/JVM, OpenSSL, BoringSSL, LibreSSL, Windows CNG, .NET cryptography, and common Python/Go crypto boundaries where feasible.
- Capture metadata only, never plaintext or secret key material by default.
- Record algorithm, mode, key size, provider/library, caller identity, endpoint, timestamp, and environment.
- Generate a signed runtime trace that can be correlated with static findings.
- Mark a static finding as `observed`, `not_observed`, or `uncovered_by_test` rather than treating absence from logs as proof of absence.

**Critical design rule:** Dynamic observation confirms exercised paths, but it cannot prove that unexecuted disaster-recovery, yearly batch, or dormant feature paths are safe. ECDAT must preserve both static potential and dynamic confirmation.

### 2.3 Hybrid analysis: CIPHERH and HardTaint

CIPHERH uses a productive hybrid pattern: fast dynamic taint analysis identifies relevant functions, then static symbolic execution analyzes paths inside those functions. This avoids the cost of whole-program symbolic execution while covering paths that were not executed in the observed trace [web:106][web:107]. HardTaint combines static analysis, selective hardware tracing, and parallel graph processing, reporting approximately 9% runtime overhead in its evaluation [web:109].

**Reverse-engineer for ECDAT:**

1. Use cheap static scanning to find candidate crypto operations.
2. Use low-overhead runtime telemetry to identify which candidates execute in real deployments or tests.
3. Apply expensive symbolic/path analysis only to high-risk or ambiguous candidates.
4. Prioritize paths that carry sensitive data or terminate public-facing protocols.
5. Use selective instrumentation rather than instrumenting every function.

This creates a three-tier cost model:

| Tier | Analysis | Use |
|---|---|---|
| Tier 1 | Regex, AST, bytecode, package metadata | Fast broad inventory |
| Tier 2 | Call graph, reachability, data-flow slicing | Remove false positives and identify actual dependencies |
| Tier 3 | Runtime instrumentation, tainting, symbolic analysis | Confirm high-risk operations and discover hidden paths |

### 2.4 Reachability analysis from modern SBOM/VEX research

Recent SBOM research shows that component-level vulnerability results can be inconsistent when code-level reachability and cloned component variants are ignored [web:85]. Another study argues that VEX is only a communication format, not an analysis engine; useful results require function-call reachability analysis before generating a VEX statement [web:84][web:114].

**Reverse-engineer for ECDAT:**

- Treat CBOM as a component inventory plus a reachability graph.
- Distinguish `contains`, `provides`, `imports`, `calls`, `executes`, `negotiates`, and `protects` relationships.
- Generate a cryptographic equivalent of VEX:
  - `crypto_present_but_unreachable`;
  - `crypto_reachable_but_not_observed`;
  - `crypto_observed_in_production`;
  - `crypto_observed_only_in_test`;
  - `crypto_configuration_unknown`.
- Attach a machine-readable justification and evidence path to every status.

### 2.5 SLSA and in-toto: evidence integrity

SLSA provenance and in-toto attestations provide a reusable model for recording how an artifact was produced, which inputs were used, and which builder executed the process [web:108][web:110]. ECDAT should use the same model for scan evidence.

**Reverse-engineer for ECDAT:**

Every scan should produce:

- the subject digest: repository commit, binary hash, image digest, or host snapshot;
- scanner version and detector-pack version;
- configuration and policy inputs;
- timestamp and environment identity;
- source materials and toolchain metadata;
- signed CBOM and signed evidence manifest;
- optional transparency-log entry;
- parent scan ID for a tamper-evident history.

The resulting evidence should be independently verifiable without trusting the ECDAT server. This solves a major market gap: a CBOM must itself be a cryptographic artifact.

### 2.6 Mosca's theorem and newer decision models

Mosca's inequality is conventionally expressed as:

\[
X + Y > Z
\]

where `X` is the data confidentiality or sensitivity lifetime, `Y` is the migration time, and `Z` is the time until a cryptographically relevant quantum computer is available [web:99][web:73][web:75]. A binary label is inadequate for enterprise decisions because all three values are uncertain and vary by asset.

**Reverse-engineer and improve:**

ECDAT should calculate a probability distribution rather than a single score:

\[
P(\text{deadline failure}) = P(X + Y > Z)
\]

For each asset, represent:

- `X`: distribution based on data class, retention policy, legal hold, archival period, and business owner input;
- `Y`: distribution based on dependency count, protocol compatibility, test effort, procurement lead time, certificate replacement effort, and release cadence;
- `Z`: configurable scenario distribution, not a claimed prediction.

Then calculate:

- probability that migration finishes too late;
- expected loss of confidentiality;
- time-to-safe-state;
- migration critical path;
- sensitivity to reducing `Y` by a specific engineering action.

Example:

| Variable | Estimate |
|---|---:|
| Data confidentiality lifetime `X` | 12–20 years |
| Migration time `Y` | 3–7 years |
| CRQC scenario `Z` | 8–15 years |
| Result | High probability of deadline failure |

The dashboard should explain *why* the result is high and which action reduces risk fastest. It should never present an uncertain quantum forecast as a precise fact.

---

## 3. Proposed ECDAT Architecture

### 3.1 Architectural principle: evidence fusion, not scanner aggregation

The central object should be an **Evidence-Centered Cryptographic Graph (ECCG)**. Every node and edge must carry provenance, confidence, timestamp, and applicability conditions.

#### Core graph nodes

- Application, service, API, repository, binary, container image.
- Algorithm, mode, key size, protocol, provider, library, hardware module.
- Key, certificate, trust anchor, KMS object, HSM slot, secret reference.
- Dataset, data class, business process, regulatory requirement.
- Environment, host, cluster, cloud account, region, network endpoint.
- Migration candidate, compatibility constraint, remediation action.

#### Core graph edges

- `contains` — binary contains library.
- `provides` — library provides cryptographic capability.
- `imports` — source imports API/provider.
- `calls` — function invokes cryptographic operation.
- `executes` — operation observed at runtime.
- `negotiates` — protocol selects algorithm/mode.
- `protects` — operation protects data or authenticates an identity.
- `depends_on` — service depends on key, certificate, provider, or protocol.
- `migrates_to` — current artifact has a proposed replacement.
- `evidenced_by` — assertion is supported by a scan, trace, configuration, or manual attestation.

### 3.2 Processing pipeline

```text
[Connectors and Sensors]
        |
        v
[Evidence Normalization Layer]
        |
        v
[Static + Binary + Container + Network + Runtime Detectors]
        |
        v
[Crypto Intermediate Representation]
        |
        v
[Reachability and Data-Flow Engine]
        |
        v
[Evidence-Centered Cryptographic Graph]
        |
        +--> [CBOM / VEX-like Status / Signed Attestations]
        |
        +--> [Probabilistic Mosca Risk Engine]
        |
        +--> [Migration Compatibility Simulator]
        |
        +--> [Remediation Planner and PR/Ticket Generator]
        |
        v
[GUI, APIs, CI/CD Gates, Audit Reports]
```

### 3.3 Connector strategy

ECDAT should avoid requiring a new heavyweight agent everywhere. Use a connector hierarchy:

1. **Repository connectors:** GitHub, GitLab, Bitbucket, local Git, package manifests, lockfiles.
2. **Build connectors:** Docker/OCI registries, CI logs, compiler/linker metadata, SBOM generators.
3. **Runtime connectors:** OpenTelemetry, eBPF, JVM agents, service mesh telemetry, API gateway logs.
4. **Network connectors:** TLS handshake metadata, passive SPAN/TAP, NDR/EDR feeds.
5. **Identity and key connectors:** Vault, cloud KMS, HSM, certificate authorities, Kubernetes secrets metadata.
6. **Manual evidence connectors:** vendor questionnaires, appliance declarations, asset-owner attestations, procurement records.

The tool should make incomplete coverage explicit. A vendor-opaque appliance should appear as `crypto_visibility_unknown`, not disappear from the inventory.

---

## 4. Innovative Features Beyond Existing Tools

### 4.1 Cryptographic digital twin

Maintain a continuously updated model of cryptographic dependencies. A single scan is a snapshot; the digital twin is a time series.

For every asset, show:

- first seen and last seen;
- current and historical algorithms;
- configuration changes;
- certificate/key rotation history;
- runtime observation frequency;
- environment drift;
- migration status;
- confidence trend.

This solves the static-CBOM problem by making change itself a first-class object.

### 4.2 Evidence lattice and confidence decay

Use multiple evidence classes:

| Evidence | Strength | Example |
|---|---:|---|
| Signed runtime trace | Very high | TLS endpoint negotiated ML-KEM hybrid in production |
| Signed deployment configuration | High | Service mesh policy selects TLS 1.3 and approved groups |
| Reachable data-flow path | High | Customer data reaches RSA encryption call |
| Binary symbol/disassembly match | Medium | OpenSSL RSA symbol exists in executable |
| Source import/API match | Medium-low | Source imports a crypto provider |
| Package capability only | Low | Dependency can provide RSA but call path unknown |
| Manual declaration | Variable | Vendor states appliance uses RSA-2048 |

Confidence should decay with age and environmental change. A runtime observation from yesterday in the same image digest is stronger than a runtime observation from six months ago in a retired image.

### 4.3 Cryptographic VEX

Create a proposed ECDAT extension called **CryptoVEX**. Its purpose is to explain whether a cryptographic artifact is relevant in a particular deployment.

Example:

```json
{
  "bom-ref": "crypto:rsa-2048:service-a",
  "status": "reachable_but_not_observed",
  "justification": "static_call_path_without_runtime_coverage",
  "evidence": [
    "scan:sha256:...",
    "callpath:service-a->encryptUserExport->RSA/ECB/OAEP"
  ],
  "affected_data": ["customer-export"],
  "confidence": 0.78,
  "recommended_action": "add_test_case_or_runtime_trace"
}
```

This prevents teams from treating every CBOM entry as equally urgent.

### 4.4 Active coverage planner

Instead of merely reporting uncovered paths, ECDAT should generate the smallest test or observation plan that maximizes cryptographic coverage.

The planner can recommend:

- run a specific API test;
- exercise a backup/restore workflow;
- execute an annual batch job in staging;
- replay a TLS client profile;
- inspect a particular container layer;
- request an attestation from a vendor.

This converts "we do not know" into a concrete evidence-acquisition task.

### 4.5 Migration digital rehearsal

Before recommending ML-KEM, ML-DSA, SLH-DSA, or a hybrid scheme, simulate operational consequences:

- handshake size and MTU fragmentation;
- certificate-chain expansion;
- CPU and memory impact;
- latency and throughput;
- maximum header or record limits;
- HSM/provider availability;
- client/server interoperability;
- rollback path;
- certificate and key rotation workload.

The output should be a migration candidate matrix, not a single universal recommendation.

| Current use | Candidate | Expected advantage | Main risk | Required test |
|---|---|---|---|---|
| RSA key exchange | ML-KEM hybrid | Quantum-resistant confidentiality | Larger handshake | TLS interoperability and MTU test |
| ECDSA authentication | ML-DSA hybrid | Quantum-resistant signatures | Larger certificate/signature | Chain-size and client compatibility test |
| Long-lived signed archive | ML-DSA or SLH-DSA | Long-term authenticity | Verification/storage overhead | Archive validation and toolchain test |
| Hash-only integrity | SHA-384/SHA-512 plus PQ signature where needed | Strong classical baseline | Misclassification of authenticity need | Data-integrity threat review |

### 4.6 Migration portfolio optimizer

Treat migration as an optimization problem. Each candidate action has:

- risk reduction;
- engineering effort;
- operational cost;
- compatibility risk;
- procurement dependency;
- expected completion time;
- affected business services.

Use a Pareto frontier to display actions that provide the best risk reduction for effort. This is more useful than sorting assets by severity.

Example actions:

- upgrade a shared crypto provider used by 80 services;
- migrate one certificate authority;
- add hybrid TLS to an API gateway;
- replace a single HSM firmware version;
- remove an unreachable legacy dependency;
- classify a data store's retention policy.

### 4.7 Privacy-preserving telemetry

Runtime discovery must not become a data-exfiltration system. ECDAT should support:

- local feature extraction;
- hashed service and endpoint identifiers;
- no plaintext capture by default;
- no key material capture;
- configurable redaction;
- differential aggregation for fleet statistics;
- remote attestation of sensor version;
- retention and deletion policies.

### 4.8 Federated enterprise discovery

Large organizations may not permit raw source code, traces, or configuration to leave business units. Use a federated architecture:

- scanners run locally;
- only normalized CBOM nodes, signed evidence digests, and approved metadata leave the environment;
- sensitive evidence remains in the originating domain;
- the central graph stores references and verification proofs.

This is especially relevant to defense, healthcare, and critical infrastructure environments.

---

## 5. Risk Engine Design

### 5.1 Asset-level risk, not algorithm-level risk

RSA-2048 should not automatically receive the same priority everywhere. Risk must be calculated for the specific use:

\[
R_i = f(Q_i, X_i, Y_i, Z, E_i, B_i, C_i, D_i)
\]

Where:

- `Q_i`: quantum vulnerability of the primitive and use;
- `X_i`: confidentiality/authenticity lifetime;
- `Y_i`: migration duration distribution;
- `Z`: configurable CRQC scenario distribution;
- `E_i`: exposure and harvestability;
- `B_i`: business criticality and blast radius;
- `C_i`: confidence and evidence quality;
- `D_i`: data sensitivity and regulatory impact.

### 5.2 HNDL-aware exposure

Two assets with the same algorithm may have different HNDL risk:

- public TLS traffic is highly harvestable;
- an internal isolated machine may have lower interception probability;
- a public certificate's private-key compromise threatens future impersonation;
- a database encrypted with a long-lived key may be harvested as ciphertext now and decrypted later.

Therefore, ECDAT should separately score:

- confidentiality loss;
- authentication/impersonation loss;
- integrity loss;
- harvestability;
- future exploitability;
- migration urgency.

### 5.3 Uncertainty-aware outputs

Never hide uncertainty behind a single number. Display:

- risk range;
- confidence range;
- evidence coverage;
- assumptions;
- most influential variable;
- recommended information-gathering action.

Example:

```text
Risk: 0.82–0.94, High
Confidence: 0.71
Primary driver: 15-year data lifetime
Most valuable missing evidence: production TLS negotiation trace
Best first action: enable hybrid TLS at the API gateway and test 12 dependent clients
```

---

## 6. Proposed Implementation Roadmap

### Phase 1: defensible MVP

- Repository scanner for Java, Python, C/C++, Go, JavaScript/Node.js.
- AST and dependency analysis.
- Binary and container extraction.
- CycloneDX CBOM export.
- Evidence manifest and signed scan result.
- Basic ECCG graph storage.
- Asset-level Mosca calculator with explicit assumptions.
- Streamlit or React dashboard.

### Phase 2: research differentiation

- Cryptoscope-inspired operation views.
- Call-graph and reachability analysis.
- CryptoVEX statuses.
- Runtime metadata collection for JVM and OpenSSL.
- Static/runtime reconciliation.
- Confidence scoring and evidence decay.
- GitHub Actions and pull-request comments.

### Phase 3: enterprise-grade innovation

- eBPF-based selective observation for Linux.
- TLS/network handshake analyzer.
- Cloud KMS/HSM/PKI connectors.
- Federated scanning and evidence references.
- Migration rehearsal and performance benchmark harness.
- Jira/ServiceNow remediation loop.
- Transparency log and independent verification CLI.

### Phase 4: advanced research contribution

- Probabilistic Mosca model with Monte Carlo simulation.
- Active coverage planner.
- Migration portfolio optimizer.
- Privacy-preserving cross-enterprise statistics.
- Open CryptoVEX proposal and interoperable reference implementation.
- Benchmark dataset with manually verified ground truth.

---

## 7. Evaluation Plan

ECDAT should publish evidence instead of making unsupported "complete coverage" claims.

### 7.1 Detection metrics

- exact precision and recall;
- partial-match recall;
- operation-level recall;
- key/nonce/random-source relationship accuracy;
- runtime/static reconciliation accuracy;
- false-positive rate by detector;
- unknown-coverage percentage.

Cryptoscope demonstrates why both exact and partial matching should be reported rather than one opaque accuracy figure [web:100].

### 7.2 Operational metrics

- scan time per million lines of code;
- memory use;
- runtime overhead by sensor;
- end-to-end change-detection latency;
- graph query latency;
- percentage of findings with reproducible evidence;
- remediation completion rate;
- percentage of generated recommendations validated by a test.

### 7.3 Benchmark corpus

Create a public or internal corpus containing:

- direct API calls;
- wrapper functions;
- reflection and dynamic dispatch;
- native library calls;
- statically linked libraries;
- dead code;
- unreachable vulnerable functions;
- TLS configuration files;
- container layers;
- generated code;
- hybrid and PQC algorithms;
- intentionally misleading package names;
- test-only and production-only paths.

Every item must have human-reviewed ground truth. This directly avoids the credibility problem identified in the fact-checked market report, where vendor-linked benchmark claims should not be treated as neutral [file:66].

### 7.4 Red-team evaluation

Invite independent teams to attempt to defeat ECDAT by:

- hiding crypto behind wrappers;
- loading providers dynamically;
- using reflection;
- embedding encrypted configuration;
- splitting the crypto operation across microservices;
- using custom hardware or vendor SDKs;
- changing algorithms at runtime;
- sending traffic through a service mesh or proxy;
- creating false-positive capability-only dependencies.

Publish missed cases and fixes. Transparent failure reporting is itself a competitive advantage.

---

## 8. What ECDAT Must Not Claim

Avoid these claims unless the evaluation genuinely supports them:

- "Complete cryptographic inventory." Use "measured coverage with explicit unknowns."
- "Real-time discovery." Publish end-to-end detection latency under a named test setup.
- "Quantum-safe recommendation." State the assumptions, standards, provider support, and interoperability tests.
- "Accurate risk score." Publish confidence, uncertainty, and sensitivity analysis.
- "Automatic remediation." Distinguish recommendation, generated patch, validated patch, and deployed patch.
- "Detects all runtime cryptography." Runtime observation only covers exercised or instrumented paths.

The strongest ECDAT report is one that clearly states what it knows, how it knows it, and what remains unknown.

---

## 9. Final Differentiation Statement

ECDAT should be positioned as:

> **An evidence-centered cryptographic digital twin that continuously reconciles code potential, reachable use, runtime behavior, network negotiation, key infrastructure, and business data lifetime — then computes uncertainty-aware quantum migration risk and verifies the remediation outcome.**

This is materially different from a scanner plus dashboard. It combines:

1. Cryptoscope-style semantic operation reconstruction [web:100].
2. CRYLOGGER-style runtime observation [web:98][web:101].
3. CIPHERH-style selective hybrid analysis [web:106][web:107].
4. Reachability-aware CBOM/VEX reasoning [web:84][web:114].
5. SLSA/in-toto-style cryptographic evidence provenance [web:108][web:110].
6. Probabilistic, asset-level Mosca risk rather than a generic severity label [web:99][web:73].
7. A verified migration and remediation loop.

The innovative contribution is not claiming that each individual technique is new. The contribution is integrating them into a **single, privacy-preserving, continuously updated, independently verifiable system** and publishing the evidence needed to trust its conclusions.

---

## 10. Recommended Research Publications for the Design Team

| Research or standard | Reusable design idea |
|---|---|
| Cryptoscope, arXiv:2503.19531 | Cryptographic operation views, data/control-flow slicing, asset relationships [web:100] |
| CRYLOGGER | Dynamic API logging and offline misuse/rule analysis [web:98][web:101] |
| CRYScanner, IACR ePrint 2022/029 | Dynamic discovery and cryptographic-library misuse analysis [web:68] |
| CIPHERH, USENIX Security 2023 | Dynamic taint plus selective static symbolic analysis [web:106][web:107] |
| HardTaint, arXiv:2402.17241 | Lower-overhead production dynamic analysis using selective tracing [web:109] |
| SBOM reachability research | Function-level reachability to reduce false positives and improve VEX decisions [web:84][web:114] |
| SLSA and in-toto | Signed, verifiable provenance for scan evidence and build artifacts [web:108][web:110] |
| CycloneDX CBOM discussions | Future direction for intended-use, migration status, and risk objects [file:66] |
| Mosca risk literature | Time-based quantum migration urgency and shelf-life modeling [web:99][web:73][web:75] |

---

## Conclusion

The practical winning design is a **hybrid evidence platform**, not a larger pattern-matching database. Static analysis gives breadth, dynamic analysis gives confirmation, reachability gives relevance, network observation gives deployment truth, provenance gives trust, probabilistic Mosca modeling gives prioritization, and migration rehearsal gives operational credibility.

ECDAT can become more innovative than existing MNC and open-source systems by making uncertainty and evidence first-class: every finding should be independently verifiable, every unknown should be visible, every risk score should expose its assumptions, and every recommendation should be tested before it is marked complete.
