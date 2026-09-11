# Next-Generation ECDAT Design – From Market Gaps to Innovative Architecture

## 1. Purpose and Scope

This report synthesizes the fact‑checked ECDAT market landscape with state‑of‑the‑art research on cryptographic discovery, quantum risk modeling, and post‑quantum (PQC) network impact to propose a next‑generation design for the **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**.[file:32][web:28][web:44][web:37][web:46][web:33][web:34][web:42]

The goal is not to marginally improve existing CBOM tools, but to define an architecture that **out-innovates both current MNC products and open‑source projects** by:
- Unifying static and dynamic crypto discovery into a reconciled evidence graph.
- Embedding an extended Mosca/QARS risk engine as a first‑class component.
- Actively modeling and mitigating PQC network‑level issues (MTU, IW, fragmentation).
- Making remediation (code/config changes) the primary output, not just inventory.[file:32][web:28][web:44]

---

## 2. Ground Truth: Confirmed Market Weaknesses

The attached fact‑checked report identifies recurring structural gaps shared across leading tools (IBM Quantum Safe Explorer, SandboxAQ AQtive Guard, Keyfactor, PQCA CBOMkit, ISARA Advance, CBOM Secure).[file:32]

The most critical weaknesses are:

1. **Static/dynamic reconciliation failure.** Static analysis gives a "static view" of potential crypto usage, while dynamic instrumentation shows only exercised paths; no platform cleanly unifies these views.[file:32][web:44][web:37][web:46]
2. **Shallow Mosca implementation.** Tools reference Mosca’s inequality but treat data lifetime X and migration time Y as coarse, global parameters, with limited modeling of adversary exposure and business sensitivity.[file:32][web:28]
3. **Remediation gap.** Discovery is commoditized; most platforms end with CBOM dashboards and export files, leaving security engineers with "expensive spreadsheets" and no integrated path from finding to fix.[file:32]
4. **PQC size and MTU problems.** PQC keys, signatures, and certificate chains are large enough to fragment TLS/DTLS handshakes, inflating latency and failure rates under packet loss and misconfigured networks.[file:32][web:33][web:34][web:42][web:41]
5. **Alert fatigue and missing data‑lifetime awareness.** Scanners flag every primitive equally regardless of whether it protects short‑lived cache data or decades‑long records, causing noisy, low‑value alerts.[file:32][web:28]

Any innovative ECDAT design must directly address these weaknesses, not just replicate today’s CBOM patterns.

---

## 3. Research Foundations Relevant to ECDAT

Several research works offer building blocks and partial solutions to the above issues.

### 3.1 Static Crypto Discovery: Cryptoscope

IBM Research’s **Cryptoscope** demonstrates compiler‑grade static crypto discovery using control‑flow and data‑flow analysis to build precise "cryptographic asset views" per codebase.[web:44]

Key properties:
- Identifies algorithms, keys, nonces, random sources, and related parameters as unified operations.
- Achieves high recall/precision on CamBench (92% exact‑match recall, 97% precision), outperforming pattern‑matching tools.[web:44]
- Produces extendable, queriable inventories suitable for risk assessment and modernization.

This shows that static discovery can be made significantly more accurate and contextual than current CBOMkit‑class scanners.[file:32][web:44]

### 3.2 Dynamic Crypto Misuse Detection: CRYLOGGER and CRYScanner

**CRYLOGGER** and **CRYScanner** detect crypto misuses dynamically by logging runtime API calls and checking parameters against rule sets.[web:37][web:46][web:35]

Key properties:
- Log parameters passed to crypto APIs (e.g., keys, IVs, randomness) during execution.[web:37]
- Apply rule engines offline to detect misuse (constant keys, weak passwords, insecure modes).[web:37][web:46]
- Architected with decoupled logging and checking, making rule extension straightforward.[web:35][web:46]

These tools explicitly complement static detectors like CryptoGuard, making the case for combining static and dynamic approaches.[web:37][web:46][web:44]

### 3.3 Quantum Risk Modeling: QARS (Extended Mosca)

"Towards a Unified Quantum Risk Assessment" introduces **QARS**, a Quantum‑Adjusted Risk Score model that extends Mosca’s inequality \(X + Y > Z\) into a continuous multi‑factor risk score.[web:28]

Key properties:
- Keeps Mosca’s timeline dimension (data lifetime X, migration time Y, quantum horizon Z).[web:28]
- Adds sensitivity (business/mission criticality) and exposure (attack surface and harvestability) dimensions.[web:28]
- Defines QARS(a) = w_T T(a) + w_S S(a) + w_E E(a) for asset a, with tunable weights.[web:28]

This responds directly to criticisms that Mosca is too coarse for operational decision‑making and provides a formal basis for per‑asset or per‑data‑class quantum risk scoring.[web:28][file:32]

### 3.4 PQC Network Impact: TLS/DTLS Fragmentation Studies

Multiple performance and measurement studies analyze how PQC inflates handshake sizes and causes fragmentation:

- A DTLS/IoT thesis shows PQC handshakes require DTLS‑level fragmentation and that relying on IP‑layer fragmentation harms reliability; it recommends MTU‑aware DTLS configuration and protocol‑aware fragmentation.[web:33]
- A QaaS performance study shows ML‑KEM/ML‑DSA hybrid TLS handshakes suffer tail‑latency spikes due to TCP window exhaustion and packet segmentation, and mitigates this by dynamically tuning TCP Initial Window and MSS via eBPF on edge load balancers.[web:34][web:36]
- TLS PQC benchmarks highlight how large schemes (Frodo, BIKE) fragment across many packets, with handshake completion time dominated by communication size under packet loss; they quantify packet counts and loss‑induced retransmissions.[web:42][web:40][web:39]
- A study on certificate chain sizes identifies discrete flight limits (10 KB and 40 KB) where packet segmentation forces extra RTTs, stressing the need for certificate size optimization.[web:41]
- PQC channel design work shows compression and batching can reduce Kyber‑based ciphertext flights from four to two MTU frames, cutting fragmentation.[web:43]

These works provide concrete mitigation strategies (IW/MSS tuning, MTU configuration, chain compression) that ECDAT can automate.[web:33][web:34][web:41][web:42][web:43]

### 3.5 Internet‑Scale PQ Readiness and Protocol Surveys

Measurement studies and surveys examine PQ readiness of widely used protocols (TLS, IPsec, SSH, QUIC, DNSSEC, OpenVPN, OpenID Connect) and track hybrid/PQC adoption on the public Internet.[web:39][web:45]

These give ECDAT baseline metrics and protocol‑specific constraints to factor into risk scoring and recommendations.

---

## 4. Design Principle 1 – Crypto Evidence Graph (Static + Dynamic Reconciliation)

### 4.1 Problem

Current tools either:
- Offer static snapshots of potential crypto usage (IBM Explorer, CBOMkit).[file:32][web:44]
- Or instrument runtime to see actual usage, but only along exercised paths, often limited to test environments.[file:32][web:37][web:46]

No platform models the **relationship** between static potential and dynamic evidence in a first‑class way, leading to both false positives (never‑used code) and false negatives (rarely‑executed paths).[file:32]

### 4.2 Research‑Inspired Solution

Leveraging Cryptoscope, CRYLOGGER, and CRYScanner, ECDAT can implement a **crypto evidence graph**:

- **Static layer (Cryptoscope‑like):**
  - For each repository/container, build "cryptographic operation views" with algorithms, keys, nonces, random sources, protocols, and call chains.[web:44]
- **Dynamic layer (CRYLOGGER/CRYScanner‑like):**
  - Instrument runtimes (JVM agents, LD_PRELOAD hooks, CNG providers, eBPF and tracing for native) to log actual API invocations, parameters, cipher suites, and key lifetimes.[web:37][web:46][web:35]

### 4.3 Innovation: Reconciliation States and Confidence Scores

ECDAT would treat each crypto asset as an **evidence‑backed node** with:

- Static evidence: where and how the crypto *could* be used.
- Dynamic evidence: where and how it *was* used, with counts and contexts.
- A confidence state: e.g., `STATIC_ONLY`, `DYNAMIC_ONLY`, `RECONCILED`, `CONFLICTING`.

This enables:
- Prioritization of assets with reconciled evidence over static‑only ones.
- Detection of code that is configured but never exercised (dead crypto) versus hidden runtime libraries not visible in static scans.[web:44][web:37]

No current tool exposes this reconciliation state clearly; it is an innovative but research‑grounded differentiator.[file:32][web:44][web:37][web:46]

---

## 5. Design Principle 2 – Data‑Centric Mosca/QARS Risk Engine

### 5.1 Problem

Most current platforms implement Mosca’s inequality at a shallow level:
- Global, coarse X (data lifetime) rather than per‑data‑class granularity.
- Y (migration time) treated as a fixed estimate rather than a resourced variable.
- Limited modeling of adversary exposure and harvestability.[file:32]

This leads to misprioritization and weak guidance on "what to fix first" under harvest‑now‑decrypt‑later threats.[file:32][web:28]

### 5.2 Research‑Inspired Solution

Using QARS, ECDAT can implement a **programmable, data‑centric Mosca engine**:

- **Data classes as first‑class objects:**
  - For each category (e‑voting ballots, health records, signing keys, financial transactions), record confidentiality and integrity lifetimes (X), regulatory constraints, and retention policies.[web:28][file:32]
- **System‑specific migration time Y:**
  - Estimate Y using dependency depth, historical change velocity (Git history, deploy cadence), code complexity metrics, and available resources.
- **Exposure E and sensitivity S:**
  - Derive exposure from network visibility, protocol properties, and storage conditions (e.g., Internet‑exposed TLS vs internal APIs, encrypted archives).[web:28][web:39][web:45]
  - Model sensitivity based on business criticality, regulatory impact, and mission role.[web:28]

### 5.3 Innovation: Tunable QARS‑like Scores Embedded in CBOM

ECDAT can:

- Compute a QARS‑inspired risk score for each **data‑flow edge** (data class ↔ crypto context) using a weighted combination of timeline, sensitivity, and exposure.[web:28]
- Attach these scores directly to CBOM assets, producing QARS‑enriched CBOMs that represent not just "what crypto is used" but "how urgent PQC migration is" for each data path.
- Expose the scoring formula in the UI, letting risk teams adjust weights and thresholds per sector (defense vs fintech vs healthcare).[web:28]

This moves Mosca from being a checkbox into a programmable risk engine within ECDAT, going beyond current proprietary scoring models.[file:32][web:28]

---

## 6. Design Principle 3 – PQC Network Autopilot

### 6.1 Problem

PQC algorithms significantly inflate handshake sizes and certificate chains, causing:
- TLS/DTLS fragmentation across multiple packets.
- Increased tail latency and handshake failure under packet loss.
- Misbehavior in legacy firewalls and middleboxes that mishandle segmented traffic.[file:32][web:33][web:34][web:42][web:41]

Current CBOM tools flag quantum‑vulnerable crypto but rarely reason about network‑level performance and failure modes of PQC deployment.[file:32]

### 6.2 Research‑Inspired Solution

ECDAT can integrate a **PQC network autopilot module** grounded in TLS/DTLS performance research:

- Use CBOM + protocol mappings to estimate handshake sizes for classical, hybrid, and PQC configurations (e.g., ML‑KEM‑768 public keys and ML‑DSA‑65 certificate chains yield multi‑kilobyte payloads).[web:34][web:39][web:43]
- Simulate fragmentation and RTT under given MTUs, IW/MSS values, and loss rates using models from TLS PQC benchmark papers.[web:42][web:40][web:41]
- Leverage QaaS and DTLS studies to determine when IW/MSS tuning, MTU‑aware fragmentation, and chain compression are necessary to maintain SLOs.[web:33][web:34][web:43]

### 6.3 Innovation: Auto‑Generated Network Mitigation Plans

For each critical system, ECDAT would produce:

- Recommended **TCP IW/MSS settings** for load balancers and edge proxies to ensure PQC handshakes fit within initial congestion windows, based on the eBPF tuning strategies shown to reduce p99 latency.[web:34][web:36]
- **DTLS/IoT MTU profiles** specifying record sizes and fragmentation strategies that avoid IP‑layer fragmentation and leverage protocol‑aware retransmission.[web:33]
- **Certificate chain optimization hints** (compression, Merkle tree certificates, batching) to keep handshake flights below critical thresholds (10 KB, 40 KB) identified in certificate size studies.[web:41][web:43]

This turns PQC network research into actionable configuration templates, making ECDAT a tool that not only discovers cryptography but also **tunes the network to accommodate PQC safely**—a capability absent in current CBOM platforms.[file:32][web:33][web:34][web:41][web:42][web:43]

---

## 7. Design Principle 4 – Developer‑First Crypto Refactoring Assistant

### 7.1 Problem

Most tools stop at detection and reporting:
- Open‑source projects like QuantumShield and cryptoscan‑pqc implement scan → score → CI alerts but explicitly state they are not full enterprise remediation platforms.[file:32]
- Commercial tools export CBOM/CSV or send tickets to SIEM/GRC, leaving actual code changes to manual processes.[file:32]

Developers lack an integrated assistant that converts findings into **concrete, safe code transformations**.[file:32]

### 7.2 Research‑Inspired Solution

Using Cryptoscope’s precise operation views and dynamic misuse detection rules from CRYLOGGER/CRYScanner, ECDAT can build a **crypto refactoring assistant**:

- Identify exact call sites and configuration blocks that implement vulnerable or legacy crypto.[web:44][web:37][web:46]
- Map them to language/ecosystem‑specific patterns for classical → PQC/hybrid transitions (e.g., `ECDH(X25519)` to `Hybrid(ML-KEM-X, X25519)`, RSA signatures to ML‑DSA hybrids).[web:45]
- Use code transformation templates per language (Java, Go, C, Python, C#) to synthesize patch diffs that implement new algorithms, update parameter sizes, and adjust protocol configurations.

### 7.3 Innovation: Auto‑Patch and Test Generation

ECDAT can:

- Generate ready‑to‑review pull requests that:
  - Replace deprecated algorithms with PQC/hybrid equivalents.
  - Add or update cipher suites, KEM parameters, and signing chains.
  - Include unit tests and integration tests to validate behavior.
- Integrate with IDEs (VS Code, IntelliJ) to show crypto findings inline and offer one‑click application of suggested fixes.

This shifts the value proposition from "You have these risks" to "Here are proposed patches and tests to remove these risks," making remediation a core product surface rather than an afterthought.[file:32][web:44][web:37][web:46]

---

## 8. Design Principle 5 – Temporal Crypto Twin and Forensics

### 8.1 Problem

CBOMs are typically static snapshots; they do not capture:
- How cryptographic posture evolves over time.
- What protected data at specific points in history.
- How prior configurations might affect current incident investigations.
[file:32]

Measurement studies show how PQ readiness can be tracked across time for public Internet deployments, but this temporal dimension is rarely reflected in enterprise tools.[web:39][web:45]

### 8.2 Research‑Inspired Solution

ECDAT can implement a **temporal crypto twin**:

- Treat each scan (static, dynamic, network, infra) as a time‑stamped state update to a cryptographic graph representing data flows, assets, and risk scores.[web:44][web:39]
- Maintain a history of CBOM states, Mosca/QARS scores, and PQC deployment configurations.

### 8.3 Innovation: Time‑Travel Queries and Forward Simulation

ECDAT would support:

- Queries like "What cryptographic algorithms protected dataset X on date D?" or "When did system Y switch from RSA‑2048 to ML‑KEM hybrid?".[web:39][web:44]
- Forward simulations of risk and performance under hypothetical migrations (e.g., moving to ML‑KEM‑1024/ML‑DSA‑87) using PQC network performance models.[web:34][web:42][web:41]

This provides both forensic capabilities and proactive planning tools that go beyond traditional CBOM dashboards.[file:32][web:39][web:41][web:42][web:44]

---

## 9. Design Principle 6 – Lifetime‑Weighted Alerting and Policy

### 9.1 Problem

Alert fatigue stems from:
- Uniform treatment of all crypto uses regardless of data lifetime and sensitivity.
- Lack of explicit data‑lifetime metadata in CBOM standards.[file:32][web:28]

Even CycloneDX maintainers acknowledge that intended use and migration status are not yet natively expressible, and they are discussing adding these fields in CBOM 2.0/CDXA.[file:32]

### 9.2 Research‑Inspired Solution

Building on QARS, ECDAT can:

- Attach data lifetime X and sensitivity S attributes to each crypto context and data flow.[web:28]
- Compute QARS‑like scores for each alert, reflecting timeline, sensitivity, and exposure.[web:28]

### 9.3 Innovation: Lifetime‑Aware Alert Prioritization

ECDAT’s alerting engine would:

- Suppress or batch low‑sensitivity, short‑lived findings (e.g., ephemeral cache encryption), while elevating long‑lived, high‑sensitivity flows (e.g., signing keys, personal records).[web:28][file:32]
- Provide dashboards where alert severity and volume are weighted by data lifetime and exposure, making it clear which issues truly matter.[web:28]

This directly addresses one of the most cited market pain points and aligns with emerging CBOM standard discussions.[file:32][web:28]

---

## 10. Conclusion – ECDAT as an Orchestrator of Best‑in‑Class Ideas

By combining and extending the strongest ideas from Cryptoscope, CRYLOGGER/CRYScanner, QARS, PQC network performance studies, and PQ readiness measurements, ECDAT can occupy a distinctive niche:

- It becomes a "crypto twin" platform that reconciles static and dynamic evidence into a single, temporal, data‑centric graph.
- It uses an extended Mosca/QARS engine to prioritize migration based on realistic timelines, sensitivity, and exposure.
- It automatically generates network and code remediation plans rooted in empirical PQC performance research.
- It treats remediation—not just discovery—as the core outcome.

This design responds directly to the structural weaknesses identified in the fact‑checked market landscape and pushes beyond what current MNC and open‑source tools provide, while remaining grounded in verified research and standards discussions.[file:32][web:28][web:44][web:37][web:46][web:33][web:34][web:42][web:41][web:43][web:39][web:45]
