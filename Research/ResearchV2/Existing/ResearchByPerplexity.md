# Enterprise Cryptographic Discovery & Analysis Tools (ECDAT) – Landscape Review and Gap Analysis

## Executive Summary

Enterprise cryptographic discovery and CBOM (Cryptographic Bill of Materials) tooling has matured rapidly in response to post‑quantum cryptography (PQC) migration pressure and regulatory mandates, but no available platform fully satisfies the requirements in your ECDAT problem statement.
Several products and open‑source toolkits lead the market on discovery depth, CBOM modeling, and quantum‑risk analytics, yet they share systemic weaknesses: incomplete coverage of legacy/OT/custom crypto, limited real‑time visibility, shallow Mosca‑style risk modeling, and poor developer ergonomics for remediation.
[cite:1][cite:5][cite:8][cite:9][cite:11][cite:12][cite:19][cite:22][cite:30]

---

## 1. Problem Context and Requirements

Transitioning to PQC requires a **cryptographic inventory and quantum‑risk assessment pipeline** that can:
- Discover and catalogue cryptographic artefacts across code, binaries, containers, infrastructure, and cloud services.
- Classify by algorithm, parameters, lifetime, business criticality, and ownership.
- Apply Mosca’s inequality (data lifetime + migration time vs. time to cryptographically relevant quantum computer) to prioritize risks.
- Recommend PQC and hybrid alternatives under latency, cost, compliance, and interoperability constraints.
[cite:16][cite:18][cite:20][cite:21][cite:24][cite:25][cite:26]

Current CBOM‑centric tools largely satisfy the **inventory and classification** layers but treat quantum‑risk modeling and migration planning as thin add‑ons, leaving room for an ECDAT design that treats Mosca‑style risk scoring and remediation orchestration as first‑class concerns.
[cite:9][cite:12][cite:19][cite:28]

---

## 2. Representative Leading Solutions

This section focuses on representative solutions that currently define the state of the art in enterprise cryptographic discovery and CBOM analytics.
We emphasize those that:
- Provide broad multi‑surface discovery (code, containers, infrastructure, network).
- Generate standards‑compliant CBOMs (CycloneDX) for integration.
- Incorporate PQC readiness, quantum risk scoring, or Mosca‑inspired heuristics.
[cite:1][cite:2][cite:5][cite:8][cite:9][cite:10][cite:11][cite:12][cite:13][cite:14][cite:15]

### 2.1 PQCA CBOMkit (IBM‑origin, now PQCA)

**Solution approach.** CBOMkit is an open‑source suite that performs static analysis of source code and container images to detect cryptographic assets and generate CBOMs.
It is built around the Sonar‑cryptography plugin (Hyperion) for source scanning, a REST service and UI for CBOM management, and Theia for filesystem and container scanning.
[cite:2][cite:3][cite:8][cite:13][cite:29]

**Core capabilities.**
- Static code analysis for Java, Python, Go, and related crypto libraries (JCA, BouncyCastle, pyca/cryptography, Go crypto).
- CBOM generation with precise source locations and algorithm metadata.
- Container and filesystem scanning via cbomkit‑theia to merge runtime artifacts with source‑level CBOMs.
- CI/CD integration via cbomkit‑action and Sonar‑cryptography in SonarQube.
[cite:2][cite:3][cite:8][cite:9][cite:13][cite:29]

**System design pattern.**
- **Scanning layer:** static analysis engine embedded in SonarQube plus standalone CLI scanners for artifacts.
- **Aggregation layer:** CBOMkit service consolidates CBOM objects from multiple scans (source, containers) into a central store.
- **Visualization and policy layer:** Web UI to browse CBOMs and a compliance engine to enforce crypto policies (e.g., flagging non‑PQC algorithms).
[cite:2][cite:3][cite:8][cite:13]

**Strengths.**
- Strong open‑source ecosystem and alignment with CBOM research and CycloneDX specifications.
- Deep language‑specific rules for detecting cryptographic API usage.
- CI‑friendly architecture enables early crypto visibility in the pipeline.
[cite:2][cite:3][cite:8][cite:9][cite:29]

**Weaknesses and user‑visible limitations.**
- Limited language and library coverage; C#, C/C++, Rust, JavaScript, and many embedded crypto stacks remain unsupported or partial.
- Known detection‑engine issues: no cross‑method data‑flow analysis, string‑based matching, and incomplete symbol resolution when repositories aren’t built prior to scanning; this leads to missed findings and false positives.
- Focused on **static CBOM generation**; lacks built‑in Mosca‑style time‑based quantum risk scoring and business‑criticality modeling.
- Requires non‑trivial SonarQube and CI setup, which can deter smaller teams or lead to sporadic adoption.
[cite:2][cite:3][cite:8][cite:9][cite:19][cite:29]

**Common user complaints / gaps.**
- Desire for "one click" enterprise‑wide inventory instead of per‑repo configuration.
- Need for better support of non‑Java/Python ecosystems (e.g., microservices in Node.js, Rust, or C++).
- Expectation that CBOMkit would also handle **live systems** (network, cloud KMS, HSMs), which it currently does not.
[cite:8][cite:19][cite:22][cite:29]

---

### 2.2 Enterprise Cryptographic Posture Platforms (Atlas/Qinsight, Encryption Consulting CBOM Secure, QuantumGenie)

Several commercial platforms position themselves as **cryptographic posture management (CPM)** systems, combining broad discovery with CBOM‑backed reporting and quantum‑risk analytics.
Representative examples include Atlas/Qinsight, Encryption Consulting CBOM Secure, and QuantumGenie.
[cite:5][cite:10][cite:11][cite:16][cite:19]

#### 2.2.1 Qinsight Atlas Cryptographic Discovery

**Solution approach.** Atlas automates discovery across networks, infrastructure, cloud, and software supply chain to build a live CBOM and feed a CPM dashboard.
[cite:5]

**Core capabilities.**
- Sensors and credentialed scans across network segments, servers, cloud accounts.
- Normalization of findings into a searchable CBOM enriched with business context: algorithms, key sizes, certificate chains, protocols, systems, owners.
- Policy checks for deprecated/weak crypto, expired certificates, short keys, and quantum‑susceptible usage.
[cite:5]

**System design pattern.**
- **Sensor network:** deployable agents or connectors per segment.
- **Source connectors:** integrations to PKI, cloud KMS, directories, and server configuration APIs.
- **Analytics and reporting:** CPM dashboard with severity‑scored issues and export options (CSV/PDF, CMDB/ticketing sync).
[cite:5]

**Strengths.**
- Strong on **cryptography‑in‑motion** and **cryptography‑at‑rest** via network and infrastructure scans.
- Business‑context enrichment (owner, environment, system) makes CBOMs actionable.
- Policy engine for quantum‑susceptible usage flags.
[cite:5][cite:19]

**Weaknesses and limitations.**
- Limited direct view into **application source code** and custom crypto; relies on what network and infrastructure expose.
- CBOM is largely **asset‑centric**, with limited explicit modeling of data lifetime and Mosca‑style timing dimensions.
- Real‑time posture requires ongoing sensor deployment and maintenance, which many users find operationally heavy.
[cite:5][cite:19][cite:22][cite:30]

**User‑visible pain points.**
- Difficulty covering segmented, air‑gapped, or OT networks.
- Perception of "black‑box" scoring with insufficient transparency into how quantum risk levels are computed.
[cite:19][cite:22][cite:30]

#### 2.2.2 Encryption Consulting CBOM Secure

**Solution approach.** CBOM Secure aims to be an enterprise‑wide platform that continuously discovers, inventories, and monitors every key, certificate, algorithm, and cryptographic library across code, cloud, and on‑premises infrastructure.
It emphasizes an asset relationship graph linking certificates to keys and secrets to consuming services.
[cite:7][cite:11][cite:16]

**Core capabilities.**
- Continuous CBOM inventory with full estate coverage: cloud infrastructure, PKI, certificate managers, application source code.
- Risk and compliance scoring per asset (strength, alignment with standards, quantum exposure).
- Relationship graph modeling of cryptographic dependencies and execution paths.
[cite:7][cite:11]

**System design pattern.**
- **Discovery connectors:** integrations to cloud providers, PKI, certificate stores, code repositories.
- **Graph store:** models relationships among assets (cert ↔ key ↔ service ↔ environment) for impact analysis.
- **Risk scoring engine:** maps assets to compliance frameworks and quantum‑risk profiles.
[cite:7][cite:11]

**Strengths.**
- Rich relationship modeling enables blast‑radius and dependency analysis.
- CBOM‑backed posture view that is continuously updated, not a one‑off scan.
[cite:7][cite:11]

**Weaknesses and limitations.**
- Focus remains on **crypto assets**, with only high‑level guidance on PQC migration sequencing and Mosca‑style timing.
- Quantum risk scoring appears asset‑centric (algorithm strength, key size, expiry) rather than **data‑lifetime‑centric**, which can mis‑prioritize short‑lived vs. long‑lived secrets.
- Enterprise deployment complexity and licensing cost are recurring complaints.
[cite:11][cite:19][cite:22][cite:30]

**User‑visible pain points.**
- Desire for deeper workflow automation (ticketing, remediation orchestration) beyond dashboards.
- Need for more explicit support of harvest‑now‑decrypt‑later (HNDL) scenarios and Mosca‑equation based prioritization.
[cite:19][cite:20][cite:21][cite:28][cite:30]

#### 2.2.3 QuantumGenie Cryptographic Discovery Platform

**Solution approach.** QuantumGenie positions itself as an AI‑native PQC platform that discovers, attributes, remediates, and continuously monitors cryptographic risk while building a live CBOM.
Its CipherScan component performs continuous discovery across code, cloud, databases, certificates, and endpoints.
[cite:10]

**Core capabilities.**
- Continuous asset discovery across multiple surfaces (source code, infrastructure, data stores).
- CBOM tracking of 70+ fields per cryptographic asset, including algorithm, key size, protocol, and classical vs post‑quantum classification.
- AI‑assisted risk analysis and remediation workflows.
[cite:10]

**System design pattern.**
- **Discovery engine:** multi‑surface scanning plus marketplace integrations (cloud platforms, IDE extensions, SIEM/SOAR).
- **CBOM store:** high‑granularity cryptographic asset records.
- **AI layer:** recommendation engine for risk treatment and PQC migration.
[cite:10]

**Strengths.**
- High‑detail CBOM schema and classification across classical vs PQC primitives.
- Broad platform availability (cloud marketplaces, developer tools) makes integration easier.
[cite:10][cite:12]

**Weaknesses and limitations.**
- Public materials emphasize asset granularity more than transparent, formal Mosca‑style quantum risk math.
- Like other tools, discovery in legacy/custom/OT domains remains opaque or dependent on manual inputs.
[cite:10][cite:19][cite:22][cite:30]

**User‑visible pain points.**
- Requests for more explainable AI recommendations and exportable, policy‑driven risk equations.
- Concerns about over‑reliance on proprietary scoring without alignment to sector‑specific Mosca / HNDL guidance.
[cite:19][cite:20][cite:21][cite:28][cite:30]

---

### 2.3 Network‑Centric Cryptographic Discovery (CipherInsights, Zeek‑based approaches)

**Solution approach.** Tools like CipherInsights and Zeek‑based TLS logging provide passive network monitoring that records cryptographic parameters (TLS versions, cipher suites, certificate chains) to build a network‑centric cryptographic inventory.
[cite:8]

**Core capabilities.**
- Continuous capture of live cryptographic usage over the wire.
- Identification of deprecated protocols, weak cipher suites, and misconfigurations.
[cite:8]

**System design pattern.**
- **Network sensors:** passive taps or mirror ports for traffic capture.
- **Analysis scripts:** extract crypto metadata into logs or CBOM‑like structures.
[cite:8]

**Strengths.**
- Direct view of **what is actually negotiated** in production (not just configured).
- Good alignment with HNDL and Mosca’s emphasis on network‑visible long‑lived secrets.
[cite:8][cite:20][cite:21]

**Weaknesses and limitations.**
- Cannot see offline or at‑rest crypto (databases, storage, internal APIs).
- Often lack structured CBOM output, requiring custom tooling to transform logs into CBOM objects.
[cite:8][cite:9][cite:19]

**User‑visible pain points.**
- Desire for unified CBOM models that merge network‑captured crypto with code/infrastructure inventories.
- Operational overhead of maintaining taps and parsing pipelines.
[cite:8][cite:19][cite:22][cite:30]

---

### 2.4 Artifact‑Centric CBOM Generation (Spice Labs)

**Solution approach.** Spice Labs argues that existing tools focus too much on source code and network traffic and too little on **built artifacts**.
Their Surveyor/Topographer tools analyze JARs and container images directly from registries to generate CBOMs and PQC security reports.
[cite:15]

**Core capabilities.**
- Hash‑level analysis of binaries and containers in Artifactory or Docker registries.
- CBOM generation even for custom‑compiled crypto and legacy binaries when hashes are provided.
- Color‑coded PQC security report (red/yellow/green) per application.
[cite:15]

**System design pattern.**
- **Artifact walkers:** scan registry contents without requiring source code or agents.
- **Binary analysis engine:** extracts embedded certificates, signing keys, and key‑exchange mechanisms.
- **Reporting layer:** CBOM plus PQC readiness scoring.
[cite:15]

**Strengths.**
- High alignment with real deployment state (built artifacts) instead of development assumptions.
- No need for source code or SBOMs; works in third‑party or opaque environments.
[cite:15]

**Weaknesses and limitations.**
- Limited visibility into **runtime configuration** and dynamic protocol negotiation.
- Focus on JVM ecosystems; non‑Java stacks and embedded/firmware remain difficult.
[cite:15][cite:19][cite:22]

**User‑visible pain points.**
- Need to correlate artifact‑level CBOMs with business context, ownership, and data‑lifetime attributes.
- Desire for tighter integration with CI pipelines and developer workflows.
[cite:15][cite:19][cite:30]

---

### 2.5 PQC Network‑Layer Migration Platforms (QuProtect R3)

**Solution approach.** QuProtect R3 discovers cryptography in use across the network, enforces PQC algorithms at the network layer (without changing application code), and generates CycloneDX CBOMs from the live inventory.
[cite:14]

**Core capabilities.**
- Network‑layer enforcement of NIST PQC algorithms by policy.
- CBOM generation from live cryptographic inventory.
[cite:14]

**System design pattern.**
- **Sensors/proxies:** intercept traffic and apply PQC at the network layer.
- **Inventory and reporting:** CBOM export for auditors and federal submissions.
[cite:14]

**Strengths.**
- Rapid mitigation path for certain classes of quantum‑vulnerable traffic without deep code changes.
- Native support for CycloneDX CBOM.
[cite:14][cite:12]

**Weaknesses and limitations.**
- Network‑centric view; cannot fully address at‑rest data or application‑internal cryptography.
- PQC enforcement is bound to supported protocols and deployment patterns.
[cite:14][cite:19][cite:21]

**User‑visible pain points.**
- Need to align network‑layer fixes with long‑term application‑layer migration plans and Mosca‑style prioritization.
[cite:19][cite:20][cite:21][cite:28]

---

## 3. Common Design Patterns Across Leading Tools

Across the above solutions, several architectural patterns recur:

### 3.1 Multi‑Surface Discovery Pipelines

Leading tools blend multiple discovery techniques:
- Static code analysis (CBOMkit, CodeQL/Sonar integrations).
- Network monitoring (Zeek, CipherInsights, QuProtect).
- Infrastructure and cloud scans (Atlas, CBOM Secure, QuantumGenie).
- Artifact/binary analysis (Spice Labs Surveyor, cbomkit‑theia).
[cite:2][cite:5][cite:8][cite:9][cite:10][cite:11][cite:13][cite:14][cite:15]

These pipelines feed into a CBOM store and analytics layer, but integration is often ad‑hoc, leaving gaps where some surfaces are much more thoroughly covered than others.
[cite:19][cite:22][cite:30]

### 3.2 CBOM as a Core Data Model (CycloneDX)

Most modern solutions adopt the CycloneDX CBOM specification or closely related models, defining:
- Algorithms, keys, certificates, protocols, and ciphers.
- Relationships to software components and services.
- Fields for quantum readiness, deprecated algorithms, and key states.
[cite:3][cite:9][cite:12]

This enables standardized export/import and cross‑tool integration, but many implementations leave higher‑level risk semantics (Mosca’s theorem, HNDL exposure, data lifetime) to external logic rather than encoding them into the CBOM objects themselves.
[cite:9][cite:12][cite:19][cite:28]

### 3.3 Policy and Compliance Engines

Commercial platforms embed policy engines to flag:
- Deprecated algorithms (e.g., RSA‑1024, SHA‑1).
- Weak key sizes and expired certificates.
- Quantum‑susceptible usage (public‑key schemes vulnerable to Shor).
[cite:5][cite:11][cite:14][cite:19]

However, these engines typically evaluate **per‑asset properties** rather than **per‑data‑class Mosca scores**, limiting their ability to prioritize which systems truly matter under harvest‑now‑decrypt‑later threat models.
[cite:18][cite:20][cite:21][cite:24][cite:25][cite:28]

---

## 4. Structural Weaknesses in Current Designs

Despite strong progress, several structural weaknesses recur across the ecosystem and directly map to user complaints.

### 4.1 Coverage Gaps: Legacy, OT, and Custom Crypto

Analyses of CBOM programs highlight that automated tools consistently miss entire categories of systems:
- Legacy systems with proprietary or non‑standard crypto.
- Operational technology (OT) and industrial control systems with segmented networks and specialized protocols.
- Custom cryptographic implementations that do not follow discoverable library patterns.
[cite:19][cite:22][cite:30]

Users frequently report a **false sense of completeness**, where CBOM dashboards show a clean inventory but later audits uncover substantial unmodeled cryptography.
Existing tools rarely surface these blind spots explicitly or provide structured workflows to address them.
[cite:22][cite:30]

### 4.2 Static Inventories and Lack of Real‑Time Activity Views

CBOMs are inherently snapshot‑style artifacts.
Several critiques note that CBOM alone "provides a static inventory and cannot reflect dynamic changes in cryptographic usage," with limited support for real‑time monitoring and historical/forensic queries.
[cite:19]

Network‑centric tools partially fill this gap, but integration between **static CBOMs** and **dynamic activity logs** (e.g., actual TLS handshakes, changing cipher suites under load) is weak.
Users want:
- Time‑series views of cryptographic posture.
- Drift detection (e.g., sudden reintroduction of deprecated ciphers).
- Forensic replay of crypto state at the time of incidents.
[cite:8][cite:19][cite:22][cite:30]

### 4.3 Shallow Quantum Risk Modeling and Mosca Integration

While many vendors reference quantum readiness and PQC migration, few expose explicit Mosca‑style risk equations.
Academia and policy guidance stress comparing:
- Data confidentiality lifetime (X).
- Migration time (Y).
- Time to cryptographically relevant quantum computer (Z).
[cite:16][cite:17][cite:18][cite:20][cite:21][cite:24][cite:25][cite:26][cite:28]

Typical tools:
- Score assets by algorithm strength and key size.
- Flag quantum‑susceptible primitives.

They rarely:
- Attach **data‑lifetime metadata** to each cryptographic context.
- Estimate migration duration per system and encode it as a first‑class attribute.
- Compute Mosca’s inequality per data class or system and use it to prioritize.
[cite:18][cite:20][cite:21][cite:24][cite:25][cite:28]

Users increasingly ask for **sector‑specific Mosca implementations** (e.g., financial transactions vs health records vs national ID systems) and for transparent scoring formulas, but many platforms provide only qualitative "high/medium/low" tags.
[cite:21][cite:23][cite:27][cite:28]

### 4.4 Insufficient Data‑Centric View (Over‑Focus on Crypto Assets)

Most current tools model cryptography around **assets**: keys, certificates, algorithms, and libraries.
Quantum risk, however, is primarily a property of **data**:
- How long must specific data classes remain confidential or trustworthy?
- Through which cryptographic contexts does that data flow (network, storage, signing, key exchange)?
[cite:20][cite:21][cite:24][cite:25][cite:26][cite:28]

Users and practitioners note that asset‑centric CBOMs make it difficult to answer core Mosca/HNDL questions like:
- "Which datasets today will still be sensitive at Q‑day and currently transit quantum‑vulnerable key exchanges?"
- "What is the blast radius if a given key or certificate is quantum‑broken?"
[cite:21][cite:22][cite:30]

### 4.5 Limited Developer‑First Remediation Workflows

Open‑source tools like CBOMkit integrate well into CI pipelines but stop at detection and reporting.
Commercial platforms provide dashboards and export features but often leave remediation as a manual, ticket‑driven process.
[cite:2][cite:3][cite:5][cite:10][cite:11][cite:13][cite:29][cite:30]

Developers and security engineers increasingly ask for:
- Automated patch suggestions (e.g., "replace ECDH‑secp256r1 with ML‑KEM‑768" in specific code locations).
- Hybrid crypto patterns ready‑made for their language/ecosystem.
- Impact analysis and test guidance for cryptographic changes.
[cite:21][cite:23][cite:27][cite:28]

Most tools do not yet provide deep **code‑level refactoring assistance** or integration with PQC libraries beyond basic recommendations.

### 4.6 Interoperability and Fragmentation

The ecosystem is fragmented:
- Different tools cover different surfaces (code vs network vs artifacts vs infrastructure).
- Each maintains its own data store and CBOM variant.
[cite:6][cite:8][cite:9][cite:12][cite:19][cite:30]

Users frequently request:
- Unified CBOM graphs that merge inventories across tools.
- Standard APIs and schemas for exchanging CBOMs.
- Lower friction to feed CBOM data into GRC, SIEM, ticketing, and AI remediation agents.
[cite:6][cite:9][cite:12][cite:19][cite:22][cite:30]

---

## 5. Limitations Users Most Often Complain About (and Vendors Rarely Fix)

Based on analyses and user‑facing commentary, several limitations are repeatedly raised but still under‑addressed in current designs.

### 5.1 Blind Spots Acknowledgement and Gap‑Handling Workflows

Users want tools to **explicitly declare what they cannot see**—legacy systems, OT, air‑gapped environments, custom crypto—and to provide structured workflows to close those gaps via interviews, architecture review, and manual CBOM entries.
[cite:22][cite:30]

Instead, most platforms present clean dashboards that implicitly suggest full coverage, leading to misplaced trust.

### 5.2 Data‑Lifetime‑Aware Risk Prioritization

Organizations seek actionable answers to "what to fix first" using Mosca’s inequality and HNDL exposure, but asset‑centric scoring obscures this.
They expect:
- Data shelf‑life classification integrated into CBOM.
- Harvestability/exposure scoring for each cryptographic context.
- Automated ordering of migration tasks based on X + Y > Z per data class.
[cite:20][cite:21][cite:24][cite:25][cite:28]

Most tools still fall back on generic severity metrics that do not model data lifetime explicitly.
[cite:19][cite:21]

### 5.3 First‑Class Support for PQC and Hybrid Crypto Choices

Users want recommendations that go beyond "use PQC" and instead:
- Map each crypto usage to concrete PQC or hybrid algorithms (ML‑KEM, ML‑DSA, etc.) under latency and cost constraints.
- Consider protocol‑level impacts and interoperability with existing stacks.
[cite:18][cite:20][cite:21][cite:24][cite:28]

Existing tools often provide high‑level guidelines but not per‑system, per‑path recommendations integrated with developer workflows.
[cite:5][cite:10][cite:11][cite:14]

### 5.4 Open, Extensible Risk Models and Explainability

Security teams increasingly demand **transparent risk models** that can be tuned to their sector and threat assumptions.
They want to see the equations, weights, and thresholds, especially for quantum risk.
[cite:21][cite:23][cite:28]

Many platforms still use proprietary scoring that is hard to audit or adapt.

### 5.5 Integrated Activity History and Forensics

CBOM snapshots are useful, but teams handling incidents or compliance audits expect:
- Historical views of cryptographic posture.
- Ability to replay what algorithms and keys protected data at specific points in time.
[cite:19]

This remains uncommon in mainstream tools.

---

## 6. Implications for ECDAT System Design

Given the above landscape, an ECDAT implementation can differentiate by:

### 6.1 Treating Mosca’s Theorem as a First‑Class Data Model

Embed Mosca’s inequality directly into the system:
- Attach X (data lifetime) and business criticality to each data class and cryptographic context.
- Estimate Y (migration time) per system using dependency depth and historical change‑rates.
- Model Z (time to CRQC) as a tunable policy parameter or range.
[cite:16][cite:18][cite:20][cite:21][cite:24][cite:25][cite:26][cite:28]

Compute per‑asset and per‑data‑class scores and drive prioritization accordingly.
This goes beyond existing tools that merely label algorithms as "quantum‑safe" or "quantum‑vulnerable."[cite:19][cite:21][cite:28]

### 6.2 Data‑Centric Graph Over Crypto Assets

Design ECDAT’s core model as a **data‑flow graph enriched with cryptographic edges**:
- Nodes: data classes, systems, services, and storage.
- Edges: cryptographic contexts (key exchanges, encryption at rest, signatures).
[cite:20][cite:21][cite:26][cite:28]

Attach CBOM assets (keys, certs, algorithms) as attributes of these edges rather than as isolated nodes.
This addresses the user desire to answer questions about which data is at risk under quantum threats.
[cite:21][cite:22][cite:30]

### 6.3 Explicit Blind‑Spot Modeling and Manual Augmentation Workflows

Include a **blind‑spot registry** in the UI:
- Mark environments where automated scanning is impossible or limited (legacy, OT, air‑gapped).
- Provide guided workflows for manual CBOM entry and risk estimation.
[cite:22][cite:30]

This directly addresses one of the most cited complaints about current tools.

### 6.4 Unified, Extensible CBOM Store with Multi‑Surface Connectors

Reuse CycloneDX CBOM format but design ECDAT as an orchestrator that:
- Imports CBOMs from CBOMkit, Spice Labs, network tools, and commercial platforms.
- Normalizes them into a single graph with consistent semantics.
[cite:3][cite:6][cite:9][cite:12][cite:13][cite:15]

Provide open APIs for risk scoring extensions and sector‑specific policy modules.

### 6.5 Developer‑Focused Remediation and PQC Recommendation Engine

Integrate with developer tooling (VS Code, GitHub, CI) to:
- Surface cryptographic findings directly in code (locations, APIs, call sites).
- Suggest concrete PQC/hybrid replacements and code‑level patterns.
[cite:2][cite:3][cite:8][cite:10][cite:13][cite:15][cite:29]

This addresses the gap between discovery and actual migration work.

---

## 7. Conclusion

The current generation of CBOM and cryptographic discovery tools has solved **scalable inventory and basic quantum‑readiness assessments**, but still lacks the **data‑centric, Mosca‑driven, and developer‑oriented design** your ECDAT project aims to provide.
By explicitly modeling data lifetime, migration time, harvestability, and blind spots—while orchestrating existing scanners rather than competing with them—ECDAT can occupy a distinct niche and address many of the limitations users most often complain about but vendors have not fully fixed.
[cite:1][cite:2][cite:3][cite:5][cite:6][cite:8][cite:9][cite:10][cite:11][cite:12][cite:13][cite:14][cite:15][cite:16][cite:18][cite:19][cite:20][cite:21][cite:22][cite:24][cite:25][cite:26][cite:28][cite:30]
