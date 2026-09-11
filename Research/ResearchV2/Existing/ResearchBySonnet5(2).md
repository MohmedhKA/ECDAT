# Market Landscape Analysis for ECDAT
### Existing Cryptographic Discovery & PQC-Readiness Tools — Design Review, System Architecture, and Failure Analysis

**Prepared for:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) — Design Reference
**Scope:** Benchmarking market-leading solutions in Cryptographic Bill of Materials (CBOM) generation, quantum-risk assessment, and PQC migration planning, followed by a systematic weakness analysis to guide ECDAT's differentiated design.

---

## 1. Why This Analysis Matters

Every credible cryptographic-discovery product on the market today converges on the same output standard — the **Cryptography Bill of Materials (CBOM)**, formalized as an extension of OWASP CycloneDX v1.6 (ratified as ECMA-424) and expanded in CycloneDX v1.7 with a dedicated Cryptography Registry [web:51][web:62]. ECDAT is therefore not entering a greenfield space — the *output format* is largely settled, but the *quality, trustworthiness, and operational usefulness* of the underlying discovery engines is where every current vendor still struggles. Understanding exactly where today's leaders fall short is the fastest path to a genuinely differentiated ECDAT design.

---

## 2. The Market Leaders: Solution Approach and System Design

### 2.1 IBM Quantum Safe Explorer (part of IBM Quantum Safe Suite)

IBM is generally regarded as the reference implementation for CBOM, since IBM Research co-authored the CycloneDX CBOM extension itself [web:62].

**Solution approach:** Quantum Safe Explorer performs **static source-code and binary analysis** to locate cryptographically relevant API calls, then builds a call graph mapping "implements" and "uses/dependsOn" relationships between libraries, algorithms, and application code [web:57][web:61]. It flags weak/quantum-vulnerable primitives (RSA, ECDSA, SHA-1, etc.) against a severity-mapped vulnerability knowledgebase.

**System design:**
- **Delivery surfaces:** a VS Code IDE extension (local developer scans, under 5-minute setup), a standalone CLI for CI/CD pipeline integration (Jenkins/GitHub Actions/Tekton), and a REST API [web:17][web:10].
- **Scan pipeline:** a broad, language-agnostic "API Discovery Scan" followed by a deeper, language-specific "Cryptographic Analysis Scan" (currently richest for Java) [web:2][web:19].
- **Externalized knowledge base:** detection signatures for libraries (JCA, Bouncy Castle, OpenSSL, Python `Crypto`) live outside the analysis engine, so new libraries can be added without re-engineering the scanner [web:17].
- **Outputs:** per-repo `.json` CBOM, `.csv` inventories, and `Findings.json`, feeding a central CBOM Store and dashboard layer (e.g., IBM's internal Developer Data Lake) [web:10][web:17].
- **Language coverage:** Java, Python, C, C++, C#, Go, Dart, with expanding platform support (LinuxONE/Z-Linux CLI added in 2025) [web:65].
- **Ecosystem tie-in:** feeds IBM Quantum Safe Advisor (risk scoring) and Remediator (patch generation), forming a Discover → Assess → Remediate pipeline.

### 2.2 SandboxAQ AQtive Guard (built on the acquired Cryptosense engine)

**Solution approach:** Positions itself as an "end-to-end cryptographic management platform," combining discovery with continuous **vulnerability and compliance analysis** and non-human-identity (service accounts, API keys, machine credentials) security [web:42][web:44].

**System design:**
- **Sensors:** modular scanning agents that analyze networks, filesystems, or applications and generate "trace files," normalized into a "Profile" for cross-project comparison [web:47].
- **Dashboard-centric UX:** a web interface gives an "up-to-date visualization of cryptographic inventory and health across all projects," emphasizing interactive drill-down over static reports [web:49][web:50].
- **AQtive Guard Protect module:** extends discovery into runtime protection of non-human identities — beyond pure inventory into active governance [web:48].
- **Open Cryptography initiative:** a public, crowdsourced crypto-risk database used as a community/threat-intel differentiator [web:52].

### 2.3 Keyfactor AgileSec Platform

**Solution approach:** Keyfactor's own published critique of CBOM sets its philosophy: *"make your cryptographic footprint visible"* first, then tie every artifact to **business-critical use cases**, not just technical existence [web:60]. It behaves less like a scanner and more like a full **PKI/certificate lifecycle management** platform with discovery attached.

**System design:**
- Strong emphasis on certificate and key **lifecycle automation** (issuance, rotation, revocation) rather than only static-code discovery — differentiating it from IBM/SandboxAQ's code-first model.
- Explicitly separates "capability" (what a library *can* do) from "configuration" (what is *actually in use*) — a distinction most competitors gloss over [web:62].

### 2.4 IBM CBOMkit (Open-Source Reference Architecture, Linux Foundation)

Because CBOMkit is open source, its architecture is the most transparent public reference for how a CBOM engine is actually built — highly relevant for ECDAT's own design:

| Component | Function |
|---|---|
| CBOMkit-Hyperion | SonarQube plugin; static source-code scanning (Java, Python) |
| CBOMkit-Theia | Container image and directory/filesystem scanning |
| CBOMkit-Coeus | Web-based CBOM viewer (the GUI layer) |
| CBOMkit-Themis | Compliance engine with built-in quantum-safe policy checks |
| CBOMkit-Action | GitHub Action for CI/CD-native scanning |

This modular, pipeline-composable architecture (scan → normalize → store → visualize → enforce policy) mirrors almost exactly what the ECDAT problem statement asks for: repo/binary/container scanning → CBOM → interactive GUI [web:62].

### 2.5 Emerging / Adjacent Players

Quantum Xchange CipherInsights, CryptoNext COMPASS, InfoSec Global AgileSec Analytics, AppViewX, and O3 Security round out the competitive set. An independent 2026 benchmark ("PQC Discovery Index") scoring 14 products found that **discovery breadth has already converged across the market** — the real competitive separation now lies in evidence integrity (cryptographic signing of scan results), change-detection latency, quantitative risk scoring, and remediation-workflow completeness (e.g., AppViewX and Keyfactor document bidirectional certificate-lifecycle ticketing that some "discovery-only" leaders still lack) [web:64].

---

## 3. Common Architectural Pattern Across Leaders

Despite marketing differences, nearly every leading tool converges on the same pipeline — a useful architectural baseline for ECDAT:

1. **Multi-surface scanners** — static source code, binaries/bytecode, container images, and (rarely) live network/TLS handshake traffic.
2. **Externalized detection knowledge base** — per-language, per-library pattern signatures decoupled from the core engine for extensibility.
3. **Standardized CBOM output** — CycloneDX JSON, enriched with "provides" vs. "uses" relationship metadata.
4. **Risk scoring layer** — severity/priority mapping, sometimes referencing Mosca's-type time-based urgency models.
5. **Dashboard/GUI** — a web console for drill-down visualization, trend tracking, and (in mature products) remediation ticket generation.

---

## 4. Where the Market Leaders Are Actually Failing

This is the section that matters most for ECDAT's differentiation. The weaknesses below are drawn from vendor-neutral technical critiques, independent benchmarking, and practitioner post-mortems — not marketing pages — and represent the complaints users and analysts raise *most consistently* across every tool in this category.

### 4.1 Static code scanning ≠ real cryptographic usage

The single most-repeated criticism, made explicitly by Keyfactor's own analysis: **"a CBOM reflects built-in capabilities but does not capture how software is configured or used in a specific organization."** A scanner can confirm a library *supports* SHA-1 and SHA-256, but not which one is actually negotiated at runtime [web:62]. This is structural, not a bug — most tools (IBM Explorer, CBOMkit, AQtive Guard) scan source/binaries, but modern cryptography is frequently a **runtime, negotiated outcome** (TLS cipher-suite negotiation, load-balancer termination, service-mesh defaults) that static analysis simply cannot see [web:62].

### 4.2 No single tool finds everything — multi-tool fatigue

NIST NCCoE testing across 47+ organizations (AWS, Cisco, Google, IBM, JPMorgan, Microsoft, NSA, CISA) explicitly concluded that **no single product finds all instances of vulnerable cryptography**, forcing enterprises into a multi-tool stitching exercise that none of the current vendors solve end-to-end [web:62]. Users repeatedly report needing IBM Explorer *and* a network-layer tool *and* a certificate-management platform just to get partial coverage.

### 4.3 Accuracy and recall figures are rarely published or independently verified

The 2026 PQC Discovery Index found that of 14 scored commercial products, **only one publishes per-detector accuracy figures**, and one open-source scanner has been independently benchmarked — every other vendor asks buyers to act on inventories without a disclosed error rate. Where a corpus was published (1,368 test cases), even the best-performing product scored a recall of only 0.7628, below its own stated integration floor, with labels that were not independently human-annotated [web:64]. This is a direct, recurring user complaint: "how do I trust a report I can't audit?"

### 4.4 Evidence integrity and tamper-evidence are almost absent

Most tools emit a CycloneDX file — a static JSON blob that can be silently edited, regenerated, or backdated with no cryptographic proof of when/how it was produced. Only two of fourteen benchmarked products document a cryptographically verifiable/tamper-evident scan record, and just one publishes a public key/procedure allowing an outside party to verify results without contacting the vendor [web:64]. For a domain literally about cryptographic trust, this is an ironic and frequently cited gap — auditors and compliance teams want provable chain-of-custody for the CBOM itself.

### 4.5 Change detection is slower than advertised

Vendors market "real-time" or "millisecond" change detection, but independent testing found the *actual* elapsed time between a real infrastructure change and its detection was closer to **~52 minutes against a 24-hour target** — the advertised low-millisecond figure was only the internal pipeline processing time, not the true detection latency [web:64]. Users who adopted tools expecting live monitoring have found this gap disappointing in incident-response scenarios.

### 4.6 Remediation is bolted on, not integrated

Discovery has converged as a commodity capability; the market's real gap is downstream — evidence integrity, change handling, quantitative risk scoring, and **closing the loop with actual remediation**. Several tools document a remediation "path in code" that has never completed a full round trip against a live ticketing system (e.g., ServiceNow/Jira) in production — meaning the promised "recommend and auto-remediate" workflow is aspirational, not proven [web:64]. This directly maps to a common user complaint: reports look good but don't actually drive a ticket, PR, or certificate rotation.

### 4.7 Certification/compliance assurance and technical capability rarely coexist in one vendor

The best *functional* discovery product in independent benchmarking held no company-level product certification of its own (only inherited cloud-infrastructure certifications), while vendors with strong certifications lagged in raw detection capability. Buyers are forced to make two separate evaluations — "does it work" and "is it approved for our regulated environment" — because no vendor currently satisfies both [web:64].

### 4.8 The "complete inventory" promise is fundamentally undeliverable

A widely cited practitioner critique (Marin Ivezic, "Rethinking CBOM") argues the entire industry framing of "inventory *all* cryptography" is close to a category error. Reasons include:
- A typical enterprise Windows estate alone may contain **80,000–500,000 certificates** — manual verification is infeasible and automated tools remain immature at this scale.
- Cryptography is frequently vendor-embedded in black-box appliances, telecom network elements, and SaaS platforms where **visibility is contractually, not just technically, constrained**.
- The U.S. government's own 2024 White House PQC report concedes that automated inventory tools "may not identify all instances of public-key cryptography" and mandates **annual manual inventory** as a supplement — an implicit admission that every current automated tool is structurally incomplete [web:62].
- CISA's own Automated Cryptographic Discovery and Inventory strategy acknowledges only **3 of 9** required OMB M-23-02 data items can be collected via automation at all — the rest require manual collection [web:62].

Tools that market themselves as "complete" or "comprehensive" repeatedly disappoint users precisely because this completeness claim collides with reality once deployed against legacy/OT systems, embedded devices, and vendor-opaque platforms.

### 4.9 Mosca's-algorithm-style risk triage is inconsistently or shallowly implemented

The problem statement calls for applying **Mosca's theorem** (comparing data shelf-life + migration time against the expected arrival of a cryptographically relevant quantum computer, "X + Y > Z"). In practice, most commercial tools reduce this to a generic severity label (High/Medium/Low) rather than a genuine time-based risk model that ingests organization-specific data-retention periods and migration-velocity estimates. Practitioner critiques note this gap explicitly under "no quantitative harvest-now-decrypt-later model" — only one or two vendors in the entire market document anything resembling a true quantitative HNDL prioritization engine [web:64].

### 4.10 CBOM's static nature vs. the need for continuous/dynamic monitoring

A recurring theme across independent PKI Consortium analysis is that **CBOM is inherently a static snapshot**; it cannot reflect drift, has no built-in key-lifecycle management, and offers no historical/forensic query capability. This is listed as a first-class limitation across the category: "CBOM lacks tools for proactive enforcement," "historical and forensic analysis capabilities are absent," and "false positives due to outdated libraries or misconfigurations" remain unresolved pain points reported by practitioners repeatedly [web:63].

---

## 5. Summary: Complaint-to-Capability Gap Matrix

| Most-repeated user complaint | Root cause in current tools | ECDAT design implication |
|---|---|---|
| "Report says a library is used but we never actually call it" | Static analysis conflates "provides" with "uses" | Build reachability/call-graph analysis, not just import/API pattern matching |
| "I can't trust the numbers without an audit trail" | No signed/tamper-evident CBOM output | Cryptographically sign and hash-chain every scan artifact |
| "Detection missed things another tool caught" | No single-engine completeness; static-only scanning | Design a hybrid pipeline: SAST + binary/container scan + optional network/TLS telemetry |
| "Real-time claims were just pipeline speed, not true detection latency" | Marketing conflates processing time with end-to-end change detection | Benchmark and publish actual detection-to-change latency, not internal processing time |
| "Recommendations never turned into an actual fix" | Remediation loop undemonstrated against live ticketing/CI systems | Native, tested bi-directional integration with Jira/ServiceNow/GitHub PRs |
| "Risk scores felt generic, not tied to our real data lifetimes" | Shallow High/Medium/Low labels instead of true Mosca-theorem math | Implement a parametrized Mosca calculator (X = data lifetime, Y = migration time, Z = CRQC arrival estimate) per asset, not per system |
| "Tool claimed 'complete' coverage but missed legacy/OT/vendor black-box systems" | Marketing overpromises completeness that policy bodies themselves say is unattainable | Explicitly model and surface "Known Unknowns" / confidence scores instead of implying 100% coverage |
| "No idea if the report is still accurate a month later" | CBOM treated as a one-time static deliverable | Build continuous re-scan + drift-detection with versioned CBOM history |

---

## 6. Takeaway for ECDAT

The market has already solved *what format* a cryptographic inventory should take (CycloneDX CBOM). What none of the current leaders — including IBM, SandboxAQ, and Keyfactor — have solved is **trustworthy, provably accurate, continuously current, and actionably remediated** cryptographic risk intelligence. ECDAT's competitive opening is not "build another scanner," but to close the specific gaps above: verifiable evidence integrity, genuine Mosca-theorem-based quantitative risk scoring per asset, honest confidence/coverage reporting instead of false completeness claims, and a remediation loop that is demonstrably closed-loop rather than aspirational.
