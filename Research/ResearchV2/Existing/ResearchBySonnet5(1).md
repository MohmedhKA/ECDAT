# Market Landscape Analysis for ECDAT
### Existing Cryptographic Discovery & PQC-Readiness Tools — Design Review, System Architecture, and Failure Analysis

**Prepared for:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) — Design Reference
**Scope:** Benchmarking the market-leading solutions in Cryptographic Bill of Materials (CBOM) generation, quantum-risk assessment, and PQC migration planning, followed by a systematic weakness analysis to guide ECDAT's differentiated design.

---

## 1. Why This Analysis Matters

Every credible cryptographic-discovery product on the market today converges on the same standard artifact — the **Cryptography Bill of Materials (CBOM)**, formalized as an extension of OWASP CycloneDX v1.6 (ratified as ECMA-424) and expanded in CycloneDX v1.7 with a dedicated Cryptography Registry [web:51][web:62]. This means ECDAT is not entering a greenfield space — it is entering a market where the *output format* is largely settled, but the *quality, trustworthiness, and operational usefulness* of the underlying discovery engines is where every vendor is still struggling. Understanding exactly where today's leaders fall short is the fastest path to a genuinely differentiated ECDAT design.

---

## 2. The Market Leaders: Solution Approach and System Design

### 2.1 IBM Quantum Safe Explorer (part of IBM Quantum Safe Suite)

IBM is generally regarded as the reference implementation for CBOM, since IBM Research co-authored the CycloneDX CBOM extension itself [web:62].

**Solution approach:**
Quantum Safe Explorer performs **static source-code and binary analysis** to locate cryptographically relevant API calls, then builds a call graph that maps "implements" and "uses/dependsOn" relationships between libraries, algorithms, and application code [web:57][web:61]. It flags weak/quantum-vulnerable primitives (e.g., RSA, ECDSA, SHA-1) directly against a severity-mapped vulnerability knowledgebase.

**System design:**
- **Delivery surfaces:** a VS Code IDE extension (local developer scans, <5 min setup), a standalone CLI (for CI/CD pipeline integration via Jenkins/GitHub Actions/Tekton), and a REST API [web:17][web:10].
- **Scan pipeline:** two distinct passes — an "API Discovery Scan" (broad, language-agnostic pattern matching) followed by a language-specific "Cryptographic Analysis Scan" (deep semantic analysis, currently richest for Java) [web:2][web:19].
- **Knowledge base externalization:** detection signatures for libraries (JCA, Bouncy Castle, OpenSSL, Python `Crypto`, etc.) are stored outside the analysis engine, so new libraries can be added without re-engineering the scanner [web:17].
- **Outputs:** per-repo `.json` CBOM, `.csv` inventories, and `Findings.json`, which feed into a central "CBOM Store" and downstream governance/dashboard layers (e.g., IBM's internal Developer Data Lake) [web:10][web:17].
- **Language coverage:** Java, Python, C, C++, C#, Go, Dart, with expanding platform support (Z/LinuxONE added in 2025) [web:65].
- **Ecosystem tie-in:** feeds IBM Quantum Safe Advisor (risk scoring) and Remediator (patch generation), forming an end-to-end Discover→Assess→Remediate pipeline.

### 2.2 SandboxAQ AQtive Guard (built on the acquired Cryptosense engine)

**Solution approach:**
AQtive Guard frames itself as an "end-to-end cryptographic management platform," combining discovery with continuous **vulnerability and compliance analysis** and non-human-identity (service accounts, API keys, machine credentials) security [web:42][web:44].

**System design:**
- **Sensors:** modular scanning agents that analyze networks, filesystems, or applications and generate "trace files," which are then normalized into a "Profile" for cross-project comparison [web:47].
- **Dashboard-centric UX:** a web interface gives an "up-to-date visualization of cryptographic inventory and health across all projects," emphasizing drill-down interactivity rather than static reports [web:49][web:50].
- **AQtive Guard Protect module:** extends discovery into runtime protection of non-human identities, positioning the product beyond pure inventory into active governance [web:48].
- **Open Cryptography initiative:** a public-facing crowdsourced crypto-risk database, used as a marketing/community differentiator and threat-intel feed [web:52].

### 2.3 Keyfactor AgileSec Platform

**Solution approach:**
Keyfactor's philosophy, distilled from its own published critique of CBOM, is explicit: *"make your cryptographic footprint visible"* first, then tie every artifact to **business-critical use cases**, not just technical existence [web:60]. It positions itself less as a scanner and more as a full **PKI/certificate lifecycle management** platform with discovery bolted on.

**System design:**
- Strong emphasis on certificate and key **lifecycle automation** (issuance, rotation, revocation) rather than only static-code discovery — differentiating it from IBM/SandboxAQ's code-first approach.
- Explicitly separates "capability" (what a library *can* do) from "configuration" (what is *actually* used) — a distinction most competitors gloss over [web:62].

### 2.4 IBM CBOMkit (Open Source Reference Architecture, Linux Foundation)

Because CBOMkit is open-sourced, its architecture is the most transparent public reference for how a CBOM engine is actually built, and is highly relevant for ECDAT's own design:

| Component | Function |
|---|---|
| CBOMkit-Hyperion | SonarQube plugin; static source-code scanning (Java, Python) |
| CBOMkit-Theia | Container image and directory/filesystem scanning |
| CBOMkit-Coeus | Web-based CBOM viewer (the GUI layer) |
| CBOMkit-Themis | Compliance engine with built-in quantum-safe policy checks |
| CBOMkit-Action | GitHub Action for CI/CD-native scanning |

This modular, pipeline-composable architecture (scan → normalize → store → visualize → enforce policy) is effectively the emerging industry reference pattern, and closely mirrors what the ECDAT problem statement itself asks for (repo/binary/container scanning → CBOM → GUI) [web:62].

### 2.5 Emerging/Adjacent Players

Quantum Xchange CipherInsights, CryptoNext COMPASS, InfoSec Global AgileSec Analytics, AppViewX, and O3 Security round out the competitive set, generally differentiating on **remediation workflow depth** (ticketing integration, certificate rotation automation) or **quantitative harvest-now-decrypt-later risk scoring** rather than on discovery breadth, which has already converged across the market [web:64].

---

## 3. Common System Design Pattern Across Leaders

Despite marketing differences, nearly every leading tool converges on the same five-stage pipeline — useful as an architectural baseline for ECDAT:

1. **Multi-surface scanners** — static source code, binaries/bytecode, container images, and (less commonly) network traffic/TLS handshakes.
2. **Externalized detection knowledge base** — pattern libraries per language/library, decoupled from the core engine for extensibility.
3. **Standardized CBOM output** — CycloneDX JSON, en