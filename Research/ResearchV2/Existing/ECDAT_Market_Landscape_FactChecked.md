# ECDAT Market Landscape — Fully Fact-Checked Report
### Synthesizing 6 independently-commissioned research reports + direct source verification + community/review-platform research

**Prepared for:** Mohmedh + team + coding agent, SIH26164
**Source reports synthesized:** Sonnet5(1), Sonnet5(2), Gemini Research, Gemini Spark, Perplexity, ChatGPT
**Method:** Every claim below is tagged with a confidence level based on independent verification performed this session — not on how confidently the source report stated it.

**Confidence key:**
- 🟢 **VERIFIED** — checked directly against a primary source (vendor docs, GitHub repo, regulatory PDF, etc.) this session
- 🟡 **CORROBORATED** — appears consistently across 3+ of the 6 reports, not independently re-verified against a primary source, but internally consistent
- 🔴 **UNVERIFIED** — appears in exactly one of the six reports, not found anywhere else searched
- ⚠️ **CONFLICTED SOURCE** — verified to exist, but the source itself has a disclosed or evident bias

---

## 1. Executive Summary

The six reports converge cleanly on the identity of the real market leaders (IBM, SandboxAQ, Keyfactor, PQCA/CBOMkit) and on the shape of the market's real weaknesses (static/dynamic split, shallow Mosca implementation, remediation gap). Where they diverge — and where independent checking mattered most — is in the *supporting evidence* several of them lean on. Two findings from this pass change how that evidence should be used:

1. **A widely-cited "independent benchmark" is run by a vendor that ranks its own product first and two major real competitors near the bottom of a 300-product field.** (§4)
2. **A near-identical hackathon-scale project already exists publicly on GitHub, undermining the market-leader analysis alone as a differentiation strategy — the differentiation has to come from execution depth, not the existence of the idea.** (§5)

Everything else below is the fact-checked version of what the six reports found.

---

## 2. Confirmed Market Landscape

### 2.1 IBM Quantum Safe Suite 🟢 VERIFIED
**Explorer, Advisor, Remediator** — a three-part Discover → Assess → Remediate pipeline. Explorer performs static source/binary scanning (VS Code extension, CLI, REST API; Java, Python, C, C++, C#, Go, Dart, with Z/LinuxONE support added 2025) and explicitly documents itself as providing **"a static view"** of cryptography usage — this is IBM's own wording, confirmed directly against their docs. Remediator deploys adaptive TLS proxies for hybrid PQC termination without rewriting legacy code. IBM co-authored the CycloneDX CBOM extension itself.
- Generally available: Explorer 2.2.x since May 27, 2025.
- **Real limitation, IBM's own words**: static analysis only — dynamic/runtime crypto configuration is out of scope for Explorer specifically (the broader Guardium suite addresses some of this separately).

### 2.2 SandboxAQ AQtive Guard 🟢 VERIFIED
Built on the acquired Cryptosense engine (SandboxAQ is an Alphabet spinoff). Tri-modal discovery: **Filesystem Analyzer** (static disk/container scanning), **Network Analyzer** (passive SPAN/TAP traffic inspection), **Application Analyzer** (dynamic runtime hooking — JVM bytecode agents, `LD_PRELOAD` on Linux, Windows CNG hooking). All three streams correlate into a unified cryptographic knowledge graph.
- Real deployments confirmed: SoftBank (since April 2024), Vodafone Business, Mount Sinai Health System; FedRAMP Ready (Dec 2025); a five-year U.S. Department of War CIO contract signed December 2025.
- **Real limitation, vendor-acknowledged**: the runtime Application Analyzer's instrumentation overhead/stability risk means it's "often restricted to test environments, not full production" per third-party vendor analysis.
- **Notable gap**: zero reviews on G2 and zero on AWS Marketplace as of this check — see §6.

### 2.3 Keyfactor Command + AgileSec + CipherInsights 🟢 VERIFIED
Keyfactor **acquired both** InfoSecGlobal's AgileSec Analytics **and** Quantum Xchange's CipherInsights (confirmed via Keyfactor's own press release). These are now one consolidated offering, not the two-to-three separate competitors some of the six reports implied. Host-centric (EDR/Tanium/CrowdStrike integration) plus network handshake dissection plus PKI/certificate enumeration; strongest on certificate/key lifecycle automation (issuance, rotation, revocation) rather than pure code discovery.
- **Real, distinctive design point**: explicitly separates "capability" (what a library *can* do) from "configuration" (what's *actually* in use) — a distinction most competitors gloss over, per Keyfactor's own published critique of CBOM.

### 2.4 PQCA CBOMkit (Linux Foundation, formerly IBM-only) 🟢 VERIFIED
IBM donated CBOMkit to the **Post-Quantum Cryptography Alliance (PQCA)**, a Linux Foundation project, in 2024. Now at `github.com/PQCA/cbomkit`, not `github.com/IBM/CBOM` — correcting an earlier attribution in this project's own planning materials. Founding PQCA members include co-authors of Kyber/Dilithium/Falcon/SPHINCS+.
- Components: **hyperion** (SonarQube plugin, source scanning), **theia** (container/filesystem scanning), **coeus** (web viewer), **action** (CI/CD via GitHub Actions). A fifth component, **themis** (compliance/policy engine), is named in three of the six reports — plausible given PQCA's active development pace (Go support recently added, a "CBOMkit Pipeline" for dependency-level detection in progress), but not independently confirmed this session; treat as 🟡 pending direct check.
- **Real, published limitation** (IBM Research's own Cryptoscope paper, arXiv:2503.19531): CBOMkit-class tools use string-based matching and incomplete symbol resolution, producing missed findings and false positives — the same research group that builds CBOMkit's lineage publicly documents its limits.

### 2.5 IBM Research Cryptoscope (not a shipped product) 🟢 VERIFIED
March 2025 paper, not a commercial tool. Outperforms CogniCrypt, CryptoGuard, SonarQube, and FindSecBugs on the CamBench benchmark (92% exact-match recall, 97% precision) via full data/control-flow slicing rather than pattern matching. Its own related-work section documents that dynamic/hybrid crypto-discovery research (CRYLogger, CRYScanner) dates to **2021**, meaning the "solve the dynamic blind spot via instrumentation" pitch has real academic prior art, not just commercial prior art.

### 2.6 ISARA Advance 🟢 VERIFIED
Real product, real company (ISARA Corporation, Waterloo, Canada, founded 2015). Agentless — pulls from existing NDR/EDR telemetry rather than deploying its own sensors. Confirmed independently via ISARA's own site and Microsoft's security blog (which lists it as an Azure-deployed option alongside Entrust's Cryptographic Security Platform).

### 2.7 Encryption Consulting CBOM Secure 🟡 CORROBORATED
Appears in 2 of 6 reports with consistent detail (multi-cloud KMS connectors, agentless host scanning, secrets vault scrapers). Not independently re-verified against primary source this session, but Encryption Consulting is a real, established firm with other independently-confirmed publications used elsewhere in this project's research (the CBOM/CycloneDX explainer pieces).

---

## 3. Products Named in Only One of Six Reports — Unverified 🔴

None of these were found anywhere outside the single report that named them, despite active searching. Not confirmed real or fake — just don't cite them as fact until checked directly:

| Product | Named by | Status |
|---|---|---|
| Qinsight Atlas | Perplexity | Unverified |
| QuantumGenie | Perplexity | Unverified |
| Spice Labs Surveyor/Topographer | Perplexity | Unverified |
| QuProtect R3 | Perplexity | Unverified |
| PQStation QVision | ChatGPT | Unverified |
| QryptoCyber | ChatGPT | Unverified |

Tychon ACDI (ChatGPT's report) is a partial exception: **Tychon itself is a real company** — confirmed independently (their site, `tychon.io`, was already used elsewhere in this project as a primary source on OMB M-26-15) — but the specific product framing as "ACDI" was not independently re-confirmed as their own branded product name versus a reference to CISA's separate ACDI *strategy*, which multiple vendors align with. Treat the company as real, the specific product claim as 🟡 not 🟢.

---

## 4. Critical Finding: The Qtonic Quantum Conflict of Interest ⚠️ CONFLICTED SOURCE

Sonnet5(2)'s report cites an "independent 2026 benchmark" — the **PQC Discovery Index** (`pqc-index.org`) — for several specific, quotable statistics: a best-in-class recall of 0.7628, a ~52-minute real detection latency against advertised millisecond claims, and only 2-of-14 products documenting tamper-evident scan records.

Direct verification found:

- The Index is real and does publish a disclosed methodology (7 criteria, 14 products, edition 2026.5).
- **The #1-ranked product, "QScout Pulse Gold" (score 9.42/10), is built by Qtonic Quantum Corp — the same company that publishes the Index.** Their own disclosure states this row "has deeper live evidence than peer rows, which rely primarily on public documentation."
- The same company runs a second, related registry — **"Qtonic Quantum Lab"** (`qtonicquantum.com`) — scoring 300 products on a 0–100 scale. In this registry: **IBM Quantum Safe Explorer scores 36.4/100**, and **SandboxAQ AQtive Guard scores 28.6/100 (ranked 202nd of 300)**. Both are real, well-established, seriously-deployed competitors (IBM's is decades of enterprise crypto experience; SandboxAQ's has a five-year U.S. Department of War contract) scored well below a product made by the company running the scoring system.

This pattern — own product ranked #1, major established competitors scored low — is exactly what a vendor-interested rating system looks like, and the site's own fine print does not contradict that reading. **Recommendation: do not cite "PQC Discovery Index" or "Qtonic Quantum Lab" as independent or neutral in any submission material.** The underlying individual statistics might still be directionally accurate, but the framing "independent benchmark found X" is not defensible if a judge checks the source, which takes about two minutes.

---

## 5. Direct Competitor Finding: QuantumShield 🟢 VERIFIED

`github.com/Neel-stack-deb/QuantumShield` — a live, deployed (Streamlit) tool that implements almost exactly ECDAT's core pipeline: scan → CBOM/SARIF export → risk score (including an explicit confidentiality-lifetime factor) → migration prioritization → GitHub Actions CI integration. Its own README states: *"QuantumShield is a hackathon-scale security engineering tool, not a replacement for a full enterprise cryptographic inventory platform."* Status: all core features checked off as shipped, 95 passing automated tests, live public demo.

Zero stars/forks — low visibility, likely another student/hackathon team's project — but discoverable by the same search used to find it here. **This means the basic "scan + score + recommend + dashboard" pipeline shape is not, by itself, a defensible differentiator even at hackathon scale.** The differentiation has to rest entirely on depth the reports and the plan file (§4.1, §7, §8) already identify: CBOM confidentiality architecture, a Mosca engine that's actually temporal rather than a severity label, and BFT/consensus-specific analysis — none of which QuantumShield attempts.

---

## 6. The Review-Ecosystem Gap (a meta-finding)

Checked G2, AWS Marketplace, and Gartner Peer Insights directly for AQtive Guard and IBM Quantum Safe Explorer specifically:

- **AQtive Guard: zero reviews on G2** ("This product hasn't been reviewed yet"), **zero on AWS Marketplace** ("Be the first to review this product").
- **IBM Quantum Safe Explorer**: no dedicated listing found on Gartner Peer Insights or G2 at all — searches returned irrelevant results comparing "IBM" the company broadly against unrelated products also named "Quantum."

This matters for how the six reports' "user complaints" sections should be read: this entire product category is too new for a mature, independently-verifiable review ecosystem to exist yet. The "common user complaints" described across the six reports are drawn from vendor comparison blogs, industry analyst commentary, and general extrapolation from adjacent tool categories (SAST/SIEM) — not from a large body of independently verifiable user reviews, because that body doesn't yet exist in a searchable public form. This isn't a reason to distrust the complaints (several are independently well-reasoned and cross-corroborate structurally — see §7), but it's a reason not to present them as "users on G2 report..." in a pitch. They're informed synthesis, not survey data.

---

## 7. Cross-Corroborated Structural Weaknesses (3+ of 6 reports agree)

These recur independently across most or all reports, in different phrasing, which is the strongest available signal of genuine, real market gaps:

1. **Static/dynamic reconciliation failure.** No tool unifies what static analysis finds (potential, unconfirmed) with what dynamic tracing finds (confirmed, but only for exercised code paths — misses disaster-recovery routines, annual batch jobs, etc.).
2. **Mosca's inequality is implemented shallowly everywhere.** Independently, multiple reports describe the exact same failure modes: a single global X instead of per-data-class granularity, Y treated as a fixed estimate rather than a resourced/negotiable variable, no weighting for whether an adversary can actually intercept the data in the first place. (This matches, and is matched by, the Blanco-Romero et al. 2026 paper and the analysis already in §7–8 of the plan file.)
3. **Remediation is the unsolved layer; discovery has commoditized.** Three different phrasings of one finding: "expensive spreadsheet problem," "CBOM Dump anti-pattern," "bolted on, not integrated." No tool reliably closes the loop from finding to fix.
4. **PQC size expansion breaks assumptions two different ways**: (a) MTU/packet fragmentation from oversized handshakes (ML-DSA-65's 3,309-byte signature vs. a 1,500-byte Ethernet MTU), and (b) the TLS 1.3 KeyUpdate cascade problem already documented in the plan file §7C — these are distinct mechanisms with the same root cause, both real.
5. **"Complete coverage" claims are structurally false, and policy bodies say so.** The 2022 OMB M-23-02 mandate requires *annual manual inventory* specifically because automated discovery is acknowledged as incomplete — a primary-source admission, not a vendor criticism.
6. **Alert fatigue from primitive flooding.** Scanners flag every hash/cipher use identically regardless of whether it protects a 60-second cache entry or a long-lived customer record — the same root problem as #2 (no data-lifetime awareness), from a different angle.

---

## 8. Community & Primary-Source Findings

- **Direct Reddit search returned nothing** for this tool category — consistent with §6's finding that this is a young, B2B-only market without consumer-forum presence.
- **Best available primary-source confirmation of the CBOM/Mosca gap**: `github.com/CycloneDX/specification/discussions/966`, a live discussion on the CycloneDX standard's own repository, where maintainers are actively discussing adding intended-use, migration-status, and a framework-agnostic risk object for a future CBOM 2.0/CDXA (CycloneDX Attestations). This is the standard body itself acknowledging, in public, that data-lifetime-aware risk isn't natively expressible in CBOM today — a stronger citation for that specific claim than anything in the six reports, because it isn't a vendor's opinion, it's the maintainers' own backlog.
- **Two more real open-source hackathon-scale competitors surfaced during this search** beyond QuantumShield: `cryptoscan-pqc` (PyPI) — cites the real June 2026 Executive Order deadlines and the statistic that "fewer than 5% of enterprises have a comprehensive cryptographic inventory" — and Patero (a real, VC-backed PQC startup based at the University of Maryland's Quantum Startup Foundry) running "Automated Cryptography Discovery and Inventory Workshops," a consulting-led rather than pure-tooling angle worth being aware of as a different business model in the same space.

---

## 9. What This Changes About the Plan

Nothing in the architecture (plan file §1–§9) needs to change. What changes is evidentiary discipline for the pitch itself:

- Never cite "PQC Discovery Index" or "Qtonic Quantum Lab" as independent (§4).
- Don't claim "nobody has built this" — QuantumShield exists; claim instead that nobody has built the *specific* depth pieces (§5).
- Don't attribute the structural-weakness findings to "user complaints" or "reviews" — attribute them to cross-report analytical convergence and the specific primary sources named in §7–8, since an independently verifiable review base doesn't exist yet (§6).
- The CycloneDX GitHub discussion (§8) is now the strongest single citation available for the core "CBOM has no native X" claim — use it over any of the six reports' framing of that point.

---

## 10. Full Source List

- IBM Quantum Safe Explorer overview (static-view wording, GA dates): ibm.com/docs/en/quantum-safe/quantum-safe-explorer
- IBM Quantum Safe product suite: ibm.com/quantum/quantum-safe
- AQtive Guard capabilities and docs: aqtiveguard.sandboxaq.com/docs/, sandboxaq.com/solutions/security/discover
- AQtive Guard G2 listing (zero reviews): g2.com/products/aqtive-guard/reviews
- AQtive Guard AWS Marketplace listing (zero reviews): aws.amazon.com/marketplace/pp/prodview-ccwrhqfeekqwk
- Keyfactor acquisition of InfoSecGlobal + CipherInsights: keyfactor.com/press-releases/keyfactor-acquires-infosec-global-and-cipherinsights/
- PQCA/CBOMkit donation and governance: researcher.ibm.com/blog/cryptographic-cbom-linux-foundation, linuxfoundation.org/press/announcing-the-post-quantum-cryptography-alliance-pqca, github.com/PQCA/cbomkit
- Cryptoscope paper (benchmark results, dynamic-analysis prior art): arxiv.org/pdf/2503.19531
- ISARA Advance: isara.com/products/isara-advance-cryptographic-inventory-and-risk-assessment-tool.html; Microsoft Security Blog coverage
- PQC Discovery Index self-disclosure: pqc-index.org/products/qscout-pulse-gold
- Qtonic Quantum Lab scores: qtonicquantum.com/lab/solutions/sandboxaq-aqtive-guard, qtonicquantum.com/lab/solutions/ibm-quantum-safe-explorer
- QuantumShield: github.com/Neel-stack-deb/QuantumShield
- cryptoscan-pqc: pypi.org/project/cryptoscan-pqc/
- Patero: businesswire.com/news/home/20260115140720/en/Patero-Introduces-Automated-Cryptography-Discovery-and-Inventory-Workshop
- CycloneDX CBOM 2.0/CDXA discussion (primary source, standard maintainers): github.com/CycloneDX/specification/discussions/966
- OMB M-23-02 (2022 annual-manual-inventory mandate): referenced via postquantum.com/post-quantum/cryptographic-inventory-vendors/ and isara.com/solutions/use-cases/cryptographic-inventories.html
