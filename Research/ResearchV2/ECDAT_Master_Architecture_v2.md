# ECDAT Master Architecture v2
### Synthesized from 12 independent research reports (2 rounds × 6 models) + direct source verification

**Status:** This supersedes the architecture sections of the original plan file; the market-landscape and Mosca-critique sections there still stand. This file is the "what to actually build" answer.

**Confidence key carried over:** 🟢 verified this session · 🟡 corroborated across 3+ independent reports · 🔵 single-report proposal, architecturally sound, not yet cross-corroborated · ⚠️ vision/aspirational — do not promise as a working deliverable

---

## 1. On "99.9%"

Not a real target — the honest range for this problem, per the actual state of the art, is high-80s to mid-90s in narrow cases and mid-70s in messy real-world ones:

- IBM Research Cryptoscope 🟢: 92% exact recall, 97% precision (curated Java benchmark).
- Näther & Hirsch, "Hidden Ciphers and Where to Find Them" 🟢 (arXiv:2608.04857, submitted Aug 5, 2026 — this week): F1 = 0.75 on 10 real production services, 57,610 files, 6 minutes scan time, 370 assets found including 6 CVE-linked vulnerabilities and 52 PQC migration candidates.

Claiming 99.9% would mean claiming to beat IBM Research's best published static-analysis effort by a wide margin. **The actual differentiator is publishing an honest number and an explicit unknowns ledger instead of an unverifiable one.** Two of the twelve reports reached this same conclusion independently — treat it as validated, not just my opinion.

---

## 2. Converged Architecture (3+ independent reports agree — build this)

### 2.1 Evidence-centered graph, not a scanner + dashboard 🟡
Every report proposed a version of this. Converged shape: each cryptographic finding is a node carrying **provenance, confidence, and an explicit state** — not a flat CBOM row.

Minimum state taxonomy (synthesizing the clearest version, from Sonnet5 round 2):
- `E0` unconfirmed hypothesis (string match only)
- `E1` static artifact (symbol/API call found)
- `E2` reachable path (call graph confirms reachability)
- `E3` configuration-confirmed (deployed config enables it)
- `E4` runtime-observed (seen executing)
- `E5` correlated (static + config + runtime agree, signed)

**Critical design rule, stated identically across multiple reports:** absence of dynamic evidence is not evidence of absence. A finding that's `E1`/reachable but never observed at runtime must be labeled `not_observed_during_coverage_window`, never silently dropped or silently trusted.

### 2.2 eBPF as the default dynamic mechanism, not JVM agents/LD_PRELOAD 🟡
Corroborated by 4+ reports, and reinforced by a new finding this round: invasive instrumentation isn't just an SRE-adoption problem, it's an outright **compliance blocker** in DO-178C (aerospace) and IEC 62443 (industrial control) certified environments — third-party runtime agents are prohibited by the certification regime itself, not by preference. eBPF uprobes on `libssl`/`libcrypto` entry points, reading only function arguments (cipher IDs, key-size flags) from CPU registers, never touching key material or memory buffers, reported at <1.5% CPU overhead. This also satisfies FIPS 140-3 zeroization requirements, since no secret material is ever copied.

### 2.3 CBOM extension addressing the real, standard-acknowledged gap 🟡
Three reports independently built a JSON extension adding intended-use, data-lifetime, and reachability fields — directly answering the gap the CycloneDX maintainers themselves are discussing in `discussions/966`. Converged minimum field set:
```json
"attestations": {
  "reachabilityProof": { "status": "reachable|unreachable|conditional|unknown" },
  "dataLifetime": { "value": 20, "unit": "years", "source": "inferred|declared|default", "confidence": 0.7 },
  "runtimeExecutionStatus": "confirmed|not_observed|unsupported_surface",
  "adversarialExposure": { "publicInternetEgress": true, "harvestProbability": 0.0_to_1.0 }
}
```
Export standard CycloneDX for interoperability; keep this as an ECDAT-specific attestation layer on top, not a fork of the standard itself — multiple reports converged on this "don't corrupt the standard" principle independently.

### 2.4 Stochastic Mosca, X/Y/Z as distributions 🟡
Already established in this project; reinforced by every report this round. Converged refinement worth adopting: **Y should be partly derived from data-lineage tooling where an org already has it** (OpenLineage, Apache Atlas, cloud data-catalog tags), not purely user-declared — use existing metadata as a *signal*, always with a human-confirm step, never as silent authority.

### 2.5 PQC network/MTU impact as an active test, not a static warning 🔵→🟡 (2 reports)
Genuinely new this round and well-grounded: before recommending an algorithm, actively determine whether the target network path can carry it.
- Send DF-bit-set probe packets to determine real path MTU and whether middleboxes drop non-initial fragments.
- Classify each route: `Profile-Standard` (1500 MTU, strict fragment filtering), `Profile-Flexible` (reassembly verified), `Profile-Constrained` (<1280 MTU — VPNs, cellular).
- Recommend the algorithm/compression combination that actually fits the verified path, not a generic "use ML-KEM-768."
- **A specific, checkable number worth using in the pitch:** ML-DSA-65's 51.7x size expansion over ECDSA P-256 (independently confirmed by both my own earlier arithmetic and this round's reports) means a single ML-DSA-65 certificate plus an ML-KEM-768 handshake can exceed 7KB before the connection has done anything — several times a standard 1500-byte MTU.

### 2.6 Signed evidence provenance via SLSA/in-toto, not a bespoke scheme 🔵
One report proposed this specifically, and it's a better foundation than my own earlier Merkle-commitment idea: SLSA and in-toto are real, existing, actively-maintained supply-chain attestation standards (the same ones used for build provenance). Reuse their model — subject digest, tool/version, signed manifest, optional transparency-log entry — instead of inventing a new evidence format. Lower engineering cost, and "we used the standard supply-chain attestation model" is a stronger claim than "we invented our own."

---

## 3. Single-report ideas worth adopting (architecturally sound, not yet cross-corroborated)

- **Uncertainty as a separate axis from risk** (Sonnet5 round 2): a low-confidence finding should raise *investigation priority*, not *risk score* — conflating the two means a scanner's own uncertainty gets mistaken for a confirmed vulnerability. Clean, correct distinction, worth keeping.
- **Negative proof instead of bare "not found"** (Sonnet5 round 2): report what was actually checked (commit hash, binary digest, N production entry points, M observed requests) alongside a clean result, not just an absence claim. Far more defensible to an auditor.
- **Migration as a Pareto/portfolio optimization** (multiple round-2 reports, converging with the Markowitz idea from earlier in this project): rank remediation actions by risk-reduction-per-effort rather than a flat severity sort — this was independently proposed by outside research too, which is good corroboration of the earlier from-finance idea.

---

## 4. Explicitly vision, not roadmap — say this out loud in the pitch, don't promise it as built

- **Fully automated, SMT-verified (Z3) code remediation with auto-generated compatibility shims.** Two reports propose this as a near-term phase. Formally verified automated program repair for cryptographic code is an open research problem in its own right — worth describing as the long-term direction (it makes the pitch sound ambitious and technically literate), but never as something the team will demo working end-to-end. If a judge asks "does this actually work," the honest answer is "not yet, and here's why that's a hard problem, not a scoping oversight."
- **GNN-based binary crypto detection on stripped firmware.** Real research area, not fabricated, but requires a trained model and real evaluation data neither this team nor most vendors currently have. Cite it as the right long-term answer for OT/embedded coverage, not a working feature.
- **Synthetic in-kernel network-bloat emulation** (injecting simulated PQC-sized padding into real traffic via eBPF to pre-test middlebox behavior): clever, plausible, genuinely buildable in spirit — but scope it down for a real demo to a *passive* MTU/fragmentation probe (§2.5) rather than the more ambitious *active traffic injection* version, which risks tripping IDS systems and needs real production safety guarantees before anyone would run it.

---

## 5. Sources added this round

- Näther & Hirsch, "Hidden Ciphers and Where to Find Them: Static Discovery and Assessment of Cryptographic Assets in Software," arXiv:2608.04857, submitted Aug 5, 2026 — the strongest, most current, most directly relevant academic source found in this entire project. Read this one directly if you read only one paper.
- SLSA / in-toto attestation model: slsa.dev, in-toto.io
- CycloneDX Discussion #966 (already in the main plan file, reused here as the schema-gap citation)
- Cross-referenced but not independently re-verified this round (already confirmed in the main plan/market files): Cryptoscope (arXiv:2503.19531), CRYLogger, CRYScanner, NIST IR 8547, OMB M-26-15, PQCA/CBOMkit.
