# ECDAT Codebase vs. MY-Plan-V2 — Exhaustive Gap Analysis & Change Manifest

**Date:** 2026-09-11
**Source:** Line-by-line analysis of all 25 Python source files against [MY-Plan-V2.md](./MY-Plan-V2.md)
**Purpose:** Identify every change, addition, and refactor required to transform the current ECDAT v0.1.0 into the MY-Plan-V2 specification.

---

## TABLE OF CONTENTS

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Snapshot](#2-current-architecture-snapshot)
3. [Pillar-by-Pillar Gap Analysis](#3-pillar-by-pillar-gap-analysis)
4. [File-Level Change Manifest](#4-file-level-change-manifest)
5. [New Files Required](#5-new-files-required)
6. [Test Coverage Gap](#6-test-coverage-gap)
7. [Dependency Changes](#7-dependency-changes)
8. [Cross-Cutting Concerns](#8-cross-cutting-concerns)
9. [Prioritized Implementation Order](#9-prioritized-implementation-order)

---

## 1. EXECUTIVE SUMMARY

### Scorecard: Current vs. Plan

| Dimension | Current State | Plan Target | Gap Severity |
|---|---|---|---|
| **Discovery (Scanning)** | Regex + AST for 4 languages, Theia bridge, manifest parsing | Same + schema extraction + config parsing + K8s manifest parsing | MODERATE |
| **Risk Model (Mosca)** | Deterministic scalar: $Y_{\max} = Z - X$ | Stochastic Monte Carlo: $P(X+Y>Z)$ with $P_{\text{HNDL}}$ and $A_{\text{CAMS}}$ | CRITICAL |
| **Intent Classification** | None | 4-class DSIS forward taint (OP_UTIL, INTEG, AUTH, CONF) | CRITICAL (new) |
| **Evidence Taxonomy** | Flat `CryptoAsset` with single `x_confidence` string | E0-E5 state machine with promotion history + Unknowns Ledger | CRITICAL (new) |
| **Data Lifetime ($X$)** | 4-tier manual lookup table in `constants.py` | Auto-extracted from SQL DDL, ORM schemas, TTL indices | MAJOR (new) |
| **Network Exposure ($P_{\text{HNDL}}$)** | None | K8s/Docker manifest parser for deployment exposure scoring | MAJOR (new) |
| **Agility Scoring (CAMS)** | Buffer hazard audit only (Python AST) | 4-level agility maturity detection (Rigid → Runtime Agile) | MAJOR (new) |
| **MTU Probing** | Static buffer check (`buf < 3309 B`) | Active DF-bit PMTUD probing with route profiles | CRITICAL (new) |
| **Attestation** | Custom SHA-256 Merkle tree, unsigned JSON CBOM | SLSA/in-toto signed envelopes + Ed25519/ML-DSA hybrid | MAJOR (upgrade) |
| **Remediation Planning** | Flat severity sort by $Y_{\max}$ | Pareto portfolio optimization: $\max \Delta R / \text{Cost}$ | MAJOR (new) |
| **Report & Dashboard** | 7-tab HTML with D3 contagion graph | Same + MTU tab + Pareto frontier + E0-E5 heatmap + info banners | MODERATE (upgrade) |

### Summary Metrics

- **Existing source files that need modification:** 12 of 14 non-empty Python files
- **New source files required:** 11-14 new modules
- **New test files required:** 7-9 new test files
- **Estimated total new code:** ~3,500-5,000 lines
- **Estimated refactored code:** ~800-1,200 lines of existing code

---

## 2. CURRENT ARCHITECTURE SNAPSHOT

### Module Map (25 files, 14 non-trivial)

```
ecdat/
├── __init__.py                    (0 lines — empty package marker)
├── models.py                      (47 lines — CryptoAsset, MoscaScore, XTier, PrimitiveType)
├── constants.py                   (97 lines — OMB schedule, GRI probs, NIST sizes, X-tier defaults)
├── pipeline.py                    (362 lines — main orchestrator, CLI, CycloneDX output)
├── report.py                      (200 lines — CISO Markdown report generator)
│
├── scanners/
│   ├── __init__.py                (re-exports theia_bridge only)
│   ├── filters.py                 (28 dir exclusions, 4 regex patterns)
│   ├── source_scanner.py          (~450 lines — regex JS/TS/Go/Rust patterns, shredding context)
│   ├── manifest_scanner.py        (~300 lines — npm/cargo/go.mod/requirements.txt, 23 known libs)
│   └── theia_bridge.py            (~350 lines — Go binary bridge, X.509 ASN.1, dedup)
│
├── x_inference/
│   ├── __init__.py                (0 lines — empty)
│   ├── ast_tracer.py              (~200 lines — Python AST taint visitor, CryptoTaintVisitor)
│   └── sink_stubs.py              (~100 lines — 4-tier sink signature catalog)
│
├── mosca/
│   ├── __init__.py                (0 lines — empty)
│   └── engine.py                  (~200 lines — deterministic Y_max = Z - X)
│
├── contagion/
│   ├── __init__.py                (docstring only)
│   └── engine.py                  (~350 lines — NetworkX DiGraph, R0, superspreaders, D3 JSON)
│
├── agility/
│   ├── __init__.py                (0 lines — empty)
│   ├── buffer_audit.py            (~180 lines — Python AST buffer overflow detection)
│   └── recommender.py             (~250 lines — PQC migration rule engine)
│
├── merkle/
│   ├── __init__.py                (0 lines — empty)
│   ├── tree.py                    (~200 lines — SHA-256 Merkle tree, selective disclosure)
│   └── verifier.py                (~100 lines — CLI proof verifier)
│
└── dashboard/
    ├── __init__.py                (re-exports generate_html_dashboard)
    └── generator.py               (~2,057 lines — monolithic HTML/JS/CSS report generator)
```

### What Works Well (Foundations to Keep)

1. **Polyglot regex scanner** — covers JS/TS/Go/Rust with PQC patterns (ML-DSA, ML-KEM). Keep.
2. **Python AST taint analysis** — real `ast.NodeVisitor` with proper tokenization. Keep and extend.
3. **Theia bridge** — sophisticated X.509 ASN.1 parsing with content-addressable dedup. Keep.
4. **Contagion $R_0$ graph** — epidemiological model with NetworkX is unique. Keep and extend.
5. **Merkle tree** — selective disclosure proofs with WebCrypto verification. Keep and upgrade.
6. **Buffer hazard audit** — AST-based Python buffer detection. Keep and extend.
7. **PQC recommender** — hybrid-first migration with NIST/IETF citations. Keep and extend.
8. **Dashboard** — 7-tab interactive HTML with D3, KaTeX, glassmorphism. Keep and extend.
9. **Manifest scanner** — 4 ecosystem support with 23 known crypto libraries. Keep and extend.

---

## 3. PILLAR-BY-PILLAR GAP ANALYSIS

---

### PILLAR 1: DSIS Intent Classification — GAP: CRITICAL (Entirely New)

**Plan Requires:**
- 4-class security lattice: `OPERATIONAL_UTILITY`, `INTEGRITY_CHECKSUM`, `AUTHENTICATION_SIGNATURE`, `CONFIDENTIALITY_ENVELOPE`
- Forward taint slicing from crypto output to terminal sink
- Language-specific sink signature maps
- 90%+ alert suppression for operational utility uses

**Current State:**
- `source_scanner.py` has a `_check_crypto_shredding_context()` that scans a ±20-line window for keywords like `"redis"`, `"session"`, `"s3"`, `"archive"` — but this classifies **data lifetime** (XTier), NOT **functional intent**.
- `x_inference/ast_tracer.py` tracks crypto variables from source to sink via Python AST — but only outputs `XTier` (EPHEMERAL/SHORT_TERM/OPERATIONAL/ARCHIVAL), never intent.
- `x_inference/sink_stubs.py` has 4-tier sink signatures — but all tiers are lifespan-based, not intent-based.
- **Zero intent classification exists anywhere in the codebase.**

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| `ecdat/models.py` | ADD | New `IntentClass(str, Enum)` with 4 values |
| `ecdat/models.py` | MODIFY | Add `intent_class: IntentClass` field to `CryptoAsset` |
| NEW `ecdat/intent/classifier.py` | CREATE | DSIS forward taint classifier using existing sink infra |
| NEW `ecdat/intent/sink_signatures.py` | CREATE | Per-language intent sink signature maps (separate from lifespan sinks) |
| `ecdat/x_inference/ast_tracer.py` | MODIFY | Extend taint visitor to emit both XTier AND IntentClass |
| `ecdat/source_scanner.py` | MODIFY | Pass intent classification context alongside XTier |
| `ecdat/pipeline.py` | MODIFY | Integrate intent classifier into pipeline, filter alerts by intent |
| `ecdat/dashboard/generator.py` | MODIFY | Add intent badge/filter to CBOM tab, add toggle to suppress OP_UTIL |
| `ecdat/report.py` | MODIFY | Group assessments by intent class, separate metrics |

**Core Design Decision:**
The intent classifier should **share the same forward-taint walk** as the existing X-inference engine. Both analyze crypto-output → sink flow, but classify along orthogonal axes:
- X-Inference: "How long does the data live?" → XTier
- DSIS: "What is the crypto protecting?" → IntentClass

The `ast_tracer.py` visitor should emit a combined result: `(XTier, IntentClass)` per tracked variable.

**Intent Sink Signature Map (Example for JavaScript):**

| Sink Pattern | Intent Class |
|---|---|
| `res.setHeader('ETag', ...)` | OPERATIONAL_UTILITY |
| `cache.set(...)`, `redis.setex(key, ttl, hash)` | OPERATIONAL_UTILITY |
| `hashMap.put(...)`, `Map.set(...)` | OPERATIONAL_UTILITY |
| `fs.writeFileSync(..., checksum)` | INTEGRITY_CHECKSUM |
| `jwt.sign(...)`, `crypto.sign(...)` | AUTHENTICATION_SIGNATURE |
| `cert.verify(...)` | AUTHENTICATION_SIGNATURE |
| `cipher.update(...)`, `crypto.createCipheriv(...)` | CONFIDENTIALITY_ENVELOPE |
| `db.query('INSERT ...', encrypted_col)` | CONFIDENTIALITY_ENVELOPE |
| `s3.putObject({Body: encrypted})` | CONFIDENTIALITY_ENVELOPE |

---

### PILLAR 2: E0-E5 Evidence Taxonomy — GAP: CRITICAL (Model Redesign)

**Plan Requires:**
- 6-level evidence state machine (E0-E5)
- Promotion history tracking
- `not_observed_during_coverage_window` status for dormant assets
- Unknowns Ledger: explicit list of uninspectable areas
- Orthogonal confidence vs. risk axes

**Current State:**
- `models.py` has `x_confidence: str = "LOW"` — a single unvalidated string, not a typed enum.
- No concept of evidence levels. An AST-detected crypto call and a regex string match get the same data model.
- No concept of promotion history, coverage window, or absence tracking.
- `source_scanner.py` produces flat assets with no distinction between regex match (should be E0) and AST-confirmed call (should be E1).
- `theia_bridge.py` discovers certificates on disk (should be E3) but stores them as the same `CryptoAsset` with no evidence level.
- No Unknowns Ledger exists anywhere.

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| `ecdat/models.py` | ADD | `EvidenceLevel(str, Enum)`: E0-E5 + DORMANT |
| `ecdat/models.py` | MODIFY | Add `evidence_level: EvidenceLevel`, `evidence_sources: List[str]`, `coverage_window: Optional[str]`, `promotion_history: List[Dict]` to `CryptoAsset` |
| `ecdat/models.py` | ADD | `ConfidenceLevel(str, Enum)`: UNVALIDATED, LOW, MEDIUM, HIGH, VERIFIED |
| `ecdat/models.py` | ADD | `UnknownEntry(BaseModel)`: area, reason, recommended_action |
| `ecdat/source_scanner.py` | MODIFY | Set `evidence_level=E0` for regex matches, `E1` for AST-confirmed calls |
| `ecdat/x_inference/ast_tracer.py` | MODIFY | Set `evidence_level=E2` when call-graph reachability confirmed |
| `ecdat/scanners/theia_bridge.py` | MODIFY | Set `evidence_level=E3` for filesystem certificates/keys |
| `ecdat/pipeline.py` | MODIFY | Collect Unknowns Ledger (excluded dirs, binary files, encrypted archives) |
| `ecdat/report.py` | MODIFY | Add Unknowns Ledger section to CISO report |
| `ecdat/dashboard/generator.py` | MODIFY | Add E0-E5 heatmap visualization, evidence badge per asset |
| `ecdat/constants.py` | ADD | `EVIDENCE_LEVEL_DESCRIPTIONS` mapping |

**Evidence Level Assignment Rules:**

| Discovery Source | Initial Evidence Level |
|---|---|
| Regex string match in `source_scanner.py` | E0 (Unconfirmed Hypothesis) |
| AST-confirmed API call in `source_scanner.py` | E1 (Static Artifact) |
| Python AST taint trace reaching entry point in `ast_tracer.py` | E2 (Reachable Path) |
| Filesystem certificate/key found by `theia_bridge.py` | E3 (Configuration-Confirmed) |
| Config file analysis (new — Pillar 3) | E3 (Configuration-Confirmed) |
| eBPF runtime observation (future — not for SIH) | E4 (Runtime-Observed) |
| Multi-source agreement + signed attestation | E5 (Correlated & Signed) |

**Unknowns Ledger Collection Points:**

| Pipeline Stage | What Gets Logged as Unknown |
|---|---|
| `filters.py` exclusions | Directories skipped by filter rules |
| `source_scanner.py` | Binary files encountered but unparseable |
| `theia_bridge.py` | Encrypted PKCS#12 keystores, password-protected keys |
| `manifest_scanner.py` | Lockfiles not parsed (transitive deps invisible) |
| `pipeline.py` | File extensions not supported (`.java`, `.c`, `.cpp`) |

---

### PILLAR 3: Autonomous $X_{\text{auto}}$ Extraction — GAP: MAJOR (New Modules)

**Plan Requires:**
- Source A: SQL DDL / migration script parsing for retention hints and TTL indices
- Source B: ORM / application model parsing (Prisma, Hibernate, Django)
- Source C: K8s/Docker manifest parsing for network exposure $P_{\text{HNDL}}$
- Integration into enriched Mosca formula: $R_Q = (X_{\text{auto}} + Y_{\text{code}} - Z_{\text{reg}}) \times P_{\text{HNDL}} \times (1 - A_{\text{CAMS}})$

**Current State:**
- `constants.py` has `X_TIER_DEFAULT_YEARS`: 4 static values (0.0, 1.5, 5.0, 10.0).
- `mosca/engine.py` uses `X_TIER_DEFAULT_YEARS.get(tier, 5.0)` — a flat lookup, never derived from code.
- `source_scanner.py` does a ±20-line keyword search for `"redis"`, `"session"`, `"s3"`, `"archive"` to **guess** XTier — but this is heuristic, not schema-derived.
- No SQL/ORM/Prisma parser exists.
- No K8s/Docker manifest parser exists.
- No $P_{\text{HNDL}}$ concept exists.

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| NEW `ecdat/schema_extractor/` | CREATE | New subpackage for schema-based X extraction |
| NEW `ecdat/schema_extractor/sql_parser.py` | CREATE | Parse `CREATE TABLE`, TTL indices, retention comments |
| NEW `ecdat/schema_extractor/orm_parser.py` | CREATE | Parse Prisma schemas, Django models, Hibernate annotations |
| NEW `ecdat/schema_extractor/ttl_detector.py` | CREATE | Detect MongoDB `expireAfterSeconds`, Redis TTL patterns |
| NEW `ecdat/exposure_scanner/` | CREATE | New subpackage for deployment exposure |
| NEW `ecdat/exposure_scanner/k8s_parser.py` | CREATE | Parse K8s Service/Ingress manifests for exposure classification |
| NEW `ecdat/exposure_scanner/docker_parser.py` | CREATE | Parse Docker Compose port bindings and network modes |
| `ecdat/models.py` | ADD | `ExposureProfile(str, Enum)`: PUBLIC, INTERNAL, AIRGAPPED |
| `ecdat/models.py` | MODIFY | Add `p_hndl: float = 1.0`, `exposure_profile: ExposureProfile` to `CryptoAsset` |
| `ecdat/models.py` | MODIFY | Add `x_auto_source: str = "default"` to track extraction provenance |
| `ecdat/mosca/engine.py` | MODIFY | Integrate $P_{\text{HNDL}}$ and $A_{\text{CAMS}}$ into risk formula |
| `ecdat/pipeline.py` | MODIFY | Run schema extractors and exposure scanner before Mosca |
| `ecdat/constants.py` | ADD | `EXPOSURE_PROFILE_P_HNDL` mapping (PUBLIC=1.0, INTERNAL=0.05, AIRGAPPED=0.0) |
| `ecdat/scanners/filters.py` | MODIFY | Add manifest file types to whitelist (`.yaml`, `.yml`, `.prisma`, `.sql`) |

**$P_{\text{HNDL}}$ Classification Rules:**

| Deployment Pattern | $P_{\text{HNDL}}$ | Exposure Profile |
|---|---|---|
| K8s `type: LoadBalancer` or Ingress with public domain | 1.0 | PUBLIC |
| K8s `type: NodePort` | 0.7 | PUBLIC |
| Docker Compose `ports: "0.0.0.0:8080:8080"` | 1.0 | PUBLIC |
| Docker Compose `ports: "127.0.0.1:8080:8080"` | 0.2 | INTERNAL |
| K8s `type: ClusterIP` with no Ingress | 0.05 | INTERNAL |
| Docker Compose with no ports exposed | 0.01 | INTERNAL |
| No network binding found | 0.0 | AIRGAPPED |

---

### PILLAR 4: CAMS Agility Score — GAP: MAJOR (New Module)

**Plan Requires:**
- 4-level maturity scale: Rigid(0) → Configurable(1) → Provider/Factory(2) → Runtime Agile(3)
- AST detection of algorithm string source (literal vs config vs DI vs policy)
- Per-asset `agility_level` field
- Integration into $Y_{\text{code}}$ migration effort multiplier

**Current State:**
- `agility/buffer_audit.py` checks if buffer sizes are too small for PQC — this is about **byte capacity**, not **algorithm swappability**.
- `agility/recommender.py` recommends PQC alternatives — this is about **what to migrate to**, not **how hard migration will be**.
- No concept of agility levels exists. A hardcoded `Cipher.getInstance("AES/CBC/PKCS5Padding")` and a config-driven `TinkKeysetHandle` get the same treatment.
- `source_scanner.py` regex patterns match call sites but never analyze whether the algorithm string comes from a literal, config, or factory.

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| NEW `ecdat/agility/cams_detector.py` | CREATE | AST-based agility level classifier |
| `ecdat/models.py` | ADD | `AgilityLevel(int, Enum)`: RIGID=0, CONFIGURABLE=1, PROVIDER=2, RUNTIME_AGILE=3 |
| `ecdat/models.py` | MODIFY | Add `agility_level: AgilityLevel = AgilityLevel.RIGID` to `CryptoAsset` |
| `ecdat/models.py` | MODIFY | Add `y_code_multiplier: float` to `MoscaScore` |
| `ecdat/mosca/engine.py` | MODIFY | Use agility level to compute $Y_{\text{code}}$ multiplier (1.0, 0.7, 0.4, 0.15) |
| `ecdat/agility/recommender.py` | MODIFY | Factor CAMS level into recommendation urgency |
| `ecdat/pipeline.py` | MODIFY | Run CAMS detector, pass agility level to Mosca engine |
| `ecdat/report.py` | MODIFY | Add agility distribution to executive summary |
| `ecdat/dashboard/generator.py` | MODIFY | Add agility badge per asset in CBOM tab |

**Detection Patterns (Per Language):**

| Agility Level | JavaScript Pattern | Go Pattern | Python Pattern |
|---|---|---|---|
| 0 (Rigid) | `crypto.createCipheriv('aes-256-gcm', ...)` — literal string | `aes.NewCipher(...)` — hardcoded | `Cipher.new(AES.MODE_GCM, ...)` — literal |
| 1 (Configurable) | `crypto.createCipheriv(config.cipher, ...)` — from config | `cfg.GetString("crypto.algo")` | `algo = settings.CRYPTO_ALGO` |
| 2 (Provider) | `factory.createCipher(...)` — DI/factory | `provider.NewCipher(...)` | `cipher_factory.create(...)` |
| 3 (Runtime Agile) | `tink.keysetHandle.getPrimitive(...)` — Tink/KMS | Policy-driven selector | `cryptography.fernet.Fernet(key)` with key rotation |

---

### PILLAR 5: Active MTU Probing — GAP: CRITICAL (Entirely New)

**Plan Requires:**
- Raw socket DF-bit packet probing at 1280/1400/1500/2000 byte payloads
- Route profile classification: STANDARD, FLEXIBLE, CONSTRAINED
- PQC algorithm filtering by PathProfile
- Handshake expansion calculator

**Current State:**
- `agility/buffer_audit.py` only checks Python **source code** byte buffers (e.g., `bytearray(64)`) against the 3,309 B ML-DSA-65 threshold. It does NOT probe any network.
- `agility/recommender.py` mentions MTU concerns in `implementation_guidance` strings but never actually tests anything.
- **Zero network probing capability exists.**

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| NEW `ecdat/network/` | CREATE | New subpackage for network analysis |
| NEW `ecdat/network/mtu_prober.py` | CREATE | DF-bit PMTUD probe engine using raw sockets or scapy |
| NEW `ecdat/network/handshake_calculator.py` | CREATE | TLS flight size calculator for PQC algorithm combinations |
| NEW `ecdat/network/models.py` | CREATE | `PathProfile`, `RouteProbeResult`, `HandshakeEstimate` models |
| `ecdat/agility/recommender.py` | MODIFY | Filter PQC recommendations by PathProfile feasibility |
| `ecdat/pipeline.py` | MODIFY | Optional MTU probe step (requires network access) |
| `ecdat/dashboard/generator.py` | MODIFY | Add new "Network Readiness" tab with MTU results |
| `ecdat/report.py` | MODIFY | Add network readiness section to CISO report |
| `ecdat/constants.py` | ADD | `PQC_HANDSHAKE_SIZES` for TLS flight computation |

**PathProfile Classification:**

| Probe Result | Profile | Algorithm Constraint |
|---|---|---|
| All probes up to 1500 B succeed, 2000 B fails | STANDARD | Limit to ML-KEM-768 (1,184 B pk). Block ML-KEM-1024 (1,568 B > 1,500 B MTU). |
| All probes including 2000 B succeed (reassembly works) | FLEXIBLE | All algorithms OK. Warn about multi-segment ML-DSA-65 cert chains. |
| Probes fail below 1280 B | CONSTRAINED | Restrict to ML-KEM-512 or hybrid X25519+ML-KEM-768 with cert compression. |

**Note:** Requires `BypassSandbox: true` and possibly root/CAP_NET_RAW for raw sockets. For SIH demo, can use pre-computed results or simulated probe on localhost.

---

### PILLAR 6: Signed Provenance & Unknowns Ledger — GAP: MAJOR (Upgrade Existing)

**Plan Requires:**
- SLSA/in-toto attestation envelope wrapping the CycloneDX CBOM
- Ed25519 + ML-DSA-65 hybrid signature
- Negative proof envelopes: commit hash, binary digest, entry points, requests observed
- Unknowns Ledger export

**Current State:**
- `merkle/tree.py` builds SHA-256 Merkle trees with selective disclosure proofs — this is a **commitment** scheme, not a **signing** scheme.
- `merkle/verifier.py` verifies Merkle paths but has a critical bug: **it never re-hashes the asset metadata**, so an adversary could edit claim text without invalidating the proof.
- The CycloneDX CBOM output in `pipeline.py` is **unsigned plain JSON**.
- No digital signature (Ed25519 or ML-DSA) is applied to any output.
- No in-toto or SLSA envelope format is used.
- No Unknowns Ledger exists.

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| NEW `ecdat/attestation/` | CREATE | New subpackage for signed evidence |
| NEW `ecdat/attestation/signer.py` | CREATE | Ed25519 signing + optional ML-DSA-65 hybrid |
| NEW `ecdat/attestation/envelope.py` | CREATE | SLSA/in-toto JSON envelope formatter |
| NEW `ecdat/attestation/negative_proof.py` | CREATE | Negative proof envelope generator |
| `ecdat/merkle/verifier.py` | FIX (BUG) | Re-hash asset metadata fields before path verification |
| `ecdat/merkle/tree.py` | MODIFY | Add RFC 6962 domain separation (0x00 leaf prefix, 0x01 node prefix) |
| `ecdat/pipeline.py` | MODIFY | Sign CBOM output, generate attestation envelope, emit Unknowns Ledger |
| `ecdat/report.py` | MODIFY | Add Unknowns Ledger section with audit perimeter metadata |
| `ecdat/dashboard/generator.py` | MODIFY | Display signature verification status in Attestation tab |
| `requirements.txt` | MODIFY | Add `pynacl>=1.5.0` (Ed25519) or continue using `cryptography` |

**Verifier Bug Detail:**
In `merkle/verifier.py`, `verify_proof_package()` only checks that `leaf_hash` hashes to `expected_root` via the sibling path. But it **never re-computes** `leaf_hash` from the metadata fields (`algorithm`, `key_size`, `x_tier`, etc.). An adversary could:
1. Take a valid proof package
2. Change `"algorithm": "RSA-2048"` to `"algorithm": "ML-KEM-768"`
3. Leave `leaf_hash` untouched
4. The verifier would report `VERIFIED` — a false positive

**Fix:** Add a step that calls `hash_asset_leaf()` with the claimed metadata and compares the result to the stored `leaf_hash` before proceeding to path verification.

---

### PILLAR 7: Pareto Migration Portfolio Optimizer — GAP: MAJOR (New Module)

**Plan Requires:**
- Pareto frontier: $\max_{S} \sum_{i \in S} \Delta R_i$ subject to $\sum_{i \in S} C_i \le B$
- $\Delta R_i = R_0(i) \times P_{\text{compromise}}(i)$
- $C_i = Y_{\text{code}}(i)$ from CAMS level
- Scatter plot visualization on dashboard

**Current State:**
- `contagion/engine.py` computes $R_0$ and identifies superspreaders — this gives us half the formula ($R_0(i)$).
- `mosca/engine.py` computes $Y_{\max}$ and risk level — this gives us $P_{\text{compromise}}$ proxies.
- `report.py` sorts assessments by $Y_{\max}$ ascending — this is a **flat severity sort**, not portfolio optimization.
- No concept of engineering cost $C_i$, sprint budget $B$, or Pareto frontier exists.

**What Must Change:**

| File | Change Type | Description |
|---|---|---|
| NEW `ecdat/optimizer/` | CREATE | New subpackage for remediation optimization |
| NEW `ecdat/optimizer/pareto.py` | CREATE | Fractional knapsack / greedy Pareto optimizer |
| NEW `ecdat/optimizer/models.py` | CREATE | `RemediationCandidate`, `ParetoResult`, `SprintPlan` |
| `ecdat/pipeline.py` | MODIFY | Run Pareto optimizer after Mosca + contagion, generate sprint plan |
| `ecdat/report.py` | MODIFY | Add "Prioritized Sprint Plan" section showing Pareto-optimal fixes |
| `ecdat/dashboard/generator.py` | MODIFY | Add Pareto frontier scatter plot (D3.js) to new tab or existing tab |

**Algorithm:** Fractional knapsack (greedy by $\Delta R_i / C_i$ ratio) is sufficient — no need for full integer programming at hackathon scale.

---

## 4. FILE-LEVEL CHANGE MANIFEST

### Files to MODIFY (Existing)

| # | File | Lines (Current) | Changes Required | Effort |
|---|---|---|---|---|
| 1 | [`models.py`](file:///home/mohmedh/personal/ECDAT/ecdat/models.py) | 47 | Add 4 new enums (EvidenceLevel, IntentClass, ConfidenceLevel, AgilityLevel, ExposureProfile), 1 new model (UnknownEntry), 6 new fields on CryptoAsset, 2 new fields on MoscaScore | HIGH |
| 2 | [`constants.py`](file:///home/mohmedh/personal/ECDAT/ecdat/constants.py) | 97 | Add EVIDENCE_LEVEL_DESCRIPTIONS, EXPOSURE_PROFILE_P_HNDL, PQC_HANDSHAKE_SIZES, CAMS_Y_MULTIPLIERS, INTENT_CLASS_RISK_WEIGHT | MODERATE |
| 3 | [`pipeline.py`](file:///home/mohmedh/personal/ECDAT/ecdat/pipeline.py) | 362 | Integrate intent classifier, CAMS detector, schema extractor, exposure scanner, Unknowns Ledger collection, Pareto optimizer, signed attestation, fix hardcoded timestamp | HIGH |
| 4 | [`report.py`](file:///home/mohmedh/personal/ECDAT/ecdat/report.py) | 200 | Add Unknowns Ledger section, intent class grouping, Pareto sprint plan, network readiness section, agility distribution | MODERATE |
| 5 | [`source_scanner.py`](file:///home/mohmedh/personal/ECDAT/ecdat/scanners/source_scanner.py) | 450 | Set evidence_level per detection type (E0 for regex, E1 for AST), detect agility patterns | MODERATE |
| 6 | [`manifest_scanner.py`](file:///home/mohmedh/personal/ECDAT/ecdat/scanners/manifest_scanner.py) | 300 | Use `tomllib` for Cargo.toml, parse lockfiles, set evidence_level=E3 | LOW |
| 7 | [`theia_bridge.py`](file:///home/mohmedh/personal/ECDAT/ecdat/scanners/theia_bridge.py) | 350 | Set evidence_level=E3, track unknowns (encrypted PKCS#12, unparseable keys) | LOW |
| 8 | [`filters.py`](file:///home/mohmedh/personal/ECDAT/ecdat/scanners/filters.py) | 100 | Whitelist `.yaml`, `.yml`, `.prisma`, `.sql`, `.toml` for schema/config scanning, track filtered dirs in Unknowns Ledger | LOW |
| 9 | [`ast_tracer.py`](file:///home/mohmedh/personal/ECDAT/ecdat/x_inference/ast_tracer.py) | 200 | Emit IntentClass alongside XTier, set evidence_level=E2 for reachable paths | MODERATE |
| 10 | [`sink_stubs.py`](file:///home/mohmedh/personal/ECDAT/ecdat/x_inference/sink_stubs.py) | 100 | Add intent classification signatures alongside lifespan signatures | MODERATE |
| 11 | [`mosca/engine.py`](file:///home/mohmedh/personal/ECDAT/ecdat/mosca/engine.py) | 200 | Add stochastic Monte Carlo mode, integrate P_HNDL and A_CAMS, compute Y_code multiplier | HIGH |
| 12 | [`contagion/engine.py`](file:///home/mohmedh/personal/ECDAT/ecdat/contagion/engine.py) | 350 | Add agility level to node data, export R0 for Pareto optimizer consumption | LOW |
| 13 | [`agility/recommender.py`](file:///home/mohmedh/personal/ECDAT/ecdat/agility/recommender.py) | 250 | Filter recommendations by PathProfile, add CAMS level context | MODERATE |
| 14 | [`agility/buffer_audit.py`](file:///home/mohmedh/personal/ECDAT/ecdat/agility/buffer_audit.py) | 180 | Support `ast.AnnAssign`, extend to Go/Rust static buffers (stretch goal) | LOW |
| 15 | [`merkle/tree.py`](file:///home/mohmedh/personal/ECDAT/ecdat/merkle/tree.py) | 200 | Add RFC 6962 domain separation prefixes | LOW |
| 16 | [`merkle/verifier.py`](file:///home/mohmedh/personal/ECDAT/ecdat/merkle/verifier.py) | 100 | **BUG FIX**: Re-hash metadata before path verification | CRITICAL |
| 17 | [`dashboard/generator.py`](file:///home/mohmedh/personal/ECDAT/ecdat/dashboard/generator.py) | 2,057 | Add E0-E5 heatmap, intent filter toggle, Pareto scatter plot, MTU tab, agility badges, Unknowns Ledger tab | HIGH |

---

## 5. NEW FILES REQUIRED

| # | File Path | Purpose | Estimated Lines | Pillar |
|---|---|---|---|---|
| 1 | `ecdat/intent/__init__.py` | Package marker | 5 | P1 |
| 2 | `ecdat/intent/classifier.py` | DSIS forward taint intent classifier | 200-300 | P1 |
| 3 | `ecdat/intent/sink_signatures.py` | Per-language intent sink signature maps | 150-200 | P1 |
| 4 | `ecdat/schema_extractor/__init__.py` | Package marker | 5 | P3 |
| 5 | `ecdat/schema_extractor/sql_parser.py` | SQL DDL, TTL, retention comment parser | 200-300 | P3 |
| 6 | `ecdat/schema_extractor/orm_parser.py` | Prisma/Django/Hibernate model parser | 150-250 | P3 |
| 7 | `ecdat/exposure_scanner/__init__.py` | Package marker | 5 | P3 |
| 8 | `ecdat/exposure_scanner/k8s_parser.py` | K8s Service/Ingress exposure classifier | 150-200 | P3 |
| 9 | `ecdat/exposure_scanner/docker_parser.py` | Docker Compose port/network parser | 100-150 | P3 |
| 10 | `ecdat/agility/cams_detector.py` | AST-based agility level classifier | 200-300 | P4 |
| 11 | `ecdat/network/__init__.py` | Package marker | 5 | P5 |
| 12 | `ecdat/network/mtu_prober.py` | DF-bit PMTUD probe engine | 250-350 | P5 |
| 13 | `ecdat/network/handshake_calculator.py` | TLS flight size calculator | 100-150 | P5 |
| 14 | `ecdat/network/models.py` | PathProfile, RouteProbeResult models | 50-80 | P5 |
| 15 | `ecdat/attestation/__init__.py` | Package marker | 5 | P6 |
| 16 | `ecdat/attestation/signer.py` | Ed25519 + ML-DSA-65 hybrid signer | 150-200 | P6 |
| 17 | `ecdat/attestation/envelope.py` | SLSA/in-toto envelope formatter | 150-200 | P6 |
| 18 | `ecdat/attestation/negative_proof.py` | Negative proof envelope generator | 100-150 | P6 |
| 19 | `ecdat/optimizer/__init__.py` | Package marker | 5 | P7 |
| 20 | `ecdat/optimizer/pareto.py` | Fractional knapsack Pareto optimizer | 150-250 | P7 |
| 21 | `ecdat/optimizer/models.py` | RemediationCandidate, ParetoResult | 50-80 | P7 |

**Total new files: 21**
**Total new lines: ~2,200 - 3,400**

---

## 6. TEST COVERAGE GAP

### Current Tests (12 files, 46 tests — all passing)

| Test File | What It Tests | Adequate for Plan? |
|---|---|---|
| `test_agility.py` | Buffer hazard detection | Needs CAMS detector tests |
| `test_contagion.py` | R0 graph construction | Needs agility-level-aware node tests |
| `test_dashboard.py` | HTML report generation | Needs new tab tests (MTU, Pareto, E0-E5) |
| `test_filters.py` | Path filtering | Needs new extension whitelist tests |
| `test_manifest_scanner.py` | Manifest parsing | Needs lockfile tests |
| `test_merkle.py` | Merkle tree + verification | Needs domain separation + metadata re-hash tests |
| `test_mosca.py` | Mosca scoring | Needs Monte Carlo, P_HNDL, CAMS integration tests |
| `test_pipeline.py` | Pipeline orchestration | Needs end-to-end with new modules |
| `test_scaffold.py` | Project structure | OK as-is |
| `test_source_scanner.py` | Polyglot regex patterns | Needs evidence level assertions |
| `test_theia_bridge.py` | Theia bridge | Needs unknowns tracking assertions |
| `test_x_inference.py` | Python AST taint | Needs intent classification assertions |

### New Test Files Required

| # | Test File | Tests For | Priority |
|---|---|---|---|
| 1 | `test_intent_classifier.py` | DSIS 4-class intent classification | P1 |
| 2 | `test_evidence_levels.py` | E0-E5 assignment and promotion | P1 |
| 3 | `test_schema_extractor.py` | SQL/ORM parsing, TTL detection | P1 |
| 4 | `test_exposure_scanner.py` | K8s/Docker exposure classification | P1 |
| 5 | `test_cams_detector.py` | Agility level detection | P2 |
| 6 | `test_mtu_prober.py` | MTU probe (mocked sockets) | P2 |
| 7 | `test_attestation.py` | Signing, envelope, negative proofs | P2 |
| 8 | `test_pareto.py` | Knapsack optimization, sprint plan | P3 |
| 9 | `test_stochastic_mosca.py` | Monte Carlo P(X+Y>Z) | P3 |

---

## 7. DEPENDENCY CHANGES

### Current Dependencies (`requirements.txt`)

```
cyclonedx-bom>=4.0.0
cryptography>=42.0.0
networkx>=3.0
pydantic>=2.0.0
pytest>=8.0.0
```

### Additional Dependencies Needed

| Package | Version | Purpose | Pillar |
|---|---|---|---|
| `pyyaml>=6.0` | Stable | K8s/Docker Compose YAML parsing | P3 |
| `numpy>=1.26` | Stable | Monte Carlo simulation for stochastic Mosca | P3/P7 |
| `scapy>=2.5` | Optional | Raw socket MTU probing (alternative: stdlib `socket`) | P5 |
| `in-toto>=2.0` | Optional | SLSA/in-toto attestation envelope format | P6 |

**Note:** `tomllib` is built into Python 3.11+ (already required by `pyproject.toml`), so no extra dep for Cargo.toml parsing.

**Minimal new deps for Phase 1:** Only `pyyaml` is strictly required. `numpy` is optional (can use stdlib `random` for Monte Carlo). `scapy` and `in-toto` are Phase 2/3.

---

## 8. CROSS-CUTTING CONCERNS

### 8.1 Existing Code Quality Issues to Fix During Refactor

| Issue | File(s) | Severity | Fix |
|---|---|---|---|
| **Verifier doesn't re-hash metadata** | `merkle/verifier.py` | CRITICAL (security bug) | Add `hash_asset_leaf()` call before path verification |
| `CURRENT_YEAR = 2026` hardcoded | `constants.py` | LOW | Replace with `datetime.date.today().year` |
| CycloneDX timestamp hardcoded `"2026-09-04T15:00:00Z"` | `pipeline.py` | LOW | Replace with `datetime.utcnow().isoformat()` |
| `x_confidence` is unvalidated string | `models.py` | MEDIUM | Replace with `ConfidenceLevel` enum |
| `risk_level` is unvalidated string | `models.py` | MEDIUM | Replace with `RiskLevel` enum |
| Cargo.toml parsed with ad-hoc line scanner | `manifest_scanner.py` | LOW | Use `tomllib` (Python 3.11+) |
| Substring match `k.lower() in name_clean` can false-positive | `manifest_scanner.py` | LOW | Use exact match or word-boundary regex |
| `SHA` substring matches SHA-1 (broken) | `mosca/engine.py` | MEDIUM | Explicitly exclude SHA-1 from safe list |
| `scanners/__init__.py` only exports `theia_bridge` | `scanners/__init__.py` | LOW | Export all scanner functions |
| Dashboard uses CDN deps (fails air-gapped) | `dashboard/generator.py` | LOW | Bundle or provide offline fallback (stretch) |

### 8.2 Architectural Decisions for the Refactor

1. **Intent + Lifespan should share the forward-taint walk.** Don't create two separate AST passes. Extend `CryptoTaintVisitor` to emit `(XTier, IntentClass)` in a single traversal.

2. **Evidence levels should be set at the point of discovery, not retroactively.** Each scanner function should directly assign the appropriate E-level when creating the `CryptoAsset`.

3. **The Unknowns Ledger is a pipeline-level accumulator.** Pass a `List[UnknownEntry]` through the pipeline, appending at each stage where data is skipped or unparseable.

4. **Stochastic Mosca should be opt-in.** Keep the deterministic $Y_{\max}$ as default for speed. Add a `--stochastic` CLI flag that runs Monte Carlo. Both modes should coexist.

5. **MTU probing must be optional.** It requires network access and possibly root privileges. Add a `--probe-mtu` CLI flag. Without it, assume `STANDARD` profile (conservative).

6. **The dashboard generator needs to be split.** At 2,057 lines and growing (new tabs will add ~500-800 lines), consider splitting into `generator.py` (orchestrator), `tabs/contagion.py`, `tabs/mosca.py`, etc. Or use Jinja2 templates.

---

## 9. PRIORITIZED IMPLEMENTATION ORDER

### Phase 1: "The Demo Killer" (Weeks 1-2)

These changes create the features that make the 3-minute SIH pitch impossible to ignore.

| Order | Task | Files Touched | New Files | Tests | Effort |
|---|---|---|---|---|---|
| 1.0 | **Fix verifier metadata re-hash bug** | `merkle/verifier.py` | — | Update `test_merkle.py` | 1h |
| 1.1 | **Add model enums & fields** (EvidenceLevel, IntentClass, AgilityLevel, ExposureProfile, ConfidenceLevel) | `models.py`, `constants.py` | — | `test_scaffold.py` update | 3h |
| 1.2 | **DSIS Intent Classifier** | `x_inference/ast_tracer.py`, `x_inference/sink_stubs.py` | `intent/classifier.py`, `intent/sink_signatures.py` | `test_intent_classifier.py` | 8h |
| 1.3 | **E0-E5 Evidence Taxonomy** | `source_scanner.py`, `theia_bridge.py`, `ast_tracer.py` | — | `test_evidence_levels.py` | 4h |
| 1.4 | **Schema-based $X_{\text{auto}}$ extractor** (SQL/ORM/TTL) | `pipeline.py` | `schema_extractor/sql_parser.py`, `schema_extractor/orm_parser.py` | `test_schema_extractor.py` | 8h |
| 1.5 | **K8s/Docker $P_{\text{HNDL}}$ parser** | `pipeline.py` | `exposure_scanner/k8s_parser.py`, `exposure_scanner/docker_parser.py` | `test_exposure_scanner.py` | 6h |
| 1.6 | **Update Mosca to enriched $R_Q$ formula** | `mosca/engine.py` | — | Update `test_mosca.py` | 4h |
| 1.7 | **Pipeline integration** (wire P1-1.6 together) | `pipeline.py` | — | Update `test_pipeline.py` | 4h |
| 1.8 | **Dashboard updates** (intent filter, E0-E5 badges) | `dashboard/generator.py` | — | Update `test_dashboard.py` | 6h |

**Phase 1 Total: ~44 hours (~2 weeks at focused pace)**

### Phase 2: "The Competitive Moat" (Weeks 3-4)

| Order | Task | Files Touched | New Files | Tests | Effort |
|---|---|---|---|---|---|
| 2.1 | **CAMS Agility Level detector** | `source_scanner.py` | `agility/cams_detector.py` | `test_cams_detector.py` | 6h |
| 2.2 | **Active MTU Prober** | — | `network/mtu_prober.py`, `network/handshake_calculator.py`, `network/models.py` | `test_mtu_prober.py` | 8h |
| 2.3 | **MTU-aware recommendation filter** | `agility/recommender.py` | — | Update `test_agility.py` | 3h |
| 2.4 | **Signed CBOM + Unknowns Ledger** | `pipeline.py`, `report.py` | `attestation/signer.py`, `attestation/envelope.py`, `attestation/negative_proof.py` | `test_attestation.py` | 10h |
| 2.5 | **CycloneDX #966 attestation fields** | `pipeline.py` | — | Update `test_pipeline.py` | 4h |

**Phase 2 Total: ~31 hours**

### Phase 3: "The Executive Knockout" (Weeks 5-6)

| Order | Task | Files Touched | New Files | Tests | Effort |
|---|---|---|---|---|---|
| 3.1 | **Pareto Portfolio Optimizer** | `pipeline.py`, `report.py` | `optimizer/pareto.py`, `optimizer/models.py` | `test_pareto.py` | 8h |
| 3.2 | **Stochastic Mosca (Monte Carlo)** | `mosca/engine.py` | — | `test_stochastic_mosca.py` | 6h |
| 3.3 | **Negative Proof Envelope generator** | `pipeline.py`, `report.py` | — (using P2 attestation) | Update `test_attestation.py` | 3h |
| 3.4 | **Dashboard: MTU tab + Pareto chart + E0-E5 heatmap** | `dashboard/generator.py` | — | Update `test_dashboard.py` | 10h |
| 3.5 | **End-to-end demo on E-Voting-V2** | `pipeline.py` | — | Manual verification | 4h |

**Phase 3 Total: ~31 hours**

---

## APPENDIX A: CURRENT vs PLAN FORMULA COMPARISON

### Mosca Risk Score

**CURRENT:**
$$Y_{\max} = (Z_{\text{reg}} - 2026) - X_{\text{tier\_default}}$$
$$\text{Risk} = \begin{cases} \text{CRITICAL} & Y_{\max} \le 1.0 \\ \text{HIGH} & 1.0 < Y_{\max} \le 2.5 \\ \text{MEDIUM} & 2.5 < Y_{\max} \le 4.5 \\ \text{LOW} & Y_{\max} > 4.5 \end{cases}$$

**PLAN (Deterministic mode):**
$$R_Q = \max\left(0,\; (X_{\text{auto}} + Y_{\text{code}}) - Z_{\text{reg}}\right) \times P_{\text{HNDL}} \times (1 - A_{\text{CAMS}})$$

Where:
- $X_{\text{auto}}$ from schema/ORM/TTL extraction (replaces flat lookup table)
- $Y_{\text{code}} = Y_{\text{base}} \times (1 + \alpha \log(\text{FanIn}) + \beta \frac{\text{CC}}{10} + \gamma \cdot \text{HardcodedPenalty})$
- $P_{\text{HNDL}}$ from K8s/Docker exposure scanner (0.0 - 1.0)
- $A_{\text{CAMS}}$ from CAMS agility detector (0.0 - 0.85)

**PLAN (Stochastic mode):**
$$P_{\text{compromise}} = P(X + Y > Z) = \int_0^\infty \int_0^\infty \int_0^{x+y} f_X(x) f_Y(y) f_Z(z) \, dz \, dy \, dx$$

Evaluated via 10,000-iteration Monte Carlo simulation.

### Readiness Score

**CURRENT:**
$$\text{Readiness} = \max(5, \min(100, 100 - 12 N_{\text{crit}} - 6 N_{\text{high}} - 8 N_{\text{hazards}}))$$

**PLAN:** Same formula but should additionally weight by $R_0$ (a critical in a superspreader costs more than a critical in an isolated leaf).

---

## APPENDIX B: THE "WHAT WE KEEP UNTOUCHED" LIST

These modules are **architecturally sound** and need only minor field additions, not redesigns:

1. `contagion/engine.py` — The $R_0$ NetworkX graph model is unique. Just add agility_level to node data.
2. `merkle/tree.py` — SHA-256 Merkle commitment is solid. Just add domain separation prefixes.
3. `agility/buffer_audit.py` — Python AST buffer detection works. Extend to `AnnAssign` as a stretch goal.
4. `scanners/filters.py` — Path filtering is clean. Just whitelist new extensions.
5. `agility/recommender.py` — PQC recommendation engine is well-cited. Just add PathProfile filtering.

---

## APPENDIX C: FILE TREE AFTER ALL CHANGES

```
ecdat/
├── __init__.py
├── models.py                      (MODIFIED — 4 new enums, 6 new fields, 2 new models)
├── constants.py                   (MODIFIED — 5 new constant dictionaries)
├── pipeline.py                    (MODIFIED — 7 new integration points)
├── report.py                      (MODIFIED — 4 new sections)
│
├── scanners/
│   ├── __init__.py                (MODIFIED — export all scanners)
│   ├── filters.py                 (MODIFIED — new whitelists)
│   ├── source_scanner.py          (MODIFIED — evidence levels, agility hints)
│   ├── manifest_scanner.py        (MODIFIED — tomllib, lockfiles)
│   └── theia_bridge.py            (MODIFIED — evidence levels, unknowns)
│
├── x_inference/
│   ├── __init__.py                (MODIFIED — add exports)
│   ├── ast_tracer.py              (MODIFIED — emit IntentClass + evidence level)
│   └── sink_stubs.py              (MODIFIED — add intent signatures)
│
├── intent/                        ← NEW PACKAGE
│   ├── __init__.py
│   ├── classifier.py              (DSIS forward taint)
│   └── sink_signatures.py         (per-language intent maps)
│
├── schema_extractor/              ← NEW PACKAGE
│   ├── __init__.py
│   ├── sql_parser.py              (DDL / TTL / retention)
│   └── orm_parser.py              (Prisma / Django / Hibernate)
│
├── exposure_scanner/              ← NEW PACKAGE
│   ├── __init__.py
│   ├── k8s_parser.py              (Service / Ingress → P_HNDL)
│   └── docker_parser.py           (Compose ports → P_HNDL)
│
├── mosca/
│   ├── __init__.py
│   └── engine.py                  (MODIFIED — enriched R_Q + Monte Carlo)
│
├── contagion/
│   ├── __init__.py
│   └── engine.py                  (MODIFIED — agility in nodes)
│
├── agility/
│   ├── __init__.py
│   ├── buffer_audit.py            (MODIFIED — AnnAssign support)
│   ├── recommender.py             (MODIFIED — PathProfile filter)
│   └── cams_detector.py           ← NEW MODULE
│
├── network/                       ← NEW PACKAGE
│   ├── __init__.py
│   ├── mtu_prober.py              (DF-bit PMTUD)
│   ├── handshake_calculator.py    (TLS flight sizes)
│   └── models.py                  (PathProfile, RouteProbeResult)
│
├── attestation/                   ← NEW PACKAGE
│   ├── __init__.py
│   ├── signer.py                  (Ed25519 + ML-DSA hybrid)
│   ├── envelope.py                (SLSA / in-toto)
│   └── negative_proof.py          (audit perimeter envelopes)
│
├── optimizer/                     ← NEW PACKAGE
│   ├── __init__.py
│   ├── pareto.py                  (fractional knapsack)
│   └── models.py                  (RemediationCandidate, ParetoResult)
│
├── merkle/
│   ├── __init__.py
│   ├── tree.py                    (MODIFIED — RFC 6962 domain separation)
│   └── verifier.py                (MODIFIED — BUG FIX: metadata re-hash)
│
└── dashboard/
    ├── __init__.py
    └── generator.py               (MODIFIED — 3 new tabs/views)
```

**Total source files after changes: 42** (up from 25)

---

*End of Gap Analysis Report*
