# ECDAT — Executive Cryptographic Risk & Migration Report

> **Standards Baseline:** NIST IR 8547 / FIPS 203, 204, 205 | US OMB M-26-15 | GRI 2025 Survey
> **Attestation Commitment:** SHA-256 Merkle Root `0xc639e82a0db1b2efede2cbd2cf0e3ec04526b441804ad59161d41d9982fb7a0f`

## 1. Executive Summary

| Metric | Value | Executive Assessment |
| :--- | :--- | :--- |
| **Total Cryptographic Assets** | `11` | Discovered across source code & infrastructure |
| **Critical Risk ($Y_{max} \le 1.0\text{y}$)** | `4` | Immediate migration queue (HNDL window open / past deadline) |
| **High Risk ($1.0 < Y_{max} \le 2.5\text{y}$)** | `0` | Must be scheduled in current 2-year planning budget |
| **Manual Review Required ($E_0$)** | `2` | Dynamic unresolvable cryptographic calls quarantined for auditor triage |
| **Medium / Low Risk** | `5` | Safe operational window ($> 2.5\text{y}$ buffer) |
| **Operational Utility Suppressed** | `1` | False-positives eliminated (ETags/Caches: $R_Q = 0.0$) |
| **Buffer Overflow Hazards** | `1` | Fixed-size memory allocations incompatible with PQC |
| **Boundary Unknowns Logged** | `4` | Explicitly audited excluded paths and binary limitations |

### 4-Tier Data Lifespan ($X$) Distribution

| Lifespan Tier | Assets | Estimated Secrecy $X$ | Typical Sinks |
| :--- | :--- | :--- | :--- |
| **`EPHEMERAL`** | `3` | ~0 Years | Network sockets, transient memory buffers zeroed on close |
| **`SHORT_TERM`** | `1` | ~1–2 Years | Caching layers (Redis TTL), rotating session tokens |
| **`OPERATIONAL`** | `3` | ~5 Years | Relational databases (PostgreSQL/MySQL), customer records |
| **`ARCHIVAL`** | `2` | ~10+ Years | Long-term cloud backups (S3), HIPAA/SOX compliance logs |
| **`HUMAN_REVIEW`** | `2` | Flagged | Ambiguous dataflows / unanalyzed external library boundaries |

### Cryptographic Agility Maturity (CAMS Model)

| Agility Level | Assets | Architectural Implementation | Refactor Effort | Urgency Multiplier |
| :--- | :---: | :--- | :---: | :---: |
| **`L0: RIGID`** | `11` | Hardcoded string literals, inflexible primitives | `1.00x` | `1.00x` (Full urgency) |
| **`L1: CONFIGURABLE`** | `0` | Parameterized configs/env vars, no code edits | `0.70x` | `0.70x` (30% discount) |
| **`L2: PROVIDER`** | `0` | Pluggable crypto provider abstraction | `0.40x` | `0.40x` (60% discount) |
| **`L3: RUNTIME_AGILE`** | `0` | Dynamic runtime negotiation / agile wrapper | `0.15x` | `0.15x` (85% discount) |

### Functional Security Intent (DSIS Lattice)

| Functional Intent Class | Assets | Quantum Exploit Risk | Mitigation Status |
| :--- | :---: | :--- | :--- |
| **`CONFIDENTIALITY_ENVELOPE`** | `7` | High ($W=1.0$) | Primary HNDL target — payload confidentiality |
| **`AUTHENTICATION_SIGNATURE`** | `3` | Medium-High ($W=0.8$) | Identity forgery — handshake & token authentication |
| **`INTEGRITY_CHECKSUM`** | `0` | Low-Medium ($W=0.3$) | Tamper detection — audit trails & code integrity |
| **`OPERATIONAL_UTILITY`** | `1` | **Zero ($R_Q = 0.0$)** | **Suppressed from CISO queue (HTTP ETags & CDN caches)** |

### Deployment Exposure & Harvest Interception ($P_{\text{HNDL}}$)

| Exposure Profile | Assets | $P_{\text{HNDL}}$ Interception Factor | Threat Model Scope |
| :--- | :---: | :---: | :--- |
| **`PUBLIC`** | `11` | `1.00` | Internet Ingress / LoadBalancer (Actively harvested) |
| **`INTERNAL`** | `0` | `0.05` | Private VPC / ClusterIP (Requires lateral pivot) |
| **`AIRGAPPED`** | `0` | `0.00` | Standalone isolated host (Immune to passive HNDL) |

### Transport Network Path MTU & PQC Fragmentation Readiness

| Transport Metric | Measured Value | PQC Engineering Assessment |
| :--- | :--- | :--- |
| **Effective Path MTU** | `1280 Bytes` | Maximum Transmission Unit over network route |
| **Route Classification** | **`STANDARD`** | `Standard Ethernet route (1,500 B). ML-KEM-1024 and ML-DSA exceed MSS and require fragmentation.` |
| **TCP Fragmentation Drop Risk** | **`MEDIUM`** | Middlebox packet drop exposure under PQC expansion |
| **Don't Fragment (DF) Enforcement** | `True` | Strict DF bit prevents IP fragmentation |

#### PQC Handshake Flight Overhead (NIST FIPS 203 / 204)

| Algorithm | Primitive | Flight Overhead | TCP Packets | Packet Drop Risk |
| :--- | :--- | :---: | :---: | :---: |
| **`ML-KEM-512`** | `KEM` | `800 B` | `1 pkt` | `LOW` |
| **`ML-KEM-768`** | `KEM` | `1184 B` | `1 pkt` | `LOW` |
| **`ML-KEM-1024`** | `KEM` | `1568 B` | `2 pkt` | `HIGH` |
| **`X25519MLKEM768`** | `HYBRID_KEM` | `1216 B` | `1 pkt` | `LOW` |
| **`ML-DSA-44`** | `SIGNATURE` | `3732 B` | `4 pkt` | `HIGH` |
| **`ML-DSA-65`** | `SIGNATURE` | `5261 B` | `5 pkt` | `HIGH` |
| **`ML-DSA-87`** | `SIGNATURE` | `7219 B` | `6 pkt` | `HIGH` |
| **`SLH-DSA-128S`** | `SIGNATURE` | `7888 B` | `7 pkt` | `HIGH` |

---

## 2. Actionable Migration Backlog (Ranked by $Y_{max}$ Budget)

The table below replaces flat checklists with mathematically grounded deadlines: **$Y_{max} = (Z_{reg} - 2026) - X_{eff}$**.

| Priority | Asset ID | File Location & Line | Trigger Sink / Evidence | Algorithm | CAMS | $X$ Tier | $Y_{max}$ Budget | Mandate Year | Recommended Hybrid | Risk Level |
| :---: | :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| **#1** | `ASSET-010` | `certs/legacy_rsa.key:1` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `ARCHIVAL` | **`-6.0y`** | `2030` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#2** | `ASSET-008` | `common_crypto.py:13` | `Variable 'session_key' created at line 8 does not flow into any persistence sink; retained exclusively in volatile memory scope.` | `ECDSA-P256` | `RIGID` | `EPHEMERAL` | **`+0.0y`** | `2026` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#3** | `ASSET-009` | `certs/legacy_ca.crt:1` | `O=Legacy Org,CN=legacy-enterprise-ca.internal` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`+0.0y`** | `2031` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#4** | `ASSET-011` | `certs/legacy_rsa.key:1` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`+0.0y`** | `2031` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#5** | `ASSET-005` | `app.py:34` | `vendor_client.sync_data` | `ECDSA-P256` | `RIGID` | `HUMAN_REVIEW` | **`+2.5y`** | `2030` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`MANUAL_REVIEW_REQUIRED`** |
| **#6** | `ASSET-006` | `app.py:39` | `vendor_client.sync_data` | `AES-256-GCM` | `RIGID` | `HUMAN_REVIEW` | **`+2.5y`** | `2030` | N/A (Symmetric) | **`MANUAL_REVIEW_REQUIRED`** |
| **#7** | `ASSET-002` | `app.py:14` | `redis.setex` | `AES-256-GCM` | `RIGID` | `SHORT_TERM` | **`+22.5y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#8** | `ASSET-003` | `app.py:20` | `db.session.add` | `AES-256-GCM` | `RIGID` | `OPERATIONAL` | **`+22.5y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#9** | `ASSET-004` | `app.py:27` | `s3.put_object` | `AES-256-GCM` | `RIGID` | `ARCHIVAL` | **`+22.5y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#10** | `ASSET-001` | `app.py:8` | `client_socket.sendall` | `AES-256-GCM` | `RIGID` | `EPHEMERAL` | **`+24.0y`** | `2050` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`LOW`** |
| **#11** | `ASSET-007` | `common_crypto.py:8` | `Variable 'session_key' created at line 8 does not flow into any persistence sink; retained exclusively in volatile memory scope.` | `AES-256-GCM` | `RIGID` | `EPHEMERAL` | **`+24.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |

---

## 3. Cryptographic Agility & Buffer Hazard Audit

| Variable Name | Allocated Buffer | PQC Requirement (ML-DSA-65) | Line | Severity | Action Required |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `sig_buffer` | `64 B` | `3309 B` | Line 33 | **`CRITICAL`** | Expand static buffer before swapping algorithm to avoid buffer overflow |

---

## 4. Epidemiological R0 Dependency Contagion (Superspreaders)

Cryptographic vulnerability propagates through software dependency contact networks. The **$R_0$ score** measures how many downstream services inherit quantum risk from an unmigrated component.

| Component / Module | $R_0$ Score | Direct Crypto | Downstream Affected Services | Actionable Mitigation Impact |
| :--- | :---: | :---: | :--- | :--- |
| **`common_crypto`** | **`3`** | `True` | `payment_service, api_gateway, auth_service` | SUPERSPREADER (R0=3): Migrating 'common_crypto' to PQC immediately eliminates quantum risk across 3 downstream services: payment_service, api_gateway, auth_service. |

---

## 5. Privacy-Preserving Attestation via Merkle Commitments

Conventional audit practices require handing over full, plain-text Cryptography Bills of Materials (CBOMs), which inadvertently functions as a targeting map for adversaries. ECDAT resolves this through **selective inclusion proofs**:

- **Committed Root Hash:** `0xc639e82a0db1b2efede2cbd2cf0e3ec04526b441804ad59161d41d9982fb7a0f`
- **Auditor Verification Protocol:** For any compliance query, ECDAT issues a single leaf proof package (`proof_<assetId>.json`).
- **Verification Command:**
  ```bash
  python -m ecdat.merkle.verifier --proof proofs/proof_asset_1.json --root cbom_root.hex
  ```
- **Guarantee:** Proves mathematically that a specific component is compliant without disclosing internal codebase paths or unpatched inventory items.


---

## 6. Auditable Unknowns Ledger & Boundary Declarations

Conventional vulnerability scanners report false 100% perimeter coverage by silently omitting files or paths they cannot parse. ECDAT enforces **Auditable Boundary Honesty** by declaring all excluded paths, uninspected binary files, and encrypted containers.

| Item Path / Identifier | Category | Scanning Boundary Reason | Recommended Auditor Action |
| :--- | :---: | :--- | :--- |
| `common_crypto.py:13` | `UNCONFIRMED_DATAFLOW` | Dataflow variable 'token_sig' could not be statically bound to a verified cryptographic API call | Manually review variable lineage to determine if an unmodeled cryptographic library is invoked. |
| `app.py:34` | `UNCONFIRMED_DATAFLOW` | Dataflow variable 'signature' could not be statically bound to a verified cryptographic API call | Manually review variable lineage to determine if an unmodeled cryptographic library is invoked. |
| `payment_service.py:8` | `UNCONFIRMED_DATAFLOW` | Dataflow variable 'encrypted_envelope' could not be statically bound to a verified cryptographic API call | Manually review variable lineage to determine if an unmodeled cryptographic library is invoked. |
| `auth_service.py:8` | `UNCONFIRMED_DATAFLOW` | Dataflow variable 'token' could not be statically bound to a verified cryptographic API call | Manually review variable lineage to determine if an unmodeled cryptographic library is invoked. |

---

## 7. SLSA / in-toto Signed DSSE Attestation & Negative Proofs

ECDAT produces cryptographically non-malleable, tamper-evident audit attestations complying with the **in-toto v1.0 Statement** specification and **RFC 9162 Dead Simple Signing Envelope (DSSE)**.

- **Attestation Envelope File:** `attestation.dsse.json`
- **Payload Type:** `application/vnd.in-toto+json`
- **Predicate Type:** `https://ecdat.dev/attestation/v1`
- **Primary Signer Key ID:** `ed25519:5a20ea9e828ea614` (2 signatures: Ed25519 primary + ML-DSA-65 post-quantum hybrid commitment)
- **Committed Merkle Root:** `0xc639e82a0db1b2efede2cbd2cf0e3ec04526b441804ad59161d41d9982fb7a0f`

### Certified Negative Proofs

> **Assertion:** Audited perimeter contains 4 declared boundary unknowns; all other paths certified.
> 
> ECDAT certifies that within the audited codebase boundary (11 cryptographic assets discovered), no reachable vulnerable primitives outside the declared inventory exist. All exclusions and uninspected binary files are strictly quarantined in the Auditable Unknowns Ledger.

### Independent Auditor Verification Protocol

Auditors can independently verify the authenticity, integrity, and non-repudiation of this scan without access to the ECDAT source code:

```bash
# Verify Ed25519 DSSE envelope against the public key
python -m ecdat.attestation.verifier --envelope ecdat_output/attestation.dsse.json --pubkey ecdat_output/attestation_pubkey.pem
```

---

## 8. Pareto Migration Portfolio Optimization (Pillar 7)

Rather than an unranked severity list, ECDAT formulates remediation as a resource-constrained knapsack problem with target budget $B = 10.0$ developer-weeks:

- **Target Sprint Capacity:** `10.0 dev-weeks`
- **Allocated Effort:** `9.8 dev-weeks`
- **Estate Risk Reduction Achieved:** `+96.8%` (4 / 11 assets selected)

| Asset ID | Component | Algorithm | Effort (dev-wks) | Blast Reduction ($\Delta R$) | ROI Efficiency | Sprint Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `ASSET-008` | `common_crypto:token_sig` | `ECDSA-P256` | `2.9` | `30.0` | `10.35` | **SELECTED FOR SPRINT** |
| `ASSET-009` | `x509_cert:legacy_ca` | `RSA-2048` | `2.3` | `10.0` | `4.35` | **SELECTED FOR SPRINT** |
| `ASSET-010` | `keyfile:legacy_rsa_private-key` | `RSA-2048` | `2.3` | `10.0` | `4.35` | **SELECTED FOR SPRINT** |
| `ASSET-011` | `keyfile:legacy_rsa_public-key` | `RSA-2048` | `2.3` | `10.0` | `4.35` | **SELECTED FOR SPRINT** |
| `ASSET-005` | `app:signature` | `ECDSA-P256` | `2.3` | `2.0` | `0.87` | **DEFERRED** |
| `ASSET-001` | `app:session_key` | `AES-256-GCM` | `0.2` | `0.0` | `0.00` | **DEFERRED** |
| `ASSET-002` | `app:auth_token` | `AES-256-GCM` | `0.2` | `0.0` | `0.00` | **DEFERRED** |
| `ASSET-003` | `app:encrypted_pan` | `AES-256-GCM` | `0.2` | `0.0` | `0.00` | **DEFERRED** |
| `ASSET-004` | `app:encrypted_archive` | `AES-256-GCM` | `0.2` | `0.0` | `0.00` | **DEFERRED** |
| `ASSET-006` | `app:token_blob` | `AES-256-GCM` | `0.2` | `0.0` | `0.00` | **DEFERRED** |

---

## 9. Stochastic Monte Carlo Quantum Risk Analysis

Under empirical Monte Carlo sampling (5000 iterations) calibrated against the Global Risk Institute (GRI) 2025 Quantum Threat Report:

- **Mean Estate Breach Probability:** `38.3%`
- **Peak Single-Asset Breach Probability:** `89.8%`
- **Critical Probabilistic Exposure Assets:** `4`
