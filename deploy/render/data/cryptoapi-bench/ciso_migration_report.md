# ECDAT — Executive Cryptographic Risk & Migration Report

> **Standards Baseline:** NIST IR 8547 / FIPS 203, 204, 205 | US OMB M-26-15 | GRI 2025 Survey
> **Attestation Commitment:** SHA-256 Merkle Root `0x2df9c2d84eb0a75eb4313f5ec9130b27fb86fb4765d8336543c00b78bf8f01a5`

## 1. Executive Summary

| Metric | Value | Executive Assessment |
| :--- | :--- | :--- |
| **Total Cryptographic Assets** | `289` | Discovered across source code & infrastructure |
| **Critical Risk ($Y_{max} \le 1.0\text{y}$)** | `177` | Immediate migration queue (HNDL window open / past deadline) |
| **High Risk ($1.0 < Y_{max} \le 2.5\text{y}$)** | `0` | Must be scheduled in current 2-year planning budget |
| **Manual Review Required ($E_0$)** | `1` | Dynamic unresolvable cryptographic calls quarantined for auditor triage |
| **Medium / Low Risk** | `111` | Safe operational window ($> 2.5\text{y}$ buffer) |
| **Operational Utility Suppressed** | `0` | False-positives eliminated (ETags/Caches: $R_Q = 0.0$) |
| **Buffer Overflow Hazards** | `0` | Fixed-size memory allocations incompatible with PQC |
| **Boundary Unknowns Logged** | `5` | Explicitly audited excluded paths and binary limitations |

### 4-Tier Data Lifespan ($X$) Distribution

| Lifespan Tier | Assets | Estimated Secrecy $X$ | Typical Sinks |
| :--- | :--- | :--- | :--- |
| **`EPHEMERAL`** | `0` | ~0 Years | Network sockets, transient memory buffers zeroed on close |
| **`SHORT_TERM`** | `0` | ~1–2 Years | Caching layers (Redis TTL), rotating session tokens |
| **`OPERATIONAL`** | `288` | ~5 Years | Relational databases (PostgreSQL/MySQL), customer records |
| **`ARCHIVAL`** | `0` | ~10+ Years | Long-term cloud backups (S3), HIPAA/SOX compliance logs |
| **`HUMAN_REVIEW`** | `1` | Flagged | Ambiguous dataflows / unanalyzed external library boundaries |

### Cryptographic Agility Maturity (CAMS Model)

| Agility Level | Assets | Architectural Implementation | Refactor Effort | Urgency Multiplier |
| :--- | :---: | :--- | :---: | :---: |
| **`L0: RIGID`** | `213` | Hardcoded string literals, inflexible primitives | `1.00x` | `1.00x` (Full urgency) |
| **`L1: CONFIGURABLE`** | `74` | Parameterized configs/env vars, no code edits | `0.70x` | `0.70x` (30% discount) |
| **`L2: PROVIDER`** | `0` | Pluggable crypto provider abstraction | `0.40x` | `0.40x` (60% discount) |
| **`L3: RUNTIME_AGILE`** | `2` | Dynamic runtime negotiation / agile wrapper | `0.15x` | `0.15x` (85% discount) |

### Functional Security Intent (DSIS Lattice)

| Functional Intent Class | Assets | Quantum Exploit Risk | Mitigation Status |
| :--- | :---: | :--- | :--- |
| **`CONFIDENTIALITY_ENVELOPE`** | `246` | High ($W=1.0$) | Primary HNDL target — payload confidentiality |
| **`AUTHENTICATION_SIGNATURE`** | `11` | Medium-High ($W=0.8$) | Identity forgery — handshake & token authentication |
| **`INTEGRITY_CHECKSUM`** | `32` | Low-Medium ($W=0.3$) | Tamper detection — audit trails & code integrity |
| **`OPERATIONAL_UTILITY`** | `0` | **Zero ($R_Q = 0.0$)** | **Suppressed from CISO queue (HTTP ETags & CDN caches)** |

### Deployment Exposure & Harvest Interception ($P_{\text{HNDL}}$)

| Exposure Profile | Assets | $P_{\text{HNDL}}$ Interception Factor | Threat Model Scope |
| :--- | :---: | :---: | :--- |
| **`PUBLIC`** | `289` | `1.00` | Internet Ingress / LoadBalancer (Actively harvested) |
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
| **#1** | `ASSET-001` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:12` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#2** | `ASSET-002` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:14` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#3** | `ASSET-003` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:15` | `Direct Cryptographic Material` | `IDEA` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#4** | `ASSET-004` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:17` | `Direct Cryptographic Material` | `IDEA-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#5** | `ASSET-005` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:16` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#6** | `ASSET-006` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:18` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#7** | `ASSET-007` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:15` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#8** | `ASSET-008` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:17` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#9** | `ASSET-010` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:19` | `Direct Cryptographic Material` | `RC4-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#10** | `ASSET-011` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:16` | `Direct Cryptographic Material` | `RC2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#11** | `ASSET-012` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:18` | `Direct Cryptographic Material` | `RC2-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#12** | `ASSET-013` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:16` | `Direct Cryptographic Material` | `IDEA` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#13** | `ASSET-014` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:18` | `Direct Cryptographic Material` | `IDEA-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#14** | `ASSET-015` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:12` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#15** | `ASSET-016` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:14` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#16** | `ASSET-018` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:14` | `Direct Cryptographic Material` | `RC4-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#17** | `ASSET-019` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:12` | `Direct Cryptographic Material` | `RC2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#18** | `ASSET-020` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:14` | `Direct Cryptographic Material` | `RC2-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#19** | `ASSET-021` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:20` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#20** | `ASSET-022` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:22` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#21** | `ASSET-023` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase6.java:15` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#22** | `ASSET-024` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase6.java:17` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#23** | `ASSET-026` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase7.java:17` | `Direct Cryptographic Material` | `RC4-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#24** | `ASSET-027` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase8.java:15` | `Direct Cryptographic Material` | `RC2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#25** | `ASSET-028` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase8.java:17` | `Direct Cryptographic Material` | `RC2-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#26** | `ASSET-029` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:12` | `Direct Cryptographic Material` | `IDEA` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#27** | `ASSET-030` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:14` | `Direct Cryptographic Material` | `IDEA-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#28** | `ASSET-031` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC1.java:12` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#29** | `ASSET-032` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC1.java:14` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#30** | `ASSET-033` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC2.java:12` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#31** | `ASSET-034` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC2.java:14` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#32** | `ASSET-036` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC3.java:14` | `Direct Cryptographic Material` | `RC4-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#33** | `ASSET-037` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC4.java:12` | `Direct Cryptographic Material` | `RC2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#34** | `ASSET-038` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC4.java:14` | `Direct Cryptographic Material` | `RC2-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#35** | `ASSET-039` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC5.java:12` | `Direct Cryptographic Material` | `IDEA` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#36** | `ASSET-040` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC5.java:14` | `Direct Cryptographic Material` | `IDEA-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#37** | `ASSET-051` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:28` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#38** | `ASSET-052` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:30` | `Direct Cryptographic Material` | `DES-56` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#39** | `ASSET-053` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:28` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#40** | `ASSET-054` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:30` | `Direct Cryptographic Material` | `Blowfish-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#41** | `ASSET-056` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase3.java:30` | `Direct Cryptographic Material` | `RC4-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#42** | `ASSET-057` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:29` | `Direct Cryptographic Material` | `RC2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#43** | `ASSET-058` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:31` | `Direct Cryptographic Material` | `RC2-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#44** | `ASSET-059` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:29` | `Direct Cryptographic Material` | `IDEA` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#45** | `ASSET-060` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:31` | `Direct Cryptographic Material` | `IDEA-128` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#46** | `ASSET-061` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:13` | `Direct Cryptographic Material` | `DES-56` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#47** | `ASSET-062` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:15` | `Direct Cryptographic Material` | `DES-56` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#48** | `ASSET-063` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:12` | `Direct Cryptographic Material` | `Blowfish-128` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#49** | `ASSET-064` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:14` | `Direct Cryptographic Material` | `Blowfish-128` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#50** | `ASSET-066` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase3.java:14` | `Direct Cryptographic Material` | `RC4-128` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Symmetric) | **`CRITICAL`** |
| **#51** | `ASSET-067` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:12` | `Direct Cryptographic Material` | `RC2` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#52** | `ASSET-068` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:14` | `Direct Cryptographic Material` | `RC2-128` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#53** | `ASSET-069` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:12` | `Direct Cryptographic Material` | `IDEA` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#54** | `ASSET-070` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:14` | `Direct Cryptographic Material` | `IDEA-128` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#55** | `ASSET-073` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:13` | `Direct Cryptographic Material` | `SHA-1` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#56** | `ASSET-074` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:18` | `Direct Cryptographic Material` | `MD5` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#57** | `ASSET-075` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:18` | `Direct Cryptographic Material` | `MD4` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#58** | `ASSET-076` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:18` | `Direct Cryptographic Material` | `MD2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#59** | `ASSET-077` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:13` | `Direct Cryptographic Material` | `MD5` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#60** | `ASSET-078` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:13` | `Direct Cryptographic Material` | `MD4` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#61** | `ASSET-079` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:13` | `Direct Cryptographic Material` | `MD2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#62** | `ASSET-080` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase5.java:25` | `Direct Cryptographic Material` | `SHA-1` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#63** | `ASSET-081` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase6.java:25` | `Direct Cryptographic Material` | `MD5` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#64** | `ASSET-082` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase7.java:25` | `Direct Cryptographic Material` | `MD4` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#65** | `ASSET-083` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase8.java:25` | `Direct Cryptographic Material` | `MD2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#66** | `ASSET-084` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:18` | `Direct Cryptographic Material` | `SHA-1` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#67** | `ASSET-085` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC1.java:8` | `Direct Cryptographic Material` | `SHA-1` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#68** | `ASSET-086` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC2.java:8` | `Direct Cryptographic Material` | `MD5` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#69** | `ASSET-087` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC3.java:8` | `Direct Cryptographic Material` | `MD4` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#70** | `ASSET-088` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC4.java:8` | `Direct Cryptographic Material` | `MD2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#71** | `ASSET-093` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:29` | `Direct Cryptographic Material` | `SHA-1` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#72** | `ASSET-094` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:31` | `Direct Cryptographic Material` | `MD5` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#73** | `ASSET-095` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:31` | `Direct Cryptographic Material` | `MD4` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#74** | `ASSET-096` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:31` | `Direct Cryptographic Material` | `MD2` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#75** | `ASSET-097` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase1.java:9` | `Direct Cryptographic Material` | `SHA-1` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#76** | `ASSET-098` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase2.java:9` | `Direct Cryptographic Material` | `MD5` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#77** | `ASSET-099` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase3.java:9` | `Direct Cryptographic Material` | `MD4` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#78** | `ASSET-100` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase4.java:9` | `Direct Cryptographic Material` | `MD2` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#79** | `ASSET-103` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:16` | `Direct Cryptographic Material` | `HMAC-MD5` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#80** | `ASSET-106` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:16` | `Direct Cryptographic Material` | `HMAC-SHA1` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | N/A (Cryptographic Hash) | **`CRITICAL`** |
| **#81** | `ASSET-112` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABHCase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#82** | `ASSET-114` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#83** | `ASSET-115` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#84** | `ASSET-117` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase3.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#85** | `ASSET-118` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABMC1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#86** | `ASSET-120` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#87** | `ASSET-123` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#88** | `ASSET-126` | `src/main/java/org/cryptoapi/bench/dummycertvalidation/DummyCertValidationCase1.java:7` | `Direct Cryptographic Material` | `DUMMY-CERT-VALIDATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#89** | `ASSET-127` | `src/main/java/org/cryptoapi/bench/dummycertvalidation/DummyCertValidationCase2.java:7` | `Direct Cryptographic Material` | `DUMMY-CERT-VALIDATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#90** | `ASSET-128` | `src/main/java/org/cryptoapi/bench/dummycertvalidation/DummyCertValidationCase3.java:7` | `Direct Cryptographic Material` | `DUMMY-CERT-VALIDATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#91** | `ASSET-129` | `src/main/java/org/cryptoapi/bench/dummyhostnameverifier/DummyHostNameVerifierCase1.java:6` | `Direct Cryptographic Material` | `DUMMY-HOSTNAME-VERIFIER` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#92** | `ASSET-132` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:14` | `Direct Cryptographic Material` | `AES-ECB` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#93** | `ASSET-134` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:17` | `Direct Cryptographic Material` | `AES-ECB` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#94** | `ASSET-136` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:18` | `Direct Cryptographic Material` | `AES-ECB` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#95** | `ASSET-138` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMC1.java:15` | `Direct Cryptographic Material` | `AES-ECB` | `CONFIGURABLE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#96** | `ASSET-144` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoBBCase1.java:14` | `Direct Cryptographic Material` | `AES-ECB` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#97** | `ASSET-147` | `src/main/java/org/cryptoapi/bench/http/HttpProtocolABICase1.java:1` | `Direct Cryptographic Material` | `CLEARTEXT-HTTP` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#98** | `ASSET-148` | `src/main/java/org/cryptoapi/bench/http/HttpProtocolABICase2.java:1` | `Direct Cryptographic Material` | `CLEARTEXT-HTTP` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#99** | `ASSET-149` | `src/main/java/org/cryptoapi/bench/http/HttpProtocolABICase3.java:1` | `Direct Cryptographic Material` | `CLEARTEXT-HTTP` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#100** | `ASSET-150` | `src/main/java/org/cryptoapi/bench/http/HttpProtocolABMC1.java:1` | `Direct Cryptographic Material` | `CLEARTEXT-HTTP` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#101** | `ASSET-151` | `src/main/java/org/cryptoapi/bench/http/HttpProtocolBBCase1.java:1` | `Direct Cryptographic Material` | `CLEARTEXT-HTTP` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#102** | `ASSET-152` | `src/main/java/org/cryptoapi/bench/impropersslsocketfactory/ImproperSocketManualHostBBCase1.java:9` | `Direct Cryptographic Material` | `IMPROPER-SSL-SOCKET-FACTORY` | `RUNTIME_AGILE` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#103** | `ASSET-153` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:12` | `Direct Cryptographic Material` | `RSA-1024` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | Composite-Sign (ECDSA-P256 + ML-DSA-44) | **`CRITICAL`** |
| **#104** | `ASSET-154` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:16` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#105** | `ASSET-155` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:24` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#106** | `ASSET-156` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:16` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#107** | `ASSET-157` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:24` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#108** | `ASSET-158` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:41` | `Direct Cryptographic Material` | `RSA-1024` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | Composite-Sign (ECDSA-P256 + ML-DSA-44) | **`CRITICAL`** |
| **#109** | `ASSET-159` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:18` | `Direct Cryptographic Material` | `RSA-1024` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | Composite-Sign (ECDSA-P256 + ML-DSA-44) | **`CRITICAL`** |
| **#110** | `ASSET-160` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:23` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#111** | `ASSET-161` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:31` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#112** | `ASSET-162` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:13` | `Direct Cryptographic Material` | `RSA-1024` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | Composite-Sign (ECDSA-P256 + ML-DSA-44) | **`CRITICAL`** |
| **#113** | `ASSET-163` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:16` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#114** | `ASSET-164` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:17` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#115** | `ASSET-166` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABPSCase1.java:20` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#116** | `ASSET-167` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:9` | `Direct Cryptographic Material` | `RSA-1024` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | Composite-Sign (ECDSA-P256 + ML-DSA-44) | **`CRITICAL`** |
| **#117** | `ASSET-168` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:15` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#118** | `ASSET-169` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:23` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#119** | `ASSET-171` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABHCase1.java:1` | `Direct Cryptographic Material` | `PBE-WEAK-ITERATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#120** | `ASSET-173` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABICase1.java:1` | `Direct Cryptographic Material` | `PBE-WEAK-ITERATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#121** | `ASSET-175` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABICase2.java:1` | `Direct Cryptographic Material` | `PBE-WEAK-ITERATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#122** | `ASSET-177` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABICase3.java:1` | `Direct Cryptographic Material` | `PBE-WEAK-ITERATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#123** | `ASSET-179` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABMC1.java:1` | `Direct Cryptographic Material` | `PBE-WEAK-ITERATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#124** | `ASSET-183` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEBBCase1.java:1` | `Direct Cryptographic Material` | `PBE-WEAK-ITERATION` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#125** | `ASSET-185` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABHCase2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#126** | `ASSET-186` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#127** | `ASSET-187` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#128** | `ASSET-188` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase3.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#129** | `ASSET-189` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABMC1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#130** | `ASSET-191` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#131** | `ASSET-192` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyBBCase1.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-KEY` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#132** | `ASSET-196` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABHCase2.java:31` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#133** | `ASSET-197` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABICase1.java:22` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#134** | `ASSET-198` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABICase2.java:33` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#135** | `ASSET-199` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABICase3.java:27` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#136** | `ASSET-200` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABMC1.java:17` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#137** | `ASSET-202` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABSCase1.java:34` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#138** | `ASSET-203` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordBBCase1.java:23` | `Direct Cryptographic Material` | `PREDICTABLE-KEYSTORE-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#139** | `ASSET-207` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABHCase2.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#140** | `ASSET-209` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABICase1.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#141** | `ASSET-211` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABICase2.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#142** | `ASSET-213` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABICase3.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#143** | `ASSET-215` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABMC1.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#144** | `ASSET-218` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABSCase1.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#145** | `ASSET-220` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordBBCase1.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#146** | `ASSET-222` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordBBCase2.java:1` | `Direct Cryptographic Material` | `HARDCODED-PASSWORD` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#147** | `ASSET-224` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABHCase2.java:19` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#148** | `ASSET-227` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABHCase4.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#149** | `ASSET-228` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase1.java:13` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#150** | `ASSET-230` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#151** | `ASSET-231` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase3.java:25` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#152** | `ASSET-233` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase4.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#153** | `ASSET-234` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase5.java:17` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#154** | `ASSET-236` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase6.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#155** | `ASSET-237` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABMC1.java:8` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#156** | `ASSET-239` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABMC2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#157** | `ASSET-242` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABSCase1.java:34` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#158** | `ASSET-244` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABSCase2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#159** | `ASSET-245` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsBBCase1.java:10` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#160** | `ASSET-247` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsBBCase2.java:1` | `Direct Cryptographic Material` | `PREDICTABLE-SEED` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#161** | `ASSET-251` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#162** | `ASSET-254` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#163** | `ASSET-257` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#164** | `ASSET-260` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#165** | `ASSET-263` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#166** | `ASSET-266` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#167** | `ASSET-272` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#168** | `ASSET-275` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:1` | `Direct Cryptographic Material` | `STATIC-IV` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (Key Exchange) or Composite ML-DSA | **`CRITICAL`** |
| **#169** | `ASSET-279` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABHCase1.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#170** | `ASSET-280` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABICase1.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#171** | `ASSET-281` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABICase2.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#172** | `ASSET-282` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABICase3.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#173** | `ASSET-283` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABMC1.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#174** | `ASSET-285` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABSCase1.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#175** | `ASSET-286` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsBBCase1.java:1` | `Direct Cryptographic Material` | `STATIC-SALT` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#176** | `ASSET-288` | `src/main/java/org/cryptoapi/bench/untrustedprng/UntrustedPRNGCase1.java:1` | `Direct Cryptographic Material` | `UNTRUSTED-PRNG` | `RIGID` | `OPERATIONAL` | **`-5.0y`** | `2026` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`CRITICAL`** |
| **#177** | `ASSET-142` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:34` | `Direct Cryptographic Material` | `DYNAMIC_UNRESOLVED` | `RIGID` | `HUMAN_REVIEW` | **`+0.0y`** | `2030` | Manual Triage Required | **`MANUAL_REVIEW_REQUIRED`** |
| **#178** | `ASSET-165` | `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABPSCase1.java:8` | `Direct Cryptographic Material` | `RSA-2048` | `RIGID` | `OPERATIONAL` | **`+0.0y`** | `2031` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`CRITICAL`** |
| **#179** | `ASSET-009` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:17` | `Direct Cryptographic Material` | `RC4` | `CONFIGURABLE` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#180** | `ASSET-017` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:12` | `Direct Cryptographic Material` | `RC4` | `CONFIGURABLE` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#181** | `ASSET-025` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase7.java:15` | `Direct Cryptographic Material` | `RC4` | `CONFIGURABLE` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#182** | `ASSET-035` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC3.java:12` | `Direct Cryptographic Material` | `RC4` | `CONFIGURABLE` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#183** | `ASSET-041` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#184** | `ASSET-042` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:16` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#185** | `ASSET-043` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:11` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#186** | `ASSET-044` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#187** | `ASSET-045` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase3.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#188** | `ASSET-046` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase3.java:16` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#189** | `ASSET-047` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#190** | `ASSET-048` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:16` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#191** | `ASSET-049` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:11` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#192** | `ASSET-050` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#193** | `ASSET-055` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase3.java:28` | `Direct Cryptographic Material` | `RC4` | `CONFIGURABLE` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#194** | `ASSET-065` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase3.java:12` | `Direct Cryptographic Material` | `RC4` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM512 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#195** | `ASSET-071` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoCorrected.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#196** | `ASSET-072` | `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoCorrected.java:14` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#197** | `ASSET-089` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase1.java:11` | `Direct Cryptographic Material` | `SHA-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Cryptographic Hash) | **`LOW`** |
| **#198** | `ASSET-090` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase2.java:11` | `Direct Cryptographic Material` | `SHA-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Cryptographic Hash) | **`LOW`** |
| **#199** | `ASSET-091` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase3.java:11` | `Direct Cryptographic Material` | `SHA-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Cryptographic Hash) | **`LOW`** |
| **#200** | `ASSET-092` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase4.java:11` | `Direct Cryptographic Material` | `SHA-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Cryptographic Hash) | **`LOW`** |
| **#201** | `ASSET-101` | `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashCorrected.java:10` | `Direct Cryptographic Material` | `SHA-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Cryptographic Hash) | **`LOW`** |
| **#202** | `ASSET-102` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:10` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#203** | `ASSET-104` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#204** | `ASSET-105` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:10` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#205** | `ASSET-107` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#206** | `ASSET-108` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:10` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#207** | `ASSET-109` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:16` | `Direct Cryptographic Material` | `HMAC-SHA256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Cryptographic Hash) | **`LOW`** |
| **#208** | `ASSET-110` | `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#209** | `ASSET-111` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABHCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#210** | `ASSET-113` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#211** | `ASSET-116` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase3.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#212** | `ASSET-119` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABMCCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#213** | `ASSET-121` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:22` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#214** | `ASSET-122` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#215** | `ASSET-124` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringCorrected.java:21` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#216** | `ASSET-125` | `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#217** | `ASSET-130` | `src/main/java/org/cryptoapi/bench/dummyhostnameverifier/DummyHostNameVerifierCorrected.java:7` | `Direct Cryptographic Material` | `TLS-HOSTNAME-VERIFIER` | `RUNTIME_AGILE` | `OPERATIONAL` | **`+19.0y`** | `2050` | ECDSA-P256 + ML-DSA-65 (Composite Signature) | **`LOW`** |
| **#218** | `ASSET-131` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#219** | `ASSET-133` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#220** | `ASSET-135` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:16` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#221** | `ASSET-137` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMC1.java:13` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#222** | `ASSET-139` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABPSCase1.java:11` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#223** | `ASSET-140` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABPSCase1.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#224** | `ASSET-141` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:32` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#225** | `ASSET-143` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoBBCase1.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#226** | `ASSET-145` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoCorrected.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#227** | `ASSET-146` | `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoCorrected.java:14` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#228** | `ASSET-170` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABHCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#229** | `ASSET-172` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABICase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#230** | `ASSET-174` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABICase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#231** | `ASSET-176` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABICase3.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#232** | `ASSET-178` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABMC1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#233** | `ASSET-180` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#234** | `ASSET-181` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEABSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#235** | `ASSET-182` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBEBBCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#236** | `ASSET-184` | `src/main/java/org/cryptoapi/bench/pbeiteration/LessThan1000IterationPBECorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#237** | `ASSET-190` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#238** | `ASSET-193` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyCorrected.java:21` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#239** | `ASSET-194` | `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#240** | `ASSET-195` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABHCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#241** | `ASSET-201` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#242** | `ASSET-204` | `src/main/java/org/cryptoapi/bench/predictablekeystorepassword/PredictableKeyStorePasswordCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#243** | `ASSET-205` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABHCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#244** | `ASSET-206` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABHCase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#245** | `ASSET-208` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABICase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#246** | `ASSET-210` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABICase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#247** | `ASSET-212` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABICase3.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#248** | `ASSET-214` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABMC1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#249** | `ASSET-216` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#250** | `ASSET-217` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordABSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#251** | `ASSET-219` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordBBCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#252** | `ASSET-221` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordBBCase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#253** | `ASSET-223` | `src/main/java/org/cryptoapi/bench/predictablepbepassword/PredictablePBEPasswordCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#254** | `ASSET-225` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABHCase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#255** | `ASSET-226` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABHCase4.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#256** | `ASSET-229` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#257** | `ASSET-232` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase3.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#258** | `ASSET-235` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABICase5.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#259** | `ASSET-238` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABMC1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#260** | `ASSET-240` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#261** | `ASSET-241` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABPSCase2.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#262** | `ASSET-243` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#263** | `ASSET-246` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsBBCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#264** | `ASSET-248` | `src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#265** | `ASSET-249` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#266** | `ASSET-250` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:17` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#267** | `ASSET-252` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:16` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#268** | `ASSET-253` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:18` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#269** | `ASSET-255` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:13` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#270** | `ASSET-256` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#271** | `ASSET-258` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:18` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#272** | `ASSET-259` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:20` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#273** | `ASSET-261` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:13` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#274** | `ASSET-262` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#275** | `ASSET-264` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:15` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#276** | `ASSET-265` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:17` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#277** | `ASSET-267` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#278** | `ASSET-268` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:14` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#279** | `ASSET-269` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#280** | `ASSET-270` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:33` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#281** | `ASSET-271` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:35` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#282** | `ASSET-273` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:12` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#283** | `ASSET-274` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:14` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#284** | `ASSET-276` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:39` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#285** | `ASSET-277` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:41` | `Direct Cryptographic Material` | `AES-256` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | N/A (Symmetric) | **`LOW`** |
| **#286** | `ASSET-278` | `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#287** | `ASSET-284` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsABPSCase1.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#288** | `ASSET-287` | `src/main/java/org/cryptoapi/bench/staticsalts/StaticSaltsCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |
| **#289** | `ASSET-289` | `src/main/java/org/cryptoapi/bench/untrustedprng/UntrustedPRNGCorrected.java:1` | `Direct Cryptographic Material` | `SECURE-PRNG` | `RIGID` | `OPERATIONAL` | **`+19.0y`** | `2050` | X25519MLKEM768 (ECDHE-ML-KEM Hybrid) | **`LOW`** |

---

## 3. Cryptographic Agility & Buffer Hazard Audit

No fixed-size buffer hazards detected adjacent to cryptographic call sites.

---

## 4. Epidemiological R0 Dependency Contagion (Superspreaders)

Cryptographic vulnerability propagates through software dependency contact networks. The **$R_0$ score** measures how many downstream services inherit quantum risk from an unmigrated component.

No critical cryptographic superspreader hubs detected. Vulnerabilities are isolated to individual endpoints.

---

## 5. Privacy-Preserving Attestation via Merkle Commitments

Conventional audit practices require handing over full, plain-text Cryptography Bills of Materials (CBOMs), which inadvertently functions as a targeting map for adversaries. ECDAT resolves this through **selective inclusion proofs**:

- **Committed Root Hash:** `0x2df9c2d84eb0a75eb4313f5ec9130b27fb86fb4765d8336543c00b78bf8f01a5`
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
| `build` | `EXCLUDED_DIR` | Standard dependency / build artifact directory 'build' excluded by scanning policy | Execute dedicated supply-chain audit on lockfiles if unmanaged vendor packages exist. |
| `.git` | `EXCLUDED_DIR` | Standard dependency / build artifact directory '.git' excluded by scanning policy | Execute dedicated supply-chain audit on lockfiles if unmanaged vendor packages exist. |
| `.gradle/9.2.0/fileChanges/last-build.bin` | `UNINSPECTED_BINARY` | Compiled binary format '.bin' cannot be analyzed via static source AST | Perform binary symbol extraction or dynamic eBPF runtime audit. |
| `.gradle/9.2.0/fileHashes/fileHashes.bin` | `UNINSPECTED_BINARY` | Compiled binary format '.bin' cannot be analyzed via static source AST | Perform binary symbol extraction or dynamic eBPF runtime audit. |
| `.gradle/8.9/fileChanges/last-build.bin` | `UNINSPECTED_BINARY` | Compiled binary format '.bin' cannot be analyzed via static source AST | Perform binary symbol extraction or dynamic eBPF runtime audit. |

---

## 7. SLSA / in-toto Signed DSSE Attestation & Negative Proofs

ECDAT produces cryptographically non-malleable, tamper-evident audit attestations complying with the **in-toto v1.0 Statement** specification and **RFC 9162 Dead Simple Signing Envelope (DSSE)**.

- **Attestation Envelope File:** `attestation.dsse.json`
- **Payload Type:** `application/vnd.in-toto+json`
- **Predicate Type:** `https://ecdat.dev/attestation/v1`
- **Primary Signer Key ID:** `ed25519:5a20ea9e828ea614` (2 signatures: Ed25519 primary + ML-DSA-65 post-quantum hybrid commitment)
- **Committed Merkle Root:** `0x2df9c2d84eb0a75eb4313f5ec9130b27fb86fb4765d8336543c00b78bf8f01a5`

### Certified Negative Proofs

> **Assertion:** Audited perimeter contains 5 declared boundary unknowns; all other paths certified.
> 
> ECDAT certifies that within the audited codebase boundary (289 cryptographic assets discovered), no reachable vulnerable primitives outside the declared inventory exist. All exclusions and uninspected binary files are strictly quarantined in the Auditable Unknowns Ledger.

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
- **Allocated Effort:** `10.0 dev-weeks`
- **Estate Risk Reduction Achieved:** `+5.6%` (13 / 289 assets selected)

| Asset ID | Component | Algorithm | Effort (dev-wks) | Blast Reduction ($\Delta R$) | ROI Efficiency | Sprint Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `ASSET-152` | `ImproperSocketManualHostBBCase1:improper_ssl_socket` | `IMPROPER-SSL-SOCKET-FACTORY` | `0.3` | `10.0` | `29.41` | **SELECTED FOR SPRINT** |
| `ASSET-002` | `BrokenCryptoABICase1:des_56` | `DES-56` | `1.2` | `10.0` | `8.26` | **SELECTED FOR SPRINT** |
| `ASSET-004` | `BrokenCryptoABICase10:idea_128` | `IDEA-128` | `1.2` | `10.0` | `8.26` | **SELECTED FOR SPRINT** |
| `ASSET-006` | `BrokenCryptoABICase11:des_56` | `DES-56` | `1.2` | `10.0` | `8.26` | **SELECTED FOR SPRINT** |
| `ASSET-008` | `BrokenCryptoABICase12:blowfish_128` | `Blowfish-128` | `1.2` | `10.0` | `8.26` | **SELECTED FOR SPRINT** |
| `ASSET-010` | `BrokenCryptoABICase13:rc4_128` | `RC4-128` | `1.2` | `10.0` | `8.26` | **SELECTED FOR SPRINT** |
| `ASSET-012` | `BrokenCryptoABICase14:rc2_128` | `RC2-128` | `1.2` | `10.0` | `8.26` | **SELECTED FOR SPRINT** |
| `ASSET-014` | `BrokenCryptoABICase15:idea_128` | `IDEA-128` | `1.2` | `10.0` | `8.26` | **DEFERRED** |
| `ASSET-016` | `BrokenCryptoABICase2:blowfish_128` | `Blowfish-128` | `1.2` | `10.0` | `8.26` | **DEFERRED** |
| `ASSET-018` | `BrokenCryptoABICase3:rc4_128` | `RC4-128` | `1.2` | `10.0` | `8.26` | **DEFERRED** |

---

## 9. Stochastic Monte Carlo Quantum Risk Analysis

Under empirical Monte Carlo sampling (5000 iterations) calibrated against the Global Risk Institute (GRI) 2025 Quantum Threat Report:

- **Mean Estate Breach Probability:** `55.8%`
- **Peak Single-Asset Breach Probability:** `61.5%`
- **Critical Probabilistic Exposure Assets:** `183`
