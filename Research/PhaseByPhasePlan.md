# ECDAT Implementation Plan: Phase-by-Phase Roadmap

This document outlines the step-by-step technical implementation plan for **ECDAT** (Enterprise Cryptographic Discovery and Analysis Tool) inside `/mnt/shared/ECDAT`. Each phase is self-contained with clear deliverables and automated verification criteria, designed to proceed one phase at a time without breaking dependencies.

---

## Architecture & Directory Structure

We will organize `/mnt/shared/ECDAT` into a clean modular Python package alongside our reference materials:

```
/mnt/shared/ECDAT/
├── Research/                  # Existing plans, presentations, benchmarks, scripts
├── bin/                       # Local compiled tooling (cbomkit-theia binary)
├── ecdat/                     # Core Python Engine
│   ├── __init__.py
│   ├── constants.py           # NIST FIPS, OMB M-26-15, GRI 2025 lookup tables
│   ├── models.py              # Pydantic / dataclasses for CBOM assets & scores
│   ├── mosca/                 # Phase 1: Mosca Engine (Y_max = Z - X)
│   │   ├── __init__.py
│   │   └── engine.py
│   ├── merkle/                # Phase 2: Merkle Tree & Inclusion Proofs
│   │   ├── __init__.py
│   │   ├── tree.py
│   │   └── verifier.py
│   ├── x_inference/           # Phase 3: 4-Tier X-Inference & Taint Sinks
│   │   ├── __init__.py
│   │   ├── ast_tracer.py
│   │   └── sink_stubs.py
│   ├── agility/               # Phase 4: Hybrid Guidance & Buffer Audit
│   │   ├── __init__.py
│   │   ├── recommender.py
│   │   └── buffer_audit.py
│   ├── pipeline.py            # Phase 5: End-to-End Orchestrator (CLI)
│   └── report.py              # Executive CISO summary generator
├── tests/                     # Automated test suite (pytest)
│   ├── test_mosca.py
│   ├── test_merkle.py
│   ├── test_x_inference.py
│   ├── test_agility.py
│   └── test_pipeline.py
├── testbeds/                  # Target test codebases with ground truth
│   └── sample_crypto_app/     # Sample app with mixed crypto & persistence sinks
├── pyproject.toml             # Python package configuration
└── requirements.txt           # Project dependencies
```

---

## Phase 0: Workspace Scaffolding & Tooling Setup

**Goal:** Establish the project directories, virtual environment, system dependencies, and install `cbomkit-theia`.

### Tasks:
1. Create directories: `ecdat/`, `tests/`, `bin/`, `testbeds/sample_crypto_app/`.
2. Initialize Python virtual environment `.venv` inside `/mnt/shared/ECDAT`.
3. Install core Python dependencies:
   - `cyclonedx-bom` (for CycloneDX 1.6 / ECMA-424 CBOM processing)
   - `cryptography` (for high-speed SHA-256 Merkle tree hashing)
   - `networkx` (for dependency graph & call-graph analysis)
   - `pydantic` (for rigorous data validation & schema serialization)
   - `pytest` (for automated test verification)
4. Compile/install `cbomkit-theia` binary into `/mnt/shared/ECDAT/bin/` using Go `go1.26.2`.

### Deliverables:
- Working virtual environment `.venv` with all dependencies installed.
- Executable binary `bin/cbomkit-theia --version` functioning locally.

---

## Phase 1: Reference Data Tables & Mosca Temporal Planning Engine

**Goal:** Implement the mathematical foundation of ECDAT: $Y_{max} = Z - X$ with dual-Z lookups and crypto-shredding evaluation.

### Tasks:
1. **`ecdat/constants.py`**:
   - `NIST_PRIMITIVE_SIZES`: ECDSA (64 B), RSA-2048 (256 B), ML-DSA-65 (3,309 B), ML-DSA-87 (4,627 B), SLH-DSA (17,088 B), ML-KEM-768 ciphertext (1,088 B).
   - `OMB_M2615_SCHEDULE`: Phase 3 (2030, Key Establishment), Phase 4 (2031, Signatures), Phase 5 (2035, Full Disallowance).
   - `GRI_2025_DISTRIBUTION`: 10-year CRQC probability (28%–49%), 15-year (67%–89%).
2. **`ecdat/models.py`**:
   - `CryptoAsset`: Algorithm, key size, primitive type, file path, line number.
   - `XTier`: Enum (`EPHEMERAL`, `SHORT_TERM`, `OPERATIONAL`, `ARCHIVAL`, `HUMAN_REVIEW`).
   - `MoscaScore`: $X$ (years), $Y_{max}$ (years), $Z_{regulatory}$, $Z_{physical}$, risk category, crypto-shredding flag.
3. **`ecdat/mosca/engine.py`**:
   - Function `compute_mosca_score(asset: CryptoAsset, x_years: float, has_crypto_shredding: bool) -> MoscaScore`.
   - Computes $Y_{max} = Z_{regulatory} - X$.
   - Flags if crypto-shredding reduces effective $X$ from Archival (10 yr) to Operational/Short-term (1–2 yr).
   - Assigns priority ranking: `CRITICAL` ($Y_{max} \le 1.0$), `HIGH` ($1.0 < Y_{max} \le 3.0$), `MEDIUM` ($3.0 < Y_{max} \le 5.0$), `LOW` ($Y_{max} > 5.0$).
4. **Unit Tests (`tests/test_mosca.py`)**:
   - Test $Y_{max}$ for RSA-2048 with $X=10$ (Archival) vs $X=0$ (Ephemeral).
   - Test crypto-shredding lever effect.
   - Test boundary conditions (negative $Y_{max}$ = already past deadline).

### Deliverables:
- Fully tested, deterministic Mosca engine with OMB M-26-15 and GRI 2025 dual-Z grounding.

---

## Phase 2: Privacy-Preserving Merkle Tree Commitment & Proof Exporter

**Goal:** Build the cryptographic attestation module that allows external compliance audits via selective inclusion proofs without exposing internal codebases.

### Tasks:
1. **`ecdat/merkle/tree.py`**:
   - `hash_asset_leaf(asset: CryptoAsset, score: MoscaScore, salt: str) -> bytes`: Deterministic canonical SHA-256 leaf serializer.
   - `MerkleTree` class:
     - Builds balanced binary tree from an arbitrary list of leaves.
     - Computes the single 32-byte root (`cbom_root.hex`).
     - Generates selective inclusion proof: `get_proof(leaf_index) -> List[SiblingHash]`.
2. **`ecdat/merkle/verifier.py`**:
   - Standalone verifier function: `verify_proof(leaf_data, sibling_hashes, expected_root) -> bool`.
   - CLI command for third-party auditors: `ecdat-verify --proof proof_asset_12.json --root cbom_root.hex`.
3. **Unit Tests (`tests/test_merkle.py`)**:
   - Test Merkle root reproducibility across identical asset sets.
   - Test valid selective inclusion proofs for specific leaves.
   - Test that tampering with any field (e.g. changing algorithm or key size) causes proof verification to fail.

### Deliverables:
- Working Merkle tree commitment generator and auditor verification tool.

---

## Phase 3: Automated 4-Tier X-Inference & Taint Persistence Engine

**Goal:** Automate data lifespan $X$ detection using static AST parsing and pre-annotated persistence sink signatures.

### Tasks:
1. **`ecdat/x_inference/sink_stubs.py`**:
   - Pre-annotated sink library:
     - Relational & ORM Sinks (`session.add`, `repository.save`, `PreparedStatement.setBytes`, `pymongo.insert_one`) $\to$ `OPERATIONAL` (~5 yr) / `ARCHIVAL` (~10 yr).
     - Object & Cloud Sinks (`s3.put_object`, `blobClient.upload`) $\to$ `ARCHIVAL` (~10 yr).
     - Cache & Memory Sinks (`redis.setex` with TTL, `memcached.set`) $\to$ `SHORT_TERM` (~1–2 yr).
     - Ephemeral / Zeroization (`socket.send`, `Arrays.fill(0)`, `sodium_memzero`) $\to$ `EPHEMERAL` (~0 yr).
2. **`ecdat/x_inference/ast_tracer.py`**:
   - Static AST visitor for Python files:
     - Detects cryptographic assignments (`c = cipher.encrypt(...)`).
     - Traces dataflow of `c` to surrounding function calls and sinks.
     - Maps target sinks to `XTier`.
     - Assigns confidence: `HIGH` (explicit sink found), `MEDIUM` (heuristic match), `HUMAN_REVIEW` (cross-boundary call into unknown library).
3. **Unit Tests (`tests/test_x_inference.py`)**:
   - Test classification on RAM-only TLS socket code $\to$ `EPHEMERAL`.
   - Test classification on database write (`db.session.add(record)`) $\to$ `OPERATIONAL`.
   - Test classification on file backup (`open('backup.enc', 'wb')`) $\to$ `ARCHIVAL`.
   - Test unanalyzed external call $\to$ `HUMAN_REVIEW` with warning flag.

### Deliverables:
- AST-based persistence tracer classifying crypto assets into the 4 tiers with confidence metrics.

---

## Phase 4: Hybrid-First Guidance & Buffer Agility Auditor

**Goal:** Implement algorithm replacement recommendations aligned with FIPS 203/204/205 and audit codebases for fixed-size buffer overflow hazards.

### Tasks:
1. **`ecdat/agility/recommender.py`**:
   - Recommends standardized PQC primitives and hybrid pairings:
     - Classical RSA/ECDH $\to$ Hybrid `X25519MLKEM768` (RFC 9180 / draft-ietf-tls-ecdhe-mlkem) or standalone FIPS 203 `ML-KEM-768`.
     - Classical RSA/ECDSA $\to$ Dual composite signature (`ECDSA-P256 + ML-DSA-65`) or standalone FIPS 204 `ML-DSA-65`.
     - Hash-based signature fallback: FIPS 205 `SLH-DSA`.
2. **`ecdat/agility/buffer_audit.py`**:
   - Scans variable allocations adjacent to cryptographic call sites.
   - Detects fixed-size byte array allocations (e.g., `byte[64]` or `byte[256]`) attempting to store PQC outputs.
   - Generates buffer hazard warnings (e.g., *"Buffer size 64 bytes is insufficient for ML-DSA-65 signature size of 3,309 bytes"*).
3. **Unit Tests (`tests/test_agility.py`)**:
   - Test recommendation mapping for RSA-2048, ECDSA P-256, and ECDH.
   - Test buffer hazard detection on fixed 64-byte array declarations.

### Deliverables:
- Cryptographic agility auditor and hybrid recommendation engine.

---

## Phase 5: CBOMkit Ingestion, End-to-End Pipeline & CISO Reporting

**Goal:** Connect all modules into a unified CLI tool that ingests standard CBOM files, enriches them with our risk and agility calculations, and outputs executive reports.

### Tasks:
1. **`ecdat/pipeline.py` (Main CLI)**:
   - Command: `ecdat scan --dir /path/to/project --output-cbom enriched_cbom.json`
   - Steps:
     1. Runs `cbomkit-theia` on target directory $\to$ baseline CycloneDX CBOM JSON.
     2. Runs `x_inference` on source files $\to$ assigns $X$-tier & confidence.
     3. Runs `mosca` engine $\to$ computes $Y_{max}$, dual-$Z$, and priority ranking.
     4. Runs `agility` auditor $\to$ adds hybrid recommendations and buffer warnings.
     5. Runs `merkle` builder $\to$ constructs tree, exports `cbom_root.hex` and proof catalog.
2. **`ecdat/report.py`**:
   - Generates executive CISO Markdown summary:
     - Total assets scanned, breakdown by $X$-tier.
     - Top priority migration list ranked by shortest $Y_{max}$.
     - 32-Byte Merkle root commitment.
     - Agility & buffer overflow hazard callouts.
3. **Integration Test on `testbeds/sample_crypto_app` (`tests/test_pipeline.py`)**:
   - End-to-end execution on our sample app with verification of all outputs.

### Deliverables:
- Fully integrated, end-to-end ECDAT CLI tool and test suite.

---

## Verification Plan

### Automated Tests
- Run complete test suite:
  ```bash
  pytest -v /mnt/shared/ECDAT/tests/
  ```
- Run end-to-end scan on sample testbed:
  ```bash
  python -m ecdat.pipeline scan --target testbeds/sample_crypto_app
  ```
- Run independent Merkle proof verification:
  ```bash
  python -m ecdat.merkle.verifier --proof testbeds/sample_crypto_app/proofs/proof_0.json --root testbeds/sample_crypto_app/cbom_root.hex
  ```

### Manual Review Checkpoint
- Inspect the generated `enriched_cbom.json` to verify compliance with CycloneDX 1.6 / ECMA-424.
- Inspect the executive CISO report to verify risk prioritization and $Y_{max}$ calculations.
