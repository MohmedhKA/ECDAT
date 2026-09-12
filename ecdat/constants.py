"""
ECDAT Constants: Regulatory mandates, physical quantum arrival distributions,
and cryptographic primitive size specifications.

All values are grounded in official published standards:
- NIST IR 8547: Transition to Post-Quantum Cryptography Standards (Nov 2024)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) (Aug 2024)
- US OMB M-26-15: Executive Memorandum on Federal PQC Transition (June 24, 2026)
- Global Risk Institute (GRI): Quantum Threat Timeline Report 2025
"""

CURRENT_YEAR = 2026

# NIST IR 8547 & OMB M-26-15 5-Phase Schedule Deadlines
OMB_M2615_SCHEDULE = {
    "PHASE_1": {
        "year": 2025,
        "name": "Governance & Discovery Mandate",
        "description": "Establish post-quantum executive governance and initiate cryptographic inventory.",
    },
    "PHASE_2": {
        "year": 2026,
        "name": "Automated Tooling & Discovery Baseline",
        "description": "Deploy automated discovery tooling to produce initial enterprise CBOMs by October 2026.",
    },
    "PHASE_3": {
        "year": 2030,
        "name": "Key Establishment Deprecation",
        "description": "Classical key establishment algorithms (RSA key exchange, DH, ECDH) deprecated and disallowed for high-impact systems.",
    },
    "PHASE_4": {
        "year": 2031,
        "name": "Digital Signature Deprecation",
        "description": "Classical digital signature algorithms (RSA signatures, DSA, ECDSA) deprecated across federal civilian agencies.",
    },
    "PHASE_5": {
        "year": 2035,
        "name": "Full Classical Disallowance",
        "description": "Total disallowance of all classical public-key cryptography across all federal and critical infrastructure systems.",
    },
}

# Global Risk Institute (GRI) 2025 Survey: Probabilistic CRQC Arrival Distributions
GRI_2025_DISTRIBUTION = {
    "5_YEAR": {
        "target_year": 2030,
        "probability_range": "7%–18%",
        "mean_probability": 0.125,
    },
    "10_YEAR": {
        "target_year": 2035,
        "probability_range": "28%–49%",
        "mean_probability": 0.385,
    },
    "15_YEAR": {
        "target_year": 2040,
        "probability_range": "67%–89%",
        "mean_probability": 0.780,
    },
}

# Exact Cryptographic Sizes (bytes) per NIST FIPS 203/204/205 & Classical Baselines
NIST_PRIMITIVE_SIZES = {
    # Classical Signatures
    "ECDSA_P256": {"signature_bytes": 64, "public_key_bytes": 64, "security_category": "Classical (128-bit)"},
    "ECDSA_P384": {"signature_bytes": 96, "public_key_bytes": 96, "security_category": "Classical (192-bit)"},
    "RSA_2048":   {"signature_bytes": 256, "public_key_bytes": 256, "security_category": "Classical (112-bit)"},
    "RSA_3072":   {"signature_bytes": 384, "public_key_bytes": 384, "security_category": "Classical (128-bit)"},
    "RSA_4096":   {"signature_bytes": 512, "public_key_bytes": 512, "security_category": "Classical (192-bit)"},

    # NIST FIPS 204: ML-DSA (Lattice-Based Signatures)
    "ML_DSA_44":  {"signature_bytes": 2420, "public_key_bytes": 1312, "security_category": "NIST Level 2"},
    "ML_DSA_65":  {"signature_bytes": 3309, "public_key_bytes": 1952, "security_category": "NIST Level 3"},
    "ML_DSA_87":  {"signature_bytes": 4627, "public_key_bytes": 2592, "security_category": "NIST Level 5"},

    # NIST FIPS 205: SLH-DSA (Stateless Hash-Based Signatures)
    "SLH_DSA_128F": {"signature_bytes": 17088, "public_key_bytes": 32, "security_category": "NIST Level 1"},
    "SLH_DSA_128S": {"signature_bytes": 7856,  "public_key_bytes": 32, "security_category": "NIST Level 1"},

    # NIST FIPS 203: ML-KEM (Key Encapsulation Mechanism)
    "ML_KEM_512":  {"ciphertext_bytes": 768,  "public_key_bytes": 800,  "security_category": "NIST Level 1"},
    "ML_KEM_768":  {"ciphertext_bytes": 1088, "public_key_bytes": 1184, "security_category": "NIST Level 3"},
    "ML_KEM_1024": {"ciphertext_bytes": 1568, "public_key_bytes": 1568, "security_category": "NIST Level 5"},

    # Classical Key Exchange
    "X25519":     {"public_key_bytes": 32, "shared_secret_bytes": 32, "security_category": "Classical (128-bit)"},
}

# 4-Tier X-Inference Default Durations (Years)
X_TIER_DEFAULT_YEARS = {
    "EPHEMERAL": 0.0,
    "SHORT_TERM": 1.5,
    "OPERATIONAL": 5.0,
    "ARCHIVAL": 10.0,
    "HUMAN_REVIEW": 5.0,  # Conservative default when ambiguous
}

# Deployment Exposure Interception Probabilities P_HNDL
EXPOSURE_PROFILE_P_HNDL = {
    "PUBLIC": 1.0,       # Ingress / LoadBalancer exposed to public Internet
    "INTERNAL": 0.05,    # Private VPC / ClusterIP / internal service mesh
    "AIRGAPPED": 0.0,    # Isolated environment without external network egress
}

# CAMS Agility Discounts (Reduction applied to migration urgency)
CAMS_AGILITY_DISCOUNTS = {
    0: 0.0,   # RIGID: Hardcoded algorithm literals (no discount)
    1: 0.30,  # CONFIGURABLE: Config-driven parameters (30% discount)
    2: 0.60,  # PROVIDER: Abstracted factory / provider architecture (60% discount)
    3: 0.85,  # RUNTIME_AGILE: Dynamic crypto-agile facade with KMS (85% discount)
}

# Functional Security Intent Risk Multipliers (DSIS Lattice)
INTENT_CLASS_WEIGHTS = {
    "OPERATIONAL_UTILITY": 0.0,           # ETags, cache dedup, in-memory hashes (0% quantum exposure)
    "INTEGRITY_CHECKSUM": 0.20,           # Short-lived builds, non-archival integrity checks
    "AUTHENTICATION_SIGNATURE": 0.90,     # Session authentication, JWTs, mTLS
    "CONFIDENTIALITY_ENVELOPE": 1.0,      # Data-at-rest & data-in-transit encryption
}

# Evidence State Descriptions
EVIDENCE_LEVEL_DESCRIPTIONS = {
    "E0_UNCONFIRMED": "Regex or keyword match without AST structure confirmation.",
    "E1_STATIC_ARTIFACT": "AST-confirmed cryptographic API invocation in source code.",
    "E2_REACHABLE_PATH": "Static data-flow trace confirms path from invocation to persistence sink.",
    "E3_CONFIG_CONFIRMED": "Active deployment configuration or physical certificate file on disk.",
    "E4_RUNTIME_OBSERVED": "Observed actively executing in live process memory/kernel.",
    "E5_CORRELATED_SIGNED": "Multi-modal correlation confirmed and cryptographically signed.",
    "DORMANT": "Static asset not observed executing during dynamic coverage window.",
}
