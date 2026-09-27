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
    "TRANSIENT": 0.0,
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
    3: 0.85,  # RUNTIME_AGILE: Dynamic protocol negotiation / TLS handshake (85% discount)
    4: 0.90,  # ORCHESTRATED: Policy-driven orchestration / Tink / KMS (90% discount)
    5: 0.95,  # QUANTUM_AGILE: Autonomous quantum-safe algorithms (95% discount)
}

# Functional Security Intent Risk Multipliers (DSIS Lattice)
INTENT_CLASS_WEIGHTS = {
    "OPERATIONAL_UTILITY": 0.0,           # ETags, cache dedup, in-memory hashes (0% quantum exposure)
    "INTEGRITY_CHECKSUM": 0.20,           # Short-lived builds, non-archival integrity checks
    "AUTHENTICATION_SIGNATURE": 0.90,     # Session authentication, JWTs, mTLS
    "AUTHENTICATION_HANDSHAKE": 0.90,     # TLS certificate authentication
    "CONFIDENTIALITY_ENVELOPE": 1.0,      # Data-at-rest & data-in-transit encryption
    "CONFIDENTIALITY_IN_TRANSIT": 1.0,    # In-transit TLS payload confidentiality
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

# MITRE Common Weakness Enumeration (CWE) Formal Cryptographic Taxonomy
CWE_TAXONOMY = {
    # Cryptographic Weakness Findings
    "UNTRUSTED-PRNG": {
        "cwe_id": "CWE-338",
        "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/338.html",
        "description": "The product uses a weak PRNG (e.g. java.util.Random, math/rand) in a security or cryptographic context where predictability creates vulnerability.",
    },
    "PREDICTABLE-SEED": {
        "cwe_id": "CWE-335",
        "name": "Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/335.html",
        "description": "The pseudo-random number generator is seeded with a constant, timestamp, or predictable input value.",
    },
    "PREDICTABLE-KEYSTORE-PASSWORD": {
        "cwe_id": "CWE-259",
        "name": "Use of Hard-coded Password",
        "mitre_url": "https://cwe.mitre.org/data/definitions/259.html",
        "description": "A hard-coded password or keystore passphrase is used in source code.",
    },
    "HARDCODED-PASSWORD": {
        "cwe_id": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "mitre_url": "https://cwe.mitre.org/data/definitions/798.html",
        "description": "Authentication secrets or cryptographic credentials are embedded directly in source code.",
    },
    "PREDICTABLE-KEY": {
        "cwe_id": "CWE-321",
        "name": "Use of Hard-coded Cryptographic Key",
        "mitre_url": "https://cwe.mitre.org/data/definitions/321.html",
        "description": "The use of a hard-coded cryptographic key significantly increases the possibility that keys will become compromised.",
    },
    "STATIC-IV": {
        "cwe_id": "CWE-329",
        "name": "Generation of Predictable IV with CBC Mode",
        "mitre_url": "https://cwe.mitre.org/data/definitions/329.html",
        "description": "The software generates a predictable or static initialization vector (IV) for encryption.",
    },
    "PBE-WEAK-ITERATION": {
        "cwe_id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "mitre_url": "https://cwe.mitre.org/data/definitions/326.html",
        "description": "Password-based encryption parameters use an insufficient iteration count.",
    },
    "STATIC-SALT": {
        "cwe_id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "mitre_url": "https://cwe.mitre.org/data/definitions/326.html",
        "description": "A fixed or static salt is used in cryptographic key derivation.",
    },
    "CLEARTEXT-HTTP": {
        "cwe_id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "mitre_url": "https://cwe.mitre.org/data/definitions/319.html",
        "description": "The software transmits sensitive data over an unencrypted network protocol (HTTP/ws).",
    },
    "UNENCRYPTED-SOCKET": {
        "cwe_id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "mitre_url": "https://cwe.mitre.org/data/definitions/319.html",
        "description": "Network sockets communicate without transport layer encryption (TLS).",
    },
    "IMPROPER-SSL-SOCKET-FACTORY": {
        "cwe_id": "CWE-295",
        "name": "Improper Certificate Validation",
        "mitre_url": "https://cwe.mitre.org/data/definitions/295.html",
        "description": "Custom SSL socket factory bypasses trust manager or certificate chain validation.",
    },
    "DUMMY-CERT-VALIDATION": {
        "cwe_id": "CWE-295",
        "name": "Improper Certificate Validation",
        "mitre_url": "https://cwe.mitre.org/data/definitions/295.html",
        "description": "TrustManager implementation blindly accepts all X.509 server certificates.",
    },
    "DUMMY-HOSTNAME-VERIFIER": {
        "cwe_id": "CWE-295",
        "name": "Improper Certificate Validation",
        "mitre_url": "https://cwe.mitre.org/data/definitions/295.html",
        "description": "HostnameVerifier implementation returns true unconditionally, allowing MITM attacks.",
    },
    # Algorithm Classifications
    "MD5": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "MD5 suffers from practical collision attacks and is disallowed by NIST for cryptographic use.",
    },
    "HMAC-MD5": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "HMAC constructed over MD5 should be migrated to HMAC-SHA-256 or KMAC per NIST SP 800-131A.",
    },
    "SHA-1": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "SHA-1 collision resistance is broken; disallowed by NIST SP 800-131A Rev 2.",
    },
    "DES": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "DES 56-bit key size is vulnerable to practical brute-force attacks.",
    },
    "3DES": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Triple-DES 64-bit block size is vulnerable to Sweet32 collision attacks; disallowed by NIST.",
    },
    "RC4": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "RC4 stream cipher keystream biases allow plaintext recovery; prohibited in TLS (RFC 7465).",
    },
    "BLOWFISH": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Blowfish 64-bit block cipher is vulnerable to Sweet32 birthday attacks on large data streams.",
    },
    "RSA": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm (Quantum Vulnerable)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Classical RSA integer factorization is completely broken in polynomial time by Shor's algorithm on a CRQC.",
    },
    "DSA": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm (Quantum Vulnerable)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Classical DSA discrete logarithm is completely broken by Shor's algorithm on a CRQC.",
    },
    "ECDSA": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm (Quantum Vulnerable)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Classical Elliptic Curve DSA is completely broken by Shor's algorithm on a CRQC.",
    },
    "ECDH": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm (Quantum Vulnerable)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Classical ECDH key exchange is susceptible to Shor's algorithm and retroactive HNDL attacks.",
    },
    "TLS": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm (Classical Handshake)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "Standard TLS configuration without hybrid post-quantum key exchange is vulnerable to HNDL interception.",
    },
    "TLSv1.2": {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm (Classical Handshake)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/327.html",
        "description": "TLS 1.2 lacks native post-quantum key encapsulation support and uses legacy handshake negotiation.",
    },
    # Additional Top 100 Cryptographic Vulnerabilities
    "ECB": {
        "cwe_id": "CWE-1240",
        "name": "Use of a Cryptographic Primitive with a Risky Implementation (ECB Mode)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/1240.html",
        "description": "Encryption in ECB mode leaks structural patterns because identical plaintext blocks produce identical ciphertext blocks.",
    },
    "RSA-NO-OAEP": {
        "cwe_id": "CWE-780",
        "name": "Use of RSA Algorithm without OAEP",
        "mitre_url": "https://cwe.mitre.org/data/definitions/780.html",
        "description": "RSA encryption without Optimal Asymmetric Encryption Padding (OAEP) is vulnerable to chosen-ciphertext and Bleichenbacher padding attacks.",
    },
    "MD4": {
        "cwe_id": "CWE-328",
        "name": "Use of Weak Hash (MD4)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/328.html",
        "description": "MD4 is cryptographically broken and collision-vulnerable; hand calculation level effort can find collisions.",
    },
    "WEAK-KEY-LENGTH": {
        "cwe_id": "CWE-326",
        "name": "Inadequate Encryption Strength (<2048 bits)",
        "mitre_url": "https://cwe.mitre.org/data/definitions/326.html",
        "description": "Asymmetric key lengths below 2048 bits or symmetric keys below 128 bits are vulnerable to brute-force factorization.",
    },
    "TIMING-SIDE-CHANNEL": {
        "cwe_id": "CWE-208",
        "name": "Observable Timing Discrepancy",
        "mitre_url": "https://cwe.mitre.org/data/definitions/208.html",
        "description": "Non-constant-time comparison of MAC, signature, or secret values creates an exploitable timing oracle.",
    },
    "WEAK-KDF": {
        "cwe_id": "CWE-916",
        "name": "Use of Password Hash With Insufficient Computational Effort",
        "mitre_url": "https://cwe.mitre.org/data/definitions/916.html",
        "description": "Single-iteration or unsalted hashing used for password storage or key derivation allows rapid GPU/ASIC rainbow table cracking.",
    },
}

