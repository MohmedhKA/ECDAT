"""
ECDAT Cryptographic Agility Maturity Score (CAMS) Detector:
Evaluates code patterns at cryptographic call sites to classify agility level (0 to 3):
- Level 0 (RIGID): Hardcoded algorithm string literals (e.g., "AES/CBC/PKCS5Padding").
- Level 1 (CONFIGURABLE): Loaded from environment variable, config file, or settings.
- Level 2 (PROVIDER): Abstracted behind factory class, provider interface, or dependency injection.
- Level 3 (RUNTIME_AGILE): Policy-driven crypto-agile facade (e.g., Google Tink KeysetHandle, hybrid policy engine).
"""

import re
import ast
from typing import Optional, Tuple, Any
from ecdat.models import AgilityLevel
from ecdat.constants import CAMS_AGILITY_DISCOUNTS

# Effort multipliers for code migration timeline Y_code based on CAMS level
CAMS_Y_MULTIPLIERS = {
    AgilityLevel.RIGID: 1.0,          # Baseline effort
    AgilityLevel.CONFIGURABLE: 0.70,  # 30% reduction (just update config)
    AgilityLevel.PROVIDER: 0.40,      # 60% reduction (implement new provider)
    AgilityLevel.RUNTIME_AGILE: 0.15, # 85% reduction (policy update only)
}

CAMS_DESCRIPTIONS = {
    AgilityLevel.RIGID: "Hardcoded string literals, inflexible primitives",
    AgilityLevel.CONFIGURABLE: "Parameterized configs/env vars, no code edits",
    AgilityLevel.PROVIDER: "Pluggable crypto provider abstraction",
    AgilityLevel.RUNTIME_AGILE: "Dynamic runtime negotiation / agile wrapper",
}

# Regex patterns for detecting CAMS patterns across languages (Python, Java, JS/TS, Go, Rust)
RUNTIME_AGILE_PATTERNS = [
    re.compile(r"KeysetHandle", re.IGNORECASE),
    re.compile(r"TinkConfig", re.IGNORECASE),
    re.compile(r"HybridDecrypt|HybridEncrypt", re.IGNORECASE),
    re.compile(r"AeadConfig", re.IGNORECASE),
    re.compile(r"CryptoPolicy|CipherSuitePolicy|AlgorithmPolicy", re.IGNORECASE),
    re.compile(r"@crypto_agile|CryptoAgileWrapper", re.IGNORECASE),
    re.compile(r"dynamic_cipher|policy_selector", re.IGNORECASE),
]

PROVIDER_PATTERNS = [
    re.compile(r"(?:Crypto|Cipher|Key|SecretKey|Signature|Digest)Factory\.", re.IGNORECASE),
    re.compile(r"(?:Security|Cipher)Provider\.", re.IGNORECASE),
    re.compile(r"Security\.getProvider", re.IGNORECASE),
    re.compile(r"provider\.get(?:Cipher|Key|Signer|Digest)", re.IGNORECASE),
    re.compile(r"crypto_provider|cipher_provider", re.IGNORECASE),
    re.compile(r"inject\(|@Inject|DependencyInjection", re.IGNORECASE),
    re.compile(r"get_crypto_service|cryptoServiceFactory", re.IGNORECASE),
]

CONFIGURABLE_PATTERNS = [
    re.compile(r"os\.getenv\s*\(", re.IGNORECASE),
    re.compile(r"os\.environ(?:\[|\.get)", re.IGNORECASE),
    re.compile(r"process\.env(?:\.|\[)", re.IGNORECASE),
    re.compile(r"System\.getenv\s*\(", re.IGNORECASE),
    re.compile(r"System\.getProperty\s*\(", re.IGNORECASE),
    re.compile(r"env::var\s*\(", re.IGNORECASE),
    re.compile(r"config(?:\.get|\[|->get)", re.IGNORECASE),
    re.compile(r"app\.config(?:\.get|\[)", re.IGNORECASE),
    re.compile(r"cfg(?:\.get|\.|\b)", re.IGNORECASE),
    re.compile(r"properties\.getProperty", re.IGNORECASE),
    re.compile(r"viper\.GetString", re.IGNORECASE),
    re.compile(r"settings\.(?:CRYPTO|CIPHER|ALGORITHM|HASH)", re.IGNORECASE),
]

def detect_cams_agility(
    source_line: str,
    surrounding_code: Optional[str] = None,
    ast_node: Optional[Any] = None,
) -> Tuple[AgilityLevel, str]:
    """
    Evaluates cryptographic invocation context and returns (AgilityLevel, reasoning_str).
    Checks runtime agile facades -> provider/factory -> configurable -> rigid literal.
    """
    combined_text = f"{source_line}\n{surrounding_code or ''}"

    # 1. Level 3 Check: Runtime Agile Facades
    for pat in RUNTIME_AGILE_PATTERNS:
        if pat.search(combined_text):
            return AgilityLevel.RUNTIME_AGILE, f"Runtime crypto-agile facade matched: {pat.pattern}"

    # 2. Level 2 Check: Provider / Factory Abstraction
    for pat in PROVIDER_PATTERNS:
        if pat.search(combined_text):
            return AgilityLevel.PROVIDER, f"Provider/Factory abstraction matched: {pat.pattern}"

    # 3. Level 1 Check: Configurable / Environment / Settings
    for pat in CONFIGURABLE_PATTERNS:
        if pat.search(combined_text):
            return AgilityLevel.CONFIGURABLE, f"Configurable/environment-driven pattern matched: {pat.pattern}"

    # 4. AST node parameter check (if available for Python)
    if ast_node is not None:
        if isinstance(ast_node, ast.Call):
            if ast_node.args:
                first_arg = ast_node.args[0]
                if isinstance(first_arg, (ast.Name, ast.Attribute)):
                    # Passed as a variable name or attribute, not a hardcoded string literal
                    return AgilityLevel.CONFIGURABLE, f"Algorithm passed as variable/attribute '{ast.unparse(first_arg)}'"

    # 5. Default: Level 0 (Rigid / Hardcoded Literal)
    return AgilityLevel.RIGID, "Hardcoded cryptographic algorithm literal (no agility abstraction)"

def get_cams_discount(level: AgilityLevel) -> float:
    """Returns the regulatory urgency discount [0.0 - 0.85] for the given CAMS level."""
    return CAMS_AGILITY_DISCOUNTS.get(int(level), 0.0)

def get_cams_y_multiplier(level: AgilityLevel) -> float:
    """Returns the migration effort multiplier [0.15 - 1.0] for the given CAMS level."""
    return CAMS_Y_MULTIPLIERS.get(level, 1.0)

get_cams_effort_multiplier = get_cams_y_multiplier

