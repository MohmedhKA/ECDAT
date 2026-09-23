"""
ECDAT Cryptographic Agility Maturity Score (CAMS) Detector:
Evaluates code patterns at cryptographic call sites to classify agility level (0 to 3):
- Level 0 (RIGID): Hardcoded algorithm string literals (e.g., "AES/CBC/PKCS5Padding").
- Level 1 (CONFIGURABLE): Loaded from environment variable, config file, or settings.
- Level 2 (PROVIDER): Abstracted behind factory class, provider interface, or dependency injection.
- Level 3 (RUNTIME_AGILE): Policy-driven crypto-agile facade (e.g., Google Tink KeysetHandle, hybrid policy engine).
"""

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

# Substring tokens for detecting CAMS patterns across polyglot ecosystems (ZERO REGEX)
RUNTIME_AGILE_TOKENS = (
    "keysethandle",
    "tinkconfig",
    "hybriddecrypt",
    "hybridencrypt",
    "aeadconfig",
    "cryptopolicy",
    "ciphersuitepolicy",
    "algorithmpolicy",
    "@crypto_agile",
    "cryptoagilewrapper",
    "dynamic_cipher",
    "policy_selector",
)

PROVIDER_TOKENS = (
    "cryptofactory.",
    "cipherfactory.",
    "keyfactory.",
    "secretkeyfactory.",
    "signaturefactory.",
    "digestfactory.",
    "securityprovider.",
    "cipherprovider.",
    "security.getprovider",
    "provider.getcipher",
    "provider.getkey",
    "provider.getsigner",
    "provider.getdigest",
    "crypto_provider",
    "cipher_provider",
    "inject(",
    "@inject",
    "dependencyinjection",
    "get_crypto_service",
    "cryptoservicefactory",
)

CONFIGURABLE_TOKENS = (
    "os.getenv(",
    "os.getenv (",
    "os.environ[",
    "os.environ.get",
    "process.env.",
    "process.env[",
    "system.getenv(",
    "system.getenv (",
    "system.getproperty(",
    "system.getproperty (",
    "env::var(",
    "env::var (",
    "config.get",
    "config[",
    "config->get",
    "app.config.get",
    "app.config[",
    "cfg.get",
    "cfg[",
    "cfg.",
    "properties.getproperty",
    "viper.getstring",
    "settings.crypto",
    "settings.cipher",
    "settings.algorithm",
    "settings.hash",
)

def detect_cams_agility(
    source_line: str,
    surrounding_code: Optional[str] = None,
    ast_node: Optional[Any] = None,
) -> Tuple[AgilityLevel, str]:
    """
    Evaluates cryptographic invocation context and returns (AgilityLevel, reasoning_str).
    Checks runtime agile facades -> provider/factory -> configurable -> rigid literal.
    """
    combined_lower = f"{source_line}\n{surrounding_code or ''}".lower()

    # 1. Level 3 Check: Runtime Agile Facades
    for token in RUNTIME_AGILE_TOKENS:
        if token in combined_lower:
            return AgilityLevel.RUNTIME_AGILE, f"Runtime crypto-agile facade matched: '{token}'"

    # 2. Level 2 Check: Provider / Factory Abstraction
    for token in PROVIDER_TOKENS:
        if token in combined_lower:
            return AgilityLevel.PROVIDER, f"Provider/Factory abstraction matched: '{token}'"

    # 3. Level 1 Check: Configurable / Environment / Settings
    for token in CONFIGURABLE_TOKENS:
        if token in combined_lower:
            return AgilityLevel.CONFIGURABLE, f"Configurable/environment-driven pattern matched: '{token}'"

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

