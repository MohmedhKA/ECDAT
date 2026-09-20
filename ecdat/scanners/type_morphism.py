"""
ECDAT Type-Morphic Parameter Arity Classifier:
Classifies uncataloged function calls, custom wrappers, and foreign bindings based on
mathematical parameter shapes and algebraic input/output arity.
"""

from typing import List, Dict, Optional, Any
from ecdat.models import PrimitiveType, IntentClass, EvidenceLevel

class TypeMorphismClassifier:
    """Classifies uncataloged function calls based on mathematical parameter signatures."""

    @staticmethod
    def classify_signature(func_name: str, param_names_or_args: List[str]) -> Optional[Dict[str, Any]]:
        """
        Evaluates parameter names or argument expressions to determine cryptographic primitive.
        """
        args_lower = [str(p).lower() for p in param_names_or_args]

        # 1. Check for Key Derivation Function (KDF) signature
        # Inputs: (password/secret, salt, iterations/cost/rounds, [key_len])
        has_secret = any(any(term in a for term in ("password", "passphrase", "secret", "pwd")) for a in args_lower)
        has_salt = any("salt" in a for a in args_lower)
        has_iterations = any(any(term in a for term in ("cost", "iter", "round", "rounds", "time_cost", "mem_cost")) for a in args_lower) or any(a.isdigit() and int(a) > 100 for a in args_lower if a.isdigit())

        if has_secret and has_salt and (has_iterations or len(param_names_or_args) >= 3):
            return {
                "primitive_type": PrimitiveType.KEY_EXCHANGE,
                "inferred_algorithm": "GENERIC-KDF",
                "functional_intent": IntentClass.AUTHENTICATION_SIGNATURE,
                "evidence_level": EvidenceLevel.E1_STATIC_ARTIFACT,
                "confidence": 0.85,
                "description": f"Algebraic KDF parameter arity detected in {func_name}(password, salt, iterations)"
            }

        # 2. Check for Symmetric Cipher / AEAD signature
        # Inputs: (key, iv/nonce, plaintext/data, [auth_data/aad])
        has_key = any("key" in a for a in args_lower)
        has_iv_nonce = any(any(term in a for term in ("iv", "nonce", "gcm_iv")) for a in args_lower)
        has_payload = any(any(term in a for term in ("plaintext", "data", "src", "payload", "cleartext")) for a in args_lower)

        if has_key and has_iv_nonce and has_payload:
            has_aad = any(any(term in a for term in ("aad", "auth_data", "associated_data", "tag")) for a in args_lower)
            alg_name = "GENERIC-AEAD-CIPHER" if has_aad else "GENERIC-BLOCK-CIPHER"
            return {
                "primitive_type": PrimitiveType.ENCRYPTION,
                "inferred_algorithm": alg_name,
                "functional_intent": IntentClass.CONFIDENTIALITY_ENVELOPE,
                "evidence_level": EvidenceLevel.E1_STATIC_ARTIFACT,
                "confidence": 0.85,
                "description": f"Algebraic symmetric cipher parameter arity detected in {func_name}(key, iv, data)"
            }

        # 3. Check for Asymmetric Digital Signature signature
        # Inputs: (private_key/priv, digest/message_hash)
        has_priv = any(any(term in a for term in ("private_key", "privkey", "priv", "sk")) for a in args_lower)
        has_digest = any(any(term in a for term in ("digest", "hash", "msg_hash")) for a in args_lower)

        if has_priv and has_digest:
            return {
                "primitive_type": PrimitiveType.SIGNATURE,
                "inferred_algorithm": "GENERIC-ASYMMETRIC-SIGNER",
                "functional_intent": IntentClass.AUTHENTICATION_SIGNATURE,
                "evidence_level": EvidenceLevel.E1_STATIC_ARTIFACT,
                "confidence": 0.80,
                "description": f"Algebraic asymmetric signature parameter arity detected in {func_name}(private_key, digest)"
            }

        return None
