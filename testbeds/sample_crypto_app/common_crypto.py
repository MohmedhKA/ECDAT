"""
Shared Cryptographic Utility Library
Provides foundational cryptographic primitives across the microservice mesh.
"""

def crypto_envelope_encrypt(data_payload):
    """Core cryptographic envelope encryption using legacy RSA/AES"""
    session_key = cipher.encrypt(data_payload)
    return session_key

def crypto_sign_jwt(claims):
    """Core digital signature token generation"""
    token_sig = cipher.sign(claims)
    return token_sig
