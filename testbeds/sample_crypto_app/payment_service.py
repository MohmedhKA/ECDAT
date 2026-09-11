"""
Payment Gateway Microservice
Depends on common_crypto for securing payment envelopes.
"""
import common_crypto

def process_transaction(card_data):
    encrypted_envelope = common_crypto.crypto_envelope_encrypt(card_data)
    return encrypted_envelope
