"""
Authentication Microservice
Depends on common_crypto for issuing signed auth tokens.
"""
import common_crypto

def authenticate_user(user_creds):
    token = common_crypto.crypto_sign_jwt(user_creds)
    return token
