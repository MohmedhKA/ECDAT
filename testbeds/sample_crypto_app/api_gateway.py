"""
API Gateway Microservice
Aggregates and routes requests across authentication and payment microservices.
"""
import auth_service
import payment_service

def route_request(endpoint, payload):
    if endpoint == "login":
        return auth_service.authenticate_user(payload)
    elif endpoint == "pay":
        return payment_service.process_transaction(payload)
    return None
