from fastapi import Request
from slowapi import Limiter
from app.config.config import get_settings

settings = get_settings()

def get_real_client_ip(request: Request) -> str:
    """
    Root Fix for Proxy Blindness: Extracts the true client IP from X-Forwarded-For.
    Falling back to request.client.host only if no proxy headers exist.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Use the first IP in the chain (the true originator)
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

# 🧱 Global Rate Limiter Instance
# This decoupling prevents circular imports in the 7-tier architecture.
limiter = Limiter(
    key_func=get_real_client_ip, 
    storage_uri=settings.redis_url,
    swallow_errors=True
)
