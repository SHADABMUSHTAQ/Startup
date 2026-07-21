import ipaddress

from fastapi import Request
from slowapi import Limiter
from app.config.config import get_settings

settings = get_settings()

def get_real_client_ip(request: Request) -> str:
    """
    Return the address observed by the immediate trusted reverse proxy.

    Production Nginx overwrites X-Forwarded-For with ``$remote_addr``. Reading
    the final valid address also remains safe if an upstream proxy appends to
    an existing chain. Never trust the first value because a client can supply
    it directly and bypass per-IP authentication limits.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
        for candidate in reversed(candidates):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return request.client.host if request.client else "127.0.0.1"

# Global rate limiter instance.
limiter = Limiter(
    key_func=get_real_client_ip,
    storage_uri=settings.redis_url,
    # Authentication throttling is a security boundary. If its Redis backend
    # is unavailable, fail the limited request instead of silently disabling it.
    swallow_errors=False,
)
