from slowapi import Limiter
from slowapi.util import get_remote_address
from app.config.config import get_settings

settings = get_settings()

# 🧱 Global Rate Limiter Instance
# This decoupling prevents circular imports in the 7-tier architecture.
limiter = Limiter(
    key_func=get_remote_address, 
    storage_uri=settings.redis_url,
    swallow_errors=True
)
