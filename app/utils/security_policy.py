import os
from typing import Annotated, Any

from pydantic import AfterValidator, Field


ABSOLUTE_MAX_TENANT_AGENTS = 50


def _configured_agent_ceiling() -> int:
    try:
        configured = int(os.getenv("MAX_TENANT_AGENTS", str(ABSOLUTE_MAX_TENANT_AGENTS)))
    except ValueError:
        configured = ABSOLUTE_MAX_TENANT_AGENTS
    return max(1, min(ABSOLUTE_MAX_TENANT_AGENTS, configured))


PLATFORM_MAX_AGENTS = _configured_agent_ceiling()
PASSWORD_MIN_LENGTH = max(16, int(os.getenv("PASSWORD_MIN_LENGTH", "16")))
PASSWORD_MAX_BYTES = 72


def effective_agent_limit(value: Any, default: int = 10) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(PLATFORM_MAX_AGENTS, parsed))


def validate_strong_password(value: str) -> str:
    password = str(value or "")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must contain at least {PASSWORD_MIN_LENGTH} characters")
    if len(password.encode("utf-8")) > PASSWORD_MAX_BYTES:
        raise ValueError(f"Password must not exceed {PASSWORD_MAX_BYTES} UTF-8 bytes")
    if not any(character.islower() for character in password):
        raise ValueError("Password must contain a lowercase letter")
    if not any(character.isupper() for character in password):
        raise ValueError("Password must contain an uppercase letter")
    if not any(character.isdigit() for character in password):
        raise ValueError("Password must contain a number")
    if not any(not character.isalnum() and not character.isspace() for character in password):
        raise ValueError("Password must contain a symbol")
    return password


StrongPassword = Annotated[
    str,
    Field(min_length=PASSWORD_MIN_LENGTH),
    AfterValidator(validate_strong_password),
]
