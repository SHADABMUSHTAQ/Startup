from __future__ import annotations


INACTIVE_AGENT_STATES = frozenset({"inactive", "revoked"})
LEGACY_CONNECTIVITY_STATES = frozenset({"online", "offline"})


def normalize_agent_lifecycle_status(value: object) -> str:
    status = str(value or "active").strip().lower()
    return status or "active"


def agent_lifecycle_is_active(value: object) -> bool:
    return normalize_agent_lifecycle_status(value) not in INACTIVE_AGENT_STATES


def agent_status_needs_lifecycle_migration(value: object) -> bool:
    return normalize_agent_lifecycle_status(value) in LEGACY_CONNECTIVITY_STATES
