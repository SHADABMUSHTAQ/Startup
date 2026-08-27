import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _artifacts():
    policy = json.loads((ROOT / "docs" / "WARSOC_AUTHORIZATION_POLICY.json").read_text())
    inventory = json.loads(
        (ROOT / "docs" / "generated" / "WARSOC_API_SECURITY_INVENTORY.json").read_text()
    )
    routes = {f"{row['method']} {row['route']}": row for row in inventory["routes"]}
    return policy, inventory, routes


def test_implementation_inventory_matches_independent_authorization_policy():
    policy, inventory, routes = _artifacts()
    assert inventory["summary"]["manual_review_required"] == 0
    public = {key for key, row in routes.items() if row["auth_type"] == "PUBLIC_BOUNDED"}
    assert public == set(policy["public_routes"])

    platform_admin = {
        key for key, row in routes.items() if row["auth_type"] == "PLATFORM_ADMIN_KEY"
    }
    assert platform_admin == set(policy["platform_admin_routes"])

    for auth_type, expected in policy["service_identity_routes"].items():
        observed = {key for key, row in routes.items() if row["auth_type"] == auth_type}
        assert observed == set(expected), auth_type

    for key, expected_roles in policy["sensitive_role_requirements"].items():
        assert key in routes, key
        assert routes[key]["allowed_roles"] == sorted(expected_roles), key

    for prefix, expected_gate in policy["feature_gate_requirements"].items():
        matched = [row for row in routes.values() if row["route"].startswith(prefix)]
        assert matched, prefix
        assert all(row["feature_condition"] == expected_gate for row in matched), prefix

    tenant_auth_types = set(policy["tenant_scoped_auth_types"])
    for row in routes.values():
        if row["auth_type"] in tenant_auth_types:
            assert row["tenant_scope"] in {
                "AUTHENTICATED_TENANT_CONTEXT",
                "AUTHENTICATED_TENANT",
            }
        assert row["auth_type"] != "REVIEW_REQUIRED"
        assert row["tenant_scope"] != "REVIEW_REQUIRED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/admin/tenants",
        "/api/v1/archive-retrievals",
        "/api/v1/compliance/cases",
        "/api/v1/compliance/evidence",
        "/api/v1/compliance/holds",
        "/api/v1/compliance/retention/status",
        "/api/v1/logs",
        "/metrics",
    ],
)
async def test_sensitive_read_boundaries_deny_unauthenticated_requests(
    async_client,
    path,
    monkeypatch,
):
    async_client.cookies.clear()
    if path == "/metrics":
        from app.routes import metrics as metrics_module

        monkeypatch.setattr(metrics_module.settings, "metrics_allowlist_ips", "")
        monkeypatch.setattr(metrics_module.settings, "metrics_bearer_token", "metrics-required")
    response = await async_client.get(path)
    assert response.status_code in {401, 403}, (path, response.status_code, response.text)
