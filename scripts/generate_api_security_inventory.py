"""Generate a static WarSOC API security inventory without exposing Swagger.

The generator intentionally reports REVIEW_REQUIRED when source inspection cannot
prove an authentication or tenant boundary. It never upgrades an unknown route
to a secure classification by assumption.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any


INVENTORY_VERSION = "2026-08-20.phase0"
HTTP_DECORATORS = {"get", "post", "put", "patch", "delete", "options", "head"}
SIMPLE_TYPES = {
    "str",
    "int",
    "float",
    "bool",
    "bytes",
    "dict",
    "list",
    "Any",
    "Request",
    "Response",
    "WebSocket",
    "UploadFile",
}


def _unparse(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    return ast.unparse(node)


def _constant_string(node: ast.AST | None, default: str = "") -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return default


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _join_path(prefix: str, path: str) -> str:
    joined = f"/{prefix.strip('/')}/{path.strip('/')}".replace("//", "/")
    return joined if joined != "" else "/"


class IncludeRouterVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.guards: list[str] = []
        self.includes: list[dict[str, str | None]] = []

    def visit_If(self, node: ast.If) -> Any:
        self.guards.append(ast.unparse(node.test))
        for child in node.body:
            self.visit(child)
        self.guards.pop()
        for child in node.orelse:
            self.visit(child)

    def visit_Call(self, node: ast.Call) -> Any:
        if _call_name(node.func) == "app.include_router" and node.args:
            router_name = _call_name(node.args[0])
            module_name = router_name.removesuffix(".router")
            prefix = ""
            for keyword in node.keywords:
                if keyword.arg == "prefix":
                    prefix = _constant_string(keyword.value)
            self.includes.append(
                {
                    "module": module_name,
                    "prefix": prefix,
                    "feature_condition": " and ".join(self.guards) or None,
                }
            )
        self.generic_visit(node)


def _role_values(node: ast.AST) -> list[str]:
    roles = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if _call_name(child.func).split(".")[-1] not in {"RoleChecker", "RequireRole"}:
            continue
        if not child.args or not isinstance(child.args[0], (ast.List, ast.Tuple, ast.Set)):
            continue
        for item in child.args[0].elts:
            value = _constant_string(item).strip().lower()
            if value:
                roles.add(value)
    return sorted(roles)


def _dependency_names(node: ast.AST) -> list[str]:
    dependencies = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or _call_name(child.func) != "Depends":
            continue
        if child.args:
            dependencies.add(_call_name(child.args[0]))
    return sorted(value for value in dependencies if value)


def _request_schemas(function: ast.AsyncFunctionDef | ast.FunctionDef) -> list[str]:
    schemas = set()
    positional = [*function.args.posonlyargs, *function.args.args]
    defaults = [None] * (len(positional) - len(function.args.defaults)) + list(
        function.args.defaults
    )
    for argument, default in zip(positional, defaults):
        annotation = _unparse(argument.annotation)
        if not annotation:
            continue
        base = annotation.replace("Optional[", "").replace("]", "").split("[")[0]
        default_call = _call_name(default.func) if isinstance(default, ast.Call) else ""
        if base in SIMPLE_TYPES or default_call in {
            "Depends",
            "Query",
            "Header",
            "Cookie",
            "Path",
            "File",
            "Form",
        }:
            continue
        schemas.add(annotation)
    return sorted(schemas)


def _boundary_evidence(node: ast.AST) -> list[str]:
    evidence = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        qualified_call = _call_name(child.func)
        if qualified_call.endswith("limiter.limit"):
            value = _constant_string(child.args[0] if child.args else None)
            evidence.add(f"rate_limit:{value or 'dynamic'}")
        call = _call_name(child.func).split(".")[-1]
        if call in {"Query", "Path", "Header", "File", "Form"}:
            constraints = []
            for keyword in child.keywords:
                if keyword.arg in {"ge", "gt", "le", "lt", "min_length", "max_length"}:
                    constraints.append(f"{keyword.arg}={_unparse(keyword.value)}")
            if constraints:
                evidence.add(f"{call}({', '.join(constraints)})")
    source = ast.unparse(node).lower()
    for marker in (
        "rate_limit",
        "max_body",
        "max_batch",
        "content-length",
        "quota",
        "replay",
    ):
        if marker in source:
            evidence.add(f"source_marker:{marker}")
    return sorted(evidence)


def _classify_security(
    path: str,
    handler: str,
    dependencies: list[str],
    roles: list[str],
    source: str,
) -> tuple[str, str, str]:
    lowered_dependencies = {value.lower() for value in dependencies}
    lowered_source = source.lower()

    if any("verify_admin" in value for value in lowered_dependencies) and roles:
        auth_type = "USER_JWT_RBAC_AND_PLATFORM_ADMIN_KEY"
    elif any("verify_admin" in value for value in lowered_dependencies):
        auth_type = "PLATFORM_ADMIN_KEY"
    elif roles:
        auth_type = "USER_JWT_RBAC"
    elif any("require_premium_plan" in value for value in lowered_dependencies):
        auth_type = "USER_JWT_ENTITLEMENT"
    elif any("get_current_user" in value for value in lowered_dependencies):
        auth_type = "USER_JWT"
    elif "x-admin-key" in lowered_source or "super_admin_api_key" in lowered_source:
        auth_type = "PLATFORM_ADMIN_KEY"
    elif handler == "register_relay":
        auth_type = "RELAY_ONE_TIME_ACTIVATION"
    elif handler == "recover_relay_key":
        auth_type = "RELAY_KEY_RECOVERY_AUTHORIZATION"
    elif handler == "relay_contract":
        # Public, feature-gated compatibility contract: exposes version
        # constants only (no tenant data) so installers can compare versions
        # before registration — same exposure class as /health.
        auth_type = "PUBLIC_BOUNDED"
    elif "relay" in path and any(
        marker in lowered_source
        for marker in ("relay authentication", "relay token", "relay signature")
    ):
        auth_type = "RELAY_IDENTITY"
    elif any("verify_agent_token" in value for value in lowered_dependencies):
        auth_type = "AGENT_IDENTITY"
    elif path.startswith("/api/v1/agent/") and handler in {
        "register_agent",
        "validate_activation",
    }:
        auth_type = "AGENT_ONE_TIME_ACTIVATION"
    elif path.startswith("/api/v1/agent/") and any(
        marker in lowered_source
        for marker in (
            "agent_token",
            "activation_code",
            "verify_agent",
            "x-agent",
            "x_warsoc_signature",
            "ed25519",
        )
    ):
        auth_type = "AGENT_IDENTITY"
    elif handler == "metrics" and "bearer" in lowered_source and "allowlist" in lowered_source:
        auth_type = "METRICS_BEARER_OR_IP_ALLOWLIST"
    elif handler == "websocket_endpoint" and "ticket" in lowered_source:
        auth_type = "WEBSOCKET_ONE_TIME_TICKET"
    elif handler in {"login", "signup", "activate_invite"}:
        auth_type = "PUBLIC_BOUNDED"
    elif path in {"/health", "/api/v1/auth/login"} or path.startswith("/api/v1/sales"):
        auth_type = "PUBLIC_BOUNDED"
    else:
        auth_type = "REVIEW_REQUIRED"

    if auth_type.startswith("USER_JWT"):
        tenant_scope = "AUTHENTICATED_TENANT_CONTEXT"
    elif "current_user" in lowered_source and "tenant_id" in lowered_source:
        tenant_scope = "AUTHENTICATED_TENANT"
    elif auth_type in {
        "AGENT_IDENTITY",
        "AGENT_ONE_TIME_ACTIVATION",
        "RELAY_IDENTITY",
        "RELAY_ONE_TIME_ACTIVATION",
        "RELAY_KEY_RECOVERY_AUTHORIZATION",
    }:
        tenant_scope = "SERVICE_IDENTITY_TENANT"
    elif auth_type == "PLATFORM_ADMIN_KEY":
        tenant_scope = "PLATFORM_ADMIN_OPERATION"
    elif auth_type in {
        "PUBLIC_BOUNDED",
        "METRICS_BEARER_TOKEN",
        "METRICS_BEARER_OR_IP_ALLOWLIST",
    }:
        tenant_scope = "NOT_APPLICABLE"
    elif auth_type == "WEBSOCKET_ONE_TIME_TICKET":
        tenant_scope = "TICKET_BOUND_TENANT"
    else:
        tenant_scope = "REVIEW_REQUIRED"

    review_state = (
        "STATICALLY_CLASSIFIED"
        if auth_type != "REVIEW_REQUIRED" and tenant_scope != "REVIEW_REQUIRED"
        else "MANUAL_REVIEW_REQUIRED"
    )
    return auth_type, tenant_scope, review_state


def _route_records(
    repo_root: Path,
    source_path: Path,
    module_name: str,
    prefix: str,
    feature_condition: str | None,
) -> list[dict[str, Any]]:
    source_text = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source_text, filename=str(source_path))
    records = []
    for node in tree.body:
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in HTTP_DECORATORS | {"websocket"}:
                continue
            owner = _call_name(decorator.func.value)
            if owner not in {"router", "app"}:
                continue
            route_path = _constant_string(decorator.args[0] if decorator.args else None, "/")
            full_path = _join_path(prefix, route_path)
            dependencies = _dependency_names(node)
            roles = _role_values(node)
            endpoint_source = ast.get_source_segment(source_text, node) or ast.unparse(node)
            auth_type, tenant_scope, review_state = _classify_security(
                full_path, node.name, dependencies, roles, endpoint_source
            )
            response_schema = _unparse(node.returns)
            for keyword in decorator.keywords:
                if keyword.arg == "response_model":
                    response_schema = _unparse(keyword.value)
            records.append(
                {
                    "method": "WEBSOCKET" if method == "websocket" else method.upper(),
                    "route": full_path,
                    "source_file": source_path.relative_to(repo_root).as_posix(),
                    "source_line": node.lineno,
                    "handler": node.name,
                    "router_module": module_name,
                    "feature_condition": feature_condition,
                    "auth_type": auth_type,
                    "auth_evidence": dependencies,
                    "allowed_roles": roles,
                    "tenant_scope": tenant_scope,
                    "request_schemas": _request_schemas(node),
                    "response_schema": response_schema,
                    "rate_size_boundary_evidence": _boundary_evidence(node),
                    "review_state": review_state,
                }
            )
    return records


def build_inventory(repo_root: Path) -> dict[str, Any]:
    main_path = repo_root / "app" / "main.py"
    main_tree = ast.parse(main_path.read_text(encoding="utf-8"), filename=str(main_path))
    visitor = IncludeRouterVisitor()
    visitor.visit(main_tree)

    routes = _route_records(repo_root, main_path, "main", "", None)
    for include in visitor.includes:
        module_name = str(include["module"])
        route_path = repo_root / "app" / "routes" / f"{module_name}.py"
        if not route_path.exists():
            continue
        routes.extend(
            _route_records(
                repo_root,
                route_path,
                module_name,
                str(include["prefix"] or ""),
                include["feature_condition"],
            )
        )

    unique = {}
    for route in routes:
        key = (route["method"], route["route"], route["source_file"], route["source_line"])
        unique[key] = route
    ordered = sorted(
        unique.values(), key=lambda item: (item["route"], item["method"], item["source_file"])
    )
    review_required = sum(
        1 for route in ordered if route["review_state"] == "MANUAL_REVIEW_REQUIRED"
    )
    return {
        "inventory_version": INVENTORY_VERSION,
        "source": "Static AST analysis of app/main.py and included app/routes modules",
        "limitations": [
            "This inventory does not replace negative authorization tests.",
            "MANUAL_REVIEW_REQUIRED is fail-closed and must not be interpreted as public access.",
            "Runtime middleware and nested dependency behavior require test evidence in addition to this artifact.",
        ],
        "summary": {
            "route_count": len(ordered),
            "manual_review_required": review_required,
            "feature_gated_routes": sum(
                1 for route in ordered if route["feature_condition"] is not None
            ),
        },
        "routes": ordered,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="docs/generated/WARSOC_API_SECURITY_INVENTORY.json",
        help="Output path relative to the repository root",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    output_path = repo_root / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    inventory = build_inventory(repo_root)
    output_path.write_text(
        json.dumps(inventory, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    print(
        f"Wrote {inventory['summary']['route_count']} routes to {output_path}; "
        f"manual review required for {inventory['summary']['manual_review_required']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
