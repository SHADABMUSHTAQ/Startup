"""
WarSOC launch readiness validator.

Run after rebuilding/restarting Docker. Recommended:

  docker compose exec api python scripts/launch_readiness_validator.py ^
    --base-url http://127.0.0.1:8000 ^
    --admin-key "%SUPER_ADMIN_API_KEY%" ^
    --email-domain warsoc.tech

For prod compose:

  docker compose -f docker-compose.prod.yml exec warsoc-api python scripts/launch_readiness_validator.py \
    --base-url http://127.0.0.1:8000 \
    --admin-key "$SUPER_ADMIN_API_KEY" \
    --email-domain warsoc.tech
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


@dataclass
class Response:
    status: int
    body: object
    raw: bytes
    headers: object


class ApiClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf_token: str | None = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def request(
        self,
        method: str,
        path: str,
        json_body: object | None = None,
        body_bytes: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> Response:
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        data = None
        if json_body is not None:
            data = json.dumps(json_body, separators=(",", ":"), default=str).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        elif body_bytes is not None:
            data = body_bytes
            req_headers.setdefault("Content-Type", "application/json")

        if self.csrf_token and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            req_headers.setdefault("X-CSRF-Token", self.csrf_token)

        request = urllib.request.Request(self._url(path), data=data, headers=req_headers, method=method.upper())
        try:
            with self.opener.open(request, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
                headers_obj = resp.headers
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
            headers_obj = exc.headers

        body = raw
        content_type = (headers_obj.get("content-type") or "").lower()
        if raw and ("json" in content_type or raw[:1] in (b"{", b"[")):
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                body = raw.decode("utf-8", errors="replace")
        elif raw:
            body = raw.decode("utf-8", errors="replace")

        return Response(status=status, body=body, raw=raw, headers=headers_obj)

    def login(self, username: str, password: str) -> Response:
        resp = self.request("POST", "/api/v1/auth/login", {"username": username, "password": password})
        if isinstance(resp.body, dict):
            self.csrf_token = resp.body.get("csrf_token")
        if not self.csrf_token:
            for cookie in self.cookies:
                if cookie.name == "csrf_token":
                    self.csrf_token = cookie.value
                    break
        return resp


class Validator:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.run_id = uuid.uuid4().hex[:10]
        self.admin = ApiClient(args.base_url)
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def record(self, name: str, ok: bool, detail: str = ""):
        label = "PASS" if ok else "FAIL"
        print(f"[{label}] {name}{': ' + detail if detail else ''}")
        if not ok:
            self.failures.append(f"{name}: {detail}")

    def warn(self, name: str, detail: str):
        print(f"[WARN] {name}: {detail}")
        self.warnings.append(f"{name}: {detail}")

    def unique_email(self, prefix: str) -> str:
        return f"{prefix}-{self.run_id}@{self.args.email_domain}"

    def wait_for(self, name: str, fn, timeout: int):
        deadline = time.time() + timeout
        last_detail = ""
        while time.time() < deadline:
            ok, detail = fn()
            if ok:
                self.record(name, True, detail)
                return True
            last_detail = detail
            time.sleep(2)
        self.record(name, False, last_detail or f"timed out after {timeout}s")
        return False

    def run(self) -> int:
        print("WarSOC launch readiness validator")
        print(f"Base URL: {self.args.base_url}")
        print(f"Run ID: {self.run_id}")

        self.basic_public_checks()
        tenant_id, admin_email, admin_password = self.provision_and_login()
        if not tenant_id:
            return self.finish()

        agent_id, agent_jwt, private_key = self.agent_flow()
        if agent_id and agent_jwt and private_key:
            self.blacklist_flow(agent_id, private_key)
            self.ingest_and_pipeline(agent_jwt)

        self.rbac_flow(admin_password)
        self.export_checks()

        return self.finish()

    def basic_public_checks(self):
        health = self.admin.request("GET", "/health", timeout=10)
        self.record("Backend health", health.status == 200, str(health.body)[:160])

        signup_payload = {
            "username": f"rogue_{self.run_id}",
            "email": self.unique_email("rogue"),
            "password": "RoguePass123!",
            "full_name": "Rogue Signup",
            "plan_type": "Enterprise",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "role": "admin",
        }
        signup = self.admin.request("POST", "/api/v1/auth/signup", signup_payload)
        self.record("Public signup blocked", signup.status == 403, f"HTTP {signup.status}")

        quote = self.admin.request("POST", "/api/v1/sales/request-quote", {
            "contact_name": "Launch Buyer",
            "contact_email": self.unique_email("buyer"),
            "contact_phone": "+920000000000",
            "company_name": "Launch Validation Pvt Ltd",
            "plan_type": "Customized",
            "endpoints": 15,
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "billing_cycle": "monthly",
            "frontend_calculated_total": 0,
        })
        self.record("Sales quote request", quote.status == 200, f"HTTP {quote.status}")

        contact = self.admin.request("POST", "/api/v1/sales/contact", {
            "name": "Launch Contact",
            "email": self.unique_email("contact"),
            "company": "Launch Validation Pvt Ltd",
            "inquiry_type": "demo",
            "message": f"Launch readiness contact validation {self.run_id}",
        })
        self.record("Homepage contact request", contact.status == 200, f"HTTP {contact.status}")

        safepay = self.admin.request("POST", "/api/v1/sales/safepay/webhook", {"event": "test"})
        self.record("Safepay fails closed", safepay.status == 501, f"HTTP {safepay.status}")

    def provision_and_login(self):
        admin_email = self.unique_email("admin")
        admin_password = f"AdminPass-{self.run_id}-123!"
        provision = self.admin.request(
            "POST",
            "/api/v1/admin/provision",
            {
                "company_name": "Launch Validation Tenant",
                "plan_type": "Enterprise",
                "compliance_packs": ["fbr_pos", "peca_forensic"],
                "max_agents": 15,
                "admin_email": admin_email,
                "admin_name": "Launch Admin",
                "admin_password": admin_password,
            },
            headers={"X-Admin-Key": self.args.admin_key},
        )
        tenant_id = provision.body.get("tenant_id") if isinstance(provision.body, dict) else None
        self.record("Admin tenant provisioning", provision.status == 200 and bool(tenant_id), f"HTTP {provision.status}; tenant={tenant_id}")
        if not tenant_id:
            return None, admin_email, admin_password

        login = self.admin.login(admin_email, admin_password)
        self.record("Provisioned admin login", login.status == 200, f"HTTP {login.status}")

        me = self.admin.request("GET", "/api/v1/auth/me")
        user_context = me.body.get("user") if isinstance(me.body, dict) and isinstance(me.body.get("user"), dict) else me.body
        ok = (
            me.status == 200
            and isinstance(user_context, dict)
            and user_context.get("tenant_id") == tenant_id
        )
        self.record("Auth context hydration", ok, str(me.body)[:180])
        return tenant_id, admin_email, admin_password

    def agent_flow(self):
        activation = self.admin.request("POST", "/api/v1/agent/generate-activation", {})
        code = activation.body.get("activation_code") if isinstance(activation.body, dict) else None
        self.record("Agent activation code", activation.status == 200 and bool(code), f"HTTP {activation.status}")
        if not code:
            return None, None, None

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        register = self.admin.request("POST", "/api/v1/agent/register", {
            "activation_code": code,
            "public_key": public_pem,
        })
        agent_id = register.body.get("agent_id") if isinstance(register.body, dict) else None
        agent_jwt = register.body.get("agent_jwt") if isinstance(register.body, dict) else None
        self.record("Agent registration", register.status == 200 and bool(agent_id) and bool(agent_jwt), f"HTTP {register.status}; agent={agent_id}")
        return agent_id, agent_jwt, private_key

    def signed_heartbeat(self, agent_id: str, private_key) -> Response:
        payload = {
            "agent_id": agent_id,
            "current_version": "launch-validator",
            "timestamp": time.time(),
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = private_key.sign(body).hex()
        return self.admin.request(
            "POST",
            "/api/v1/agent/heartbeat",
            body_bytes=body,
            headers={"X-WarSOC-Signature": signature},
        )

    def blacklist_flow(self, agent_id: str, private_key):
        attacker_ip = f"203.0.113.{int(self.run_id[:2], 16) % 200 + 1}"
        mitigate = self.admin.request("POST", "/api/v1/mitigate", {
            "ip": attacker_ip,
            "reason": f"launch validator {self.run_id}",
        })
        self.record("Attacker IP mitigation", mitigate.status == 200, f"HTTP {mitigate.status}; ip={attacker_ip}")

        heartbeat = self.signed_heartbeat(agent_id, private_key)
        bans = heartbeat.body.get("enforce_bans", []) if isinstance(heartbeat.body, dict) else []
        self.record("Agent heartbeat receives blacklist", heartbeat.status == 200 and attacker_ip in bans, f"HTTP {heartbeat.status}; bans={bans}")

        self.self_lockout_guard(agent_id)
        self.admin.request("POST", "/api/v1/revoke", {"ip": attacker_ip, "reason": "cleanup"})

    def self_lockout_guard(self, agent_id: str):
        guard_ip = "198.51.100.42"
        try:
            from pymongo import MongoClient, ReturnDocument

            mongo_uri = os.getenv("MONGODB_URI")
            db_name = os.getenv("MONGODB_DB_NAME") or os.getenv("DB_NAME") or "WarSOC_DB"
            if not mongo_uri:
                self.warn("Self-lockout guard", "MONGODB_URI unavailable inside validator container; skipped DB setup")
                return
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = client[db_name]
            original = db["agents"].find_one_and_update(
                {"agent_id": agent_id},
                {"$set": {"last_ip": guard_ip, "status": "active"}},
                return_document=ReturnDocument.BEFORE,
            )
            if not original:
                self.warn("Self-lockout guard", "agent document not found for direct last_ip setup")
                return
            guarded = self.admin.request("POST", "/api/v1/mitigate", {
                "ip": guard_ip,
                "reason": f"self-lockout guard validation {self.run_id}",
            })
            self.record("Active agent IP self-lockout guard", guarded.status == 409, f"HTTP {guarded.status}")
        except Exception as exc:
            self.warn("Self-lockout guard", f"skipped due to DB helper error: {exc}")
        finally:
            try:
                if "client" in locals() and "original" in locals() and original:
                    db["agents"].update_one(
                        {"agent_id": agent_id},
                        {"$set": {"last_ip": original.get("last_ip"), "status": original.get("status", "active")}},
                    )
            except Exception:
                pass

    def ingest_and_pipeline(self, agent_jwt: str):
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "event_id": "4625",
                "event_uid": f"{self.run_id}-siem",
                "timestamp": now,
                "source_ip": "203.0.113.88",
                "user": "launch-validator",
                "message": f"login failed failed password launch validation {self.run_id}",
                "raw_data": {"event_uid": f"{self.run_id}-siem"},
            },
            {
                "event_id": "4663",
                "event_uid": f"{self.run_id}-fbr",
                "timestamp": now,
                "source_ip": "203.0.113.89",
                "user": "pos-user",
                "message": f"FBR POS file object access modified launch validation {self.run_id}",
                "raw_data": {"event_uid": f"{self.run_id}-fbr"},
            },
            {
                "event_id": "1102",
                "event_uid": f"{self.run_id}-peca",
                "timestamp": now,
                "source_ip": "203.0.113.90",
                "user": "security-admin",
                "message": f"Security audit log cleared PECA forensic launch validation {self.run_id}",
                "raw_data": {"event_uid": f"{self.run_id}-peca"},
            },
        ]
        ingest = self.admin.request(
            "POST",
            "/api/v1/ingest/pulse",
            {
                "nonce": uuid.uuid4().hex,
                "timestamp": int(time.time()),
                "payload": events,
            },
            headers={"Authorization": f"Bearer {agent_jwt}"},
        )
        self.record("Agent telemetry ingest", ingest.status in {200, 202}, f"HTTP {ingest.status}; {ingest.body}")

        def alert_ready():
            resp = self.admin.request("GET", f"/api/v1/alerts?event_uid={urllib.parse.quote(self.run_id + '-siem')}&limit=20")
            if resp.status != 200:
                return False, f"alerts HTTP {resp.status}"
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            return bool(data), f"alerts={len(data)}"

        def fbr_ready():
            resp = self.admin.request("GET", "/api/v1/compliance/evidence/fbr_pos?limit=50")
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            return resp.status == 200 and bool(data), f"HTTP {resp.status}; rows={len(data)}"

        def peca_ready():
            resp = self.admin.request("GET", "/api/v1/compliance/evidence/peca_forensic?limit=50")
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            return resp.status == 200 and bool(data), f"HTTP {resp.status}; rows={len(data)}"

        self.wait_for("SIEM alert visibility", alert_ready, self.args.wait_seconds)
        self.wait_for("FBR evidence visibility", fbr_ready, self.args.wait_seconds)
        self.wait_for("PECA evidence visibility", peca_ready, self.args.wait_seconds)

    def rbac_flow(self, admin_password: str):
        auditor_email = self.unique_email("auditor")
        invite = self.admin.request("POST", "/api/v1/auth/invite", {
            "email": auditor_email,
            "temp_password": admin_password,
            "role": "auditor",
            "allowed_packs": ["fbr_pos", "peca_forensic"],
        })
        self.record("Auditor provisioning", invite.status == 201, f"HTTP {invite.status}")
        if invite.status != 201:
            return

        auditor = ApiClient(self.args.base_url)
        login = auditor.login(auditor_email, admin_password)
        self.record("Auditor login", login.status == 200, f"HTTP {login.status}")

        team = auditor.request("GET", "/api/v1/auth/team")
        self.record("Auditor denied team management", team.status == 403, f"HTTP {team.status}")

        alerts = auditor.request("GET", "/api/v1/alerts")
        self.record("Auditor denied operational alerts API", alerts.status == 403, f"HTTP {alerts.status}")

        activation = auditor.request("POST", "/api/v1/agent/generate-activation", {})
        self.record("Auditor denied agent activation API", activation.status == 403, f"HTTP {activation.status}")

        evidence = auditor.request("GET", "/api/v1/compliance/evidence/fbr_pos?limit=10")
        self.record("Auditor entitled FBR evidence access", evidence.status == 200, f"HTTP {evidence.status}")

    def export_checks(self):
        csv_resp = self.admin.request("GET", "/api/v1/export/csv?data_type=alerts&limit=100", timeout=60)
        self.record("CSV export", csv_resp.status == 200 and len(csv_resp.raw) > 20, f"HTTP {csv_resp.status}; bytes={len(csv_resp.raw)}")

        if self.args.skip_pdf:
            self.warn("PDF export", "skipped by --skip-pdf")
            return
        pdf_resp = self.admin.request("GET", "/api/v1/export/audit-report?pack_id=peca_forensic", timeout=90)
        self.record("PDF audit export", pdf_resp.status == 200 and pdf_resp.raw.startswith(b"%PDF"), f"HTTP {pdf_resp.status}; bytes={len(pdf_resp.raw)}")

    def finish(self) -> int:
        print()
        print("Launch Readiness Summary")
        print(f"PASS/FAIL complete. Failures: {len(self.failures)} Warnings: {len(self.warnings)}")
        if self.failures:
            for item in self.failures:
                print(f" - {item}")
            return 1
        return 0


def parse_args():
    parser = argparse.ArgumentParser(description="Run WarSOC launch readiness checks against a rebuilt backend.")
    parser.add_argument("--base-url", default=os.getenv("WARSOC_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--admin-key", default=os.getenv("SUPER_ADMIN_API_KEY", ""))
    parser.add_argument("--email-domain", default=os.getenv("WARSOC_TEST_EMAIL_DOMAIN", "warsoc.tech"))
    parser.add_argument("--wait-seconds", type=int, default=int(os.getenv("WARSOC_WAIT_SECONDS", "90")))
    parser.add_argument("--skip-pdf", action="store_true")
    args = parser.parse_args()
    if not args.admin_key:
        parser.error("--admin-key or SUPER_ADMIN_API_KEY is required")
    return args


if __name__ == "__main__":
    sys.exit(Validator(parse_args()).run())
