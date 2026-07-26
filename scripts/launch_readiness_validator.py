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
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.utils.agent_crypto import (
    EVENT_SIGNATURE_VERSION,
    build_event_signature_string,
    build_payload_hash,
    build_signable_event_payload,
)


@dataclass
class Response:
    status: int
    body: object
    raw: bytes
    headers: object


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
        follow_redirects: bool = True,
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
        opener = self.opener
        if not follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(self.cookies),
                NoRedirectHandler(),
            )
        try:
            with opener.open(request, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
                headers_obj = resp.headers
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
            headers_obj = exc.headers
        except urllib.error.URLError as exc:
            raw = str(exc.reason).encode("utf-8", errors="replace")
            status = 0
            headers_obj = {}
        except TimeoutError as exc:
            raw = str(exc).encode("utf-8", errors="replace")
            status = 0
            headers_obj = {}

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
        self.results: list[dict[str, str]] = []

    def record(self, name: str, ok: bool, detail: str = ""):
        label = "PASS" if ok else "FAIL"
        print(f"[{label}] {name}{': ' + detail if detail else ''}")
        self.results.append({"name": name, "status": label, "detail": detail})
        if not ok:
            self.failures.append(f"{name}: {detail}")

    def warn(self, name: str, detail: str):
        print(f"[WARN] {name}: {detail}")
        self.results.append({"name": name, "status": "WARN", "detail": detail})
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

        email_baseline = self.read_metric("warsoc_email_delivered_total")
        if not self.basic_public_checks():
            return self.finish()
        tenant_id, admin_email, admin_password = self.provision_and_login()
        if not tenant_id:
            return self.finish()

        self.agent_download_flow()
        agent_id, agent_jwt, private_key = self.agent_flow()
        if agent_id and agent_jwt and private_key:
            self.blacklist_flow(agent_id, private_key)
            websocket_probe = self.start_websocket_probe()
            self.ingest_and_pipeline(agent_id, agent_jwt, private_key)
            self.dashboard_live_read_flow()
            self.finish_websocket_probe(websocket_probe)

        self.rbac_flow(admin_password)
        self.export_checks()
        self.email_delivery_flow(email_baseline)

        return self.finish()

    def read_metric(self, metric_name: str) -> float | None:
        if not self.args.metrics_token:
            return None
        response = self.admin.request(
            "GET",
            "/metrics",
            headers={"Authorization": f"Bearer {self.args.metrics_token}"},
            timeout=15,
        )
        if response.status != 200:
            return None
        text = response.raw.decode("utf-8", errors="replace")
        match = re.search(
            rf"(?m)^{re.escape(metric_name)}(?:\{{[^}}]*\}})?\s+([0-9.eE+-]+)\s*$",
            text,
        )
        return float(match.group(1)) if match else None

    def basic_public_checks(self):
        def health_ready():
            health = self.admin.request("GET", "/health", timeout=10)
            return health.status == 200, f"HTTP {health.status}; {str(health.body)[:160]}"

        if not self.wait_for("Backend health", health_ready, self.args.wait_seconds):
            return False

        signup_payload = {
            "username": f"rogue_{self.run_id}",
            "email": self.unique_email("rogue"),
            "password": "RoguePass123!Secure",
            "full_name": "Rogue Signup",
            "plan_type": "Customized",
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

        legacy_payment = self.admin.request("POST", "/api/v1/sales/safepay/webhook", {"event": "test"})
        self.record("Legacy payment webhook absent", legacy_payment.status == 404, f"HTTP {legacy_payment.status}")
        return True

    def provision_and_login(self):
        admin_email = self.unique_email("admin")
        admin_password = f"AdminPass-{self.run_id}-123!"
        provision = self.admin.request(
            "POST",
            "/api/v1/admin/provision",
            {
                "company_name": "Launch Validation Tenant",
                "plan_type": "Customized",
                "compliance_packs": ["fbr_pos", "peca_forensic"],
                "max_agents": 15,
                "admin_email": admin_email,
                "admin_name": "Launch Admin",
                "admin_password": admin_password,
            },
            headers={"X-Admin-Key": self.args.admin_key},
            timeout=self.args.provision_timeout,
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

    def agent_download_flow(self):
        if self.args.skip_agent_download:
            self.warn("Agent installer CDN", "skipped by --skip-agent-download")
            return

        redirect = self.admin.request(
            "GET",
            "/api/v1/agent/download",
            timeout=30,
            follow_redirects=False,
        )
        location = redirect.headers.get("location") if redirect.headers else None
        if location:
            location = urllib.parse.urljoin(self.args.base_url + "/", location)
        parsed = urllib.parse.urlsplit(location or "")
        redirect_ok = (
            redirect.status in {301, 302, 303, 307, 308}
            and parsed.scheme == "https"
            and parsed.path.lower().endswith(".exe")
        )
        self.record(
            "Agent installer CDN redirect",
            redirect_ok,
            f"HTTP {redirect.status}; location={location or 'missing'}",
        )
        if not redirect_ok or not self.args.manifest_path:
            if redirect_ok and not self.args.manifest_path:
                self.warn("Agent installer CDN hash", "no --manifest-path supplied")
            return

        try:
            manifest = json.loads(Path(self.args.manifest_path).read_text(encoding="utf-8-sig"))
            installer = next(
                item
                for item in manifest.get("artifacts", [])
                if item.get("role") == "windows-installer"
            )
            expected_hash = str(installer["sha256"]).upper()
            expected_size = int(installer["size_bytes"])
        except Exception as exc:
            self.record("Agent installer CDN hash", False, f"invalid manifest: {exc}")
            return

        digest = hashlib.sha256()
        downloaded = 0
        try:
            request = urllib.request.Request(
                location,
                headers={"User-Agent": "WarSOC-Production-Acceptance/1.0"},
            )
            with urllib.request.urlopen(request, timeout=self.args.download_timeout) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > expected_size:
                        raise ValueError(
                            f"CDN artifact exceeds manifest size {expected_size}"
                        )
                    digest.update(chunk)
            actual_hash = digest.hexdigest().upper()
            matches = downloaded == expected_size and actual_hash == expected_hash
            self.record(
                "Agent installer CDN hash",
                matches,
                f"bytes={downloaded}; sha256={actual_hash}",
            )
        except Exception as exc:
            self.record("Agent installer CDN hash", False, str(exc))

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

    def start_websocket_probe(self):
        ticket_response = self.admin.request("POST", "/api/v1/ws/ticket")
        ticket = ticket_response.body.get("ticket") if isinstance(ticket_response.body, dict) else None
        if ticket_response.status != 200 or not ticket:
            self.record(
                "Authenticated WebSocket delivery",
                False,
                f"ticket HTTP {ticket_response.status}",
            )
            return None

        parsed = urllib.parse.urlsplit(self.args.base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = urllib.parse.urlunsplit(
            (
                ws_scheme,
                parsed.netloc,
                "/ws/alerts",
                urllib.parse.urlencode({"ticket": ticket}),
                "",
            )
        )
        ready = threading.Event()
        result = {
            "connected": False,
            "matched": False,
            "detail": "listener did not start",
        }

        async def listen_for_run_alert():
            import websockets

            try:
                async with websockets.connect(
                    ws_url,
                    open_timeout=10,
                    close_timeout=5,
                    ping_interval=20,
                ) as websocket:
                    result["connected"] = True
                    result["detail"] = "connected; waiting for run-specific alert"
                    ready.set()
                    deadline = time.monotonic() + self.args.wait_seconds
                    while time.monotonic() < deadline:
                        remaining = max(0.1, deadline - time.monotonic())
                        message = await asyncio.wait_for(websocket.recv(), timeout=remaining)
                        decoded = json.loads(message)
                        if self.run_id in json.dumps(decoded, separators=(",", ":"), default=str):
                            result["matched"] = True
                            result["detail"] = "received run-specific SIEM alert"
                            return
                    result["detail"] = "timed out waiting for run-specific SIEM alert"
            except Exception as exc:
                result["detail"] = f"{type(exc).__name__}: {exc}"
            finally:
                ready.set()

        def thread_target():
            asyncio.run(listen_for_run_alert())

        thread = threading.Thread(
            target=thread_target,
            name=f"warsoc-ws-probe-{self.run_id}",
            daemon=True,
        )
        thread.start()
        ready.wait(timeout=12)
        if not result["connected"]:
            thread.join(timeout=1)
            self.record("Authenticated WebSocket delivery", False, result["detail"])
            return None
        return thread, result

    def finish_websocket_probe(self, probe):
        if probe is None:
            return
        thread, result = probe
        thread.join(timeout=self.args.wait_seconds + 5)
        self.record(
            "Authenticated WebSocket delivery",
            bool(result["connected"] and result["matched"]),
            result["detail"],
        )

    def ingest_and_pipeline(self, agent_id: str, agent_jwt: str, private_key):
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "event_id": "1102",
                "event_uid": f"{self.run_id}-siem",
                "timestamp": now,
                "source_ip": "203.0.113.88",
                "user": "security-admin",
                "message": f"Security audit log cleared launch validation {self.run_id}",
                "raw_data": {"event_uid": f"{self.run_id}-siem"},
            },
            {
                "event_id": "4663",
                "event_uid": f"{self.run_id}-fbr-intent",
                "timestamp": now,
                "source_ip": "203.0.113.89",
                "user": "pos-user",
                "message": f"POS database delete intent launch validation {self.run_id}",
                "processed_data": {
                    "object_name": r"C:\POS\data\launch-validator.mdf",
                    "handle_id": "0x44",
                    "access_mask": "0x10000",
                },
                "raw_data": {"event_uid": f"{self.run_id}-fbr-intent"},
            },
            {
                "event_id": "4660",
                "event_uid": f"{self.run_id}-fbr-delete",
                "timestamp": now,
                "source_ip": "203.0.113.89",
                "user": "pos-user",
                "message": f"POS database deleted launch validation {self.run_id}",
                "processed_data": {"handle_id": "0x44"},
                "raw_data": {"event_uid": f"{self.run_id}-fbr-delete"},
            },
        ]
        for event in events:
            payload_hash = build_payload_hash(build_signable_event_payload(event))
            signature_input = build_event_signature_string(
                agent_id,
                event["timestamp"],
                event["event_uid"],
                payload_hash,
            ).encode("utf-8")
            event.update({
                "payload_hash": payload_hash,
                "agent_signature": private_key.sign(signature_input).hex(),
                "signature_version": EVENT_SIGNATURE_VERSION,
            })
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

        pos_envelope = {
            "nonce": uuid.uuid4().hex,
            "timestamp": time.time(),
            "payload": {
                "event_id": "FBR-INV-MOD",
                "event_uid": f"{self.run_id}-invoice",
                "invoice_id": f"INV-{self.run_id}",
                "timestamp": now,
                "actor": "launch-validator",
                "source_system": "launch-pos",
                "reason": "Launch validation invoice modification",
            },
        }
        pos_body = json.dumps(pos_envelope, separators=(",", ":")).encode("utf-8")
        pos_ingest = self.admin.request(
            "POST",
            "/api/v1/fbr/pos/ingest",
            body_bytes=pos_body,
            headers={
                "Authorization": f"Bearer {agent_jwt}",
                "X-WarSOC-Signature": private_key.sign(pos_body).hex(),
            },
        )
        self.record(
            "Authenticated POS ingest",
            pos_ingest.status == 202,
            f"HTTP {pos_ingest.status}; {pos_ingest.body}",
        )

        def alert_ready():
            resp = self.admin.request("GET", f"/api/v1/alerts?event_uid={urllib.parse.quote(self.run_id + '-siem')}&limit=20")
            if resp.status != 200:
                return False, f"alerts HTTP {resp.status}"
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            return bool(data), f"alerts={len(data)}"

        def fbr_ready():
            resp = self.admin.request(
                "GET",
                "/api/v1/compliance/evidence/fbr_pos?event_id=FIM-DB-MOD&limit=50",
            )
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            expected_uid = f"{self.run_id}-fbr-delete:fim-delete"
            matched = any(row.get("event_uid") == expected_uid for row in data)
            return resp.status == 200 and matched, f"HTTP {resp.status}; matched={matched}; rows={len(data)}"

        def fbr_invoice_ready():
            resp = self.admin.request(
                "GET",
                "/api/v1/compliance/evidence/fbr_pos?event_id=FBR-INV-MOD&limit=50",
            )
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            expected_uid = f"{self.run_id}-invoice"
            matched = any(row.get("event_uid") == expected_uid for row in data)
            return resp.status == 200 and matched, f"HTTP {resp.status}; matched={matched}; rows={len(data)}"

        def peca_ready():
            resp = self.admin.request(
                "GET",
                "/api/v1/compliance/evidence/peca_forensic?event_id=1102&limit=50",
            )
            data = resp.body.get("data", []) if isinstance(resp.body, dict) else []
            expected_uid = f"{self.run_id}-siem"
            matched = any(row.get("event_uid") == expected_uid for row in data)
            return resp.status == 200 and matched, f"HTTP {resp.status}; matched={matched}; rows={len(data)}"

        self.wait_for("SIEM alert visibility", alert_ready, self.args.wait_seconds)
        self.wait_for("FBR correlated tamper visibility", fbr_ready, self.args.wait_seconds)
        self.wait_for("FBR invoice evidence visibility", fbr_invoice_ready, self.args.wait_seconds)
        self.wait_for("PECA evidence visibility", peca_ready, self.args.wait_seconds)

    def dashboard_live_read_flow(self):
        for source, limit in (("security_alerts", 500), ("siem", 100)):
            started = time.perf_counter()
            response = self.admin.request(
                "GET",
                f"/api/v1/logs/live?source={source}&limit={limit}&aggregate={'true' if source == 'security_alerts' else 'false'}",
                timeout=10,
            )
            elapsed = time.perf_counter() - started
            body = response.body if isinstance(response.body, dict) else {}
            ok = (
                response.status == 200
                and body.get("mode") == "hot_live"
                and body.get("source") == source
                and isinstance(body.get("data"), list)
                and "total" not in body
                and "raw_total" not in body
                and elapsed < 10
            )
            self.record(
                f"Dashboard live read ({source})",
                ok,
                f"HTTP {response.status}; seconds={elapsed:.3f}; returned={body.get('returned')}; has_more={body.get('has_more')}",
            )

    def rbac_flow(self, admin_password: str):
        auditor_email = self.unique_email("auditor")
        invite = self.admin.request("POST", "/api/v1/auth/invite", {
            "email": auditor_email,
            "role": "auditor",
            "allowed_packs": ["fbr_pos", "peca_forensic"],
        })
        invite_body = invite.body if isinstance(invite.body, dict) else {}
        invite_ok = (
            invite.status == 201
            and invite_body.get("status") == "pending"
            and invite_body.get("email_queued") is True
        )
        self.record(
            "Auditor secure invitation",
            invite_ok,
            f"HTTP {invite.status}; status={invite_body.get('status')}; email_queued={invite_body.get('email_queued')}",
        )
        if invite.status != 201:
            return

        auditor = ApiClient(self.args.base_url)
        login = auditor.login(auditor_email, admin_password)
        self.record(
            "Pending auditor cannot log in",
            login.status in {401, 403},
            f"HTTP {login.status}",
        )
        self.warn(
            "Activated auditor RBAC",
            "Complete the emailed one-time link, then verify team/alerts/agent APIs return 403 and entitled compliance evidence returns 200.",
        )

    def export_checks(self):
        csv_resp = self.admin.request("GET", "/api/v1/export/csv?data_type=alerts&limit=100", timeout=60)
        self.record("CSV export", csv_resp.status == 200 and len(csv_resp.raw) > 20, f"HTTP {csv_resp.status}; bytes={len(csv_resp.raw)}")

        if self.args.skip_pdf:
            self.warn("PDF export", "skipped by --skip-pdf")
            return
        pdf_resp = self.admin.request("GET", "/api/v1/export/audit-report?pack_id=peca_forensic", timeout=90)
        self.record("PDF audit export", pdf_resp.status == 200 and pdf_resp.raw.startswith(b"%PDF"), f"HTTP {pdf_resp.status}; bytes={len(pdf_resp.raw)}")

    def email_delivery_flow(self, baseline: float | None):
        if not self.args.metrics_token:
            self.warn(
                "SMTP worker delivery",
                "not measured; supply --metrics-token for production acceptance",
            )
            return
        if baseline is None:
            self.record(
                "SMTP worker delivery",
                False,
                "email delivery metric was unavailable before the test",
            )
            return

        deadline = time.time() + self.args.email_delivery_timeout
        latest = baseline
        while time.time() < deadline:
            observed = self.read_metric("warsoc_email_delivered_total")
            if observed is not None:
                latest = observed
                if observed >= baseline + 2:
                    self.record(
                        "SMTP worker delivery",
                        True,
                        f"delivered_total increased by {observed - baseline:g}",
                    )
                    return
            time.sleep(3)
        self.record(
            "SMTP worker delivery",
            False,
            f"delivered_total increased by only {latest - baseline:g}",
        )

    def finish(self) -> int:
        print()
        print("Launch Readiness Summary")
        print(f"PASS/FAIL complete. Failures: {len(self.failures)} Warnings: {len(self.warnings)}")
        if self.failures:
            for item in self.failures:
                print(f" - {item}")
        exit_code = 1 if self.failures else 0
        if self.args.report_path:
            report_path = Path(self.args.report_path)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report = {
                "run_id": self.run_id,
                "base_url": self.args.base_url,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "passed": exit_code == 0,
                "failure_count": len(self.failures),
                "warning_count": len(self.warnings),
                "results": self.results,
            }
            report_path.write_text(
                json.dumps(report, indent=2),
                encoding="utf-8",
            )
            print(f"Report: {report_path.resolve()}")
        return exit_code


def parse_args():
    parser = argparse.ArgumentParser(description="Run WarSOC launch readiness checks against a rebuilt backend.")
    parser.add_argument("--base-url", default=os.getenv("WARSOC_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--admin-key", default=os.getenv("SUPER_ADMIN_API_KEY", ""))
    parser.add_argument("--email-domain", default=os.getenv("WARSOC_TEST_EMAIL_DOMAIN", "warsoc.tech"))
    parser.add_argument("--wait-seconds", type=int, default=int(os.getenv("WARSOC_WAIT_SECONDS", "90")))
    parser.add_argument("--provision-timeout", type=int, default=int(os.getenv("WARSOC_PROVISION_TIMEOUT", "180")))
    parser.add_argument("--metrics-token", default=os.getenv("METRICS_BEARER_TOKEN", ""))
    parser.add_argument("--manifest-path", default="")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--download-timeout", type=int, default=180)
    parser.add_argument("--email-delivery-timeout", type=int, default=180)
    parser.add_argument("--skip-agent-download", action="store_true")
    parser.add_argument("--skip-pdf", action="store_true")
    args = parser.parse_args()
    if not args.admin_key:
        parser.error("--admin-key or SUPER_ADMIN_API_KEY is required")
    return args


if __name__ == "__main__":
    sys.exit(Validator(parse_args()).run())
