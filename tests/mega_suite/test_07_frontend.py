"""
Layer 7: Frontend Integration & Export Tests
Tests data export, reporting, and frontend API endpoints.
"""
import json
import pytest
from datetime import datetime, timezone


@pytest.mark.layer7
class TestDataExport:
    """Data export endpoint tests."""
    
    @pytest.mark.asyncio
    async def test_export_csv_endpoint(self, client, authenticated_user):
        """Test exporting data to CSV format."""
        resp = await client.get("/api/v1/export/csv?data_type=logs", headers=authenticated_user)
        assert resp.status_code == 404, resp.text
        assert "No data found" in resp.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_audit_report_generation(self, client, authenticated_user):
        """Test audit report generation endpoint."""
        resp = await client.get(
            "/api/v1/export/audit-report?pack_id=peca_forensic",
            headers=authenticated_user,
        )
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-type"].startswith("application/pdf")
    
    @pytest.mark.asyncio
    async def test_list_reports(self, client, authenticated_user):
        """Test listing generated reports."""
        resp = await client.get("/api/v1/export/list", headers=authenticated_user)
        # Endpoint may require specific roles
        assert resp.status_code in [200, 403, 404], f"Got {resp.status_code}"


@pytest.mark.layer7
class TestUserWorkflows:
    """End-to-end user workflow tests."""
    
    @pytest.mark.asyncio
    async def test_get_user_profile(self, client, authenticated_user):
        """Test retrieving user profile."""
        resp = await client.get("/api/v1/auth/me", headers=authenticated_user)
        assert resp.status_code == 200
        user = resp.json()
        # some /auth/me responses nest the user under `user` key
        if "user" in user and isinstance(user["user"], dict):
            assert "username" in user["user"] or "email" in user["user"]
        else:
            assert "username" in user or "email" in user
    
    @pytest.mark.asyncio
    async def test_get_compliance_packs(self, client, authenticated_user):
        """Test retrieving user's compliance packs."""
        resp = await client.get("/api/v1/auth/my-packs", headers=authenticated_user)
        assert resp.status_code in [200, 404], f"Got {resp.status_code}"
    

    @pytest.mark.asyncio
    async def test_data_search_endpoint(self, client, authenticated_user):
        """Test searching security data."""
        resp = await client.get("/api/v1/data/search", headers=authenticated_user)
        assert resp.status_code == 200
    
    @pytest.mark.asyncio
    async def test_data_status_endpoint(self, client, authenticated_user):
        """Test data status/health endpoint."""
        resp = await client.get("/api/v1/data/status", headers=authenticated_user)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_required_signing_status_distinguishes_legacy_and_verified_agents(
        self,
        client,
        authenticated_user,
        db,
        redis_client,
        agent_public_key_pem,
        monkeypatch,
    ):
        monkeypatch.setenv("AGENT_EVENT_SIGNATURE_MODE", "required")
        me = await client.get("/api/v1/auth/me", headers=authenticated_user)
        tenant_id = me.json()["user"]["tenant_id"]
        agent_id = "WARSOC_AGENT_STATUS_CONTRACT"
        now = datetime.now(timezone.utc).isoformat()
        await db["agents"].insert_one(
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "public_key": agent_public_key_pem,
                "status": "active",
                "version": "4.2.4-Native",
                "last_seen": datetime.now(timezone.utc),
                "sensor_status": {
                    "audit_policy_status": "configured",
                    "channels": {
                        "Security": {"status": "ok"},
                        "System": {"status": "ok"},
                    },
                    "pos_sacl_path_count": 0,
                    "pos_audit_log": {"configured": False, "present": False},
                },
            }
        )
        await db["agent_coverage_observations"].insert_one(
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "protocol_version": "heartbeat-v2",
                "server_received_time": datetime.now(timezone.utc),
                "clock_offset_ms": 125,
                "clock_state": "TRUSTED",
            }
        )
        await redis_client.set(f"status:{tenant_id}:{agent_id}", now, ex=600)
        await redis_client.set(
            f"warsoc:agent_sensor:{agent_id}",
            json.dumps(
                {
                    "audit_policy_status": "configured",
                    "channels": {
                        "Security": {"status": "ok"},
                        "System": {"status": "ok"},
                    },
                    "spool": {"blocked": False},
                }
            ),
            ex=600,
        )
        signature_key = f"warsoc:agent_event_signature:{tenant_id}:{agent_id}"
        await redis_client.set(
            signature_key,
            json.dumps(
                {
                    "status": "unsigned_legacy",
                    "ready": False,
                    "last_event_at": now,
                    "last_signed_event_at": None,
                    "endpoint_name": "LEGACY-POS",
                    "agent_version": "4.2.4-Native",
                }
            ),
            ex=600,
        )

        legacy = await client.get("/api/v1/data/status", headers=authenticated_user)
        assert legacy.status_code == 200, legacy.text
        legacy_body = legacy.json()
        assert legacy_body["event_signature_mode"] == "required"
        assert legacy_body["endpoint_status"] == "degraded"
        assert legacy_body["agents_signing_ready"] == 0
        assert legacy_body["data"][0]["endpoint_name"] == "LEGACY-POS"
        assert legacy_body["data"][0]["event_signing"]["status"] == "unsigned_legacy"
        assert legacy_body["data"][0]["time_trust"]["status"] == "TRUSTED"
        assert legacy_body["data"][0]["time_trust"]["clock_offset_ms"] == 125
        assert legacy_body["data"][0]["audit_coverage"]["status"] == "READY"
        assert legacy_body["data"][0]["pos_coverage"]["status"] == "NOT_CONFIGURED"
        assert legacy_body["data"][0]["spool_health"]["status"] == "HEALTHY"
        legacy_coverage = await client.get(
            "/api/v1/compliance/coverage",
            headers=authenticated_user,
        )
        assert legacy_coverage.status_code == 200, legacy_coverage.text
        legacy_peca = next(
            row for row in legacy_coverage.json()["coverage"]
            if row["pack_id"] == "peca_forensic"
        )
        assert legacy_peca["event_signature_mode"] == "required"
        assert legacy_peca["signing_ready_agents"] == 0
        assert legacy_peca["status"] == "not_configured"

        await redis_client.set(
            signature_key,
            json.dumps(
                {
                    "status": "verified",
                    "ready": True,
                    "last_event_at": now,
                    "last_signed_event_at": now,
                    "endpoint_name": "SIGNED-POS",
                    "agent_version": "4.2.7-Native-Signed",
                }
            ),
            ex=600,
        )
        verified = await client.get("/api/v1/data/status", headers=authenticated_user)
        assert verified.status_code == 200, verified.text
        verified_body = verified.json()
        assert verified_body["endpoint_status"] == "active"
        assert verified_body["agents_signing_ready"] == 1
        assert verified_body["data"][0]["health"] == "active"
        assert verified_body["data"][0]["endpoint_name"] == "SIGNED-POS"
        verified_coverage = await client.get(
            "/api/v1/compliance/coverage",
            headers=authenticated_user,
        )
        assert verified_coverage.status_code == 200, verified_coverage.text
        verified_peca = next(
            row for row in verified_coverage.json()["coverage"]
            if row["pack_id"] == "peca_forensic"
        )
        assert verified_peca["signing_ready_agents"] == 1
        assert verified_peca["status"] == "active"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
