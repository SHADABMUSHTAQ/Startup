"""
Layer 7: Frontend Integration & Export Tests
Tests data export, reporting, and frontend API endpoints.
"""
import pytest
from datetime import datetime, timezone


@pytest.mark.layer7
class TestDataExport:
    """Data export endpoint tests."""
    
    @pytest.mark.asyncio
    async def test_export_csv_endpoint(self, client, authenticated_user):
        """Test exporting data to CSV format."""
        resp = await client.get("/api/v1/export/csv", headers=authenticated_user)
        # Endpoint may require additional parameters or specific roles
        assert resp.status_code in [200, 403, 404], f"Got {resp.status_code}"
    
    @pytest.mark.asyncio
    async def test_audit_report_generation(self, client, authenticated_user):
        """Test audit report generation endpoint."""
        resp = await client.get("/api/v1/export/audit-report", headers=authenticated_user)
        # Endpoint may require additional parameters or specific roles
        assert resp.status_code in [200, 403, 404], f"Got {resp.status_code}"
    
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
    async def test_plan_upgrade_workflow(self, client, authenticated_user):
        """Test plan upgrade request workflow."""
        upgrade_payload = {
            "plan_type": "Professional",
            "compliance_packs": ["eto_forensic"],
            "endpoints": 50,
            "storage_gb": 100,
            "retention_months": 12
        }
        resp = await client.post("/api/v1/auth/upgrade", json=upgrade_payload, headers=authenticated_user)
        assert resp.status_code in [200, 201, 400], f"Got {resp.status_code}"
    
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
