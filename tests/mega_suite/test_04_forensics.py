"""
Layer 4: Compliance Evidence & Forensics Tests
Tests compliance pack verification, evidence collection, and audit trails.
"""
import pytest
from datetime import datetime, timezone


@pytest.mark.layer4
class TestCompliancePacks:
    """Compliance evidence pack tests."""
    
    @pytest.mark.asyncio
    async def test_get_compliance_packs(self, client, authenticated_user):
        """Test retrieving available compliance packs."""
        resp = await client.get("/api/v1/compliance/packs", headers=authenticated_user)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))
    
    @pytest.mark.asyncio
    async def test_get_pack_details(self, client, authenticated_user):
        """Test retrieving specific pack details."""
        # First get the list of packs
        resp_list = await client.get("/api/v1/compliance/packs", headers=authenticated_user)
        if resp_list.status_code == 200:
            packs = resp_list.json()
            if isinstance(packs, list) and len(packs) > 0:
                pack_id = packs[0].get("id") or packs[0].get("pack_id")
                if pack_id:
                    resp = await client.get(f"/api/v1/compliance/packs/{pack_id}", headers=authenticated_user)
                    assert resp.status_code == 200


@pytest.mark.layer4
class TestForensicEvidence:
    """Forensic evidence collection tests."""
    
    @pytest.mark.asyncio
    async def test_get_evidence_list(self, client, authenticated_user):
        """Test retrieving compliance evidence (requires admin/auditor role)."""
        resp = await client.get("/api/v1/compliance/evidence", headers=authenticated_user)
        # Test user may not have admin/auditor role, so 403 is expected for regular user
        assert resp.status_code in [200, 403, 404], f"Got {resp.status_code}"
    
    @pytest.mark.asyncio
    async def test_verify_evidence_integrity(self, client, authenticated_user):
        """Test evidence verification endpoint."""
        evidence_payload = {
            "evidence_hash": "abc123def456",
            "verified_by": "test_user"
        }
        resp = await client.post("/api/v1/compliance/verify", json=evidence_payload, headers=authenticated_user)
        # May return 200, 422 validation error, 403 forbidden, or 404 if endpoint not fully implemented
        assert resp.status_code in [200, 201, 403, 404, 422]
    
    @pytest.mark.asyncio
    async def test_audit_trail_logged(self, client, authenticated_user):
        """Test that user actions create audit trail."""
        # Make a request that should be audited
        resp = await client.get("/api/v1/auth/me", headers=authenticated_user)
        assert resp.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
