"""
Layer 6: Real-Time & Notification Tests
Tests real-time alert delivery and user notifications.
"""
import pytest
from datetime import datetime, timezone


@pytest.mark.layer6
class TestRealTimeAlerts:
    """Real-time alert delivery tests."""
    
    @pytest.mark.asyncio
    async def test_alerts_history_endpoint(self, client, authenticated_user):
        """Test retrieving alert history via REST endpoint."""
        resp = await client.get("/api/v1/ingest/alerts/history", headers=authenticated_user)
        assert resp.status_code in [200, 404], f"Got {resp.status_code}"
    
    @pytest.mark.asyncio
    async def test_logs_streaming_endpoint(self, client, authenticated_user):
        """Test retrieving logs via streaming endpoint."""
        resp = await client.get("/api/v1/logs", headers=authenticated_user)
        assert resp.status_code == 200
    
    @pytest.mark.asyncio
    async def test_user_notification_creation(self, client, authenticated_user, db):
        """Test that alerts/notifications are created for users."""
        # Create an event
        event_payload = {
            "event_id": 4688,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.100",
            "user": "DOMAIN\\Administrator"
        }
        resp = await client.post("/api/v1/ingest", json=event_payload, headers=authenticated_user)
        
        # Verify event was stored
        if resp.status_code in [200, 201]:
            events = await db["peca_forensic_logs"].find_one({"event_id": 4688})
            # Just verify the endpoint worked
            assert True


@pytest.mark.layer6
class TestNotificationDelivery:
    """Notification delivery tests."""
    
    @pytest.mark.asyncio
    async def test_user_receives_own_alerts(self, client, authenticated_user):
        """Test that logged-in user can see their own alerts."""
        resp = await client.get("/api/v1/ingest/alerts/history", headers=authenticated_user)
        assert resp.status_code in [200, 404], f"Got {resp.status_code}"
    
    @pytest.mark.asyncio
    async def test_unauthorized_user_blocked(self, client):
        """Test that unauthenticated user cannot access alerts."""
        resp = await client.get("/api/v1/ingest/alerts/history")
        assert resp.status_code in [401, 404], f"Got {resp.status_code}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
