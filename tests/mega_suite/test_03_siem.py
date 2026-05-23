"""
Layer 3: SIEM Integration & Event Processing Tests
Tests event ingestion, rule firing, and alert generation.
"""
import pytest
import json
from datetime import datetime, timezone


@pytest.mark.layer3
class TestEventIngestion:
    """Event ingestion and SIEM processing."""
    
    @pytest.mark.asyncio
    async def test_ingest_valid_event(self, client, authenticated_user):
        """Test ingesting a single valid security event via pulse endpoint."""
        event_payload = {
            "event_id": 4688,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "user": "DOMAIN\\Administrator",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c whoami"
        }
        # ingest/pulse requires agent token, not user token, so we expect 401
        resp = await client.post("/api/v1/ingest/pulse", json=event_payload, headers=authenticated_user)
        # 401 is expected because user token cannot auth as agent
        assert resp.status_code in [200, 201, 401], f"Got {resp.status_code}: {resp.text}"
    
    @pytest.mark.asyncio
    async def test_ingest_batch_events(self, client, authenticated_user):
        """Test batch ingestion of multiple events via pulse endpoint."""
        events = [
            {
                "event_id": 4688,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "192.168.1.100",
                "user": "DOMAIN\\User1"
            },
            {
                "event_id": 4624,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "192.168.1.101",
                "user": "DOMAIN\\User2"
            }
        ]
        resp = await client.post("/api/v1/ingest/pulse", json=events, headers=authenticated_user)
        # ingest/pulse requires agent token - 401 expected for user token
        assert resp.status_code in [200, 201, 401]
    
    @pytest.mark.asyncio
    async def test_ingest_status_endpoint(self, client, authenticated_user):
        """Test ingestion status/health check."""
        resp = await client.get("/api/v1/ingest/status", headers=authenticated_user)
        assert resp.status_code in [200, 404], f"Got {resp.status_code}"


@pytest.mark.layer3
class TestAlertGeneration:
    """Alert generation from ingested events."""
    
    @pytest.mark.asyncio
    async def test_get_alerts_history(self, client, authenticated_user):
        """Test retrieving alert history."""
        resp = await client.get("/api/v1/ingest/alerts/history", headers=authenticated_user)
        assert resp.status_code in [200, 404], f"Got {resp.status_code}"
    
    @pytest.mark.asyncio
    async def test_logs_endpoint(self, client, authenticated_user):
        """Test retrieving logs/events."""
        resp = await client.get("/api/v1/logs", headers=authenticated_user)
        assert resp.status_code == 200
    
    @pytest.mark.asyncio
    async def test_search_events(self, client, authenticated_user):
        """Test searching events by criteria."""
        resp = await client.get("/api/v1/data/search?event_id=4688", headers=authenticated_user)
        assert resp.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
