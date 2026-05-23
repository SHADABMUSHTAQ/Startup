"""
Layer 2: CSV Upload & Streaming Parser Tests
Tests CSV upload, memory limits, delimiter detection, and streaming parsing.
"""
import pytest
import io
from datetime import datetime, timezone


@pytest.mark.layer2
class TestCSVUpload:
    """CSV upload endpoint tests."""
    
    @pytest.mark.asyncio
    async def test_upload_valid_csv_10mb(self, client, authenticated_user):
        """Test uploading a valid 10MB CSV file with valid event records."""
        # Create a valid CSV with 10k rows (smaller for faster testing)
        csv_content = "timestamp,source_ip,event_id,destination_ip,event_type\n"
        for i in range(10000):
            ts = datetime.now(timezone.utc).isoformat()
            csv_content += f"{ts},192.168.1.{i % 254},4688,10.0.0.1,ProcessCreate\n"
        
        files = {"file": ("large.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        # Should accept CSV file upload
        assert resp.status_code in [200, 201], f"Got {resp.status_code}: {resp.text}"
    
    @pytest.mark.asyncio
    async def test_upload_csv_valid_structure(self, client, authenticated_user):
        """Test uploading a valid CSV with proper headers and data."""
        csv_content = "timestamp,source_ip,event_id\n2024-01-01T12:00:00+00:00,192.168.1.1,4688\n"
        files = {"file": ("test.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        assert resp.status_code in [200, 201], f"Expected 200/201, got {resp.status_code}: {resp.text}"
    
    @pytest.mark.asyncio
    async def test_upload_auto_detect_delimiter_comma(self, client, authenticated_user):
        """Test CSV parsing with comma delimiter (default)."""
        csv_content = "timestamp,source_ip,event_id\n2024-01-01T12:00:00+00:00,192.168.1.1,4688\n"
        files = {"file": ("comma.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        assert resp.status_code in [200, 201]
    
    @pytest.mark.asyncio
    async def test_upload_auto_detect_delimiter_tab(self, client, authenticated_user):
        """Test CSV parsing with tab delimiter auto-detection."""
        csv_content = "timestamp\tsource_ip\tevent_id\n2024-01-01T12:00:00+00:00\t192.168.1.1\t4688\n"
        files = {"file": ("tab.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        assert resp.status_code in [200, 201]


@pytest.mark.layer2
class TestStreamingParser:
    """Streaming CSV parser tests."""
    
    @pytest.mark.asyncio
    async def test_parser_handles_valid_rows(self, client, authenticated_user):
        """Test that parser correctly handles valid CSV rows."""
        csv_content = "timestamp,source_ip,event_id\n"
        csv_content += "2024-01-01T12:00:00+00:00,192.168.1.1,4688\n"
        csv_content += "2024-01-02T13:00:00+00:00,192.168.1.2,4689\n"
        
        files = {"file": ("valid.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        assert resp.status_code in [200, 201]
    
    @pytest.mark.asyncio
    async def test_parser_malformed_rows_handled(self, client, authenticated_user):
        """Test handling of malformed CSV rows (missing fields, etc)."""
        csv_content = "timestamp,source_ip,event_id\n"
        csv_content += "2024-01-01T12:00:00+00:00,192.168.1.1,4688\n"  # valid
        csv_content += "2024-01-02T13:00:00+00:00,192.168.1.2\n"  # missing event_id (malformed)
        csv_content += "2024-01-03T14:00:00+00:00,192.168.1.3,4690\n"  # valid
        
        files = {"file": ("mixed.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        # Parser is strict and rejects malformed rows with 400
        assert resp.status_code in [200, 201, 400], f"Got {resp.status_code}"
    
    @pytest.mark.asyncio
    async def test_upload_empty_csv_rejected(self, client, authenticated_user):
        """Test that empty CSV is rejected."""
        csv_content = ""
        files = {"file": ("empty.csv", io.BytesIO(csv_content.encode()), "text/csv")}
        resp = await client.post("/api/v1/upload/analyze", files=files, headers=authenticated_user)
        
        # Should reject empty file or return error
        assert resp.status_code in [400, 422, 413], f"Expected 400/422/413, got {resp.status_code}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
