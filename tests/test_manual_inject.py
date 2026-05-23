import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException
from app.routes.logs import inject_manual_log

@pytest.mark.asyncio
async def test_inject_manual_log_redis_xadd():
    # 1. Setup mock payload and objects
    payload = {
        "event_id": 4625,
        "message": "Failed logon attempt simulated",
        "source_ip": "192.168.1.50",
        "user": "TargetUser"
    }
    
    mock_db = MagicMock()  # MongoDB mock database
    mock_user = {
        "username": "test_admin",
        "tenant_id": "TENANT_12345"
    }
    mock_role = "admin"
    
    # Mock FastAPI Request with app.state.redis
    mock_request = MagicMock()
    mock_redis = AsyncMock()
    mock_request.app.state.redis = mock_redis
    
    # 2. Call the endpoint function directly
    response = await inject_manual_log(
        payload=payload,
        db=mock_db,
        current_user=mock_user,
        role=mock_role,
        request=mock_request
    )
    
    # 3. Verifications
    # Verify the response structure
    assert response["status"] == "success"
    assert "event_uid" in response
    assert isinstance(response["event_uid"], str)
    
    # Verify that redis_client.xadd was called with the correct parameters
    mock_redis.xadd.assert_called_once()
    call_args, call_kwargs = mock_redis.xadd.call_args
    
    # Check stream name
    assert call_args[0] == "raw_logs_queue"
    
    # Check payload key and content
    stream_payload = call_args[1]
    assert "payload" in stream_payload
    
    # Parse the serialized payload back to verify data integrity
    serialized_data = json.loads(stream_payload["payload"])
    assert serialized_data["tenant_id"] == "TENANT_12345"
    assert serialized_data["injected_by"] == "test_admin"
    assert serialized_data["event_id"] == 4625
    assert serialized_data["event_uid"] == response["event_uid"]
    assert "timestamp" in serialized_data
    
    # 4. Strict verify: MongoDB database was NEVER called
    mock_db.assert_not_called()
    mock_db["logs"].insert_one.assert_not_called()
