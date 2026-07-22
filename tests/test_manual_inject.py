import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException
from app.routes import logs

@pytest.mark.asyncio
async def test_inject_manual_log_is_disabled_by_default():
    with pytest.raises(HTTPException) as exc:
        await logs.inject_manual_log(
            payload={"event_id": 4625},
            db=MagicMock(),
            current_user={"username": "test_admin", "tenant_id": "TENANT_12345"},
            role="admin",
            request=MagicMock(),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_inject_manual_log_requires_explicit_opt_in(monkeypatch):
    # 1. Setup mock payload and objects
    payload = {
        "event_id": 4625,
        "message": "Failed logon attempt simulated",
        "source_ip": "192.168.1.50",
        "user": "TargetUser"
    }
    
    mock_db = MagicMock()  # MongoDB mock database
    mock_db["logs"].insert_one = AsyncMock(return_value=MagicMock(inserted_id="fake_id"))
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
    monkeypatch.setattr(logs._settings, "enable_manual_log_injection", True)
    response = await logs.inject_manual_log(
        payload=payload,
        db=mock_db,
        current_user=mock_user,
        role=mock_role,
        request=mock_request
    )
    
    # 3. Verifications
    # Verify the response structure
    assert response["status"] == "success"
    assert "id" in response
    assert isinstance(response["id"], str)
    
    # Verify that db["logs"].insert_one was called
    mock_db["logs"].insert_one.assert_called_once()
    call_args, call_kwargs = mock_db["logs"].insert_one.call_args
    log_entry = call_args[0]
    
    assert log_entry["tenant_id"] == "TENANT_12345"
    assert log_entry["injected_by"] == "test_admin"
    assert log_entry["event_id"] == 4625
    assert "timestamp" in log_entry
