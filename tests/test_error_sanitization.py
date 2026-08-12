import json

import pytest
from fastapi import HTTPException, Request

from app.main import (
    sanitized_http_exception_handler,
    sanitized_unhandled_exception_handler,
)


def _request() -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/api/v1/compliance/packs",
            "raw_path": b"/api/v1/compliance/packs",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("api.warsoc.tech", 443),
        }
    )
    request.state.request_id = "errorref12345678"
    return request


@pytest.mark.asyncio
async def test_infrastructure_http_error_is_masked():
    response = await sanitized_http_exception_handler(
        _request(),
        HTTPException(status_code=503, detail="Redis unavailable for compliance catalog"),
    )

    body = json.loads(response.body)
    assert response.status_code == 503
    assert body["detail"] == "The service is temporarily unavailable."
    assert body["request_id"] == "errorref12345678"
    assert body["error"] == {
        "code": "service_unavailable",
        "message": "The service is temporarily unavailable.",
        "request_id": "errorref12345678",
    }
    assert response.headers["X-Request-ID"] == "errorref12345678"
    assert "Redis" not in response.body.decode()


@pytest.mark.asyncio
async def test_unhandled_error_is_masked():
    response = await sanitized_unhandled_exception_handler(
        _request(),
        RuntimeError("MongoDB connection string leaked"),
    )

    body = json.loads(response.body)
    assert response.status_code == 500
    assert body["detail"] == "The service is temporarily unavailable."
    assert body["request_id"] == "errorref12345678"
    assert body["error"]["code"] == "service_unavailable"
    assert "MongoDB" not in response.body.decode()


@pytest.mark.asyncio
async def test_validation_error_hides_internal_schema_names(async_client):
    response = await async_client.post(
        "/api/v1/sales/request-quote",
        json={"frontend_calculated_total": "not-a-number"},
    )

    body = response.json()
    serialized = json.dumps(body)
    assert response.status_code == 422
    assert body["detail"] == "Some request fields are invalid."
    assert body["error"]["code"] == "invalid_request"
    assert body["request_id"]
    assert response.headers["X-Request-ID"] == body["request_id"]
    assert "frontend_calculated_total" not in serialized
    assert "Field required" not in serialized
