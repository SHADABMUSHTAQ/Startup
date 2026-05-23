"""
Layer 1: Authentication & Authorization Tests
Tests signup, login, logout, token validation.
All tests use async_client fixture for async HTTP calls.
"""
import pytest


@pytest.mark.asyncio
async def test_signup_valid(async_client):
    """Test valid user signup."""
    payload = {
        "username": "integ_signup_user",
        "password": "Password123!",
        "email": "integ_signup@example.com",
        "full_name": "Integ Signup",
        "plan_type": "Free",
    }
    resp = await async_client.post("/api/v1/auth/signup", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert "tenant_id" in body


@pytest.mark.asyncio
async def test_signup_duplicate(async_client):
    """Test signup with duplicate username/email."""
    payload = {
        "username": "dup_user",
        "password": "Password123!",
        "email": "dup@example.com",
        "full_name": "Dup User",
        "plan_type": "Free",
    }
    r1 = await async_client.post("/api/v1/auth/signup", json=payload)
    assert r1.status_code == 201
    r2 = await async_client.post("/api/v1/auth/signup", json=payload)
    assert r2.status_code == 400


@pytest.mark.asyncio
async def test_login_valid_and_logout(async_client):
    """Test valid login followed by logout."""
    payload = {
        "username": "login_user",
        "password": "Password123!",
        "email": "login_user@example.com",
        "full_name": "Login User",
        "plan_type": "Free",
    }
    r = await async_client.post("/api/v1/auth/signup", json=payload)
    assert r.status_code == 201

    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": payload["password"]}
    )
    assert login.status_code == 200
    assert "warsoc_token" in login.cookies
    csrf_token = login.json().get("csrf_token")
    logout = await async_client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf_token})
    assert logout.status_code == 200

    # Token should now be revoked
    me = await async_client.get("/api/v1/auth/me")
    assert me.status_code in [401, 403]


@pytest.mark.asyncio
async def test_login_wrong_password(async_client):
    """Test login with incorrect password."""
    payload = {
        "username": "wrongpass_user",
        "password": "Password123!",
        "email": "wrongpass@example.com",
        "full_name": "WrongPass User",
        "plan_type": "Free",
    }
    r = await async_client.post("/api/v1/auth/signup", json=payload)
    assert r.status_code == 201

    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": "BadPassword"}
    )
    assert login.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(async_client):
    """Test login for non-existent user."""
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_user", "password": "SomePassword123!"}
    )
    assert login.status_code == 401
