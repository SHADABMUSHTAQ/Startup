#!/usr/bin/env python3
"""
Create test accounts for security testing
"""

import asyncio
import bcrypt
from pymongo import AsyncMongoClient
from datetime import datetime, timezone, timedelta

async def create_test_accounts():
    """Create agent and user test accounts"""

    # MongoDB credentials from docker-compose
    mongo_url = "mongodb://warsoc_admin:W4rS0c_M0ng0_S3cur3_2026!@localhost:27017/siem_project?authSource=admin"
    client = AsyncMongoClient(mongo_url)
    db = client["siem_project"]

    # Password: test123
    password_hash = bcrypt.hashpw("test123".encode(), bcrypt.gensalt()).decode()

    # Create agent account (for log ingestion)
    agent = {
        "agent_id": "agent_windows_01",
        "tenant_id": "tenant_1",
        "approved": True,
        "agent_type": "windows",
        "version": "1.0",
        "created_at": datetime.now(timezone.utc)
    }

    # Create admin user account
    user = {
        "email": "admin@warsoc.io",
        "password_hash": password_hash,
        "tenant_id": "tenant_1",
        "subscription_plan": "Enterprise",
        "roles": ["admin"],
        "created_at": datetime.now(timezone.utc)
    }

    # Create attacker user account (low privilege)
    attacker = {
        "email": "user@warsoc.io",
        "password_hash": password_hash,
        "tenant_id": "tenant_1",
        "subscription_plan": "Basic",
        "roles": ["user"],
        "created_at": datetime.now(timezone.utc)
    }

    try:
        # Create tenant first
        tenant = {
            "_id": "tenant_1",
            "name": "Test Tenant",
            "plan": "Enterprise",
            "created_at": datetime.now(timezone.utc)
        }
        await db.tenants.insert_one(tenant)
        print("[OK] Created tenant")
    except Exception as e:
        print(f"[INFO] Tenant already exists")

    try:
        await db.agents.insert_one(agent)
        print("[OK] Created agent account")
    except Exception as e:
        print(f"[INFO] Agent exists")

    try:
        await db.users.insert_one(user)
        print("[OK] Created admin user")
    except Exception as e:
        print(f"[INFO] Admin exists")

    try:
        await db.users.insert_one(attacker)
        print("[OK] Created test user")
    except Exception as e:
        print(f"[INFO] Test user exists")

    await client.close()

asyncio.run(create_test_accounts())
