import asyncio
import traceback
from fastapi.testclient import TestClient
from app.main import app
import httpx
import os
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.routes.auth import verify_agent_token
from app.utils.rate_limiter import redis_ingest_rate_limit

private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")


def mock_verify_agent_token():
    return {'tenant_id': 'tenant-test', 'agent_id': 'agent-test', 'public_key': public_key}

async def mock_redis_ingest_rate_limit():
    pass

app.dependency_overrides[verify_agent_token] = mock_verify_agent_token
app.dependency_overrides[redis_ingest_rate_limit] = mock_redis_ingest_rate_limit

class MockPipeline:
    def __init__(self, *args, **kwargs):
        pass
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    async def xadd(self, *args, **kwargs):
        pass
    async def execute(self):
        pass

class MockRedis:
    async def set(self, *args, **kwargs):
        return True

    def pipeline(self, transaction=True):
        return MockPipeline()

app.state.redis = MockRedis()

client = TestClient(app)

payload = {
  'nonce': 'fbr-test-nonce-1234567890',
  'timestamp': time.time(),
  'payload': [
    {
      'event_id': 'FBR-INV-DEL', 
      'event_uid': 'unique-event-uuid-1234',
      'invoice_id': 'INV-2026-0001',
      'timestamp': '2026-07-02T12:00:00Z',
      'actor': 'pos_user_1',
      'source_system': 'RetailBranch_42',
      'reason': 'Customer requested refund',
      'before_hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'after_hash': 'cf23df2207d99a74fbe169e3eba035e633b65d94c2f6f7f2e7d5b6b95f20e31a',
      'metadata': {
        'terminal_id': 'T-01'
      }
    }
  ]
}

try:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    response = client.post(
        '/api/v1/fbr/pos/ingest',
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-WarSOC-Signature": private_key.sign(body).hex(),
        },
    )
    print(response.status_code)
    print(response.json())
except Exception as e:
    traceback.print_exc()
