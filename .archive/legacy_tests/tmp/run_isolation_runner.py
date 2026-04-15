import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27018")
DB_NAME = os.environ.get("MONGODB_DB_NAME", "siem_project")

async def run_isolation_check():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    tenant_a = "TENANT_A_ISOLATION_TEST"
    tenant_b = "TENANT_B_ISOLATION_TEST"

    # cleanup previous
    await db["logs"].delete_many({"tenant_id": {"$in": [tenant_a, tenant_b]}})
    await db["security_alerts"].delete_many({"tenant_id": {"$in": [tenant_a, tenant_b]}})
    await db["peca_forensic_logs"].delete_many({"tenant_id": {"$in": [tenant_a, tenant_b]}})

    # seed
    await db["logs"].insert_many([
        {"tenant_id": tenant_a, "message": "A data", "event_id": 111},
        {"tenant_id": tenant_b, "message": "B data", "event_id": 222}
    ])
    await db["security_alerts"].insert_many([
        {"tenant_id": tenant_a, "title": "Alert A"},
        {"tenant_id": tenant_b, "title": "Alert B"}
    ])
    await db["peca_forensic_logs"].insert_many([
        {"tenant_id": tenant_a, "digital_signature": "SIG_A", "event_id": 333},
        {"tenant_id": tenant_b, "digital_signature": "SIG_B", "event_id": 444}
    ])

    # query as tenant_a
    logs = await db["logs"].find({"tenant_id": tenant_a}).to_list(100)
    alerts = await db["security_alerts"].find({"tenant_id": tenant_a}).to_list(100)
    forensics = await db["peca_forensic_logs"].find({"tenant_id": tenant_a}).to_list(100)

    failures = 0
    for log in logs:
        if log.get("tenant_id") == tenant_b:
            print("❌ FATAL: Privacy Breach in Logs Collection!")
            failures += 1
    for alert in alerts:
        if alert.get("tenant_id") == tenant_b:
            print("❌ FATAL: Privacy Breach in Security Alerts Collection!")
            failures += 1
    for record in forensics:
        if record.get("tenant_id") == tenant_b:
            print("❌ FATAL: Privacy Breach in PECA Vaults!")
            failures += 1

    if len(logs) == 1 and len(alerts) == 1 and len(forensics) == 1 and failures == 0:
        print("\n✅ ISOLATION CHECK PASSED: zero cross-tenant leakage.")
        ret = 0
    else:
        print(f"\n❌ ISOLATION CHECK FAILED: Found {failures} breaches or incorrect counts.")
        ret = 1

    # cleanup
    await db["logs"].delete_many({"tenant_id": {"$in": [tenant_a, tenant_b]}})
    await db["security_alerts"].delete_many({"tenant_id": {"$in": [tenant_a, tenant_b]}})
    await db["peca_forensic_logs"].delete_many({"tenant_id": {"$in": [tenant_a, tenant_b]}})
    client.close()
    return ret

if __name__ == '__main__':
    rc = asyncio.run(run_isolation_check())
    raise SystemExit(rc)
