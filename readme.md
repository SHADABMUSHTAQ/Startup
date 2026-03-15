WarSOC: Enterprise SIEM and Compliance Engine
Atomic Backend and Real-Time Pipeline (NIC Karachi MVP) [cite: 2026-02-14, 2026-02-20]
1. The Real-Time Command Center
To run the full pipeline, you must open four separate terminals in this exact order: [cite: 2026-02-26]

Backbone: Run 'redis-server' [cite: 2026-02-18]

API Gateway: Run 'uvicorn app.main:app --reload --port 8000' [cite: 2026-02-26]

Analysis Engine: Run 'python worker.py' (Processes logs from Redis to MongoDB) [cite: 2026-02-26]

Security Agent: Run 'python windows_agent.py' (Streams live Windows Events) [cite: 2026-02-26]

2. Project Architecture and Mapping (Source of Truth)
FRONTEND RULE: Use these exact keys for your React components. Do not rename them. [cite: 2026-02-18, 2026-02-26]

MongoDB Collection: logs (Main Feed) [cite: 2026-02-26]
Database Key: timestamp | React Variable: log.timestamp | Format: ISO String [cite: 2026-02-26]

Database Key: source_ip | React Variable: log.source_ip | Format: String (IPv4) [cite: 2026-02-26]

Database Key: event_id | React Variable: log.event_id | Format: Integer (e.g., 4624) [cite: 2026-02-26]

Database Key: message | React Variable: log.message | Format: String (Log summary) [cite: 2026-02-26]

Database Key: tenant_id | React Variable: log.tenant_id | Format: String (Identity) [cite: 2026-02-27]

MongoDB Collection: security_alerts (Threat Center) [cite: 2026-02-26]
Database Key: severity | React Variable: alert.severity | Use for color (RED = CRITICAL) [cite: 2026-02-26]

Database Key: title | React Variable: alert.title | Threat description (e.g., Brute Force) [cite: 2026-02-26]

Database Key: mitre | React Variable: alert.mitre | MITRE ATT&CK Mapping (e.g., T1110) [cite: 2026-02-26]

3. API Integration Cheat Sheet (v1)
Base URL: http://127.0.0.1:8000/api/v1 [cite: 2026-02-26]

Auth: POST /auth/token (Returns JWT and tenant_id) [cite: 2026-02-18]

Live Logs: GET /ingest/logs?limit=10 (Secure tenant-isolated fetch) [cite: 2026-02-26]

Active Mitigation: POST /mitigate (Payload: {"ip": "x.x.x.x", "reason": "..."}) [cite: 2026-02-27]

Firewall Revoke: POST /revoke (Restore access to a specific IP) [cite: 2026-02-27]

4. Environment and Deployment Security
Before pushing to GitHub, ensure your .env file is in the root: [cite: 2026-02-20, 2026-02-26]

TENANT_ID=WARSOC_898F3395
MONGODB_URI=mongodb://localhost:27017
REDIS_URL=redis://localhost:6379
SECRET_KEY=yoursecretkeyhere

5. Common Vibe Coding Fixes
Invalid Date in UI: Stop multiplying by 1000. Use: new Date(log.timestamp).toLocaleTimeString() [cite: 2026-02-26]

Unknown Host: Change log.hostname to log.source_ip [cite: 2026-02-26]

Empty Tables: Ensure the user logged into the dashboard has the exact same tenant_id as the Agent and the logs in MongoDB [cite: 2026-02-20, 2026-02-26, 2026-02-27]

AI Prompt for Frontend Developer
"I am building the WarSOC frontend. My backend is a FastAPI SIEM using a MongoDB collection called 'logs' with these keys: timestamp, source_ip, event_id, and message. The architecture uses B2B tenant isolation via tenant_id. Please generate a React table that fetches data from /api/v1/ingest/logs and maps these keys correctly while handling the ISO timestamp string." [cite: 2026-02-18, 2026-02-26]