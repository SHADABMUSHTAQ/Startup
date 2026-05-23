# Complete System Architecture and Detection Deep Dive

This document consolidates the two previous walkthroughs into one place:
- full system architecture and file relationships
- SIEM / FBR / PECA detection pipeline and telemetry inventory

## 1. Top-Level Architecture

```text
[Frontend: Startup-main]
  -> React UI, routing, auth store, API client
  -> talks to backend over HTTP and WebSocket

[Edge / Deployment]
  -> Nginx reverse proxy
  -> production compose isolates MongoDB and Redis on internal network only

[Backend API: Startup-backend]
  -> FastAPI entry point in app/main.py
  -> JWT auth, CSRF handling, proxy trust boundary
  -> WebSocket bridge for real-time alerts
  -> ingestion endpoints, alert queries, threat intel, uploads, compliance

[Workers]
  -> SIEM worker: detection and correlation
  -> PECA worker: signed forensic logging
  -> FBR worker: encrypted compliance logging
  -> detection / threat intel worker: updates malicious IP knowledge

[Data Layer]
  -> MongoDB for durable records
  -> Redis for streams, pub/sub, cooldowns, bans, correlation windows, rate limits
```

## 2. Backend File Map

### Entry point and core services

- `app/main.py`
  - creates the FastAPI app
  - attaches middleware such as CORS, proxy trust, memory guard, rate limiting
  - mounts routers
  - starts Redis Pub/Sub listeners for alert fanout and threat intel updates
  - bridges Redis messages to tenant WebSocket connections

- `app/database.py`
  - manages the async MongoDB client
  - exposes `db_manager` and helpers for collections
  - is the common persistence layer for workers and routes

- `app/config/config.py`
  - central environment and settings loader
  - supplies database and Redis connection values and other runtime settings

### Ingestion routes

- `app/routes/ingest_pulse.py`
  - signed agent ingestion endpoint
  - validates payload structure and timestamp integrity
  - checks Redis banned-IP sets before parsing the body fully
  - applies tenant rate limits and body-size limits
  - queues validated events into Redis Streams

- `app/routes/ingestion.py`
  - bulk ingestion route for raw logs
  - pushes incoming logs into `raw_logs_queue`
  - uses tenant rate limiting and avoids direct DB writes

### Detection and alert routes

- `app/routes/alerts.py`
  - tenant-isolated alert listing and status updates
  - queries `security_alerts` in MongoDB
  - serializes legacy and new alert formats for the frontend

- `app/routes/threat_intel.py`
  - threat intel lookup and learned-IP management
  - feeds the malicious IP cache used by detection logic

- `app/routes/logs.py`, `app/routes/compliance.py`, `app/routes/export.py`, `app/routes/upload.py`
  - read paths and operational workflows used by the dashboard and compliance screens

### SIEM and shared utilities

- `app/utils/siem_logic.py`
  - core SIEM engine
  - regex rules, event-ID rules, phishing scoring, whitelist checks
  - cooldown state is stored in Redis so alerts do not spam after restarts
  - boots malicious IPs from MongoDB into an in-memory cache

- `app/utils/agent_crypto.py`
  - agent signature and timestamp helpers
  - used by ingestion validation

- `app/utils/tenant_cache.py`
  - tenant plan / policy helpers used by the workers and routes

- `app/utils/observability.py`
  - Redis-based counters and lightweight operational telemetry helpers

### Workers

- `app/workers/siem_worker.py`
  - consumes `raw_logs_queue` with a Redis consumer group
  - normalizes logs and enriches them with event-ID meaning
  - runs SIEMEngine and CorrelationEngine
  - persists alerts and publishes them to Redis Pub/Sub
  - handles stale messages and DLQ quarantine

- `app/workers/peca_worker.py`
  - forensic signing worker
  - stores deterministic signed payloads for immutable verification

- `app/workers/fbr_worker.py`
  - compliance worker for field encryption and protected storage

- `app/workers/detection_worker.py`
  - threat-intel update worker / support process for malicious IP updates

### Frontend files

- `src/App.jsx`
  - root routing and route protection wiring

- `src/api/apiClient.js`
  - axios client with cookie support, CSRF header injection, and 401 handling

- `src/store/authStore.js`
  - client session, token, and CSRF state

- `src/assets/Pages/*`
  - dashboard, login, pricing, payment, auditor, and related screens

- `src/assets/Components/*`
  - navigation, logs, alerts, network map, footer, hero, and other UI pieces

## 3. Data Flow Summary

### Ingestion path

```text
Agent
  -> /api/v1/ingest/pulse
  -> banned-IP check
  -> rate limit check
  -> schema / signature / timestamp validation
  -> Redis Stream raw_logs_queue
```

### Detection path

```text
raw_logs_queue
  -> siem_worker.py
  -> SIEMEngine rule evaluation
  -> CorrelationEngine stateful checks
  -> MongoDB security_alerts
  -> Redis Pub/Sub security_alerts
  -> main.py WebSocket bridge
  -> Frontend dashboard
```

### Forensics and compliance paths

```text
raw_logs_queue
  -> peca_worker.py
  -> signed forensic record in MongoDB

raw_logs_queue
  -> fbr_worker.py
  -> encrypted compliance record in MongoDB
```

## 4. SIEM Detection Pipeline

### Stage 1: API perimeter

The earliest controls happen in `app/routes/ingest_pulse.py`:
- reject banned IPs before parsing the full body
- apply a 300 requests/second limiter
- apply tenant throttle checks
- reject oversized or malformed payloads
- validate signed agent payloads and timestamp drift

This means bad traffic is stopped before it can fill queues or trigger worker load.

### Stage 2: stream consumption

`app/workers/siem_worker.py` reads from Redis Streams using a consumer group:
- reads batches from `raw_logs_queue`
- reclaims stale messages
- moves poison pills to `raw_logs_queue_dlq`
- normalizes timestamps and event IDs
- loads the current dynamic config on a refresh cycle

### Stage 3: SIEM engine

`app/utils/siem_logic.py` contains the detection logic:
- service-account and IP whitelists
- event-ID driven alerts
- regex-driven detections from config
- phishing scoring
- cooldowns stored in Redis
- max-alerts-per-log protection

The engine intentionally supports hot reload of rules so detection can change without a full restart.

### Stage 4: correlation engine

The correlation layer turns single events into attack narratives:
- spray detection over a 2 hour window
- impossible travel over a 12 hour window
- privilege escalation tracking
- threat-intel enrichment using learned malicious IPs

When a correlation rule hits, the worker can:
- elevate severity
- write to MongoDB
- publish to Redis Pub/Sub
- add the source IP to the banned-IP set
- trigger auto-revocation workflows

### Stage 5: fanout

`app/main.py` listens on `security_alerts` and broadcasts them to the right tenant WebSocket connections. The frontend receives the message and updates the dashboard in real time.

## 5. Telemetry Inventory

### Ingestion telemetry

Collected at the perimeter in `app/routes/ingest_pulse.py`:
- HTTP 200 accepted and queued
- HTTP 403 banned IP rejected
- HTTP 429 rate-limited request
- HTTP 401 invalid signature or timestamp drift
- HTTP 413 payload too large
- HTTP 400 / 422 malformed payload or schema failure
- payload size
- events per request
- source IP distribution
- event-ID distribution
- agent version distribution

### Worker telemetry

Collected in `app/workers/siem_worker.py`:
- Redis stream batch sizes
- JSON parse failures
- DLQ ejections
- tenant plan distribution
- stale message reclaims
- threat-intel match counts
- bouncer suppression counts
- MongoDB insert success and failure counts

### SIEM telemetry

Collected in `app/utils/siem_logic.py` and the worker:
- rule evaluations
- rule matches
- rule cooldown hits
- whitelist suppressions
- phishing signal types
- phishing scores
- event-ID mappings resolved
- alerts created by severity

### Correlation telemetry

Tracked through Redis state and alert output:
- spray window growth
- impossible travel calculations
- privilege escalation triggers
- severity elevation events
- SOAR revocation attempts
- banned-IP additions

### Persistence telemetry

From MongoDB and Redis writes:
- `security_alerts` inserts
- `logs` inserts
- PECA signed forensic inserts
- FBR encrypted compliance inserts
- DLQ insertions
- Redis Pub/Sub publications
- Redis cooldown keys
- Redis ban-set mutations

### Operational telemetry

From the runtime and containers:
- FastAPI / Uvicorn logs
- worker logs
- Nginx access and error logs
- MongoDB and Redis health checks
- queue depth and pending stream entries

## 6. Main Data Stores

### MongoDB collections

- `security_alerts`
  - SIEM alert records
  - tenant-scoped and queryable by severity / status

- `logs`
  - raw stored logs and audit copies

- `peca_forensic_logs`
  - signed forensic records for immutable verification

- `fbr_pos_logs`
  - encrypted compliance records

- `dead_letter_logs`
  - poison-pill quarantine storage

- `threat_intel_learned_ips`
  - cached malicious IP knowledge

- `analysis_results`
  - upload and manual-analysis outputs

### Redis keys and channels

- `raw_logs_queue`
  - primary stream for all raw log ingestion

- `raw_logs_queue_dlq`
  - dead-letter queue for malformed or unrecoverable entries

- `warsoc:banned_ips:{tenant_id}`
  - tenant-specific banned IP set

- `warsoc:throttle:tenant:{tenant_id}`
  - tenant request counter for minute-level throttling

- `warsoc:siem_cooldown:{rule}:{ip}:{event_type}`
  - rule-level cooldown protection

- `warsoc:spray_window:{tenant_id}:{ip}`
  - stateful spray-detection window

- `warsoc:travel_window:{tenant_id}:{user}`
  - stateful travel-detection window

- `security_alerts`
  - pub/sub channel for alert broadcast

- `threat_intel_updates`
  - pub/sub channel for malicious-IP updates

## 7. PECA and FBR in the Pipeline

### PECA

PECA is the signed forensic path:
- receives selected forensic events
- canonicalizes the payload
- signs it with RSA PSS SHA-256
- stores the signed payload in MongoDB
- supports offline verification later

Telemetry for PECA is mostly about integrity and write success:
- signed payload present
- signature algorithm used
- verification result
- record retention metadata

### FBR

FBR is the encrypted compliance path:
- selects compliance-relevant event IDs
- encrypts sensitive fields such as message and raw_event
- stores only encrypted values at rest
- keeps TTL / retention metadata for cleanup

Telemetry for FBR is mostly about encryption and retention:
- routing correctness
- encryption success
- encrypted field coverage
- write latency
- retention expiry metadata

## 8. Frontend Relationship

The frontend talks to the backend through the axios client in `src/api/apiClient.js`:
- sends cookies with `withCredentials: true`
- injects CSRF tokens for mutating requests
- logs out on unexpected 401 responses
- uses the auth store for session state

`src/App.jsx` routes the user to:
- home
- login
- pricing
- payment
- dashboard
- auditor dashboard

The dashboard consumes:
- alerts
- log feeds
- WebSocket updates
- tenant-scoped backend APIs

## 9. What Is Production-Hardened Right Now

- banned IPs are enforced before queueing
- proxy trust is restricted to the internal reverse proxy
- MongoDB and Redis are not exposed on public host ports in production compose
- detection rules are hot-reloadable
- SIEM cooldowns are Redis-backed
- stale stream entries are reclaimed
- poison messages are isolated into a DLQ

## 10. Short Version

If you want the shortest possible mental model:

```text
Agent logs in
  -> backend validates and queues them
  -> SIEM worker detects attacks
  -> correlation upgrades severity
  -> MongoDB stores alerts
  -> Redis broadcasts alerts
  -> frontend shows them in real time

PECA signs forensic records
FBR encrypts compliance records
Redis and MongoDB hold all state
Nginx is the only public entry point
```
