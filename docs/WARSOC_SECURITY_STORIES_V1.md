# WarSOC Security Stories V1

**Document status:** Engineering candidate contract
**As-of date:** 2026-09-04
**Feature flag:** `SECURITY_STORIES_ENABLED=false` by default
**Customer/production status:** Disabled; not a current capability claim

## 1. Purpose

Security Stories correlate a small set of related WarSOC observations into a
bounded, tenant-scoped operator view. A story helps an analyst understand a
sequence such as repeated remote login failures followed by access and
persistence.

A Security Story is a mutable operational interpretation. It is not canonical
evidence, a PECA/FBR evidence object, a replacement for a WarSOC incident, or a
new detection authority. Source events, detections, incidents, custody records
and archive objects remain independent and unchanged.

## 2. Non-Negotiable Boundaries

1. Canonical ingestion, SIEM, PECA, FBR, incidents and Azure archival must
   continue if Security Story projection fails.
2. Every query, ledger identity and story identity is tenant-scoped. Tenant
   identity comes from authenticated backend state, never a request parameter.
3. A story references bounded source IDs; it does not copy raw event payloads.
4. Wazuh shadow observations are not actionable story input. Only a candidate
   admitted through WarSOC policy and projected into a WarSOC incident may
   contribute as that incident.
5. Firewall egress requires authenticated network-relay evidence. Windows
   Events 5156/5157 and blocked firewall traffic cannot prove permitted egress.
6. Medium-confidence correlations begin as `CANDIDATE`; high-confidence
   correlations begin as `OPEN`.
7. The customer-facing detection source remains `WarSOC`.
8. Enabling stories does not enable the network relay, Wazuh primary mode or
   Windows Server monitoring.

## 3. End-to-End Flow

```text
signed endpoint or relay telemetry
        -> canonical source envelope and normal Redis dispatch
        -> SIEM / PECA / FBR continue independently
        -> security_story_group reads new raw events
        -> normalized bounded story signal
        -> story_signal_ledger
        -> leased Security Story worker
        -> deterministic correlation
        -> security_stories projection
        -> tenant-scoped API
```

Actionable WarSOC detections have a second handoff:

```text
canonical detection -> WarSOC incident occurrence marked PENDING
                    -> durable story signal
                    -> occurrence marked ENQUEUED
```

The worker periodically recovers `PENDING` incident handoffs. A story failure
therefore cannot roll back or suppress the canonical incident.

On first enablement, `security_story_group` is created at Redis stream position
`$`. Historical raw-stream backlog is not replayed automatically.

## 4. Persistence Contracts

### 4.1 `story_signal_ledger`

- Unique identity: `(tenant_id, source_type, source_uid)`.
- Accepted source types: `event` and `incident`.
- States: `PENDING`, `PROCESSING`, `RETRY`, `PROCESSED`, `FAILED`.
- A 60-second lease makes an interrupted record reclaimable.
- Exponential retry is bounded by `SECURITY_STORY_MAX_ATTEMPTS`.
- Event signals receive short delayed rechecks so a later observation can close
  an ordered correlation without unbounded polling.
- TTL is controlled by `SECURITY_STORY_SIGNAL_RETENTION_DAYS` and defaults to
  30 days. The ledger is processing context, not evidence.

### 4.2 `security_stories`

- Unique identity: `(tenant_id, story_id)`.
- Workflow states: `CANDIDATE`, `OPEN`, `ACKNOWLEDGED`, `CLOSED`.
- Optimistic `version` prevents lost operator updates.
- A closed story receiving new projected activity remains closed and is marked
  with `has_new_activity`; the worker does not silently reopen analyst work.
- A candidate can promote to `OPEN` when later evidence raises confidence to
  high.
- Evidence, incident and network references are bounded by
  `SECURITY_STORY_MAX_REFERENCES`, default 100.
- Timeline and workflow history are each bounded to 50 entries; assets are
  bounded to 20.
- Technical severity/confidence are separate from asset-derived business
  impact and attention priority.

### 4.3 `asset_ip_bindings`

- Unique identity: `(tenant_id, asset_id, ip_address)`.
- Only valid private, non-loopback Windows asset addresses are recorded.
- Authentication/network observations are not used to self-assert the endpoint
  address being resolved.
- Resolution requires one unambiguous asset binding fresh within one hour.
- Stale or ambiguous bindings fail closed and do not create a movement or
  firewall-enrichment story.
- Bindings use the same configurable processing-context TTL as the signal
  ledger.

## 5. V1 Correlation Families

| Story | Required ordered evidence | Window and confidence | Rejection boundary |
|---|---|---|---|
| `SERVER_ACCOUNT_COMPROMISE` | At least 10 failed remote logons, then a successful remote logon for the same tenant, server, human account and source IP | Failures within 10 minutes before success; high confidence. A matching privileged session may enrich the story. | Wrong order, local logons, system/machine accounts, mismatched source/account/server or cross-tenant data |
| `SERVER_COMPROMISE_PERSISTENCE` | Successful remote server login, actionable suspicious execution by the same account, then service or scheduled-task persistence | Within 20 minutes; exact logon-session continuity is high, bounded chronology without it is medium | Missing actionable execution, wrong asset/account/order or cross-tenant data |
| `SERVER_ANTI_FORENSICS` | Actionable suspicious server activity, then Event 1102 or 4719 | Within 30 minutes; exact session is high, same-server chronology is medium | Anti-forensics without prior actionable activity or wrong tenant/server/order |
| `WORKSTATION_TO_SERVER_MOVEMENT` | Actionable workstation execution, fresh workstation-IP binding, remote server login from that IP, then actionable server execution/persistence for the same account | Workstation activity within 15 minutes before login and server activity within 20 minutes; high confidence | Public/stale/ambiguous IP, missing account continuity, wrong order or cross-tenant data |
| `EXTERNAL_ACTIVITY_AFTER_SERVER_COMPROMISE` | Existing active server story, then authenticated relay evidence of an allowed private-source to public-destination connection from that server | Parent story within 30 minutes; inherits parent confidence/severity | Windows 5156/5157, blocked traffic, non-network source, private destination, stale/ambiguous IP or cross-tenant data |

Remote logon types are `3` and `10`. These stories describe possible attack
sequences; they do not prove attribution or compromise on their own.

## 6. API and RBAC

All routes require a user JWT and authenticated tenant context.

| Method and route | Roles | Contract |
|---|---|---|
| `GET /api/v1/security-stories/status` | admin, manager, analyst | Reports flag state and WarSOC policy; remains readable while disabled |
| `GET /api/v1/security-stories/summary` | admin, manager, analyst | Tenant-scoped 24-hour/open/candidate aggregates using one bounded `$facet` query |
| `GET /api/v1/security-stories` | admin, manager, analyst | Bounded cursor list with status, priority, type and asset filters |
| `GET /api/v1/security-stories/{story_id}` | admin, manager, analyst | Tenant-scoped detail |
| `PATCH /api/v1/security-stories/{story_id}/status` | admin, manager | `OPEN`, `ACKNOWLEDGED` or `CLOSED`, notes up to 2,000 characters and required expected version |

Except for `/status`, disabled feature access returns 404. Candidate and closed
stories are excluded from the default list unless explicitly requested.

## 7. Failure and Capacity Behavior

- Redis processing uses an independent consumer group and pending-entry reclaim.
- Mongo processing uses durable unique records, leases and bounded retries.
- Invalid source payloads are acknowledged and counted; transient persistence
  errors remain pending for retry.
- Story worker health and invalid-source counters are exposed in metrics only
  when the feature is required.
- Stream trimming requires the story group only while the feature is enabled.
- Every database read has a tenant, time, type, asset or indexed work-queue
  boundary. Projection arrays cannot grow without limit.

## 8. Enablement and Acceptance Gate

Do not enable the feature until all of the following are recorded against one
release candidate:

1. Python compilation and API inventory generation pass.
2. Focused Security Story tests pass.
3. The complete maintained backend suite passes.
4. Bandit high-severity scan, dependency audit, dependency consistency and diff
   hygiene pass or have an explicitly accepted pre-existing exception.
5. Mongo indexes are created successfully on an isolated runtime stack.
6. Redis outage/recovery and expired Mongo lease recovery are demonstrated.
7. Tenant/RBAC negative tests and duplicate/replay tests pass.
8. Each positive story family and its principal rejection cases pass with
   production-shaped synthetic data.
9. When relay enrichment is evaluated, it uses an entitled authenticated relay
   and confirms blocked traffic and Windows 5156/5157 do not qualify.
10. Rollback is proven by setting `SECURITY_STORIES_ENABLED=false` and
    recreating the unified worker/API without altering canonical evidence.

Current engineering evidence is 27 focused tests passing. The complete suite
and security gate have not yet been recorded for this candidate, so production
must remain disabled.

## 9. Source Map

| Concern | Source |
|---|---|
| Correlation and persistence | `app/utils/security_stories.py` |
| Worker and Redis handoff | `app/workers/security_story_worker.py` |
| API and RBAC | `app/routes/security_stories.py`, `app/schemas/security_stories.py` |
| Incident handoff | `app/utils/security_incidents.py` |
| Indexes | `app/db/init_db.py` |
| Worker supervision and retention | `app/workers/unified_worker.py`, `app/workers/stream_retention.py` |
| Metrics | `app/routes/metrics.py` |
| Tests | `tests/test_security_stories.py` |
| Authorization intent and generated inventory | `docs/WARSOC_AUTHORIZATION_POLICY.json`, `docs/generated/WARSOC_API_SECURITY_INVENTORY.json` |
