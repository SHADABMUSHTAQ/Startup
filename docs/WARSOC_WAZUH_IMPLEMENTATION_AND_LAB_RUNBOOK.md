# WarSOC Wazuh Implementation and Two-Laptop Lab Runbook

**Status:** Controlled two-host shadow active as of 2026-08-28; primary promotion, broad rule coverage, HA and firewall projection remain disabled

**Last updated:** 2026-08-28

## 1. Non-Negotiable Boundary

WarSOC remains the system of record. Wazuh is a replaceable generic SIEM
detection engine. It cannot enroll endpoints, choose a tenant, read canonical
evidence, create FBR or PECA evidence, create customer incidents directly,
change retention, block an address, or expose a customer dashboard.

The two machines have different roles:

| Machine | Role | Components |
|---|---|---|
| WarSOC development/backend machine (Compute A) | Trust and evidence owner | Canonical Mongo SIEM, projector, encrypted dispatch outbox, dispatcher, candidate API, validator and shadow ledger |
| Colleague's Wazuh laptop (Compute B) | Isolated detector lab | Wazuh 4.14.7 manager/indexer/dashboard, private JSON listener, WarSOC bridge, encrypted local spools and `alerts.json` tailer |

Do not install Wazuh on Compute A. Do not give Compute B MongoDB, Redis, FBR,
PECA, tenant-admin, archive, or incident credentials.

## 2. Implemented Data Flow

```text
signed Windows event or relay-attested network event
  -> WarSOC authenticated ingestion
  -> siem_cold_vault canonical persistence
  -> existing WarSOC SIEM remains unchanged
  -> approved-rule projector
  -> encrypted detection_dispatch_outbox
  -> mTLS + HMAC request to Compute B
  -> encrypted SQLite input spool and idempotent receipt
  -> loopback TCP 15140 JSON line to Wazuh
  -> approved Wazuh rule
  -> /var/ossec/logs/alerts/alerts.json
  -> rotation-aware tailer
  -> encrypted SQLite candidate spool
  -> signed health/counter heartbeat
  -> mTLS + HMAC return to Compute A
  -> dispatch, tenant, evidence and registry validation
  -> detection_engine_observations shadow ledger
```

FBR and PECA collections are not projector inputs. A Wazuh outage cannot prevent
canonical ingest, current WarSOC detection, FBR, PECA, incident processing, or
Azure archival.

## 3. Implemented Components

| Component | Source | Responsibility |
|---|---|---|
| Contracts | `app/wazuh_integration/contracts.py` | Strict versioned input, candidate and receipt schemas; no candidate tenant field |
| Connector security | `app/wazuh_integration/security.py` | HMAC request signing, body hashes, freshness, nonces, correlation HMAC and Fernet helpers |
| Projector | `app/wazuh_integration/projector.py` | Reads only persisted SIEM evidence, checks source assurance and approved registry, minimizes and encrypts |
| Dispatcher | `app/wazuh_integration/dispatcher.py` | Claims, batches, retries, expires and DLQs outbox records over mTLS |
| Dispatch worker | `app/workers/wazuh_dispatch_worker.py` | Runs projector and dispatcher outside the current unified worker |
| Candidate service | `app/wazuh_integration/candidate_service.py` | Resolves trusted tenant/evidence/rule semantics and writes shadow observations |
| Candidate API | `app/wazuh_integration/candidate_api.py` | Private mTLS/HMAC candidate and bridge-health endpoints with Redis replay rejection |
| Bridge configuration | `app/wazuh_integration/bridge_config.py` | Compute-B fail-fast configuration |
| Bridge spool | `app/wazuh_integration/bridge_spool.py` | Encrypted byte/age-bounded SQLite spools, retry scheduling, bounded receipts, counters, health events and digest checkpoints |
| Bridge runtime | `app/wazuh_integration/bridge_runtime.py` | Signed ingress, Wazuh loopback delivery, truncation/rotation-safe tail, signed candidates and signed health |
| Registry validator | `app/wazuh_integration/registry.py` | Enforces reviewed per-source projection fields and rule metadata before seeding or bridge startup |
| Compute-A services | `docker-compose.prod.yml` profile `wazuh-detection` | Disabled dispatcher and candidate API services |
| Compute-B service | `docker-compose.wazuh-bridge.yml` | Disabled-by-operator isolated bridge deployment |
| Canary rule | `deploy/wazuh/rules/warsoc_canary_rules.xml` | Matches only signed Windows 4688 events for `whoami.exe` |
| Canary registry | `deploy/wazuh/registry/warsoc-lab-canary-v1.json` | Pins category, severity, fields, Wazuh level and reviewed ruleset hash |

## 4. Admission Rules

Only these source types can be projected:

1. Windows endpoint events with `signature_verified=true`,
   `source_assurance=agent_signed`, and `telemetry_family=windows`.
2. Network events only when `NETWORK_RELAY_ENABLED=true`, with
   `signature_verified=true`, `source_assurance=relay_attested`,
   `source_type=network_device`, and `telemetry_family=network`.

Unsigned legacy endpoint data, direct syslog, FBR evidence, PECA evidence, POS
invoice contents, packet payloads, arbitrary raw documents, credentials, and
unapproved event IDs are not dispatched.

Every dispatch requires an approved registry record for the exact Wazuh ruleset,
source family and event ID. The registry explicitly maps the minimum normalized
fields Wazuh may receive. Password, credential, token, secret, invoice, card,
payload and similar fields are denied. Common secret assignments in allowed text
are redacted before encryption and dispatch.

Registry JSON is not trusted configuration by itself. Both seeding and Compute-B
startup validate it against a static source-family field catalog. Raw tenant
identity, actor identity, source/destination IP, invoice/POS fields, payloads and
free-form messages are not registry-selectable. Cross-event correlation uses
purpose-separated opaque HMAC fields instead.

## 5. Delivery and Failure States

Dispatch states are `pending`, `in_flight`, `retry`, `delivered`, `expired`,
`rejected`, or `failed`. A deterministic dispatch UID prevents duplicate outbox
records. Retry payloads retain the same identity and become `dispatch_mode=retry`.
Events older than the approved live window go to a terminal DLQ and open a
detection-coverage gap; they are not replayed into live Wazuh correlation.

The Mongo outbox is encrypted and capped at 256 MiB by default. When full, the
projector refuses new external dispatch and records a coverage gap. It does not
drop canonical events or block current WarSOC pipelines.

The Compute-B bridge has separate encrypted input and candidate spools. The
default limits are 512 MiB and 256 MiB. Accepted input is remembered after local
handoff so a repeated request with different bytes is rejected. Candidate spool
saturation stops checkpoint advancement and records a health event.

Retries use bounded exponential backoff. Input records expire at the live event
deadline; candidate records expire after the configured delivery window.
Receipts, nonces and exported health metadata are pruned. Same-inode truncation,
missing rotation and committed-byte digest rollback are detected. Loss and gap
events are signed back to Compute A and create internal coverage-gap records.

## 6. Candidate Trust Rules

Wazuh output is untrusted. Compute A performs all of these checks:

1. mTLS transport and HMAC body signature.
2. Timestamp freshness and one-time nonce.
3. Connector, engine, version and ruleset match.
4. Registry SHA-256 matches the active reviewed connector.
5. Active connector registry entry.
6. Known dispatch UID.
7. Engine detection time falls inside the dispatch live window and delivery age.
8. Tenant and event UID resolved from that dispatch, never from Wazuh.
9. Canonical `siem_cold_vault` evidence still exists.
10. Rule was eligible for the dispatch and is candidate-approved.
11. Engine level, category and MITRE mapping match the registry.
12. Delivery identity and logical candidate fingerprint are unique.

Mismatches are quarantined. Valid results are stored as
`shadow_observation`. They do not create incidents, notifications, or response
actions in this phase.

## 7. Current Test Result

The focused suite is:

```powershell
docker compose -f docker-compose.yml run --rm --no-deps `
  -v "${PWD}:/workspace:ro" -w /workspace api `
  python -m pytest -q `
  tests/test_wazuh_integration_contract.py `
  tests/test_wazuh_projection_candidate.py `
  tests/test_wazuh_bridge_contract.py `
  tests/test_wazuh_health_contract.py `
  tests/test_wazuh_transport_state_machine.py
```

Result recorded on 2026-08-12 after the bridge hardening review and mTLS client
compatibility fix: **32 passed**.

The focused tests prove durable-before-ack bridge admission, request tamper and
replay rejection, idempotent receipts, signed dispatcher responses, bounded
retry/expiry, same-file truncation recovery, candidate time validation, signed
health storage and explicit coverage-gap creation.

Compatibility checks also passed for endpoint event signing, the existing
network relay, production Compose contracts, native detection, tenant/platform
quotas, seven-day SIEM hot retention, immutable archive deletion safeguards,
evidence access scope, incident workflow, the FBR deep dive, and the PECA
11-event deep dive. The final 2026-08-13 maintained release gate records **432
passed, 3 explicitly skipped, and 0 failed** across Wazuh, relay, native
SIEM/FBR/PECA, incidents, signing, storage, retrieval, quotas, security, user
journeys, and backend hardening. This is a
selected release-gate suite, not a claim that every historical test file is
current or that Wazuh is approved as a production-primary detector.

The isolated local live harness additionally proved mutual TLS in both
directions, Wazuh manager receipt, canary rule `100500`, signed candidate return,
manager-outage recovery, bridge-restart recovery, durable retry state and
shadow-only side effects. It rejected replay, tampering, wrong connector
identity, oversized bodies and missing client certificates.

The 2026-08-13 separate two-host run then proved private Tailscale binding,
bidirectional mTLS, durable receipt, rule 100500, signed candidate return,
two-tenant lineage isolation, manager/bridge/candidate-API outage recovery and
fail-closed live-window expiry. The adjacent maintained Docker regression gate
recorded **233 passed**. Real spool saturation under load, explicit host-firewall
rules, ruleset upgrade/rollback and production detection quality remain open.

## 8. Compute-B Preparation

On the colleague's Wazuh laptop only:

1. Confirm Wazuh 4.14.7 manager, indexer, and dashboard are running.
2. Keep all existing Wazuh host bindings on `127.0.0.1`.
3. Identify the Wazuh Compose network, log volume, and one unused IP in that
   network.
4. Review the private listener IP and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\prepare_wazuh_lab_integration.ps1 `
  -LabRoot "C:\Users\DELL\wazuh-docker\single-node" `
  -BridgeContainerIp "REPLACE_WITH_RESERVED_BRIDGE_IP" `
  -ComposeProjectName "warsoc-wazuh-4147" `
  -Apply
```

The script backs up the host-mounted manager configuration and local rules, adds
TCP 15140 with an exact bridge-IP allowlist, installs rule 100500, runs
`wazuh-analysisd -t`, requires a successful `wazuh-logtest`, recreates only the
manager, and prints hashes. Updating the host-mounted configuration is required;
editing only `/var/ossec/etc/ossec.conf` inside the running container is not
persistent across recreation.

Do not continue if configuration validation or logtest fails.

## 9. mTLS and Bridge Preconditions

Before either optional service starts, create two trust directions:

- Compute-A client certificate trusted by the Compute-B ingress.
- Compute-B client certificate trusted by the Compute-A candidate API.
- Compute-B ingress server certificate trusted by Compute A.
- Compute-A candidate server certificate trusted by Compute B.

Use separate request-signing, candidate-signing, outbox-encryption,
bridge-spool-encryption, and correlation-HMAC secrets. Never commit keys or real
environment files. The `keys/` and `.env.*` paths remain ignored.

Copy `.env.wazuh-bridge.example` to an ignored `.env.wazuh-bridge` on Compute B.
Set the actual Wazuh log volume, Docker network, reserved bridge IP, registry
SHA-256, private Compute-A candidate URL, and certificate paths. Validate the
Compose rendering before starting it:

The bridge Compose includes a one-shot root init service which creates the named
spool directory as UID/GID 1000 with mode `0700`. Do not remove it: without this
step a fresh named volume is root-owned and the non-root bridge cannot open its
SQLite spool.

The Compute-B environment also sets a private Compute-A health URL. It uses the
same B-to-A mTLS identity and candidate-signing secret, but a separate route and
replay namespace. `WAZUH_RULE_REGISTRY_SHA256` must be identical on Compute A
and Compute B and must match the reviewed file bytes.

```powershell
docker compose --env-file .env.wazuh-bridge `
  -f docker-compose.wazuh-bridge.yml config --quiet
```

Do not expose bridge port 9443 publicly. Bind it to the private overlay address
when Compute A is remote; loopback is valid only when an approved private tunnel
forwards the connection locally.

## 10. Compute-A Shadow Preparation

Do not change production until the Compute-B listener, certificates, and private
route are ready. Set `WAZUH_DETECTION_MODE=shadow`, never `primary`. Configure the
exact 4.14.7 engine/ruleset identity, private HTTPS dispatch URL, separate
secrets, mTLS paths, and bounded limits from `.env.example`.

Seed the reviewed connector and rule in dry-run mode first:

```bash
PYTHONPATH=/app python /app/scripts/seed_wazuh_shadow_registry.py \
  --registry /app/deploy/wazuh/registry/warsoc-lab-canary-v1.json \
  --sha256 18f43311a55ddbf168dbe433a820fa00756042d365bf1dd2fb5fbdba1e088406
```

After the dry run is correct, repeat with `--apply`. Start only the optional
profile after configuration validation:

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml \
  --profile wazuh-detection config --quiet

docker compose --env-file .env.prod -f docker-compose.prod.yml \
  --profile wazuh-detection up -d --build \
  wazuh-dispatch-worker wazuh-candidate-api
```

## 11. First Live Canary

Use a non-customer demo tenant with the current signed WarSOC agent. Run
`whoami.exe` normally so Windows produces Event 4688. Acceptance requires one
continuous lineage:

1. Signed 4688 exists in `siem_cold_vault`.
2. One deterministic encrypted outbox record is created.
3. Compute B returns an idempotent dispatch receipt.
4. Wazuh rule 100500 appears once in `alerts.json` with the dispatch UID.
5. Bridge candidate spool persists before its checkpoint advances.
6. Compute A resolves the demo tenant from the dispatch.
7. One `shadow_observation` is stored.
8. No customer incident, FBR record, PECA record, email, or block action is
   created.

Repeat the same request and alert to prove duplicate safety. Then stop Wazuh and
prove WarSOC SIEM, FBR, PECA, incidents, and archive remain healthy while the
outbox retries within its cap.

## 12. Remaining Acceptance Work

Compute-B baseline and private two-host shadow transport are accepted. Wazuh
4.14.7, loopback-only host bindings, the exact bridge-IP listener allowlist,
rule `100500`, configuration validation, Tailscale-only service binding,
bidirectional mTLS, signed requests and responses, cross-tenant lineage, and
manager/bridge/candidate-API recovery passed. Alert-file identity change was
reported and processing resumed. A dispatch older than its bounded live window
expired with signed critical health instead of producing a late detection.

The integration is not production-complete until these artifacts pass:

- explicit bridge and candidate API Windows firewall proof on both hosts;
- physical outbox and both bridge-spool saturation/load behavior (bounded
  refusal and retry behavior currently pass by contract only);
- ruleset upgrade and rollback;
- FBR/PECA/current-SIEM independence during forced Wazuh failure;
- positive, negative, noise, malformed, and boundary corpora for each proposed
  rule family;
- measured shadow precision, recall, latency, and operator usefulness.

Only one reviewed generic SIEM rule family may be promoted at a time. Primary
mode remains blocked by `WAZUH_PRIMARY_APPROVED=false`. Firewall relay enablement
is a separate acceptance decision and is not implied by Wazuh readiness.

## 13. Rollback

Set `WAZUH_DETECTION_MODE=disabled` and stop the two optional Compute-A services.
Stop the Compute-B bridge. Do not delete canonical SIEM, FBR, PECA, incident, or
archive data. Preserve outbox, DLQ, quarantine, shadow observations, bridge
health events, configuration hashes, and acceptance artifacts for review.

The phase-by-phase implementation and remaining-gate ledger is
`docs/WARSOC_WAZUH_FIREWALL_IMPLEMENTATION_LEDGER_2026-08-13.md`.
