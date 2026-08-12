# WarSOC-Wazuh Integration Readiness and Requirements

**Status:** Lab platform accepted; disabled connector foundation implemented and unit-tested; live integration not yet enabled

**Review date:** 2026-08-11

**Applies to:** Generic SIEM detection enrichment only

**Does not change:** WarSOC endpoint collection, tenant isolation, canonical evidence, FBR, PECA, retention, incidents, customer access, or response ownership

## 1. Executive Verdict

The colleague's Wazuh Docker lab is ready to begin controlled WarSOC integration
work. The latest evidence proves that the Wazuh platform is running and its
network exposure is bounded:

- Manager, indexer, and dashboard are running on Wazuh `4.14.7`.
- Host bindings are loopback-only: `127.0.0.1` for manager, indexer, and dashboard.
- `wazuh-analysisd` and the required manager services are running.
- Wazuh analysis queues report zero dropped events.
- The remote-input state reports zero discarded events.
- The generic JSON decoder was exercised successfully with `wazuh-logtest`.

This is not an integration-complete result. WarSOC now has disabled, versioned
input/candidate contracts, a post-persistence projector, an encrypted bounded
Mongo outbox, an mTLS/HMAC dispatcher, a Compute-B bridge with encrypted SQLite
spools, an `alerts.json` tailer, and a tenant-resolving shadow candidate service.
Their focused contract and transport suite passes 23 tests. The components have not yet been
deployed together across the two laptops or proven with live mTLS traffic and a
real signed endpoint event. WarSOC's own SIEM remains the active detector.

## 2. Permanent Ownership Boundary

WarSOC is the system of record. Wazuh is a replaceable, untrusted generic
detection engine.

| Capability | Owner | Wazuh role |
|---|---|---|
| Endpoint enrollment and Ed25519 signing | WarSOC | None |
| Tenant identity and RBAC | WarSOC | No tenant authority |
| Canonical event persistence and chain of custody | WarSOC | No authority |
| Generic SIEM candidate detection | WarSOC currently | Candidate engine |
| FBR invoice/file evidence | WarSOC only | Excluded |
| PECA evidence catalog and control status | WarSOC only | Excluded |
| Incident grouping and customer severity | WarSOC | Supplies candidate evidence only |
| Hot storage, Azure archive, retention, retrieval | WarSOC | Excluded |
| Blocking, active response, or firewall control | WarSOC policy | Disabled in Wazuh |
| Customer dashboard and reports | WarSOC | Hidden implementation detail |

A Wazuh alert is never canonical evidence, a PECA/FBR record, a tenant selector,
an instruction to block an address, or proof that a device authored a log.

## 3. Current Product Scope

The current WarSOC endpoint remains the only endpoint collector. Do not install a
Wazuh endpoint agent on customer machines for this integration.

The approved current path is:

```text
WarSOC Windows Agent
    -> WarSOC authenticated ingestion
    -> canonical WarSOC persistence
    -> current WarSOC SIEM / FBR / PECA consumers
    -> optional minimized detection dispatch
    -> private Wazuh manager
    -> candidate result
    -> WarSOC validation and shadow ledger
    -> optional WarSOC incident candidate
```

The network path remains separate and disabled:

```text
Customer firewall
    -> customer-side WarSOC Relay
    -> WarSOC canonical network evidence
    -> optional minimized Wazuh shadow input
```

Direct pfSense or firewall-to-Wazuh ingestion is not an accepted integration
path. Network relay evidence remains `relay_attested`, not
`device_authenticated`, unless a future device-authentication contract proves
otherwise.

## 4. Required Deployment Topology

The target deployment separates WarSOC from Wazuh:

- **Compute A:** WarSOC API, workers, MongoDB, Redis, current detection, FBR,
  PECA, incidents, and archive pipeline.
- **Compute B:** Wazuh manager and the WarSOC Wazuh ingress/export services.
- Redis must not be exposed or consumed across the host boundary.
- Compute A to Compute B must use a private network or overlay, host firewalls,
  mTLS, and request signing.
- Wazuh manager, enrollment, API, indexer, dashboard, and lab-ingress ports
  must remain private. Loopback binding is valid for the local lab.
- Wazuh must not be placed on the WarSOC production critical path until the
  failure tests pass.

The full indexer/dashboard stack is useful for internal diagnosis, but it is not
automatically required for the WarSOC connector. The manager, durable ingress,
and alert exporter are the integration minimum. The final topology must be sized
from measured event rate, retention, disk, and memory usage.

## 5. Inbound Requirements: WarSOC to Wazuh

The integration must use a durable, bounded dispatch path.

1. WarSOC persists canonical evidence before dispatching anything to Wazuh.
2. A post-persistence projector selects only approved generic SIEM telemetry.
3. The projector writes an encrypted, idempotent `detection_dispatch_outbox`
   record. It does not participate in endpoint acknowledgement and does not
   read FBR or PECA collections.
4. A dispatcher sends versioned `warsoc.detection-input/v1` envelopes to the
   private Wazuh ingress.
5. The envelope is authenticated with mTLS and a signed request containing a
   timestamp, nonce, body hash, connector identity, and signature.
6. The receiver validates schema, size, freshness, replay, source family,
   dispatch UID, and sequence/idempotency before accepting the event.
7. The Wazuh ingress durably accepts the envelope and forwards only a local,
   loopback JSON representation to the manager.
8. Redis is not an unlimited Wazuh backlog. The outbox has byte, age, retry,
   and terminal-expiry limits with explicit coverage-gap records.

The input must contain enough context for an approved rule but must exclude:

- plaintext passwords and secrets;
- packet payloads or PCAP;
- invoice contents and POS `processed_data`;
- unnecessary full user profiles;
- arbitrary raw event documents;
- customer-controlled Wazuh rule IDs or tenant IDs.

Tenant authority is resolved by WarSOC from the server-side dispatch record. A
tenant value returned by Wazuh is never trusted.

## 6. Wazuh Rule and Decoder Requirements

Every rule family requires its own versioned compatibility package:

- approved decoder or honest stock-decoder mapping;
- approved rule XML;
- required telemetry family and fields;
- positive JSONL corpus;
- negative/noise corpus;
- boundary and malformed-input corpus;
- expected decoder, rule ID, severity, category, and MITRE mapping;
- ruleset manifest and SHA-256 hash;
- owner, version, effective date, and rollback version.

The package must be tested with `wazuh-logtest` before it is installed. A parser
match alone is not end-to-end proof. Stock rules may be reused only when the
field mapping preserves the original event meaning. WarSOC must add a minimal
custom decoder/rule when stock semantics would be falsified.

Wazuh generic detection is limited to approved SIEM rule families. It must not
reimplement the FBR or PECA catalogs. Windows events must not trigger unrelated
web-WAF rules, and source-family isolation must be tested for every rule release.

## 7. Outbound Requirements: Wazuh to WarSOC

For v1, `/var/ossec/logs/alerts/alerts.json` is the only authoritative Wazuh
candidate output. The exporter must:

1. Read JSON alerts through a rotation-safe tailer.
2. Drain the rotated file before switching to its replacement.
3. Persist an encrypted checkpoint and spool the candidate durably before
   advancing the checkpoint.
4. Survive process restart, power loss, partial writes, and duplicate delivery.
5. Send candidates to a private WarSOC endpoint using mTLS and a signed request.
6. Preserve connector ID, Wazuh instance, pinned version, ruleset hash, alert ID,
   rule ID, and trigger dispatch UID.
7. Treat a candidate as untrusted until WarSOC validates tenant, evidence
   linkage, rule ownership, freshness, and provenance.

The validator must reject unknown, expired, mixed-tenant, duplicate, unsigned,
or registry-inconsistent candidates. Customer-facing incidents must use WarSOC's
normalized severity and message, not raw Wazuh JSON or raw engine severity.

## 8. Tenant Isolation and Evidence Linkage

- Every stateful correlation key must include a WarSOC tenant-scoped component.
- Manager-wide or global frequency rules are disabled unless partitioning is
  proven.
- A candidate must resolve to a known WarSOC `dispatch_uid` and canonical event.
- Multi-event lineage is `complete` only when WarSOC reconstructs every eligible
  contributing event. Otherwise it is explicitly `trigger_only`.
- Candidate deduplication uses stable engine identity plus WarSOC's deterministic
  fingerprint; a new Wazuh alert ID must not create a duplicate logical incident.
- Wazuh has write-only access to the candidate endpoint and no evidence-read
  permission.
- Cross-tenant canary tests run in every connector and ruleset release.

## 9. FBR, PECA, and Firewall Constraints

FBR remains based on validated invoice/application records and configured POS or
database file-integrity telemetry. Wazuh receives no invoice payload and cannot
create FBR evidence.

PECA remains based on WarSOC's entitled 11-control evidence catalog and its
retention/chain-of-custody pipeline. A Wazuh candidate may help generic SIEM
triage but cannot alter PECA control status or evidence.

Firewall integration remains metadata-only and feature-gated. The customer
firewall sends local syslog to the WarSOC Relay, not directly to Wazuh. The relay
must enforce source registration, allowlists, EPS/byte limits, bounded encrypted
evidence/control spools, signed batches, sequence protection, and explicit loss
reporting before any Wazuh shadow projection is considered.

## 10. Security Requirements

- Pin one approved stable Wazuh release and image digest across manager, indexer,
  and dashboard.
- Hash and retain the Wazuh configuration, custom decoders, rules, manifests,
  connector binaries, and container/image identities.
- Keep all Wazuh ports private; apply host and provider firewalls.
- Use separate certificates/keys for transport, request signing, outbox
  encryption, and correlation-key derivation.
- Support connector rotation and immediate revocation.
- Enforce request freshness, nonce replay protection, size limits, rate limits,
  and bounded local disk usage.
- Keep Wazuh Active Response, email, full-event logging, and `logall_json`
  disabled unless separately approved and tested.
- Do not expose Wazuh credentials, raw alerts, internal ports, or connector
  details through customer-facing errors.
- Back up configuration, rules, decoders, manifests, connector state, and
  checkpoints. Wazuh is not the legal archive or backup for WarSOC evidence.

## 11. Required Acceptance Gates

The integration may move from lab to shadow only after all gates below have
recorded an artifact, timestamp, commit/version, and operator.

| Gate | Required proof | Current status |
|---|---|---|
| Lab platform | Services running; stable pinned version; private ports | Passed on colleague lab |
| Parser compatibility | Positive, negative, malformed, and boundary corpora | Generic JSON parsing passed; WarSOC bundle pending |
| Inbound transport | mTLS, signed envelope, replay rejection, schema/size limits | Implemented; live two-host proof pending |
| Durable dispatch | Outbox retry, bounded disk, crash/restart, expiry and DLQ | Implemented; restart/saturation artifact pending |
| Output export | `alerts.json` rotation, checkpoint, fsync, duplicate safety | Implemented foundation; real rotation/power-loss artifact pending |
| Candidate validation | Tenant/evidence/rule/provenance checks | Implemented and unit-tested; live return proof pending |
| Tenant isolation | Cross-tenant canaries and stateful correlation proof | Pending implementation |
| FBR/PECA independence | Forced Wazuh outage leaves both pipelines healthy | Pending integration test |
| Detection quality | Precision, recall, latency, noise, and operator usefulness | Pending shadow run |
| Security | Private network, key rotation, revocation, disk limits, secret review | Lab ports passed; connector controls pending |
| Rollback | Disable Wazuh without data loss or WarSOC outage | Pending runbook proof |

The lab is ready to start these integration gates. It is not ready for
`wazuh_primary`, customer visibility, firewall enablement, or a claim that
WarSOC is fully Wazuh-integrated.

## 12. Explicit Non-Goals for This Phase

These are intentionally excluded and must not be added to the current scope:

- a second Wazuh endpoint agent;
- Wazuh vulnerability inventory, SCA, rootcheck, or generic FIM claims;
- packet payload capture or PCAP;
- direct firewall-to-Wazuh syslog;
- Wazuh Active Response or automatic blocking;
- moving FBR or PECA rule ownership into Wazuh;
- customer access to the Wazuh dashboard;
- Wazuh as a second evidence archive;
- automatic promotion of all Wazuh rules;
- enabling the WarSOC network relay merely because Wazuh is installed.

## 13. Source Documents

- `docs/WARSOC_WAZUH_DETECTION_TARGET_ARCHITECTURE.md` - target architecture
  and integration contract.
- `docs/WAZUH_LAB_OPERATOR_RUNBOOK.md` - colleague lab validation procedure.
- `docs/WARSOC_CURRENT_STATE_ARCHITECTURE.md` - current WarSOC ownership and
  product boundaries.
- `docs/NETWORK_RELAY_BACKEND_FOUNDATION.md` - disabled firewall relay
  architecture and assurance boundary.

**Final decision:** Wazuh is ready as a private lab platform for the next
integration work. The WarSOC connector remains disabled until the acceptance
gates in Section 11 are implemented and evidenced.
