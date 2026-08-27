# WarSOC P0 Evidence-Integrity Closure

**Date:** 2026-08-20
**State:** HISTORICAL P0 BASELINE / SUPERSEDED BY LATER SOURCE IMPLEMENTATION / NOT PRODUCTION-DEPLOYED
**Scope:** Current endpoint, POS, disabled relay, SIEM, PECA, FBR, Redis, Mongo,
and Azure archive boundaries. No frontend, Wazuh promotion, relay launch, legal
case workflow, or new compliance feature is included. Later source work is
recorded in `WARSOC_BACKEND_EVIDENCE_PROGRAM_IMPLEMENTATION_2026-08-20.md`.

> **Retention supersession (2026-08-24):** Sections describing unresolved,
> tax-period, 2,190-day, or 2,557-day FBR retention are historical design
> evidence. The active product uses tenant-entitlement retention for new FBR
> records and does not rewrite historical evidence.

## 1. Decisions Closed

| Gap | Implemented decision |
|---|---|
| Legacy syslog could resemble compliance telemetry | Server-owned source classification makes legacy UDP syslog SIEM-only. |
| Redis could receive an event before canonical source evidence existed | Endpoint, POS and relay routes commit encrypted Mongo source envelopes before making outbox rows ready. |
| A Redis outage could force source retransmission without a backend durability boundary | The committed outbox retries independently and heals exact retries idempotently. |
| Fixed FBR expiry was derived from ingestion time | FBR retention is unresolved until an approved tax-period resolver supplies the legal boundary. |
| A synthetic legal hold could mask missing retention logic | No legal hold is invented. Holds must be explicit future records. |
| A six-year container could delete unresolved evidence too early | Unresolved FBR requires a 2,557-day preservation floor; shorter Azure policy fails closed. |

## 2. Server-Owned Source Classes

| Source class | Evidence profile | SIEM | PECA | FBR |
|---|---|---:|---:|---:|
| `signed_windows_agent` | `windows_endpoint` | Yes | Yes | Yes for catalog-matched FIM/native evidence |
| `authenticated_pos` | `fbr_pos_semantic` | Yes | No | Yes |
| `relay_attested_network` | `network_telemetry` | Candidate only | No | No |
| `legacy_syslog` | `network_telemetry` | Yes | No | No |
| `legacy_endpoint_unverified` | `windows_endpoint` | Observe/compatibility only | No | No |
| `internal_test` | `internal_test` | Test only | No | No |

Classification is recalculated by the server. A client cannot become compliance
eligible by sending `source_class`, `source_assurance`, or signature-like fields.
`type=network_log` is always legacy syslog in the current intake.

## 3. Admission and Dispatch Flow

### Signed Windows endpoint

```text
agent JWT + enrolled Ed25519 signature
        -> identity/signature/quota/size validation
        -> classify each event by retention class
        -> encrypted Mongo source envelope per retained class
        -> source outbox ready
        -> Redis raw/priority streams
        -> SIEM + eligible PECA/FBR workers
```

### Authenticated POS

```text
agent JWT + Ed25519 signature over exact HTTP body
        -> nonce/time/schema/size/quota validation
        -> exact body encrypted in FBR source envelope
        -> source outbox ready
        -> Redis raw stream
        -> FBR worker
```

### Disabled network relay

```text
relay identity + signed batch + sequence/quota/capacity admission
        -> exact body encrypted in SIEM source envelope
        -> source outbox ready
        -> Redis raw/priority streams
        -> SIEM only
```

The relay remains disabled in production. This flow is a backend durability
contract, not a customer-launch claim.

### Legacy UDP syslog

```text
IP allowlist + UDP datagram
        -> deterministic event UID
        -> source_class=legacy_syslog
        -> Redis raw stream
        -> SIEM only
```

Legacy syslog does not receive the authenticated source-envelope guarantee and
cannot feed PECA/FBR evidence. It is retained only for compatibility while the
authenticated relay remains disabled.

## 4. Canonical Source Envelope

Collections are physically split by retention class:

```text
source_envelopes_siem
source_envelopes_peca
source_envelopes_fbr
```

Each envelope records:

- tenant, authenticated source principal and channel;
- immutable source-envelope UID;
- SHA-256 of authenticated source bytes;
- SHA-256 of the complete dispatch set;
- compressed encrypted source bytes and dispatch payloads;
- encryption algorithm and key ID;
- authentication metadata and source/receive timestamps;
- `PREPARING`, `COMMITTED`, and `dispatch_complete` state.

The transport outbox stores references, event identity, payload hash, target
streams, lease/retry state and published stream IDs. It does not store a second
plaintext copy of the source or event body.

## 5. Idempotency and Failure Physics

1. The same source UID plus the same authenticated bytes/dispatch set reuses the
   original envelope.
2. The same source UID with different bytes or payloads is rejected as a source
   evidence conflict.
3. Outbox identity is stable per tenant, source principal, source channel and
   event UID.
4. A failure before envelope commit cannot expose a ready outbox row.
5. A failure after commit leaves the outbox retryable.
6. Publication uses one Redis transaction for all target streams.
7. Raw-stream entry admission is checked before publication.
8. A crash after Redis commit but before Mongo publication marking can redispatch
   once; downstream event UID uniqueness is the at-least-once dedupe boundary.
9. Only published outbox transport rows receive a cleanup TTL. Canonical source
   envelopes never receive an independent Mongo TTL.

## 6. FBR Retention Contract

New and backfilled FBR records contain:

```text
retention_state = UNRESOLVED
retention_basis = TAX_PERIOD_PENDING
base_retention_until = null
effective_retention_until = null
automatic_archive_expiry_allowed = false
retention_calculation_version = fbr-tax-period-v1
```

They do not contain an invented `_expire_at`. Ingestion time is not treated as
the applicable tax-period boundary. P0 also does not invent `legal_hold` or
`proceeding_hold` booleans; those states require explicit, audited hold records
in the later governance phase.

Until the tax-period resolver is designed, legally reviewed and implemented,
the archive requires 2,557 days. This number is a conservative seven-year-plus-
two-day preservation floor. It is deliberately not described as the statutory
retention result. A verified Azure policy shorter than this raises an error and
the exact Mongo records are not deleted.

## 7. Archive Contract

Source-envelope collections join the existing archive-before-delete process.
Only envelopes with `dispatch_complete=true` are eligible. The transaction is:

```text
select eligible completed envelope
        -> upload immutable JSON batch + SHA companion
        -> verify blob bytes/hash
        -> verify Azure immutability covers required retention
        -> write storage_archives ledger
        -> delete exact Mongo documents
```

Any upload, hash, immutability, ledger, unresolved-retention, or dispatch-state
failure preserves Mongo records.

## 8. Configuration

The source candidate adds these optional settings:

```dotenv
SOURCE_ENVELOPE_ENCRYPTION_KEY=
SOURCE_ENVELOPE_KEY_ID=source-envelope-v1
SOURCE_OUTBOX_MAX_ATTEMPTS=20
SOURCE_OUTBOX_LEASE_SECONDS=60
SOURCE_OUTBOX_RETENTION_DAYS=30
```

When `SOURCE_ENVELOPE_ENCRYPTION_KEY` is empty, the existing `ENCRYPTION_KEY` is
used. Production startup validates that the effective value is a valid Fernet
key. A dedicated key is recommended before deployment, but adding it requires a
managed rotation/decryption plan; changing it after evidence exists without a
key ring would make old envelopes unreadable.

## 9. Verification Evidence

Focused tests prove:

- encrypted envelope persistence and absence of plaintext outbox payload;
- exact retry idempotency and conflicting UID rejection;
- Redis-failure preservation and later publication;
- relay route Mongo-before-Redis ordering;
- PECA/FBR source isolation;
- FBR unresolved state without fake expiry or hold;
- rejection of a 2,190-day Azure policy for unresolved FBR;
- archive eligibility only after dispatch completion;
- backfill removal of legacy FBR expiry;
- Mongo-failure no-ack and duplicate-delivery behavior for signed evidence.

Final local result:

```text
462 passed, 1 skipped, 28 deprecation warnings
python compileall: pass
git diff --check: pass
Bandit high-severity scan: zero findings
```

The skip is an existing isolated/destructive test boundary. The warnings are
test-only uses of deprecated `datetime.utcnow()` and are not runtime failures.
The medium Bandit scan reported only `B104` matches: seven are `0.0.0.0` IP
sentinel values, not socket binds; the remaining match is the disabled legacy
syslog process listening on all interfaces inside its container. Production
host exposure remains restricted by the Compose loopback port binding and the
service/profile stays disabled. This exception must be re-reviewed before any
legacy syslog profile is enabled outside a lab.

## 10. Deployment Gate

Do not deploy this source candidate until all of these are true:

1. A backup and rollback revision are recorded.
2. `.env.prod` contains a stable source-envelope key/key ID or deliberately uses
   the existing stable Fernet key.
3. Mongo startup creates the three envelope collections and outbox indexes.
4. Azure FBR immutability is at least 2,557 days, or operations explicitly accept
   that unresolved FBR hot records will remain in Mongo and monitor disk growth.
5. API and unified worker are recreated from the same revision.
6. One signed endpoint event and one signed POS event prove envelope -> outbox ->
   Redis -> worker -> evidence flow.
7. A forced Redis outage proves committed outbox recovery.
8. Legacy syslog proves SIEM admission and PECA/FBR exclusion.
9. Archiver proves completed-envelope archive and incomplete-envelope refusal.

## 11. Remaining Work At This Historical P0 Boundary

Not completed here:

- tax-regime and tax-period resolution;
- actual case/legal-hold records and custody chain;
- encryption key ring and rotation workflow;
- historical FBR legal classification beyond safe backfill;
- Wazuh primary promotion;
- network-relay production launch;
- customer firewall hardware acceptance;
- frontend changes;
- live production deployment proof.

These are separate gated phases. None is implied by the green local suite.

The current source has since implemented tax-period calculation, explicit holds,
custody/cases, signed packages, an optional external anchor, SIEM raw-field
privacy, and a disabled synthetic reconciliation contract. Their implementation
and remaining external/deployment gates are governed by the later ledger rather
than this baseline.
