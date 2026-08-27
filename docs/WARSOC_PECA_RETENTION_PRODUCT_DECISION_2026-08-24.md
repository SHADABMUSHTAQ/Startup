# WarSOC PECA Evidence Retention Product Decision

**Status:** Active source-of-truth decision
**Effective:** 2026-08-24
**Scope:** New PECA endpoint forensic evidence, canonical PECA source envelopes,
Mongo operational storage, Azure archive routing, and customer-facing retention
metadata.

## Decision

WarSOC PECA is a **PECA Evidence Pack** containing eleven WarSOC-defined
Windows investigation-support mappings. It is not blanket PECA compliance,
certification, or a declaration that every tenant is subject to PECA section 32.

New PECA evidence inherits the tenant's existing WarSOC retention entitlement
from `tenants.retention_days`.

```text
new entitled PECA source
  -> signed/authenticated Windows admission
  -> encrypted canonical PECA source envelope
  -> retention_model = TENANT_ENTITLEMENT_V1
  -> eleven-control PECA evidence processing
  -> encrypted and RSA-PSS-signed PECA evidence
  -> seven-day Mongo operational window
  -> GENERAL_<tenant retention days> Azure route
  -> SHA-256 and immutability verification
  -> storage_archives ledger
  -> final legal-hold recheck
  -> exact Mongo hot-copy deletion
```

No active PECA customer-evidence path assigns a fixed 365-day retention period
solely because the evidence belongs to the PECA Evidence Pack.

## Preserved Architecture

- Pack ID `peca_forensic`, collection `peca_forensic_logs`, and all eleven
  existing Windows event mappings.
- Signed/authenticated endpoint provenance and server-owned tenant identity.
- Encrypted canonical source envelopes and durable Redis outbox.
- Independent `eto_group` processing and stable event-UID idempotency.
- PECA field encryption, forensic seal, canonical signed payload, and RSA-PSS
  signature.
- Seven-day Mongo operational policy.
- Tenant isolation, RBAC, evidence cases, hash-linked custody, exports, reports,
  explicit legal/proceeding holds, and retention fences.
- Azure upload, exact-byte SHA-256, immutability verification, archive ledger,
  and archive-before-delete fail-closed behavior.
- FBR, SIEM, Wazuh, network relay, incident, pricing, subscription, endpoint,
  frontend, and archive-retrieval behavior.

## Historical Compatibility Boundary

Historical PECA evidence is not rewritten, shortened, moved, deleted, or
silently adopted into the new retention model.

- Existing Azure blobs and locked immutability policies remain untouched.
- Existing Mongo PECA records and source envelopes without
  `retention_model=TENANT_ENTITLEMENT_V1` are excluded from the new automatic
  tenant-duration archive/delete path.
- Legacy `_expire_at`, `365_DAYS`, PECA-container, and ledger metadata remain
  interpretable as historical facts.
- Startup removes unsafe Mongo TTL indexes but does not backfill, unset, or
  otherwise mutate historical PECA retention markers.
- Any historical migration requires a separately approved inventory, backup,
  legal decision, dry run, rollback boundary, and evidence-preservation plan.

## Deployment Requirements

1. Every active tenant has a valid positive `retention_days` value; the current
   platform fallback remains 90 days.
2. The matching `GENERAL_<days>` private Azure route exists and its locked
   immutability policy covers at least the tenant entitlement before the route
   is enabled.
3. Missing routing, insufficient immutability, upload/hash/ledger failure, or an
   active hold preserves the Mongo copy and emits an operational failure.
4. Deployment acceptance proves one new PECA event and its canonical source
   envelope carry the tenant-entitlement marker and use the expected general
   route.
5. The eleven-control signed/encrypted evidence and tenant-negative/RBAC tests
   must remain passing.

## Legal Claim Boundary

PECA section 32 addresses specified traffic data retained by a service provider.
Whether a customer or WarSOC has a particular obligation under that section is
a separate legal and architecture decision. This product decision does not
classify WarSOC or a tenant as a service provider, does not define a section 32
traffic-data ledger, and does not treat endpoint forensic events as statutory
traffic data.

WarSOC deliberately does **not** claim that:

- the eleven mappings are statutory PECA controls;
- buying the PECA Evidence Pack creates a one-year statutory retention duty;
- preserved evidence proves an offence, intent, attribution, admissibility, or
  blanket PECA compliance; or
- tenant-entitlement retention satisfies every legal preservation request.

Case-specific legal/proceeding holds remain the mechanism for preserving
identified evidence beyond ordinary tenant retention.

## Explicit Non-Goals

- No historical PECA migration.
- No PECA section 32 traffic-metadata implementation or redesign.
- No new controls or event mappings.
- No FBR, SIEM, Wazuh, relay/firewall, frontend, pricing, incident, subscription,
  endpoint-limit, or archive-retrieval change.
- No Azure container creation, policy lock, production deployment, or data
  movement in this source change.
