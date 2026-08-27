# WarSOC FBR Retention Product Decision

**Status:** Active source-of-truth decision
**Effective:** 2026-08-24
**Scope:** New FBR POS semantic, Windows FIM, derived evidence, canonical source
envelopes, and Azure archive routing.

PECA retention was outside this decision. It is now governed independently by
`WARSOC_PECA_RETENTION_PRODUCT_DECISION_2026-08-24.md`; the preservation note
below is historical context, not an active fixed-duration PECA requirement.

## Decision

WarSOC FBR is POS/invoice integrity monitoring and security evidence. It is not
the customer's statutory tax-record repository. New FBR evidence follows the
tenant's existing normal WarSOC retention entitlement in
`tenants.retention_days`.

```text
new FBR source
  -> signed/authenticated admission
  -> encrypted canonical source envelope
  -> retention_model = TENANT_ENTITLEMENT_V1
  -> FBR detection/evidence processing
  -> seven-day Mongo operational window
  -> GENERAL_<tenant retention days> Azure route
  -> hash and immutability verification
  -> archive ledger
  -> exact Mongo hot-copy deletion
```

No product-plan name, six-year requirement, tax period, or FBR-specific
retention tier is assigned by the active FBR path.

## Preserved Architecture

- FBR semantic and Windows FIM source separation.
- Ed25519/JWT source authentication and server-owned tenant identity.
- Encrypted canonical source envelopes and durable outbox.
- FBR worker controls, encryption, rollups, SIEM alerts, and incidents.
- Tenant isolation, roles, evidence claims, cases, custody, holds, and exports.
- Seven-day operational Mongo window.
- Azure upload, SHA-256, immutability, ledger, hold recheck, and
  archive-before-delete failure safety.
- Every unrelated platform control. PECA behavior is governed by its separate
  August 24 product decision.

## Compatibility Boundary

Existing Azure blobs and immutability policies are unchanged. Existing Mongo
FBR records without `retention_model=TENANT_ENTITLEMENT_V1` are not rewritten
and are excluded from the new automatic archive/delete path. This prevents a
software release from silently shortening a historical obligation.

The tax-period helper code remains an inactive legacy interpreter. It is not
called by active ingestion, FBR processing, database initialization, or
archival. A future historical migration requires a separate approved plan,
inventory, backup, dry run, and evidence-preservation decision.

## Operational Requirements

1. Every active tenant has a valid positive `retention_days` value; the existing
   platform default remains 90 days.
2. The matching `GENERAL_<days>` Azure route exists and its locked policy covers
   at least that duration before the route is enabled.
3. Missing/short immutability, upload failure, hash failure, ledger failure, or
   an active legal hold prevents Mongo deletion.
4. Existing fallback blobs remain in their original locked container.
5. Deployment acceptance proves one new FBR semantic event and one FIM event
   carry the tenant marker and archive through the expected general route.

## Explicit Non-Goals

- No PECA redesign.
- No Wazuh, firewall, detection-rule, pricing, or frontend change.
- No customer tax-retention legal conclusion.
- No automatic migration or deletion of historical FBR evidence.
