# WarSOC Upgraded Frontend Delta

**Date:** 2026-08-21
**Purpose:** Additional functional UI required for the upgraded backend. This is
an integration contract, not a visual-design specification.

## 1. Existing Surfaces to Keep

- Login, invitation password setup and authenticated session hydration.
- Dashboard, incident list/detail, endpoint fleet, compliance catalog/evidence,
  team access and agent activation/download.
- Backend-calculated severity, counts, evidence states and permissions. The
  frontend must not recreate detection or compliance logic.

## 2. Required Additional Components

| Component | Users | Required behavior |
|---|---|---|
| Evidence Cases | Admin, auditor | List/create cases, view detail, reference hot evidence, display custody history and verification state; close is Admin-only |
| Legal Holds | Admin, auditor | List holds; apply/release is Admin-only and requires reason, authority and explicit confirmation |
| Evidence Package Jobs | Admin, auditor | Request package, poll status, show `REQUESTED`, `PROCESSING`, `READY`, `FAILED`, `EXPIRED`, or `REQUIRES_ARCHIVE_RETRIEVAL`; download only from the short-lived URL returned by the backend |
| Archive Retrieval | Authorized role defined by backend | Submit an asynchronous request and show approval, rehydration, ready, failed and expired states; never stream archive bytes through the browser API client |
| Evidence and Claim State | All entitled roles | Display `OBSERVED`, `NOT_OBSERVED`, `UNVERIFIED` separately from `SUPPORTED`, `CONDITIONALLY_SUPPORTED`, `UNSUPPORTED`; missing data is never green |
| Endpoint Trust | Admin, manager, analyst | Consume `GET /api/v1/data/status` and show last seen, version, event-signing state, time trust, audit coverage, POS coverage and spool health without exposing activation secrets or signing keys |
| Retention Status | Admin, auditor | Consume `GET /api/v1/compliance/retention/status` and show the tenant entitlement, seven-day hot window, FBR/PECA tenant-retention model, legal-hold state and observed archive-ledger availability |
| Generic Failure State | All users | Render safe message plus backend `request_id`; distinct unauthenticated, forbidden, not found, unavailable, empty and degraded states |

## 3. Firewall Relay Correction

A local correction candidate based exactly on frontend `6ffc9e0` now implements
this contract and passes ESLint, production build and focused source assertions.
It is not pushed, deployed or paired-tested, so production enablement remains
blocked.

```text
GET /api/v1/network-relay/status
response: { capability, relays }
```

Activation must submit the backend schema, including:

```text
relay_name
devices[]:
  device_id
  vendor
  model
  source_addresses[]
  transport
  timezone
  expected_eps
```

The screen must be hidden or show a neutral unavailable state when the backend
capability says disabled or the route is absent. It must support activation-key
one-time display, registered device health, revoke and key-recovery workflows
according to backend role checks. It must never expose signing private keys.

## 4. Role Contract

The UI may hide unavailable actions for usability, but backend `403` remains the
authority.

```text
Admin   -> tenant management, activation, hold apply/release, case close
Analyst -> incident investigation and permitted operational actions
Auditor -> evidence, cases, custody, exports, retention and hold visibility
Viewer  -> read-only entitled operational views
```

Every role requires explicit loading, success, empty, degraded, forbidden and
backend-unavailable checks. Do not infer authorization from a visible button.

The evidence workflow uses these backend-authoritative routes:

```text
GET/POST /api/v1/compliance/cases
GET      /api/v1/compliance/cases/{case_id}
POST     /api/v1/compliance/cases/{case_id}/close
GET/POST /api/v1/compliance/cases/{case_id}/exports
POST     /api/v1/compliance/cases/{case_id}/exports/{export_id}/download-link

GET/POST /api/v1/compliance/holds
POST     /api/v1/compliance/holds/{hold_id}/release

GET/POST /api/v1/archive-retrievals
GET      /api/v1/archive-retrievals/{request_id}
POST     /api/v1/archive-retrievals/{request_id}/download-links
```

Evidence-package and archive download URLs are requested only when an item is
`READY`; they are short-lived responses and must not be persisted in browser
storage.

## 5. Deliberate Exclusions

- No customer-facing Wazuh name, rule ID, manager state or Wazuh configuration.
- No Wazuh promotion/tuning controls.
- No FBR reconciliation UI while authoritative DB/integrator connectors are not
  implemented and the feature flag remains disabled.
- No arbitrary compliance-retention editor.
- No raw Azure credentials, container names, internal hostnames, stack traces,
  detector internals or secret material.
- No new pricing, payment or legal claims as part of this engineering delta.

## 6. Frontend Acceptance

Before deployment, run lint and production build, then authenticated browser
acceptance for Admin, Analyst, Auditor and Viewer. Prove invitation setup,
session expiry, direct-route refresh, 401/403/404/503 handling, case/hold/export
state transitions, archive request lifecycle, agent activation/download,
endpoint degraded state and relay-disabled behavior.

The release fails if the UI converts an API failure into an empty result, exposes
backend implementation details, or presents absent/unsupported evidence as a
successful compliance result.
