# Frontend / Backend Contract Map

This file records the backend routes actively used by the frontend. Shared paths and payload builders for the evidence workflows live in `src/contracts/backendContracts.js` and are covered by `npm test`.

## Runtime

- Local API: `http://127.0.0.1:8000/api/v1`
- Production API: `https://api.warsoc.tech/api/v1`
- Authentication uses the HttpOnly `warsoc_token` cookie.
- State-changing browser requests include the in-memory `X-CSRF-Token` value.

## Public And Authentication

- `GET /sales/pricing`
- `POST /sales/contact`
- `POST /sales/request-quote`
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`
- `POST /auth/activate-invite`
- `GET|PUT /auth/profile`
- `POST /auth/2fa/setup|verify|disable`
- `GET /auth/my-packs`

Public signup and browser-side plan activation remain unavailable.

## Operations

- `GET /data/status`
- `GET /incidents`
- `GET /incidents/summary`
- `GET /incidents/assignees`
- `GET /incidents/{incident_id}`
- `PATCH /incidents/{incident_id}/status`
- `GET /logs/live`
- `GET /logs/{log_id}/evidence`
- `POST /ws/ticket`
- `WS /ws/alerts?ticket=...`
- `POST /upload/analyze`
- `GET|DELETE /upload/results/{analysis_id}`
- `GET /upload/results`
- `POST /mitigate`
- `POST /revoke`
- `GET /list`

Endpoint Trust is part of the `/data/status` response. The frontend must not issue a second `/endpoint-trust` request.

## Agent And Relay Administration

- `POST /agent/generate-activation`
- `GET /agent/download`
- `GET /network-relay/status`
- `POST /network-relay/generate-activation`
- `POST /network-relay/{relay_id}/revoke`
- `POST /network-relay/{relay_id}/authorize-key-recovery`

Agent and relay registration/telemetry are performed by their installers, not the browser.

## Compliance And Evidence

- `GET /compliance/packs`
- `GET /compliance/packs/{pack_id}`
- `GET /compliance/coverage`
- `GET /compliance/evidence/{pack_id}`
- `GET /compliance/retention/status`
- `GET|POST /compliance/cases`
- `GET /compliance/cases/{case_id}`
- `POST /compliance/cases/{case_id}/close`
- `GET|POST /compliance/cases/{case_id}/exports`
- `GET /compliance/cases/{case_id}/exports/{export_id}`
- `POST /compliance/cases/{case_id}/exports/{export_id}/download-link`
- `GET|POST /compliance/holds`
- `POST /compliance/holds/{hold_id}/release`
- `GET /export/csv`
- `GET /export/audit-report`

Evidence packages are called exports by the backend. Case closure requires a `VERIFY` custody action and a reason. Legal-hold creation, not an `apply` action on an existing hold, applies a hold.

## Archive Retrieval

- `GET|POST /archive-retrievals`
- `GET /archive-retrievals/{request_id}`
- `POST /archive-retrievals/{request_id}/download-links`

Archive retrieval is not case-scoped. It remains hidden while `VITE_ARCHIVE_RETRIEVAL_ENABLED=false`; backend execution separately requires `ARCHIVE_RETRIEVAL_ENABLED=true` and its accepted Azure staging controls.

Evidence package export remains hidden while `VITE_EVIDENCE_EXPORT_ENABLED=false`; backend execution separately requires `EVIDENCE_EXPORT_ENABLED=true` and its worker/storage configuration.

## Roles

- `admin`: tenant/team, operations, endpoints, relay, cases, holds, exports, retention, and archive access.
- `manager`: operations, incidents, endpoints, relay, and archive access.
- `analyst`: operations, incidents, endpoints, and relay access.
- `auditor`: endpoints, compliance evidence, cases, holds, exports, retention, and archive access.

The backend remains authoritative for every role and tenant check.

## Validation

- `npm test`: shared route, payload, normalization, role, and stale-contract checks.
- `npm run lint`
- `npm run build`
- `npm audit --omit=dev`
- Backend API contract and full regression suites.
- Browser acceptance against the deployed frontend and backend before release promotion.
# Local Verification Amendment (2026-09-03)

Historical search renders the backend's exact-field matches without a second
message-only filter. Empty historical results have their own state. Compliance
cards inherit tenant retention instead of inventing year counts or fallback days.
Evidence timestamps without an explicit offset are interpreted as Mongo UTC.

`npm test` covers routes, payloads, roles, archive source/date handling, safe URLs,
historical match display, UTC timestamps and retention labels. Local browser proof
used real API/Mongo/Redis with synthetic data, not production evidence.

Full report: backend `docs/WARSOC_FRONTEND_CONTRACT_FIX_REPORT_2026-09-03.md`.
The opt-in test proxy is `tests/vite.integration.config.mjs` (API on loopback 8011).
