# Frontend / Backend Contract Map

This file records the backend routes actively used by the frontend.

## Runtime

- Local API: `http://127.0.0.1:8000/api/v1`
- Production API: `https://api.warsoc.tech/api/v1`
- Authentication uses the HttpOnly `warsoc_token` cookie.
- State-changing requests include the in-memory `X-CSRF-Token` value.

## Public Routes

- `POST /sales/contact`
- `POST /sales/request-quote`

Public signup and browser-side plan activation are intentionally unavailable.

## Authentication

- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`
- `GET /auth/profile`
- `PUT /auth/profile`
- `GET /auth/my-packs`

## Dashboard

- `GET /alerts?limit=...`
- `PATCH /alerts/{alert_id}/status`
- `GET /data/status`
- `GET /data/search`
- `GET /logs?source=siem`
- `GET /logs?source=uploads`
- `GET /logs/{log_id}/evidence`
- `POST /ws/ticket`
- `WS /ws/alerts?ticket=...`
- `POST /mitigate`
- `POST /revoke`
- `GET /list`

## Agent Administration

- `POST /agent/generate-activation`
- `GET /agent/download`

Agent registration and telemetry are performed by the installer:

- `POST /agent/register`
- `POST /ingest/pulse`

## Compliance And Export

- `GET /compliance/packs`
- `GET /compliance/packs/{pack_id}`
- `GET /compliance/coverage`
- `GET /compliance/evidence/{pack_id}`
- `GET /export/csv`
- `GET /export/audit-report`

## Team Administration

- `GET /auth/team`
- `POST /auth/invite`
- `DELETE /auth/team/{user_id}`

## UI Authorization

- Auditors land on the dashboard's Compliance tab.
- Auditors cannot access alert, network, agent, or team controls.
- Managers may acknowledge and close alerts.
- Admins may manage alerts, agents, and team access.
- The backend remains authoritative for every role and tenant check.

## Validation

- `npm run lint`
- `npm run build`
- `npm audit --omit=dev`
- Browser smoke test on desktop and mobile.
- Authenticated API testing requires the backend, MongoDB, and Redis stack.
