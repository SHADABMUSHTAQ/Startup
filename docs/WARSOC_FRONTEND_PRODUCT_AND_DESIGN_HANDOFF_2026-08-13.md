# WarSOC Frontend Designer Handoff

**Updated:** 2026-08-13  
**Frontend source:** GitHub `main` branch  
**Use:** What to design, who can use it, and where it connects to the backend.

## 1. Scope

Customer-facing WarSOC has:

1. Public website, pricing, quote and contact flows.
2. Security dashboard and incidents.
3. Windows endpoint activity and agent setup.
4. FBR and PECA evidence and reports.
5. Team accounts and permissions.
6. Firewall relay management, hidden until enabled.
7. Historical archive requests, hidden until enabled.

Wazuh is an internal background detector. Never show its name, logo, rules,
manager, indexer, ports or configuration. Customer detections are always shown
as WarSOC detections.

## 2. Roles and Navigation

| Area | Admin | Manager | Analyst | Auditor |
|---|---:|---:|---:|---:|
| Dashboard and endpoint activity | Yes | Yes | Yes | No |
| Incidents | Manage | Manage | Read | No |
| Endpoints | Manage/setup | Read | Read | No |
| Observed Activity Map | Manage blocks | Manage blocks | Read | No |
| Compliance evidence/reports | Yes | No | No | Assigned packs only |
| Team and Access | Yes | No | No | No |
| Profile | Yes | Yes | Yes | Yes |
| Firewall Relays | Manage | Read | Read | Read health |
| Archive Requests | Yes | Allowed SIEM data | No | Assigned packs only |

Use one application shell with sidebar, top bar, theme control, user menu and
Sign Out. Show only the navigation allowed for the signed-in role. The backend,
not hidden buttons, remains the security authority.

Public routes are `/`, `/pricing`, `/request-quote`, `/login`, `/set-password`,
`/privacy` and `/terms`.

## 3. Shared Header

Include:

- Search field
- Last 24 Hours / Last 7 Days selector
- Search button
- Theme control
- Telemetry status
- User menu with Profile and Sign Out

Search placeholder:

> Search event ID, source IP, user, agent ID or record ID

Do not offer All Time or 30 Days. Normal searchable data is seven days hot.
Older data uses Archive Requests.

Telemetry status:

- **Active:** a configured endpoint is reporting correctly.
- **Degraded:** endpoint data exists, but heartbeat, signing, audit or sensor
  coverage has a problem.
- **Not configured:** no eligible endpoint has reported.
- **Historical:** uploaded/offline data is being viewed.

Always show a short reason for Degraded or Not configured.

Frontend engineering must keep one shared API client. Production uses
`VITE_API_BASE_URL` for HTTPS API calls and `VITE_WS_BASE_URL` for WSS updates.
Do not create per-screen backend URLs.

### Public website

The Home page keeps the existing Navbar, product scope/features, pricing,
contact, about, CTA, partners and footer sections. Marketing text must match the
current proven scope and must not promise packet capture, guaranteed compliance
or automatic payment. The contact form sends `POST /sales/contact` and needs
loading, success and safe failure states. Privacy and Terms use approved legal
text only.

## 4. Dashboard

Show:

- Active Incidents
- Correlated Events
- Rule Matches
- Blocked Addresses
- 24-hour incident trend
- Severity breakdown
- Endpoint event load
- Telemetry source breakdown
- Current operations summary

Connections:

- Metrics: `GET /incidents/summary`
- Incidents: `GET /incidents`
- Endpoint activity: `GET /logs/live?source=siem&aggregate=true`
- Readiness: `GET /data/status`
- Live updates: `POST /ws/ticket`, then `/ws/alerts`

Do not mix normal endpoint activity and security incidents into one list. If
live presentation disconnects, keep existing information and show:

> Live updates are reconnecting. Endpoint collection continues independently.

Rename `Attacker Origin` to `Observed Source Locations`. Do not invent
countries or map positions for unknown/private addresses.

## 5. Incidents

### List

Each row shows:

- Severity and title
- Incident ID
- First/last seen
- Occurrence count such as `x12`
- Endpoint/source
- Status and assignee
- Actions allowed for the role

Equivalent detections appear once with a count. Different endpoints, users,
processes, rules, targets, outcomes or minute buckets stay separate.

### Detail

Show:

1. Summary, status and assignee.
2. Who/where: endpoint, actor, target and source.
3. How: process, parent process, command, destination and outcome.
4. Why WarSOC raised it: rule, Windows event ID, MITRE and match reason.
5. Linked evidence and occurrence coverage.
6. Workflow history.

Use `Not recorded` when the event did not contain a field. This is different
from `Not configured`.

Admin/Manager may acknowledge, assign, resolve, mark false positive, reopen and
block an approved external source. Analyst is read-only. Resolve and false
positive actions require notes.

Connections:

- `GET /incidents/{incident_id}`
- `GET /incidents/assignees`
- `PATCH /incidents/{incident_id}/status`
- `POST /mitigate`
- `POST /revoke`

## 6. Endpoint Activity

This is normal Windows evidence, not only threats.

Columns:

- Time
- Endpoint
- Source type
- Native event ID
- Count
- Safe summary

Include filters, pause/resume display, manual refresh and full-screen table.
Pausing the screen must not stop the installed agent. Use backend source types;
do not guess `WEB-WAF` from words inside a Windows event.

Connection: `GET /logs/live?source=siem&aggregate=true`.

### Offline CSV analysis

The current product also supports a separate CSV upload/history view. It must
be clearly labelled `Offline Log Analysis`; it is not live endpoint collection.
Show CSV-only validation, upload progress, bounded results, report action and
delete confirmation. Connections: `POST /upload/analyze`, `GET /upload/results`,
`GET /upload/results/{analysis_id}` and `DELETE /upload/results/{analysis_id}`.

## 7. Endpoints and Agent Setup

### Download Agent dialog - Admin only

1. Generate a one-time activation code.
2. State that it is single use and valid for 24 hours.
3. Copy code.
4. Download Windows installer.
5. Provide approved SHA-256 manifest/link.
6. Tell IT to keep Defender enabled and verify/allowlist the exact hash under
   company policy.
7. Explain that POS directories are optional and used only for FBR file
   monitoring or a configured `pos_audit.log` feed.

Connections:

- `POST /agent/generate-activation`
- `GET /agent/download`

Current approved release is 4.2.8. Engineering must read version/hash from the
approved release configuration, not permanently hardcode it. The dialog needs
X, Cancel, Escape and backdrop close behavior.

### Endpoint fleet

Build this screen from `GET /data/status`. Do not build inventory from log rows.

Show:

- Purchased, enrolled and remaining seats
- Online/degraded/offline/revoked counts
- Hostname, agent ID and version
- Last seen and signing state
- Audit/sensor state
- POS path/feed state
- Spool health
- Clear degradation reason

The same response supplies purchased seat limit, registered/online/degraded/
offline counts, endpoint details, event-signing state and sensor status.

## 8. Observed Activity Map

The current map is not a complete network topology. It shows:

- WarSOC tenant core
- Monitored Windows endpoints
- Observed external sources
- Blocked external sources

Selecting a node shows related detections and last activity. Admin/Manager may
block only a source the backend marks bannable. Do not invent routers, paths,
subnets or devices that were not observed.

## 9. Compliance and Audit

Current retention:

- PECA: 7 days hot, 365 days immutable vault.
- FBR: 7 days hot, 2,190 days immutable vault.

FBR must show its two source states separately: file-integrity monitoring and
the optional POS `pos_audit.log` business feed. Do not show invoice line-item
coverage unless that feed is configured and reporting. Current PECA coverage is
native Windows evidence; show firewall/network-device coverage only after the
Firewall Relay feature is enabled and a device is reporting.

Pack catalog cards show pack name, description, entitlement, coverage,
retention and Open Pack/Request Quote action.

Pack screen tabs:

1. Overview
2. Controls
3. Evidence and Retention
4. Reports

Evidence list shows time, event ID, source, actor, storage tier and summary.
Fetch raw evidence only after `View Evidence`. The evidence modal requires a
visible X, Escape support, loading state and safe error state.

Connections:

- `GET /compliance/packs`
- `GET /auth/my-packs`
- `GET /compliance/coverage`
- `GET /compliance/packs/{pack_id}`
- `GET /compliance/evidence/{pack_id}`
- `GET /logs/{record_id}/evidence`
- `GET /export/csv`
- `GET /export/audit-report`

Call the PDF an Evidence Summary. Do not claim guaranteed compliance, court
admissibility or guaranteed prevention of fines. The current PDF presentation
is not itself digitally signed; the underlying authorized evidence carries the
relevant integrity material.

## 10. Team and Access - Admin only

Team list shows name/email, role, Pending/Active/Revoked state, auditor pack
scope and revoke action for non-admin users.

Invite flow:

1. Enter email.
2. Select Admin, Manager, Analyst or Auditor.
3. For Auditor, select at least one entitled pack.
4. Submit.
5. Show the 24-hour one-time activation link.
6. Show whether email was queued.
7. Always provide Copy Link for secure manual sharing.

Never create or show a temporary password. The invited user chooses a password
with at least 16 characters, uppercase, lowercase, number and symbol. Invalid,
expired and used links receive the same safe message.

Connections:

- `GET /auth/team`
- `POST /auth/invite`
- `DELETE /auth/team/{user_id}`
- `POST /auth/activate-invite`

## 11. Login, Profile, Pricing and Quote

### Login/Profile

- Email/password and show/hide password
- Six-digit MFA step when required
- No Forgot Password link in current scope
- Profile/contact fields and read-only role
- MFA setup, verify and disable

Connections: `/auth/login`, `/auth/me`, `/auth/logout`, `/auth/profile` and
`/auth/2fa/*`.

### Pricing/Quote

Pricing comes from `GET /sales/pricing`; do not hardcode prices.

Allow monthly/annual, 10-50 requested endpoints, 3/6/9/12-month general archive
and optional FBR/PECA packs. Show recurring estimate, setup fee and taxes note.

Quote form collects company, name, work email and optional phone, then sends
`POST /sales/request-quote`. A quote is not payment, capacity reservation or
account creation. Success says it was received for manual review and invoicing.

## 12. Firewall Relays - Design, Keep Hidden

Hide while `NETWORK_RELAY_ENABLED=false`.

Show relay name/version, status, last seen, registered devices, vendor/model,
last event, clock confidence, parse failures, dropped events/bytes and health.

Admin setup:

1. Name relay.
2. Register approved firewall devices.
3. Generate one-time activation code.
4. Copy setup details.
5. Confirm first relay heartbeat and first event per device.

Connections:

- `POST /network-relay/generate-activation`
- `GET /network-relay/status`
- `POST /network-relay/{relay_id}/revoke`
- `POST /network-relay/{relay_id}/authorize-key-recovery`

Show metadata only: no packet payloads, firewall credentials or firewall policy
editing. Parsers exist for pfSense, Fortinet, Cisco ASA and MikroTik, but do not
claim production support before each real-device test passes.

## 13. Archive Requests - Design, Keep Hidden

Hide while `ARCHIVE_RETRIEVAL_ENABLED=false`.

User selects allowed source, date range and reason. Show estimated size and:

- Awaiting approval
- Approved
- Restoring
- Ready
- Failed
- Expired

One exact request up to 10 GiB per month is included. Additional/larger/unknown
requests need manual commercial approval. No online payment. When ready, the
browser downloads directly from Azure through a short-lived link; the WarSOC
API does not stream the file.

Connections:

- `POST /archive-retrievals`
- `GET /archive-retrievals`
- `GET /archive-retrievals/{request_id}`
- `POST /archive-retrievals/{request_id}/download-links`

## 14. Shared Design Rules

Every main screen needs Loading, Empty, Refreshing, Degraded, Offline, Access
Denied, Validation Error and Retry states.

Never show FastAPI, MongoDB, Redis, worker, deployment, traceback, internal
field names or raw backend errors.

Security:

- Use existing HttpOnly cookie authentication.
- Do not store tokens, activation codes, invitation links or Azure links in
  local storage.
- Render log/evidence values as text, never HTML.
- Do not expose credentials, private storage names or keys.
- Do not send customer evidence to third-party analytics.

Responsive sizes: 390x844, 768x1024, 1440x900 and 1920x1080. No page-level
horizontal overflow. Keep modal close buttons visible. Important controls need
at least 40x40 targets. Use text/icon plus color for status.

## 15. Existing Frontend Files

| Area | File |
|---|---|
| Routes | `src/App.jsx` |
| API/auth/errors | `src/api/apiClient.js`, `src/store/authStore.js`, `src/utils/apiError.js` |
| Public Home/contact/legal | `src/assets/Pages/Home`, `src/assets/Components/Contact`, `src/assets/Pages/Legal` |
| Dashboard/incidents/setup | `src/assets/Pages/Dashboard/Dashboard.jsx` |
| Endpoint activity | `src/assets/Components/AgentLogs/AgentLogs.jsx` |
| Activity map | `src/assets/Components/NetworkMap/NetworkMap.jsx` |
| Compliance | `src/assets/Pages/Compliance/ComplianceDashboard.jsx` |
| Team | `src/assets/Pages/Team/TeamManagement.jsx` |
| Login/invitation/profile | `src/assets/Pages/Login`, `SetPassword`, `Profile` |
| Pricing/quote | `src/assets/Pages/Pricing`, `RequestQuote` |

Improve these files and split large components when needed. Do not create a
second application shell, API client or auth store.

## 16. Delivery Order

1. Shared shell and role navigation.
2. Dashboard with separate Incidents and Endpoint Activity.
3. Incident list/detail/actions.
4. Agent setup and endpoint fleet design.
5. Observed Activity Map.
6. Compliance and reports.
7. Team invitation and account activation.
8. Login, MFA, Profile, Pricing and Quote.
9. Hidden Firewall Relay screens.
10. Hidden Archive Request screens.

Provide desktop/mobile plus loading, empty, degraded, error and access-denied
states for each main screen.

## 17. Run Frontend Locally With Live Backend

The colleague does not need to run the backend or Docker. In the frontend
repository root, create `.env.local` with:

```dotenv
VITE_API_BASE_URL=https://api.warsoc.tech/api/v1
VITE_WS_BASE_URL=https://api.warsoc.tech
```

Then run:

```powershell
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173`. The live backend must allow both
`http://127.0.0.1:5173` and `http://localhost:5173` in `ALLOWED_ORIGINS`.
Do not edit `.env.production`, do not commit `.env.local`, and do not place any
backend secret in a `VITE_` variable. If login succeeds but the session does not
remain active, allow cookies for the local site and `api.warsoc.tech` in the
test browser.
