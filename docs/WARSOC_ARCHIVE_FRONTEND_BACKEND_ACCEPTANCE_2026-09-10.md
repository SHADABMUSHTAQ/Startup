# WarSOC Archive Frontend and Backend Acceptance

**Date:** 2026-09-10

**Backend production release:** `7e9f00d`

**Frontend production release:** `7816739`

**Production canary:** `ARCHIVE-RETRIEVAL-CANARY-20260910T133007Z-413b5717`

## Verdict

The asynchronous archive backend and functional customer frontend are active.
The backend canary is the end-to-end worker/Azure proof. The frontend has
maintained contract and DOM tests. Final visual design and an authenticated
role-by-role production browser walkthrough remain open.

## Corrected Product Contract

- Normal dashboard, CSV and PDF reads remain bounded to the seven-day hot tier.
- Historical evidence uses `POST /api/v1/archive-retrievals`, an isolated worker,
  private staging and direct HTTPS download links. FastAPI does not proxy archive
  bytes.
- The included allowance defaults to **10 GiB**, not 1 GB, and is reserved
  atomically once per tenant billing month when the size estimate is exact.
- Admin and Manager may request operational sources. Admin and Auditor may
  request entitled PECA/FBR sources. Analyst has no archive permission.
- Tenant identity comes from the authenticated database-backed user. Request IDs
  and download links are tenant scoped.
- Only `READY` requests can issue links. Non-ready requests return `409`; expired
  availability returns `410`.
- Download URLs must be direct HTTPS URLs without embedded credentials. They are
  held only in component memory and must never be copied into logs or reports.
- Current production uses the explicitly accepted `service_sas` fallback. A
  future commercial Entra identity should replace it with user-delegation SAS.

## Active Lifecycle and Display Vocabulary

```text
request -> PENDING_APPROVAL -> APPROVED -> PENDING_REHYDRATION -> READY -> EXPIRED
                 manual approval                    |
                                                    +-> FAILED
```

`REJECTED` and `CANCELLED` are recognized terminal display states but the current
public router does not expose reject/cancel transitions. The UI renders explicit
text for them without pretending those operations exist. Unknown future states
fall back to readable neutral text and never expose a download action. Status is
never communicated by color alone.

## Maintained Frontend Checks

`npm test` passes 18 checks, including:

- production feature flag and `archive.retrieve` role gate;
- admin/manager/auditor/analyst permission contract;
- operational versus entitled compliance source choices;
- valid source, UTC date conversion, end-after-start, five-minute future grace,
  2,190-day API safety ceiling, and 8-500 character reason;
- all lifecycle labels plus unknown-state fallback;
- deterministic source, UTC range and byte formatting;
- `READY`-only download action;
- response-level link expiry display;
- rejection of HTTP, relative, credential-bearing, script and data URLs;
- same-tick duplicate submission prevention;
- safe customer messages for `403`, `404`, `409`, `410`, `413` and `422`;
- component loading, empty, request, download and unsafe-link behavior.

Additional frontend gates:

```text
npm run lint       PASS
npm run build      PASS (2,877 modules)
npm audit          PASS (0 vulnerabilities)
git diff --check   PASS
```

The build still reports the existing dashboard chunk at approximately 1.44 MB
minified / 445 kB gzip. This is a performance backlog item, not an archive
correctness failure.

## Maintained Backend Checks

The focused archive, authorization-policy and deployment group passes 53 tests.
It covers:

- read-only, HTTPS, short-lived service SAS generation and identity mismatch;
- exact tenant/time archive selection and customer-access expiry;
- bounded retrieval size/blob policy and atomic monthly allowance;
- disabled-feature fail-closed behavior;
- authenticated request creation and expired-evidence exclusion;
- admin/manager/auditor source filtering and analyst denial using current DB
  roles;
- forged operational/compliance source rejection;
- cross-tenant list, direct-ID and download denial;
- `READY` and expiry enforcement;
- public serialization without worker leases, internal errors, source paths or
  staging object names;
- server-side copy authorization, SHA-256 verification and failure handling;
- authorization inventory and Compose deployment contracts.

The complete tracked backend run produced:

```text
748 passed, 2 skipped, 1 failed
```

The one failure was a stale generated API inventory containing old source-line
numbers. Regeneration recorded 132 routes with zero manual-review flags; the
failed inventory test then passed on targeted rerun. No route, auth type or role
changed. A second eight-minute full run was intentionally not repeated after the
generated-only correction.

Additional backend gates:

```text
Python compileall                 PASS
Bandit high severity/confidence   PASS (0 findings)
pip check                         PASS
git diff --check                  PASS
```

## Production Evidence

- `https://warsoc.tech` returned HTTP `200`.
- The deployed dashboard bundle contains the `7816739` archive status,
  validation and secure-download UI.
- `https://api.warsoc.tech/health` returned healthy MongoDB and Redis.
- Unauthenticated `GET /api/v1/archive-retrievals` returned `401`, proving the
  route is deployed and protected.
- Canary `ARCHIVE-RETRIEVAL-CANARY-20260910T133007Z-413b5717` proved request and
  allowance handling, server-side Azure copy, streamed SHA-256 equality,
  `READY`, one direct read-only download, mutable staging cleanup, and preservation
  of the immutable source.

Directly editing MongoDB to mark a request `READY` is useful for API/UI
simulation but is **not** an end-to-end worker or Azure proof. It must not be
reported as such.

## Remaining Acceptance

1. Sign in to production as Admin, Manager, Auditor and Analyst. Confirm the tab,
   visible sources and denied paths match the role table above.
2. Perform desktop and mobile visual review with the frontend designer. No API
   or state-management changes are required for visual polish.
3. Preserve screenshots and redacted HTTP results. Never preserve a SAS query
   string, cookie, activation code or storage credential.
4. Monitor retrieval worker failures, lease age, queue depth, staging cleanup and
   link issuance. Do not rerun a destructive canary merely to prove UI styling.

## Reproduction

Frontend, from a clean checkout of `main`:

```powershell
npm ci
npm test
npm run lint
npm run build
npm audit
```

Backend, from a clean checkout of `backend` with isolated test MongoDB and Redis:

```powershell
$Python = "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"
& $Python -m pytest -q tests/test_archive_retrieval_contract.py tests/test_authorization_policy_contract.py tests/test_production_deployment_contract.py
& $Python -m pytest -q
& $Python -m compileall -q app agent scripts
& $Python -m bandit -q -r app agent scripts -lll
& $Python -m pip check
git diff --check
```

Verify the selected interpreter prints output before accepting any Python result;
on this workstation `C:\Windows\System32\python` is a silent stub and is not test
evidence.
