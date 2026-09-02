# Frontend and Backend Contract Corrections

Date: 2026-09-03 (Asia/Karachi)
Status: Implemented and locally verified. Git publication and deployed-release acceptance are separate steps; this report does not establish OCI or Vercel deployment.

## Baseline and Scope

- Backend checkout: `C:\Users\Lenovo\Desktop\Startup-backend`, base `2c7b840` (matched `origin/backend` at inspection).
- Frontend checkout: `C:\Users\Lenovo\Desktop\Startup-main-pfsense-relay`, base `5b29d20` (matched `origin/main` at inspection).
- Stale desktop frontend checkouts were not used.
- Changes repair existing workflows, not a new design or server-monitoring implementation.
- No production data, Azure blobs, locked evidence, agent binaries, detection rules, Wazuh configuration or firewall configuration was changed.

## Completed Corrections

| Problem | Correction and reason |
|---|---|
| UI requested nonexistent evidence routes | Shared route definitions now use `/compliance/cases`, its `/exports` subroutes, `/compliance/holds`, and `/compliance/retention/status`. |
| Case creation sent unsupported fields | Sends `title`, `description`, `external_reference`; required lengths match the API. |
| Case closure omitted its required body | Requires a recorded reason and sends `action=VERIFY`. |
| Case detail discarded items and custody events | Preserves the separate `case`, `items`, `custody`, and `custody_events` response sections. Record/custody hashes are not mislabeled as compliance claims. |
| Package workflow used nonexistent job endpoints | Uses case-scoped exports, `export_id`, required reasons, actual terminal statuses and authenticated download-link issuance. |
| Browser pop-up blocking could hide downloads | Archive/package link requests produce explicit HTTPS download anchors. No archive bytes pass through the browser's API response handler. |
| Hold UI attempted unsupported apply actions | Creates a scoped hold through POST `/compliance/holds`; releases through the existing hold-specific endpoint, with reason and authority. |
| Hold errors were behind the overlay | Errors remain visible inside the dialog. Native modal top-layer rendering keeps the dialog above mobile navigation; height is bounded and scrollable. |
| Duplicate case-scoped archive workflow had no backend | Removed the obsolete component. Existing collection/date-range archive retrieval remains the only workflow. |
| Archive form used naive dates and wrong reason limit | Converts local selections to UTC; enforces 8-500 character reasons, busy state, and role/pack-scoped source choices. |
| UI had an unsupported `viewer` role and omitted `manager` | Uses the four provisionable backend roles. Archive navigation also checks role, not only a build flag. |
| Endpoint Trust requested a nonexistent separate route | Shares the existing fleet `/data/status` response. Backend returns time, audit, POS and spool summaries from existing observations. |
| Auditor fleet UI was denied by the API | Added tenant-scoped read-only fleet access for auditors. Raw search remains forbidden to that role. Authorization inventory and negative tests were updated. |
| Missing/stale sensor data could appear healthy | Unknown and stale states are explicit. Malformed cached sensor data cannot crash the status route. Latest clock observation is selected with an indexed, tenant-scoped, newest-only lookup. |
| Exact search matches disappeared | Historical API results are no longer filtered a second time by message text. Event-ID and IP matches survive even when the message contains neither. |
| Empty historical results looked blank or like offline analysis | Added an explicit empty state and a separate historical-search label. |
| Compliance UI invented retention years/defaults | Pack cards show tenant entitlement; actual retention comes from `/compliance/retention/status`. Removed the 90/1095 fallback claims and obsolete six-year FBR/provider copy. |
| UTC values could shift with the browser/server timezone | Corrected Mongo UTC timestamp presentation in the affected evidence views and offline fleet timestamp serialization. |

## Verification Results

| Check | Result |
|---|---|
| Full maintained backend campaign | 591 passed, 1 skipped, 28 deprecation warnings; no failures. |
| Final endpoint/status regression after timestamp cleanup | 21 passed. |
| Focused endpoint, evidence custody and archive contract campaign | 40 passed. |
| Frontend contract tests | 13 passed; new `npm test` command. |
| Frontend lint and production build | Passed; large-dashboard-chunk warning remains. |
| Production frontend dependency audit | `npm audit --omit=dev`: zero vulnerabilities reported. |
| Scoped backend Bandit scan | Changed runtime module `app/routes/data.py`: zero findings after cleanup. Not a new repository-wide security audit. |
| API authorization inventory | Regenerated: 125 routes; zero manual-review entries. |
| Patch whitespace checks | Passed. |

Full campaign artifact: `tmp/frontend-contract-regression-20260903.xml`.
The final narrow timestamp correction was tested by the subsequent 21-test run,
not by rerunning the entire full campaign. The skipped test is
`tests.test_grand_master_e2e::test_grand_master_e2e`, requiring explicit `E2E=1`.
The 28 warnings are existing `datetime.utcnow()` deprecations in FBR stress tests.

## Real Local Browser Checks

Used the real React application and FastAPI source with real local MongoDB/Redis,
an isolated `WarSOC_UI_contract_20260903` database, Redis database 13, and a synthetic
account. Requests used a same-origin development proxy; production CSP was not weakened.
No production account or production evidence was used.

- Login completed and opened the dashboard.
- Created a case, verified returned description/reference and custody history, and closed it with a reason. Result: CLOSED.
- Applied a hold to one synthetic event and released it with a separate reason/authority. Result: RELEASED.
- Seven-day event-ID search and 24-hour IP search each displayed the synthetic record even though its message contained neither search value.
- Fleet and trust displayed the local endpoint; expired measurements became STALE/UNKNOWN rather than healthy.
- Retention displayed the test tenant's 180-day entitlement, seven-day hot window and absence of archive evidence. Pack cards matched that model.
- Optional archive/package controls were absent when their flags were disabled.
- Hold dialog inspected at 390x844; no page-width overflow and no navigation overlap. Desktop retention inspected at 1440x900.

Browser artifacts: `tmp/ui-hold-mobile-20260903.png`, `tmp/ui-retention-desktop-20260903.png`.
`tests/vite.integration.config.mjs` in the frontend is a test-only proxy configuration,
not the Vercel production configuration.

## Compatibility and Release Order

1. Review and commit the scoped backend and frontend changes from the checkouts above. Do not include `.qoder/`, test credentials or `tmp/` artifacts.
2. Deploy the backend extension first. `/data/status` keeps its existing fields and adds summaries; it does not migrate stored evidence.
3. Deploy frontend changes to `main` only after the backend release identity and health are verified.
4. Repeat authenticated acceptance with the deployed pair, including admin/auditor roles, 24-hour/seven-day searches, cases, holds and retention.
5. Verify the effective Vercel build environment. A dashboard flag is not backend authorization and can be overridden by deployment environment settings.

These defaults remain false in the frontend environment examples and production file:
`VITE_ARCHIVE_RETRIEVAL_ENABLED` and `VITE_EVIDENCE_EXPORT_ENABLED`.
Do not enable them merely because the UI paths now match. Their background workers,
private Azure staging, authorization, short-lived links, expiry and failure handling
need deployment-specific acceptance. Existing backend feature gates remain unchanged.

## Remaining Boundaries

- No zero-failure guarantee and no claim of complete live product acceptance.
- Wazuh/firewall maintained contract tests ran as part of the backend suite; no fresh physical-firewall, customer-relay or separate Wazuh-host campaign was performed here.
- No real Azure rehydration/export job, legal-hold deletion exercise, or destructive grand-master test was run. Historical/locked data remains untouched.
- Dashboard bundle is approximately 1.43 MB minified / 443 KB gzip. Code splitting remains a separate performance improvement, not hidden by raising the warning threshold.
- The architecture retains older dated deployment snapshots. This amendment records local corrections, not a claim that the old recorded production identities are current.
- Separate existing local Docker stacks were observed with a restarting syslog receiver and Wazuh manager/indexer ports published on all host interfaces. These were not started or modified by this work, and do not establish the OCI production state. Review/stop unused lab stacks separately before treating this laptop as a hardened environment.
