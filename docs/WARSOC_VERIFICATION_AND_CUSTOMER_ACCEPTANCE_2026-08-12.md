# WarSOC Verification and Customer Acceptance Record - 2026-08-12

**Last verified:** 2026-08-13

## 1. Purpose

This record separates deployed production observations, locally proven candidate
behavior, lab-only network/Wazuh evidence, and remaining acceptance gates. It is
not a marketing claim and contains no customer identifiers, credentials,
activation codes, raw evidence, private addresses, or connector secrets.

## 2. System Boundary

The approved current product remains:

```text
Windows Agent -> authenticated WarSOC ingestion -> canonical Mongo evidence
              -> Redis streams -> WarSOC SIEM / FBR / PECA workers
              -> WarSOC incidents, compliance views, reports and Azure archive
```

The customer-side firewall relay and Wazuh detector are disabled candidate
subsystems. Neither is required by the current endpoint, FBR, PECA, retention,
incident, or report path.

## 3. Current Verification Layers

| Layer | Result | Meaning |
|---|---|---|
| Current maintained backend regression selection | 432 passed, 3 skipped | Wazuh, relay, native SIEM/FBR/PECA, incidents, signing, storage, retrieval, quotas, security, user journeys and backend hardening pass against the current workspace. The skipped cases are one opt-in isolated-stack grand-master harness and two container-local Git metadata checks; the Git checks passed directly on the host. |
| Focused Wazuh contracts | 32 passed | Trust, replay, sizing, durability, health and candidate-validation contracts pass locally. |
| Network-relay contracts | 36 passed | Collector, parser, bounded spool, signed transport and failure-policy contracts pass locally. |
| Native detection/compliance/incident/signing contracts | 96 passed | Existing WarSOC behavior remains compatible with the candidate changes. |
| Storage/retrieval/quota/deployment contracts | 78 passed | Archive, retrieval, export, retention and host/tenant policy boundaries pass. |
| User/security/pricing/runtime contracts | 49 passed | User journeys, sanitized failures, upload deletion, security controls and commercial request behavior pass. |
| Deep SIEM/FBR/PECA and rule-catalog contracts | 18 passed | Maintained deep engine suites pass. |
| Backend hardening contracts | 37 passed | Tenant isolation, lazy raw-evidence detail and upload hardening pass. |
| Deployed production preflight `83aa506f9e` | Passed | DNS/TLS, frontend assets, API binding/health, CORS, security headers, blocked docs/private ports and Azure installer 4.2.8 SHA-256 pass on 2026-08-13. |
| Isolated local Wazuh live harness | Passed | Bidirectional mTLS, canary rule 100500, signed return, shadow-only persistence and selected failure recovery pass on one host. |
| Separate Compute-A/Compute-B Wazuh path | Shadow transport accepted; production disabled | A private Tailscale path, bidirectional mTLS, separate HMAC identities, durable dispatch/receipt, rule 100500, signed candidate return, tenant isolation and manager/bridge/candidate-API recovery passed against the remote 4.14.7 host. Production enablement and rule-quality promotion remain blocked. |
| pfSense relay lab | Passed as a lab candidate | Native pass/block syslog, parsing, relay signing, encrypted outage spool and recovery passed in the controlled Hyper-V lab. |
| Customer firewall model acceptance | Pending | Every sold vendor/model/configuration still requires a controlled fixture and real-device acceptance record. |

Passing tests do not make Wazuh primary, enable the relay, certify a firewall
model, or prove production capacity.

The opt-in grand-master harness is not an approved release gate. It now refuses
to run unless the operator explicitly identifies a loopback API, a dedicated
`WarSOC_DB_e2e_*` Mongo database, a non-zero Redis database and the isolated
unified-worker container; syslog is separately opt-in. This removes the prior
runtime-database and retired-container hazards, but the destructive harness has
not been executed against a freshly orchestrated isolated stack. That does not
invalidate the maintained suite or separate two-host Wazuh proof.

Backend commit `7e81a9d` was pulled and rebuilt by the deployment operator, and
frontend commit `6f0cc5a` is present in the deployed Vercel bundle. Production
preflight proves their public availability and network/security baseline; it
does not replace an authenticated user-flow or exact Docker-image digest record.

Final static security validation scanned 27,948 application lines with Bandit
1.9.4. It reported zero high-severity findings and 25 medium scanner candidates.
The medium results were reviewed: missing-IP values are telemetry sentinels,
container-internal wildcard listeners are host-loopback/profile-gated, and
bridge SQLite table/identity names are selected from a fixed internal allowlist
while record values remain parameterized. No exploitable medium/high defect was
established by this scan.

The development Compose file previously published API, MongoDB and Redis on
all host interfaces. Those three development-only mappings now bind to
`127.0.0.1`; internal container networking is unchanged. Production already
publishes only Nginx on ports 80/443, while the optional profiled syslog
receiver remains loopback-bound.

Release configuration reconciliation found the source, installer and verified
manifest at `4.2.8`, while the local untracked production environment and
tracked example still referenced `4.2.6`; the local environment also overrode
endpoint signing to `observe`. Those local candidate values now reference the
4.2.8 artifact and `required` signing. This is not a production deployment:
the deployment host must receive the same two values explicitly and pass
preflight before the release is considered synchronized.

## 4. Production Customer-Flow Observation

An authenticated browser walkthrough against the deployed WarSOC application
verified:

- login and session hydration;
- dashboard summary, incident queue and endpoint telemetry presentation;
- incident details, provenance, timeline and close control;
- agent activation-package generation and modal dismissal;
- PECA and FBR pack catalog, control lists and retention labels;
- team list, role choices and invitation modal; and
- generic customer-safe error messages rather than backend stack details.

The walkthrough also found two concrete compliance-view defects:

1. The PECA evidence list produced an approximately 1.1 MB response and took
   about 30 seconds. Nginx and FastAPI returned HTTP 200, so the visible error
   was a client timeout, not a dead API or CORS failure.
2. The FBR evidence list rendered complete JSON records, including nested raw
   event material. A customer list should show evidence summaries and load raw
   detail only after an authorized explicit action.

The deployed pair now applies a metadata-only Mongo projection, bounds the
summary message, and removes raw, processed and signed payload bodies from list
responses. The frontend renders compact evidence cards and requests
`/logs/{id}/evidence` only after an explicit authorized action. Backend
contracts, frontend ESLint, the production build, deployment preflight, and
deployed-bundle inspection pass. An authenticated browser payload/latency flow
remains the final customer-level closure artifact.

The dashboard search correctly switched from live mode to a bounded historical
result and returned to live mode through the explicit control. However, exact
duplicate endpoint rows and incident cards were rendered in both live and
filtered views. Backend occurrence counts were present, so the paired frontend
acceptance must prove list-key/reconciliation deduplication without merging
different contexts or deleting event-granular evidence.

## 5. Detection and Compliance Truth

- WarSOC's native detector remains the active production engine.
- Wazuh is an internal replaceable candidate detector and remains shadow-only.
- Wazuh observations must never appear as a second customer product or bypass
  WarSOC tenant resolution, severity, suppression, incident, RBAC or retention.
- PECA stores the configured 11-control Windows evidence set; network-device
  metadata extends correlation only after relay acceptance.
- FBR native FIM and POS invoice evidence are different sources. Invoice-level
  claims require the approved JSONL/API contract; WarSOC does not discover
  arbitrary proprietary POS databases.
- Network telemetry is metadata only. General packet payload capture is outside
  the approved architecture.

## 6. Retention and Retrieval Truth

- MongoDB is the seven-day operational hot tier for SIEM, PECA and FBR evidence.
- Azure is the immutable evidence archive; archive-before-delete remains
  fail-closed on upload, hash, ledger or immutability verification failure.
- Existing locked historical evidence remains governed by its original Azure
  immutability policy and is not rewritten or shortened.
- New FBR and PECA evidence use the tenant's normal general retention route.
  Exact tenant-duration physical retention requires the matching locked Azure
  containers before duration-specific routing is enabled.
- Historical archive retrieval remains disabled until staging, lifecycle,
  user-delegation SAS, allowance and asynchronous UI acceptance are proven.
- Normal customer APIs must not proxy or materialize archive bytes in the API
  container or on the application host disk.

## 7. Wazuh Two-Host Gate

The isolated two-host acceptance run on 2026-08-13 used Compute A as the WarSOC
trust/evidence owner and the colleague laptop as Compute B. No production or
customer database, credentials, incidents, notifications, FBR evidence, PECA
evidence or response action participated.

The accepted evidence proves:

1. bridge ingress bound only to the Compute-B Tailscale address and candidate
   ingress bound only to the Compute-A Tailscale address;
2. mutual TLS and independent request-signing identities in both directions;
3. one signed 4688 dispatch through Wazuh rule 100500 and one signed WarSOC
   `shadow_observation` with continuous dispatch/event lineage;
4. replay `409`, tamper/wrong-connector `401`, oversized body `413`, and missing
   client-certificate rejection at TLS;
5. two concurrent tenant canaries returned to their exact originating tenants,
   with zero cross-tenant mismatches;
6. manager outage, bridge outage and candidate-API outage recovery without
   duplicate customer side effects;
7. expiry of an event that exceeded its five-minute live window, with a critical
   `INPUT_SPOOL_EXPIRED` health record instead of a late fabricated detection;
8. `alerts.json` identity change detection and resumed checkpoint processing;
9. zero customer incidents, security alerts, FBR/PECA records, emails and block
   actions throughout shadow acceptance.

The run exposed and corrected two deployment defects. A fresh bridge named
volume was root-owned while the bridge runs as UID 1000, so Compose now performs
a narrow one-shot ownership initialization. The Wazuh preparation script edited
only the container copy of `ossec.conf`, so manager recreation removed the
private listener; it now updates and backs up the host-mounted configuration
source of truth before recreating the manager.

The resource-constrained laptop could not reliably restart all Wazuh daemons in
place. Compose manager recreation with host-persisted configuration recovered in
the live window. This is a lab constraint and must be measured again on the
selected Compute-B host.

Still open are explicit Windows host-firewall rule evidence, physical spool
saturation/load testing, ruleset upgrade/rollback, rule-family positive/negative
and noise corpora, measured shadow quality, and production rollback. Therefore
`WAZUH_DETECTION_MODE=disabled` remains the production default and
`WAZUH_PRIMARY_APPROVED=false` remains mandatory.

## 8. Network Relay Gate

The pfSense virtual lab is sufficient for parser, signed transport, outage and
functional correlation evidence. It is not sufficient for broad vendor support
or a production claim.

Production remains gated by a signed/approved relay artifact, Windows service
lifecycle proof, exact customer firewall model fixture, source configuration,
measured EPS and spool pressure, 24-hour non-POS pilot, and the sold Azure
retention class. Backend and frontend feature flags must be enabled together
only after this gate closes.

## 9. Customer UI Acceptance Requirements

The active interface must expose only WarSOC concepts. It must provide:

- one incident queue with grouped counts and explicit provenance;
- endpoint fleet health, signature readiness and activation handoff;
- compliance summary lists with pagination and explicit detail retrieval;
- retention/storage state without Azure credentials or blob internals;
- role-scoped team and invitation controls;
- feature-gated network relay health after approval; and
- generic errors with a support reference, while detailed exceptions remain in
  protected server logs.

Wazuh product names, credentials, ports, APIs and raw manager output must never
appear in the customer UI.

## 10. Release Decision

The current native WarSOC endpoint/SIEM/FBR/PECA architecture remains usable
independently. Do not declare the Wazuh or customer-firewall expansion complete.
Deploy the compliance summary/detail changes only as a paired backend/frontend
release and require the authenticated browser flow before acceptance. Do not enable
Wazuh until the remaining capacity, rule-quality, host-firewall and rollback
gates produce approved artifacts. The two-host shadow transport gate is closed;
production defaults remain disabled/shadow-safe.

The detailed Wazuh and firewall phase ledger is
`docs/WARSOC_WAZUH_FIREWALL_IMPLEMENTATION_LEDGER_2026-08-13.md`.
