# WarSOC Gated and Disabled Capability Proof

**Date:** 2026-09-06  
**Production executable revision:** `9974df6` on OCI  
**Frontend revision:** `e7c5aa0` on Vercel  
**Purpose:** Prove which capabilities are active, deliberately disabled, or
genuinely unfinished without enabling them in production.

## 1. Proof Method

Each conclusion uses the strongest applicable evidence:

1. source-level gate and fail-closed behavior;
2. focused maintained tests;
3. sanitized OCI environment and active-container inspection;
4. aggregate production state without reading customer payloads; and
5. frontend production feature flags where a UI exists.

No production feature flag was changed. No customer record was created or
modified, and no customer payload was inspected. Wazuh verification used only
aggregate status counts.

## 2. Production Runtime Proof

The API, unified worker, compliance cron, Wazuh dispatch, Wazuh candidate API,
Wazuh manager, and Wazuh bridge were all running with zero restarts. The
following values were read from the actual containers, so missing environment
entries were resolved through the same source defaults used at runtime:

```text
NETWORK_RELAY_ENABLED=true
EVIDENCE_EXPORT_ENABLED=true

ARCHIVE_RETRIEVAL_ENABLED=false
EVIDENCE_DAILY_ANCHOR_ENABLED=false
FBR_RECONCILIATION_ENABLED=false
SECURITY_STORIES_ENABLED=false

WAZUH_DETECTION_MODE=shadow
WAZUH_PRIMARY_APPROVED=false
ARCHIVE_RETRIEVAL_WORKER=absent
```

The frontend production contract independently reports:

```text
VITE_NETWORK_RELAY_ENABLED=true
VITE_EVIDENCE_EXPORT_ENABLED=true
VITE_ARCHIVE_RETRIEVAL_ENABLED=false
```

## 3. Gate Matrix

| Capability | Exact state | End-to-end proof | What closes the gate |
|---|---|---|---|
| Historical archive retrieval | `IMPLEMENTED-DISABLED` | Backend resolves the flag to false, the dedicated Compose-profile worker is absent, the API returns a controlled unavailable response when authenticated, the frontend flag is false, and focused contracts pass. Normal hot-data reads and evidence exports do not depend on it. | Private staging lifecycle, Azure identity/user-delegation RBAC, real archive-tier rehydration, download expiry/cleanup, and authenticated browser acceptance. |
| Daily external evidence anchor | `IMPLEMENTED-DISABLED` | Compliance cron is active, but its runtime anchor flag resolves false. The optional anchor function is therefore not called. Deterministic root, retry, and failure contracts pass in focused tests. | Create and lock the dedicated anchor container, validate harmless upload/readback/outage retry, then enable the flag. |
| FBR multi-source reconciliation | `CONTRACT/LAB ONLY-DISABLED` | Runtime flag resolves false. The generated API inventory contains only `POST /api/v1/fbr/pos/ingest`; no database or external-integrator route exists. Reconciliation outcome/hash contracts pass, but they have no live source connectors. | Build one approved read-only POS database adapter and one licensed-integrator observation adapter, then run source-authenticity, replay, mismatch, and outage acceptance. |
| Security Stories V1 | `IMPLEMENTED-DISABLED` | Runtime setting resolves false. The unified worker exits the story loop without consuming events, story APIs fail closed with 404, and no frontend capability is published. The focused suite proves disabled writes, tenant isolation, ordering, replay, leases, bounds, RBAC, and Wazuh-shadow exclusion. | Approve the complete regression/runtime gate, enable on new traffic only, prove rollback and queue behavior, then separately release a UI. |
| Wazuh primary detection | `SHADOW ACTIVE / PRIMARY DISABLED` | OCI runs all four Wazuh path services with zero restarts. Runtime mode is `shadow` and primary approval is false. In the seven-day aggregate there were 53,889 shadow observations, zero promoted observations, and zero incidents with Wazuh as a detection source. Source requires mode `primary`, explicit global approval, an approved rule family, and complete lineage before incident projection. | Qualify selected families against benign/malicious corpora, capacity and failure tests; approve them individually; then use a controlled primary canary. Broad stock-rule promotion remains prohibited. |
| Duration-specific Azure retention split | `CODE COMPLETE / CLOUD PENDING` | None of the SIEM/general 90/180/270/360 container, lock, or policy-day routes is configured on OCI. The active fallback is configured and Azure reports an immutability policy; production declares it locked for 2,190 days. This prevents early deletion but over-retains data and cost. | Create each actually sold retention route, apply/lock the matching policy, verify Azure properties, configure all three values per route, and run archive-before-delete failure tests. Existing locked evidence remains untouched. |
| Non-pfSense firewall vendors | `PARSER-PROVEN / COMMERCIAL ACCEPTANCE OPEN` | Fortinet, Cisco ASA, MikroTik, and pfSense parser contracts pass, but the customer capability response intentionally publishes only `validated_firewall_vendors: ["pfsense"]`. Relay entitlement defaults to zero and remains tenant-scoped. | Run the same physical-device or vendor-accurate virtual acceptance for each vendor before adding it to the validated list. This is not a global disabled switch. |
| POS database and licensed-integrator connectors | `NOT IMPLEMENTED` | No production route, service, or adapter exists. Only strict POS semantic ingestion is exposed. The reconciliation library is not a connector. | Approve a concrete customer schema/integrator contract and implement it as a separate authenticated, least-privilege source. |
| Automated backup and blank-host recovery | `OPEN OPERATIONAL GATE` | OCI has no WarSOC backup systemd service. A prior isolated restore drill exists, but no current encrypted scheduled backup plus final-host blank-rebuild acceptance is recorded. Evidence archive is not a MongoDB operational backup. | Configure encrypted scheduled backup, off-host retention and monitoring; restore to an isolated blank host; record RPO/RTO, counts, hashes, and application health. |
| Installer publisher trust | `PARTIAL` | The current local 4.2.13 manifest and Windows verification both report `NotSigned` for the installer. Exact SHA-256 allowlisting is available, but it is not publisher identity or reputation. | Obtain a trusted code-signing certificate, sign and timestamp the release, verify on a clean Windows host, then publish a new immutable artifact and manifest. |

## 4. Focused Verification

```text
Archive retrieval, daily anchor, FBR reconciliation,
Security Stories and Wazuh gate contracts: 76 passed

Relay entitlement, status/vendor contract and four parser
boundaries: 7 passed, 46 deselected

Latest installer Authenticode status: NotSigned
Generated FBR production routes: POST /api/v1/fbr/pos/ingest only
```

These focused tests supplement the previously recorded complete backend campaign
of 644 passed and one expected skip. They were not a replacement full-suite run
because this review did not change executable code.

## 5. Final Decision

The gates are functioning as designed: disabled capabilities are not silently
running or customer-visible, and Wazuh shadow output cannot create incidents.
The current active product remains healthy.

The main unresolved infrastructure issue is the missing duration-specific Azure
retention split. The locked fallback is fail-safe against early deletion but is
not the intended commercial storage model. The most important genuinely missing
capabilities are scheduled off-host backup/blank-host recovery and any real POS
database or licensed-integrator connector. They must not be described as
"implemented but disabled."
