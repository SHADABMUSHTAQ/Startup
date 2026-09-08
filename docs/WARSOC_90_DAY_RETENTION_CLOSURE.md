# WarSOC 90-Day Retention Closure

> Historical 90-day closure record. The active multi-duration contract is now
> `docs/WARSOC_COMMERCIAL_RETENTION_CLASSES.md`. The evidence and run IDs below
> remain valid for the 90-day route and must not be rewritten.

**Status:** production active and accepted on OCI release `5c8e2dc`; both
90-day Azure routes and the production archive/hold/failure paths are proven.

## 1. Product Contract

The currently approved commercial retention entitlement is 90 days. WarSOC
keeps operational evidence searchable in MongoDB for approximately seven days,
then retains eligible evidence in private Azure Blob Storage for the remainder
of the customer's access window. FBR and PECA evidence inherit the tenant's
normal WarSOC entitlement; neither evidence pack creates a separate statutory
tax-record retention promise.

Three dates remain distinct:

- `logical_retention_start_at`: the trusted server-controlled admission clock;
- `customer_access_until`: the end of the customer's WarSOC access entitlement;
- `physical_worm_until`: the immutability boundary reported by Azure.

Azure WORM duration starts from the blob/version creation time. Because WarSOC
normally archives after the hot window, a 90-day Azure policy can physically
retain a blob beyond the customer's 90-day access date. The ledger records both
facts. Customer access must stop at `customer_access_until`; the product must
not promise physical deletion exactly 90 days after source admission.

## 2. Storage Layout

Only these new active-product evidence destinations are approved:

| Route | Private container | Access tier | Purpose |
|---|---|---|---|
| `SIEM_90` | `warsoc-siem-90` | Cold | Raw logs, SIEM events, alerts, and SIEM source envelopes. |
| `GENERAL_90` | `warsoc-general-90` | Cold | PECA, FBR, and general evidence. |

Both require blob versioning, version-level immutability, a verified 90-day
locked policy, public access disabled, and version IDs returned on upload.
This section records the original 90-day activation. Exact 180-day, 270-day and
365-day routes were subsequently approved and proven; see the active contract.

The existing `warsoc-cold-storage` fallback and every existing blob remain
untouched. Its historical 2,190-day lock cannot be shortened. Existing ledger
rows without the new customer-access metadata are excluded from self-service
retrieval and require an explicit migration or operator decision.

## 3. Backend Contract

The release candidate enforces one server-controlled archival clock per
collection. Source timestamps remain evidence but cannot make a fresh record
eligible for archival or deletion.

The archive transaction is:

1. Select only records eligible by their trusted server clock.
2. Serialize the exact batch and calculate SHA-256.
3. Upload JSON and hash blobs to the selected route and requested tier.
4. Read back Azure tier, version ID, ETag, creation time, legal hold, and WORM
   properties.
5. Verify the configured immutability boundary.
6. Commit or refresh the tenant-scoped `storage_archives` ledger.
7. Recheck Legal Hold while holding the retention fence.
8. Delete only the exact tenant/document IDs after all checks pass.

Any missing trusted clock, upload error, tier mismatch, missing required version
ID, insufficient immutability, ledger failure, or Legal Hold preserves the Mongo
copy. The failure mode is visible storage growth, never silent evidence loss.

Successful archive statuses are `archived`, `archived_hot_deleted`, and
`archived_hot_preserved_hold`. Retrieval and availability queries recognize all
three, but customer routes also require an unexpired `customer_access_until`.

## 4. Azure Activation Gate

The storage half of this gate was executed on 2026-09-06 against private
account `warsocevidence90prod` in `rg-warsoc-production`:

1. Confirm the storage account supports blob versioning and version-level WORM.
2. Create private `warsoc-siem-90` and `warsoc-general-90` containers with
   version-level WORM capability; configure the exact routes to upload new
   blob versions at Cold tier. Do not alter the legacy container.
3. Apply an unlocked 90-day version-level policy to each container.
4. Upload harmless test objects, record version IDs, tier, ETags, and policy
   properties, and prove read access.
5. Obtain approval, then lock both policies. Locking is irreversible.
6. Re-run read-only property checks and a blocked-deletion test.
7. Configure `SIEM_90` and `GENERAL_90` routes, exact Cold tiers, exact policy
   declarations, route-specific `blob` verification scope,
   `AZURE_BLOB_VERSION_ID_REQUIRED=true`, and fail-closed exact routing.
8. Recreate only the storage archiver and run one controlled archive per route.
9. Verify hashes, ledger fields, route isolation, Legal Hold, and archive failure
   preservation before enabling customer retrieval.

Steps 1-6 are complete. Owner approval was explicit; an independent
second-person approval was not recorded. Lock run
`20260906T120359Z-e6e1ffc4` and independent verification run
`20260906T120541Z-b8d6d78e` prove both containers are private, blob versioning
and version-level WORM are enabled, each policy is `Locked` for exactly 90
days, and retained canaries expose Cold tier plus version identity. Preparation
also completed SHA-256 upload/readback verification. Direct deletion attempts
against both retained canaries were rejected and each object remained present.

Steps 7-8 and the non-hold portions of step 9 were then exercised from the
candidate in an isolated local runtime against the real Azure account. Synthetic
tenant `WARSOC_AZURE_E2E_20260906T161701Z` archived SIEM evidence to
`warsoc-siem-90` and FBR evidence to `warsoc-general-90`. Both transactions
verified Cold tier, blob version identity, JSON and sidecar SHA-256 readback,
90-day WORM coverage, ledger commit, and exact source deletion in that order.
An earlier rejected immutability-boundary attempt preserved its Mongo source,
providing real-Azure fail-closed evidence. These synthetic blob versions are
expected to remain locked for their policy lifetime.

Steps 7-9 completed on OCI on 2026-09-07. Release `5c8e2dc` is deployed at
`api.warsoc.tech` with exact `SIEM_90` and `GENERAL_90` routing to private
account `warsocevidence90prod`. Production canary
`20260907T091930Z-d1187dcd` proved:

- SIEM evidence archived to `warsoc-siem-90` at Cold tier;
- FBR/general evidence archived to `warsoc-general-90` at Cold tier;
- JSON and SHA-256 companion objects returned version IDs, passed streamed
  readback, and reported locked 90-day WORM coverage;
- the archive ledger committed before exact Mongo deletion;
- an active Legal Hold protected both Azure objects and preserved the hot
  record, then an audited release removed only the WarSOC-managed hold and an
  idempotent archive retry completed hot deletion without weakening WORM;
- a synthetic 91-day tenant with no exact route produced no archive ledger and
  retained its Mongo source until controlled canary cleanup;
- the private evidence-export container passed a small write/read/hash/delete
  probe without exposing public access.

The post-run check found three finalized `archived_hot_deleted` ledgers, six
Cold/versioned/locked Azure objects, a `RELEASED` hold and binding, a
`COMMITTED` release audit, and zero remaining mutable canary tenant or hot-data
rows. Read-only Azure inspection run `20260907T093110Z-2d241c2c` independently
reconfirmed private access, account-level versioning, and locked 90-day
version-WORM on both containers. Existing legacy objects and ledgers were not
moved or rewritten.
Customer retrieval remains a separate disabled gate.

If any check fails, keep exact routing fail-closed and preserve eligible records
in MongoDB while the new route is repaired. Do not silently send new commercial
evidence to the legacy fallback. Never attempt to roll back or weaken a WORM
lock.

## 5. Retrieval Gate

Code alone does not make days 8-90 usable. Before advertising 90-day accessible
history, WarSOC must separately prove the disabled asynchronous retrieval flow:

- private `warsoc-retrieval-staging` with automatic short-lived deletion;
- least-privilege Microsoft Entra access and user-delegation SAS permission;
- tenant/role/collection/date authorization;
- monthly and byte limits;
- Azure server-side copy with no API or local-disk byte proxy;
- SHA-256 verification, short-lived read-only download, expiry, and audit;
- rejection of expired or legacy ledger rows without customer access metadata.

Until that gate passes, the truthful offer is seven-day self-service search plus
90-day retained immutable evidence. Automated customer retrieval for days 8-90
is not yet available, so WarSOC must not advertise 90-day self-service history.

## 6. Acceptance Evidence

Release acceptance requires:

- focused archive, retrieval, compliance, FBR, and PECA tests;
- full maintained backend regression suite;
- static/security/dependency checks;
- exact-route tests for both 90-day containers;
- wrong-tier, missing-version, insufficient-WORM, Azure outage, ledger failure,
  duplicate retry, Legal Hold, cross-tenant, expired-access, and hash-mismatch
  negative cases;
- one production-like canary only after Azure activation is explicitly approved.

Candidate verification on 2026-09-06 completed with `668 passed, 4 skipped`
and zero failures in the full maintained backend suite. The previously failing
relay tests were a test-bootstrap error: the feature-gated router had not been
mounted before the test app was imported. Focused correction passed all eight
affected cases. Python compilation, production Compose rendering, OCI shell and
Azure PowerShell parsing, diff hygiene, high-severity Bandit, `pip-audit`, and
`pip check` all passed. The four skipped tests remain explicitly optional test
cases; they are not hidden failures.

Production activation on 2026-09-07 preserved all existing Azure objects,
policies and tenant entitlements. The only persistent additions are the
synthetic 90-day WORM canary objects and their explicitly labelled audit
ledgers; mutable canary tenant/source rows were removed after acceptance.
