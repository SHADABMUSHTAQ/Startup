# WarSOC Commercial Retention Classes

**Status:** Azure infrastructure and application archive routing are production
active for the supported 3, 6, 9, and 12 month entitlements.

## Product Contract

WarSOC stores operational evidence in MongoDB for approximately seven days and
then archives eligible evidence to private immutable Azure Blob Storage. FBR
and PECA evidence inherit the tenant's normal WarSOC retention entitlement;
neither pack turns WarSOC into the customer's statutory tax-record repository.

The supported terms are deliberately finite:

| Commercial term | Canonical days | SIEM route | General evidence route |
|---:|---:|---|---|
| 3 months | 90 | `SIEM_90` | `GENERAL_90` |
| 6 months | 180 | `SIEM_180` | `GENERAL_180` |
| 9 months | 270 | `SIEM_270` | `GENERAL_270` |
| 12 months | 365 | `SIEM_365` | `GENERAL_365` |

Provisioning rejects any other `retention_days` value. This prevents a tenant
from being sold a duration for which no exact physical route exists. Product
names and pricing remain commercial concerns and are not encoded in this
storage contract.

Three dates remain separate:

- `logical_retention_start_at`: trusted server admission time;
- `customer_access_until`: end of the tenant's contractual access;
- `physical_worm_until`: Azure's observed immutability boundary.

Azure WORM begins when a blob version is created, so physical retention may
extend beyond customer access. WarSOC records both facts and must not promise
deletion on the exact customer-access date.

## Active Azure Layout

All eight containers are private, use the Cold tier, have versioning enabled,
and carry a locked version-level WORM policy for their exact canonical days:

```text
warsoc-siem-90        warsoc-general-90
warsoc-siem-180       warsoc-general-180
warsoc-siem-270       warsoc-general-270
warsoc-siem-365       warsoc-general-365
```

SIEM/raw/alert/source-envelope classes use `SIEM_<days>`. PECA, FBR, uploads,
analysis and other general evidence use `GENERAL_<days>`.

The original `warsoc-cold-storage` container and all historical blobs remain
untouched. Its existing lock cannot be shortened, and no legacy object is
silently moved or rewritten.

## Archive Safety Contract

For every tenant/collection batch, WarSOC:

1. selects records by a server-controlled hot-retention clock;
2. serializes the exact batch and calculates SHA-256;
3. uploads JSON and SHA companion blobs to the exact duration/class route;
4. reads back tier, version IDs, ETags, hashes and Azure WORM properties;
5. commits the tenant-scoped `storage_archives` ledger;
6. rechecks Legal Hold while holding the retention fence;
7. deletes only the exact Mongo document IDs after every check succeeds.

Missing routes, Azure errors, wrong tier, absent version IDs, short or unlocked
policies, hash/readback errors, ledger failures and Legal Holds preserve Mongo
data. The intended failure mode is visible hot-storage growth, never silent
evidence loss.

## Production Evidence

The 90-day paths were accepted by Azure runs
`20260906T120359Z-e6e1ffc4` and `20260906T120541Z-b8d6d78e`, then by OCI
canary `20260907T091930Z-d1187dcd`.

The 180/270/365 policy preparation, lock and verification records are retained
under `tmp/azure-retention/`. OCI runtime canary
`retention_canary_20260907T191203Z_dca3a697` then proved all six new routes:

- SIEM and general evidence selected separate matching containers;
- Azure reported Cold tier and the exact locked WORM duration;
- JSON and SHA blobs returned version IDs and passed streamed readback;
- the ledger committed before exact hot deletion;
- synthetic mutable tenant/source data was removed after validation;
- immutable labelled canary blobs and ledgers remain as audit evidence.

## Customer Access Boundary

Physical retention does not mean all historical data is currently searchable.
Normal dashboard, CSV and PDF operations remain bounded to hot Mongo data.
`ARCHIVE_RETRIEVAL_ENABLED=false` remains the safe default until the private
staging lifecycle, least-privilege identity, server-side copy, user-delegation
SAS, byte/month limits, expiry, frontend workflow and end-to-end download proof
are accepted.

Until that independent gate closes, the truthful offer is approximately seven
days of self-service hot search plus immutable retained evidence for the
tenant's selected term, with historical access handled outside self-service.
