# WarSOC September 21 Architecture Correction Ledger

**Status:** Local release candidate, not deployed
**Scope:** Review of the September 19 Wazuh/SCA and evidence-integrity change batch
**Production authority:** Existing OCI release and `warsoc-projected-shadow-v2`

## 1. Executive result

The reviewed change batch was not production-grade as originally reported. It
mixed valid relay/outbox work with incorrect Wazuh rule mappings, an unproven
SCA product claim, a non-independent "dual signature", an unsafe retention
shortcut, and integrity endpoints that queried the wrong ledger collection.

The invalid behavior has been removed or placed behind a fail-closed feature
gate. Existing production detection, tenant retention, FBR, PECA, firewall
relay, source provenance, archive-before-delete, and frontend behavior were not
redesigned by this correction.

## 2. Architecture map after correction

```text
Signed WarSOC endpoint / relay evidence
        |
        +--> WarSOC native SIEM --> security alerts --> incidents
        |
        +--> PECA/FBR evidence paths (unchanged)
        |
        +--> durable minimized Wazuh projection
                  |
                  +--> active registry: warsoc-projected-shadow-v2
                  |        22 governed families, all shadow
                  |
                  +--> candidate observation stores
                           no primary promotion in production

Optional SCA candidate (OFF)
Wazuh real type=check alert
        --> bounded check-field projection
        --> tenant/agent binding
        --> latest-scan posture calculation
        --> read-only WarSOC API

Evidence case
        --> allowlisted source evidence reference
        --> versioned stable-content hash
        --> hash-linked custody events
        --> hot rehash OR explicit archived-ledger partial result
```

## 3. Findings and disposition

| Finding | Disposition |
|---|---|
| The edited `warsoc-v1-production-registry.json` was not the active production registry. | Restored to its reviewed six-rule baseline. Production remains on `warsoc-projected-shadow-v2`. |
| Rules `60106`, `60200`-`60202`, and `60600`-`60602` were assigned incorrect meanings. | Removed from the batch; no production mapping was changed. |
| Wazuh SCA summary rules `19000`-`19003` were treated as individual control results. | Parser now projects posture fields only for `data.sca.type=check`; tests use real failed/passed check IDs `19007`/`19008`. |
| SCA was presented as complete and customer-facing. | Added `WAZUH_SCA_ENABLED=false`; it cannot be enabled while Wazuh detection is disabled. Active registry and live frontend still contain no SCA product surface. |
| Dashboard status scanned tenant observation history unconditionally. | No SCA query or response field is produced while the feature is off. Enabled queries are tenant/agent restricted, latest-scan scoped, and bounded. |
| A second email address was called a dual signature without independent authentication. | Removed. Custody actions retain the authenticated actor and audit reason only. |
| HIGH/CRITICAL Wazuh observations silently created a hard-coded 90-day hold. | Removed. Tenant retention and explicit Legal Hold remain the only active retention authorities. |
| Candidate observations attempted to hash themselves before insertion. | Removed. Candidate persistence no longer makes a circular self-integrity claim. |
| Daily integrity verification queried `compliance_ledger`, which does not exist. | Corrected to `daily_forensic_ledgers`, bounded to 367 records. |
| Missing hot evidence was always labelled tampered. | Archived-ledger presence now returns `PARTIALLY_VERIFIED`; content re-verification requires archive restore. Actual hash or custody mismatch remains `INTEGRITY_VIOLATION`. |
| Case hashing included mutable alert/envelope workflow fields. | New case items use `case-evidence-sha256-v2`; existing unversioned items retain the legacy verifier. Only documented workflow metadata is excluded. |
| Custody output implied PECA/legal admissibility. | Renamed to WarSOC custody support and added an explicit legal claim boundary. |
| Static API inventory missed router-level prefixes and roles. | New routes use explicit mount prefixes and endpoint RBAC dependencies; the inventory now records full paths and roles. |

## 4. Accepted local changes

- Valid source-envelope ordering and source identity work remains intact.
- Valid pfSense/network display normalization remains intact.
- Valid network context extraction and capacity-script changes remain intact.
- Detection observation and agent-binding indexes remain because they support
  existing tenant-scoped Wazuh operations as well as the disabled SCA candidate.
- Evidence-integrity endpoints are admin/auditor-only and rate-limited.
- SCA endpoints are authenticated, role-restricted, tenant-scoped, rate-limited,
  and additionally blocked by the explicit feature gate.

## 5. Frontend truth

The authoritative production-aligned checkout is:

```text
C:\Users\Lenovo\Desktop\Startup-main-archive-availability
```

It is clean and contains no SCA UI. Experimental SCA UI exists only in the
diverged and dirty `Startup-main` checkout. It must not be merged or deployed
until backend SCA acceptance is complete. No frontend change is required for
this correction batch.

## 6. Verification result

The final local candidate completed the maintained backend regression campaign:

```text
pytest -q
822 passed, 2 skipped, 28 warnings in 464.62 seconds
```

The two skips are expected suite skips. The warnings are confined to deprecated
`datetime.utcnow()` usage in an FBR stress-test module; no runtime failure was
reported.

Additional local checks completed:

- Python compilation passed for `app`, `agent`, and `scripts`.
- The generated API security inventory contains 138 routes and zero manual-review
  entries.
- The high-severity Bandit scan completed with exit code 0.
- `pip check` reported no broken requirements.
- `git diff --check` completed with exit code 0; only Git line-ending notices
  were emitted.
- `pip-audit` was not run because the tool is not installed in the active Python
  environment. This is an unexecuted dependency-CVE check, not a passing result.

The tests verify rule-registry truth, SCA parser boundaries, latest-scan posture
calculation, disabled-route behavior, case-source restrictions, retention-hold
removal, custody request validation, daily-ledger selection, archive-aware
integrity status, stable case hashes, and compatibility with the wider backend.

They are not evidence of:

- a live Wazuh SCA scan from another host;
- an accepted SCA registry in production;
- a customer-visible SCA frontend;
- deployment of this local candidate to OCI.

## 7. Release gates still open

1. Run `pip-audit` against the release's pinned dependency set from a controlled
   environment before production acceptance.
2. If SCA is pursued, create and independently review a dedicated SCA registry
   using official Wazuh check-event semantics.
3. Prove one real two-host scan, tenant binding, latest-scan replacement,
   cross-tenant denial, and zero incident pollution.
4. Only then enable `WAZUH_SCA_ENABLED` and hand a stable API contract to the
   authoritative frontend checkout.
5. Deploy through the normal release process and record exact Git/image/runtime
   identities. Until then, production remains unchanged.
