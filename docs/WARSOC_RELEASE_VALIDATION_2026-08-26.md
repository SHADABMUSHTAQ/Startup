# WarSOC Release Validation - 2026-08-26

**Candidate:** local branch `codex/warsoc-release-reconcile-20260812`, base
commit `6c3900f`, with the uncommitted evidence/retention/relay/Wazuh candidate.

**Decision:** source validation passes; runtime release acceptance remains open.
No production service, Azure blob, locked policy or historical record was
modified by this validation.

**Frontend correction candidate:** branch
`codex/frontend-relay-retention-contract`, based exactly on frontend
`6ffc9e0`, in `tmp/frontend-contract-fix-20260826`. It is local and has not
been pushed or deployed.

## Validated

- 533 maintained tests collected successfully.
- 323 service-independent cases passed with zero assertion failures.
- 175 focused retention/evidence/firewall-relay/Wazuh cases passed.
- PECA source contracts prove `TENANT_ENTITLEMENT_V1`, tenant-day routing,
  historical-row isolation, archive failure preserving Mongo and legal-hold
  recheck preserving Mongo.
- SIEM rule execution, FBR rule separation, endpoint signing, source envelopes,
  reports/privacy, relay parser/spool/runtime and Wazuh projection/transport
  contracts pass in source.
- Python compile, production Compose render, `git diff --check`, secret/key index
  hygiene and high-severity Bandit pass.
- Generated API authorization inventory: 122 routes, zero manual review.
- Current frontend `origin/main`: ESLint pass and production build pass.
- The local frontend correction candidate passes zero-warning ESLint, its
  production Vite build, `git diff --check`, exact relay-field assertions and
  a scan proving the stale fixed-vault fallback patterns are absent.

## Runtime Gates Still Open

1. Run the complete 533-test suite against isolated MongoDB and authenticated
   Redis. The previous 523-test campaign belongs to the earlier candidate.
2. Start isolated API, unified worker and storage archiver containers from the
   exact candidate image, never from production volumes.
3. Enroll a test tenant with a non-default retention duration and ingest one
   correctly signed PECA Windows event. Prove the source envelope and
   `peca_forensic_logs` record both contain `TENANT_ENTITLEMENT_V1` and the exact
   tenant-day snapshot.
4. Backdate only the isolated test record beyond the seven-day hot boundary and
   prove upload to its locked `GENERAL_<days>` test container, exact-byte
   SHA-256 verification, immutability through the required date, archive ledger
   commit and exact-ID Mongo deletion.
5. Repeat with the target route missing or insufficiently locked. Expected:
   archiver failure and Mongo record retained.
6. Repeat with an active legal hold. Expected: verified archive may exist, but
   the Mongo record remains. Release the test hold and prove normal behavior.
7. In the same isolated stack prove one SIEM event/detection/incident, one FBR
   semantic or configured-FIM event, hot CSV and hot PDF. Their active retention
   and API behavior must not change.
8. Pair the corrected relay frontend with the enabled test backend, entitled
   test tenant and an isolated relay. Prove activation, registration, signed
   batch admission, nested device status, loss reporting and revoke/recovery.
9. Repeat the approved Wazuh shadow canary on the separate lab host through the
   private transport. Prove signed dispatch/candidate lineage, quarantine of
   unbound/mismatched data and no customer-visible second detection engine.

## Environment Findings

- Docker Desktop processes were running, but this validation sandbox was denied
  access to the Docker named pipe and could not start Windows services.
- An isolated MongoDB 8.2 process was started under `tmp/integration-mongo`.
- No real Redis-compatible server was accessible. A fake substitute was not
  used as runtime evidence because it would invalidate stream/Lua behavior.
- Local Azure configuration has the historical global fallback but no
  duration-specific general routes. Production evidence was deliberately not
  used for a destructive acceptance test.
- The pfSense lab responds to ICMP at `192.0.2.1`; HTTPS was unavailable and the
  prior synthetic route was absent. The separate Wazuh laptop was not reachable
  in this session.

## Frontend Findings

- Production API binding is `https://api.warsoc.tech/api/v1`.
- The local correction reads `capability` and `relays[].devices[]`, submits the
  exact relay/device activation body, derives allowed vendors from the backend,
  keeps one-time codes in memory and exposes the workspace only after the
  deployment flag plus successful entitled capability response. Non-admin
  roles receive read-only status.
- Compliance, pricing, quote and legal views now use the tenant entitlement
  returned by `/compliance/retention/status`. Missing runtime data is displayed
  as unavailable; the browser no longer invents a fixed PECA/FBR vault period.
  Existing immutable records and legal holds are explicitly preserved as
  possible over-retention.
- The corrected dashboard bundle is 1,388.72 kB minified / 431.32 kB gzip and
  remains a startup performance target.
- These are source/build results. Authenticated paired relay behavior and the
  deployed retention response remain runtime acceptance gates.

## Release Verdict

```text
source regression and security gates     PASS
PECA retention source contract           PASS
frontend compile/lint                     PASS
real Mongo + Redis full campaign          OPEN
isolated Azure success/failure/hold proof OPEN
paired firewall relay acceptance          OPEN
paired Wazuh shadow acceptance             OPEN
frontend relay/retention source contract   PASS - local correction candidate
frontend paired/deployed acceptance        OPEN
production deployment                      NOT APPROVED
```
