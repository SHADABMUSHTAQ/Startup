# WarSOC Hybrid Detection and Health Closure

## Scope and Execution Record

User decision: keep native WarSOC detection authoritative and Wazuh in shadow.
Do not promote detector families, redesign the frontend, alter retention, delete
queued evidence, or repeat the previously completed full regression campaign.

**Release outcome:** backend `893b190` is pushed to `origin/backend` and active
at `/opt/warsoc/releases/893b190` on OCI. The affected workstation runs the final
4.2.15 executable. At 2026-09-26 15:09:07 UTC, authenticated `/data/status`
reported `active`, no health issues, verified required signatures, and the
accepted heartbeat version `4.2.15-Native-Signed-Server-V1`. This closes the
scoped workstation recovery, not the separate offline ALPHABAY relay or every
historical rejection. No frontend changes or deployment were performed.

### System Map

```text
Signed Windows agent / signed firewall relay
  -> authenticated, tenant-bound admission
  -> canonical evidence and durable source outbox
  -> Redis -> native WarSOC SIEM -> alerts -> operator incidents
  -> canonical Mongo projection -> encrypted bounded Wazuh outbox
     -> private bridge/manager -> validated shadow observations

Native Wazuh agent -> tenant/endpoint binding -> SCA posture
  (this binding must not disable the separate security projection above)

Signed heartbeat -> /data/status -> endpoint health and recovery guidance
Signed relay batches -> /network-relay/status -> relay/device health
  -> watchdog -> durable health evidence -> operator incidents
```

### Initial Findings and Recovery Actions

- Live configuration: native SIEM active; Wazuh `shadow`; primary approval false.
- Active registry: 31 governed shadow rules, not every Wazuh stock rule.
- Before this release, a native Wazuh binding suppressed Windows projections, including
  endpoints bound only for SCA. The active registry does not replace those
  projections with admitted native Windows security rules.
- The screenshot endpoint is online and signed, but agent 4.2.12 reports both
  Security/System readers degraded and a blocked spool at 524,285,846 of
  524,288,000 bytes. Audit policy is configured; free disk is about 63 GB.
  This is spool backpressure, not insufficient free disk or a stopped service.
- The screenshot relay is `Host Laptop Relay` on `ALPHABAY`. Its last accepted
  batch at the inspected checkpoint was 2026-09-26 10:13:26.995 UTC. Relay/device
  watchdog rows describe lost visibility, not a proven firewall attack.
- The unelevated session could not read ProgramData; an administrator-approved,
  read-only snapshot subsequently collected metadata for 56 records. The 50
  historical quarantined UIDs have durable outbox identities, the three sampled
  processing records are published, and the three sampled pending UIDs are not
  yet represented there. Identity presence alone does not prove byte equality.
- Agent 4.2.15 repairs bounded recovery. A separate maximum 16 MiB working
  reserve permits quarantine while collection is paused, but does not raise the
  500 MiB collection limit or bypass the 400 MiB resume boundary/disk reserve.
  Isolated accepted/quarantined records checkpoint before a later transient
  failure. Only durably accepted/preserved prefixes may be compacted.
- Fresh telemetry is scheduled ahead of an old outage spool; every fourth chunk
  is reserved for history while both exist. Per-file byte cursors and original
  timestamps remain intact. Legacy signature fallback epochs survive restarts.
- Recovery began with hash-verified backups under the protected ProgramData
  recovery directory. The executable-only upgrade preserved enrollment,
  signing key, configuration, audit policy and firewall settings. More than
  22 MiB had been durably acknowledged at the initial 14:32 UTC checkpoint.
  The final resume and fresh-event proof is recorded below.
- A temporary, bounded 40 events/second replay override has a maximum 20-minute
  lifetime and restores the previous service environment afterward. Ordinary
  limits, signature verification, quotas and backpressure remain enforced.
- The final fairness-enabled 4.2.15 executable was installed at 14:40 UTC with
  SHA-256 `34E8419B702FB36056D12F48D157BD54982B7744C88FAE1F4EE5F1F2A5745009`.
  The in-place upgrade again verified identity/configuration preservation and
  backed up the executable, evidence and cursors before replacing the binary.
- Azure published the installer and pilot manifest without overwriting older
  versions. Public download verification matched the 18,885,226-byte installer
  SHA-256 `DB98CD8BA1519F946F66D86740143CD31181D4F5211F544ABDA9A11D93C0B660`.
  These are hash-managed, unsigned pilot artifacts, not Authenticode-signed
  enterprise releases. Backend `550c722` first deployed the scoped fixes;
  `893b190` then corrected status version selection during historical replay.

### Work Queue

| Step | Change | State |
| --- | --- | --- |
| 1 | Map source, runtime flags and screenshot causes | COMPLETE |
| 2 | Remove SCA-binding suppression of signed security projections | COMPLETE; focused integration passed |
| 3 | Add additive, safe endpoint/relay health guidance | COMPLETE; focused API/contract checks passed |
| 4 | Group ongoing outages, suppress redundant offline-child warnings | COMPLETE; focused integration passed |
| 5 | Administrator diagnostic and backed-up in-place recovery | COMPLETE for this workstation; Active and fresh Security/System delivery proved |
| 6 | Run changed-area tests once and record results | COMPLETE; 30 scoped cases passed; full campaign not repeated |
| 7 | Deploy exact backend and publish verified agent artifacts | COMPLETE; runtime `893b190`, public installer/manifest 4.2.15 |
| 8 | Update authoritative architecture and frontend contract handoff | COMPLETE for this scoped release; frontend implementation remains separate |

### Acceptance Boundaries

- Local tests alone do not establish deployment. This release also has exact
  runtime identity and authenticated endpoint/relay API evidence.
- A heartbeat and valid event signature do not prove every event channel is
  currently delivering evidence.
- Clearing/resolving an incident does not repair the underlying relay or spool.
- Restoring a relay does not backfill UDP messages lost while its listener was
  stopped. Do not claim lossless firewall collection.
- Healthy queue snapshots do not establish zero overhead, customer capacity,
  Windows Server SCA qualification, or detection of every possible attack.

## Endpoint Recovery

Run in Administrator PowerShell on the affected endpoint:

```powershell
cd C:\Users\Lenovo\Desktop\Startup-backend
.\scripts\diagnose_endpoint_health.ps1
```

This reads service state, HTTPS health, file sizes and acknowledgement offsets;
it does not read event bodies or print secrets. Send its summary for the next
recovery step. A healthy `/health` alone does not prove event ingestion works.
Do not remove the spool or reset enrollment/cursors to make the badge green.
The published 4.2.15 recovery artifact is hash-verified against its pilot
manifest; 4.2.14 published objects remain untouched. Existing enrolled endpoints
can receive a controlled executable-only update with backup/rollback, retaining
their service identity and keys. New installations still require a valid
one-time activation through the installer contract. Do not uninstall first.
After restoring delivery, require decreasing pending bytes, an unblocked spool
below its configured resume boundary, fresh Security/System collection and
`/data/status` health `active`; merely starting the service is insufficient.

### Completed Workstation Recovery

1. Backed up executable, evidence, byte cursors, enrollment and service
   configuration under `C:\ProgramData\WarSOC\recovery`. Installed the final
   executable with SHA-256
   `34E8419B702FB36056D12F48D157BD54982B7744C88FAE1F4EE5F1F2A5745009`.
   Enrollment, signing key, configuration, audit policy and firewall were preserved.
2. Two finite maintenance windows used a bounded 40-events/second override.
   The second also used 16 MiB acknowledged-prefix compaction. Both restored
   their original service environment; normal 10-events/second replay and
   64 MiB compaction resumed. No permanent quota or spool-limit increase occurred.
3. Preserved the old, unchanged 80,949,019-byte rejection file by a single
   atomic move to
   `C:\ProgramData\WarSOC\recovery\legacy-quarantine-20260926T150225Z\rejected_logs.jsonl`.
   Read-only protection and SHA-256 readback verified
   `8594E3B83BD5492941545CDEE2F086204F063672DCB82976EB689D908CEBA932`.
   Its original verified backup and a disposition manifest remain protected.
   This is rejected-evidence preservation, not backend acceptance or Azure
   archival. Pending deliveries and byte cursors were not changed by this move.
   Automatic quarantine offloading remains disabled.
4. At 15:02:31 UTC the recovery helper recorded the spool below its 400 MiB
   resume boundary and restored normal settings. At 15:09:07 UTC the signed
   heartbeat reported 413,609,091 active-spool bytes, `blocked=false`, about
   61.98 GB free disk, configured auditing, and both channels `ok`.
5. Fresh Security event readback reached record 6,869,118 and System record
   121,018. Canonical signed evidence and published source outbox identities
   were verified. The labelled System 7045 canary
   `WSCRecovery-20260926T150400Z` was a disabled service, never started, then
   immediately removed. Its signed source envelope was published and dispatch
   `WZD_8446F977A536AFA83D099DDD803D8397` reached Wazuh as `delivered`.
6. No Wazuh attack candidate is expected for that benign service: rule 100617
   requires the suspicious-service feature, which was false. This proves
   delivery with the SCA binding intact, not a new positive attack-rule test.
   Native detections, original evidence and audit records were retained. A
   cleanup guard found no isolated canary-only incident to close, so no mixed
   incident was changed.
7. Exact OCI release identity and deployed `data.py`/`projector.py` SHA-256
   parity with the release directory were verified. After normalizing archive
   CRLF to Git's LF, their hashes match the committed `893b190` source.
   Required signatures, tenant boundaries, native SIEM
   authority, Wazuh shadow mode and primary approval false remain intact.
   Queue groups had zero pending/lag at the observed low-load checkpoint.

Local sanitized artifacts are retained under `tmp/`:

- `endpoint-final-upgrade-result-20260926.json`
- `legacy-quarantine-preservation-20260926.json`
- `endpoint-replay-bound-20260926.json`
- `endpoint-final-recovery-bound-20260926.json`
- `recovery-delivery-canary-20260926.json`
- `hybrid-live-check-893b190-final.json`
- `canary-canonical-shadow-proof-20260926.json`
- `canary-shadow-admission-20260926.json`
- `canary-incident-cleanup-20260926.json`

These artifacts contain sanitized metadata, not credentials or raw event bodies.
The remaining pending history is still draining. Neither this recovery nor a
zero-lag snapshot proves every historical rejection has been accepted.

## Relay Recovery and Log Meaning

- `NET-DEVICE-HEALTH / periodic_health`: relay status, not an attack.
- `RELAY_OFFLINE`: no accepted relay batch for over 900 seconds. Restore the
  relay host, `WarSOC_Relay` service and outbound backend HTTPS connectivity.
- `DEVICE_SILENT`: parent relay reachable, but device log evidence is stale.
  Verify pfSense remote syslog IP/port/transport/categories and registered
  source/listener rules. Use the installed service's actual name if customized.
- `NET-CONNECTION-BLOCK`: the firewall blocked a connection. A block alone is
  not proof of compromise; attack rules require their own evidence/thresholds.
- `NET-CONNECTION-ALLOW`: a connection was allowed, not necessarily malicious.

New repeated OFFLINE/SILENT evidence retains its normal archive-safe lifecycle
but shares one operational incident for an unchanged last-seen anchor. Fresh
reporting followed by another outage forms a new incident. Known offline or
revoked/inactive parents suppress redundant child warnings, not device evidence
or attack detection. Existing alerts/incidents are not retroactively deleted or
merged. Resolving/acknowledging an incident does not repair collection.

## Frontend Contract Handoff (No Redesign)

- `/data/status`: show each endpoint's `health_summary`, and on badge click
  show `health_issues[].code`, `summary`, `affected_channels`, `remediation`.
  Preserve the authoritative health value and spool usage/resume information.
- `/network-relay/status`: relay/device `health_issues[]` explains recovery.
  Distinguish parent relay offline from a reachable relay with a silent device.
- `/incidents`: `context.signal_kind=telemetry_health` means monitoring health,
  not an attack. Show the incident `title`/`message` and `context.remediation`.
  Retain acknowledge/resolve workflow; do not imply those buttons fix services.
- Existing clients may ignore these additive fields. Until the frontend uses
  them, the badge may still lack an explanation despite the corrected backend.

## Verification Record

- Focused selection: **19 passed in 7.40 seconds**, using isolated local
  Mongo/Redis test databases. Includes the active v3 registry with an SCA-bound
  endpoint, one durable projection on retry, no projection-created incidents,
  spool backpressure/recovery response, parent outage suppression, separate
  incidents after recovery and a new outage, tenant/relay isolation, and normal
  attack-incident minute grouping preservation.
- Additional newly added bounded/redacted guidance contract: **1 passed in
  0.51 seconds**. None of the first 19 tests was rerun.
- Changed Python modules compile successfully. High-severity Bandit checks
  passed; the final bounded-guidance helper is checked separately after its edit.
- Administrator diagnostic executed successfully; protected metadata was read
  through standard UAC approval, without broadening existing access controls.
- Seven new agent recovery cases passed: full-buffer quarantine, bounded reserve
  and disk-reserve rejection, isolated-progress retry, restart-safe cursors,
  stable legacy signatures, live/history fairness, and bounded heartbeat reserve
  metadata. Only the initially failing Windows-newline case was rerun after
  fixing actual byte accounting. No passing selection was repeated.
- The changed 4.2.15 installation-chain manifest contract passed. The earlier
  deployment-order assertion was corrected to match the existing profile-aware
  Compose build command; no deployment behavior was changed for that correction.
- The new status regression for an old replay event versus the installed
  signed-heartbeat version passed: **1 passed in 1.06 seconds**. The API now
  prefers the heartbeat version and only falls back to the event when needed.
- Total scoped cases: **30 passed** (20 health/projection, seven agent recovery,
  installation manifest, corrected deployment assertion, and version regression).
- `git diff --check` passed. Previously completed full regression/detection
  campaigns were not rerun. The previous full campaign recorded 828 passed,
  two skipped and one stale deployment assertion; this scoped run closed that
  assertion only, and is not a newly executed full-suite acceptance claim.
- One labelled, never-started System-service canary was created and removed in
  production. Its source, native detection and audit records were preserved.
- No changes to detection thresholds, signature enforcement, enrollment,
  evidence retention, legal holds, Wazuh promotion flags, response actions or
  historical/locked evidence. No new broad attack rules were introduced.

## Still Open

1. Monitor remaining pending backlog at normal limits and separately review the
   preserved historical 409 rejects. Outbox UID presence alone does not prove
   matching bytes or authorize readmission. Do not delete protected recovery
   backups or quarantine to make the product appear clean.
2. Restore the ALPHABAY relay host/service/connectivity and confirm fresh
   accepted device logs; confirm syslog separately if the parent recovers but
   the device remains silent.
3. Resolve the derived-timestamp discrepancy found during canary proof. Its
   original signed System time is `2026-09-26T15:04:00.8911357Z`, but the
   `siem_cold_vault.timestamp` readback is processing time
   `2026-09-26T15:05:30.460Z`. Original time remains in the encrypted source
   package; no historical record was rewritten. The current projector reads
   the derived timestamp, so historical-age filtering is not accepted end to
   end until source/processing time separation is verified and corrected.
   Do not promote Wazuh or advertise historical replay as live attack proof.
4. Frontend owner connects the additive recovery fields described above. No
   frontend redesign or frontend deployment was performed here.
5. Sustained load/precision and Windows Server SCA qualification remain their
   earlier named acceptance boundaries. The current low-load queue/resource
   snapshot is not proof of zero performance overhead or universal detection.
