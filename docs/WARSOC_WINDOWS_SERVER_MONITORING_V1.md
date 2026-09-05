# WarSOC Windows Server Monitoring V1

**Status:** Implemented engineering candidate; not deployed or customer-supported
**Candidate:** `4.2.13-Native-Signed-Server-V1`
**Contract date:** 2026-09-03
**Local installer:** 18,879,454 bytes; SHA-256
`6D1800F253EA74F3953BEED1F80B9A90DACD0EFCB90413503B543FE12FC41648`
**Publisher trust:** Not Authenticode-signed; exact-hash qualification only

## 1. Scope

General Server V1 extends the existing WarSOC Windows agent to one deliberately
narrow qualification target:

- Windows Server 2022 Standard, Desktop Experience, build 20348;
- AMD64/X86_64;
- Security and System event channels;
- the existing WarSOC detection/evidence pipeline;
- monitoring only, with no server-side automated response.

The profile does not claim support for domain controllers, IIS, file servers,
POS/database hosts, Linux, broad FIM, registry monitoring, network shares, or
customer-defined commands. Those require separate profiles and qualification.

## 2. End-to-End Architecture

```text
Tenant admin
    -> fixed backend General Server profile (revision + SHA-256)
    -> TLS response bound to the accepted signed-heartbeat request nonce
    -> agent validates host, tenant, agent, revision and exact profile hash
    -> atomic last-known-good profile state
    -> effective Windows audit-policy readback
    -> Security/System event allowlist
    -> event stamped with profile ID/version/hash/revision before signing
    -> durable local spool
    -> authenticated WarSOC ingestion
    -> canonical persistence and Redis fan-out
    -> WarSOC SIEM / PECA processing / incidents / evidence storage
    -> optional private Wazuh shadow projection after persistence
```

The browser and Wazuh are not required for collection. WarSOC remains the
authoritative product and incident owner.

## 3. Fixed Profile

The backend owns one immutable profile body: `general_server` version `1`.
Only expected revision, activation state, asset environment and asset criticality
are operator inputs. Unknown request fields are rejected.

The event allowlist is:

```text
1100 1102 4616 4624 4625 4648 4672 4688 4697
4698 4719 4720 4726 4732 4798 5157 7045
```

These support audit-log disruption, time changes, authentication, explicit and
privileged logon, process creation, service and scheduled-task persistence,
audit-policy changes, account/group changes, discovery and blocked connection
evidence. Existing WarSOC rules decide whether an event becomes a detection.

General Server V1 explicitly excludes file/registry auditing, share events,
domain-controller authentication events, POS paths, web paths and capture-all
modes.

## 4. Trust and Safety Boundaries

1. Registration host facts are restrictive only. They may force server safety,
   but cannot authorize server collection.
2. A signed heartbeat supplies the authoritative host facts used for profile
   eligibility and health.
3. Compatibility requires Server 2022 Standard build 20348, AMD64/X86_64 and a
   stable MachineGuid-derived fingerprint. This fingerprint detects unexpected
   image/identity changes; it is not hardware attestation.
4. Profile revisions are monotonic. Replays, same-revision substitutions,
   identity mismatches and malformed/oversized profiles fail closed.
5. The heartbeat response must echo the signed request nonce before the agent
   accepts a profile.
6. Profile state is atomically persisted. The previous revision is retained for
   diagnosis; a broken update does not replace the last known good profile.
7. The exact profile snapshot used to admit an event is embedded in that event
   before spool persistence and endpoint signing.
8. Servers never apply WarSOC IP-ban responses. `response_mode` is permanently
   `MONITOR_ONLY` for this profile.
9. Runtime profile delivery never executes arbitrary commands and never changes
   audit, firewall, GPO, registry, service or application configuration.

The installer may configure the approved local audit categories and process
command-line auditing on a fresh installation. It does not edit domain GPO.
Runtime readback uses the native Windows `AuditQuerySystemPolicy` API and reports
drift without remediation. Existing installations preserve their stored audit
rollback baseline instead of being silently rewritten.

## 5. Control API

The feature remains off unless the backend has:

```text
WINDOWS_SERVER_MONITORING_ENABLED=true
```

Catalog/status:

```http
GET /api/v1/agent/server-profiles
```

Admin-only assignment, tenant-scoped and compare-and-set revisioned:

```http
PUT /api/v1/agent/{agent_id}/server-profile
Content-Type: application/json

{
  "expected_revision": 0,
  "enabled": true,
  "environment": "staging",
  "criticality": "high"
}
```

Every requested change writes `management_audit` as `REQUESTED`, then `APPLIED`
or `CONFLICT`. A server is healthy only when the signed report ACKs the exact
desired revision and profile hash, the effective audit readback is fresh, and
all required audit controls are present.

## 6. Health States

```text
READY
PROFILE_PENDING
PROFILE_PAUSED
PROFILE_INVALID
PROFILE_APPLY_FAILED
HOST_UNSUPPORTED
HOST_IDENTITY_CHANGED
AUDIT_UNKNOWN
AUDIT_STALE
AUDIT_DRIFTED
```

Fleet health and audit coverage are degraded unless server profile health is
`READY`. Workstation health behavior remains unchanged.

## 7. Rollout Stages

### Stage A - Source and package proof

- focused unit/integration tests pass;
- full backend regression passes;
- PowerShell parses and the Windows executable/installer build;
- manifest hashes match all candidate files;
- feature flag remains false.

### Stage B - Disposable server qualification

Use a clean Windows Server 2022 Standard Desktop Experience AMD64 VM. Prove:

- fresh enrollment and automatic-service restart;
- signed heartbeat and compatible signed host facts;
- assignment revision 1 reaches exact ACK within one heartbeat interval;
- effective audit state is `AUDIT_OK`;
- each supported event family reaches raw evidence, WarSOC detection where a
  rule applies, PECA evidence where entitled, and an incident where applicable;
- unsupported events and paths are not collected;
- profile pause/resume, replay rejection and identity-conflict behavior;
- dashboard closure does not interrupt collection;
- server receives no ban/firewall response.

### Stage C - Failure and recovery proof

- disconnect network, generate events, reconnect and drain the spool exactly once;
- restart the service and host while events are queued;
- make a required audit setting ineffective and verify `AUDIT_DRIFTED` without
  WarSOC rewriting policy;
- send malformed, oversized, cross-agent and stale-revision assignments;
- verify backend/Redis interruption preserves endpoint evidence;
- verify no workstation regression.

### Stage D - Soak and acceptance

Run 24 to 72 hours on the qualification VM. Record agent CPU/RAM, spool growth,
ingestion latency, Redis lag, Mongo growth, detections and false positives.
Stop the qualification on any event loss, signature rejection, cross-tenant
visibility, profile mismatch, unexpected OS-policy change, automated firewall
change, crash/OOM, or backlog that does not drain after recovery.

Initial engineering investigation thresholds are sustained agent CPU above 5%
for 15 minutes, private working set above 300 MiB, a healthy-network spool that
grows for 15 minutes, or ingest/detection p95 above two seconds for 15 minutes.
These are abort thresholds for the first qualification, not supported-capacity
claims.

## 8. Verification Evidence

The 2026-09-03 local candidate completed:

- 109 focused server, endpoint, packaging and authorization tests;
- the full maintained campaign: 607 passed, one opt-in destructive isolated-stack
  test skipped, zero assertion failures;
- Python and PowerShell parsing plus embedded C# compilation;
- executable and installer compilation on Windows AMD64;
- exact verification of all five manifest artifacts;
- full deployable-tree high-severity Bandit scan with no findings;
- `pip-audit` with no known requirement vulnerabilities and `pip check` clean.

The current Windows 10 development host was correctly classified as a client and
the non-elevated audit query failed closed when its token lacked
`SeSecurityPrivilege`. The packaged agent service runs as LocalSystem and now
temporarily enables/restores that privilege around audit readback, but this still
requires proof on the target Windows Server VM.

## 9. Acceptance Boundary

Source tests or a successful workstation build do not approve Windows Server.
Customer support may be declared only after Stage B through D evidence is saved
against the exact installer hash. The current shared 50-agent platform ceiling
does not increase as part of this feature.
