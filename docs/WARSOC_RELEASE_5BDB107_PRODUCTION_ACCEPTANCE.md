# WarSOC Backend Release 5bdb107 Production Acceptance

**Accepted:** 2026-09-08

**Environment:** OCI production

**Executable revision:** `5bdb1076f9c44a60066ef06b669c8a861f7e8cb5`

**Release path:** `/opt/warsoc/releases/5bdb107`

## Scope

This release activates the supported commercial retention routes, hardens the
native WarSOC detector, and enables Security Stories V1. It does not promote
Wazuh to a primary detector, enable historical archive retrieval, qualify real
Windows Server hardware, or change the endpoint agent binary.

## Delivered Behavior

- Tenant retention is restricted to 90, 180, 270, or 365 days.
- Each duration has an exact private Azure `SIEM_<days>` and
  `GENERAL_<days>` Cold/version-WORM route.
- Unsupported or mismatched retention routes fail closed.
- Private, non-global, malformed, trusted, loopback, unspecified, and multicast
  addresses cannot trigger public threat-intelligence findings unless a valid
  private indicator has been explicitly approved; control addresses remain
  non-actionable under every override.
- Windows Event 4616 detects clock movement of at least five minutes from
  structured previous/new timestamps.
- Windows Event 4698 inspects only bounded scheduled-task executable action
  fields and rejects malformed, DTD, entity, or oversized XML.
- Security Stories runs as an independent Redis/Mongo projection. It cannot
  roll back canonical ingestion, SIEM, PECA, FBR, incidents, custody, or archive
  processing.

## Verification Evidence

| Gate | Result |
|---|---|
| Focused retention/detection/story release gate | 112 passed |
| Complete maintained backend suite | 684 passed, 2 expected skips |
| Final detector-focused regression | 45 passed |
| API authorization inventory | 132 routes, zero manual-review routes |
| Production/development requirements audit | No known vulnerabilities |
| Production image dependency check | Pillow 12.3.0, pip 26.2.1, no `ecdsa` |
| Bandit high-severity gate | Zero high-severity findings |
| Python compilation, `pip check`, diff hygiene | Passed |

The immutable release archive SHA-256 was
`d6518f5d6803ef1835ea2c4b0e88425eee1002d2935cd5d851ec21047edb2225`.
All eight application containers use image ID
`sha256:008446b680622714cadf8ba80c7130f0591c400562fffa51189501b3072a1b57`,
carry the exact Git revision label, run with zero restarts, and showed no error,
critical, or traceback lines in the final bounded log window. Public and
container-local health checks reported healthy MongoDB and Redis.

### Signed detection and story canary

Run `DETECTION-STORY-20260908T055417Z-8a55d8` sent 15 labelled, correctly
signed Windows-shaped events through the public API. It proved:

- all 15 reached the SIEM vault with zero admission rejection;
- the large clock-change and suspicious scheduled-task rules each created a
  versioned alert and incident;
- the small clock change and normal task XML did not trigger those rules;
- ten failed remote logons followed by a successful logon created one
  high-confidence server-account-compromise story;
- cross-tenant reads, auditor access, analyst writes, and stale versions were
  denied correctly;
- canonical outbox and PECA processing remained independent;
- all labelled non-audit tenant/source records were removed after the run.

This is synthetic server-context validation, not real Windows Server hardware
qualification. The other four positive Story families remain covered by the
maintained integration suite rather than this production canary.

### Feature rollback

Run `STORY-FLAG-20260908T055848Z-555a78` set Stories off and recreated only the
API and unified worker. Status reported disabled, list/summary returned 404,
core SIEM/FBR/PECA/retention heartbeats remained healthy, and no canonical
evidence was mutated. The run then restored Stories. Its worker heartbeat was
2.1 seconds old and `security_story_group` had zero pending entries and zero
lag. The labelled fixture tenant was removed.

### Retention

The existing 90-day acceptance and runtime canary
`retention_canary_20260907T191203Z_dca3a697` together prove all eight Azure
routes, exact locked duration, class separation, streamed hash readback,
version identity, ledger-before-delete, Legal Hold fail-closed behavior, and
exact hot deletion. Existing legacy blobs and immutable policies were not
changed.

## Accepted Runtime State

| Setting | Production state |
|---|---|
| Endpoint signatures | `required` |
| Security Stories | enabled |
| Network relay backend | enabled; tenant entitlement defaults to zero |
| Wazuh | shadow only; primary approval false |
| Exact Azure retention routing | required |
| Historical archive retrieval | disabled |
| Windows Server monitoring profile | disabled / not hardware-qualified |

## Remaining Independent Gates

- Build and accept the Security Stories frontend before calling it a complete
  customer workflow.
- Qualify the Windows Server monitoring profile on real supported hardware.
- Keep Wazuh shadow-only until rule-family promotion criteria are separately
  met; this release does not authorize primary mode.
- Historical archive retrieval remains unavailable until its Azure staging,
  identity/SAS, quota, expiry, UI, and download acceptance gate passes.
- The relay backend is enabled, but each customer still requires an entitled,
  source-restricted onboarding and package/device acceptance. pfSense is the
  only currently validated vendor family.

No remaining item above invalidates the accepted endpoint, SIEM, PECA, FBR,
incident, evidence-governance, exact-retention, or scoped Security Stories
backend paths.
