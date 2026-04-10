# Phase 4 Gate Decision (2026-04-05)

## Scope
Phase 4 validates deployment resilience, sustained ingest behavior, queue backpressure, and crash-signature hygiene before production release.

## Evidence Snapshot
- Sustained ingest pulse completed: 120 batches x 25 events = 3000 events.
- Observed duration: ~24.9s (~120 events/sec).
- HTTP outcomes during pulse: 200=120, 401=0, 403=0, 413=0, 429=0, 5xx=0.
- Queue health after pulse (`raw_logs_queue` groups):
  - `fbr_group`: pending=0, lag=0, entries-read=3013
  - `peca_group`: pending=0, lag=0, entries-read=3013
  - `siem_group`: pending=0, lag=0, entries-read=3013
- API critical/degraded signature count in recent window: 0
  - pattern set: `CRITICAL|Traceback|Error -5 connecting to redis|Redis unavailable|queue unavailable|Pipeline crash`

## Severity-Weighted Findings Matrix

| Severity | Finding | Evidence | Impact | Required Action |
|---|---|---|---|---|
| High | Repeated worker reclaim parser error persists in all 3 workers (`XCLAIM` non-fatal `list index out of range`) | Recent-window counts: SIEM=435, FBR=435, PECA=435 occurrences | Under normal flow the queue drains, but during worker crash/restart scenarios reclaim logic can fail when pending recovery is needed. This is a resilience risk and can delay or strand messages in edge conditions. | Patch reclaim response parsing in all workers, then run a forced pending-recovery drill (kill/restart consumer with pending entries) and confirm zero reclaim errors. |
| Low | Compose warning about obsolete `version` key | `docker compose` repeatedly warns: `the attribute version is obsolete` | No immediate runtime impact, but adds operator noise and can hide important warnings. | Remove top-level `version` from compose file in a cleanup pass. |

## Gate Decision
- Phase 4 Gate: FAIL

## Official Release Recommendation
- Production GO/NO-GO: NO-GO

## Exit Criteria to Flip to GO
1. Reclaim error count is zero for all workers under sustained pulse (same or higher load profile).
2. Pending-recovery chaos drill passes (create pending, kill consumer, restart, reclaim succeeds, pending returns to zero).
3. Re-run Phase 4 checklist and retain updated artifact evidence.
