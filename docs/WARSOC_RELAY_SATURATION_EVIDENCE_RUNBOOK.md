# WarSOC Network Relay Saturation and Fault Evidence Runbook

**Status:** `PENDING` — Gate 4 of the six production gates
**Purpose:** Prove the relay and backend behave correctly under saturation,
fault injection, and adversarial conditions at measured EPS. Produce the
drop-rate, spool-growth, and recovery-time evidence required before the
24-hour pilot (Gate 5).
**Production impact:** None (lab only)
**Required production state:** `NETWORK_RELAY_ENABLED=false` (local test backend only)

## 1. Acceptance Boundary

This runbook can approve the relay's **behavioral limits** on one recorded
hardware profile and backend configuration. It cannot approve:

- Physical firewall models (see Gate 3)
- Pilot operations or customer-facing SLAs (see Gate 5)
- PECA retention classification (see Gate 6)

## 2. Test Environment

| Item | Requirement |
|---|---|
| Relay host | Windows Server VM matching Gate 2 spec |
| Local backend | Docker Compose dev stack, `NETWORK_RELAY_ENABLED=true` |
| Load generator | `locustfile.py` or custom UDP syslog sender |
| Monitoring | Docker stats + relay service logs + backend API metrics |
| Baseline hardware | Record: CPU cores, RAM, disk type (SSD/HDD), network |

Record the measured baseline before starting:

```bash
docker stats --no-stream
```

## 3. Scenarios

Each scenario must run for at least the specified duration. Record: input EPS,
accepted EPS, dropped EPS (with drop reason), spool size, relay CPU %, relay
memory MB, backend CPU %, and end-to-end latency (device_event_time to cloud
receipt).

### Scenario A: Steady-State Throughput

- **Input:** 100 EPS sustained for 10 minutes (the `expected_eps` default)
- **Pass criteria:** 0 evidence drops, spool drains to empty within 60s of
  input stop, latency p99 < 5s

### Scenario B: Burst Overload

- **Input:** 2000 EPS (the `global_eps` cap) for 60 seconds, then stop
- **Pass criteria:** Token bucket admits at the configured rate, excess is
  counted in loss-control records (not silently discarded), spool drains after
  input stops, no crash, no spool corruption (verify_chain passes)

### Scenario C: Spoof Flood

- **Input:** 5000 EPS from an unregistered source IP for 60 seconds
- **Pass criteria:** All spoofed messages rejected by device-contract check
  (per-device bucket BEFORE global bucket — verified in code), zero spoofed
  records enter the evidence spool, legitimate traffic continues uninterrupted

### Scenario D: Disk Reserve Exhaustion

- **Method:** Set `minimum_free_disk_bytes` above actual free disk, then send
  traffic
- **Pass criteria:** Relay stops accepting new evidence with a clear
  disk-reserve error, never corrupts existing spool, recovers automatically
  when disk is freed

### Scenario E: Cloud Outage and Replay

- **Method:** Stop the backend Docker containers, continue sending traffic
  for 1 hour, restart the backend
- **Pass criteria:** Outbox retains all pending batches (encrypted), replay
  after backend restart delivers byte-identical batches (exact-retry),
  duplicate-ack handling works, zero evidence loss

### Scenario F: Revocation Under Load

- **Method:** Revoke the relay while it is sending at 100 EPS
- **Pass criteria:** Backend rejects subsequent batches immediately (within
  one request), relay stops retrying after receiving the revocation signal,
  no evidence accepted after the revocation timestamp

### Scenario G: Dead-Key Recovery

- **Method:** Trigger the dead-key recovery flow while the relay has pending
  outbox batches
- **Pass criteria:** Recovery increments the key epoch, chain resets to
  genesis, previously pending batches with the old key are rejected
  (fail-closed), new batches with the new key are accepted, evidence spool is
  preserved (never deleted)

### Scenario H: Parser Budget Saturation

- **Input:** Send malformed/adversarial messages designed to hit the
  parser time budget (25ms default)
- **Pass criteria:** Parser budget is respected (no single message blocks the
  event loop), losses are attributed to the correct device, other devices'
  evidence continues flowing

## 4. Evidence Collection Template

For each scenario, record:

| Metric | Scenario A | B | C | D | E | F | G | H |
|---|---|---|---|---|---|---|---|---|
| Input EPS | | | | | | | | |
| Accepted EPS | | | | | | | | |
| Dropped (rate-limited) | | | | | | | | |
| Dropped (disk) | | | | | | | | |
| Spool peak (bytes) | | | | | | | | |
| Relay CPU peak (%) | | | | | | | | |
| Relay memory peak (MB) | | | | | | | | |
| Latency p99 (s) | | | | | | | | |
| Recovery time (s) | | | | | | | | |
| Evidence loss count | | | | | | | | |

## 5. Evidence Bundle

Collect into a single directory (NOT committed to git):

- The completed metrics table above
- Relay service-output.log and service-error.log for each scenario
- Backend API container logs for each scenario
- `docker stats` snapshots at peak load
- Spool verify_chain() output after each fault scenario
- Outbox pending-count before/after replay (Scenario E)

## 6. Writing the Evidence Document

After all scenarios pass, write `docs/WARSOC_RELAY_SATURATION_EVIDENCE.md` with:

1. The environment spec (hardware, versions, config values)
2. The completed metrics table
3. Narrative analysis of each scenario (what happened, why, any deviations)
4. Known limits discovered (e.g., maximum sustainable EPS, disk headroom needed)
5. Operator sign-off

## 7. Recording the Result

Update this runbook's status header to:

```
**Status:** `SATURATION_PROVEN` at <measured EPS> EPS, <date>
```
