# WarSOC Wazuh Lab Operator Runbook

**Purpose:** Prepare and validate the colleague's Wazuh machine without touching
WarSOC production.

**Status:** Lab compatibility proof only. Completing this runbook does not mean
the WarSOC-to-Wazuh integration is production-ready.

## 1. Hard Boundaries

1. Run these commands on the Linux machine or VM that hosts the Wazuh manager.
2. Do not run them on DigitalOcean/HostKey/Azure production.
3. Do not install a Wazuh agent on a customer endpoint. The WarSOC agent remains
   the endpoint collector.
4. Do not send pfSense directly to Wazuh. The eventual path is:

   ```text
   pfSense -> WarSOC Relay -> WarSOC canonical evidence -> Wazuh shadow
   ```

5. Do not expose Wazuh manager, enrollment, API or lab-ingress ports publicly.
6. Do not enable Wazuh Active Response, Wazuh email, `logall` or `logall_json`.
7. Do not send passwords, packet payloads, invoice contents, POS
   `processed_data`, secrets or production PII to the lab.
8. Do not copy a rule into the manager until its checksum and test corpus are
   supplied by the WarSOC repository.
9. Do not treat a `wazuh-logtest` match as complete WarSOC integration. The
   durable dispatch, candidate-return, tenant resolution and shadow comparison
   paths are separate acceptance gates.
10. Do not freeze decoders or rules against an alpha, beta or release-candidate
    Wazuh image. Manager, indexer and dashboard images must use the same approved
    stable release tag. As of 2026-08-10, the lab target is Wazuh `4.14.7`.
11. Default Docker demonstration credentials must be rotated before Section 6
    or any WarSOC event is submitted, even when host ports bind to loopback.

## 2. Create a Lab Evidence Directory

Run as the colleague's normal Linux account:

```bash
set -u
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LAB_DIR="$HOME/warsoc-wazuh-lab/$RUN_ID"
mkdir -p "$LAB_DIR"
printf '%s\n' "$LAB_DIR"
date -u | tee "$LAB_DIR/utc-time.txt"
uname -a | tee "$LAB_DIR/uname.txt"
cat /etc/os-release | tee "$LAB_DIR/os-release.txt"
timedatectl status | tee "$LAB_DIR/timedatectl.txt"
```

Keep the printed `LAB_DIR` value for every later command in the same shell.

## 3. Identify the Installation Type

```bash
if sudo test -x /var/ossec/bin/wazuh-control; then
  echo native-package | tee "$LAB_DIR/install-mode.txt"
elif command -v docker >/dev/null 2>&1; then
  echo possible-docker | tee "$LAB_DIR/install-mode.txt"
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' \
    | tee "$LAB_DIR/docker-ps.txt"
else
  echo manager-not-found | tee "$LAB_DIR/install-mode.txt"
fi
```

If the result is `manager-not-found`, stop. If it is `possible-docker`, complete
section 4B and send the artifacts before changing configuration. Docker volume
paths differ between deployments and must not be guessed.

## 4A. Native-Package Baseline

Run this section only when `install-mode.txt` says `native-package`:

```bash
sudo systemctl status wazuh-manager --no-pager \
  | tee "$LAB_DIR/wazuh-manager-status.txt"
sudo /var/ossec/bin/wazuh-control info \
  | tee "$LAB_DIR/wazuh-info.txt"
sudo /var/ossec/bin/wazuh-control status \
  | tee "$LAB_DIR/wazuh-processes.txt"
sudo /var/ossec/bin/wazuh-logtest -V \
  | tee "$LAB_DIR/wazuh-logtest-version.txt"
sudo sha256sum /var/ossec/etc/ossec.conf \
  | tee "$LAB_DIR/ossec-conf.sha256"
sudo grep -nE \
  'jsonout_output|alerts_log|logall|logall_json|email_notification|active-response|<remote>|</remote>|<auth>|</auth>|<port>|<protocol>|<local_ip>|<allowed-ips>' \
  /var/ossec/etc/ossec.conf \
  | tee "$LAB_DIR/relevant-config.txt"
sudo ss -lntup | tee "$LAB_DIR/listeners.txt"
sudo journalctl -u wazuh-manager --since '30 minutes ago' --no-pager \
  | tee "$LAB_DIR/wazuh-journal.txt"
sudo sh -c 'test -f /var/ossec/var/run/wazuh-analysisd.state && cat /var/ossec/var/run/wazuh-analysisd.state' \
  | tee "$LAB_DIR/analysisd-state.txt"
sudo sh -c 'test -f /var/ossec/var/run/wazuh-remoted.state && cat /var/ossec/var/run/wazuh-remoted.state' \
  | tee "$LAB_DIR/remoted-state.txt"
```

Create a recoverable configuration backup:

```bash
sudo install -d -m 0700 /var/backups/warsoc-wazuh-lab
sudo tar -C /var/ossec -czf \
  "/var/backups/warsoc-wazuh-lab/wazuh-etc-$RUN_ID.tar.gz" etc
sudo sha256sum \
  "/var/backups/warsoc-wazuh-lab/wazuh-etc-$RUN_ID.tar.gz" \
  | sudo tee "/var/backups/warsoc-wazuh-lab/wazuh-etc-$RUN_ID.tar.gz.sha256"
```

## 4B. Docker Baseline

Run this section only when `install-mode.txt` says `possible-docker`:

```bash
docker ps --no-trunc | tee "$LAB_DIR/docker-ps-full.txt"
docker compose ls | tee "$LAB_DIR/docker-compose-ls.txt"
docker compose config --images | tee "$LAB_DIR/docker-images.txt"
docker inspect $(docker ps -q) \
  --format '{{.Name}} {{.Config.Image}} {{json .Mounts}}' \
  | tee "$LAB_DIR/docker-mounts.txt"
sudo ss -lntup | tee "$LAB_DIR/listeners.txt"
sha256sum docker-compose.yml | tee "$LAB_DIR/docker-compose.sha256"
```

Identify the manager container from `docker-ps-full.txt`, then set its exact name:

```bash
export WAZUH_CONTAINER='REPLACE_WITH_MANAGER_CONTAINER_NAME'
docker exec "$WAZUH_CONTAINER" /var/ossec/bin/wazuh-control info \
  | tee "$LAB_DIR/wazuh-info.txt"
docker exec "$WAZUH_CONTAINER" /var/ossec/bin/wazuh-control status \
  | tee "$LAB_DIR/wazuh-processes.txt"
docker exec "$WAZUH_CONTAINER" /var/ossec/bin/wazuh-logtest -V \
  | tee "$LAB_DIR/wazuh-logtest-version.txt"
docker exec "$WAZUH_CONTAINER" sha256sum /var/ossec/etc/ossec.conf \
  | tee "$LAB_DIR/ossec-conf.sha256"
docker logs --since 30m "$WAZUH_CONTAINER" \
  | tee "$LAB_DIR/wazuh-container.log"
```

Stop after this section. The compose file and mount map must be reviewed before
editing a Docker installation.

## 5. Baseline Acceptance

Do not change the manager until all of these statements are true:

- The exact Wazuh version and installation type are recorded.
- The manager, indexer and dashboard use one approved stable tag; no alpha,
  beta or release-candidate image is accepted.
- `wazuh-analysisd` is running.
- UTC time synchronization is healthy.
- No Wazuh listener is exposed directly to the public Internet.
- Existing configuration and its SHA-256 hash are backed up.
- `events_dropped` and `discarded_count` are recorded; the required value during
  controlled tests is zero.
- Default Docker demonstration credentials are absent before proceeding to
  configuration or event submission. Credential values are never copied into
  the evidence archive.

If any statement is false, stop and send the evidence directory before continuing.

## 6. Required Manager Configuration

This section applies to a reviewed native-package installation. Use `sudoedit`;
do not replace the whole XML file.

```bash
sudoedit /var/ossec/etc/ossec.conf
```

Inside the existing `<ossec_config>` document, ensure the existing `<global>`
block contains these values exactly once:

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>
  <logall_json>no</logall_json>
  <email_notification>no</email_notification>
</global>
```

Ensure Active Response is disabled on the manager:

```xml
<active-response>
  <disabled>yes</disabled>
</active-response>
```

Add the lab ingress listener only if TCP port `15140` is unused. It must bind to
loopback and accept only the future local durable ingress process:

```xml
<remote>
  <connection>syslog</connection>
  <port>15140</port>
  <protocol>tcp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
  <local_ip>127.0.0.1</local_ip>
</remote>
```

Do not delete or alter unrelated blocks during this lab step.

Restart and immediately verify:

```bash
sudo systemctl restart wazuh-manager
sleep 5
sudo systemctl --no-pager --full status wazuh-manager
sudo /var/ossec/bin/wazuh-control status
sudo ss -lntup | grep -E '(:15140\b|wazuh)'
sudo journalctl -u wazuh-manager --since '5 minutes ago' --no-pager
sudo grep -nE 'jsonout_output|alerts_log|logall|logall_json|email_notification|active-response|15140|127.0.0.1' \
  /var/ossec/etc/ossec.conf
```

Required result: port `15140` is bound to `127.0.0.1`, not `0.0.0.0`, `::` or a
LAN/public address.

## 7. Verify the Stock JSON Decoder

This only proves Wazuh can parse the neutral WarSOC envelope. It does not prove a
WarSOC rule or live connector.

```bash
cat > "$LAB_DIR/detection-input-sanitized.json" <<'JSON'
{"schema":"warsoc.detection-input/v1","dispatch_uid":"lab-dispatch-0001","event_uid":"lab-event-0001","tenant_scope":"lab-tenant-opaque-a","source_family":"windows_endpoint","source_assurance":"endpoint_signed","original_event_time":"2026-08-10T12:00:00Z","receipt_time":"2026-08-10T12:00:01Z","dispatch_time":"2026-08-10T12:00:02Z","dispatch_mode":"live","event_age_ms":2000,"event_id":"4625","endpoint_id":"lab-endpoint-opaque-01","correlation_key_version":"corr-lab-v1","correlation_keys":{"corr_tenant":"lab-hmac-a","corr_tenant_source":"lab-hmac-b","corr_tenant_actor":"lab-hmac-c","corr_tenant_endpoint":"lab-hmac-d","corr_tenant_actor_source":"lab-hmac-e"},"security_fields":{"source_ip":"198.51.100.10","target_user":"lab-user"}}
JSON

sudo /var/ossec/bin/wazuh-logtest -v \
  < "$LAB_DIR/detection-input-sanitized.json" \
  | tee "$LAB_DIR/json-decoder-result.txt"
```

Record the decoded field names exactly. Do not change the WarSOC schema merely to
force a stock Wazuh rule to match.

## 8. Install the Approved WarSOC Rule Bundle

This phase cannot be completed until WarSOC supplies all of these files:

```text
warsoc_decoders.xml
warsoc_rules.xml
ruleset-manifest.sha256
positive JSONL corpus
negative JSONL corpus
boundary JSONL corpus
expected-results manifest
```

After receiving and verifying that bundle:

```bash
cd /path/to/approved/warsoc-wazuh-bundle
sha256sum --check ruleset-manifest.sha256
sudo install -o root -g wazuh -m 0640 warsoc_decoders.xml \
  /var/ossec/etc/decoders/warsoc_decoders.xml
sudo install -o root -g wazuh -m 0640 warsoc_rules.xml \
  /var/ossec/etc/rules/warsoc_rules.xml
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-control status
```

If checksum verification fails, stop. Never install that bundle.

## 9. Run Deterministic Rule Tests

Run every supplied event independently unless the expected-results manifest marks
the rule as stateful. Use a single persistent `wazuh-logtest` session for an
ordered stateful sequence.

Example single-event command:

```bash
printf '%s\n' 'REPLACE_WITH_ONE_SANITIZED_JSON_EVENT' \
  | sudo /var/ossec/bin/wazuh-logtest -v
```

For an expected rule ID, level and decoder, use Wazuh's assertion option:

```bash
printf '%s\n' 'REPLACE_WITH_ONE_SANITIZED_JSON_EVENT' \
  | sudo /var/ossec/bin/wazuh-logtest \
      -U 'EXPECTED_RULE_ID:EXPECTED_LEVEL:EXPECTED_DECODER'
echo "exit_code=$?"
```

The required corpus includes:

- correct positive events;
- normal administrative activity that must not alert;
- missing and malformed fields;
- old `historical_replay` events;
- duplicate dispatch identifiers;
- two tenants with identical users, addresses and endpoints;
- clock-skew boundaries;
- wrong source family and source assurance;
- PECA/FBR context candidates with missing linkage keys.

## 10. Exercise the Loopback Input

Do this only after the approved decoder/rule corpus passes:

```bash
python3 - "$LAB_DIR/detection-input-sanitized.json" <<'PY'
import pathlib
import socket
import sys

payload = pathlib.Path(sys.argv[1]).read_bytes().rstrip(b"\n") + b"\n"
with socket.create_connection(("127.0.0.1", 15140), timeout=5) as sock:
    sock.sendall(payload)
PY

sleep 3
sudo tail -n 20 /var/ossec/logs/alerts/alerts.json \
  | tee "$LAB_DIR/alerts-tail.jsonl"
sudo cat /var/ossec/var/run/wazuh-analysisd.state \
  | tee "$LAB_DIR/analysisd-state-after.txt"
sudo cat /var/ossec/var/run/wazuh-remoted.state \
  | tee "$LAB_DIR/remoted-state-after.txt"
```

Required result: the expected rule fires once, the dispatch UID is recoverable,
and both drop counters remain zero.

## 11. What Still Requires WarSOC Engineering

The colleague cannot complete these items by configuring Wazuh alone:

1. Post-persistence projector from canonical `siem_cold_vault` evidence.
2. Encrypted, idempotent detection-dispatch outbox.
3. Local durable Compute-B ingress and retry spool.
4. Signed/mTLS candidate return connector.
5. `alerts.json` crash-safe tailer and checkpoint.
6. Tenant resolution from `dispatch_uid`.
7. Semantic rule-registry validation and quarantine.
8. Shadow comparison against the current WarSOC detector.
9. PECA/FBR context linking against canonical evidence.
10. Dashboard/customer presentation.

Until those items pass, Wazuh remains a lab detector and WarSOC's current SIEM
remains authoritative.

## 12. Firewall Sequence

Firewall testing starts only after the endpoint JSON/rule path passes:

1. pfSense sends sanitized test syslog to the customer-side WarSOC Relay.
2. The Relay preserves original and receipt clocks, raw hash, device identity and
   `relay_attested` assurance.
3. WarSOC authenticates and persists canonical network evidence.
4. Only eligible normalized fields are projected to Wazuh shadow.
5. WarSOC resolves the returned candidate to the canonical network evidence.
6. Physical-device, EPS, spoofing, queue-loss and tenant-crossing tests pass.

Direct pfSense-to-Wazuh success is not WarSOC firewall integration proof.

## 13. Export the Lab Evidence

```bash
sudo journalctl -u wazuh-manager --since "$(cat "$LAB_DIR/utc-time.txt")" --no-pager \
  > "$LAB_DIR/final-wazuh-journal.txt" 2>&1 || true
sudo sha256sum /var/ossec/etc/ossec.conf \
  > "$LAB_DIR/final-ossec-conf.sha256"
sudo tar -C "$LAB_DIR" -czf "$HOME/warsoc-wazuh-lab-$RUN_ID.tar.gz" .
sha256sum "$HOME/warsoc-wazuh-lab-$RUN_ID.tar.gz" \
  > "$HOME/warsoc-wazuh-lab-$RUN_ID.tar.gz.sha256"
ls -lh "$HOME/warsoc-wazuh-lab-$RUN_ID.tar.gz" \
  "$HOME/warsoc-wazuh-lab-$RUN_ID.tar.gz.sha256"
```

Review the archive for secrets or production data before sharing it.

## 14. Rollback

For a native package, restore only if the manager fails after an approved change:

```bash
sudo systemctl stop wazuh-manager
sudo tar -C /var/ossec -xzf \
  "/var/backups/warsoc-wazuh-lab/wazuh-etc-$RUN_ID.tar.gz"
sudo systemctl start wazuh-manager
sudo /var/ossec/bin/wazuh-control status
```

Do not use this rollback command on Docker. Restore the reviewed bind mount or
named-volume backup for that deployment instead.
