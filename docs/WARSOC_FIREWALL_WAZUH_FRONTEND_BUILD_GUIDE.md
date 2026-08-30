# WarSOC Firewall and Detection Frontend Build Guide

**Status:** Implementation contract for the frontend team
**Backend snapshot:** 2026-08-20 RC2 closure workspace
**Rule:** The customer product is WarSOC. Do not display Wazuh names, logos,
rule IDs, manager/API details, or a second detection engine.

## 1. What the frontend must build

Build one **Firewall Relays** workspace inside the existing authenticated
dashboard. It manages metadata-only customer firewall collection and shows
relay/device health. It does not configure firewall policy and does not display
packet payloads, PCAP, credentials, raw syslog, Azure details, or internal
detector provenance.

A local correction candidate based exactly on frontend `6ffc9e0` now implements
this contract in `src/assets/Components/OperationsViews/OperationsViews.jsx`
and `src/assets/Pages/Dashboard/Dashboard.jsx`. Source assertions, ESLint and
the production build pass. It is not pushed, deployed or paired-tested; keep
the feature disabled until the acceptance section closes.

## 2. Visibility and roles

1. Keep the Vite flag only as a deployment kill switch.
2. After login, call `GET /api/v1/network-relay/status`.
3. Show the workspace only when the request succeeds and
   `capability.entitled` is `true`.
4. `capability.can_manage=true` enables management controls.
5. Admin may generate activation, revoke, and authorize key recovery.
6. Manager, analyst, and auditor may view status but must not see enabled
   management controls.
7. A 404 means the module is disabled. A 403 means the user or tenant is not
   authorized. Show a generic unavailable/not-included state, not backend
   internals.

Never use a frontend role check as the security boundary; the backend remains
authoritative.

## 3. Status API

### Request

```http
GET /api/v1/network-relay/status
Authorization: Bearer <session token>
```

### Response shape

```json
{
  "capability": {
    "enabled": true,
    "entitled": true,
    "max_relays": 1,
    "active_relays": 1,
    "remaining_relays": 0,
    "can_manage": true,
    "metadata_only": true,
    "validated_firewall_vendors": ["pfsense"]
  },
  "relays": [
    {
      "relay_id": "...",
      "relay_name": "Branch firewall relay",
      "hostname": "...",
      "version": "...",
      "status": "active",
      "health": "ACTIVE",
      "last_seen": "...",
      "last_seen_age_seconds": 10,
      "last_health_state": "ACTIVE",
      "last_health_reason": null,
      "last_sequence": 42,
      "device_count": 1,
      "device_health_summary": {"ACTIVE": 1},
      "devices": [
        {
          "device_id": "edge-fw-01",
          "vendor": "pfsense",
          "model": "2.8.1",
          "transport": "udp",
          "expected_eps": 100,
          "health": "ACTIVE",
          "last_event_at": "...",
          "last_event_age_seconds": 8,
          "last_event_type": "NET-CONNECTION-BLOCK",
          "time_confidence": "HIGH",
          "detected_clock_offset_seconds": 0,
          "last_failure_at": null,
          "last_failure_reason": null,
          "last_reported_drops": 0,
          "last_reported_dropped_bytes": 0
        }
      ]
    }
  ]
}
```

Read `relays`, not `items` or `data`. Device rows are nested under each relay;
do not invent flattened vendor, model, drop, or event fields on the relay.

## 4. Admin setup flow

Use a compact setup form with these required fields:

- Relay name.
- Device ID.
- Vendor. Only values returned by
  `capability.validated_firewall_vendors` may be offered commercially.
- Model/firmware label.
- Approved source IP address or CIDR.
- Transport.
- Device timezone.
- Expected events per second.
- Relay LAN listener IP and UDP port. The address must be the explicit unicast
  address of the always-on Windows relay host, not `0.0.0.0`.

### Generate activation

```http
POST /api/v1/network-relay/generate-activation
Content-Type: application/json
```

```json
{
  "relay_name": "Branch firewall relay",
  "devices": [
    {
      "device_id": "edge-fw-01",
      "vendor": "pfsense",
      "model": "2.8.1",
      "source_addresses": ["192.0.2.1"],
      "transport": "udp",
      "timezone": "UTC",
      "expected_eps": 100
    }
  ],
  "listeners": [
    {
      "transport": "udp",
      "bind_host": "192.0.2.10",
      "port": 5514
    }
  ]
}
```

The response contains `activation_code`, `expires_in_seconds`, and a `setup`
object containing the validated `relay-config.json` data. Show the code once
with a copy button and expiry. Offer the configuration as a local JSON download.
When `setup.package_available=true`, the admin may open the authenticated
`GET /network-relay/setup-package` route to download the approved versioned
setup kit. Do not persist the code in local storage, logs, analytics, URLs, or
browser history, and do not insert it into the configuration file.

## 5. Relay actions

### Revoke

```http
POST /api/v1/network-relay/{relay_id}/revoke
{"reason":"Decommissioned branch relay"}
```

Require confirmation and a reason. Revocation is not a normal status toggle.

### Authorize dead-key recovery

```http
POST /api/v1/network-relay/{relay_id}/authorize-key-recovery
{"reason":"Approved relay host rebuild","totp_code":"123456"}
```

Use a separate high-risk modal. Never store the TOTP code. The relay performs
the later recovery handshake; the browser must not call `/recover-key`.

## 6. Customer presentation

Use these WarSOC concepts only:

- **WarSOC Detection** for incident authority.
- **Endpoint evidence** and **Firewall metadata** for evidence source.
- **Relay attested** when explaining legacy UDP provenance.

Do not label a normal allowed/blocked firewall record as an attack. It becomes
an incident only when the backend returns a WarSOC incident. Existing incident
and evidence views continue to use their current APIs; the browser must never
call the Wazuh manager, indexer, dashboard, bridge, or candidate API.

## 7. Required UI states

- Loading without clearing the last successful view.
- Not included for an unentitled tenant.
- Disabled/unavailable for backend 404.
- Read-only for authorized non-admin roles.
- Empty: entitled but no relay registered.
- Active, degraded, offline, silent-device, inactive, and revoked states.
- Generic retry state for network/5xx failure.
- Explicit one-time activation success and expiry.

Do not expose exception text, database names, collection names, environment
variables, stack traces, internal route identities, or detector names.

## 8. Acceptance before enablement

1. Frontend lint and production build pass.
2. Admin can create a valid activation request with one pfSense device.
3. Manager, analyst, and auditor can read but cannot manage.
4. Unentitled tenants cannot see or call management actions.
5. Relay and nested device health render from the exact API response.
6. Revoke and recovery require confirmation and produce a refreshed state.
7. Activation codes never enter storage, logs, URLs, or analytics.
8. No Wazuh/vendor detector identity appears in customer HTML, requests, or
   incident output.
9. 404, 403, timeout, empty, degraded, and offline states are exercised.
10. The feature remains off until the accepted frontend commit, backend commit,
    deployment configuration, and post-deploy authenticated smoke test are
    recorded together.
