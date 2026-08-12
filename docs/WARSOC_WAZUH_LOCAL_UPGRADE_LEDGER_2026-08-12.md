# WarSOC Local Wazuh Upgrade Ledger

**Machine role:** WarSOC development machine and optional secondary Wazuh lab

**Change date:** 2026-08-12

**Rule:** Functional and detection testing is deferred until the complete
WarSOC/Wazuh integration is assembled. Configuration validation may be used to
prevent an invalid deployment from being created.

## Baseline

| Item | Recorded state |
|---|---|
| Existing Wazuh checkout | `/home/lenovo/wazuh-docker` |
| Existing release | `v4.9.2` |
| Existing Compose SHA-256 | `5338548c507f39ee450ae37c23b5c9afa295c0c404aa9fa5c7c7402030fdc1c4` |
| Existing containers | Manager and indexer stopped; dashboard not running |
| Existing volumes | Preserved under the `single-node_` Docker volume prefix |
| Existing data deletion | None |

## Target

- Release: `v4.14.7` exactly.
- Checkout: `/home/lenovo/wazuh-docker-4.14.7`.
- Compose project: `warsoc-wazuh-local-4147`.
- New project must not attach any `single-node_` legacy volume.
- Manager, indexer, dashboard and API host ports remain loopback-only.
- WarSOC listener `15140` remains Docker-private and source-restricted.
- WarSOC bridge and candidate paths remain disabled until mTLS material and the
  final two-host topology are ready.

## Action Ledger

| Step | Action | Expected result | Rollback |
|---:|---|---|---|
| 1 | Inventory old checkout, containers and volumes | Exact baseline recorded | None required; read-only |
| 2 | Clone official Wazuh Docker tag `v4.14.7` to the target checkout | Pinned, separate source tree | Delete only the new checkout |
| 3 | Assign the isolated Compose project name | New container and volume namespace | Stop the new project without `-v` |
| 4 | Restrict all host-published ports to loopback | No Wazuh central port exposed on LAN or internet | Restore target Compose backup |
| 5 | Add reviewed WarSOC private listener and canary files | Integration-ready configuration, still inactive | Restore target configuration backup |
| 6 | Generate target certificates and create target services | New volumes only; legacy stack untouched | Stop new project; preserve both volume sets |
| 7 | Defer functional/detection tests | No premature acceptance claim | Run documented acceptance later |

## Applied Upgrade State

| Item | Applied result |
|---|---|
| Official source | Tag `v4.14.7`, commit `adcc5b57d2f7edfcbe6c399272dc76fbdf12b623` |
| Target checkout | `/home/lenovo/wazuh-docker-4.14.7` |
| Compose project | `warsoc-wazuh-local-4147` |
| Manager image | `wazuh/wazuh-manager:4.14.7`, digest `sha256:c364ef100ba40d501537b1668a5a72bba4c4fbcf39bbef6a02123ff221fc40d0` |
| Indexer image | `wazuh/wazuh-indexer:4.14.7`, digest `sha256:fba7f2a0c441d0df54f93d22326ceae795051e60d0030ceb3ee3cde3b8defe7e` |
| Dashboard image | `wazuh/wazuh-dashboard:4.14.7`, digest `sha256:b175a3957b0d4e14ec88fdc02a7abae2cbe15a1780a41345b353f7652763c22e` |
| Generated certificates | 12 files generated in the target checkout; no legacy certificate tree reused |
| Original target Compose hash | `6d9c7f8fdffe291ff5711f9e8fa6c535b94b22c551eed1cc46a86225abf576d3` |
| Loopback target Compose hash | `561a4b489b1b945eace3c1e4d7b50b34bc1c7f1b36d634aa5419cc53717ad4ed` |
| Original manager config hash | `b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce` |
| WarSOC manager config hash | `f99027ed1bf26bae56fe873e68264f12c90fc242344ca486a4587e5f69f44f9e` |
| Docker network | `warsoc-wazuh-local-4147_default`, subnet `172.19.0.0/16` |
| Current service addresses | Manager `172.19.0.2`, indexer `172.19.0.3`, dashboard `172.19.0.4` |
| Reserved bridge address | `172.19.0.50` |
| WarSOC manager listener | Container-only TCP `15140`, allowed source `172.19.0.50` |
| WarSOC canary rule | Rule `100500` installed; no canary event generated yet |
| Published Wazuh ports | `443`, `514/udp`, `1514`, `1515`, `9200`, and `55000` bind only to `127.0.0.1` |
| Active Response | Not enabled by this upgrade |
| Production integration | Not enabled by this upgrade |

The three target services were started successfully with restart policy
`always`. The old `single-node_*` containers remain stopped and all
`single-node_*` volumes remain present. The target services use only
`warsoc-wazuh-local-4147_*` volumes.

## Prohibited During Upgrade

- No `docker compose down -v` against either project.
- No deletion or reuse of `single-node_` volumes.
- No public binding of Wazuh ports.
- No production WarSOC activation.
- No Wazuh Active Response.
- No FBR or PECA routing into Wazuh.

## Final Acceptance Still Required

The upgrade alone does not establish a working WarSOC integration. Final
acceptance requires the mTLS/Tailscale path, signed 4688 canary, duplicate and
replay checks, outage recovery, rotation recovery, saturation behavior and
proof that Wazuh results remain shadow-only.

No signed endpoint canary, candidate round trip, duplicate/replay injection,
outage recovery, key rotation, saturation, cross-tenant, or source-family test
was run during this upgrade. Those tests remain one controlled final acceptance
phase after the bridge, mTLS identities, and two-host private path are assembled.
