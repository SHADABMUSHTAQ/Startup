# WarSOC Customer Features and Service Boundary

**Document type:** Customer-facing capability summary  
**Release reference:** Windows agent 4.2.6  
**Privacy rule:** This document contains no customer credentials, tenant identifiers, personal addresses, internal infrastructure addresses or operational secrets.

## 1. Product Purpose

WarSOC is a Windows-focused security monitoring and evidence platform for small and medium-sized organizations. It combines native endpoint telemetry, SIEM detection, incident workflow and optional FBR/PECA-oriented evidence packs.

WarSOC supports monitoring and investigation. It does not replace antivirus, EDR, a firewall, legal advice or a complete regulatory certification program.

## 2. Customer Onboarding

1. WarSOC and the customer agree the endpoint count, evidence packs, retention and commercial terms.
2. WarSOC provisions an isolated tenant and administrator account.
3. The tenant administrator generates a one-time agent activation code.
4. The administrator downloads the versioned Windows installer and verifies its supplied SHA-256 manifest.
5. The installer configures approved native Windows auditing and installs the agent as an automatically restarted Windows service.
6. Additional users are invited with single-use activation links and assigned role-based permissions.

## 3. Windows Endpoint Monitoring

- Native Windows Security and System event collection without Sysmon.
- Process creation, logon, account, group, service, audit-policy, object-access and blocked-connection evidence.
- Language-independent Windows XML parsing.
- Durable local queue with retry after temporary internet/backend outages.
- Bounded local storage and degraded-health reporting when disk safety limits are reached.
- Cryptographically signed endpoint events using the enrolled agent identity.
- Agent and telemetry health shown as Active, Degraded or Not Configured.

## 4. SIEM and Incident Features

- Tenant-isolated event processing and evidence storage.
- Normal activity retained as investigation evidence without turning every event into an alert.
- Actionable detections projected into grouped incidents to reduce repetitive dashboard noise.
- Severity, occurrence count, endpoint, actor, target, process and evidence references where the source event supplies them.
- Live dashboard delivery through authenticated sessions.
- Acknowledge, assign, annotate and close incident workflows according to role.
- IP/CIDR mitigation controls with active-agent and self-lockout safeguards.

## 5. Security Behaviors Detected

Current Windows-focused detection includes these categories when the required event fields are available:

- Brute-force authentication and password spraying.
- Suspicious account creation, deletion and privileged-group changes.
- Suspicious PowerShell, command-line, reverse-shell and credential-dumping behavior.
- Service, scheduled-task and registry persistence.
- Audit-log clearing, logging shutdown and anti-forensic behavior.
- Reconnaissance, user enumeration and SMB lateral activity.
- Ransomware/destructive deletion patterns and protected database-file tampering.
- Blocked-connection and blocked-port-scan patterns.

Web-attack signatures require an approved structured HTTP-log source. Full network-flow analytics, DNS tunnelling, payload inspection and Linux monitoring are not included in the current Windows service.

## 6. PECA-Oriented Evidence Pack

The PECA-oriented pack preserves signed forensic evidence for 11 native Windows controls:

- Failed and successful logons.
- Process creation.
- Special privileges assigned.
- Account creation and deletion.
- Privileged/local-group membership changes.
- Service installation from Security and System channels.
- Audit-log clearing and Event Log service shutdown.

Evidence is encrypted, tenant isolated, idempotent and cryptographically sealed. Normal evidence does not automatically become a threat alert. The pack is designed to support investigation and evidence workflows; it is not a blanket legal-compliance guarantee.

## 7. FBR-Oriented Evidence Pack

The FBR-oriented pack has two separate evidence sources:

1. **Invoice evidence:** the POS application writes the approved JSON Lines record or calls the authenticated POS API for invoice modification/deletion events.
2. **File-integrity evidence:** native Windows auditing monitors customer-approved local POS/database directories for database-file deletion and permission tampering.

WarSOC does not read or infer proprietary invoice tables automatically. Without POS integration, WarSOC can provide file-integrity evidence but cannot identify invoice numbers, line items or business meaning hidden inside a proprietary database.

## 8. Storage, Retention and Reports

- Seven days of operational SIEM, PECA and FBR data in the hot tier.
- Encrypted immutable archive storage after the hot window.
- PECA-oriented evidence retention configured for 365 days.
- FBR-oriented evidence retention configured for 2,190 days.
- Verified hot-plus-cold retrieval for authorized views and exports.
- CSV evidence export and human-readable PDF audit reports.

Retention depends on the contracted configuration and correctly locked archive containers. A PDF summarizes source evidence; it is not itself represented as a cryptographically signed court document.

## 9. Roles and Access

- **Administrator:** tenant configuration, team management, agent activation and authorized operational/compliance actions.
- **Manager:** operational incident handling according to policy.
- **Analyst:** investigation and read access without tenant-administration authority.
- **Auditor:** read-only compliance evidence and authorized exports.

The backend enforces tenant and role boundaries even when a frontend control is hidden or unavailable.

## 10. Agent 4.2.6

Agent 4.2.6 is the current native signed-event release. Its main upgrade over 4.2.5 is stronger compatibility for Windows DPAPI-protected Ed25519 private keys across supported pywin32 versions. It validates DPAPI output before storing or loading key material and keeps the existing native telemetry, durable spool, retry, health and event-signing behavior.

Agent 4.2.6 does not introduce packet capture, Sysmon, proprietary POS parsing or network-firewall collection.

## 11. Network-Device Status

A separate customer-side network relay is under controlled validation for Fortinet, Cisco ASA, MikroTik and pfSense metadata. Its parsers, encrypted spools, signed batches and backend admission logic have passed isolated tests, but the feature remains disabled until real-device, Windows service, outage and pilot acceptance gates pass.

Network packet payload capture is not part of the approved design. Legacy UDP syslog is relay-attested and source-allowlisted; it is not represented as cryptographically authenticated by the originating firewall.

Wazuh is not a separate customer feature or customer-visible engine. It is a
disabled internal candidate detector that may later contribute validated shadow
observations behind WarSOC. Current customer detection remains WarSOC-native.

Compliance evidence lists return operational metadata only. Raw evidence is
available only through a separately authorized record-detail workflow; list
views must not render complete raw event bodies.

## 12. Customer Responsibilities and Limitations

- Keep Windows Defender or the organization’s approved endpoint protection enabled.
- Verify unsigned pilot artifacts by the supplied hash and use an organization-approved allow rule when required.
- Supply valid one-time activation codes and approved POS paths.
- Enable the audit policies required by the installer and avoid deleting the agent’s protected data directories.
- Provide POS JSONL/API integration when invoice-level evidence is required.
- Maintain accurate endpoint time, network connectivity and sufficient disk space.
- Review incidents; WarSOC does not guarantee automatic prevention or blocking of every attack.
- Treat regulatory mappings as evidence support, not legal certification.
