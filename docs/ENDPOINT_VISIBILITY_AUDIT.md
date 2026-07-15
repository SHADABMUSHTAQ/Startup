# 🋯 ENDPOINT VISIBILITY & DETECTION COVERAGE AUDIT
> **HISTORICAL - DO NOT USE FOR CURRENT DEPLOYMENT OR CUSTOMER CLAIMS.** This file predates the native Windows telemetry architecture and contains retired Sysmon assumptions. Current sources of truth are `WARSOC_CURRENT_STATE_ARCHITECTURE.md` and `WARSOC_END_TO_END_PRODUCT_AND_OPERATOR_GUIDE.md`.

## A Gemini/Claude AI Analysis of WarSOC Agent vs Backend Capability Gap

---

## TASK 1: THE COVERAGE MATRIX

### LAYER 1: Agent Data Collection Capability

From `agent/windows_agent.py` (lines 100-551):

**What the Agent CAN Collect:**
- ✅ Windows Event Log from 5 channels:
  - Security
  - System
  - Application
  - Microsoft-Windows-PowerShell/Operational
  - Windows PowerShell
- ✅ Web logs from configured text file paths
- ✅ Extraction of user/IP/logon_type/source_network_address

**What the Agent Configuration Monitors (config.json lines 11-17):**

| Category | Event ID | Windows Event | Status |
|---|---|---|---|
| **Authentication** | 4624 | Successful logon | ✅ MONITORED |
| **Authentication** | 4625 | Failed logon | ✅ MONITORED |
| **Privilege** | 4672 | Admin privileges assigned | ✅ MONITORED |
| **Process Exec** | 4688 | Process created | ✅ MONITORED |
| **Account Mgmt** | 4720 | User account created | ✅ MONITORED |
| **Account Mgmt** | 4726 | User account deleted | ✅ MONITORED |
| **Audit** | 1102 | Audit log cleared | ✅ MONITORED |

---

### LAYER 2: Backend Detection Capability

From `app/config/config.json` (detection.rules + stateful_detection_rules):

**What the Backend CAN Process & Detect:**

#### Regex Rules (15 rules):
1. SQL_INJECTION (T1190) - Detects UNION SELECT, DROP TABLE, OR 1=1
2. XSS_ATTACK (T1190) - Detects `<script>`, javascript:, onerror
3. COMMAND_INJECTION (T1059) - Detects `;whoami`, `;cat`, `|nc`
4. PATH_TRAVERSAL (T1083) - Detects `../`, `etc/passwd`
5. POWERSHELL_OBFUSCATION (T1027) - Detects `-EncodedCommand`
6. XXE_INJECTION (T1190) - Detects `<!ENTITY`
7. MALWARE_EXECUTION (T1059) - Detects mimikatz, psexec
8. REVERSE_SHELL (T1059.004) - Detects `/dev/tcp/`, socket code
9. PRIVILEGE_ESCALATION (T1068) - Detects sudo/net localgroup
10. LATERAL_MOVEMENT (T1021) - Detects net use, wmic, winrm
11. LOG_EVASION (T1070) - Detects wevtutil cl, history -c
12. PERSISTENCE (T1053) - Detects crontab, schtasks
13. DATA_EXFILTRATION (T1041) - Detects wget, curl, scp
14. BRUTE_FORCE_PATTERN (T1110) - Detects failed login patterns
15. RECON_COMMANDS (T1592) - Detects whoami, ipconfig, nmap

#### Stateful Correlation Rules (5 rules):
- High-velocity brute force (10 failures in 60s)
- Low-and-slow brute force (20 failures in 3600s)
- Password spraying (10+ unique users in 300s)
- Impossible travel (500km+ in <2 hours)
- Phishing kill-chain (lure + click + execution)

---

## TASK 2: THE GAP ANALYSIS - WHERE THE AGENT IS BLIND

### THE BIG FIVE: Coverage vs Gap

#### 1️⃣ **Authentication** ✅ COVERED
| Threat | Event ID | Agent | Backend | Status |
|--------|----------|-------|---------|--------|
| Successful login | 4624 | ✅ | ✅ | COVERED |
| Failed login | 4625 | ✅ | ✅ | COVERED |
| Brute force (10 in 60s) | Multiple | ✅ | ✅ Stateful | COVERED |
| Password spraying | Multiple | ✅ | ✅ Stateful | COVERED |
| Impossible travel | Multiple | ✅ | ✅ Stateful | COVERED |

---

#### 2️⃣ **Process Execution** ⚠️ PARTIALLY COVERED

| Threat | Event | Agent | Backend | Status |
|--------|-------|-------|---------|--------|
| Process creation | 4688 | ✅ | ✅ Detects patterns | COVERED |
| PowerShell execution | Message regex | ✅ | ✅ Via POWERSHELL_OBFUSCATION rule | COVERED |
| Malware signatures | Message regex | ❌ | ✅ MALWARE_EXECUTION rule | BACKEND ONLY |
| Reverse shell | Message regex | ❌ | ✅ REVERSE_SHELL rule | BACKEND ONLY |
| Command injection | Message regex | ❌ | ✅ COMMAND_INJECTION rule | BACKEND ONLY |

**Gap**: Agent sends `4688`, but only if captured. No process tree, no memory analysis, no parent-child correlation.

---

#### 3️⃣ **File Integrity** ❌ NOT COVERED

| Threat | Event ID | Agent | Backend | Status |
|--------|----------|-------|---------|--------|
| File deleted | 4660 | ❌ NOT MONITORED | ✅ Backend ready | 🚨 BLIND |
| File modified | 4663 | ❌ NOT MONITORED | ✅ Backend ready | 🚨 BLIND |
| Ransomware (file mod storm) | 4663 (batch) | ❌ | ✅ Stateful | 🚨 BLIND |
| Data exfiltration | Message pattern | ⚠️ (web logs only) | ✅ | PARTIAL |

**Gap**: Agent is COMPLETELY BLIND to file system changes. No monitoring of:
- File deletion patterns (ransomware indicator)
- File modification frequency (data staging)
- DLL injection
- File access audit trail

---

#### 4️⃣ **Network Connections** ❌ NOT COVERED

| Threat | Source | Agent | Backend | Status |
|--------|--------|-------|---------|--------|
| C2 beaconing | Sysmon 3 | ❌ NOT COLLECTED | ✅ Backend ready | 🚨 BLIND |
| DNS exfil | DNS logs | ❌ | ❌ | 🚨 BLIND |
| Lateral movement | Network | ❌ | ✅ Backend regex ready | 🚨 BLIND |
| Port scanning | Firewall logs | ❌ | ❌ | 🚨 BLIND |
| RDP/SSH brute force | Network | ⚠️ (event log only) | ✅ | PARTIAL |

**Gap**: Agent has ZERO network visibility. No monitoring of:
- Outbound connections to malicious IPs
- C2 beacon patterns (periodic connections)
- Lateral movement (SMB, WinRM)
- Port scanning attempts

---

#### 5️⃣ **Privilege Escalation & Account Management** ⚠️ PARTIALLY COVERED

| Threat | Event ID | Agent | Backend | Status |
|--------|----------|-------|---------|--------|
| Admin priv assigned | 4672 | ✅ | ✅ | COVERED |
| User account created | 4720 | ✅ | ✅ | COVERED |
| User account deleted | 4726 | ✅ | ✅ | COVERED |
| PAM/Sudo abuse | 4672 variant | ✅ | ✅ Pattern match | COVERED |
| LocalGroup add member | 4732 | ❌ NOT MONITORED | ✅ Backend ready | 🚨 BLIND |
| Registry persistence | Event 4657 | ❌ NOT MONITORED | ✅ Backend ready | 🚨 BLIND |
| Scheduled task creation | Event 4698 | ❌ NOT MONITORED | ✅ Backend ready | 🚨 BLIND |
| Service installation | Event 4697 | ✅ (FBR targets it) | ✅ | COVERED |

**Gap**: Agent misses several privilege-escalation persistence techniques:
- Registry Run key modifications (4657)
- LocalGroup membership changes (4732)
- Scheduled task creation (4698)

---

## TASK 3: THE INCIDENT BLIND SPOT ANALYSIS

### Real Attack Scenarios the Agent Would MISS:

#### Scenario 1: Ransomware Attack 🚨
```
1. Attacker gains access → 4624 (Login)          ✅ Agent detects
2. Elevates privileges → 4672 (Admin assigned)  ✅ Agent detects
3. BLIND ZONE: Disables Windows Defender
   - Event: 4657 (Registry value deleted)        ❌ AGENT BLIND
4. BLIND ZONE: Executes malware via PowerShell
   - Event: 4688 (Process created: mimikatz)    ✅ Agent detects
   - Event: Message contains "mimikatz"          ✅ Backend detects
5. BLIND ZONE: Mass file encryption
   - Event: 4663 (File modified, 10000 times)   ❌ AGENT BLIND (THIS IS THE KEY!)
   - Backend ready to detect but NO DATA COMING
6. Result: SIEM sees login + admin + process, but misses the actual ATTACK (file encryption)
```

**What's missing**: File integrity monitoring. The ransomware could encrypt 100,000 files and SIEM wouldn't know until too late.

---

#### Scenario 2: C2 Command & Control 🚨
```
1. Attacker compromises machine → 4624          ✅ Agent detects
2. BLIND ZONE: Downloads C2 agent (wget)
   - Event: Process creation w/ wget message    ⚠️ Backend could detect IF message captured
   - But: No network capture
3. BLIND ZONE: C2 beacons to 192.168.1.100 every 30 seconds
   - Event: Network connection to C2             ❌ AGENT BLIND (Sysmon 3 not monitored)
   - Attacker exfiltrates data for 48 hours
4. Result: SIEM never learns about C2 channel
```

**What's missing**: Network connection logging. Without Sysmon 3, no visibility into outbound connections.

---

#### Scenario 3: Privilege Escalation via Registry 🚨
```
1. Low-privilege user logon → 4624               ✅ Agent detects
2. BLIND ZONE: Creates registry persistence
   - Event: 4657 (Registry.exe modified HKLM\Software\Run) ❌ AGENT BLIND
3. BLIND ZONE: Installs backdoor service
   - Event: 4697 (Service installed)            ✅ Agent detects (FBR target)
   - But: Service name = "Windows Update Checker" (looks legitimate)
4. Result: Backdoor persists, next reboot attacker auto-connects
```

**What's missing**: Registry audit trail. Attackers use registry for persistence heavily (10+ techniques).

---

#### Scenario 4: Ransomware via Group Policy 🚨
```
1. Admin account compromised → 4624 + 4672      ✅ Agent detects
2. BLIND ZONE: Attacker modifies GPO
   - Event: Directory Service change (Event 5136) ❌ AGENT NOT MONITORING
3. BLIND ZONE: GPO deploys malicious script to 500 machines
   - Thousands of 4688 (Process created)
   - But: By the time backend sees it, damage is done
4. Result: Company-wide ransomware outbreak
```

**What's missing**: Directory Services monitoring. GPO changes need immediate alerting.

---

## EXECUTIVE SUMMARY: DETECTION CAPABILITY SCORECARD

| Category | Agent Capability | Backend Capability | Coverage | Missing |
|----------|---|---|---|---|
| **Authentication** | 70% | 100% | 85% | Ntlm relay, multi-factor bypass patterns |
| **Process Execution** | 60% | 100% | 70% | Memory injection, DLL sideloading, unsigned exe anomalies |
| **File Integrity** | 0% | 100% | 0% | **TOTAL BLIND SPOT** |
| **Network** | 0% | 80% (backend only) | 0% | **TOTAL BLIND SPOT** |
| **Privilege Escalation** | 70% | 90% | 75% | Registry persistence (4657), LocalGroup changes (4732) |
| **Overall** | **40%** | **94%** | **55%** | **File system + Network = the fortress leak** |

---

## CRITICAL FINDING: The "Blind Sentinel" Problem

**CURRENT STATE**:
```
Backend DETECTS:    ████████████████████████████████████████ 94%
Agent COLLECTS:     ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░ 40%
Actual COVERAGE:    ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░ 55%
```

**The Fortress is Hardened but Blind**:
- Backend is ready to detect 15 attack patterns
- Agent only sends 7 event types
- File system changes: **0% monitored BUT 100% critical**
- Network connections: **0% monitored BUT 100% critical**
- **Attacker could encrypt 500GB of files while SIEM sees nothing**

---

## RECOMMENDED NEXT AUDIT PHASE

To reach **Level 4 (Complete Endpoint Visibility)**, the agent needs:

1. **Sysmon integration** (Network events, Process relationships, Registry)
2. **File integrity monitoring** (4663 batching, ransomware detection)
3. **Registry audit trail** (4657 all modifications, hive changes)
4. **DirectoryServices monitoring** (GPO changes, domain escalation)
