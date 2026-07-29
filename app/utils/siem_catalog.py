#  THE SIEM SINGLE SOURCE OF TRUTH (SSOT)
# This file contains all detection rules, thresholds, event mappings, and alert labels.

SIEM_RULES = {
    "normalization": {
        "local_ips": [
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "localhost"
        ],
        "event_type_keywords": {
            "http_request": [
                "get /",
                "post /",
                "put /",
                "delete /",
                "http/"
            ],
            "http_404": [
                "404 "
            ],
            "http_500": [
                "500 "
            ]
        }
    },
    "source_classification": {
        "Windows-Sec": {
            "trigger_keywords": [
                "event",
                "logon",
                "account",
                "registry",
                "network",
                "process",
                "scheduled",
                "task"
            ],
            "trigger_event_ids": [
                4624,
                4625,
                4672,
                4720,
                4726,
                1100,
                1102,
                4663,
                4660,
                4657,
                4698,
                4732,
                4670,
                4616,
                4697,
                4719,
                4670,
                4616,
                4697,
                4719,
                4798,
                4648,
                4776,
                4768,
                4769,
                5140,
                7045,
                4688,
                5157
            ],
            "severity_by_event_id": {
                "4625": "HIGH",
                "1100": "CRITICAL",
                "1102": "CRITICAL",
                "4720": "MEDIUM",
                "4732": "HIGH",
                "4726": "MEDIUM",
                "4648": "HIGH",
                "4776": "HIGH",
                "4768": "MEDIUM",
                "4769": "MEDIUM",
                "5140": "MEDIUM",
                "4663": "MEDIUM",
                "4660": "MEDIUM",
                "4657": "HIGH",
                "4698": "HIGH",
                "4798": "LOW",
                "5157": "HIGH",
                "7045": "CRITICAL"
            },
            "severity_by_keyword": {
                "failed": "HIGH",
                "cleared": "CRITICAL",
                "unauthorized": "HIGH"
            },
            "false_positive_tuning": {
                "4624": {
                    "allowed_logon_types": [
                        2,
                        10,
                        11
                    ]
                }
            }
        },
        "Web-WAF": {
            "trigger_keywords": [
                "get /",
                "post /",
                "http",
                "union select",
                "xss"
            ],
            "severity_by_keyword": {
                "union select": "CRITICAL",
                "drop table": "CRITICAL",
                "<script>": "CRITICAL",
                "admin": "HIGH"
            }
        },
        "Linux-Auth": {
            "trigger_keywords": [
                "sudo",
                "root",
                "/etc/",
                "sshd",
                "invalid user"
            ],
            "severity_by_keyword": {
                "failed password": "HIGH",
                "invalid user": "HIGH",
                "without permission": "CRITICAL",
                "root access": "CRITICAL"
            }
        },
        "Endpoint-EDR": {
            "trigger_keywords": [
                "miner",
                "xmrig",
                "crypto",
                "file encrypted",
                "ransomware"
            ],
            "severity_by_keyword": {
                "miner": "CRITICAL",
                "xmrig": "CRITICAL",
                "file encrypted": "CRITICAL",
                "ransomware": "CRITICAL"
            }
        },
        "Network-IDS": {
            "trigger_keywords": [
                "port scan",
                "syn packet"
            ],
            "severity_by_keyword": {
                "port scan": "MEDIUM",
                "syn packet": "MEDIUM"
            }
        }
    },
    "alert_title_map": {
        "High-velocity brute force attack detected": "Many failed login attempts were detected in a short time",
        "Low-and-slow brute force attack detected": "Repeated failed login attempts were detected over time",
        "Password spraying attack detected": "A password spraying pattern was detected",
        "Impossible travel detected": "A login was detected from locations too far apart in a short time",
        "Login from new geographic location": "A login from a new location was detected",
        "Concurrent sessions from multiple IPs": "The same account is active from multiple IP addresses",
        "After-hours suspicious activity": "Unusual activity was detected outside normal working hours",
        "Mass account creation detected": "A large number of user accounts were created",
        "Privilege escalation spike detected": "Multiple privilege escalation events were detected",
        "Dormant account reactivated": "An inactive account became active again",
        "Mass file modification - Ransomware indicator": "A large number of files were modified quickly",
        "Mass file deletion detected": "A large number of files were deleted quickly",
        "Correlated phishing kill-chain detected": "Multiple phishing-related stages were detected for the same user",
        "SMB lateral movement detected": "Credential use or ticket activity suggests lateral movement across shares",
        "SMB share enumeration detected": "A source is probing multiple SMB shares in a short window",
        "Ransomware raw-access pattern detected": "Raw disk access and mass file mutations were detected",
        "Process injection detected": "A remote thread was created in a sensitive process",
        "Registry persistence detected": "A persistence-related registry location was modified"
    },
    "threat_intelligence": {
        "enabled": True,
        "ips": [
            "192.168.1.100",
            "10.0.0.200"
        ],
        "files": [
            "data/blacklist_ip.txt"
        ],
        "options": {
            "ignore_private_ips": False,
            "minimum_confidence": 80,
            "confidence": {
                "direct_ip": 95,
                "file_ip": 90,
                "cidr": 75
            },
            "trusted_networks": [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"
            ],
            "private_ip_allowlist": []
        }
    },
    "whitelist": {
        "enabled": True,
        "service_accounts": [
            "svc_backup",
            "nagios",
            "backup",
            "root",
            "daemon"
        ],
        "ips": [
            "127.0.0.1",
            "::1",
            "localhost"
        ],
        "system_ips": [
            "127.0.0.1",
            "localhost",
            "::1",
            "0.0.0.0"
        ]
    },
    "event_id_map": {
        "1100": {"event_type": "event_logging_stopped", "severity": "CRITICAL", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "1102": {"event_type": "clear_logs", "severity": "CRITICAL", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "4616": {"event_type": "system_time_changed", "severity": "MEDIUM", "frameworks": [], "alert_on_event": False},
        "4624": {"event_type": "successful_login", "severity": "INFO", "frameworks": ["peca_forensic"], "alert_on_event": False},
        "4625": {"event_type": "failed_login", "severity": "HIGH", "frameworks": ["peca_forensic"], "alert_on_event": False},
        "4648": {"event_type": "explicit_credential_use", "severity": "HIGH", "frameworks": [], "alert_on_event": False},
        "4657": {"event_type": "registry_modified", "severity": "HIGH", "frameworks": [], "alert_on_event": False},
        "4660": {"event_type": "object_deleted", "severity": "MEDIUM", "frameworks": ["fbr_pos"], "alert_on_event": False},
        "4663": {"event_type": "object_access", "severity": "MEDIUM", "frameworks": ["fbr_pos"], "alert_on_event": False},
        "4670": {"event_type": "permissions_changed", "severity": "HIGH", "frameworks": ["fbr_pos"], "alert_on_event": False},
        "4672": {"event_type": "special_privileges_assigned", "severity": "MEDIUM", "frameworks": ["peca_forensic"], "alert_on_event": False},
        "4688": {"event_type": "process_create", "severity": "INFO", "frameworks": ["peca_forensic"], "alert_on_event": False},
        "4697": {"event_type": "service_installed", "severity": "CRITICAL", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "4698": {"event_type": "scheduled_task_created", "severity": "MEDIUM", "frameworks": [], "alert_on_event": False},
        "4719": {"event_type": "policy_change", "severity": "HIGH", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "4720": {"event_type": "account_created", "severity": "HIGH", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "4726": {"event_type": "account_deleted", "severity": "HIGH", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "4732": {"event_type": "localgroup_member_added", "severity": "HIGH", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "4768": {"event_type": "kerberos_auth_ticket", "severity": "MEDIUM", "frameworks": [], "alert_on_event": False},
        "4769": {"event_type": "kerberos_service_ticket", "severity": "MEDIUM", "frameworks": [], "alert_on_event": False},
        "4776": {"event_type": "ntlm_authentication", "severity": "HIGH", "frameworks": [], "alert_on_event": False},
        "4798": {"event_type": "user_enumeration", "severity": "LOW", "frameworks": ["peca_forensic"], "alert_on_event": False},
        "5140": {"event_type": "network_share_accessed", "severity": "MEDIUM", "frameworks": [], "alert_on_event": False},
        "5156": {"event_type": "network_connection_permitted", "severity": "INFO", "frameworks": [], "alert_on_event": False},
        "5157": {"event_type": "network_connection_blocked", "severity": "HIGH", "frameworks": ["peca_forensic"], "alert_on_event": False},
        "7045": {"event_type": "service_installed", "severity": "CRITICAL", "frameworks": ["peca_forensic"], "alert_on_event": True},
        "FBR-INV-DEL": {"event_type": "invoice_deleted", "severity": "WARNING", "frameworks": ["fbr_pos"], "alert_on_event": False},
        "FBR-INV-MOD": {"event_type": "invoice_modified", "severity": "CRITICAL", "frameworks": ["fbr_pos"], "alert_on_event": False},
        "FIM-DB-MOD": {"event_type": "database_tampered", "severity": "CRITICAL", "frameworks": ["fbr_pos"], "alert_on_event": False}
    },
    "hybrid_network_correlation": {
        "enabled": True,
        "vpn_password_spray": {
            "threshold_users": 5,
            "window_seconds": 300,
            "severity": "HIGH",
        },
        "vpn_to_windows_logon": {
            "window_seconds": 600,
            "allowed_logon_types": ["3", "10"],
        },
        "high_risk_host_to_public_network": {
            "window_seconds": 300,
            "events": {
                "1100": {"kind": "event_logging_stopped", "severity": "CRITICAL"},
                "1102": {"kind": "audit_log_cleared", "severity": "CRITICAL"},
                "4697": {"kind": "service_installed", "severity": "HIGH"},
                "4732": {"kind": "administrator_membership_changed", "severity": "HIGH"},
                "7045": {"kind": "service_installed", "severity": "HIGH"},
            },
        },
    },
    "detection": {
        "siem_rules": [
            {
                "rule_id": "SIEM-FW-001",
                "name": "Firewall Connection Blocked",
                "event_id": 5157,
                "severity": "HIGH",
                "action": "alert"
            }
        ],
        "brute_force_threshold": 3,
        "failed_login_patterns": [
            "failed password",
            "authentication failure",
            "login failed",
            "access denied"
        ],
        "fp_controls": {
            "default_min_message_length": 12,
            "max_alerts_per_log": 2,
            "rule_cooldown_seconds": 30,
            "suppress_if_message_contains": [
                "healthcheck",
                "status check",
                "system heartbeat",
                "normal user login",
                "normal navigation",
                "profile update",
                "connectivity check",
                "windows update"
            ]
        },
        "native_windows_detection": {
            "elevated_powershell": {
                "enabled": True,
                "severity": "MEDIUM",
                "mitre_id": "T1059.001",
                "full_token_values": [
                    "%%1937",
                    "token elevation type full",
                    "tokenelevationtypefull",
                    "full"
                ]
            }
        },
        "phishing_detection": {
            "enabled": True,
            "score_threshold": 40,
            "minimum_signals": 2,
            "delivery_event_types": [
                "email",
                "email_gateway",
                "email_message",
                "browser_download",
                "url_click",
                "web_proxy",
                "http_request"
            ],
            "credential_lure_keywords": [
                "verify your account",
                "password expired",
                "reset password",
                "urgent action required",
                "invoice attached",
                "payment failed",
                "mfa required",
                "security alert"
            ],
            "url_shorteners": [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly"
            ],
            "trusted_domains": [
                "microsoft.com",
                "google.com",
                "apple.com",
                "amazon.com",
                "github.com",
                "linkedin.com"
            ],
            "suspicious_tlds": [
                "xyz",
                "top",
                "click",
                "work",
                "gq",
                "fit",
                "support"
            ],
            "risky_attachment_extensions": [
                ".html",
                ".htm",
                ".lnk",
                ".iso",
                ".img",
                ".docm",
                ".xlsm",
                ".js",
                ".vbs",
                ".zip"
            ],
            "lolbin_indicators": [
                "powershell -enc",
                "mshta",
                "wscript",
                "cscript",
                "rundll32",
                "regsvr32",
                "certutil -urlcache",
                "bitsadmin"
            ],
            "weights": {
                "credential_lure": 20,
                "suspicious_domain": 20,
                "raw_ip_url": 30,
                "punycode_domain": 35,
                "risky_attachment": 30,
                "lolbin_execution": 50,
                "url_shortener": 20,
                "sender_spoof_hint": 25
            }
        },
        "rules": {
            "SQL_INJECTION": {
                "regex": "(?i)(%27|'|%22)\\s*(union\\s+(all\\s+)?select|select\\s+.{0,80}from|insert\\s+into|update\\s+.*set|delete\\s+from|drop\\s+(table|database)|or\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d|--|;\\s*--|xp_cmdshell|information_schema|1\\s*=\\s*1)",
                "sev": "HIGH",
                "mitre": "T1190",
                "requires_context": [
                    "http_request"
                ],
                "must_include_any": [
                    "select",
                    "union",
                    "or 1=1",
                    "--",
                    "drop",
                    "information_schema"
                ],
                "min_message_length": 24,
                "cooldown_seconds": 60
            },
            "SIEM-FW-001": {
                "enabled": False,
                "disabled_reason": "Event 5157 is owned by the native event map; a regex alert would duplicate it",
                "regex": "(?i)\\b(firewall|connection blocked)\\b",
                "sev": "MEDIUM",
                "mitre": "N/A",
                "summary": "Firewall Connection Blocked",
                "requires_context": [
                    "Windows-Sec"
                ],
                "must_include_any": [
                    "firewall",
                    "connection blocked"
                ],
                "min_message_length": 1,
                "cooldown_seconds": 30
            },
            "XSS_ATTACK": {
                "regex": "(?i)(<script|javascript:|onerror=|onload=)",
                "sev": "HIGH",
                "mitre": "T1190",
                "requires_context": [
                    "http_request"
                ],
                "must_include_any": [
                    "<script",
                    "javascript:",
                    "onerror",
                    "onload"
                ],
                "min_message_length": 20,
                "cooldown_seconds": 45
            },
            "COMMAND_INJECTION": {
                "regex": "(?i)(;\\s*(whoami|cat|id|ls|dir|uname|curl|wget|bash|sh|nc|python|perl|ruby|chmod|chown|rm\\s)\\b|\\|\\s*nc|\\$\\s*\\(|`[a-z]+`)",
                "sev": "CRITICAL",
                "mitre": "T1059",
                "requires_context": ["http_request"]
            },
            "PATH_TRAVERSAL": {
                "regex": "(?i)(\\.\\.\\/|\\.\\.\\\\|etc/passwd|win.ini)",
                "sev": "HIGH",
                "mitre": "T1083",
                "requires_context": ["http_request"]
            },
            "POWERSHELL_OBFUSCATION": {
                "regex": "(?i)powershell[\\s+.\\-]*(\\-e(nc)?(odedcommand)?|\\-w(indowstyle)?[\\s+]+h(idden)?)[\\s+]+[A-Za-z0-9+/=]{10,}",
                "sev": "CRITICAL",
                "mitre": "T1027",
                "requires_context": ["process_create", "command_line", "powershell"]
            },
            "PRIVILEGE_ESCALATION": {
                "regex": "(?i)(sudo\\s+su\\s+\\-|nopasswd:\\s+all|net\\s+localgroup\\s+administrators\\s+.*\\s+/add|passwd\\s+\\-d)",
                "sev": "HIGH",
                "mitre": "T1068",
                "requires_context": ["process_create", "command_line"]
            },
            "LATERAL_MOVEMENT": {
                "regex": "(?i)(net\\s+use\\s+\\\\\\\\[a-z0-9.]+\\\\c\\$|wmic\\s+/node:.*process\\s+call\\s+create|winrm\\s+invoke|enter-pssession)",
                "sev": "HIGH",
                "mitre": "T1021",
                "requires_context": ["process_create", "command_line"]
            },
            "LOG_EVASION": {
                "regex": "(?i)(wevtutil\\s+cl\\s+|history\\s+\\-c|rm\\s+.*\\.log|shred\\s+|clear-eventlog|set-mppreference\\s+-disablerealtime)",
                "sev": "HIGH",
                "mitre": "T1070",
                "requires_context": ["process_create", "command_line"]
            },
            "REVERSE_SHELL": {
                "regex": "(?i)(bash\\s+\\-i\\s+>\\&\\s+/dev/tcp/|python.*\\-c.*socket|perl\\s+\\-e.*socket|nc\\s+-e\\s+/bin/sh)",
                "sev": "CRITICAL",
                "mitre": "T1059.004",
                "requires_context": ["process_create", "command_line"]
            },
            "RECON_COMMANDS": {
                "regex": "(?i)(whoami|ipconfig|netstat|enum4linux|nmap|arp -a)",
                "sev": "MEDIUM",
                "mitre": "T1592",
                "requires_context": ["process_create", "command_line"]
            },
            "PERSISTENCE": {
                "regex": "(?i)(crontab -e|authorized_keys|registry run keys|schtasks /create)",
                "sev": "HIGH",
                "mitre": "T1053",
                "requires_context": ["process_create", "command_line"]
            },
            "DATA_EXFILTRATION": {
                "regex": "(?i)(wget\\s+.*(-O|--output|http)|curl\\s+.*(-d|--data|-F|--upload|POST)|nc\\s+-w\\s+\\d+|sftp\\s+.*@|scp\\s+.*:)",
                "sev": "HIGH",
                "mitre": "T1041",
                "requires_context": ["process_create", "command_line"]
            },
            "STAGING": {
                "regex": "(?i)(7z\\s+a|zip\\s+\\-r|tar\\s+\\-czf)\\s+.*(/tmp/|/windows/temp/|/appdata/|/var/tmp/)",
                "sev": "MEDIUM",
                "mitre": "T1074",
                "requires_context": ["process_create", "command_line"]
            },
            "BRUTE_FORCE_PATTERN": {
                "regex": "(?i)(failed password|authentication failure|login failed|access denied)",
                "sev": "MEDIUM",
                "mitre": "T1110",
                "requires_context": [
                    "failed_login"
                ],
                "must_include_any": [
                    "failed",
                    "denied"
                ],
                "min_message_length": 10,
                "cooldown_seconds": 20
            },
            "XXE_INJECTION": {
                "regex": "(?i)(<!ENTITY\\s+|<!DOCTYPE\\s+.*SYSTEM\\s+|SYSTEM\\s+[\"']\\s*(?:file|https?|ftp)://|file:///)",
                "sev": "CRITICAL",
                "mitre": "T1190",
                "requires_context": ["http_request"]
            },
            "MALWARE_EXECUTION": {
                "regex": "(?i)(mimikatz|hashcat|psexec\\.exe|lazagne|rubeus|sharphound|bloodhound|cobalt\\s*strike|meterpreter)",
                "sev": "CRITICAL",
                "mitre": "T1059",
                "requires_context": ["process_create", "command_line"]
            },
            "SIGMA_RANSOMWARE_SHADOW_DELETE": {
                "regex": "(?i)(vssadmin.*delete.*shadows|bcdedit.*recoveryenabled.*no|wmic.*shadowcopy.*delete)",
                "sev": "CRITICAL",
                "mitre": "T1490",
                "requires_context": ["process_create", "command_line"],
                "summary": "Ransomware Behavior: Volume Shadow Copy Deletion"
            },
            "SIGMA_CREDENTIAL_DUMPING": {
                "regex": "(?i)(procdump.*lsass|rundll32.*comsvcs.*minidump)",
                "sev": "CRITICAL",
                "mitre": "T1003.001",
                "requires_context": ["process_create", "command_line"],
                "summary": "Credential Dumping: LSASS Memory Access"
            },
            "DEFENSE_EVASION_DEFENDER": {
                "regex": "(?i)(Set-MpPreference\\s+-DisableRealtimeMonitoring\\s+\\$true|Remove-MpPreference|net\\s+stop\\s+windefend)",
                "sev": "HIGH",
                "mitre": "T1562.001",
                "requires_context": ["process_create", "powershell", "command_line"],
                "summary": "Defense Evasion: Antivirus Disabled"
            },
            "LOLBIN_DOWNLOADER": {
                "regex": "(?i)(certutil\\s+-urlcache\\s+-split\\s+-f|bitsadmin\\s+/transfer)",
                "sev": "MEDIUM",
                "mitre": "T1105",
                "requires_context": ["process_create", "command_line"],
                "summary": "Suspicious Download via LOLBin"
            },
            "LINUX_SYSTEM_TIMESTOMPING": {
                "enabled": False,
                "disabled_reason": "Linux/syslog intake is not enabled for the Windows SMB pilot",
                "regex": "(?i)(touch\\s+-t\\s+\\d+|touch\\s+-m\\s+-d)",
                "sev": "MEDIUM",
                "mitre": "T1070.006",
                "requires_context": ["process_create", "linux_auth", "command_line"],
                "summary": "Timestomping: File Modification Time Altered"
            },
            "WEB_SHELL_ACTIVITY": {
                "regex": "(?i)(cmd\\.exe\\s+/c|powershell(?:\\.exe)?).*?\\s+HTTP/",
                "sev": "HIGH",
                "mitre": "T1505.003",
                "requires_context": ["http_request"],
                "summary": "Web Shell Activity: Shell spawned from web context"
            }
        }
    },
    "stateful_detection_rules": {
        "auth_identity": {
            "phishing_kill_chain": {
                "enabled": True,
                "window_seconds": 900,
                "mitre_id": "T1566",
                "severity": "CRITICAL",
                "description": "Correlated phishing kill-chain detected",
                "group_by": "tenant_agent_user",
                "event_filter": "all",
                "minimum_stages": 2,
                "delivery_event_types": [
                    "email",
                    "email_gateway",
                    "email_message",
                    "browser_download",
                    "url_click",
                    "web_proxy",
                    "http_request"
                ],
                "ignored_identities": [
                    "system",
                    "local service",
                    "network service",
                    "anonymous logon",
                    "unknown"
                ],
                "lure_keywords": [
                    "verify your account",
                    "password expired",
                    "invoice attached",
                    "urgent action required",
                    "security alert"
                ],
                "click_keywords": [
                    "http://",
                    "https://",
                    "login",
                    "signin",
                    "verify",
                    "mfa",
                    "reset"
                ],
                "execution_keywords": [
                    "powershell",
                    "mshta",
                    "wscript",
                    "cscript",
                    "rundll32",
                    "regsvr32",
                    "certutil",
                    "bitsadmin",
                    "macro"
                ],
                "suspicious_execution_markers": [
                    "-enc",
                    "-encodedcommand",
                    "downloadstring",
                    "invoke-webrequest",
                    "frombase64string",
                    "-windowstyle hidden",
                    "http://",
                    "https://",
                    ".js",
                    ".jse",
                    ".vbs",
                    ".vbe",
                    ".hta",
                    "javascript:"
                ],
                "suspicious_parent_processes": [
                    "winword.exe",
                    "excel.exe",
                    "outlook.exe",
                    "powerpnt.exe",
                    "acrord32.exe",
                    "chrome.exe",
                    "msedge.exe",
                    "firefox.exe"
                ]
            },
            "high_velocity_brute_force": {
                "enabled": True,
                "threshold": 50,
                "window_seconds": 60,
                "mitre_id": "T1110.001",
                "severity": "HIGH",
                "description": "High-velocity brute force attack detected",
                "group_by": "source_ip",
                "event_filter": "failed_login"
            },
            "low_slow_brute_force": {
                "enabled": True,
                "threshold": 20,
                "window_seconds": 3600,
                "mitre_id": "T1110.001",
                "severity": "MEDIUM",
                "description": "Low-and-slow brute force attack detected",
                "group_by": "source_ip",
                "event_filter": "failed_login"
            },
            "password_spraying": {
                "enabled": True,
                "handler": "password_spray",
                "threshold_users": 5,
                "threshold_attempts": 1,
                "window_seconds": 300,
                "mitre_id": "T1110.003",
                "severity": "HIGH",
                "description": "Password spraying attack detected",
                "group_by": "source_ip",
                "unique_field": "username",
                "event_filter": "failed_login"
            },
            "impossible_travel": {
                "enabled": False,
                "disabled_reason": "No trusted GeoIP enrichment populates native Windows login coordinates in the pilot pipeline",
                "handler": "impossible_travel",
                "max_travel_time_hours": 2,
                "min_distance_km": 500,
                "window_seconds": 7200,
                "mitre_id": "T1078",
                "severity": "CRITICAL",
                "description": "Impossible travel detected",
                "event_filter": "successful_login"
            },
            "new_location_access": {
                "enabled": False,
                "disabled_reason": "Requires a trusted GeoIP enrichment and location-baseline contract",
                "mitre_id": "T1078",
                "severity": "MEDIUM",
                "description": "Login from new geographic location",
                "event_filter": "successful_login"
            },
            "concurrent_sessions": {
                "enabled": True,
                "threshold": 3,
                "window_seconds": 300,
                "mitre_id": "T1078",
                "severity": "MEDIUM",
                "description": "Concurrent sessions from multiple IPs",
                "group_by": "username",
                "unique_field": "source_ip",
                "event_filter": "successful_login",
                "logon_types": ["3", "10"]
            },
            "after_hours_activity": {
                "enabled": False,
                "disabled_reason": "Requires tenant timezone and approved business-hours policy; fixed UTC hours create false positives",
                "handler": "after_hours_activity",
                "start_hour": 2,
                "end_hour": 5,
                "mitre_id": "T1078",
                "severity": "MEDIUM",
                "description": "After-hours suspicious activity",
                "event_filter": "successful_login"
            },
            "account_storm": {
                "enabled": True,
                "threshold": 5,
                "window_seconds": 60,
                "mitre_id": "T1136",
                "severity": "HIGH",
                "description": "Mass account creation detected",
                "group_by": "tenant",
                "event_filter": "account_created"
            },
            "privilege_escalation_spike": {
                "enabled": False,
                "disabled_reason": "No native event emits the generic privilege_escalation type; precise 4688 and 4732 detections remain active",
                "threshold": 5,
                "window_seconds": 60,
                "mitre_id": "T1548",
                "severity": "HIGH",
                "description": "Privilege escalation spike detected",
                "event_filter": "privilege_escalation",
                "keywords": [
                    "sudo",
                    "runas",
                    "su",
                    "elevation"
                ]
            },
            "dormant_account_activation": {
                "enabled": True,
                "handler": "dormant_account_activation",
                "dormant_days": 30,
                "mitre_id": "T1078.002",
                "severity": "MEDIUM",
                "description": "Dormant account reactivated",
                "event_filter": "successful_login"
            },
            "ghost_admin_sequence": {
                "enabled": True,
                "handler": "ghost_admin_sequence",
                "window_seconds": 300,
                "mitre_id": "T1548+T1070",
                "severity": "CRITICAL",
                "description": "Ghost Admin Sequence Detected"
            },
            "smb_lateral_movement": {
                "enabled": True,
                "handler": "smb_lateral_movement",
                "threshold_users": 2,
                "threshold_attempts": 2,
                "window_seconds": 7200,
                "mitre_id": "T1021.002",
                "severity": "HIGH",
                "description": "SMB lateral movement detected",
                "group_by": "source_ip",
                "unique_field": "user",
                "event_filter": "all"
            },
            "smb_share_enumeration": {
                "enabled": True,
                "handler": "smb_enumeration",
                "threshold": 5,
                "window_seconds": 300,
                "mitre_id": "T1135",
                "severity": "MEDIUM",
                "description": "SMB share enumeration detected",
                "group_by": "source_ip",
                "unique_field": "share_name",
                "event_filter": "network_share_accessed"
            },
            "registry_persistence": {
                "enabled": True,
                "handler": "registry_persistence",
                "window_seconds": 300,
                "mitre_id": "T1112",
                "severity": "HIGH",
                "description": "Registry persistence detected",
                "event_filter": "registry_modified"
            }
        },
        "filesystem_ransomware": {
            "mass_file_modification": {
                "enabled": False,
                "disabled_reason": "The pilot SACL audits delete and permission rights, not ordinary write operations",
                "threshold": 50,
                "window_seconds": 60,
                "mitre_id": "T1486",
                "severity": "CRITICAL",
                "description": "Mass file modification - Ransomware indicator",
                "group_by": "username",
                "event_filter": "file_modify"
            },
            "mass_file_deletion": {
                "enabled": True,
                "threshold": 50,
                "window_seconds": 60,
                "mitre_id": "T1485",
                "severity": "CRITICAL",
                "description": "Mass file deletion detected",
                "group_by": "agent_user",
                "event_filter": "file_delete"
            },
            "sensitive_file_touch": {
                "enabled": False,
                "disabled_reason": "The pilot SACL does not audit ordinary read access",
                "threshold": 5,
                "window_seconds": 60,
                "mitre_id": "T1005",
                "severity": "HIGH",
                "description": "Multiple sensitive file accesses",
                "group_by": "username",
                "event_filter": "file_access",
                "sensitive_keywords": [
                    "confidential",
                    "finance",
                    "payroll",
                    "secret",
                    "private"
                ]
            },
            "ransomware_extensions": {
                "enabled": False,
                "disabled_reason": "The pilot SACL does not collect reliable file-write/rename telemetry",
                "threshold": 1,
                "window_seconds": 60,
                "mitre_id": "T1486",
                "severity": "CRITICAL",
                "description": "Ransomware file extension detected",
                "group_by": "username",
                "event_filter": "file_write",
                "ransomware_extensions": [
                    ".crypt",
                    ".locked",
                    ".encrypted",
                    ".locky",
                    ".wannacry",
                    ".cerber",
                    ".cryptolocker"
                ]
            },
            "data_exfiltration_volume": {
                "enabled": False,
                "disabled_reason": "Requires byte-counted upload telemetry not collected by the Windows pilot agent",
                "threshold_bytes": 104857600,
                "window_seconds": 300,
                "mitre_id": "T1041",
                "severity": "HIGH",
                "description": "Large data upload detected",
                "group_by": "username",
                "event_filter": "data_upload"
            },
            "log_clearing_sequence": {
                "enabled": False,
                "disabled_reason": "Events 1100 and 1102 alert directly; the ghost-admin handler implements 4732 followed by 1102, not this declared sequence",
                "handler": "ghost_admin_sequence",
                "window_seconds": 60,
                "mitre_id": "T1070",
                "severity": "CRITICAL",
                "description": "Log clearing sequence detected",
                "group_by": "source_ip",
                "event_sequence": [
                    "stop_logging",
                    "clear_logs"
                ]
            }
        },
        "network_lateral": {
            "vertical_port_scan": {
                "enabled": True,
                "threshold": 10,
                "window_seconds": 60,
                "mitre_id": "T1046",
                "severity": "HIGH",
                "description": "Vertical port scan detected",
                "group_by": "source_ip",
                "unique_field": "destination_port",
                "event_filter": "network_connection_blocked"
            },
            "horizontal_port_scan": {
                "enabled": True,
                "threshold": 10,
                "window_seconds": 60,
                "mitre_id": "T1046",
                "severity": "HIGH",
                "description": "Horizontal port scan detected",
                "group_by": "source_ip",
                "unique_field": "destination_ip",
                "event_filter": "network_connection_blocked"
            },
            "beaconing_c2": {
                "enabled": False,
                "disabled_reason": "Requires ordered network-flow intervals not collected by the Windows pilot agent",
                "threshold": 10,
                "variance_seconds": 1,
                "mitre_id": "T1071",
                "severity": "CRITICAL",
                "description": "C2 beaconing pattern detected",
                "group_by": "source_ip",
                "event_filter": "network_connection"
            },
            "long_duration_connection": {
                "enabled": False,
                "disabled_reason": "Requires connection start/end or duration telemetry",
                "threshold_hours": 24,
                "mitre_id": "T1572",
                "severity": "MEDIUM",
                "description": "Long-duration connection - Potential tunnel",
                "event_filter": "network_connection"
            },
            "rare_port_usage": {
                "enabled": False,
                "disabled_reason": "Requires a tenant port baseline and complete network-flow telemetry",
                "mitre_id": "T1571",
                "severity": "MEDIUM",
                "description": "Rare port usage detected",
                "event_filter": "network_connection",
                "suspicious_ports": [
                    6667,
                    6697,
                    31337,
                    12345,
                    54321,
                    1337
                ]
            },
            "dns_tunneling": {
                "enabled": False,
                "disabled_reason": "Native Windows DNS query telemetry is not collected by the pilot agent",
                "threshold": 50,
                "window_seconds": 60,
                "subdomain_min_length": 50,
                "mitre_id": "T1071.004",
                "severity": "HIGH",
                "description": "DNS tunneling detected",
                "group_by": "source_ip",
                "event_filter": "dns_query"
            },
            "rdp_brute_force": {
                "enabled": True,
                "threshold": 10,
                "window_seconds": 60,
                "mitre_id": "T1021.001",
                "severity": "HIGH",
                "description": "RDP brute force detected",
                "group_by": "source_ip",
                "event_filter": "failed_login",
                "logon_types": ["10"]
            },
            "smb_storm": {
                "enabled": True,
                "threshold": 100,
                "window_seconds": 60,
                "mitre_id": "T1021.002",
                "severity": "HIGH",
                "description": "SMB access storm detected",
                "group_by": "source_ip",
                "event_filter": "network_share_accessed"
            }
        },
        "web_application": {
            "high_vol_sql_injection": {
                "enabled": True,
                "threshold": 10,
                "window_seconds": 60,
                "mitre_id": "T1190",
                "severity": "HIGH",
                "description": "SQL injection flood detected",
                "group_by": "source_ip",
                "event_filter": "http_request",
                "sql_patterns": [
                    "'",
                    "union",
                    "select",
                    "insert",
                    "drop",
                    "delete",
                    "--",
                    "/*"
                ]
            },
            "directory_brute_force": {
                "enabled": False,
                "disabled_reason": "Web log collector does not yet emit a structured HTTP status code",
                "threshold": 20,
                "window_seconds": 60,
                "mitre_id": "T1083",
                "severity": "MEDIUM",
                "description": "Directory brute force detected",
                "group_by": "source_ip",
                "event_filter": "http_404"
            },
            "waf_evasion_flood": {
                "enabled": False,
                "disabled_reason": "Web log collector does not emit structured header or request-body sizes",
                "threshold": 50,
                "window_seconds": 60,
                "max_header_size": 8192,
                "max_payload_size": 1048576,
                "mitre_id": "T1190",
                "severity": "HIGH",
                "description": "WAF evasion flood detected",
                "group_by": "source_ip",
                "event_filter": "http_request"
            },
            "xss_flooding": {
                "enabled": True,
                "threshold": 10,
                "window_seconds": 60,
                "mitre_id": "T1059.007",
                "severity": "MEDIUM",
                "description": "XSS flood detected",
                "group_by": "source_ip",
                "event_filter": "http_request",
                "xss_patterns": [
                    "<script",
                    "javascript:",
                    "onerror=",
                    "onload="
                ]
            },
            "bot_scraping": {
                "enabled": True,
                "threshold": 100,
                "window_seconds": 60,
                "mitre_id": "T1213",
                "severity": "LOW",
                "description": "Bot scraping detected",
                "group_by": "source_ip",
                "event_filter": "http_request",
                "target_path_prefix": "/product"
            },
            "error_storm": {
                "enabled": False,
                "disabled_reason": "Web log collector does not yet emit a structured HTTP status code",
                "threshold": 50,
                "window_seconds": 60,
                "mitre_id": "T1499",
                "severity": "MEDIUM",
                "description": "Application error storm detected",
                "group_by": "source_ip",
                "event_filter": "http_500"
            }
        }
    },
}
