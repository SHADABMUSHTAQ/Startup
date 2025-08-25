import re
import json
import os
import logging
import uuid
import time
import csv
import argparse
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter

# Default configuration with enhanced command detection
DEFAULT_CONFIG = {
    "threat_intelligence": {
        "ips": [],
        "cidrs": [],
        "files": []
    },
    "detection": {
        "brute_force_threshold": 3,
        "port_scan_threshold": 5,
        "failed_login_patterns": [
            "failed password", "authentication failure", "login failed",
            "invalid user", "access denied", "authentication error",
            "status=failed", "status=fail"
        ],
        "suspicious_keywords": [
            "malware", "trojan", "exploit", "ransomware", "backdoor",
            "powershell -enc", "iex", "invoke-expression", "nishang",
            "mimikatz", "cobaltstrike", "metasploit", "reverse shell",
            "privilege escalation", "web shell", "c99 shell", "r57 shell",
            "bind shell", "port scan", "sql injection", "xss",
            "cross-site scripting", "buffer overflow", "credential dump",
            "pass-the-hash", "golden ticket", "lateral movement",
            "exfiltration", "data theft", "keylogger", "rootkit",
            "command and control", "c2", "exfiltration"
        ],
        "suspicious_file_extensions": [
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
            ".dll", ".scr", ".com", ".pif", ".application", ".gadget",
            ".msi", ".msp", ".mst", ".sys", ".drv", ".bin", ".cpl",
            ".hta", ".scr", ".sh", ".py", ".pl", ".rb", ".sh", ".deb",
            ".rpm", ".app", ".dmg", ".apk"
        ],
        "suspicious_commands": [
            "format", "fdisk", "diskpart", "chmod", "chown", "wget",
            "curl", "lynx", "nc", "netcat", "ncat", "telnet", "ssh",
            "scp", "ftp", "tftp", "certutil", "bitsadmin", "debug",
            "reg add", "reg delete", "reg copy", "reg save", "taskkill",
            "schtasks", "at", "crontab", "nslookup", "dig", "whois",
            "tracert", "traceroute", "route", "arp", "netstat", "ipconfig",
            "ifconfig", "systeminfo", "whoami", "quser", "query user",
            "ps", "tasklist", "get-process", "net user", "net group",
            "net localgroup", "net share", "net session", "net use",
            "mount", "umount", "mkdir", "rmdir", "rm", "del", "erase",
            "move", "copy", "xcopy", "robocopy", "attrib", "icacls",
            "cacls", "takeown", "fsutil", "vssadmin", "wbadmin", "bcdedit",
            "bootcfg", "diskraid", "lodctr", "unlodctr", "typeperf",
            "logman", "wevtutil", "eventcreate", "auditpol", "subinacl",
            "sc", "net start", "net stop", "shutdown", "powercfg",
            "psshutdown", "pskill", "psexec", "psexec", "wmic", "wscript",
            "cscript", "rundll32", "regsvr32", "msiexec", "msbuild",
            "csc", "vbc", "jsc", "rc", "cl", "link", "nmake", "cmake",
            "make", "gcc", "g++", "clang", "clang++", "apt-get", "yum",
            "dnf", "zypper", "pacman", "emerge", "pip", "gem", "npm",
            "composer", "docker", "kubectl", "helm", "terraform", "ansible",
            "puppet", "chef", "salt", "vagrant", "virtualbox", "vmware",
            "vboxmanage", "vmrun", "qemu", "xen", "hyper-v", "azure",
            "aws", "gcloud", "oci", "ibmcloud", "openstack", "minikube",
            "kind", "k3s", "k0s", "microk8s", "k9s", "krew", "tiller",
            "helm", "istio", "linkerd", "envoy", "consul", "vault",
            "nomad", "serf", "terraform", "packer", "vagrant", "ansible",
            "puppet", "chef", "salt", "cfn", "cloudformation", "troposphere",
            "pulumi", "cdk", "sceptre", "formica", "stacker", "kustomize",
            "ksonnet", "jsonnet", "dhall", "cue", "nickel", "json",
            "yaml", "yml", "toml", "ini", "xml", "csv", "tsv", "jsonl",
            "ndjson", "hcl", "tf", "tfvars", "pp", "rb", "py", "pl",
            "pm", "t", "php", "js", "ts", "jsx", "tsx", "vue", "svelte",
            "angular", "react", "next", "nuxt", "gatsby", "gridsome",
            "quasar", "electron", "nw", "react-native", "flutter",
            "dart", "kotlin", "swift", "objective-c", "java", "scala",
            "clojure", "groovy", "go", "rust", "haskell", "ocaml",
            "f#", "elixir", "erlang", "cobol", "fortran", "pascal",
            "basic", "lisp", "scheme", "prolog", "smalltalk", "forth",
            "ada", "verilog", "vhdl", "systemverilog", "verilog",
            "chisel", "bluespec", "spinalhdl", "nmigen", "magma",
            "coreir", "llhd", "calyx", "dahlia", "heterocl", "spark",
            "accord", "kafka", "rabbitmq", "nats", "zeromq", "activemq",
            "ibmmq", "amqp", "mqtt", "stomp", "jms", "websocket",
            "socketio", "sockjs", "signalr", "grpc", "thrift", "avro",
            "protobuf", "flatbuffers", "capnproto", "msgpack", "cbor",
            "bson", "ubjson", "smile", "ion", "avro", "parquet",
            "orc", "arrow", "feather", "hdf5", "netcdf", "zarr",
            "tensorflow", "pytorch", "keras", "mxnet", "caffe",
            "caffe2", "onnx", "openvino", "tensorrt", "ncnn", "mnn",
            "paddlepaddle", "mindspore", "darknet", "yolo", "detectron",
            "maskrcnn", "retinanet", "efficientdet", "centernet",
            "yolov", "ssd", "fasterrcnn", "resnet", "inception",
            "vgg", "mobilenet", "shufflenet", "squeezenet", "densenet",
            "nasnet", "pnasionet", "efficientnet", "regnet", "vision",
            "detr", "swin", "vit", "bert", "gpt", "transformer",
            "t5", "bart", "electra", "albert", "xlnet", "roberta",
            "distilbert", "camembert", "flaubert", "xlm", "mbert",
            "xlmroberta", "layoutlm", "longformer", "reformer",
            "linformer", "performer", "bigbird", "led", "rag",
            "dpr", "biencoder", "polyencoder", "crossencoder",
            "colbert", "densephrases", "realm", "orqa", "dpr",
            "rag", "tapas", "tabnet", "namu", "fttransformer",
            "tabtransformer", "autoint", "xdeepfm", "deepfm",
            "nfm", "afm", "ffm", "fm", "lr", "gbdt", "xgboost",
            "lightgbm", "catboost", "ngboost", "tabnet", "namu",
            "node", "snap", "deepgbm", "gaminet", "stg", "born",
            "inn", "eanet", "nam", "namu", "nami", "naml", "namu",
            "nam", "nami", "naml", "namu", "nam", "nami", "naml"
        ]
    },
    "system": {
        "max_file_size_mb": 100,
        "log_level": "INFO",
        "log_file": "logs/analyzer.log",
        "output_format": "both"
    }
}

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
COMMAND_REGEX = re.compile(r'\b([a-zA-Z0-9_\-]+)(?:\s+|$)')

# ---------------------------- LOGGING SETUP ---------------------------- #
def setup_logging(log_level: str = "INFO", log_file: str = "analyzer.log") -> logging.Logger:
    """Configure comprehensive logging"""
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logger = logging.getLogger("SIEMAnalyzer")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.handlers.clear()
    
    console_handler = logging.StreamHandler()
    console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    try:
        file_handler = logging.FileHandler(log_file)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Failed to set up file logging: {e}")
    
    return logger

logger = setup_logging()

# ---------------------------- CONFIGURATION ---------------------------- #
def load_config(config_file: str = "config.json") -> Dict[str, Any]:
    """Load configuration from JSON file"""
    config = DEFAULT_CONFIG.copy()
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            for section, settings in user_config.items():
                if section in config and isinstance(settings, dict):
                    config[section].update(settings)
                else:
                    config[section] = settings
            logger.info(f"Configuration loaded from {config_file}")
        else:
            logger.warning(f"Config file {config_file} not found, using defaults")
    except Exception as e:
        logger.error(f"Error loading config: {e}")
    
    return config

# ---------------------------- UTILITY FUNCTIONS ---------------------------- #
def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except (ImportError, ValueError):
        return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) is not None

def generate_finding_id() -> str:
    """Generate unique finding ID"""
    return f"find_{uuid.uuid4().hex[:12]}"

def validate_file_access(file_path: str, max_size_mb: int = 100) -> Dict[str, Any]:
    """Comprehensive file validation"""
    try:
        if not os.path.exists(file_path):
            return {"valid": False, "error": "file-not-found", "message": f"File {file_path} does not exist"}
        if not os.access(file_path, os.R_OK):
            return {"valid": False, "error": "access-denied", "message": f"Cannot read file {file_path}"}
        
        file_size = os.path.getsize(file_path)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        if file_size == 0:
            return {"valid": False, "error": "empty-file", "message": "File is empty"}
        if file_size > max_size_bytes:
            return {"valid": False, "error": "file-too-large", "message": f"File exceeds maximum size of {max_size_mb}MB"}
        
        return {"valid": True, "file_size": file_size}
    except Exception as e:
        return {"valid": False, "error": "validation-error", "message": str(e)}

# ---------------------------- THREAT INTELLIGENCE ---------------------------- #
def load_threat_intelligence(config: Dict) -> Dict[str, Any]:
    """Load threat intelligence from multiple sources"""
    threat_intel = {"ips": set(), "cidrs": set(), "domains": set()}
    ti_config = config.get("threat_intelligence", {})
    
    for ip in ti_config.get("ips", []):
        if validate_ip(ip):
            threat_intel["ips"].add(ip)
    
    for cidr in ti_config.get("cidrs", []):
        threat_intel["cidrs"].add(cidr)
    
    for file_path in ti_config.get("files", []):
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if re.match(IP_REGEX, line) and validate_ip(line):
                                threat_intel["ips"].add(line)
                            elif '/' in line:
                                threat_intel["cidrs"].add(line)
                            else:
                                threat_intel["domains"].add(line)
        except Exception as e:
            logger.error(f"Failed to load threat intel from {file_path}: {e}")
    
    logger.info(f"Loaded threat intelligence: {len(threat_intel['ips'])} IPs, {len(threat_intel['cidrs'])} CIDRs")
    return threat_intel

def is_malicious_ip(ip: str, threat_intel: Dict) -> bool:
    """Check if IP is in threat intelligence data"""
    if not validate_ip(ip):
        return False
    if ip in threat_intel['ips']:
        return True
    
    # Check if IP belongs to any malicious CIDR
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        for cidr in threat_intel['cidrs']:
            try:
                network = ipaddress.ip_network(cidr)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
    except ImportError:
        logger.warning("ipaddress module not available, CIDR matching disabled")
    
    return False

# ---------------------------- FILE PARSERS ---------------------------- #
def parse_syslog_text(text: str) -> List[Dict[str, Any]]:
    """Enhanced syslog parser with comprehensive error handling"""
    events = []
    try:
        for line_num, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                patterns = [
                    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$",
                    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$",
                    r"^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)$"
                ]
                
                parsed = False
                for pattern in patterns:
                    match = re.match(pattern, line)
                    if match:
                        groups = match.groups()
                        timestamp = groups[0] if len(groups) > 0 else "N/A"
                        host = groups[1] if len(groups) > 1 else "N/A"
                        process = groups[2] if len(groups) > 2 else "N/A"
                        message = groups[3] if len(groups) > 3 else line
                        
                        events.append({
                            "raw": line, "timestamp": timestamp, "host": host,
                            "process": process, "message": message, "line_number": line_num
                        })
                        parsed = True
                        break
                
                if not parsed:
                    events.append({
                        "raw": line, "timestamp": "N/A", "host": "N/A",
                        "process": "N/A", "message": line, "line_number": line_num
                    })
                    
            except Exception as e:
                logger.warning(f"Error parsing line {line_num}: {e}")
                events.append({
                    "raw": line, "timestamp": "N/A", "host": "N/A",
                    "process": "N/A", "message": line, "line_number": line_num
                })
    except Exception as e:
        logger.error(f"Failed to parse syslog text: {e}")
        raise
    
    return events

def parse_csv_file(path: str) -> List[Dict[str, Any]]:
    """Robust CSV parser with comprehensive error handling and field mapping"""
    events = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            sample = f.read(2048)
            f.seek(0)
            
            try:
                has_header = csv.Sniffer().has_header(sample)
                dialect = csv.Sniffer().sniff(sample)
            except:
                has_header = True
                dialect = csv.excel
            
            if has_header:
                reader = csv.DictReader(f, dialect=dialect)
                for row_num, row in enumerate(reader, 1):
                    try:
                        timestamp = row.get('timestamp') or row.get('time') or row.get('date') or ""
                        host = row.get('host') or row.get('hostname') or row.get('server') or row.get('ip') or ""
                        process = row.get('process') or row.get('service') or row.get('application') or row.get('action') or ""
                        
                        # Create a meaningful message for detection rules
                        message_parts = []
                        for key, value in row.items():
                            if key.lower() not in ['timestamp', 'time', 'date', 'host', 'hostname', 'server', 'process', 'service', 'application']:
                                if value and value != 'N/A':
                                    message_parts.append(f"{key}={value}")
                        
                        message = " | ".join(message_parts)
                        
                        events.append({
                            "raw": json.dumps(row), 
                            "timestamp": timestamp, 
                            "host": host,
                            "process": process, 
                            "message": message, 
                            "line_number": row_num + 1, 
                            "source": "csv",
                            # Store extracted fields for specialized detection if needed
                            "_extracted": row
                        })
                    except Exception as e:
                        logger.warning(f"Error processing CSV row {row_num}: {e}")
            else:
                reader = csv.reader(f, dialect=dialect)
                for row_num, row in enumerate(reader, 1):
                    try:
                        events.append({
                            "raw": ",".join(row), 
                            "timestamp": row[0] if len(row) > 0 else "",
                            "host": row[1] if len(row) > 1 else "", 
                            "process": row[2] if len(row) > 2 else "",
                            "message": ",".join(row[3:]) if len(row) > 3 else ",".join(row),
                            "line_number": row_num, 
                            "source": "csv"
                        })
                    except Exception as e:
                        logger.warning(f"Error processing CSV row {row_num}: {e}")
    except Exception as e:
        logger.error(f"CSV parsing failed: {e}")
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            return parse_syslog_text(text)
        except:
            return []
    
    return events

def parse_evtx_file(path: str) -> List[Dict[str, Any]]:
    """EVTX parser with XML extraction and field parsing"""
    events = []
    try:
        from Evtx import Evtx
    except ImportError:
        logger.error("python-evtx not installed. Install with: pip install python-evtx")
        return []
    
    try:
        with Evtx.Evtx(path) as evtx:
            for record in evtx.records():
                try:
                    xml_content = record.xml()
                    
                    # Extract basic information from XML
                    timestamp_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml_content)
                    timestamp = timestamp_match.group(1) if timestamp_match else ""
                    
                    event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml_content)
                    event_id = event_id_match.group(1) if event_id_match else ""
                    
                    computer_match = re.search(r'<Computer>([^<]+)</Computer>', xml_content)
                    computer = computer_match.group(1) if computer_match else ""
                    
                    # Create a simplified message for detection
                    message = f"EventID: {event_id}, Computer: {computer}"
                    
                    events.append({
                        "raw": xml_content, 
                        "timestamp": timestamp, 
                        "host": computer,
                        "process": f"event-{event_id}", 
                        "message": message, 
                        "source": "evtx",
                        "_xml": xml_content  # Store full XML for advanced parsing
                    })
                except Exception as e:
                    logger.warning(f"Error processing EVTX record: {e}")
    except Exception as e:
        logger.error(f"EVTX parsing failed: {e}")
        return []
    
    return events

def parse_file_based_on_type(file_path: str, file_type: str = "auto") -> List[Dict[str, Any]]:
    """Parse file based on type or extension"""
    if file_type == "auto":
        _, ext = os.path.splitext(file_path.lower())
        if ext == '.csv': file_type = 'csv'
        elif ext == '.evtx': file_type = 'evtx'
        else: file_type = 'text'
    
    try:
        if file_type == 'csv': return parse_csv_file(file_path)
        elif file_type == 'evtx': return parse_evtx_file(file_path)
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            return parse_syslog_text(text)
    except Exception as e:
        logger.error(f"Failed to parse file {file_path}: {e}")
        return []

# ---------------------------- DETECTION RULES ---------------------------- #
def detect_failed_logins(events: List[Dict[str, Any]], config: Dict) -> List[Dict[str, Any]]:
    """Failed login detection with configurable patterns"""
    findings = []
    patterns = config.get("detection", {}).get("failed_login_patterns", [])
    
    for event in events:
        try:
            msg = event.get("message", "").lower()
            
            # Check for explicit status=failed in CSV-like messages
            is_failed = ("status=failed" in msg or "status=fail" in msg)
            
            # Check for pattern matches
            pattern_match = any(re.search(pattern, msg) for pattern in patterns)
            
            if is_failed or pattern_match:
                raw_text = event.get("raw", "")
                ips = IP_REGEX.findall(str(raw_text))
                valid_ips = [ip for ip in ips if validate_ip(ip)]
                
                # Extract IP from message if not found in raw text
                if not valid_ips:
                    msg_ips = IP_REGEX.findall(msg)
                    valid_ips = [ip for ip in msg_ips if validate_ip(ip)]
                
                findings.append({
                    "id": generate_finding_id(), 
                    "attack_type": "Failed Login",
                    "summary": f"Failed login detected: {msg[:100]}...",
                    "explanation": "Authentication attempt failed", 
                    "severity": "medium",
                    "evidence": [raw_text], 
                    "source_ips": valid_ips,
                    "event_timestamp": event.get("timestamp", "N/A"), 
                    "confidence": 0.7
                })
        except Exception as e:
            logger.warning(f"Error in failed login detection: {e}")
    
    return findings

def detect_brute_force(events: List[Dict[str, Any]], config: Dict) -> List[Dict[str, Any]]:
    """Detect brute force patterns across different log formats"""
    threshold = config.get("detection", {}).get("brute_force_threshold", 3)
    ip_attempts = defaultdict(list)
    
    for event in events:
        msg = event.get("message", "").lower()
        
        # Check multiple failure indicators
        is_failed = (
            any(pattern in msg for pattern in config.get("detection", {}).get("failed_login_patterns", [])) or
            "status=failed" in msg or
            "status=fail" in msg
        )
        
        if is_failed:
            # Extract IPs from both message and raw text
            ips = set()
            for text_source in [msg, event.get("raw", "")]:
                found_ips = IP_REGEX.findall(text_source)
                for ip in found_ips:
                    if validate_ip(ip):
                        ips.add(ip)
            
            # Add to tracking
            for ip in ips:
                ip_attempts[ip].append(event)
    
    findings = []
    
    # Check IP-based brute force
    for ip, attempts in ip_attempts.items():
        if len(attempts) >= threshold:
            findings.append({
                "id": generate_finding_id(), 
                "attack_type": "Brute Force Attack",
                "summary": f"Brute force attack detected from {ip} ({len(attempts)} attempts)",
                "explanation": "Multiple failed authentication attempts from same IP", 
                "severity": "high",
                "evidence": [e.get("raw") for e in attempts[:3]], 
                "source_ips": [ip],
                "count": len(attempts), 
                "confidence": 0.9
            })
    
    return findings

def detect_suspicious_commands(events: List[Dict[str, Any]], config: Dict) -> List[Dict[str, Any]]:
    """Detect suspicious commands using configurable keywords"""
    findings = []
    keywords = config.get("detection", {}).get("suspicious_keywords", [])
    commands = config.get("detection", {}).get("suspicious_commands", [])
    file_extensions = config.get("detection", {}).get("suspicious_file_extensions", [])
    
    for event in events:
        try:
            msg = event.get("message", "").lower()
            matched_keywords = [kw for kw in keywords if kw.lower() in msg]
            
            # Check for suspicious commands
            found_commands = []
            for cmd in commands:
                # Match whole words to avoid false positives
                if re.search(rf'\b{re.escape(cmd)}\b', msg, re.IGNORECASE):
                    found_commands.append(cmd)
            
            # Check for suspicious file extensions
            found_extensions = []
            for ext in file_extensions:
                if ext.lower() in msg:
                    found_extensions.append(ext)
            
            if matched_keywords or found_commands or found_extensions:
                # Create summary
                summary_parts = []
                if matched_keywords:
                    summary_parts.append(f"keywords: {', '.join(matched_keywords[:3])}")
                if found_commands:
                    summary_parts.append(f"commands: {', '.join(found_commands[:3])}")
                if found_extensions:
                    summary_parts.append(f"extensions: {', '.join(found_extensions[:3])}")
                
                summary = f"Suspicious activity detected: {'; '.join(summary_parts)}"
                if len(matched_keywords) > 3 or len(found_commands) > 3 or len(found_extensions) > 3:
                    summary += " ..."
                
                findings.append({
                    "id": generate_finding_id(), 
                    "attack_type": "Suspicious Command Execution",
                    "summary": summary,
                    "explanation": "Potentially malicious command or file activity", 
                    "severity": "high",
                    "evidence": [event.get("raw", "")], 
                    "matched_keywords": matched_keywords,
                    "matched_commands": found_commands,
                    "matched_extensions": found_extensions,
                    "confidence": 0.8
                })
        except Exception as e:
            logger.warning(f"Error in suspicious command detection: {e}")
    
    return findings

def detect_malicious_ips(events: List[Dict[str, Any]], threat_intel: Dict) -> List[Dict[str, Any]]:
    """Detect activity from malicious IPs using threat intelligence"""
    findings = []
    
    for event in events:
        try:
            raw_text = event.get("raw", "")
            msg = event.get("message", "")
            
            # Extract IPs from both raw text and message
            ips = set()
            for text_source in [raw_text, msg]:
                found_ips = IP_REGEX.findall(text_source)
                for ip in found_ips:
                    if validate_ip(ip):
                        ips.add(ip)
            
            for ip in ips:
                if is_malicious_ip(ip, threat_intel):
                    findings.append({
                        "id": generate_finding_id(), 
                        "attack_type": "Malicious IP Communication",
                        "summary": f"Activity from known malicious IP: {ip}",
                        "explanation": "Connection from malicious IP", 
                        "severity": "high",
                        "evidence": [raw_text], 
                        "source_ips": [ip], 
                        "confidence": 0.95
                    })
        except Exception as e:
            logger.warning(f"Error in malicious IP detection: {e}")
    
    return findings

# ---------------------------- OUTPUT FORMATTERS ---------------------------- #
def generate_text_report(analysis_result: Dict[str, Any]) -> str:
    """Generate human-readable text report"""
    report = []
    metadata = analysis_result.get("metadata", {})
    stats = analysis_result.get("statistics", {})
    findings = analysis_result.get("findings", [])
    
    report.append("=" * 60)
    report.append("SIEM SECURITY ANALYSIS REPORT")
    report.append("=" * 60)
    report.append(f"File: {metadata.get('file_name', 'N/A')}")
    report.append(f"Path: {metadata.get('file_path', 'N/A')}")
    report.append(f"Analyzed: {metadata.get('analyzed_at', 'N/A')}")
    report.append(f"Duration: {metadata.get('analysis_duration', 0):.2f}s")
    report.append(f"Total Events: {stats.get('total_events', 0)}")
    report.append(f"Total Findings: {stats.get('total_findings', 0)}")
    report.append("-" * 60)
    
    severity_counts = stats.get('findings_by_severity', {})
    if severity_counts:
        report.append("FINDINGS BY SEVERITY:")
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0: report.append(f"  {severity.upper()}: {count}")
        report.append("-" * 60)
    
    if findings:
        report.append("DETAILED FINDINGS:")
        report.append("-" * 60)
        for i, finding in enumerate(findings, 1):
            report.append(f"\n{i}. [{finding.get('severity', 'medium').upper()}] {finding.get('attack_type')}")
            report.append(f"   Summary: {finding.get('summary')}")
            report.append(f"   Explanation: {finding.get('explanation')}")
            if finding.get('source_ips'):
                report.append(f"   Source IPs: {', '.join(finding.get('source_ips'))}")
            if finding.get('matched_keywords'):
                report.append(f"   Keywords: {', '.join(finding.get('matched_keywords'))}")
            if finding.get('matched_commands'):
                report.append(f"   Commands: {', '.join(finding.get('matched_commands'))}")
            if finding.get('matched_extensions'):
                report.append(f"   File Extensions: {', '.join(finding.get('matched_extensions'))}")
            if finding.get('count', 1) > 1:
                report.append(f"   Count: {finding.get('count')}")
    else:
        report.append("\nNo security findings detected.")
    
    report.append("=" * 60)
    report.append("Analysis completed successfully.")
    return "\n".join(report)

# ---------------------------- MAIN ANALYZER ---------------------------- #
def analyze_file(file_path: str, file_type: str = "auto", config_file: str = "config.json") -> Dict[str, Any]:
    """Main analysis function with comprehensive error handling"""
    start_time = time.time()
    
    try:
        config = load_config(config_file)
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return {"error": "config-error", "message": str(e)}
    
    threat_intel = load_threat_intelligence(config)
    max_size = config.get("system", {}).get("max_file_size_mb", 100)
    validation_result = validate_file_access(file_path, max_size)
    
    if not validation_result.get("valid", False):
        logger.error(f"File validation failed: {validation_result.get('message')}")
        return validation_result
    
    logger.info(f"Analyzing {file_type} file: {file_path}")
    events = parse_file_based_on_type(file_path, file_type)
    
    if not events:
        logger.warning("No events found in file")
        return {"error": "no-events", "message": "No events found in file"}
    
    logger.info(f"Parsed {len(events)} events from file")
    findings = []
    
    try:
        detection_functions = [
            lambda e: detect_failed_logins(e, config),
            lambda e: detect_brute_force(e, config),
            lambda e: detect_suspicious_commands(e, config),
            lambda e: detect_malicious_ips(e, threat_intel)
        ]
        
        for detector in detection_functions:
            try:
                new_findings = detector(events)
                findings.extend(new_findings)
            except Exception as e:
                logger.error(f"Detection rule failed: {e}")
    except Exception as e:
        logger.error(f"Detection process failed: {e}")
        return {"error": "detection-error", "message": str(e)}
    
    analysis_time = time.time() - start_time
    result = {
        "metadata": {
            "file_name": os.path.basename(file_path), 
            "file_path": os.path.abspath(file_path),
            "file_type": file_type, 
            "file_size": validation_result.get("file_size", 0),
            "analysis_duration": round(analysis_time, 2), 
            "analyzed_at": datetime.utcnow().isoformat() + "Z",
            "analyzer_version": "2.0.0"
        },
        "statistics": {
            "total_events": len(events), 
            "total_findings": len(findings),
            "findings_by_severity": dict(Counter(f.get("severity", "unknown") for f in findings)),
            "findings_by_type": dict(Counter(f.get("attack_type", "unknown") for f in findings)),
            "events_processed_per_second": round(len(events) / analysis_time, 2) if analysis_time > 0 else 0
        },
        "findings": findings, 
        "status": "completed"
    }
    
    result["text_report"] = generate_text_report(result)
    logger.info(f"Analysis completed: {len(findings)} findings in {analysis_time:.2f}s")
    return result

# ---------------------------- COMMAND LINE INTERFACE ---------------------------- #
def main():
    """Command-line interface with comprehensive argument parsing"""
    parser = argparse.ArgumentParser(
        description="SIEM Log Analyzer - Analyze security logs for threats and anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py --file access.log
  python analyzer.py --file security.csv --type csv
  python analyzer.py --file events.evtx --output json
  python analyzer.py --file auth.log --config myconfig.json --verbose
        """
    )
    
    parser.add_argument("--file", "-f", required=True, help="Path to log file")
    parser.add_argument("--type", "-t", choices=['auto', 'text', 'csv', 'evtx'], default='auto', help="File type")
    parser.add_argument("--config", "-c", default="config.json", help="Configuration file")
    parser.add_argument("--output", "-o", choices=['json', 'text', 'both'], default='both', help="Output format")
    parser.add_argument("--log-level", "-l", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help="Logging level")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    log_level = "DEBUG" if args.verbose else args.log_level
    global logger
    logger = setup_logging(log_level=log_level)
    
    logger.info(f"Starting analysis of {args.file}")
    
    try:
        result = analyze_file(args.file, args.type, args.config)
        
        if 'error' in result:
            logger.error(f"Analysis failed: {result['message']}")
            print(f"Error: {result['message']}")
            sys.exit(1)
        
        if args.output in ['json', 'both']:
            print(json.dumps(result, indent=2))
        
        if args.output in ['text', 'both']:
            print("\n" + result["text_report"])
        
        sys.exit(0 if result['statistics']['total_findings'] == 0 else 1)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Critical error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
