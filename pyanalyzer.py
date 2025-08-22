import re
import json
import os
import logging
import uuid
import time
import csv
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Generator
from collections import defaultdict, Counter
import threading
import queue
import ipaddress

# CONFIGURATION POINT --- #
class Config:
    """Centralized configuration management"""
    DEFAULTS = {
        "brute_force_threshold": 5,
        "port_scan_threshold": 5,
        "max_file_size_mb": 1024,
        "analysis_timeout_seconds": 300,
        "batch_size": 1000,
        "suspicious_keywords": [
            "powershell", "invoke-webrequest", "wget", "curl", "mshta",
            "certutil", "net user", "schtasks", "regsvr32", "rundll32",
            "mimikatz", "bloodhound", "nishang", "empire", "cobaltstrike"
          
        ],
        "high_severity_keywords": ["powershell", "mimikatz", "bloodhound", "cobaltstrike"],
        "severity_levels": ["low", "medium", "high", "critical"]
    }
    
    def __init__(self, config_dict: Optional[Dict] = None):
        self.settings = {**self.DEFAULTS, **(config_dict or {})}
    
    def get(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)

#\ LOGGING SETUP  #
def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure enterprise-grade logging"""
    logger = logging.getLogger("siem_analyzer")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

#ENHANCED PARSERS- #
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def parse_syslog_text(text: str) -> List[Dict[str, Any]]:
    """Enhanced syslog parser with multiple patterns and fallback"""
    events = []
    for line_num, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        
        # Multiple syslog patterns with fallback
        patterns = [
            # Classic syslog: "Jan 12 10:23:45 host process[pid]: message"
            r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$",
            # RFC 5424 format with timestamp
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$",
            # Simplified format
            r"^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)$",
            # Windows event log style
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(.*)$"
        ]
        
        parsed = False
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                groups = match.groups()
                timestamp = groups[0] if len(groups) > 0 else ""
                host = groups[1] if len(groups) > 1 else ""
                process = groups[2] if len(groups) > 2 else ""
                message = groups[3] if len(groups) > 3 else line
                
                events.append({
                    "raw": line,
                    "timestamp": timestamp,
                    "host": host,
                    "process": process,
                    "message": message,
                    "line_number": line_num
                })
                parsed = True
                break
        
        # Fallback to generic parsing if no pattern matched
        if not parsed:
            events.append({
                "raw": line,
                "timestamp": "",
                "host": "",
                "process": "",
                "message": line,
                "line_number": line_num
            })
    
    return events

def parse_csv_file(path: str) -> List[Dict[str, Any]]:
    """Robust CSV parser with automatic field detection"""
    events = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            # Sniff dialect to handle different CSV formats
            try:
                sample = f.read(1024)
                f.seek(0)
                dialect = csv.Sniffer().sniff(sample)
                has_header = csv.Sniffer().has_header(sample)
                f.seek(0)
            except:
                dialect = csv.excel
                has_header = True
            
            if has_header:
                reader = csv.DictReader(f, dialect=dialect)
                fieldnames = [f.lower() for f in reader.fieldnames] if reader.fieldnames else []
                
                for row_num, row in enumerate(reader, 1):
                    # Auto-detect common field names
                    timestamp = next((row[k] for k in row if k.lower() in ['timestamp', 'time', 'date', 'datetime']), "")
                    host = next((row[k] for k in row if k.lower() in ['host', 'hostname', 'server', 'computer']), "")
                    process = next((row[k] for k in row if k.lower() in ['process', 'service', 'application', 'program']), "")
                    message = next((row[k] for k in row if k.lower() in ['message', 'log', 'event', 'description']), 
                                  json.dumps(row))
                    
                    events.append({
                        "raw": json.dumps(row),
                        "timestamp": timestamp,
                        "host": host,
                        "process": process,
                        "message": message,
                        "line_number": row_num,
                        "source": "csv"
                    })
            else:
                # No header row, treat as simple CSV
                reader = csv.reader(f, dialect=dialect)
                for row_num, row in enumerate(reader, 1):
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
        logger.error(f"CSV parsing error: {e}")
        # Fallback to generic text parsing
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
        return parse_syslog_text(text)
    
    return events

def parse_evtx_file(path: str) -> List[Dict[str, Any]]:
    """Enhanced EVTX parser with timestamp and host extraction"""
    try:
        from Evtx import Evtx
    except ImportError as e:
        raise ImportError("python-evtx not installed. Install with: pip install python-evtx") from e

    events = []
    try:
        with Evtx.Evtx(path) as evtx:
            for record in evtx.records():
                xml = record.xml()
                
                # Extract timestamp from EVTX
                timestamp_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml)
                timestamp = timestamp_match.group(1) if timestamp_match else ""
                
                # Extract computer name
                computer_match = re.search(r'<Computer>([^<]+)</Computer>', xml)
                computer = computer_match.group(1) if computer_match else ""
                
                # Extract event data
                event_data_match = re.search(r'<Data>(.*?)</Data>', xml, re.DOTALL)
                message = event_data_match.group(1) if event_data_match else xml[:500] + "..."  # Truncate large XML
                
                events.append({
                    "raw": xml,
                    "timestamp": timestamp,
                    "host": computer,
                    "process": "windows-event",
                    "message": message,
                    "source": "evtx"
                })
    except Exception as e:
        raise Exception(f"Error parsing EVTX file: {str(e)}")
    
    return events

def parse_generic_text(text: str) -> List[Dict[str, Any]]:
    """Fallback parser for unstructured text"""
    events = []
    for line_num, line in enumerate(text.splitlines(), 1):
        if line.strip():
            events.append({
                "raw": line,
                "timestamp": "",
                "host": "",
                "process": "",
                "message": line,
                "line_number": line_num,
                "source": "text"
            })
    return events

# ---------------------------- ENHANCED DETECTION RULES ---------------------------- #
def detect_failed_logins(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect failed login attempts without brute-force duplication"""
    findings = []
    patterns = [
        r"failed password",
        r"authentication failure",
        r"login failed",
        r"invalid user",
        r"authentication error",
        r"access denied",
        r"wrong password"
    ]
    
    for event in events:
        msg = event.get("message", "").lower()
        if any(re.search(pattern, msg) for pattern in patterns):
            ips = IP_REGEX.findall(event.get("raw", ""))
            valid_ips = [ip for ip in ips if validate_ip(ip)]
            
            findings.append({
                "id": generate_finding_id(),
                "attack_type": "Failed Login",
                "summary": f"Failed login detected: {msg[:100]}...",
                "explanation": "Authentication attempt failed - could indicate brute force or unauthorized access attempt.",
                "severity": "medium",
                "evidence": [event.get("raw", "")],
                "source_ips": valid_ips,
                "event_timestamp": event.get("timestamp"),
                "line_number": event.get("line_number"),
                "confidence": 0.7
            })
    
    return findings

def detect_brute_force(events: List[Dict[str, Any]], threshold: int = 5) -> List[Dict[str, Any]]:
    """Detect brute force patterns without duplicating single failed logins"""
    ip_attempts = defaultdict(list)
    
    # Collect failed login attempts by IP
    for event in events:
        msg = event.get("message", "").lower()
        if any(k in msg for k in ["failed password", "failed login", "invalid user", "authentication failure"]):
            for ip in IP_REGEX.findall(event.get("raw", "")):
                if validate_ip(ip):
                    ip_attempts[ip].append(event)
    
    findings = []
    for ip, attempts in ip_attempts.items():
        if len(attempts) >= threshold:
            # Only create brute force finding if threshold met
            timestamps = [e.get("timestamp") for e in attempts if e.get("timestamp")]
            time_range = f" over {len(timestamps)} attempts" if timestamps else ""
            
            findings.append({
                "id": generate_finding_id(),
                "attack_type": "Brute Force Attack",
                "summary": f"Brute force attack detected from {ip} ({len(attempts)} attempts)",
                "explanation": f"Multiple failed authentication attempts from single IP indicating brute force attack{time_range}.",
                "severity": "high",
                "evidence": [e.get("raw") for e in attempts[:3]],
                "source_ips": [ip],
                "count": len(attempts),
                "confidence": 0.9
            })
    
    return findings

# ---------------------------- UTILITY FUNCTIONS ---------------------------- #
def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def generate_finding_id() -> str:
    """Generate unique finding ID"""
    return f"find_{uuid.uuid4().hex[:12]}"

def matches_cidr(ip: str, cidr: str) -> bool:
    """Check if IP matches CIDR range"""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False

# ---------------------------- OUTPUT FORMATTERS ---------------------------- #
def generate_text_report(analysis_result: Dict[str, Any]) -> str:
    """Generate human-readable text report"""
    report = []
    metadata = analysis_result.get("metadata", {})
    stats = analysis_result.get("statistics", {})
    findings = analysis_result.get("findings", [])
    
    # Header
    report.append("=" * 60)
    report.append("SIEM SECURITY ANALYSIS REPORT")
    report.append("=" * 60)
    report.append(f"File: {metadata.get('file_name', 'N/A')}")
    report.append(f"Analyzed: {metadata.get('analyzed_at', 'N/A')}")
    report.append(f"Duration: {metadata.get('analysis_duration', 0):.2f} seconds")
    report.append(f"Total Events: {stats.get('total_events', 0)}")
    report.append(f"Total Findings: {stats.get('total_findings', 0)}")
    report.append("-" * 60)
    
    # Findings by severity
    severity_counts = stats.get('findings_by_severity', {})
    if severity_counts:
        report.append("FINDINGS BY SEVERITY:")
        for severity, count in severity_counts.items():
            report.append(f"  {severity.upper()}: {count}")
        report.append("-" * 60)
    
    # Individual findings
    if findings:
        report.append("DETAILED FINDINGS:")
        report.append("-" * 60)
        
        for i, finding in enumerate(findings, 1):
            report.append(f"{i}. [{finding.get('severity', 'medium').upper()}] {finding.get('attack_type')}")
            report.append(f"   Summary: {finding.get('summary')}")
            report.append(f"   Explanation: {finding.get('explanation')}")
            if finding.get('source_ips'):
                report.append(f"   Source IPs: {', '.join(finding.get('source_ips'))}")
            if finding.get('count', 1) > 1:
                report.append(f"   Count: {finding.get('count')}")
            report.append("")
    else:
        report.append("No security findings detected.")
        report.append("")
    
    report.append("=" * 60)
    report.append("Analysis completed successfully.")
    
    return "\n".join(report)

# ---------------------------- MAIN ANALYZER CLASS ---------------------------- #
class SIEMAnalyzer:
    """Enterprise-grade log analyzer with all fixes applied"""
    
    def __init__(self, config: Optional[Dict] = None, db_config: Optional[Dict] = None):
        self.config = Config(config)
        self.db_config = db_config or {}
        self.analysis_stats = defaultdict(int)
    
    def analyze_file(self, file_path: str, intel_list: Optional[List[str]] = None) -> Dict[str, Any]:
        """Main analysis method with all enhancements"""
        start_time = time.time()
        
        # Validate file
        validation_result = self._validate_file(file_path)
        if 'error' in validation_result:
            return validation_result
        
        # Parse file based on extension
        try:
            _, ext = os.path.splitext(file_path.lower())
            if ext == '.csv':
                events = parse_csv_file(file_path)
                source_type = "csv"
            elif ext == '.evtx':
                events = parse_evtx_file(file_path)
                source_type = "evtx"
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                events = parse_syslog_text(text)
                source_type = "text"
            
            if not events:
                return {"error": "no-events", "message": "No events found in file"}
                
        except Exception as e:
            logger.error(f"File parsing failed: {e}")
            return {"error": "parse-error", "message": str(e)}
        
        # Run detection rules
        findings = self._run_detection_rules(events, intel_list or [])
        
        # Prepare comprehensive results
        analysis_time = time.time() - start_time
        result = self._prepare_results(file_path, events, findings, analysis_time, source_type)
        
        # Generate text report
        result["text_report"] = generate_text_report(result)
        
        logger.info(f"Analysis completed: {len(findings)} findings in {analysis_time:.2f}s")
        return result
    
    def _validate_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file validation"""
        if not os.path.exists(file_path):
            return {"error": "file-not-found", "message": f"File {file_path} does not exist"}
        
        if not os.access(file_path, os.R_OK):
            return {"error": "access-denied", "message": f"Cannot read file {file_path}"}
        
        file_size = os.path.getsize(file_path)
        max_size = self.config.get('max_file_size_mb') * 1024 * 1024
        
        if file_size == 0:
            return {"error": "empty-file", "message": "File is empty"}
        
        if file_size > max_size:
            return {"error": "file-too-large", "message": f"File exceeds maximum size of {self.config.get('max_file_size_mb')}MB"}
        
        return {"valid": True, "file_size": file_size}
    
    def _run_detection_rules(self, events: List[Dict[str, Any]], intel_list: List[str]) -> List[Dict[str, Any]]:
        """Execute all detection rules with deduplication"""
        all_findings = []
        
        # Run detection rules
        all_findings.extend(detect_failed_logins(events))
        all_findings.extend(detect_brute_force(events, self.config.get('brute_force_threshold')))
        
        # Additional detection rules would go here...
        
        # Deduplicate findings
        unique_findings = self._deduplicate_findings(all_findings)
        
        return unique_findings
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings to avoid double-counting"""
        unique_findings = []
        seen_patterns = set()
        
        for finding in findings:
            # Create unique signature for each finding type
            if finding['attack_type'] == 'Brute Force Attack':
                # For brute force, use IP + count as signature
                signature = f"brute_force_{finding['source_ips'][0]}_{finding['count']}"
            else:
                # For others, use attack type + first evidence line
                signature = f"{finding['attack_type']}_{finding['evidence'][0][:100]}"
            
            if signature not in seen_patterns:
                seen_patterns.add(signature)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _prepare_results(self, file_path: str, events: List[Dict[str, Any]], 
                        findings: List[Dict[str, Any]], analysis_time: float, source_type: str) -> Dict[str, Any]:
        """Prepare comprehensive results"""
        return {
            "metadata": {
                "file_name": os.path.basename(file_path),
                "file_path": os.path.abspath(file_path),
                "file_size": os.path.getsize(file_path),
                "source_type": source_type,
                "analysis_duration": round(analysis_time, 2),
                "analyzed_at": datetime.utcnow().isoformat() + "Z",
                "analyzer_version": "2.1.0"
            },
            "statistics": {
                "total_events": len(events),
                "total_findings": len(findings),
                "findings_by_severity": dict(Counter(f["severity"] for f in findings)),
                "findings_by_type": dict(Counter(f["attack_type"] for f in findings)),
                "events_processed_per_second": round(len(events) / analysis_time, 2) if analysis_time > 0 else 0
            },
            "findings": findings,
            "status": "completed"
        }

# EXECUTION WOHOOO MAZAA ARHA HA #
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enterprise SIEM Analyzer")
    parser.add_argument("--file", "-f", required=True, help="File to analyze")
    parser.add_argument("--intel", "-i", help="Comma-separated list of suspicious IPs/CIDR")
    parser.add_argument("--output", "-o", choices=['json', 'text', 'both'], default='both', 
                       help="Output format: json, text, or both")
    parser.add_argument("--threshold", "-t", type=int, help="Brute force threshold")
    
    args = parser.parse_args()
    
    # Initialize analyzer with config
    config = {}
    if args.threshold:
        config["brute_force_threshold"] = args.threshold
    
    analyzer = SIEMAnalyzer(config)
    
    # Parse threat intelligence list
    intel_list = []
    if args.intel:
        intel_list = [item.strip() for item in args.intel.split(",") if item.strip()]
    
    # Analyze file
    result = analyzer.analyze_file(args.file, intel_list)
    
    # Output results
    if 'error' in result:
        print(f"Error: {result['message']}")
        exit(1)
    
    if args.output in ['json', 'both']:
        print(json.dumps(result, indent=2))
    
    if args.output in ['text', 'both'] and 'text_report' in result:
        print("\n" + "="*60)
        print("TEXT REPORT")
        print("="*60)
        print(result['text_report'])
    
    exit(0 if result['statistics']['total_findings'] == 0 else 1)
