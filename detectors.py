"""Detection rules functions"""
import re
from collections import defaultdict
from utils import generate_finding_id, validate_ip
from threat_intel import is_malicious_ip

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

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
            print(f"Error in failed login detection: {e}")
    
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
    
    for event in events:
        try:
            msg = event.get("message", "").lower()
            matched_keywords = [kw for kw in keywords if kw.lower() in msg]
            if matched_keywords:
                findings.append({
                    "id": generate_finding_id(), 
                    "attack_type": "Suspicious Command Execution",
                    "summary": f"Suspicious command detected: {', '.join(matched_keywords)}",
                    "explanation": "Potentially malicious command execution", 
                    "severity": "high",
                    "evidence": [event.get("raw", "")], 
                    "matched_keywords": matched_keywords, 
                    "confidence": 0.8
                })
        except Exception as e:
            print(f"Error in suspicious command detection: {e}")
    
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
            print(f"Error in malicious IP detection: {e}")
    
    return findings

def run_detection_rules(events: List[Dict[str, Any]], config: Dict, threat_intel: Dict) -> List[Dict[str, Any]]:
    """Run all detection rules"""
    findings = []
    
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
            print(f"Detection rule failed: {e}")
    
    return findings
