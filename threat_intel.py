"""Threat intelligence functions"""
import re
import os
from utils import validate_ip

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def load_threat_intelligence(config):
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
            print(f"Failed to load threat intel from {file_path}: {e}")
    
    print(f"Loaded threat intelligence: {len(threat_intel['ips'])} IPs, {len(threat_intel['cidrs'])} CIDRs")
    return threat_intel

def is_malicious_ip(ip: str, threat_intel: dict) -> bool:
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
        print("ipaddress module not available, CIDR matching disabled")
    
    return False
