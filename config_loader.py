"""Configuration loading functions"""
import json
import os

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
            "privilege escalation"
        ]
    },
    "system": {
        "max_file_size_mb": 100,
        "log_level": "INFO",
        "log_file": "logs/analyzer.log",
        "output_format": "both"
    }
}

def load_config(config_file: str = "config.json"):
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
            print(f"Configuration loaded from {config_file}")
        else:
            print(f"Config file {config_file} not found, using defaults")
    except Exception as e:
        print(f"Error loading config: {e}")
    
    return config
