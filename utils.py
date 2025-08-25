"""Utility functions"""
import os
import logging
import uuid
import re

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def setup_logging(log_level: str = "INFO", log_file: str = "logs/analyzer.log") -> logging.Logger:
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
