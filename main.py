import os
import sys
import json
import time
from datetime import datetime
from collections import Counter
from typing import Dict, Any, List

#!/usr/bin/env python3
"""SIEM Analyzer - Main entry point"""
import argparse
import sys
import json
from config_loader import load_config
from threat_intel import load_threat_intelligence
from parsers import parse_file_based_on_type
from detectors import run_detection_rules
from outputs import generate_text_report
from utils import setup_logging, validate_file_access

def analyze_file(file_path: str, file_type: str = "auto", config_file: str = "config.json") -> Dict[str, Any]:
    """Main analysis function"""
    import time
    from datetime import datetime
    from collections import Counter
    
    start_time = time.time()
    logger = setup_logging()
    
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
    findings = run_detection_rules(events, config, threat_intel)
    
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

def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description="SIEM Log Analyzer - Analyze security logs for threats and anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --file access.log
  python main.py --file security.csv --type csv
  python main.py --file events.evtx --output json
  python main.py --file auth.log --config myconfig.json --verbose
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
