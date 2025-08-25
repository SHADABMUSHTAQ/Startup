"""Log parsing functions"""
import csv
import json
import re
from typing import List, Dict, Any

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

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
                print(f"Error parsing line {line_num}: {e}")
                events.append({
                    "raw": line, "timestamp": "N/A", "host": "N/A",
                    "process": "N/A", "message": line, "line_number": line_num
                })
    except Exception as e:
        print(f"Failed to parse syslog text: {e}")
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
                            "_extracted": row
                        })
                    except Exception as e:
                        print(f"Error processing CSV row {row_num}: {e}")
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
                        print(f"Error processing CSV row {row_num}: {e}")
    except Exception as e:
        print(f"CSV parsing failed: {e}")
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
        print("python-evtx not installed. Install with: pip install python-evtx")
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
                        "_xml": xml_content
                    })
                except Exception as e:
                    print(f"Error processing EVTX record: {e}")
    except Exception as e:
        print(f"EVTX parsing failed: {e}")
        return []
    
    return events

def parse_file_based_on_type(file_path: str, file_type: str = "auto") -> List[Dict[str, Any]]:
    """Parse file based on type or extension"""
    if file_type == "auto":
        import os
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
        print(f"Failed to parse file {file_path}: {e}")
        return []
