import asyncio
import sys
import traceback

def run_test():
    try:
        from app.utils.siem_logic import SIEMEngine
        engine = SIEMEngine(redis_client=None)
        
        log_entry = {
            "event_id": "4688",
            "event_type": "process_create",
            "message": "Process started by admin: ipconfig.exe; command: ipconfig /all",
            "user": "admin",
            "source_ip": "10.0.0.5",
            "raw_data": {
                "NewProcessName": "C:\\Windows\\System32\\ipconfig.exe",
                "CommandLine": "ipconfig /all"
            },
            "processed_data": {
                "command_line": "ipconfig /all",
                "new_process_name": "C:\\Windows\\System32\\ipconfig.exe"
            }
        }
        
        findings = asyncio.run(engine.analyze_single_log(log_entry))
        
        print(f"Total Alerts: {len(findings)}")
        for f in findings:
            print(f"ALERT: {f['type']} - {f['summary']}")
    except Exception as e:
        print("EXCEPTION OCCURRED")
        traceback.print_exc()

if __name__ == "__main__":
    run_test()
