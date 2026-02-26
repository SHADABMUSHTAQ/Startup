import os
import sys
import asyncio
import importlib.util
import redis
from datetime import datetime
from pathlib import Path

# --- COLORS ---
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_step(msg): print(f"\n{CYAN}--- {msg} ---{RESET}")

def check_file(path):
    if os.path.exists(path):
        print(f"[{GREEN}OK{RESET}] Found: {path}")
        return True
    print(f"[{RED}MISSING{RESET}] Error: {path}")
    return False

def check_secrets():
    print_step("Checking Security Configuration")
    if os.path.exists(".env"):
        print(f"[{GREEN}OK{RESET}] Secrets file (.env) found.")
        return True
    print(f"[{RED}CRITICAL{RESET}] .env file is MISSING!")
    return False

async def check_mongodb():
    print_step("Checking MongoDB Connectivity")
    try:
        from app.database import init_db
        # We just test if we can trigger the init
        await init_db()
        print(f"[{GREEN}OK{RESET}] MongoDB is Online and Responsive.")
        return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] MongoDB Connection Error: {str(e)}")
        return False

def check_redis():
    print_step("Checking Redis Connectivity")
    try:
        r = redis.Redis(host='localhost', port=6379, socket_connect_timeout=2)
        r.ping()
        print(f"[{GREEN}OK{RESET}] Redis is Online (Port 6379).")
        return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Redis is Offline: {e}")
        return False

def test_imports_and_engine():
    print_step("Checking Logic & Detection Engine")
    try:
        # Aligned with your actual file names
        from app.utils.siem_logic import SIEMEngine
        from app.api.ws_manager import manager
        
        mock_config = {"detection": {}, "whitelist": {}, "threat_intelligence": {}}
        engine = SIEMEngine(config=mock_config)
        
        print(f"[{GREEN}OK{RESET}] SIEMEngine logic loaded.")
        print(f"[{GREEN}OK{RESET}] WebSocket Manager initialized.")
        return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Logic/Import Error: {e}")
        return False

def check_dependencies():
    print_step("Checking Dependencies")
    # Updated to match our new requirements.txt
    required = ["fastapi", "motor", "redis", "uvicorn", "cryptography", "pydantic"]
    missing = []
    for lib in required:
        if importlib.util.find_spec(lib) is None:
            missing.append(lib)
    
    if not missing:
        print(f"[{GREEN}OK{RESET}] All core dependencies installed.")
        return True
    else:
        for m in missing: print(f"[{RED}MISSING{RESET}] Library: {m}")
        return False

async def main():
    print(f"🔍 {CYAN}WARSOC BACKEND ARCHITECTURE DIAGNOSIS{RESET}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    all_good = True

    # 1. File Integrity (Added ws_manager and config check)
    critical_files = [
        "worker.py", "app/main.py", "app/api/ws_manager.py", 
        "app/utils/siem_logic.py", "app/routes/threat_intel.py", "app/config/config.py"
    ]
    if not all(check_file(f) for f in critical_files): all_good = False

    # 2. Security & Deps
    if not check_secrets(): all_good = False
    if not check_dependencies(): all_good = False

    # 3. Logic Check
    if not test_imports_and_engine(): all_good = False

    # 4. Infrastructure Check
    if not check_redis(): all_good = False
    if not await check_mongodb(): all_good = False

    # FINAL VERDICT
    print("\n" + "="*50)
    if all_good:
        print(f"{GREEN}✅ BACKEND IS FULLY FUNCTIONAL AND READY{RESET}")
        print(f"Next Steps: \n1. Run API: {YELLOW}python -m app.main{RESET}")
        print(f"2. Run Worker: {YELLOW}python worker.py{RESET}")
    else:
        print(f"{RED}❌ BACKEND HAS CRITICAL ISSUES{RESET}")
    print("="*50 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
