import os
import shutil

# --- CONFIGURATION (The Debris List) ---
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_DIR = os.path.join(ROOT_DIR, "docs")

TO_DELETE_ROOT = [
    "access.log", "api.log", "backend_500.log", "backend_error.log", "nginx.log", "peca.log", 
    "startup.log", "worker.log", "tmp_api_10m.log", "tmp_api_recent.log", "tmp_fbr_20m.log", 
    "tmp_peca_20m.log", "tmp_siem_10m.log", "tmp_siem_5m.log", "tmp_siem_recent.log",
    "attack_runner.py", "check_ips.py", "crash_backend.py", "create_test_accounts.py", 
    "get_users.py", "get_users2.py", "hit_8000.py", "hit_8001.py", "hit_with_magic_token.py", 
    "investigate_db01.py", "override_secret.py", "trigger_alert.py",
    "_deprecated_worker.py", "worker.py", "fix_agent.py", "fix_typing.py", "cd", "push_out.txt"
]

TO_DELETE_SCRIPTS = [
    "architect_e2e_check.py", "attack_battery.py", "battle_drill.py", 
    "check_api_include_csv.py", "check_creds.py", "check_peca_4616.py", 
    "e2e_full_verify.py", "e2e_verify.py", "final_certification.py", "fix_agent_secret.py", 
    "generate_mock_evidence.py", "phase1_alias_normalization_proof.py", 
    "phase2_terminal_matrix.py", "push_4616.py", "restart_warsoc_agent.ps1", 
    "run_e2e.ps1", "simulate_ingest_and_siem.py", "ultimate_omni_matrix.py"
]

TO_MOVE_DOCS = [
    "WARSOC_AS_BUILT_AUDIT_2026-04-05.md", "LEVEL4_UPGRADE_REPORT.md", "audit_report.md", 
    "DEPLOYMENT_STATUS.md", "ENDPOINT_VISIBILITY_AUDIT.md", "IRONCLAD_INGESTION_IMPLEMENTATION.md", 
    "LEVEL4_ACTIVATION.md", "TEST_COMMANDS.md", "QUICK_REFERENCE.md"
]

def execute_cleanup():
    print("========================================================")
    print("       WarSOC Production Cleanup Detonator v1.0")
    print("========================================================\n")

    # 1. Ensure docs directory exists
    if not os.path.exists(DOC_DIR):
        print(f"[*] Creating {DOC_DIR}...")
        os.makedirs(DOC_DIR)

    # 2. Delete Root Debris
    print(f"[*] Cleaning Root Directory: {ROOT_DIR}")
    for filename in TO_DELETE_ROOT:
        path = os.path.join(ROOT_DIR, filename)
        if os.path.exists(path):
            try:
                os.remove(path)
                print(f" [DELETED] {filename}")
            except Exception as e:
                print(f" [ERROR] Could not delete {filename}: {e}")

    # 3. Delete Script Debris
    print(f"\n[*] Cleaning Scripts Directory...")
    scripts_dir = os.path.join(ROOT_DIR, "scripts")
    for filename in TO_DELETE_SCRIPTS:
        path = os.path.join(scripts_dir, filename)
        if os.path.exists(path):
            try:
                os.remove(path)
                print(f" [DELETED] {filename}")
            except Exception as e:
                print(f" [ERROR] Could not delete {filename}: {e}")

    # 4. Consolidate Docs
    print("\n[*] Consolidating Forensic Documentation...")
    for filename in TO_MOVE_DOCS:
        old_path = os.path.join(ROOT_DIR, filename)
        new_path = os.path.join(DOC_DIR, filename)
        if os.path.exists(old_path):
            try:
                shutil.move(old_path, new_path)
                print(f" [MOVED] {filename} -> /docs/")
            except Exception as e:
                print(f" [ERROR] Could not move {filename}: {e}")

    print("\n========================================================")
    print("  CLEANUP COMPLETE: YOUR BACKEND IS NOW PRODUCTION READY.")
    print("========================================================\n")

if __name__ == "__main__":
    execute_cleanup()
