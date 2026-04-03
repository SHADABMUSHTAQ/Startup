# WarSOC Architecture Boundaries

"NEVER mix FBR, PECA, and SIEM logic in the same Python file. They are strictly separate domains."

"Every framework must have its own dedicated Redis consumer worker (siem_worker.py, fbr_worker.py, peca_worker.py)."

"Configurations must remain isolated in app/config/siem_policy.json, app/config/fbr_policy.json, and app/config/peca_policy.json."
