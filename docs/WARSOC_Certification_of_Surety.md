WARSOC Certification Of Surety — Phase 1 Sign-Off

Terminal Output (verbatim):

====================================================
      WarSOC 3.0 Production Validation CI
====================================================

[*] Testing Redis Connectivity...
✅ Redis: Connected and Responsive.
[*] Testing MongoDB Connectivity...
✅ MongoDB: Connected to 'WarSOC_DB'.
[*] Testing API Health (/docs)...
✅ API: Web Gateway is UP.
[*] Checking Git Sanitization...
✅ Git Sanitization: Clean (No secrets in index).

----------------------------------------------------
🚀 SYSTEM STATUS: 100% FUNCTIONAL AND RE-CERTIFIED.
----------------------------------------------------


== Attempting LOGIN ==
LOGIN -> 200 {'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjb3BpbG90X3Rlc3RfdXNlciIsInR5cGUiOiJ1c2VyIiwidGVuYW50X2lkIjoiV0FSU09DXzlFNzFDRTY5Iiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzc2Mjc0NTQzLCJqdGkiOiI2MTM3ZmJkMC1mYjBiLTQ4ZTYtYmUyZC1kMjA2ZjlhYTIxZGYifQ.ZLHFqVSGhuS_ID4Shs2OLGxnNGoPEnRGDFoNuitSYaQ', 'token_type': 'bearer', 'username': 'copilot_test_user', 'tenant_id': 'WARSOC_9E71CE69', 'plan_type': 'Professional', 'has_active_plan': True, 'compliance_packs': ['peca_forensic']}
TOKEN length: 279
/auth/me -> 200 {'_id': '69dcb516e7a990bef0c77ed4', 'username': 'copilot_test_user', 'email': 'copilot_test_user@example.com', 'full_name': 'Copilot Test', 'tenant_id': 'WARSOC_9E71CE69', 'plan_type': 'Professional', 'role': 'admin', 'compliance_packs': ['peca_forensic'], 'has_active_plan': True, 'created_at': '2026-04-13T09:19:18.036000'}

== CORS preflight test ==
OPTIONS @ /auth/login -> 200
access-control-allow-origin: http://127.0.0.1
access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
access-control-allow-headers: content-type
OPTIONS @ /auth/login from 5173 -> 200
access-control-allow-origin: http://127.0.0.1:5173
access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
access-control-allow-headers: content-type


INSERTED_ID:69de7b5a4c0f4b813acc0a39

Computed seal: 87bc80d9a03a5ef3c5f685adc3fe928039e9bf3d37247b2d6ab45b41a4bf7066
Stored   seal: 87bc80d9a03a5ef3c5f685adc3fe928039e9bf3d37247b2d6ab45b41a4bf7066
OK: Signature verification passed. Forensic evidence intact.


[1/3] Injecting FBR Log (Event 4697) into Redis Stream...
[*] Waiting 5 seconds for Workers to process...
[2/3] Checking MongoDB fbr_pos_logs for cryptographic seal...
✅ Log Found in FBR Vault!
   - Event ID: 4697
   - Forensic Seal (Hash): 0fbed7336745dcbce5181b41cdfc3b208250754e3b33a211f5f676e1154977c6
   - Digital Signature: NeV7suDTjQbI8S5OY7oNmv7fm/X/wNzOkrnQV5WzOLyIijcDYf...
   - Signer ID: WarSOC-FBR-v1

🔥 SUCCESS: FBR cryptographic engine is active and non-repudiable!
