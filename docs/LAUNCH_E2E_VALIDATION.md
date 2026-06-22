# WarSOC Launch E2E Validation

This validates the real launch model:

Pricing quote -> sales lead -> admin provisioning -> issued credentials -> login/profile -> agent activation/download -> agent telemetry -> SIEM/FBR/PECA processing -> alert workflow -> auditor RBAC.

## Before Running

Start the backend stack first. The validator expects:

- FastAPI reachable at `http://127.0.0.1:8000`
- MongoDB running
- Redis running
- SIEM, FBR, and PECA workers running
- `SUPER_ADMIN_API_KEY` configured
- `AGENT_CDN_URL` configured if you want installer redirect validation
- A normal public-style email domain for synthetic users. The backend correctly rejects reserved test domains such as `.test`, `.invalid`, and `localhost`.

If you use Docker Compose, start the full stack you normally use for launch. If you run workers manually, make sure the unified worker or all three workers are alive before running the script.

## Main Command

From `C:\Users\Lenovo\Desktop\Startup-backend`:

```powershell
.\scripts\run_launch_e2e.ps1 `
  -BaseUrl "http://127.0.0.1:8000" `
  -AdminKey "YOUR_SUPER_ADMIN_API_KEY" `
  -FrontendPath "C:\Users\Lenovo\Desktop\Startup-main" `
  -EmailDomain "warsoc.tech" `
  -RunFrontendBuild
```

If `SUPER_ADMIN_API_KEY` is already in your environment:

```powershell
$env:SUPER_ADMIN_API_KEY="YOUR_SUPER_ADMIN_API_KEY"
.\scripts\run_launch_e2e.ps1 -RunFrontendBuild
```

If you do not want synthetic QA emails under `warsoc.tech`, pass a domain you control:

```powershell
.\scripts\run_launch_e2e.ps1 -EmailDomain "your-company.com" -SkipAgentDownload
```

## What It Checks

- Public signup is blocked.
- Quote request works for the 15-agent FBR + PECA package.
- Admin provisioning creates a tenant with 15 agents and both compliance packs.
- Provisioned admin can log in.
- `/auth/me` and `/auth/profile` return the frontend contract.
- Profile updates persist through `PUT /auth/profile`.
- Agent installer endpoint redirects to `AGENT_CDN_URL`.
- Admin can generate activation code.
- Agent can register and receive JWT.
- Agent can send synthetic Windows security telemetry.
- SIEM log appears in `siem_cold_vault`.
- SIEM alert appears in `security_alerts`.
- FBR evidence appears in `fbr_pos_logs`.
- PECA evidence appears in `peca_forensic_logs`.
- Alert acknowledge and close persist.
- Closing an alert without notes is rejected.
- Compliance CSV/PDF export routes work with the frontend query contract.
- Auditor can log in.
- Auditor is denied team management.
- Auditor is denied operational alerts API.
- Auditor is denied operational status/search APIs.
- Auditor is denied agent activation/download APIs.
- Auditor can access entitled compliance evidence.
- Frontend source has no public signup/payment copy.
- Optional frontend production build passes.

## Useful Variants

Skip frontend checks:

```powershell
.\scripts\run_launch_e2e.ps1 -AdminKey "YOUR_SUPER_ADMIN_API_KEY" -SkipFrontend
```

Skip installer redirect if `AGENT_CDN_URL` is not configured locally:

```powershell
.\scripts\run_launch_e2e.ps1 -AdminKey "YOUR_SUPER_ADMIN_API_KEY" -SkipAgentDownload
```

Skip detection if workers are not running and you only want auth/sales/provisioning/RBAC:

```powershell
.\scripts\run_launch_e2e.ps1 -AdminKey "YOUR_SUPER_ADMIN_API_KEY" -SkipDetection
```

Increase worker wait time:

```powershell
.\scripts\run_launch_e2e.ps1 -AdminKey "YOUR_SUPER_ADMIN_API_KEY" -WaitSeconds 240
```

If you run `unified_worker.py` as one monolithic worker, PECA signing can briefly delay SIEM cold-vault flushing. Use the worker-specific timeout for detection/evidence checks:

```powershell
.\scripts\run_launch_e2e.ps1 -AdminKey "YOUR_SUPER_ADMIN_API_KEY" -WorkerWaitSeconds 300
```

## Result File

The script writes:

```text
C:\Users\Lenovo\Desktop\Startup-backend\tmp\launch_e2e_report.json
```

Treat any `FAIL` as launch-blocking unless you intentionally skipped that subsystem locally.

Common failures:

- `Agent installer redirect` fails: set `AGENT_CDN_URL`.
- SIEM/FBR/PECA visibility times out: workers are not running, Redis stream groups are stuck, or Mongo is unreachable.
- Quote request fails: Redis email queue or Mongo is down.
- Admin provisioning fails: missing or wrong `SUPER_ADMIN_API_KEY`.
- Frontend build fails: fix React build before frontend handoff.

## Existing Installed-Agent Check

If you also want to validate a real already-installed Windows agent folder, use the older backend QA runner:

```powershell
.\scripts\qa_backend_e2e.ps1 `
  -BaseUrl "http://127.0.0.1:8000" `
  -Username "client-admin@example.com" `
  -Password "CLIENT_PASSWORD" `
  -AgentDir "C:\Program Files (x86)\WarSOC"
```

Use `run_launch_e2e.ps1` for launch acceptance. Use `qa_backend_e2e.ps1` for validating a physical installed agent after deployment.
