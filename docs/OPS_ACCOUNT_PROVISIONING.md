# WarSOC Account Provisioning Runbook

This is the minimal operator flow for creating customer accounts after a sale closes.

## Account Types

### 1. Customer tenant admin

Created by WarSOC operations through the protected backend route:

```text
POST https://api.warsoc.tech/api/v1/admin/provision
Header: X-Admin-Key: <SUPER_ADMIN_API_KEY>
```

This creates:

- tenant record
- tenant compliance entitlements
- tenant agent limit
- retention/quota settings
- forensic genesis ledger
- first customer admin user
- Redis entitlement cache entries

Use this for every new customer after contract/payment approval.

### 2. Customer team users

Created by the customer's tenant admin from the WarSOC dashboard/team screen.

Backend route:

```text
POST https://api.warsoc.tech/api/v1/auth/invite
```

Allowed roles:

- `admin`
- `manager`
- `analyst`
- `auditor`

Do not create normal team users with the super-admin provision route. That route is only for creating a tenant and its first admin.

## Minimal Ops GUI

Run this on the WarSOC operator machine:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\warsoc_ops_console.ps1
```

To validate the GUI loads before opening it:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\warsoc_ops_console.ps1 -SelfTest
```

The GUI asks for:

- production API URL
- `SUPER_ADMIN_API_KEY`
- company name
- custom contract type
- compliance packs
- max agents, capped at 50
- retention days
- optional daily quota
- customer admin email/name/password

Retention days is the custom tenant default/archive setting. Compliance vault retention is policy-driven:

- FBR POS evidence: 2190 days
- PECA forensic evidence: 365 days

The tool does not store the super-admin key or customer password on disk.

## 15-Agent Custom FBR + PECA Customer

Use:

```text
Contract type: Customized
Compliance packs: FBR POS + PECA Forensic
Max agents: 15
Retention days: 90 unless contract says otherwise
Daily quota GiB: 0 for backend default
```

The generated customer admin logs in at:

```text
https://warsoc.tech
```

## 50-Agent Custom Customer

Use:

```text
Contract type: Customized
Compliance packs: FBR POS + PECA Forensic
Max agents: 50
Retention days: contract value
Daily quota GiB: contract value, or 0 for backend default
```

## Security Rules

- Never put `SUPER_ADMIN_API_KEY` in Vercel.
- Never add this operator GUI to the public frontend.
- Never email passwords in plain text if the customer has a secure handover channel.
- Passwords must be at least 16 characters and include uppercase, lowercase, number, and symbol.
- Keep public self-signup disabled for production.

## What To Give The Customer

After provisioning, give the customer:

- login URL: `https://warsoc.tech`
- admin email
- temporary admin password
- installer download instructions
- installer SHA-256 hash manifest
- tenant onboarding instructions

Do not give the customer the super-admin key.
