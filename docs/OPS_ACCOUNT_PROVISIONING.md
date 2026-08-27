# WarSOC Account Provisioning Runbook

This is the minimal operator flow for creating customer accounts after a sale closes. It is current as of 2026-07-15 and is intended for customized contracts, not named pricing tiers.

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

The invite is not an active account immediately. The backend creates a pending user, emails a single-use activation link, and denies login until activation completes. The recipient must open the link before expiry, choose a password that meets policy, and then sign in. The tenant admin should verify the resulting role from Team & Access.

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

Retention days is the tenant's normal WarSOC evidence entitlement:

- FBR POS/invoice-integrity evidence: tenant retention entitlement
- PECA evidence-pack records: tenant retention entitlement

Mongo hot storage for SIEM, FBR, and PECA is seven days. New FBR and PECA evidence route through the matching general tenant-retention class. Existing blobs already written to a locked Azure container keep their original immutable obligation and must not be moved, shortened, or deleted early.

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

`Daily quota GiB` is an internal WarSOC safety limit, not a customer self-service option. On the current shared 8GB RAM / 4 vCPU pilot infrastructure, keep it at `0` unless a contract specifically requires a tighter value. The backend hard-caps custom provisioning at `3 GiB/day`.

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
Daily quota GiB: 0 for backend default, or a contract value up to 3
```

## Security Rules

- Never put `SUPER_ADMIN_API_KEY` in Vercel.
- Never add this operator GUI to the public frontend.
- Never email a reusable plaintext password. Deliver the first tenant-admin credential through an approved secure handover channel and require rotation; team users must use the single-use invitation activation flow.
- Passwords must be at least 16 characters and include uppercase, lowercase, number, and symbol.
- Keep public self-signup disabled for production.

## What To Give The Customer

After provisioning, give the customer:

- login URL: `https://warsoc.tech`
- admin email
- initial admin credential through the approved secure handover channel
- installer download instructions
- installer SHA-256 hash manifest
- tenant onboarding instructions

Do not give the customer the super-admin key.
