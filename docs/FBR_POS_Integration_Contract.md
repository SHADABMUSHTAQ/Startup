# WarSOC FBR POS Integration Contract

Date: 2026-07-02
Audience: Customers, Implementation Leads, Sales

## Executive Summary

WarSOC provides two distinct integration modes for the FBR POS (Federal Board of Revenue - Point of Sale) compliance pack. It is critical for the sales and implementation processes to clearly distinguish between zero-integration File Integrity Monitoring (Mode A) and deep invoice-level integration (Mode B).

For the initial pilot phase, **Mode B (Invoice-Level Integration via Authenticated API)** is the preferred and officially supported path for demonstrating end-to-end POS invoice tracking, unless the customer specifically requires only database tampering detection.

---

## Mode A: Zero-Integration FIM (File Integrity Monitoring)

**Target Audience:** Customers with legacy POS systems where source-code modification or direct API integration is not feasible.

### Capabilities
- The customer supplies protected local POS database directories via the installer's `/POS_PATHS` argument.
- WarSOC uses native Windows Security auditing and SACLs (System Access Control Lists) to detect supported database-file deletion and permission changes.
- **Important:** WarSOC detects *file-level* tampering. It **does not** claim to detect proprietary row-level or invoice-level changes within the database file itself without further parsing logic.

### Limitations
- The WarSOC state directory (`%ProgramData%\WarSOC`) is strictly protected (SYSTEM and Administrators only). Ordinary POS processes cannot write custom telemetry logs here without compromising endpoint security.
- Does not automatically extract `invoice_id`, `actor`, or business logic metadata.

---

## Mode B: Invoice-Level Integration (Preferred for Pilot)

**Target Audience:** Modern POS implementations or customers capable of updating their POS backend to emit structured telemetry.

### Capabilities
- The POS backend directly pushes authenticated events to the WarSOC Cloud API.
- WarSOC records `invoice_id`, the acting user, the supplied reason, and optional customer-supplied SHA-256 before/after hashes.
- Enables compliance evidence search, reporting, and controlled export.

### Integration Contract

For the pilot, POS systems must send structured JSON events directly to the WarSOC ingest endpoint.

**Endpoint:**
```http
POST /api/v1/fbr/pos/ingest
Content-Type: application/json
Authorization: Bearer <AGENT_JWT>
```

**Payload Schema:**
The payload must be an array of event objects or an envelope containing a `payload` array.

```json
{
  "payload": [
    {
      "event_id": "FBR-INV-DEL", 
      "event_uid": "unique-event-uuid-1234",
      "invoice_id": "INV-2026-0001",
      "timestamp": "2026-07-02T12:00:00Z",
      "actor": "pos_user_1",
      "source_system": "RetailBranch_42",
      "reason": "Customer requested refund",
      "before_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "after_hash": "cf23df2207d99a74fbe169e3eba035e633b65d94c2f6f7f2e7d5b6b95f20e31a",
      "metadata": {
        "terminal_id": "T-01"
      }
    }
  ]
}
```

**Field Rules:**
- `event_id`: Must be `"FBR-INV-DEL"` or `"FBR-INV-MOD"`.
- `event_uid`: Must be unique. Idempotent retries are supported.
- `timestamp`: Must include a timezone (e.g., `Z` or `+05:00`).
- `before_hash` and `after_hash`: If provided, must be exactly 64-character valid SHA-256 hex strings.

### Security and Identity
- **For the Pilot:** Do not attempt to write directly to `%ProgramData%\WarSOC\pos_audit.log` from standard user POS processes. The ACL on this directory will not be weakened.
- The authenticated API method guarantees tenant isolation and preserves the integrity of the agent installation.
