import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  API_ROUTES,
  archiveSourceOptions,
  buildArchiveRetrievalPayload,
  buildCaseClosurePayload,
  buildCustodyActionPayload,
  buildEvidenceCasePayload,
  buildEvidenceCaseItemPayload,
  buildEvidenceExportPayload,
  buildLegalHoldPayload,
  buildLegalHoldReleasePayload,
  normalizeEvidenceCaseDetail,
  safeDownloadUrl,
  formatPackRetention,
} from "../src/contracts/backendContracts.js";
import { ROLE_PERMISSIONS, hasPermission } from "../src/utils/roleContract.js";
import { shouldDisplayLog } from "../src/utils/logSearch.js";
import { parseBackendTime } from "../src/utils/backendTime.js";

test("Mongo UTC timestamps do not silently become browser-local times", () => {
  assert.equal(parseBackendTime("2026-09-02T19:21:10").toISOString(), "2026-09-02T19:21:10.000Z");
  assert.equal(parseBackendTime("2026-09-03T00:21:10+05:00").toISOString(), "2026-09-02T19:21:10.000Z");
  assert.equal(parseBackendTime("invalid"), null);
});

test("pack retention labels do not invent a fixed compliance duration", () => {
  assert.equal(formatPackRetention({ inherits_tenant_retention_days: true, vault_days: null }), "Tenant entitlement");
  assert.equal(formatPackRetention({ vault_days: 180 }), "180 days");
  assert.equal(formatPackRetention({}), "Not recorded");
});

test("historical exact-field matches are not hidden by a second message filter", () => {
  const row = { event_id: 4625, source_ip: "192.0.2.25", message: "Synthetic authentication failure", level: "INFO" };
  assert.equal(shouldDisplayLog(row, "4625", false), true);
  assert.equal(shouldDisplayLog(row, "192.0.2.25", false), true);
  assert.equal(shouldDisplayLog(row, "", true), false);
  assert.equal(shouldDisplayLog({ ...row, level: "HIGH" }, "authentication", true), true);
});

test("evidence and retention routes match the FastAPI contract", () => {
  assert.equal(API_ROUTES.endpointStatus, "/data/status");
  assert.equal(API_ROUTES.evidenceCases, "/compliance/cases");
  assert.equal(API_ROUTES.evidenceCase("CASE/A"), "/compliance/cases/CASE%2FA");
  assert.equal(API_ROUTES.evidenceCaseItems("CASE/A"), "/compliance/cases/CASE%2FA/items");
  assert.equal(API_ROUTES.evidenceCaseCustody("CASE/A"), "/compliance/cases/CASE%2FA/custody");
  assert.equal(API_ROUTES.evidenceCaseClose("CASE/A"), "/compliance/cases/CASE%2FA/close");
  assert.equal(API_ROUTES.evidenceExports("CASE/A"), "/compliance/cases/CASE%2FA/exports");
  assert.equal(API_ROUTES.evidenceExport("CASE/A", "EXPORT/B"), "/compliance/cases/CASE%2FA/exports/EXPORT%2FB");
  assert.equal(API_ROUTES.evidenceExportDownload("CASE/A", "EXPORT/B"), "/compliance/cases/CASE%2FA/exports/EXPORT%2FB/download-link");
  assert.equal(API_ROUTES.legalHolds, "/compliance/holds");
  assert.equal(API_ROUTES.legalHoldRelease("HOLD/A"), "/compliance/holds/HOLD%2FA/release");
  assert.equal(API_ROUTES.retentionStatus, "/compliance/retention/status");
  assert.equal(API_ROUTES.archiveRetrievals, "/archive-retrievals");
  assert.equal(API_ROUTES.archiveRetrievalDownloads("ARR/A"), "/archive-retrievals/ARR%2FA/download-links");
});

test("request builders produce only backend-accepted fields", () => {
  assert.deepEqual(buildEvidenceCasePayload({ title: " Case ", description: " Description ", externalReference: " REF " }), {
    title: "Case",
    description: "Description",
    external_reference: "REF",
  });
  assert.deepEqual(buildCaseClosurePayload(" Verified evidence "), { action: "VERIFY", reason: "Verified evidence" });
  assert.deepEqual(buildEvidenceCaseItemPayload({ collection: " security_alerts ", referenceType: "event_uid", reference: " EV-1 ", reason: " Attach evidence " }), {
    collection: "security_alerts", document_id: null, event_uid: "EV-1", reason: "Attach evidence",
  });
  assert.deepEqual(buildCustodyActionPayload({ action: "transfer", reason: " Transfer evidence ", caseItemId: " ITEM-1 ", transferTo: " Legal team " }), {
    action: "TRANSFER", reason: "Transfer evidence", case_item_id: "ITEM-1", transfer_to: "Legal team",
  });
  assert.deepEqual(buildEvidenceExportPayload(" Authorized export "), { reason: "Authorized export" });
  assert.deepEqual(buildLegalHoldPayload({ scopeType: "tenant", collection: "security_alerts", eventUid: "EV-1", reason: " Preserve ", authority: " CEO ", proceedingReference: " CASE-9 " }), {
    scope_type: "TENANT",
    collection: null,
    event_uid: null,
    reason: "Preserve",
    authority: "CEO",
    proceeding_reference: "CASE-9",
  });
  assert.deepEqual(buildLegalHoldPayload({ scopeType: "event", collection: "security_alerts", eventUid: " EV-1 ", reason: " Preserve ", authority: " CEO " }), {
    scope_type: "EVENT",
    collection: "security_alerts",
    event_uid: "EV-1",
    reason: "Preserve",
    authority: "CEO",
    proceeding_reference: null,
  });
  assert.deepEqual(buildLegalHoldReleasePayload({ reason: " Released ", authority: " Legal " }), { reason: "Released", authority: "Legal" });
});

test("case detail keeps case, item, and custody response sections together", () => {
  const result = normalizeEvidenceCaseDetail({
    case: { case_id: "CASE-1", title: "Investigation" },
    items: [{ case_item_id: "ITEM-1" }],
    custody: { status: "VERIFIED" },
    custody_events: [{ custody_event_id: "EVENT-1" }],
  });
  assert.equal(result.case_id, "CASE-1");
  assert.equal(result.evidence[0].case_item_id, "ITEM-1");
  assert.equal(result.custody_history[0].custody_event_id, "EVENT-1");
  assert.equal(result.custody_verification.status, "VERIFIED");
});

test("frontend role names match provisionable backend roles", () => {
  assert.deepEqual(Object.keys(ROLE_PERMISSIONS).sort(), ["admin", "analyst", "auditor", "manager"]);
  assert.equal(hasPermission("manager", "endpoint.trust.read"), true);
  assert.equal(hasPermission("auditor", "retention.read"), true);
  assert.equal(hasPermission("viewer", "operations.read"), false);
});

test("archive inputs use UTC and reject inverted windows", () => {
  const body = buildArchiveRetrievalPayload({ source: "security_alerts", start: "2026-08-01T10:00:00+05:00", end: "2026-08-02T10:00:00+05:00", reason: " Authorized review " });
  assert.deepEqual(body, { collections: ["security_alerts"], start_at: "2026-08-01T05:00:00.000Z", end_at: "2026-08-02T05:00:00.000Z", reason: "Authorized review" });
  assert.throws(() => buildArchiveRetrievalPayload({ start: "invalid", end: "invalid" }));
  assert.throws(() => buildArchiveRetrievalPayload({ start: "2026-08-02", end: "2026-08-01" }));
});

test("archive source choices respect role and pack entitlement", () => {
  assert.equal(archiveSourceOptions("manager", ["fbr_pos"]).length, 4);
  assert.equal(archiveSourceOptions("manager", ["fbr_pos"]).some(([name]) => name === "fbr_pos_logs"), false);
  assert.deepEqual(archiveSourceOptions("auditor", ["peca_forensic"]), [["peca_forensic_logs", "PECA evidence"]]);
  assert.deepEqual(archiveSourceOptions("analyst", ["peca_forensic", "fbr_pos"]), []);
  assert.equal(archiveSourceOptions("admin", ["peca_forensic", "fbr_pos"]).length, 6);
  assert.deepEqual(archiveSourceOptions("auditor", []), []);
});

test("download links reject script, cleartext, relative and credential URLs", () => {
  for (const value of ["javascript:alert(1)", "data:text/html,unsafe", "http://example.com/file", "/file", "https://user:secret@example.com/file", null]) assert.equal(safeDownloadUrl(value), null);
  assert.equal(safeDownloadUrl("https://example.com/evidence.zip?sig=test"), "https://example.com/evidence.zip?sig=test");
});

const sourceFiles = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const path = join(directory, entry.name);
  if (entry.isDirectory()) return sourceFiles(path);
  return /\.(js|jsx)$/.test(entry.name) ? [path] : [];
});

test("removed placeholder API paths cannot return to application source", () => {
  const source = sourceFiles(join(process.cwd(), "src")).map((path) => readFileSync(path, "utf8")).join("\n");
  for (const stalePath of ["/evidence/cases", "/evidence/package-jobs", "/legal-holds", "/retention/status", "/endpoint-trust", "/archive-retrieval"]) {
    assert.equal(source.includes(`"${stalePath}"`), false, `stale API path found: ${stalePath}`);
  }
});

test("historical retrieval stays disabled while accepted package exports are enabled only in production", () => {
  for (const file of [".env.local.example", ".env.production", ".env.production.example"]) {
    const content = readFileSync(join(process.cwd(), file), "utf8");
    assert.match(content, /^VITE_ARCHIVE_RETRIEVAL_ENABLED=false$/m);
  }
  assert.match(readFileSync(join(process.cwd(), ".env.local.example"), "utf8"), /^VITE_EVIDENCE_EXPORT_ENABLED=false$/m);
  for (const file of [".env.production", ".env.production.example"]) {
    assert.match(readFileSync(join(process.cwd(), file), "utf8"), /^VITE_EVIDENCE_EXPORT_ENABLED=true$/m);
  }
});

test("public copy does not promise obsolete infrastructure or six-year FBR storage", () => {
  const legal = readFileSync(join(process.cwd(), "src/assets/Pages/Legal/LegalPage.jsx"), "utf8");
  const pricing = readFileSync(join(process.cwd(), "src/assets/Pages/Pricing/Pricing.jsx"), "utf8");
  for (const obsolete of ["Digital Ocean", "Nexus Cloud VPS", "FBR POS Integrity Logs: Mandatory 6 years", "Azure Cold Storage for 6-year compliance"]) {
    assert.equal(`${legal}\n${pricing}`.includes(obsolete), false, `obsolete public claim found: ${obsolete}`);
  }
});
