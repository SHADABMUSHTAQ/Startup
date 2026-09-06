const encodeId = (value) => encodeURIComponent(String(value || "").trim());

export const formatPackRetention = (retention) => {
  if (retention?.inherits_tenant_retention_days === true) return "Tenant entitlement";
  const days = retention?.vault_days;
  return typeof days === "number" && days > 0 ? `${days} days` : "Not recorded";
};

export const API_ROUTES = Object.freeze({
  endpointStatus: "/data/status",
  evidenceCases: "/compliance/cases",
  evidenceCase: (caseId) => `/compliance/cases/${encodeId(caseId)}`,
  evidenceCaseItems: (caseId) => `/compliance/cases/${encodeId(caseId)}/items`,
  evidenceCaseCustody: (caseId) => `/compliance/cases/${encodeId(caseId)}/custody`,
  evidenceCaseClose: (caseId) => `/compliance/cases/${encodeId(caseId)}/close`,
  evidenceExports: (caseId) => `/compliance/cases/${encodeId(caseId)}/exports`,
  evidenceExport: (caseId, exportId) => `/compliance/cases/${encodeId(caseId)}/exports/${encodeId(exportId)}`,
  evidenceExportDownload: (caseId, exportId) => `/compliance/cases/${encodeId(caseId)}/exports/${encodeId(exportId)}/download-link`,
  legalHolds: "/compliance/holds",
  legalHoldRelease: (holdId) => `/compliance/holds/${encodeId(holdId)}/release`,
  retentionStatus: "/compliance/retention/status",
  archiveRetrievals: "/archive-retrievals",
  archiveRetrieval: (requestId) => `/archive-retrievals/${encodeId(requestId)}`,
  archiveRetrievalDownloads: (requestId) => `/archive-retrievals/${encodeId(requestId)}/download-links`,
});

export const HOLDABLE_EVIDENCE_COLLECTIONS = Object.freeze([
  "fbr_pos_logs",
  "source_envelopes_fbr",
  "peca_forensic_logs",
  "source_envelopes_peca",
  "siem_cold_vault",
  "source_envelopes_siem",
  "security_alerts",
  "agent_coverage_observations",
]);

export const CASE_EVIDENCE_COLLECTIONS = HOLDABLE_EVIDENCE_COLLECTIONS;

export const buildEvidenceCasePayload = ({ title, description, externalReference }) => ({
  title: String(title || "").trim(),
  description: String(description || "").trim(),
  external_reference: String(externalReference || "").trim() || null,
});

export const buildCaseClosurePayload = (reason) => ({
  action: "VERIFY",
  reason: String(reason || "").trim(),
});

export const buildEvidenceCaseItemPayload = ({ collection, referenceType, reference, reason }) => ({
  collection: String(collection || "").trim(),
  document_id: referenceType === "document_id" ? String(reference || "").trim() || null : null,
  event_uid: referenceType === "event_uid" ? String(reference || "").trim() || null : null,
  reason: String(reason || "").trim(),
});

export const buildCustodyActionPayload = ({ action, reason, caseItemId, transferTo }) => {
  const normalizedAction = String(action || "VIEW").trim().toUpperCase();
  return {
    action: normalizedAction,
    reason: String(reason || "").trim(),
    case_item_id: String(caseItemId || "").trim() || null,
    transfer_to: normalizedAction === "TRANSFER" ? String(transferTo || "").trim() || null : null,
  };
};

export const buildEvidenceExportPayload = (reason) => ({
  reason: String(reason || "").trim(),
});

export const buildArchiveRetrievalPayload = ({ source, start, end, reason }) => {
  const startAt = new Date(start);
  const endAt = new Date(end);
  if (!Number.isFinite(startAt.getTime()) || !Number.isFinite(endAt.getTime()) || endAt <= startAt) {
    throw new Error("Choose a valid archive date range.");
  }
  return {
    collections: [source],
    start_at: startAt.toISOString(),
    end_at: endAt.toISOString(),
    reason: String(reason || "").trim(),
  };
};

export const archiveSourceOptions = (role, packs = []) => {
  const sources = [];
  if (["admin", "manager"].includes(role)) {
    sources.push(
      ["logs", "Security logs"], ["siem_cold_vault", "Endpoint evidence"],
      ["security_alerts", "Security alerts"], ["csv_uploads", "Offline findings"],
    );
  }
  if (["admin", "auditor"].includes(role)) {
    if (packs.includes("peca_forensic")) sources.push(["peca_forensic_logs", "PECA evidence"]);
    if (packs.includes("fbr_pos")) sources.push(["fbr_pos_logs", "FBR evidence"]);
  }
  return sources;
};

export const safeDownloadUrl = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url.href : null;
  } catch { return null; }
};

export const buildLegalHoldPayload = ({ scopeType, collection, eventUid, reason, authority, proceedingReference }) => {
  const scope = String(scopeType || "TENANT").trim().toUpperCase();
  return {
    scope_type: scope,
    collection: scope === "TENANT" ? null : String(collection || "").trim() || null,
    event_uid: scope === "EVENT" ? String(eventUid || "").trim() || null : null,
    reason: String(reason || "").trim(),
    authority: String(authority || "").trim(),
    proceeding_reference: String(proceedingReference || "").trim() || null,
  };
};

export const buildLegalHoldReleasePayload = ({ reason, authority }) => ({
  reason: String(reason || "").trim(),
  authority: String(authority || "").trim(),
});

export const normalizeEvidenceCaseDetail = (payload) => {
  const caseRecord = payload?.case || payload?.data || payload || {};
  return {
    ...caseRecord,
    evidence: Array.isArray(payload?.items) ? payload.items : [],
    custody_history: Array.isArray(payload?.custody_events) ? payload.custody_events : [],
    custody_verification: payload?.custody || null,
  };
};
