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
  archiveRetrievalAvailability: "/archive-retrievals/availability",
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

const ARCHIVE_RETRIEVAL_MAX_DAYS = 2190;
const ARCHIVE_RETRIEVAL_FUTURE_GRACE_MS = 5 * 60 * 1000;
const ARCHIVE_RETRIEVAL_SOURCES = new Set([
  "logs",
  "siem_cold_vault",
  "security_alerts",
  "csv_uploads",
  "peca_forensic_logs",
  "fbr_pos_logs",
]);

export const buildArchiveRetrievalPayload = ({ source, start, end, reason }, now = new Date()) => {
  const normalizedSource = String(source || "").trim();
  const normalizedReason = String(reason || "").trim();
  const startAt = new Date(start);
  const endAt = new Date(end);
  const currentTime = new Date(now);

  if (!ARCHIVE_RETRIEVAL_SOURCES.has(normalizedSource)) {
    throw new Error("Choose an authorized evidence source.");
  }
  if (!Number.isFinite(startAt.getTime()) || !Number.isFinite(endAt.getTime()) || endAt <= startAt) {
    throw new Error("Choose a valid archive date range.");
  }
  if (!Number.isFinite(currentTime.getTime())) {
    throw new Error("The current time could not be verified.");
  }
  if (endAt.getTime() > currentTime.getTime() + ARCHIVE_RETRIEVAL_FUTURE_GRACE_MS) {
    throw new Error("The archive end date cannot be in the future.");
  }
  if (endAt.getTime() - startAt.getTime() > ARCHIVE_RETRIEVAL_MAX_DAYS * 24 * 60 * 60 * 1000) {
    throw new Error("The archive date range cannot exceed 2,190 days.");
  }
  if (normalizedReason.length < 8 || normalizedReason.length > 500) {
    throw new Error("Enter a reason between 8 and 500 characters.");
  }
  return {
    collections: [normalizedSource],
    start_at: startAt.toISOString(),
    end_at: endAt.toISOString(),
    reason: normalizedReason,
  };
};

export const buildArchiveAvailabilityParams = ({ source, start, end } = {}) => {
  const params = {};
  const normalizedSource = String(source || "").trim();
  if (normalizedSource) params.collection = normalizedSource;
  if (!start && !end) return params;

  const startAt = new Date(start);
  const endAt = new Date(end);
  if (!Number.isFinite(startAt.getTime()) || !Number.isFinite(endAt.getTime()) || endAt <= startAt) {
    throw new Error("Choose a valid archive date range.");
  }
  params.start_at = startAt.toISOString();
  params.end_at = endAt.toISOString();
  return params;
};

const ARCHIVE_STATUS = Object.freeze({
  PENDING_APPROVAL: Object.freeze({ label: "Waiting for approval", className: "pending" }),
  APPROVED: Object.freeze({ label: "Accepted and queued", className: "queued" }),
  PENDING_REHYDRATION: Object.freeze({ label: "Preparing secure archive", className: "preparing" }),
  READY: Object.freeze({ label: "Download available", className: "ready" }),
  FAILED: Object.freeze({ label: "Retrieval failed", className: "failed" }),
  REJECTED: Object.freeze({ label: "Request rejected", className: "failed" }),
  CANCELLED: Object.freeze({ label: "Request cancelled", className: "closed" }),
  EXPIRED: Object.freeze({ label: "Download period ended", className: "closed" }),
});

const titleCaseKey = (value) => String(value || "Unknown")
  .trim()
  .toLowerCase()
  .replaceAll("_", " ")
  .replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());

export const archiveStatusInfo = (value) => {
  const key = String(value || "").trim().toUpperCase();
  return ARCHIVE_STATUS[key] || { label: titleCaseKey(key), className: "unknown" };
};

const ARCHIVE_SOURCE_LABELS = Object.freeze({
  logs: "Security logs",
  siem_cold_vault: "Endpoint evidence",
  security_alerts: "Security alerts",
  csv_uploads: "Offline findings",
  peca_forensic_logs: "PECA evidence",
  fbr_pos_logs: "FBR evidence",
});

export const archiveSourceLabel = (value) => (
  ARCHIVE_SOURCE_LABELS[String(value || "").trim()] || titleCaseKey(value)
);

export const formatArchiveSources = (values) => {
  if (!Array.isArray(values) || values.length === 0) return "Not recorded";
  return values.map(archiveSourceLabel).join(", ");
};

export const formatArchiveBytes = (value) => {
  if (value === undefined || value === null || value === "") return "Not recorded";
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "Not recorded";
  if (bytes === 0) return "0 bytes";
  if (bytes < 1024) return `${Math.round(bytes)} bytes`;
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const amount = bytes / (1024 ** unitIndex);
  return `${new Intl.NumberFormat("en", { maximumFractionDigits: unitIndex === 0 ? 0 : 1 }).format(amount)} ${units[unitIndex]}`;
};

export const formatArchiveTimestamp = (value) => {
  if (value === undefined || value === null || value === "") return "Not recorded";
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return "Not recorded";
  return parsed.toISOString().replace("T", " ").replace(".000Z", "Z");
};

export const formatArchiveDateRange = (start, end) => {
  const startLabel = formatArchiveTimestamp(start);
  const endLabel = formatArchiveTimestamp(end);
  if (startLabel === "Not recorded" || endLabel === "Not recorded") return "Not recorded";
  return `${startLabel} to ${endLabel}`;
};

export const archiveActionErrorMessage = (error, action = "request") => {
  const status = Number(error?.response?.status);
  if (action === "download") {
    if (status === 403) return "Your role cannot download this archive.";
    if (status === 404) return "This archive request is no longer available.";
    if (status === 409) return "This archive is not ready for download.";
    if (status === 410) return "The download period for this archive has ended.";
    return "Secure download links are temporarily unavailable. Please retry.";
  }
  if (status === 403) return "Your role cannot request the selected evidence source.";
  if (status === 404) return "No retained evidence matches that source and date range.";
  if (status === 413) return "The request is too broad. Select a smaller date range.";
  if (status === 422) return "Check the source, date range, and reason, then retry.";
  return "The archive request could not be submitted. Please retry.";
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
