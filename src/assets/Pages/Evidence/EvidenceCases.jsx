import { useCallback, useEffect, useRef, useState } from "react";
import {
  CheckCircle2,
  ChevronLeft,
  Eye,
  History,
  Paperclip,
  Plus,
  ShieldAlert,
  X,
} from "lucide-react";

import apiClient from "../../../api/apiClient";
import AsyncState from "../../../components/AsyncState";
import {
  API_ROUTES,
  CASE_EVIDENCE_COLLECTIONS,
  buildCaseClosurePayload,
  buildCustodyActionPayload,
  buildEvidenceCaseItemPayload,
  buildEvidenceCasePayload,
  normalizeEvidenceCaseDetail,
} from "../../../contracts/backendContracts";
import useRole from "../../../hooks/useRole";
import { formatApiError } from "../../../utils/apiError";
import { formatBackendTime } from "../../../utils/backendTime";
import EvidencePackageJobs from "./EvidencePackageJobs";
import "./EvidenceCases.css";
import "./EvidenceCaseActions.css";
import "./EvidenceActionOverrides.css";

const display = (value, fallback = "Not recorded") =>
  value === undefined || value === null || value === "" ? fallback : String(value);
const requestIdFrom = (error) =>
  error?.response?.data?.request_id || error?.response?.data?.requestId || "";
const stateFromError = (error, hasData = false) => {
  const status = error?.response?.status;
  if (status === 401) return "unauthenticated";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  return hasData ? "degraded" : "unavailable";
};
const normaliseCases = (data) =>
  Array.isArray(data) ? data : data?.cases || data?.data || data?.items || [];
const caseId = (item) => item.case_id || item.id || item.caseId;
const statusClass = (value) =>
  String(value || "unknown").toLowerCase().replace(/\s+/g, "-");

function CaseForm({ busy, onCancel, onSubmit }) {
  const [form, setForm] = useState({ title: "", description: "", externalReference: "" });
  const update = (field, value) => setForm((current) => ({ ...current, [field]: value }));
  return (
    <form className="evidence-form" onSubmit={(event) => { event.preventDefault(); onSubmit(form); }}>
      <div className="evidence-form-heading">
        <div>
          <span className="evidence-kicker">New evidence case</span>
          <h3>Open a case</h3>
          <p>Create a bounded case record for investigation and custody tracking.</p>
        </div>
        <button type="button" className="evidence-icon-button" onClick={onCancel} aria-label="Close case form"><X size={18} /></button>
      </div>
      <div className="evidence-form-grid">
        <label>Case title<input required minLength={3} maxLength={200} value={form.title} onChange={(event) => update("title", event.target.value)} /></label>
        <label>External reference<input maxLength={300} value={form.externalReference} onChange={(event) => update("externalReference", event.target.value)} placeholder="Optional internal reference" /></label>
        <label className="evidence-form-wide">Description<textarea required minLength={10} maxLength={4000} value={form.description} onChange={(event) => update("description", event.target.value)} /></label>
      </div>
      <div className="evidence-form-actions"><button type="button" className="ops-secondary" onClick={onCancel}>Cancel</button><button type="submit" disabled={busy}><Plus size={15} /> {busy ? "Opening..." : "Open case"}</button></div>
    </form>
  );
}

function AttachEvidenceForm({ busy, onCancel, onSubmit }) {
  const [form, setForm] = useState({ collection: CASE_EVIDENCE_COLLECTIONS[0], referenceType: "event_uid", reference: "", reason: "" });
  const update = (field, value) => setForm((current) => ({ ...current, [field]: value }));
  return (
    <form className="evidence-form evidence-action-form" onSubmit={async (event) => { event.preventDefault(); if (await onSubmit(form)) onCancel(); }}>
      <div className="evidence-form-grid">
        <label>Evidence collection<select value={form.collection} onChange={(event) => update("collection", event.target.value)}>{CASE_EVIDENCE_COLLECTIONS.map((collection) => <option key={collection} value={collection}>{collection}</option>)}</select></label>
        <label>Reference type<select value={form.referenceType} onChange={(event) => update("referenceType", event.target.value)}><option value="event_uid">Event UID</option><option value="document_id">Mongo document ID</option></select></label>
        <label className="evidence-form-wide">Evidence reference<input required maxLength={200} value={form.reference} onChange={(event) => update("reference", event.target.value)} /></label>
        <label className="evidence-form-wide">Attachment reason<textarea required minLength={10} maxLength={2000} value={form.reason} onChange={(event) => update("reason", event.target.value)} /></label>
      </div>
      <div className="evidence-form-actions"><button type="button" className="ops-secondary" onClick={onCancel}>Cancel</button><button type="submit" disabled={busy}><Paperclip size={15} /> {busy ? "Attaching..." : "Attach evidence"}</button></div>
    </form>
  );
}

function CustodyForm({ busy, evidence, onCancel, onSubmit }) {
  const [form, setForm] = useState({ action: "VIEW", reason: "", caseItemId: "", transferTo: "" });
  const update = (field, value) => setForm((current) => ({ ...current, [field]: value }));
  return (
    <form className="evidence-form evidence-action-form" onSubmit={async (event) => { event.preventDefault(); if (await onSubmit(form)) onCancel(); }}>
      <div className="evidence-form-grid">
        <label>Custody action<select value={form.action} onChange={(event) => update("action", event.target.value)}><option value="VIEW">View</option><option value="VERIFY">Verify</option><option value="TRANSFER">Transfer</option></select></label>
        <label>Evidence item<select value={form.caseItemId} onChange={(event) => update("caseItemId", event.target.value)}><option value="">Entire case</option>{evidence.map((entry) => <option key={entry.case_item_id} value={entry.case_item_id}>{entry.event_uid || entry.document_id}</option>)}</select></label>
        {form.action === "TRANSFER" && <label className="evidence-form-wide">Transfer to<input required maxLength={300} value={form.transferTo} onChange={(event) => update("transferTo", event.target.value)} /></label>}
        <label className="evidence-form-wide">Reason<textarea required minLength={10} maxLength={2000} value={form.reason} onChange={(event) => update("reason", event.target.value)} /></label>
      </div>
      <div className="evidence-form-actions"><button type="button" className="ops-secondary" onClick={onCancel}>Cancel</button><button type="submit" disabled={busy}><History size={15} /> {busy ? "Recording..." : "Record action"}</button></div>
    </form>
  );
}

function CaseDetail({ item, onBack, permissions, busy, onAttach, onCustody, onClose, exportEnabled }) {
  const [action, setAction] = useState(null);
  const [closeReason, setCloseReason] = useState("");
  const evidence = item.evidence || [];
  const custody = item.custody_history || [];
  const open = String(item.status || "").toUpperCase() === "OPEN";
  return (
    <div className="evidence-detail-view">
      <button type="button" className="ops-secondary evidence-back" onClick={onBack}><ChevronLeft size={16} /> Back to cases</button>
      <div className="evidence-detail-heading">
        <div><span className="evidence-kicker">Evidence case</span><h3>{display(item.title || item.name, caseId(item))}</h3><p>{display(item.description, "No case description recorded.")}</p></div>
        <div className="evidence-detail-actions">
          {permissions.attach && open && <button type="button" className="ops-secondary" onClick={() => setAction(action === "attach" ? null : "attach")}><Paperclip size={15} /> Attach</button>}
          {permissions.custody && <button type="button" className="ops-secondary" onClick={() => setAction(action === "custody" ? null : "custody")}><History size={15} /> Custody</button>}
          {permissions.close && open && <button type="button" className="evidence-danger" onClick={() => setAction(action === "close" ? null : "close")}><CheckCircle2 size={15} /> Close case</button>}
        </div>
      </div>
      {action === "attach" && <AttachEvidenceForm busy={busy} onCancel={() => setAction(null)} onSubmit={onAttach} />}
      {action === "custody" && <CustodyForm busy={busy} evidence={evidence} onCancel={() => setAction(null)} onSubmit={onCustody} />}
      {action === "close" && <form className="evidence-form evidence-close-form" onSubmit={async (event) => { event.preventDefault(); if (await onClose(closeReason)) setAction(null); }}><label>Verification reason<textarea required minLength={10} maxLength={2000} value={closeReason} onChange={(event) => setCloseReason(event.target.value)} /></label><div className="evidence-form-actions"><button type="button" className="ops-secondary" onClick={() => setAction(null)}>Cancel</button><button type="submit" disabled={busy}>{busy ? "Closing..." : "Verify and close"}</button></div></form>}
      <div className="evidence-meta-grid"><div><span>Status</span><strong className={`evidence-status ${statusClass(item.status)}`}>{display(item.status, "Open")}</strong></div><div><span>Created</span><strong>{item.created_at ? formatBackendTime(item.created_at) : "Not recorded"}</strong></div><div><span>Owner</span><strong>{display(item.created_by || item.owner)}</strong></div><div><span>Reference</span><strong>{display(item.external_reference || item.reference)}</strong></div></div>
      <section className="evidence-section">
        <div className="evidence-section-heading"><div><span className="evidence-kicker">Referenced records</span><h4>Evidence items</h4></div><span className="evidence-count">{evidence.length} items</span></div>
        {evidence.length ? <div className="evidence-items">{evidence.map((entry, index) => <div className="evidence-item" key={entry.case_item_id || index}><div className="evidence-item-icon"><Eye size={16} /></div><div><strong>{display(entry.event_uid || entry.document_id, `Evidence item ${index + 1}`)}</strong><span>{display(entry.collection)} | {display(entry.reason, "Evidence reference")}</span></div><div className="evidence-state-groups"><span className="evidence-count">{display(entry.state)}</span><span className="evidence-count">{entry.evidence_record_hash ? "Record hash recorded" : "Record hash missing"}</span></div></div>)}</div> : <AsyncState status="empty" title="No evidence attached" description="Attach a tenant-scoped hot evidence event before closing this case." />}
      </section>
      <section className="evidence-section">
        <div className="evidence-section-heading"><div><span className="evidence-kicker">Chain of custody</span><h4>Custody history</h4></div><span className="evidence-count">{display(item.custody_verification?.status, "Not verified")}</span></div>
        {custody.length ? <div className="custody-list">{custody.map((entry, index) => <div className="custody-row" key={entry.custody_event_id || index}><div><strong>{display(entry.action, "Custody event")}</strong><span>{display(entry.actor_email || entry.actor)} | {entry.occurred_at ? formatBackendTime(entry.occurred_at) : "Time unavailable"}</span></div><span className="evidence-count">{display(entry.state)}</span><span className="evidence-count">{entry.current_custody_hash ? "Custody hash recorded" : "Custody hash missing"}</span></div>)}</div> : <AsyncState status="empty" title="No custody events recorded" />}
      </section>
      {exportEnabled && <EvidencePackageJobs caseId={caseId(item)} />}
    </div>
  );
}

export default function EvidenceCases() {
  const { can, canAny } = useRole();
  const entitled = canAny(["cases.read", "evidence.read"]);
  const exportEnabled = import.meta.env.VITE_EVIDENCE_EXPORT_ENABLED === "true";
  const [state, setState] = useState("loading");
  const [items, setItems] = useState([]);
  const itemsRef = useRef([]);
  const [requestId, setRequestId] = useState("");
  const [message, setMessage] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState(null);
  const [detailState, setDetailState] = useState("idle");
  const [detailRequestId, setDetailRequestId] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!entitled) { setState("forbidden"); return; }
    setState((current) => current === "ready" ? "refreshing" : "loading");
    try {
      const { data } = await apiClient.get(API_ROUTES.evidenceCases);
      const next = normaliseCases(data);
      itemsRef.current = next;
      setItems(next);
      setRequestId(data?.request_id || "");
      setState(next.length ? "ready" : "empty");
      setMessage("");
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setState(stateFromError(error, itemsRef.current.length > 0));
    }
  }, [entitled]);

  useEffect(() => { load(); }, [load]);

  const loadDetail = async (target) => {
    setSelected(target);
    setDetailState("loading");
    setDetailRequestId("");
    try {
      const { data } = await apiClient.get(API_ROUTES.evidenceCase(caseId(target)));
      setSelected(normalizeEvidenceCaseDetail(data));
      setDetailState("ready");
      setMessage("");
      return true;
    } catch (error) {
      setDetailRequestId(requestIdFrom(error));
      setDetailState(stateFromError(error));
      return false;
    }
  };

  const createCase = async (form) => {
    setBusy(true);
    try {
      await apiClient.post(API_ROUTES.evidenceCases, buildEvidenceCasePayload(form));
      setShowForm(false);
      await load();
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setMessage(formatApiError(error, "The case could not be opened."));
    } finally { setBusy(false); }
  };

  const mutateDetail = async (route, payload, fallback) => {
    if (!selected) return false;
    setBusy(true);
    setMessage("");
    try {
      await apiClient.post(route, payload);
      await loadDetail(selected);
      return true;
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setMessage(formatApiError(error, fallback));
      return false;
    } finally { setBusy(false); }
  };

  const attachEvidence = (form) => mutateDetail(API_ROUTES.evidenceCaseItems(caseId(selected)), buildEvidenceCaseItemPayload(form), "The evidence could not be attached.");
  const recordCustody = (form) => mutateDetail(API_ROUTES.evidenceCaseCustody(caseId(selected)), buildCustodyActionPayload(form), "The custody action could not be recorded.");
  const closeCase = async (reason) => {
    const closed = await mutateDetail(API_ROUTES.evidenceCaseClose(caseId(selected)), buildCaseClosurePayload(reason), "The case could not be verified and closed.");
    if (closed) await load();
    return closed;
  };

  if (!entitled) return <section className="case-workspace"><AsyncState status="forbidden" /></section>;
  if (selected) return <section className="case-workspace">
    {detailState === "loading" && <AsyncState status="loading" />}
    {["unauthenticated", "forbidden", "not_found", "unavailable", "degraded"].includes(detailState) && <AsyncState status={detailState} requestId={detailRequestId} onRetry={() => loadDetail(selected)} />}
    {detailState === "ready" && <CaseDetail item={selected} onBack={() => { setSelected(null); setDetailState("idle"); setMessage(""); }} permissions={{ attach: can("cases.attach"), custody: can("custody.record"), close: can("cases.close") }} busy={busy} onAttach={attachEvidence} onCustody={recordCustody} onClose={closeCase} exportEnabled={exportEnabled} />}
    {message && <div className="evidence-inline-error"><ShieldAlert size={16} />{message}</div>}
  </section>;
  return <section className="case-workspace">
    <div className="ops-heading"><div><p className="ops-eyebrow">Evidence management</p><h2>Evidence Cases</h2><p>Track investigations, referenced evidence, and verifiable custody history.</p></div><div className="ops-actions"><button className="ops-secondary" onClick={load} disabled={state === "loading" || state === "refreshing"}>Refresh</button>{can("cases.create") && <button onClick={() => setShowForm((current) => !current)}><Plus size={16} /> {showForm ? "Hide form" : "Open case"}</button>}</div></div>
    {message && <div className="evidence-inline-error"><ShieldAlert size={16} />{message}</div>}
    {showForm && <CaseForm busy={busy} onCancel={() => setShowForm(false)} onSubmit={createCase} />}
    {state === "loading" && <AsyncState status="loading" />}
    {state === "refreshing" && <div className="evidence-refreshing">Refreshing case register...</div>}
    {["unauthenticated", "forbidden", "not_found", "unavailable", "degraded"].includes(state) && <AsyncState status={state} requestId={requestId} onRetry={load} />}
    {state === "empty" && <AsyncState status="empty" title="No evidence cases yet" description="Open a case when an investigation needs evidence and custody tracking." />}
    {state === "ready" && <div className="evidence-table-wrap"><table className="evidence-table"><thead><tr><th>Case</th><th>Status</th><th>Created</th><th>Description</th><th /></tr></thead><tbody>{items.map((item) => <tr key={caseId(item)}><td><strong>{display(item.title || item.name, caseId(item))}</strong><small>{display(item.external_reference || item.reference)}</small></td><td><span className={`evidence-status ${statusClass(item.status)}`}>{display(item.status, "Open")}</span></td><td>{item.created_at ? formatBackendTime(item.created_at, true) : "Not recorded"}</td><td>{display(item.description, "No description recorded.")}</td><td><button className="evidence-view-button" onClick={() => loadDetail(item)}><Eye size={15} /> View</button></td></tr>)}</tbody></table></div>}
  </section>;
}
