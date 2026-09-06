import { useCallback, useEffect, useRef, useState } from "react";
import { Gavel, Lock, Plus, RefreshCw, ShieldAlert, X } from "lucide-react";
import apiClient from "../../../api/apiClient";
import AsyncState from "../../../components/AsyncState";
import {
  API_ROUTES,
  HOLDABLE_EVIDENCE_COLLECTIONS,
  buildLegalHoldPayload,
  buildLegalHoldReleasePayload,
} from "../../../contracts/backendContracts";
import useRole from "../../../hooks/useRole";
import { formatApiError } from "../../../utils/apiError";
import "./LegalHolds.css";
import "./EvidenceActionOverrides.css";

const display = (value, fallback = "Not recorded") => value === undefined || value === null || value === "" ? fallback : String(value);
const requestIdFrom = (error) => error?.response?.data?.request_id || error?.response?.data?.requestId || "";
const errorState = (error, hasData) => { const code = error?.response?.status; if (code === 401) return "unauthenticated"; if (code === 403) return "forbidden"; if (code === 404) return "not_found"; return hasData ? "degraded" : "unavailable"; };
const normaliseHolds = (data) => Array.isArray(data) ? data : data?.holds || data?.data || data?.items || [];
const holdId = (hold) => hold.hold_id || hold.id || hold.holdId;
const holdState = (hold) => String(hold.state || hold.status || "unknown").toLowerCase().replace(/\s+/g, "-");
const protectionState = (value) => String(value || "pending").toLowerCase().replace(/\s+/g, "-");
const scopeLabel = (hold) => {
  const scope = String(hold.scope_type || "TENANT").toUpperCase();
  if (scope === "EVENT") return `${display(hold.collection)} / ${display(hold.event_uid)}`;
  if (scope === "COLLECTION") return display(hold.collection);
  return "Entire tenant";
};

function HoldActionModal({ action, hold, busy, message, onCancel, onSubmit }) {
  const dialogRef = useRef(null);
  useEffect(() => {
    const dialog = dialogRef.current;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  const applying = action === "apply";
  const [scopeType, setScopeType] = useState("TENANT");
  const [collection, setCollection] = useState(HOLDABLE_EVIDENCE_COLLECTIONS[0]);
  const [eventUid, setEventUid] = useState("");
  const [reason, setReason] = useState("");
  const [authority, setAuthority] = useState("");
  const [proceedingReference, setProceedingReference] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const submit = (event) => {
    event.preventDefault();
    onSubmit({ scopeType, collection, eventUid, reason, authority, proceedingReference, confirmed });
  };

  return <dialog ref={dialogRef} aria-labelledby="hold-action-title" className="hold-modal-overlay" onCancel={(event) => { event.preventDefault(); if (!busy) onCancel(); }}><form className="hold-modal" onSubmit={submit}>
    <button type="button" className="hold-modal-close" onClick={onCancel} aria-label="Close hold action"><X size={18} /></button>
    <div className="hold-modal-icon"><Gavel size={20} /></div>
    <span className="holds-kicker">Admin authorization</span>
    <h3 id="hold-action-title">{applying ? "Apply legal hold?" : "Release legal hold?"}</h3>
    {message && <div className="holds-error" role="alert">{message}</div>}
    <p>{applying ? "Choose the exact tenant evidence scope that must be preserved." : <>This releases <strong>{display(hold?.hold_id)}</strong>. The action is permanently recorded.</>}</p>
    {applying && <>
      <label>Scope<select value={scopeType} onChange={(event) => setScopeType(event.target.value)}><option value="TENANT">Entire tenant</option><option value="COLLECTION">One evidence collection</option><option value="EVENT">One evidence event</option></select></label>
      {scopeType !== "TENANT" && <label>Evidence collection<select value={collection} onChange={(event) => setCollection(event.target.value)}>{HOLDABLE_EVIDENCE_COLLECTIONS.map((name) => <option key={name} value={name}>{name}</option>)}</select></label>}
      {scopeType === "EVENT" && <label>Event UID<input required maxLength={200} value={eventUid} onChange={(event) => setEventUid(event.target.value)} placeholder="Authenticated event UID" /></label>}
      <label>Proceeding reference<input maxLength={300} value={proceedingReference} onChange={(event) => setProceedingReference(event.target.value)} placeholder="Optional matter or proceeding reference" /></label>
    </>}
    <label>Reason<textarea required minLength={10} maxLength={2000} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain the authorized preservation decision" /></label>
    <label>Authority<input required minLength={2} maxLength={300} value={authority} onChange={(event) => setAuthority(event.target.value)} placeholder="Matter, order, or approving authority" /></label>
    <label className="hold-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} required /><span>I confirm this {action} request is authorized and recorded.</span></label>
    <div className="hold-modal-actions"><button type="button" className="ops-secondary" onClick={onCancel}>Cancel</button><button type="submit" disabled={busy || !confirmed}>{busy ? "Submitting…" : applying ? "Apply hold" : "Release hold"}</button></div>
  </form></dialog>;
}

export default function LegalHolds() {
  const { can, canAny } = useRole();
  const entitled = canAny(["holds.read", "holds.apply", "holds.release"]);
  const canApply = can("holds.apply");
  const canRelease = can("holds.release");
  const [state, setState] = useState("loading");
  const [items, setItems] = useState([]);
  const itemsRef = useRef([]);
  const [requestId, setRequestId] = useState("");
  const [action, setAction] = useState(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!entitled) { setState("forbidden"); return; }
    setState((current) => current === "ready" ? "refreshing" : "loading");
    try {
      const { data } = await apiClient.get(API_ROUTES.legalHolds);
      setRequestId(data?.request_id || "");
      const next = normaliseHolds(data);
      itemsRef.current = next;
      setItems(next);
      setState(next.length ? "ready" : "empty");
      setMessage("");
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setState(errorState(error, itemsRef.current.length > 0));
    }
  }, [entitled]);

  useEffect(() => { load(); }, [load]);

  const submitAction = async (form) => {
    if (!action || !form.confirmed) return;
    setBusy(true);
    setMessage("");
    try {
      if (action.type === "apply") {
        await apiClient.post(API_ROUTES.legalHolds, buildLegalHoldPayload(form));
      } else {
        await apiClient.post(API_ROUTES.legalHoldRelease(holdId(action.hold)), buildLegalHoldReleasePayload(form));
      }
      setAction(null);
      await load();
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setMessage(formatApiError(error, `The hold could not be ${action.type === "apply" ? "applied" : "released"}. Please retry.`));
    } finally {
      setBusy(false);
    }
  };

  if (!entitled) return <section className="holds-workspace"><AsyncState status="forbidden" /></section>;
  return <section className="holds-workspace">
    <div className="ops-heading"><div><p className="ops-eyebrow">Evidence governance</p><h2>Legal Holds</h2><p>Mongo preservation starts immediately; Azure protection is verified asynchronously.</p></div><div className="ops-actions"><button className="ops-secondary" onClick={load} disabled={state === "loading" || state === "refreshing"}><RefreshCw size={15} className={state === "refreshing" ? "ops-spin" : ""} /> Refresh</button>{canApply && <button onClick={() => setAction({ type: "apply", hold: null })}><Plus size={15} /> Apply hold</button>}</div></div>
    {message && <div className="holds-error"><ShieldAlert size={16} />{message}</div>}
    {state === "loading" && <AsyncState status="loading" />}
    {state === "refreshing" && <div className="holds-refreshing">Refreshing legal-hold register…</div>}
    {["unauthenticated", "forbidden", "not_found", "unavailable", "degraded"].includes(state) && <AsyncState status={state} requestId={requestId} onRetry={load} />}
    {state === "empty" && <AsyncState status="empty" title="No legal holds recorded" description="Apply a hold when evidence must remain preserved beyond normal retention handling." />}
    {state === "ready" && <div className="holds-table-wrap"><table className="holds-table"><thead><tr><th>Hold</th><th>State</th><th>Archive protection</th><th>Authority</th><th>Scope</th><th>Updated</th><th>Actions</th></tr></thead><tbody>{items.map((hold) => <tr key={holdId(hold)}><td><strong>{display(holdId(hold))}</strong><small>{display(hold.reason)}</small></td><td><span className={`hold-state ${holdState(hold)}`}><Lock size={12} />{display(hold.status, "Unknown")}</span></td><td><span className={`hold-state ${protectionState(hold.archive_protection_status)}`}>{display(hold.archive_protection_status, "Pending")}</span></td><td>{display(hold.authority)}</td><td>{scopeLabel(hold)}</td><td>{hold.updated_at ? formatBackendTime(hold.updated_at) : "Not recorded"}</td><td>{canRelease && holdState(hold) === "active" ? <button className="holds-action holds-release" onClick={() => setAction({ type: "release", hold })}>Release</button> : <span className="holds-readonly">Read only</span>}</td></tr>)}</tbody></table></div>}
    {action && <HoldActionModal action={action.type} hold={action.hold} busy={busy} message={message} onCancel={() => setAction(null)} onSubmit={submitAction} />}
  </section>;
}
import { formatBackendTime } from "../../../utils/backendTime";
