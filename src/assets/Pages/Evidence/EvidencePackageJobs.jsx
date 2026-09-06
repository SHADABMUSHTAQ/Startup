import { useCallback, useEffect, useRef, useState } from "react";
import { Download, PackageCheck, RefreshCw, ShieldAlert } from "lucide-react";
import apiClient from "../../../api/apiClient";
import AsyncState from "../../../components/AsyncState";
import { API_ROUTES, buildEvidenceExportPayload, safeDownloadUrl } from "../../../contracts/backendContracts";
import useRole from "../../../hooks/useRole";
import "./EvidencePackageJobs.css";
import "./EvidenceActionOverrides.css";

const TERMINAL_STATES = new Set(["READY", "FAILED", "EXPIRED", "REQUIRES_ARCHIVE_RETRIEVAL"]);
const display = (value, fallback = "Not recorded") => value === undefined || value === null || value === "" ? fallback : String(value);
const requestIdFrom = (error) => error?.response?.data?.request_id || error?.response?.data?.requestId || "";
const stateFromError = (error, hasData = false) => { const status = error?.response?.status; if (status === 401) return "unauthenticated"; if (status === 403) return "forbidden"; if (status === 404) return "not_found"; return hasData ? "degraded" : "unavailable"; };
const normaliseJobs = (data) => Array.isArray(data) ? data : data?.exports || data?.data || [];
const jobId = (job) => job.export_id || job.id;
const jobStatus = (job) => String(job.status || "REQUESTED").toUpperCase();

export default function EvidencePackageJobs({ caseId }) {
  const { canAny } = useRole();
  const canRequest = canAny(["cases.read", "evidence.read"]);
  const [state, setState] = useState("loading");
  const [jobs, setJobs] = useState([]);
  const jobsRef = useRef([]);
  const [activeJobId, setActiveJobId] = useState("");
  const [requestId, setRequestId] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");
  const [downloadLink, setDownloadLink] = useState(null);

  const load = useCallback(async () => {
    if (!canRequest) { setState("forbidden"); return; }
    setState((current) => current === "ready" ? "refreshing" : "loading");
    try {
      const { data } = await apiClient.get(API_ROUTES.evidenceExports(caseId));
      const next = normaliseJobs(data);
      jobsRef.current = next;
      setJobs(next);
      setRequestId(data?.request_id || "");
      setState(next.length ? "ready" : "empty");
      const pending = next.find((job) => !TERMINAL_STATES.has(jobStatus(job)));
      setActiveJobId(pending ? jobId(pending) : "");
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setState(stateFromError(error, jobsRef.current.length > 0));
    }
  }, [caseId, canRequest]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!activeJobId) return undefined;
    let cancelled = false;
    let inFlight = false;
    const poll = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const { data } = await apiClient.get(API_ROUTES.evidenceExport(caseId, activeJobId));
        if (cancelled) return;
        setRequestId(data?.request_id || "");
        const updated = data?.export || data?.data || data;
        setJobs((current) => current.map((job) => jobId(job) === activeJobId ? { ...job, ...updated } : job));
        if (TERMINAL_STATES.has(jobStatus(updated))) setActiveJobId("");
      } catch (error) {
        if (!cancelled) { setRequestId(requestIdFrom(error)); setMessage("Package status could not be refreshed. The last known job state is retained."); }
      } finally { inFlight = false; }
    };
    poll();
    const timer = window.setInterval(poll, 4000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [activeJobId, caseId]);

  const requestPackage = async () => {
    setBusy(true); setMessage("");
    try {
      const { data } = await apiClient.post(API_ROUTES.evidenceExports(caseId), buildEvidenceExportPayload(reason));
      const created = data?.export || data?.data || data;
      setJobs((current) => [created, ...current]);
      setState("ready");
      setActiveJobId(jobId(created));
      setRequestId(data?.request_id || "");
      setReason("");
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setMessage("The evidence package request could not be submitted. Backend authorization remains authoritative.");
    } finally { setBusy(false); }
  };

  const downloadPackage = async (exportId) => {
    setMessage("");
    setDownloadLink(null);
    setBusy(true);
    try {
      const { data } = await apiClient.post(API_ROUTES.evidenceExportDownload(caseId, exportId));
      const url = safeDownloadUrl(data?.url);
      if (!url) throw new Error("Valid download URL was not returned");
      setDownloadLink({ url, expiresAt: data.expires_at });
    } catch (error) {
      setRequestId(requestIdFrom(error));
      setMessage("A short-lived package download link could not be issued. Please retry.");
    } finally { setBusy(false); }
  };

  if (!canRequest) return <section className="package-panel"><AsyncState status="forbidden" /></section>;
  return <section className="package-panel"><div className="package-heading"><div><span className="evidence-kicker">Evidence export</span><h4>Evidence package exports</h4><p>Package generation is asynchronous and follows the backend export lifecycle.</p></div></div><form className="package-request-form" onSubmit={(event) => { event.preventDefault(); requestPackage(); }}><label>Export reason<textarea required minLength={10} maxLength={2000} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain why this evidence package is required" /></label><button type="submit" disabled={busy}><PackageCheck size={15} /> {busy ? "Requesting…" : "Request package"}</button></form>{downloadLink && <div className="package-download-links"><a href={downloadLink.url} target="_blank" rel="noopener noreferrer"><Download size={14} /> Download package</a>{downloadLink.expiresAt && <span>Expires {formatBackendTime(downloadLink.expiresAt)}</span>}</div>}{message && <div className="package-error"><ShieldAlert size={15} />{message}</div>}{state === "loading" && <AsyncState status="loading" />}{state === "refreshing" && <div className="package-refreshing">Refreshing package exports…</div>}{["unauthenticated", "forbidden", "not_found", "unavailable", "degraded"].includes(state) && <AsyncState status={state} requestId={requestId} onRetry={load} />}{state === "empty" && <AsyncState status="empty" title="No package exports yet" description="Request a package when committed case evidence needs to be exported." />}{state === "ready" && <div className="package-job-list">{jobs.map((job) => { const status = jobStatus(job); return <div className="package-job-row" key={jobId(job)}><div className="package-job-main"><strong>{display(jobId(job), "Evidence export")}</strong><span>{job.created_at ? formatBackendTime(job.created_at) : "Time unavailable"}</span></div><span className={`package-status package-${status.toLowerCase()}`}>{status.replaceAll("_", " ")}</span>{status === "READY" ? <button type="button" className="package-download" disabled={busy} onClick={() => downloadPackage(jobId(job))}><Download size={14} /> Download</button> : !TERMINAL_STATES.has(status) ? <span className="package-polling"><RefreshCw size={13} /> Updating</span> : <span className="package-muted">No download available</span>}{!TERMINAL_STATES.has(status) && activeJobId !== jobId(job) && <button type="button" className="package-refresh-button" onClick={() => setActiveJobId(jobId(job))} aria-label="Poll package export"><RefreshCw size={14} /></button>}</div>; })}</div>}</section>;
}
import { formatBackendTime } from "../../../utils/backendTime";
