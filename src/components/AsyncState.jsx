import React from "react";
import { AlertCircle, CheckCircle2, Clock3, Copy, FileQuestion, LockKeyhole, RefreshCw, SearchX, ShieldAlert } from "lucide-react";
import "./AsyncState.css";

const STATE_COPY = {
  loading: [Clock3, "Loading", "We are retrieving the latest information."],
  unauthenticated: [LockKeyhole, "Session required", "Please sign in again to continue."],
  forbidden: [ShieldAlert, "Access unavailable", "Your current role is not authorized for this view."],
  not_found: [SearchX, "Not found", "The requested resource could not be found."],
  unavailable: [AlertCircle, "Temporarily unavailable", "This service is not responding right now. Please try again shortly."],
  empty: [FileQuestion, "Nothing to show", "There is no information available here yet."],
  degraded: [AlertCircle, "Showing limited information", "Some information could not be refreshed. Last known data may be shown."],
  success: [CheckCircle2, "Ready", ""],
};

export default function AsyncState({ status, requestId, onRetry, children, title, description }) {
  if (status === "success") return typeof children === "function" ? children() : children || null;
  const [Icon, defaultTitle, defaultDescription] = STATE_COPY[status] || STATE_COPY.unavailable;
  const copyRequestId = async () => { if (requestId && navigator.clipboard) await navigator.clipboard.writeText(requestId); };
  return <div className={`async-state async-state-${status || "unavailable"}`} role="status">
    <div className="async-state-icon"><Icon size={22} /></div>
    <h3>{title || defaultTitle}</h3>
    <p>{description || defaultDescription}</p>
    {requestId && <button type="button" className="async-state-request" onClick={copyRequestId} title="Copy request ID"><Copy size={13} /> Request ID: {requestId}</button>}
    {onRetry && <button type="button" className="async-state-retry" onClick={onRetry}><RefreshCw size={14} /> Try again</button>}
  </div>;
}
