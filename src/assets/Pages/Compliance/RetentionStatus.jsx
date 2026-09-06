import { useCallback, useEffect, useState } from "react";
import { Archive, CalendarClock, LockKeyhole, RefreshCw } from "lucide-react";
import apiClient from "../../../api/apiClient";
import AsyncState from "../../../components/AsyncState";
import { API_ROUTES } from "../../../contracts/backendContracts";
import useRole from "../../../hooks/useRole";
import "./RetentionStatus.css";

const display = (value, fallback = "Not recorded") => value === undefined || value === null || value === "" ? fallback : String(value);
const requestIdFrom = (error) => error?.response?.data?.request_id || error?.response?.data?.requestId || "";
const errorState = (error) => { const status = error?.response?.status; if (status === 401) return "unauthenticated"; if (status === 403) return "forbidden"; if (status === 404) return "not_found"; return "unavailable"; };

export default function RetentionStatus() {
  const { can } = useRole();
  const entitled = can("retention.read");
  const [state, setState] = useState("loading");
  const [data, setData] = useState(null);
  const [requestId, setRequestId] = useState("");
  const load = useCallback(async () => {
    if (!entitled) { setState("forbidden"); return; }
    setState("loading");
    try { const response = await apiClient.get(API_ROUTES.retentionStatus); const next = response.data?.retention || response.data?.data || response.data; setData(next); setRequestId(response.data?.request_id || ""); setState(next ? "ready" : "empty"); }
    catch (error) { setRequestId(requestIdFrom(error)); setState(errorState(error)); }
  }, [entitled]);
  useEffect(() => { load(); }, [load]);
  if (!entitled) return <section className="retention-status-panel"><AsyncState status="forbidden" /></section>;
  return <section className="retention-status-panel"><div className="retention-heading"><div><span className="ops-eyebrow">Evidence governance</span><h3>Retention Status</h3><p>Read-only tenant entitlement, hot-storage window, legal holds, and archive availability.</p></div><button className="ops-secondary" onClick={load} disabled={state === "loading"}><RefreshCw size={14} /> Refresh</button></div>{state === "loading" && <AsyncState status="loading" />}{["unauthenticated", "forbidden", "not_found", "unavailable", "degraded"].includes(state) && <AsyncState status={state} requestId={requestId} onRetry={load} />}{state === "empty" && <AsyncState status="empty" title="Retention status unavailable" description="No backend retention resolution has been returned for this workspace." />}{state === "ready" && data && <div className="retention-grid"><div><CalendarClock size={17} /><span>Archive entitlement</span><strong>{data.tenant_retention_days ? `${data.tenant_retention_days} days` : "Not recorded"}</strong></div><div><CalendarClock size={17} /><span>Hot storage</span><strong>{data.hot_storage_days ? `${data.hot_storage_days} days` : "Not recorded"}</strong></div><div><LockKeyhole size={17} /><span>Legal-hold state</span><strong>{display(data.legal_hold_state)}{data.active_hold_count ? ` (${data.active_hold_count})` : ""}</strong></div><div><Archive size={17} /><span>Archive availability</span><strong>{display(data.archive_availability)}</strong></div></div>}</section>;
}
