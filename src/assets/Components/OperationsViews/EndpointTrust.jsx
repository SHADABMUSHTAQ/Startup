import { Activity, ShieldCheck } from "lucide-react";
import AsyncState from "../../../components/AsyncState";
import "./EndpointTrust.css";

const display = (value, fallback = "Not recorded") => value === undefined || value === null || value === "" ? fallback : String(value);
const statusClass = (value) => String(value || "unknown").toLowerCase().replace(/\s+/g, "-");

export default function EndpointTrust({ endpoints = [], loading = false }) {
  return <section className="endpoint-trust-panel">
    <div className="endpoint-trust-heading"><div><span className="ops-eyebrow">Endpoint assurance</span><h3>Endpoint Trust</h3><p>Signing, time, audit, POS, and spool state calculated by the WarSOC backend.</p></div></div>
    {loading && <AsyncState status="loading" />}
    {!loading && endpoints.length === 0 && <AsyncState status="empty" title="No trust records available" description="Endpoint trust details will appear after authenticated endpoint telemetry arrives." />}
    {!loading && endpoints.length > 0 && <div className="endpoint-trust-grid">{endpoints.map((endpoint) => {
      const signing = endpoint.event_signing?.status;
      const timeTrust = endpoint.time_trust?.status;
      const audit = endpoint.audit_coverage?.status;
      const pos = endpoint.pos_coverage?.status;
      const spool = endpoint.spool_health?.status;
      return <article className="endpoint-trust-card" key={endpoint.agent_id}>
        <div className="endpoint-trust-card-heading"><div className="endpoint-trust-icon"><ShieldCheck size={17} /></div><div><strong>{display(endpoint.endpoint_name || endpoint.agent_id)}</strong><span>{display(endpoint.version)} · Last seen {endpoint.last_seen ? formatBackendTime(endpoint.last_seen) : "not recorded"}</span></div><span className={`endpoint-trust-status ${statusClass(endpoint.health)}`}>{display(endpoint.health, "Unknown")}</span></div>
        <dl className="endpoint-trust-metrics"><div><dt>Event signing</dt><dd>{display(signing)}</dd></div><div><dt>Time trust</dt><dd>{display(timeTrust)}</dd></div><div><dt>Audit coverage</dt><dd>{display(audit)}</dd></div><div><dt>POS coverage</dt><dd>{display(pos)}</dd></div><div><dt>Spool health</dt><dd>{display(spool)}</dd></div></dl>
        <div className="endpoint-trust-foot"><Activity size={14} /> Trust signals are backend-calculated</div>
      </article>;
    })}</div>}
  </section>;
}
import { formatBackendTime } from "../../../utils/backendTime";
