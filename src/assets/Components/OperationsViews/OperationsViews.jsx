import React, { useCallback, useEffect, useRef, useState } from "react";
import { AlertCircle, CheckCircle2, Clock3, Copy, Database, Download, FileSpreadsheet, KeyRound, RadioTower, RefreshCw, ShieldCheck, Upload, X } from "lucide-react";
import apiClient from "../../../api/apiClient";
import AsyncState from "../../../components/AsyncState";
import { API_ROUTES, archiveSourceOptions, buildArchiveRetrievalPayload, safeDownloadUrl } from "../../../contracts/backendContracts";
import useRole from "../../../hooks/useRole";
import EndpointTrust from "./EndpointTrust";
import "./OperationsViews.css";

const display = (value, fallback = "Not recorded") => value === undefined || value === null || value === "" ? fallback : String(value);
const healthLabel = (value) => ({ active: "Online", degraded: "Degraded", offline: "Offline", revoked: "Revoked" }[String(value).toLowerCase()] || "Not recorded");

function Fleet({ onDownloadAgent }) {
  const [state, setState] = useState("loading");
  const [fleet, setFleet] = useState(null);
  const [message, setMessage] = useState("");
  const load = useCallback(async () => {
    setState((current) => current === "ready" ? "refreshing" : "loading");
    try {
      const { data } = await apiClient.get(API_ROUTES.endpointStatus);
      setFleet(data);
      setState("ready");
      setMessage("");
    } catch (error) {
      setState("degraded");
      setMessage(error.response?.status === 403 ? "Access denied. Your role cannot view endpoint fleet status." : "Endpoint fleet status is temporarily unavailable. Last known information is kept when available.");
    }
  }, []);
  useEffect(() => { load(); }, [load]);
  const rows = fleet?.data || [];
  const summary = [
    ["Seats purchased", fleet?.max_agents], ["Enrolled", fleet?.registered_agents], ["Remaining", Math.max(0, Number(fleet?.max_agents || 0) - Number(fleet?.registered_agents || 0))],
    ["Online", fleet?.agents_online], ["Degraded", fleet?.agents_degraded], ["Offline", fleet?.agents_offline],
  ];
  return <section className="ops-view">
    <div className="ops-heading"><div><p className="ops-eyebrow">Endpoint operations</p><h2>Endpoint Fleet</h2><p>Current fleet status is based on agent health, not log rows.</p></div><div className="ops-actions"><button className="ops-secondary" onClick={load} disabled={state === "loading" || state === "refreshing"}><RefreshCw size={16} className={state === "refreshing" ? "ops-spin" : ""} /> Refresh</button>{onDownloadAgent && <button onClick={onDownloadAgent}><Download size={16} /> Download Agent</button>}</div></div>
    {message && <div className="ops-notice"><AlertCircle size={17} />{message}<button onClick={load}>Retry</button></div>}
    <div className="ops-stats">{summary.map(([label, value]) => <div className="ops-stat" key={label}><span>{label}</span><strong>{state === "loading" ? "—" : display(value, "0")}</strong></div>)}</div>
    <div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>Endpoint</th><th>Agent ID</th><th>Version</th><th>Last seen</th><th>Health</th><th>Signing</th><th>Audit / sensor</th><th>POS feed</th><th>Spool</th><th>Degradation reason</th></tr></thead><tbody>{state === "loading" ? <tr><td colSpan="10" className="ops-empty">Loading endpoint fleet…</td></tr> : rows.length ? rows.map((endpoint) => { const sensor = endpoint.sensor_status || {}; const channels = sensor.channels || {}; const spool = sensor.spool || {}; return <tr key={endpoint.agent_id}><td>{display(endpoint.endpoint_name)}</td><td className="ops-code">{display(endpoint.agent_id)}</td><td>{display(endpoint.version)}</td><td>{endpoint.last_seen ? new Date(endpoint.last_seen).toLocaleString() : "Not recorded"}</td><td><span className={`ops-status ${String(endpoint.health || "offline").toLowerCase()}`}>{healthLabel(endpoint.health)}</span></td><td>{display(endpoint.event_signing?.status)}</td><td>{display(sensor.audit_policy_status)} / {display(channels.Security?.status)}</td><td>{display(sensor.pos?.status)}</td><td>{spool.blocked ? "Blocked" : display(spool.status)}</td><td>{display(sensor.degradation_reason || endpoint.degradation_reason)}</td></tr>; }) : <tr><td colSpan="10" className="ops-empty">No endpoint fleet records have been received yet.</td></tr>}</tbody></table></div>
    <EndpointTrust endpoints={rows} loading={state === "loading"} />
  </section>;
}

function LegacyOfflineAnalysis() {
  const inputRef = useRef(null); const [file, setFile] = useState(null); const [state, setState] = useState("empty"); const [results, setResults] = useState([]); const [message, setMessage] = useState("");
  const upload = async () => { if (!file) { setMessage("Choose a CSV file before starting analysis."); setState("validation"); return; } setState("uploading"); setMessage(""); const form = new FormData(); form.append("file", file); try { const { data } = await apiClient.post("/upload/analyze", form, { headers: { "Content-Type": "multipart/form-data" }, timeout: 120000 }); setResults(Array.isArray(data?.findings) ? data.findings.slice(0, 100) : []); setState("ready"); } catch { setState("error"); setMessage("The CSV could not be analyzed. Check the file format and try again."); } };
  const clear = () => { setFile(null); setResults([]); setMessage(""); setState("empty"); if (inputRef.current) inputRef.current.value = ""; };
  return <section className="ops-view"><div className="ops-heading"><div><p className="ops-eyebrow">Separate from live collection</p><h2>Offline Log Analysis</h2><p>Upload a CSV for bounded, on-demand analysis. This does not affect endpoint collection.</p></div></div><div className="offline-upload"><Upload size={24}/><strong>CSV log file</strong><span>{file ? file.name : "No file selected"}</span><input ref={inputRef} type="file" accept=".csv,text/csv" onChange={(event) => { setFile(event.target.files?.[0] || null); setState("empty"); }}/><div><button onClick={upload} disabled={state === "uploading"}>{state === "uploading" ? "Analyzing…" : "Analyze CSV"}</button>{file && <button className="ops-secondary" onClick={clear}>Clear</button>}</div></div>{message && <div className="ops-notice"><AlertCircle size={17}/>{message}{state === "error" && <button onClick={upload}>Retry</button>}</div>}{state === "ready" && <div className="ops-table-wrap"><div className="ops-results-head"><strong>Analysis results</strong><span>Showing up to 100 records</span></div><table className="ops-table"><thead><tr><th>Time</th><th>Event ID</th><th>Source</th><th>Summary</th></tr></thead><tbody>{results.length ? results.map((row, index) => <tr key={row.id || index}><td>{display(row.timestamp || row.time)}</td><td>{display(row.event_id || row.eventId)}</td><td>{display(row.source || row.host || row.ip)}</td><td>{display(row.summary || row.message)}</td></tr>) : <tr><td colSpan="4" className="ops-empty">No matching records were found in this file.</td></tr>}</tbody></table></div>}</section>;
}

function OfflineAnalysis() {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [state, setState] = useState("empty");
  const [results, setResults] = useState([]);
  const [message, setMessage] = useState("");
  const [isDragging, setIsDragging] = useState(false);

  const selectFile = (selected) => {
    if (!selected) return;
    if (!selected.name.toLowerCase().endsWith(".csv")) {
      setFile(null);
      setState("validation");
      setMessage("Select a valid CSV file to continue.");
      return;
    }
    setFile(selected);
    setState("empty");
    setMessage("");
  };

  const upload = async () => {
    if (!file) {
      setState("validation");
      setMessage("Choose a CSV file before starting analysis.");
      return;
    }
    setState("uploading");
    setMessage("");
    const form = new FormData();
    form.append("file", file);
    try {
      const { data } = await apiClient.post("/upload/analyze", form, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 120000,
      });
      setResults(Array.isArray(data?.findings) ? data.findings.slice(0, 100) : []);
      setState("ready");
    } catch {
      setState("error");
      setMessage("The CSV could not be analyzed. Check the file format and try again.");
    }
  };

  const clear = () => {
    setFile(null);
    setResults([]);
    setMessage("");
    setState("empty");
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <section className="ops-view offline-analysis-view">
      <header className="offline-hero">
        <div>
          <p className="ops-eyebrow">Separate from live collection</p>
          <h2>Offline Log Analysis</h2>
          <p>Review exported security logs without interrupting endpoint collection or the live operations feed.</p>
        </div>
        <div className="offline-hero-badge"><ShieldCheck size={17} /> Isolated analysis workspace</div>
      </header>

      <div className="offline-workspace-grid">
        <section className="offline-upload-card" aria-labelledby="offline-upload-title">
          <div className="offline-card-heading">
            <div className="offline-icon-box"><FileSpreadsheet size={23} /></div>
            <div><span>Step 1</span><h3 id="offline-upload-title">Select a CSV log file</h3></div>
          </div>
          <input ref={inputRef} id="offline-file-input" className="offline-file-input" type="file" accept=".csv,text/csv" onChange={(event) => selectFile(event.target.files?.[0])} />
          <label
            htmlFor="offline-file-input"
            className={`offline-dropzone ${isDragging ? "is-dragging" : ""} ${file ? "has-file" : ""}`}
            onDragEnter={(event) => { event.preventDefault(); setIsDragging(true); }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(event) => { event.preventDefault(); setIsDragging(false); selectFile(event.dataTransfer.files?.[0]); }}
          >
            {file ? <CheckCircle2 size={34} /> : <Upload size={34} />}
            <strong>{file ? "File ready for analysis" : "Drop your CSV file here"}</strong>
            <span>{file ? file.name : "or click to browse from your device"}</span>
            {!file && <em>CSV format only</em>}
          </label>
          {file && (
            <div className="offline-selected-file">
              <FileSpreadsheet size={18} />
              <div><strong>{file.name}</strong><span>{(file.size / 1024).toFixed(1)} KB</span></div>
              <button type="button" onClick={clear} aria-label="Remove selected file"><X size={16} /></button>
            </div>
          )}
          <div className="offline-primary-actions">
            <button type="button" onClick={upload} disabled={state === "uploading" || !file}>
              {state === "uploading" ? <><RefreshCw size={17} className="ops-spin" /> Analyzing file...</> : <><ShieldCheck size={17} /> Start Analysis</>}
            </button>
            <span>Results are limited to the first 100 matching records.</span>
          </div>
        </section>

        <aside className="offline-context-panel">
          <div className="offline-card-heading">
            <div className="offline-icon-box"><Database size={23} /></div>
            <div><span>Workflow</span><h3>What happens next</h3></div>
          </div>
          <ol className="offline-steps">
            <li><span>1</span><div><strong>Validate file</strong><p>The selected CSV is checked before analysis begins.</p></div></li>
            <li><span>2</span><div><strong>Analyze records</strong><p>WarSOC reviews the upload as a separate offline dataset.</p></div></li>
            <li><span>3</span><div><strong>Review findings</strong><p>Matching records appear in a bounded results table below.</p></div></li>
          </ol>
          <div className="offline-assurance"><Clock3 size={18} /><div><strong>Live collection stays active</strong><span>This workflow does not pause or modify endpoint telemetry.</span></div></div>
        </aside>
      </div>

      {message && <div className="ops-notice offline-message"><AlertCircle size={17}/>{message}{state === "error" && <button onClick={upload}>Retry</button>}</div>}
      {state === "ready" && <div className="ops-table-wrap offline-results"><div className="ops-results-head"><strong>Analysis results</strong><span>Showing up to 100 records</span></div><table className="ops-table"><thead><tr><th>Time</th><th>Event ID</th><th>Source</th><th>Summary</th></tr></thead><tbody>{results.length ? results.map((row, index) => <tr key={row.id || index}><td>{display(row.timestamp || row.time)}</td><td>{display(row.event_id || row.eventId)}</td><td>{display(row.source || row.host || row.ip)}</td><td>{display(row.summary || row.message)}</td></tr>) : <tr><td colSpan="4" className="ops-empty">No matching records were found in this file.</td></tr>}</tbody></table></div>}
    </section>
  );
}

function RelayView() {
  const [state, setState] = useState("loading");
  const [capability, setCapability] = useState(null);
  const [relays, setRelays] = useState([]);
  const [message, setMessage] = useState("");
  const [requestId, setRequestId] = useState("");
  const [showSetup, setShowSetup] = useState(false);
  const [activation, setActivation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState(null);
  const [recoveryTarget, setRecoveryTarget] = useState(null);
  const relaysRef = useRef([]);
  const [setup, setSetup] = useState({ relay_name: "", device_id: "", model: "pfSense", source_address: "", relay_bind_host: "", relay_port: "5514", timezone: "UTC", expected_eps: "100" });

  const load = useCallback(async () => {
    setState((current) => current === "ready" ? "refreshing" : "loading");
    try {
      const { data } = await apiClient.get("/network-relay/status");
      setRequestId(data?.request_id || "");
      const nextCapability = data?.capability || {};
      setCapability(nextCapability);
      const nextRelays = Array.isArray(data?.relays) ? data.relays : [];
      relaysRef.current = nextRelays;
      setRelays(nextRelays);
      setState(nextCapability.enabled === false || nextCapability.entitled === false ? "unavailable" : (nextRelays.length ? "ready" : "empty"));
      setMessage("");
    } catch (error) {
      const status = error.response?.status;
      setRequestId(error.response?.data?.request_id || "");
      setState(status === 404 ? "unavailable" : status === 403 ? "forbidden" : relaysRef.current.length ? "degraded" : "error");
      setMessage(status === 404 || status === 403 ? "Firewall metadata is not available for this workspace." : "Firewall relay status is temporarily unavailable. Last known information is kept when available.");
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const updateSetup = (field, value) => setSetup((current) => ({ ...current, [field]: value }));
  const downloadConfiguration = () => {
    if (!activation?.configuration) return;
    const blob = new Blob([`${JSON.stringify(activation.configuration, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = activation.configurationFilename || "relay-config.json";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };
  const openSetupPackage = () => {
    const endpoint = activation?.packageEndpoint || capability?.setup_package_endpoint;
    if (!endpoint) return;
    const apiRoot = String(apiClient.defaults.baseURL || "/api/v1").replace(/\/api\/v1\/?$/, "");
    window.open(`${apiRoot}${endpoint}`, "_blank", "noopener,noreferrer");
  };
  const generate = async (event) => {
    event.preventDefault();
    if (!setup.relay_name || !setup.device_id || !setup.model || !setup.source_address || !setup.relay_bind_host || !setup.relay_port || !setup.timezone || !setup.expected_eps) {
      setMessage("Complete every relay and device field before generating activation.");
      return;
    }
    setBusy(true); setMessage(""); setActivation(null);
    try {
      const sourceAddress = setup.source_address.trim();
      const { data } = await apiClient.post("/network-relay/generate-activation", {
        relay_name: setup.relay_name.trim(),
        devices: [{ device_id: setup.device_id.trim(), vendor: "pfsense", model: setup.model.trim(), source_addresses: [sourceAddress.includes("/") ? sourceAddress : `${sourceAddress}/${sourceAddress.includes(":") ? "128" : "32"}`], transport: "udp", timezone: setup.timezone.trim(), expected_eps: Number(setup.expected_eps) }],
        listeners: [{ transport: "udp", bind_host: setup.relay_bind_host.trim(), port: Number(setup.relay_port) }],
      });
      setActivation({
        code: data?.activation_code || "",
        expires: Number(data?.expires_in_seconds || 0),
        configuration: data?.setup?.configuration || null,
        configurationFilename: data?.setup?.configuration_filename || "relay-config.json",
        packageAvailable: data?.setup?.package_available === true,
        packageEndpoint: data?.setup?.package_endpoint || capability?.setup_package_endpoint || "",
        packageSha256: data?.setup?.package_sha256 || capability?.setup_package_sha256 || "",
        publisherTrust: data?.setup?.publisher_trust || capability?.publisher_trust || "",
      });
      setMessage("Relay setup created. Download the configuration and copy the one-time activation code before leaving this page.");
    } catch { setMessage("Activation could not be generated. Please review the fields and retry."); }
    finally { setBusy(false); }
  };

  const revoke = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (!String(form.get("reason") || "").trim()) return;
    setBusy(true);
    try { await apiClient.post(`/network-relay/${encodeURIComponent(revokeTarget.relay_id)}/revoke`, { reason: String(form.get("reason")).trim() }); setRevokeTarget(null); await load(); }
    catch { setMessage("The relay could not be revoked. Please retry."); }
    finally { setBusy(false); }
  };

  const authorizeRecovery = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const reason = String(form.get("reason") || "").trim(); const totp_code = String(form.get("totp_code") || "").trim();
    if (!reason || !/^\d{6}$/.test(totp_code)) return;
    setBusy(true);
    try { await apiClient.post(`/network-relay/${encodeURIComponent(recoveryTarget.relay_id)}/authorize-key-recovery`, { reason, totp_code }); setRecoveryTarget(null); setMessage("Key recovery authorization was recorded. The relay performs the next handshake."); }
    catch { setMessage("Key recovery authorization could not be completed. Please retry."); }
    finally { setBusy(false); }
  };

  const formatAge = (seconds) => seconds === undefined || seconds === null ? "Not recorded" : `${Math.max(0, Math.round(Number(seconds)))}s ago`;
  const statusClass = (value) => String(value || "inactive").toLowerCase().replace(/\s+/g, "-");
  const canManage = capability?.can_manage === true;

  return <section className="ops-view relay-workspace">
    <div className="ops-heading"><div><p className="ops-eyebrow">Firewall metadata</p><h2>Firewall Relays</h2><p>Monitor relay and device health without exposing packet payloads, credentials, raw syslog, or policy controls.</p></div><div className="ops-actions"><button className="ops-secondary" onClick={load} disabled={state === "loading" || state === "refreshing"}><RefreshCw size={16} className={state === "refreshing" ? "ops-spin" : ""} /> Refresh</button>{canManage && <button onClick={() => setShowSetup((current) => !current)}><KeyRound size={16} /> {showSetup ? "Hide setup" : "Set up relay"}</button>}</div></div>
    {message && <div className={`ops-notice relay-notice ${state === "error" || state === "degraded" ? "is-error" : ""}`}><AlertCircle size={17} />{message}{["error", "degraded"].includes(state) && <button onClick={load}>Retry</button>}</div>}
    {state === "loading" && <AsyncState status="loading" />}
    {state === "unavailable" && <AsyncState status="unavailable" requestId={requestId} onRetry={load} title="Firewall relays unavailable" description="Firewall relay metadata is not enabled or is not available for this workspace." />}
    {state === "forbidden" && <AsyncState status="forbidden" requestId={requestId} />}
    {state === "degraded" && <AsyncState status="degraded" requestId={requestId} onRetry={load} />}
    {state === "error" && <AsyncState status="unavailable" requestId={requestId} onRetry={load} />}
    {state !== "loading" && !["unavailable", "forbidden", "degraded", "error"].includes(state) && <>
      <div className="relay-capability-grid"><div><span>Relay entitlement</span><strong>{capability?.entitled ? "Included" : "Not included"}</strong></div><div><span>Active relays</span><strong>{display(capability?.active_relays, "0")} / {display(capability?.max_relays, "0")}</strong></div><div><span>Remaining</span><strong>{display(capability?.remaining_relays, "0")}</strong></div><div><span>Collection mode</span><strong>Metadata only</strong></div></div>
      {state === "empty" && <div className="relay-state-card relay-empty"><RadioTower size={26} /><div><strong>No firewall relay registered</strong><p>{canManage ? "Use the setup form to register an approved relay and device." : "No relay has been registered for this workspace yet."}</p></div></div>}
      {relays.map((relay) => <article className="relay-card" key={relay.relay_id}><div className="relay-card-heading"><div><span className="relay-kicker">Relay metadata</span><h3>{display(relay.relay_name, relay.relay_id)}</h3><p>{display(relay.hostname)} · v{display(relay.version)}</p></div><span className={`relay-health ${statusClass(relay.health || relay.status)}`}>{display(relay.health || relay.status)}</span></div><div className="relay-detail-grid"><div><span>Last seen</span><strong>{relay.last_seen ? new Date(relay.last_seen).toLocaleString() : "Not recorded"}</strong><small>{formatAge(relay.last_seen_age_seconds)}</small></div><div><span>Health reason</span><strong>{display(relay.last_health_reason, "No active degradation")}</strong></div><div><span>Last sequence</span><strong>{display(relay.last_sequence)}</strong></div><div><span>Devices</span><strong>{display(relay.device_count, "0")}</strong></div></div><div className="relay-device-heading"><h4>Registered devices</h4><small>Firewall metadata only</small></div><div className="relay-device-list">{Array.isArray(relay.devices) && relay.devices.length ? relay.devices.map((device) => { const deviceName = device.display_name || device.device_id; return <div className="relay-device-row" key={device.device_id || device.display_name}><div className="relay-device-name"><ShieldCheck size={17} /><strong>{display(deviceName)}</strong><span className={`relay-health-dot ${statusClass(device.health)}`} />{display(device.health)}</div><div><span>Vendor / model</span><strong>{display(device.vendor)} / {display(device.model)}</strong></div><div><span>Transport</span><strong>{display(device.transport)}</strong></div><div><span>Last event</span><strong>{device.last_event_at ? new Date(device.last_event_at).toLocaleString() : "Not recorded"}</strong><small>{formatAge(device.last_event_age_seconds)}</small></div><div><span>Event type</span><strong>{display(device.last_event_type)}</strong></div><div><span>Clock confidence</span><strong>{display(device.time_confidence)}</strong></div><div><span>Drops / bytes</span><strong>{display(device.last_reported_drops, "0")} / {display(device.last_reported_dropped_bytes, "0")}</strong></div></div> }) : <p className="relay-inline-empty">No device metadata has been received yet.</p>}</div>{canManage && <div className="relay-card-actions"><button className="ops-secondary" onClick={() => setRevokeTarget(relay)} disabled={String(relay.status).toLowerCase() === "revoked"}>Revoke relay</button><button className="ops-secondary" onClick={() => setRecoveryTarget(relay)}>Authorize key recovery</button></div>}</article>)}
      {canManage && showSetup && <form className="relay-setup-card" onSubmit={generate}><div className="relay-setup-heading"><div><span className="relay-kicker">Admin controls</span><h3>Register pfSense relay</h3><p>The relay runs on an always-on Windows host in the customer network. Activation details are not written to browser storage.</p></div><ShieldCheck size={24} /></div><div className="relay-form-grid"><label>Relay name<input value={setup.relay_name} onChange={(event) => updateSetup("relay_name", event.target.value)} required placeholder="Branch firewall relay" /></label><label>Device ID<input value={setup.device_id} onChange={(event) => updateSetup("device_id", event.target.value)} required pattern="[A-Za-z0-9_.-]+" placeholder="branch-pfsense-01" /></label><label>Firewall model<input value={setup.model} onChange={(event) => updateSetup("model", event.target.value)} required placeholder="pfSense" /></label><label>pfSense source IP<input value={setup.source_address} onChange={(event) => updateSetup("source_address", event.target.value)} required placeholder="192.0.2.1" /></label><label>Relay LAN IP<input value={setup.relay_bind_host} onChange={(event) => updateSetup("relay_bind_host", event.target.value)} required placeholder="192.0.2.10" /></label><label>Relay UDP port<input type="number" min="1" max="65535" value={setup.relay_port} onChange={(event) => updateSetup("relay_port", event.target.value)} required /></label><label>Device timezone<input value={setup.timezone} onChange={(event) => updateSetup("timezone", event.target.value)} required placeholder="UTC" /></label><label>Expected events / second<input type="number" min="1" max="5000" value={setup.expected_eps} onChange={(event) => updateSetup("expected_eps", event.target.value)} required /></label></div><button type="submit" disabled={busy}><KeyRound size={16} /> {busy ? "Generating..." : "Generate relay setup"}</button>{activation && <div className="relay-activation-workflow"><div className="relay-activation"><div><span>One-time activation code</span><code>{activation.code || "Activation unavailable"}</code><small>Expires in {activation.expires ? `${Math.ceil(activation.expires / 60)} minutes` : "a limited time"}. Copy it now; it will not be shown again.</small></div>{activation.code && <button type="button" className="ops-secondary" onClick={() => navigator.clipboard.writeText(activation.code)}><Copy size={15} /> Copy code</button>}</div><div className="relay-setup-actions">{activation.packageAvailable && <button type="button" className="ops-secondary" onClick={openSetupPackage}><Download size={15} /> Download relay kit</button>}<button type="button" className="ops-secondary" onClick={downloadConfiguration} disabled={!activation.configuration}><Download size={15} /> Download configuration</button></div>{activation.packageAvailable && activation.packageSha256 && <div className="relay-hash-warning"><AlertCircle size={18} /><div><strong>Unsigned pilot package</strong><span>Windows may show Unknown publisher. Verify this SHA-256 before selecting Run anyway.</span><code>{activation.packageSha256}</code></div><button type="button" className="ops-secondary" onClick={() => navigator.clipboard.writeText(activation.packageSha256)}><Copy size={15} /> Copy hash</button></div>}<ol className="relay-install-steps"><li>Download the kit and verify its SHA-256 before extracting it.</li><li>Run the included installer as Administrator and select the downloaded configuration.</li><li>Enter the one-time activation code when the installer requests it.</li><li>In pfSense remote logging, send firewall events by UDP to {setup.relay_bind_host}:{setup.relay_port}.</li><li>Return here and refresh after the relay heartbeat arrives.</li></ol></div>}</form>}
    </>}
    {revokeTarget && <div className="relay-modal-overlay"><form className="relay-modal" onSubmit={revoke}><button type="button" className="relay-modal-close" onClick={() => setRevokeTarget(null)} aria-label="Close revoke confirmation"><X size={18} /></button><h3>Revoke relay?</h3><p>Revocation is a permanent management action for <strong>{display(revokeTarget.relay_name, revokeTarget.relay_id)}</strong>.</p><label>Reason<textarea name="reason" required maxLength="500" placeholder="Explain why this relay is being decommissioned" /></label><div><button type="button" className="ops-secondary" onClick={() => setRevokeTarget(null)}>Cancel</button><button type="submit" disabled={busy}>Confirm revoke</button></div></form></div>}
    {recoveryTarget && <div className="relay-modal-overlay"><form className="relay-modal" onSubmit={authorizeRecovery}><button type="button" className="relay-modal-close" onClick={() => setRecoveryTarget(null)} aria-label="Close key recovery authorization"><X size={18} /></button><h3>Authorize key recovery</h3><p>This high-risk action authorizes the relay host rebuild handshake. The browser never performs key recovery.</p><label>Reason<textarea name="reason" required maxLength="500" placeholder="Approved relay host rebuild" /></label><label>Authenticator code<input name="totp_code" inputMode="numeric" pattern="[0-9]{6}" maxLength="6" required placeholder="6-digit code" /></label><div><button type="button" className="ops-secondary" onClick={() => setRecoveryTarget(null)}>Cancel</button><button type="submit" disabled={busy}>Authorize recovery</button></div></form></div>}
  </section>;
}

function ArchiveView() {
  const { role } = useRole();
  const [items, setItems] = useState([]);
  const [sources, setSources] = useState([]);
  const [state, setState] = useState("loading");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [links, setLinks] = useState([]);
  const load = useCallback(async () => {
    setState("loading");
    try {
      const { data: packs } = await apiClient.get("/auth/my-packs");
      setSources(archiveSourceOptions(role, packs?.compliance_packs || []));
      const { data } = await apiClient.get(API_ROUTES.archiveRetrievals);
      setItems(data?.items || []);
      setState("ready");
    } catch {
      setState("error");
      setMessage("Archive requests are temporarily unavailable.");
    }
  }, [role]);
  useEffect(() => { load(); }, [load]);

  const request = async (event) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setBusy(true);
    setMessage("");
    try {
      await apiClient.post(API_ROUTES.archiveRetrievals, buildArchiveRetrievalPayload({
        source: form.get("source"), start: form.get("start"), end: form.get("end"), reason: form.get("reason"),
      }));
      formElement.reset();
      setMessage("Archive request submitted.");
      await load();
    } catch {
      setMessage("The archive request could not be submitted. Check the date range and selected source, then retry.");
    } finally { setBusy(false); }
  };
  const download = async (id) => {
    setBusy(true);
    setLinks([]);
    try {
      const { data } = await apiClient.post(API_ROUTES.archiveRetrievalDownloads(id));
      const next = (data?.items || []).map((item) => ({ ...item, url: safeDownloadUrl(item.url) }));
      if (!next.length || next.some((item) => !item.url)) throw new Error("No valid download links");
      setLinks(next);
      setMessage("");
    } catch {
      setMessage("Short-lived download links are not available right now. Please retry.");
    } finally { setBusy(false); }
  };

  return <section className="ops-view">
    <div className="ops-heading"><div><p className="ops-eyebrow">Historical evidence</p><h2>Archive Requests</h2></div><button className="ops-secondary" onClick={load} disabled={state === "loading"}><RefreshCw size={16} /> Refresh</button></div>
    {message && <div className="ops-notice" role="status"><AlertCircle size={16}/>{message}</div>}
    <form className="archive-form" onSubmit={request}>
      <label>Source<select name="source" required disabled={!sources.length}>{sources.length ? sources.map(([value, label]) => <option key={value} value={value}>{label}</option>) : <option value="">No authorized sources</option>}</select></label>
      <label>Start date<input type="datetime-local" name="start" required/></label>
      <label>End date<input type="datetime-local" name="end" required/></label>
      <label className="archive-reason">Reason<textarea name="reason" required minLength={8} maxLength={500}/></label>
      <button type="submit" disabled={busy || state !== "ready" || !sources.length}>{busy ? "Working..." : "Request archive retrieval"}</button>
    </form>
    {links.length > 0 && <div className="ops-notice">{links.map((item, index) => <a key={item.archive_key || index} href={item.url} target="_blank" rel="noopener noreferrer"><Download size={15}/> Download {index + 1}{item.expires_at ? ` (expires ${new Date(item.expires_at).toLocaleString()})` : ""}</a>)}</div>}
    <div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>Request</th><th>Source</th><th>Date range</th><th>Estimated size</th><th>Status</th><th>Action</th></tr></thead><tbody>
      {state === "loading" ? <tr><td colSpan="6" className="ops-empty">Loading archive requests...</td></tr> : items.length ? items.map((item) => <tr key={item.request_id}><td className="ops-code">{item.request_id}</td><td>{(item.collections || []).join(", ")}</td><td>{display(item.start_at)} - {display(item.end_at)}</td><td>{item.estimated_bytes != null ? `${item.estimated_bytes} bytes` : "Not recorded"}</td><td><span className="ops-status">{String(item.status || "Awaiting approval").replaceAll("_", " ")}</span></td><td>{item.status === "READY" ? <button onClick={() => download(item.request_id)} disabled={busy}><Download size={15}/>Get download links</button> : "-"}</td></tr>) : <tr><td colSpan="6" className="ops-empty">{state === "error" ? "Archive requests could not be loaded." : "No archive requests have been recorded."}</td></tr>}
    </tbody></table></div>
  </section>;
}

export default function OperationsViews({ mode, onDownloadAgent }) { if (mode === "fleet") return <Fleet onDownloadAgent={onDownloadAgent} />; if (mode === "relay") return <RelayView />; if (mode === "archive") return <ArchiveView />; if (mode === "offline-legacy") return <LegacyOfflineAnalysis />; return <OfflineAnalysis />; }
