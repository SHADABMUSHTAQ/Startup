import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Server,
  ShieldCheck,
} from "lucide-react";

import apiClient from "../../../api/apiClient";
import { API_ROUTES } from "../../../contracts/backendContracts";
import "./ConfigurationAssessment.css";

const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;

const statusLabel = (value) => String(value || "NOT_ASSESSED").replaceAll("_", " ");

const requestMessage = (error) => {
  if (error?.response?.status === 503) return "Configuration assessment is not enabled.";
  if (error?.response?.status === 403) return "Your role cannot view configuration assessment.";
  return "Configuration assessment is temporarily unavailable.";
};

export default function ConfigurationAssessment() {
  const [summary, setSummary] = useState(null);
  const [posture, setPosture] = useState(null);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingPosture, setLoadingPosture] = useState(false);
  const [error, setError] = useState("");

  const loadSummary = useCallback(async () => {
    setLoadingSummary(true);
    setError("");
    try {
      const { data } = await apiClient.get(API_ROUTES.scaSummary);
      const endpoints = Array.isArray(data?.endpoints) ? data.endpoints : [];
      setSummary({ ...data, endpoints });
      setSelectedAgentId((current) => (
        endpoints.some((item) => item.agent_id === current)
          ? current
          : endpoints[0]?.agent_id || ""
      ));
    } catch (requestError) {
      setSummary(null);
      setPosture(null);
      setSelectedAgentId("");
      setError(requestMessage(requestError));
    } finally {
      setLoadingSummary(false);
    }
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    let cancelled = false;
    if (!selectedAgentId) {
      setPosture(null);
      return undefined;
    }
    const loadPosture = async () => {
      setLoadingPosture(true);
      setError("");
      try {
        const { data } = await apiClient.get(API_ROUTES.scaPosture(selectedAgentId));
        if (!cancelled) setPosture(data);
      } catch (requestError) {
        if (!cancelled) {
          setPosture(null);
          setError(requestMessage(requestError));
        }
      } finally {
        if (!cancelled) setLoadingPosture(false);
      }
    };
    loadPosture();
    return () => { cancelled = true; };
  }, [selectedAgentId]);

  const findings = useMemo(
    () => Array.isArray(posture?.findings) ? posture.findings : [],
    [posture],
  );

  return (
    <section className="sca-view" aria-labelledby="sca-title">
      <header className="sca-header">
        <div>
          <span className="sca-eyebrow">Endpoint hardening</span>
          <h2 id="sca-title">Configuration Assessment</h2>
        </div>
        <button
          type="button"
          className="sca-refresh"
          onClick={loadSummary}
          disabled={loadingSummary}
          title="Refresh configuration assessment"
          aria-label="Refresh configuration assessment"
        >
          <RefreshCw size={17} className={loadingSummary ? "sca-spin" : ""} />
        </button>
      </header>

      {error && <div className="sca-notice error" role="alert"><AlertTriangle size={17} />{error}</div>}

      {!error && loadingSummary && (
        <div className="sca-notice"><RefreshCw size={17} className="sca-spin" />Loading assessment...</div>
      )}

      {!loadingSummary && summary && (
        <>
          <div className="sca-metrics" aria-label="Configuration assessment summary">
            <div><span>Average score</span><strong>{number(summary.average_compliance_score).toFixed(1)}%</strong></div>
            <div><span>Assessed</span><strong>{number(summary.assessed_endpoints)} / {number(summary.total_endpoints)}</strong></div>
            <div><span>Compliant</span><strong>{number(summary.compliant_endpoints)}</strong></div>
            <div><span>At risk</span><strong>{number(summary.at_risk_endpoints)}</strong></div>
            <div><span>Stale</span><strong>{number(summary.stale_endpoints)}</strong></div>
          </div>

          {summary.endpoints.length === 0 ? (
            <div className="sca-empty"><Server size={22} />No active endpoints are available.</div>
          ) : (
            <div className="sca-endpoint-toolbar">
              <label htmlFor="sca-endpoint">Endpoint</label>
              <div className="ops-select-wrap sca-select-wrap">
                <select
                  id="sca-endpoint"
                  value={selectedAgentId}
                  onChange={(event) => setSelectedAgentId(event.target.value)}
                >
                  {summary.endpoints.map((endpoint) => (
                    <option key={endpoint.agent_id} value={endpoint.agent_id}>
                      {endpoint.agent_id} - {statusLabel(endpoint.status)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}
        </>
      )}

      {loadingPosture && <div className="sca-notice"><RefreshCw size={17} className="sca-spin" />Loading endpoint posture...</div>}

      {!loadingPosture && posture && (
        <div className="sca-posture">
          <div className="sca-posture-heading">
            <div className={`sca-status ${String(posture.status || "").toLowerCase()}`}>
              {posture.status === "COMPLIANT" ? <CheckCircle2 size={18} /> : posture.status === "STALE" ? <Clock3 size={18} /> : <AlertTriangle size={18} />}
              {statusLabel(posture.status)}
            </div>
            <div>
              <strong>{number(posture.compliance_score).toFixed(1)}%</strong>
              <span>{posture.benchmark || "Security benchmark"}</span>
            </div>
          </div>

          <dl className="sca-posture-meta">
            <div><dt>Passed</dt><dd>{number(posture.summary?.passed)}</dd></div>
            <div><dt>Failed</dt><dd>{number(posture.summary?.failed)}</dd></div>
            <div><dt>Not applicable</dt><dd>{number(posture.summary?.not_applicable)}</dd></div>
            <div><dt>Last scan</dt><dd>{posture.last_scanned_at ? new Date(posture.last_scanned_at).toLocaleString() : "Not assessed"}</dd></div>
            <div><dt>Evidence trust</dt><dd>{statusLabel(posture.assessment_trust)}</dd></div>
            <div><dt>Scan ID</dt><dd>{posture.scan_id || "Not recorded"}</dd></div>
          </dl>

          <div className="sca-findings-header">
            <h3><ShieldCheck size={18} />Failed controls</h3>
            <span>{findings.length}</span>
          </div>
          {findings.length === 0 ? (
            <div className="sca-empty compact"><CheckCircle2 size={20} />No failed controls in the current scan.</div>
          ) : (
            <div className="sca-findings">
              {findings.map((finding) => (
                <article key={finding.check_id} className="sca-finding">
                  <div className="sca-finding-title">
                    <span className={`sca-severity ${String(finding.severity || "medium").toLowerCase()}`}>{finding.severity || "MEDIUM"}</span>
                    <h4>{finding.title || finding.check_id}</h4>
                    <code>{finding.check_id}</code>
                  </div>
                  <dl>
                    <div><dt>Control</dt><dd>{finding.cis_control || "Not mapped"}</dd></div>
                    <div><dt>Reason</dt><dd>{finding.rationale || "Not provided"}</dd></div>
                    <div><dt>Remediation</dt><dd>{finding.remediation || "Not provided"}</dd></div>
                  </dl>
                </article>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
