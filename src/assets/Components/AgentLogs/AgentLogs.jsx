import React, { useState, useEffect } from "react";
import "./AgentLogs.css";

const AgentLogs = ({ logs = [] }) => {
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Close fullscreen on Escape key
  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === "Escape" && isFullscreen) setIsFullscreen(false);
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isFullscreen]);

  // Lock body scroll when fullscreen
  useEffect(() => {
    document.body.style.overflow = isFullscreen ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [isFullscreen]);

  /* ── Shared table renderer ── */
  const renderTable = (maxHeight) => (
    <div
      className="agent-table-container"
      style={{ maxHeight, overflowY: "auto", overflowX: "hidden" }}
    >
      <table
        className="agent-table"
        style={{ width: "100%", borderCollapse: "collapse" }}
      >
        <thead
          style={{
            position: "sticky",
            top: 0,
            background: isFullscreen ? "#0d1117" : "var(--bg-dark)",
            zIndex: 10,
          }}
        >
          <tr
            style={{
              textAlign: "left",
              color: "var(--text-sub)",
              fontSize: "12px",
              borderBottom: "1px solid rgba(148, 163, 184, 0.1)",
            }}
          >
            <th style={{ padding: "12px", width: "110px" }}>TIME</th>
            <th style={{ padding: "12px", width: "140px" }}>HOST</th>
            <th style={{ padding: "12px", width: "120px" }}>TYPE</th>
            <th style={{ padding: "12px", width: "100px" }}>EVENT ID</th>
            <th style={{ padding: "12px", width: "80px" }}>COUNT</th>
            <th style={{ padding: "12px" }}>MESSAGE</th>
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td colSpan="6" className="empty-text">
                No endpoint telemetry received yet.
              </td>
            </tr>
          ) : (
            logs.slice(0, 50).map((log, i) => {
              const rawEventId =
                log.raw_data?.event_id !== undefined
                  ? log.raw_data.event_id
                  : (log.event_id ?? log.eventId);
              const displayEventId = rawEventId || "Not recorded";
              const sourceType = log.sourceType || log.source_type || log.engine || "Not recorded";
              const badgeStyle = { background: "rgba(59, 130, 246, 0.15)", color: "#3b82f6", border: "1px solid rgba(59, 130, 246, 0.3)" };

              return (
                <tr
                  key={log.id || i}
                  style={{
                    borderBottom: "1px solid rgba(148, 163, 184, 0.08)",
                    transition: "background 0.15s",
                  }}
                  className="agent-row"
                >
                  {/* Time */}
                  <td
                    style={{
                      padding: "12px",
                      fontFamily: "monospace",
                      fontSize: "12.5px",
                      color: "var(--text-sub)",
                    }}
                  >
                    {log.time ? new Date(log.time).toLocaleTimeString() : "N/A"}
                  </td>

                  {/* Host IP */}
                  <td
                    style={{
                      padding: "12px",
                      fontSize: "13px",
                      fontWeight: "600",
                      color: "var(--text-main)",
                    }}
                  >
                    {log.host || log.ip || "Unknown endpoint"}
                  </td>

                  {/* Engine Badge */}
                  <td style={{ padding: "12px" }}>
                    <span
                      style={{
                        ...badgeStyle,
                        padding: "4px 8px",
                        borderRadius: "6px",
                        fontSize: "10px",
                        fontWeight: "700",
                        letterSpacing: "0.5px",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {sourceType}
                    </span>
                  </td>

                  {/* Event ID */}
                  <td style={{ padding: "12px", fontSize: "13px", fontWeight: "600" }}>
                    <span style={{ color: "var(--text-sub)" }}>{displayEventId}</span>
                  </td>

                  {/* Same-minute occurrence quantity */}
                  <td style={{ padding: "12px" }}>
                    <span className="agent-occurrence-count">
                      x{log.occurrences || 1}
                    </span>
                  </td>

                  {/* Message */}
                  <td
                    style={{
                      padding: "12px",
                      fontSize: "13px",
                      color: "var(--text-main)",
                      maxWidth: isFullscreen ? "none" : "250px",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={log.message}
                  >
                    {log.message || "No message content"}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );

  /* ── Fullscreen overlay ── */
  if (isFullscreen) {
    return (
      <div className="agent-fullscreen-overlay">
        <div className="agent-fullscreen-inner">
          {/* Fullscreen Header */}
          <div className="agent-header" style={{ marginBottom: 0, borderBottom: "1px solid rgba(148,163,184,0.15)", paddingBottom: 14 }}>
            <div className="title-box">
              <h3>Endpoint Telemetry Stream</h3>
              <span className="live-dot"></span>
              <span className="status-text">LIVE STREAM</span>
              <span className="agent-log-count">{logs.length} entries</span>
            </div>
            <button
              className="fullscreen-btn fullscreen-btn--active"
              onClick={() => setIsFullscreen(false)}
              title="Minimize — press Esc to close"
              aria-label="Minimize logs"
            >
              {/* Minimize icon */}
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="4 14 10 14 10 20"/>
                <polyline points="20 10 14 10 14 4"/>
                <line x1="10" y1="14" x2="3" y2="21"/>
                <line x1="21" y1="3" x2="14" y2="10"/>
              </svg>
              <span className="fullscreen-btn-label">Minimize</span>
            </button>
          </div>

          {/* Full table — takes remaining height */}
          <div style={{ flex: 1, overflowY: "auto", marginTop: 8 }}>
            {renderTable("100%")}
          </div>
        </div>
      </div>
    );
  }

  /* ── Normal (inline) view ── */
  return (
    <div className="agent-logs-wrapper">
      <div className="agent-header">
        <div className="title-box">
          <h3>Endpoint Telemetry Stream</h3>
          <span className="live-dot"></span>
          <span className="status-text">LIVE STREAM</span>
        </div>
        <button
          className="fullscreen-btn"
          onClick={() => setIsFullscreen(true)}
          title="Expand to fullscreen"
          aria-label="Expand logs fullscreen"
        >
          {/* Expand icon */}
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="15 3 21 3 21 9"/>
            <polyline points="9 21 3 21 3 15"/>
            <line x1="21" y1="3" x2="14" y2="10"/>
            <line x1="3" y1="21" x2="10" y2="14"/>
          </svg>
          <span className="fullscreen-btn-label">Expand</span>
        </button>
      </div>

      {renderTable("250px")}
    </div>
  );
};

export default AgentLogs;
