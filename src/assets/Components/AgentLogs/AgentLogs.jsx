import React from "react";
import "./AgentLogs.css";

const AgentLogs = ({ logs = [] }) => {
  return (
    <div className="agent-logs-wrapper">
      <div className="agent-header">
        <div className="title-box">
          <h3>🖥️ Omni Agent Feed</h3>
          <span className="live-dot"></span>
          <span className="status-text">LIVE STREAM</span>
        </div>
      </div>

      <div
        className="agent-table-container"
        style={{ maxHeight: "250px", overflowY: "auto", overflowX: "hidden" }}
      >
        <table
          className="agent-table"
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          <thead
            style={{
              position: "sticky",
              top: 0,
              background: "var(--bg-dark)",
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
              <th style={{ padding: "12px" }}>MESSAGE</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan="5" className="empty-text">
                  No Logs Received Yet. Run agent.py
                </td>
              </tr>
            ) : (
              logs.slice(0, 50).map((log) => {
                // 🚀 1. STRICTLY 2 TYPES (Web or Windows ONLY)
                const msgLower = (log.message || "").toLowerCase();
                let rawEventId =
                  log.raw_data?.event_id !== undefined
                    ? log.raw_data.event_id
                    : log.event_id;

                let isWeb = false;

                // 🌐 Web Detection Rule
                if (
                  rawEventId === 80 ||
                  msgLower.includes("get /") ||
                  msgLower.includes("post /") ||
                  msgLower.includes("http")
                ) {
                  isWeb = true;
                }

                // 🧠 SMART EVENT ID EXTRACTOR (Never show N/A or Dash again!)
                let displayEventId = rawEventId;

                if (
                  !displayEventId ||
                  displayEventId === 0 ||
                  displayEventId === "N/A" ||
                  displayEventId === "-"
                ) {
                  // Try to extract known Windows IDs from the message text
                  const match = (log.message || "").match(
                    /\b(4624|4625|4720|4726|1102)\b/,
                  );
                  if (match) {
                    displayEventId = match[0]; // Extra ID directly from text!
                  } else if (isWeb) {
                    displayEventId = 80; // Force 80 for Web
                  } else {
                    displayEventId = "ALERT"; // For custom rules like Ransomware or Xmrig
                  }
                }

                // 🎨 2. ASSIGN STRICT BADGES
                const engine = isWeb ? "WEB-WAF" : "WINDOWS";
                const badgeStyle = isWeb
                  ? {
                      background: "rgba(139, 92, 246, 0.15)",
                      color: "#c4b5fd",
                      border: "1px solid rgba(139, 92, 246, 0.3)",
                    }
                  : {
                      background: "rgba(59, 130, 246, 0.15)",
                      color: "#3b82f6",
                      border: "1px solid rgba(59, 130, 246, 0.3)",
                    };

                return (
                  <tr
                    key={log.id || Math.random()}
                    style={{
                      borderBottom: "1px solid rgba(148, 163, 184, 0.08)",
                      transition: "0.2s",
                    }}
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
                      {log.time
                        ? new Date(log.time).toLocaleTimeString()
                        : "N/A"}
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
                      {log.ip || "Unknown"}
                    </td>

                    {/* Engine Badge (Strictly Web or Windows) */}
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
                        {engine}
                      </span>
                    </td>

                    {/* Event ID (Clean Number or ALERT) */}
                    {/* Event ID (Clean Number or Pro ALERT Badge) */}
                    <td
                      style={{
                        padding: "12px",
                        fontSize: "13px",
                        fontWeight: "600",
                      }}
                    >
                      {displayEventId === "ALERT" ? (
                        <span
                          style={{
                            background: "rgba(239, 68, 68, 0.15)",
                            color: "#ef4444",
                            border: "1px solid rgba(239, 68, 68, 0.3)",
                            padding: "4px 8px",
                            borderRadius: "6px",
                            fontSize: "10px",
                            fontWeight: "800",
                            letterSpacing: "1px",
                          }}
                        >
                          ALERT
                        </span>
                      ) : (
                        <span
                          style={{
                            color:
                              displayEventId == 4625 ||
                              displayEventId == 1102 ||
                              displayEventId == 80
                                ? "#ef4444"
                                : "var(--text-sub)",
                          }}
                        >
                          {displayEventId}
                        </span>
                      )}
                    </td>

                    {/* Message */}
                    <td
                      style={{
                        padding: "12px",
                        fontSize: "13px",
                        color: "var(--text-main)",
                        maxWidth: "250px",
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
    </div>
  );
};

export default AgentLogs;
