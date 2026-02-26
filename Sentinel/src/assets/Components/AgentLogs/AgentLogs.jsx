import React, { useEffect, useState } from "react";
import "./AgentLogs.css";

const AgentLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAgentLogs = async () => {
    try {
      const token = localStorage.getItem("token");
      const response = await fetch("http://127.0.0.1:8000/api/v1/ingest/logs?limit=10", {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const data = await response.json();
      // Ensure we handle the response as an array
      setLogs(Array.isArray(data) ? data : []); 
      setLoading(false);
    } catch (error) {
      console.error("Error fetching agent logs:", error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgentLogs();
    const interval = setInterval(fetchAgentLogs, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="agent-logs-wrapper">
      <div className="agent-header">
        <div className="title-box">
          <h3>🖥️ Windows Agent Feed</h3>
          <span className="live-dot"></span>
          <span className="status-text">LIVE</span>
        </div>
        <button className="refresh-btn" onClick={fetchAgentLogs}>Refresh</button>
      </div>

      <div className="agent-table-container">
        <table className="agent-table">
          <thead>
            <tr>
              <th>TIME</th>
              <th>HOST</th>
              <th>TYPE</th>
              <th>EVENT ID</th>
              <th>MESSAGE</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="5" className="loading-text">Connecting to Agent...</td></tr>
            ) : logs.length === 0 ? (
              <tr><td colSpan="5" className="empty-text">No Logs Received Yet. Run agent.py</td></tr>
            ) : (
              logs.map((log) => (
                <tr key={log._id || Math.random()} className="agent-row">
                  <td className="time-col">
                    {/* 🚨 SURGICAL FIX: Mapping to ISO string from worker */}
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "N/A"}
                  </td>
                  <td className="host-col">
                    {/* 🚨 SURGICAL FIX: Mapping to 'source_ip' from worker */}
                    {log.source_ip || "Unknown"}
                  </td>
                  <td>
                    <span className="log-badge badge-blue">Windows</span>
                  </td>
                  <td className={log.event_id === 4625 ? "text-red" : "text-gray"}>
                    {/* 🚨 SURGICAL FIX: Mapping to 'event_id' from worker */}
                    {log.event_id}
                  </td>
                  <td className="msg-col" title={log.message}>
                    {/* 🚨 SURGICAL FIX: Mapping to 'message' from worker */}
                    {(log.message || "").length > 60 
                      ? log.message.substring(0, 60) + "..." 
                      : log.message || "No message content"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AgentLogs;