import React, { useEffect, useState } from "react";
import "./AgentLogs.css"; // CSS file neeche hai

const AgentLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // 1. Data Fetch Karne Ka Function
  const fetchAgentLogs = async () => {
    try {
      // Backend API call
      const response = await fetch("http://127.0.0.1:8000/api/v1/data/agent/logs?limit=10");
      const data = await response.json();
      setLogs(data);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching agent logs:", error);
    }
  };

  // 2. Auto-Refresh (Live Polling)
  useEffect(() => {
    fetchAgentLogs(); // Pehli baar load karo
    const interval = setInterval(fetchAgentLogs, 2000); // Har 2 sec mein refresh
    return () => clearInterval(interval); // Cleanup
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
                <tr key={log._id} className="agent-row">
                  {/* Time Formatting */}
                  <td className="time-col">
                    {new Date(log.timestamp * 1000).toLocaleTimeString()}
                  </td>
                  
                  <td className="host-col">{log.hostname}</td>
                  
                  {/* Type Badge (Security Red, System Blue) */}
                  <td>
                    <span className={`log-badge ${log.log_type === 'Security' ? 'badge-red' : 'badge-blue'}`}>
                      {log.log_type}
                    </span>
                  </td>

                  {/* Event ID (4625 = Brute Force = Red) */}
                  <td className={log.event_id === "4625" ? "text-red" : "text-gray"}>
                    {log.event_id}
                  </td>

                  {/* Message Truncated */}
                  <td className="msg-col" title={log.raw_message}>
                    {log.raw_message.length > 60 
                      ? log.raw_message.substring(0, 60) + "..." 
                      : log.raw_message}
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