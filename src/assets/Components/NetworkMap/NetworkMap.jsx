import React, { useMemo, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import { Server, ShieldAlert, Lock, Activity, Ban } from "lucide-react";
import "./NetworkMap.css";

const NetworkMap = ({ logs = [], blockedList = [], onBlockIP }) => {
  const [selectedNode, setSelectedNode] = useState(null);

  // 🧠 AI Mapping Logic: Convert logs into Cytoscape Nodes & Edges
  const elements = useMemo(() => {
    const els = [];
    const ipMap = new Map();

    // 1. Central Core Node (Your WarSOC Server / Internal Network)
    els.push({
      data: { id: "core", label: "WarSOC Gateway", type: "internal" },
    });

    // 2. Process Logs to extract unique attacker IPs
    logs.forEach((log) => {
      const ip = log.ip || log.source_ip;
      if (!ip || ip === "N/A" || ip === "0.0.0.0") return;

      if (!ipMap.has(ip)) {
        ipMap.set(ip, {
          ip: ip,
          count: log.occurrences || 1,
          highestSev: log.level,
          lastMsg: log.message,
          engine: log.engine,
        });
      } else {
        const existing = ipMap.get(ip);
        existing.count += log.occurrences || 1;
        // Upgrade severity if needed
        if (log.level === "CRITICAL") existing.highestSev = "CRITICAL";
        else if (log.level === "HIGH" && existing.highestSev !== "CRITICAL")
          existing.highestSev = "HIGH";
      }
    });

    // 3. Create Nodes & Edges for each Attacker IP
    ipMap.forEach((data, ip) => {
      const isBlocked = blockedList.includes(ip);
      
      // Determine Node Color/Class based on severity and block status
      let nodeClass = "normal";
      if (isBlocked) nodeClass = "blocked";
      else if (data.highestSev === "CRITICAL") nodeClass = "critical";
      else if (data.highestSev === "HIGH") nodeClass = "high";

      // Add Attacker Node
      els.push({
        data: {
          id: ip,
          label: ip,
          type: "attacker",
          isBlocked: isBlocked,
          details: data,
        },
        classes: nodeClass,
      });

      // Add Edge (Line) connecting Attacker to Core
      els.push({
        data: {
          id: `edge-${ip}-core`,
          source: ip,
          target: "core",
        },
        classes: nodeClass, // Edge matches node color
      });
    });

    return els;
  }, [logs, blockedList]);

  // 🎨 Professional Styling for Graph
  const stylesheet = [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: "#94a3b8",
        "font-size": "10px",
        "text-valign": "bottom",
        "text-margin-y": "5px",
        "background-color": "#334155",
        "border-width": 2,
        "border-color": "#475569",
      },
    },
    // Core Server Node
    {
      selector: 'node[type="internal"]',
      style: {
        "background-color": "#3b82f6",
        "border-color": "#60a5fa",
        width: "50px",
        height: "50px",
        shape: "hexagon",
        "text-valign": "bottom",
        color: "#fff",
        "font-weight": "bold",
        "font-size": "12px",
      },
    },
    // Critical Threat Node (Red Pulse)
    {
      selector: ".critical",
      style: {
        "background-color": "#ef4444",
        "border-color": "#f87171",
        "line-color": "#ef4444",
        "target-arrow-color": "#ef4444",
      },
    },
    // High Threat Node (Orange)
    {
      selector: ".high",
      style: {
        "background-color": "#f59e0b",
        "border-color": "#fbbf24",
        "line-color": "#f59e0b",
        "target-arrow-color": "#f59e0b",
      },
    },
    // Blocked/Mitigated Node (Green Lock)
    {
      selector: ".blocked",
      style: {
        "background-color": "#10b981",
        "border-color": "#34d399",
        "line-color": "#10b981",
        "target-arrow-color": "#10b981",
        "line-style": "dashed", // Dashed line for blocked connection
        opacity: 0.6,
      },
    },
    // Edges (Lines)
    {
      selector: "edge",
      style: {
        width: 2,
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        opacity: 0.7,
      },
    },
  ];

  return (
    <div className="network-map-container">
      {/* 🌐 CYTOSCAPE CANVAS */}
      <div className="cy-wrapper">
        <div className="cy-overlay-text">LIVE TOPOLOGY VIEW</div>
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet}
          layout={{ name: "cose", idealEdgeLength: 100, nodeRepulsion: 400000 }} // Auto-organize layout
          className="cy-canvas"
          minZoom={0.5}
          maxZoom={3}
          cy={(cy) => {
            // Interactive Click Event
            cy.on("tap", "node", (evt) => {
              const nodeData = evt.target.data();
              if (nodeData.type === "attacker") {
                setSelectedNode(nodeData);
              } else {
                setSelectedNode(null);
              }
            });
            // Click outside to clear
            cy.on("tap", (evt) => {
              if (evt.target === cy) setSelectedNode(null);
            });
          }}
        />
      </div>

      {/* 📊 NODE DETAILS SIDEBAR */}
      <div className="node-details-panel">
        {selectedNode ? (
          <>
            <div className="nd-header">
              <div className={`nd-icon ${selectedNode.isBlocked ? "green" : "red"}`}>
                {selectedNode.isBlocked ? <Lock size={20} /> : <ShieldAlert size={20} />}
              </div>
              <div className="nd-title">
                <h3>{selectedNode.label}</h3>
                <p>{selectedNode.isBlocked ? "Access Revoked" : "Active Threat Source"}</p>
              </div>
            </div>

            <div className="nd-stats">
              <div className="stat-row">
                <span>Threat Level:</span>
                <span className={`badge ${selectedNode.details.highestSev.toLowerCase()}`}>
                  {selectedNode.details.highestSev}
                </span>
              </div>
              <div className="stat-row">
                <span>Detection Engine:</span>
                <span className="stat-val">{selectedNode.details.engine || "Multi-Vector"}</span>
              </div>
              <div className="stat-row">
                <span>Event Count:</span>
                <span className="stat-val">x{selectedNode.details.count}</span>
              </div>
            </div>

            {/* 🚀 PRO FEATURE: Threat Kill-Chain Timeline */}
            <div className="threat-timeline-container" style={{ marginTop: '20px', flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-sub)', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Attack History (Kill Chain)
              </div>
              
              <div className="timeline-scroll" style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px', paddingRight: '5px' }}>
                
                {/* 🧠 Automatically filter all logs for this specific IP */}
                {logs
                  .filter(l => (l.ip || l.source_ip) === selectedNode.id)
                  .map((log, idx) => (
                  <div key={idx} style={{ 
                    background: 'rgba(15, 23, 42, 0.4)', 
                    border: '1px solid rgba(148, 163, 184, 0.1)', 
                    borderLeft: `3px solid ${log.level === 'CRITICAL' ? '#ef4444' : log.level === 'HIGH' ? '#f59e0b' : '#3b82f6'}`, 
                    padding: '10px 12px', 
                    borderRadius: '6px' 
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      
                      {/* Dynamic Engine Badge (Web vs Windows) */}
                      <span style={{ 
                        fontSize: '9px', fontWeight: 'bold', padding: '2px 6px', borderRadius: '4px', textTransform: 'uppercase',
                        background: (log.engine || '').includes('WEB') ? 'rgba(139, 92, 246, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                        color: (log.engine || '').includes('WEB') ? '#c4b5fd' : '#a3e635',
                        border: `1px solid ${(log.engine || '').includes('WEB') ? 'rgba(139, 92, 246, 0.3)' : 'rgba(59, 130, 246, 0.3)'}`
                      }}>
                        {log.engine || 'Agent'}
                      </span>
                      
                      <span style={{ fontSize: '10px', color: '#64748b', fontFamily: 'monospace' }}>
                        {log.time ? new Date(log.time).toLocaleTimeString() : 'N/A'}
                      </span>
                      
                    </div>
                    
                    <div style={{ fontSize: '11.5px', color: '#e2e8f0', lineHeight: '1.4', wordBreak: 'break-word', display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }} title={log.message}>
                      {log.message}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <button 
              className={`btn-primary ${selectedNode.isBlocked ? "" : "danger"}`} 
              style={{ marginTop: "15px" }}
              onClick={() => onBlockIP(selectedNode.id, selectedNode.isBlocked)}
            >
              {selectedNode.isBlocked ? (
                <><Activity size={14} /> Unblock Target</>
              ) : (
                <><Ban size={14} /> Isolate & Block IP</>
              )}
            </button>
          </>
        ) : (
          <div className="empty-panel">
            <Server size={48} opacity={0.2} />
            <p>Select a node on the map to view forensic details and mitigation controls.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkMap;