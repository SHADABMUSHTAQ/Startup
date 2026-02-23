import React, { useState, useEffect } from "react";
import { Server, Shield, AlertTriangle, Lock, Globe } from "lucide-react";
import "./NetworkMap.css";

const NetworkMap = ({ logs, blockedList, onBlockIP }) => {
  const [nodes, setNodes] = useState([]);
  const [hoveredNode, setHoveredNode] = useState(null);
  
  // Canvas Dimensions
  const width = 800;
  const height = 600;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = 220; // Circle ka size

  useEffect(() => {
    // 1. Unique IPs nikalna (Deduplication)
    const uniqueIPs = {};
    
    logs.forEach(log => {
      const ip = log.ip || log.source_ip;
      if (!ip || ip === "N/A") return;

      if (!uniqueIPs[ip]) {
        uniqueIPs[ip] = {
          ip: ip,
          count: 0,
          severity: "LOW",
          latestMsg: "",
          isBlocked: blockedList.includes(ip)
        };
      }
      uniqueIPs[ip].count += (log.occurrences || 1);
      uniqueIPs[ip].latestMsg = log.message || log.title;
      if (log.level === "CRITICAL" || log.level === "HIGH") uniqueIPs[ip].severity = "CRITICAL";
    });

    // 2. Nodes ko Circle mein arrange karna (Maths)
    const ipArray = Object.values(uniqueIPs);
    const totalNodes = ipArray.length;
    
    const calculatedNodes = ipArray.map((node, index) => {
      const angle = (index / totalNodes) * 2 * Math.PI; // Circle Formula
      return {
        ...node,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });

    setNodes(calculatedNodes);
  }, [logs, blockedList]);

  return (
    <div className="network-container" style={{ width: '100%', height: '600px' }}>
      <div className="network-grid-bg"></div>

      {/* SVG Lines Layer */}
      <svg className="connections-layer" width="100%" height="100%" viewBox={`0 0 ${width} ${height}`}>
        {nodes.map((node, i) => (
          <line
            key={i}
            x1={centerX}
            y1={centerY}
            x2={node.x}
            y2={node.y}
            className={`connection-line ${node.severity === 'CRITICAL' ? 'critical' : ''} ${node.isBlocked ? 'blocked' : ''}`}
          />
        ))}
      </svg>

      {/* CENTRAL SERVER NODE */}
      <div className="node server" style={{ left: '50%', top: '50%' }}>
        <div className="icon-box">
          <Server size={32} color="white" />
        </div>
        <div className="node-label">WarSOC Server</div>
      </div>

      {/* ATTACKER NODES */}
      {nodes.map((node, i) => (
        <div
          key={i}
          className={`node threat ${node.isBlocked ? 'blocked' : ''}`}
          style={{ left: node.x, top: node.y }}
          onMouseEnter={() => setHoveredNode(node)}
          onMouseLeave={() => setHoveredNode(null)}
          onClick={() => onBlockIP(node.ip, node.isBlocked)}
        >
          <div className="icon-box">
            {node.isBlocked ? <Lock size={20} color="#10b981" /> : <Globe size={20} color={node.severity === "CRITICAL" ? "#ef4444" : "#3b82f6"} />}
          </div>
          <div className="node-label">{node.ip}</div>
        </div>
      ))}

      {/* HOVER TOOLTIP */}
      {hoveredNode && (
        <div 
          className="map-tooltip" 
          style={{ left: hoveredNode.x + 20, top: hoveredNode.y - 20 }}
        >
          <div className="tooltip-header">{hoveredNode.ip}</div>
          <div className="tooltip-row"><span>Attacks:</span> <span className="tooltip-val">{hoveredNode.count}</span></div>
          <div className="tooltip-row"><span>Severity:</span> <span className="tooltip-val" style={{color: hoveredNode.severity === 'CRITICAL' ? '#ef4444' : '#cbd5e1'}}>{hoveredNode.severity}</span></div>
          <div className="tooltip-row"><span>Last:</span> <span className="tooltip-val">{hoveredNode.latestMsg.substring(0, 15)}...</span></div>
          <div className="tooltip-row" style={{marginTop:'5px', color: hoveredNode.isBlocked ? '#10b981' : '#f59e0b'}}>
            {hoveredNode.isBlocked ? "● BLOCKED" : "● ACTIVE THREAT"}
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkMap;