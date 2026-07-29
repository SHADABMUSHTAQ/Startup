import React, { useMemo, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import { Activity, Ban, Lock, Monitor, Server, ShieldAlert } from "lucide-react";
import "./NetworkMap.css";

const severityRank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const NetworkMap = ({ logs = [], blockedList = [], canManage = false, onBlockIP }) => {
  const [selectedNode, setSelectedNode] = useState(null);

  const { elements, nodeLogs } = useMemo(() => {
    const graphElements = [
      { data: { id: "core", label: "WarSOC", type: "internal" } },
    ];
    const nodes = new Map();
    const eventsByNode = new Map();

    logs.forEach((log) => {
      const context = log.context || {};
      const source = context.source_address || log.ip;
      const endpoint = context.endpoint || log.host;
      const isExternalSource = log.bannable === true && source && source !== "N/A";
      const nodeId = isExternalSource
        ? `source:${source}`
        : endpoint && endpoint !== "Unknown endpoint"
          ? `endpoint:${endpoint}`
          : source && source !== "N/A"
            ? `observed:${source}`
            : null;
      if (!nodeId) return;

      const nodeType = isExternalSource ? "external_source" : "endpoint";
      const label = isExternalSource ? source : endpoint || source;
      const level = String(log.level || "MEDIUM").toUpperCase();
      const count = Number(log.occurrences || 1);
      const existing = nodes.get(nodeId);
      if (!existing) {
        nodes.set(nodeId, {
          id: nodeId,
          label,
          type: nodeType,
          address: source,
          endpoint,
          count,
          highestSev: level,
          engine: log.engine,
          bannable: isExternalSource,
          isBlocked: isExternalSource && blockedList.includes(source),
        });
      } else {
        existing.count += count;
        if ((severityRank[level] || 0) > (severityRank[existing.highestSev] || 0)) {
          existing.highestSev = level;
        }
      }
      eventsByNode.set(nodeId, [...(eventsByNode.get(nodeId) || []), log]);
    });

    nodes.forEach((node) => {
      let nodeClass = node.type === "endpoint" ? "endpoint" : "normal";
      if (node.isBlocked) nodeClass = "blocked";
      else if (node.highestSev === "CRITICAL") nodeClass = "critical";
      else if (node.highestSev === "HIGH") nodeClass = "high";

      graphElements.push({
        data: { ...node, details: node },
        classes: nodeClass,
      });
      graphElements.push({
        data: {
          id: `edge-${node.id}-core`,
          source: node.id,
          target: "core",
        },
        classes: nodeClass,
      });
    });

    return { elements: graphElements, nodeLogs: eventsByNode };
  }, [logs, blockedList]);

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
    {
      selector: 'node[type="internal"]',
      style: {
        "background-color": "#3b82f6",
        "border-color": "#60a5fa",
        width: "50px",
        height: "50px",
        shape: "hexagon",
        color: "#fff",
        "font-weight": "bold",
        "font-size": "12px",
      },
    },
    {
      selector: 'node[type="endpoint"]',
      style: {
        shape: "round-rectangle",
        "background-color": "#0f766e",
        "border-color": "#2dd4bf",
      },
    },
    {
      selector: ".critical",
      style: {
        "background-color": "#ef4444",
        "border-color": "#f87171",
        "line-color": "#ef4444",
        "target-arrow-color": "#ef4444",
      },
    },
    {
      selector: ".high",
      style: {
        "background-color": "#f59e0b",
        "border-color": "#fbbf24",
        "line-color": "#f59e0b",
        "target-arrow-color": "#f59e0b",
      },
    },
    {
      selector: ".blocked",
      style: {
        "background-color": "#10b981",
        "border-color": "#34d399",
        "line-color": "#10b981",
        "target-arrow-color": "#10b981",
        "line-style": "dashed",
        opacity: 0.65,
      },
    },
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

  const relatedEvents = selectedNode ? nodeLogs.get(selectedNode.id) || [] : [];
  const selectedIsExternal = selectedNode?.type === "external_source";

  return (
    <div className="network-map-container">
      <div className="cy-wrapper">
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet}
          layout={{ name: "cose", idealEdgeLength: 100, nodeRepulsion: 400000 }}
          className="cy-canvas"
          minZoom={0.5}
          maxZoom={3}
          cy={(cy) => {
            cy.off("tap", "node");
            cy.off("tap");
            cy.on("tap", "node", (event) => {
              const nodeData = event.target.data();
              setSelectedNode(nodeData.type === "internal" ? null : nodeData);
            });
            cy.on("tap", (event) => {
              if (event.target === cy) setSelectedNode(null);
            });
          }}
        />
      </div>

      <div className="node-details-panel">
        {selectedNode ? (
          <>
            <div className="nd-header">
              <div className={`nd-icon ${selectedNode.isBlocked ? "green" : selectedIsExternal ? "red" : ""}`}>
                {selectedNode.isBlocked ? <Lock size={20} /> : selectedIsExternal ? <ShieldAlert size={20} /> : <Monitor size={20} />}
              </div>
              <div className="nd-title">
                <h3>{selectedNode.label}</h3>
                <p>
                  {selectedNode.isBlocked
                    ? "Blocked external source"
                    : selectedIsExternal
                      ? "External source observed"
                      : "Monitored endpoint"}
                </p>
              </div>
            </div>

            <div className="nd-stats">
              <div className="stat-row">
                <span>Highest severity:</span>
                <span className={`badge ${String(selectedNode.details.highestSev || "MEDIUM").toLowerCase()}`}>
                  {selectedNode.details.highestSev || "MEDIUM"}
                </span>
              </div>
              <div className="stat-row">
                <span>Detection engine:</span>
                <span className="stat-val">{selectedNode.details.engine || "SIEM"}</span>
              </div>
              <div className="stat-row">
                <span>Occurrences:</span>
                <span className="stat-val">x{selectedNode.details.count}</span>
              </div>
            </div>

            <div className="threat-timeline-container">
              <div className="timeline-title">
                Related detections
              </div>
              <div className="timeline-scroll">
                {relatedEvents.map((log, index) => (
                  <div
                    key={log.id || index}
                    className={`timeline-event ${log.level === "CRITICAL" ? "critical" : log.level === "HIGH" ? "high" : ""}`}
                  >
                    <div className="timeline-event-meta">
                      <span>{log.engine || "SIEM"}</span>
                      <time>
                        {log.time ? new Date(log.time).toLocaleTimeString() : "N/A"}
                      </time>
                    </div>
                    <div className="timeline-event-message" title={log.message}>
                      {log.message}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {canManage && selectedNode.bannable && (
              <button
                className={`btn-primary ${selectedNode.isBlocked ? "" : "danger"}`}
                style={{ marginTop: "15px" }}
                onClick={() => onBlockIP(selectedNode.address, selectedNode.isBlocked)}
              >
                {selectedNode.isBlocked ? (
                  <><Activity size={14} /> Unblock source</>
                ) : (
                  <><Ban size={14} /> Block source</>
                )}
              </button>
            )}
          </>
        ) : (
          <div className="empty-panel">
            <div className="radar-icon-wrapper"><Server size={36} /></div>
            <p>Select an endpoint or verified external source to inspect related detections.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkMap;
