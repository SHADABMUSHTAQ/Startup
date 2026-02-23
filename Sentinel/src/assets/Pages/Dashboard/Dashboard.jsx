import React, { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api, threatIntel } from "../../../api";
import useWebSocket from "react-use-websocket";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// ✅ 1. NEW COMPONENT IMPORTED
import AgentLogs from "../../Components/AgentLogs/AgentLogs";
import NetworkMap from "../../Components/NetworkMap/NetworkMap"; // ✅ New Import

import {
  Shield,
  Activity,
  Lock,
  Unlock,
  FileText,
  Zap,
  BrainCircuit,
  Server,
  Users,
  Globe,
  LogOut,
  Menu,
  X,
  Download,
  Bell,
  UploadCloud,
  RefreshCw,
  Trash2,
  Eye,
  Sun,
  Moon,
  FileSpreadsheet,
  Search,
  Cpu,
  HardDrive,
  User,
  ChevronDown,
} from "lucide-react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import "./Dashboard.css";

const formatTime = (timestamp) => {
  if (!timestamp) return "N/A";
  try {
    const strTime = String(timestamp);
    return strTime.includes("T")
      ? strTime.split("T")[1].substring(0, 8)
      : strTime.substring(11, 19) || strTime;
  } catch (e) {
    return "00:00:00";
  }
};

const MetricCard = ({ title, value, icon: Icon, color }) => (
  <div className="metric-card" style={{ "--accent-color": color }}>
    <div className="metric-icon">
      <Icon size={22} />
    </div>
    <div className="metric-info">
      <h3>{value || 0}</h3>
      <p>{title}</p>
    </div>
    <div className="metric-glow" style={{ background: color }}></div>
  </div>
);

const UserMenu = ({ user, onLogout }) => {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target))
        setIsOpen(false);
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);
  return (
    <div className="user-menu-container" ref={menuRef}>
      <button className="user-btn" onClick={() => setIsOpen(!isOpen)}>
        <div className="avatar-circle">
          {user?.username ? user.username.charAt(0).toUpperCase() : "U"}
        </div>
        <div className="user-text-info">
          <span className="user-name-label">{user?.username || "User"}</span>
          <span className="user-role-label">Admin</span>
        </div>
        <ChevronDown
          size={14}
          className={`chevron ${isOpen ? "rotate" : ""}`}
        />
      </button>
      {isOpen && (
        <div className="dropdown-menu">
          <div className="dropdown-header">
            <span className="dp-name">{user?.username}</span>
            <span className="dp-email">{user?.email}</span>
          </div>
          <div className="dropdown-divider"></div>
          <button className="dropdown-item">
            <User size={14} /> My Profile
          </button>
          <button className="dropdown-item danger" onClick={onLogout}>
            <LogOut size={14} /> Sign Out
          </button>
        </div>
      )}
    </div>
  );
};

function Dashboard() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem("theme") || "dark");
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [globalQuery, setGlobalQuery] = useState("");
  const [blockedList, setBlockedList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [viewFile, setViewFile] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const navigate = useNavigate();
  const WS_URL = "ws://127.0.0.1:8000/ws/alerts";

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    const fetchUserData = async () => {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/login");
        return;
      }
      try {
        const response = await fetch("http://127.0.0.1:8000/api/v1/auth/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (response.ok) setCurrentUser(await response.json());
      } catch (e) {
        console.error(e);
      }
    };
    fetchUserData();
    fetchHistory();
    fetchBlockedList();
  }, []);

  const toggleTheme = () =>
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  const { lastJsonMessage } = useWebSocket(WS_URL, {
    shouldReconnect: () => true,
  });

  useEffect(() => {
    if (lastJsonMessage) {
      if (lastJsonMessage.type === "MITIGATION_SUCCESS") {
        setLogs((prev) =>
          prev.map((log) =>
            log.ip === lastJsonMessage.ip
              ? { ...log, status: "mitigated" }
              : log,
          ),
        );
        return;
      }
      if (lastJsonMessage.severity && !lastJsonMessage.type) {
        setLogs((prev) => {
          const exists = prev.find(
            (l) =>
              l.ip === lastJsonMessage.source_ip &&
              l.message === lastJsonMessage.title,
          );
          if (exists) return prev;
          return [
            {
              id: Date.now(),
              time: lastJsonMessage.timestamp,
              level: (lastJsonMessage.severity || "INFO").toUpperCase(),
              message: lastJsonMessage.title,
              ip: lastJsonMessage.source_ip,
              engine: lastJsonMessage.engine_source,
              status: "active",
              occurrences: 1,
            },
            ...prev,
          ];
        });
        if (lastJsonMessage.severity === "CRITICAL")
          toast.error(`🚨 ${lastJsonMessage.title}`);
      }
    }
  }, [lastJsonMessage]);

  const fetchFileDetails = async (analysisId) => {
    try {
      const token = localStorage.getItem("token");
      const res = await fetch(
        `http://127.0.0.1:8000/api/v1/upload/results/${analysisId}`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (res.ok) setSelectedFile(await res.json());
    } catch (e) {}
  };

  const fetchHistory = useCallback(async () => {
    try {
      const data = await api.getAnalyses();
      setFiles(
        Array.isArray(data)
          ? data.map((f) => ({ ...f, name: f.filename }))
          : [],
      );
    } catch (err) {}
  }, []);

  const fetchBlockedList = async () => {
    try {
      const list = await threatIntel.getBlockedList();
      setBlockedList(Array.isArray(list) ? list.map((i) => i.ip) : []);
    } catch (e) {}
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    try {
      await api.uploadLog(file);
      await fetchHistory();
      toast.success("Uploaded!");
    } catch (err) {
      toast.error("Failed");
    } finally {
      setLoading(false);
    }
  };

  const handleBan = async (ip, isBanned) => {
    try {
      isBanned
        ? await threatIntel.revokeIP(ip)
        : await threatIntel.mitigateIP(ip, "Manual Ops");
      setBlockedList((prev) =>
        isBanned ? prev.filter((b) => b !== ip) : [...prev, ip],
      );
    } catch (e) {
      toast.error("Action Failed");
    }
  };

  const handleDelete = async (analysisId) => {
    if (!window.confirm("Delete?")) return;
    try {
      const token = localStorage.getItem("token");
      await fetch(`http://127.0.0.1:8000/api/v1/upload/results/${analysisId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      setFiles((prev) =>
        prev.filter((f) => (f.analysisId || f._id) !== analysisId),
      );
    } catch (e) {}
  };

  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };

  const handleDownloadReport = () => {
    const dataToReport = logs.length > 0 ? logs : selectedFile?.findings || [];
    if (dataToReport.length === 0) {
      toast.error("No data.");
      return;
    }
    const doc = new jsPDF();
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, 210, 45, "F");
    doc.setTextColor(255);
    doc.setFontSize(24);
    doc.text("WarSOC", 14, 25);
    doc.setFontSize(10);
    doc.text("THREAT REPORT", 14, 32);
    doc.text(`Date: ${new Date().toLocaleString()}`, 195, 20, {
      align: "right",
    });
    const tableData = dataToReport.map((l) => [
      formatTime(l.time || l.timestamp),
      l.occurrences ? `x${l.occurrences}` : "x1",
      l.level || l.severity,
      l.message || l.title,
      l.engine || l.engine_source,
      l.ip || l.source_ip,
    ]);
    autoTable(doc, {
      startY: 60,
      head: [["Time", "Count", "Sev", "Alert", "Engine", "IP"]],
      body: tableData,
      theme: "grid",
      headStyles: { fillColor: [30, 41, 59] },
    });
    doc.save(`WarSOC_Report_${Date.now()}.pdf`);
  };

  const handleGlobalSearch = async (e) => {
    if (e.key === "Enter") {
      const query = globalQuery.trim();
      if (!query) return;

      setLoading(true);
      try {
        const token = localStorage.getItem("token");
        const res = await fetch(
          `http://127.0.0.1:8000/api/v1/data/search?q=${encodeURIComponent(query)}`,
          {
            headers: { Authorization: `Bearer ${token}` },
          },
        );

        if (res.ok) {
          const data = await res.json();
          if (data.results && data.results.length > 0) {
            setLogs(
              data.results.map((f, i) => ({
                id: i,
                time: f.timestamp,
                level: (f.severity || "INFO").toUpperCase(),
                message: f.message || f.title,
                ip: f.source_ip || f.ip || "N/A",
                engine: f.engine_source || "Stateless",
                status: f.status || "active",
                occurrences: f.occurrences || 1,
              })),
            );
            toast.success(`Found ${data.count} matches for "${query}"`);
          } else {
            toast.info(
              `No matching logs found for "${query}" in global database.`,
            );
          }
        }
      } catch (err) {
        toast.error("Connection Error with Backend.");
      } finally {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    if (selectedFile?.findings) {
      setLogs(
        selectedFile.findings.map((f, i) => ({
          id: i,
          time: f.timestamp,
          level: (f.severity || "INFO").toUpperCase(),
          message: f.title || f.message || "Unknown",
          ip: f.source_ip || f.ip || "N/A",
          engine: f.engine_source || "Stateless",
          status: f.status || "active",
          occurrences: f.occurrences || 1,
        })),
      );
    }
  }, [selectedFile]);

  const activeThreatsCount = logs.filter(
    (log) => log.status !== "mitigated" && !blockedList.includes(log.ip),
  ).length;
  const chartData = [
    { name: "Low", value: logs.filter((l) => l.level === "LOW").length },
    { name: "Med", value: logs.filter((l) => l.level === "MEDIUM").length },
    { name: "High", value: logs.filter((l) => l.level === "HIGH").length },
    {
      name: "Crit",
      value: logs.filter((l) => ["CRITICAL", "ALERT"].includes(l.level)).length,
    },
  ];

  return (
    <div className="siem-layout" data-theme={theme}>
      <ToastContainer
        position="bottom-right"
        theme={theme === "dark" ? "dark" : "light"}
      />
      <aside
        className={`siem-sidebar ${isMobileMenuOpen ? "mobile-open" : ""}`}
      >
        <div className="logo-container">
          <div className="logo-box">
            <Shield size={24} />
          </div>
          <h2>WarSOC</h2>
        </div>
        <nav className="nav-links">
          <button
            className={activeTab === "dashboard" ? "active" : ""}
            onClick={() => setActiveTab("dashboard")}
          >
            <Activity size={18} /> Dashboard
          </button>
          <button
            className={activeTab === "network" ? "active" : ""}
            onClick={() => setActiveTab("network")}
          >
            <Globe size={18} /> Network Map
          </button>
        </nav>
      </aside>
      <main className="siem-main">
        <header className="siem-header">
          <button
            className="menu-toggle"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            <Menu size={24} />
          </button>

          <div className="search-wrapper">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              className="global-search"
              placeholder="Search (e.g. 'faield lgoin')..."
              value={globalQuery}
              onChange={(e) => setGlobalQuery(e.target.value)}
              onKeyDown={handleGlobalSearch}
            />
          </div>

          <div className="header-actions">
            <button onClick={toggleTheme} className="icon-btn theme-toggle">
              {theme === "dark" ? <Moon size={18} /> : <Sun size={18} />}
            </button>
            <div className="live-pill">
              <div className="pulse"></div> LIVE
            </div>
            <div className="divider-v"></div>
            <UserMenu
              user={currentUser}
              onLogout={() => setShowLogoutModal(true)}
            />
          </div>
        </header>
        <div className="content-scrollable">
          <div className="dashboard-container">
            {activeTab === "dashboard" && (
              <>
                <div className="metrics-grid">
                  <MetricCard
                    title="Active Threats"
                    value={activeThreatsCount}
                    icon={Shield}
                    color="#ef4444"
                  />
                  <MetricCard
                    title="Behavioral"
                    value={logs.filter((l) => l.engine === "Stateful").length}
                    icon={BrainCircuit}
                    color="#f59e0b"
                  />
                  <MetricCard
                    title="Signature"
                    value={logs.filter((l) => l.engine === "Stateless").length}
                    icon={Zap}
                    color="#3b82f6"
                  />
                  <MetricCard
                    title="Active Bans"
                    value={blockedList.length}
                    icon={Lock}
                    color="#10b981"
                  />
                </div>

                <div className="chart-section-full">
                  <div className="chart-box">
                    <h4>Threat Volume</h4>
                    <ResponsiveContainer width="100%" height={200}>
                      <AreaChart data={chartData}>
                        <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                        <Tooltip
                          contentStyle={{
                            background: "#1e293b",
                            border: "none",
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="value"
                          stroke="#3b82f6"
                          fill="rgba(59, 130, 246, 0.2)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="chart-box">
                    <h4>Severity Mix</h4>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={chartData}
                          dataKey="value"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={5}
                        >
                          <Cell fill="#3b82f6" />
                          <Cell fill="#ef4444" />
                          <Cell fill="#f59e0b" />
                          <Cell fill="#10b981" />
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: "#1e293b",
                            border: "none",
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* ✅ 2. AGENT COMPONENT ADDED HERE (Separated Section) */}
                <div className="agent-logs-section">
                  <AgentLogs />
                </div>

                <div className="bottom-split-grid">
                  <div className="logs-table-card">
                    <div className="table-header">
                      <div className="th-left">
                        <FileText size={16} /> <span>Live Inspection</span>
                      </div>
                      <div className="th-right">
                        <input
                          type="text"
                          placeholder="Filter current view..."
                          onChange={(e) => setSearch(e.target.value)}
                        />
                        <button
                          className="btn-primary"
                          onClick={handleDownloadReport}
                        >
                          <Download size={14} /> Report
                        </button>
                      </div>
                    </div>
                    <div className="table-body">
                      {logs
                        .filter((l) =>
                          (l.message || "")
                            .toLowerCase()
                            .includes(search.toLowerCase()),
                        )
                        .map((log, i) => (
                          <div
                            key={i}
                            className={`tr ${log.status === "mitigated" ? "dimmed" : ""}`}
                          >
                            <div className="td time">
                              {formatTime(log.time)}
                            </div>
                            <div className="td sev">
                              <span className={`badge ${log.level}`}>
                                {log.level}
                              </span>
                            </div>
                            <div className="td msg">
                              <span className={`engine-badge ${log.engine}`}>
                                {log.engine || "Stateless"}
                              </span>
                              <span className="msg-text">{log.message}</span>
                              {log.occurrences > 1 && (
                                <span className="count-badge">
                                  x{log.occurrences}
                                </span>
                              )}
                              <span className="ip-tag">{log.ip}</span>
                            </div>
                            <div className="td action">
                              {log.ip !== "N/A" && (
                                <button
                                  className={`act-btn ${blockedList.includes(log.ip) ? "unblock" : "block"}`}
                                  onClick={() =>
                                    handleBan(
                                      log.ip,
                                      blockedList.includes(log.ip),
                                    )
                                  }
                                >
                                  {blockedList.includes(log.ip)
                                    ? "Unblock"
                                    : "Block"}
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                  <div className="history-panel">
                    <div className="panel-header">
                      <h4>Data Sources</h4>
                      <button onClick={fetchHistory} className="refresh-btn">
                        <RefreshCw size={14} />
                      </button>
                    </div>
                    <div className="upload-area">
                      {loading ? (
                        <div className="loader"></div>
                      ) : (
                        <UploadCloud size={32} className="up-icon" />
                      )}
                      <span>Drop logs here</span>
                      <input
                        type="file"
                        onChange={handleFileUpload}
                        disabled={loading}
                      />
                    </div>
                    <div className="history-list">
                      {files.map((f, i) => (
                        <div
                          key={i}
                          className={`history-item ${selectedFile?._id === f._id ? "active" : ""}`}
                          onClick={() =>
                            fetchFileDetails(f.analysisId || f._id)
                          }
                        >
                          <FileText size={16} className="file-icon" />
                          <div className="file-info">
                            <span className="fname">
                              {(f.name || "").substring(0, 22)}...
                            </span>
                            <span className="fdate">
                              {new Date(f.uploaded_at).toLocaleDateString()}
                            </span>
                          </div>
                          <button
                            className="del-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDelete(f.analysisId || f._id);
                            }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </>
            )}
            {activeTab === "network" && (
              <div
                className="network-tab-wrapper"
                style={{ marginTop: "20px" }}
              >
                <div className="chart-box" style={{ width: "100%" }}>
                  <div
                    className="panel-header"
                    style={{
                      marginBottom: "15px",
                      display: "flex",
                      justifyContent: "space-between",
                    }}
                  >
                    <h3>🌍 Live Threat Topology</h3>
                    <div style={{ fontSize: "0.9rem", color: "#94a3b8" }}>
                      <span style={{ color: "#ef4444" }}>● Critical</span>{" "}
                      &nbsp;
                      <span style={{ color: "#3b82f6" }}>● Normal</span> &nbsp;
                      <span style={{ color: "#10b981" }}>● Blocked</span>
                    </div>
                  </div>

                  {/* ✅ NETWORK MAP COMPONENT */}
                  <NetworkMap
                    logs={logs}
                    blockedList={blockedList}
                    onBlockIP={(ip, isBanned) => handleBan(ip, isBanned)}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
      {showLogoutModal && (
        <div className="modal-overlay">
          <div className="modal-card confirm-box">
            <h3>Sign Out?</h3>
            <div className="modal-btns">
              <button
                className="btn-cancel"
                onClick={() => setShowLogoutModal(false)}
              >
                Cancel
              </button>
              <button className="btn-danger" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </div>
        </div>
      )}
      {viewFile && (
        <div
          className="modal-overlay"
          style={{ zIndex: 10000 }}
          onClick={() => setViewFile(null)}
        >
          <div
            className="modal-card details-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <h3 className="modal-filename">{viewFile.filename}</h3>
              <button onClick={() => setViewFile(null)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <div className="modal-body scroll-custom">
              <div className="findings-list">
                {viewFile.findings?.map((f, i) => (
                  <div key={i} className="finding-card">
                    <div className="finding-content">
                      <div className="finding-top">
                        <span className={`badge ${f.severity.toLowerCase()}`}>
                          {f.severity}
                        </span>
                      </div>
                      <h5 className="finding-title">{f.title || f.type}</h5>
                      <p className="finding-summary">
                        {f.description || f.message}
                      </p>
                      <div className="meta-item">
                        <span>IP: {f.source_ip || f.ip}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
export default Dashboard;
