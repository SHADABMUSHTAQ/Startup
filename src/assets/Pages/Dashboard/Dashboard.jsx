import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  useMemo,
} from "react";
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
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import AgentLogs from "../../Components/AgentLogs/AgentLogs";
import NetworkMap from "../../Components/NetworkMap/NetworkMap";

import {
  Shield,
  Activity,
  Lock,
  BrainCircuit,
  Zap,
  FileText,
  Globe,
  LogOut,
  Menu,
  X,
  Download,
  UploadCloud,
  RefreshCw,
  Trash2,
  Search,
  User,
  ChevronDown,
  AlertTriangle,
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

// 🚀 PRO UPGRADE: Metric Card with Trend Arrows & Glow
const MetricCard = ({
  title,
  value,
  icon: Icon,
  color,
  trend,
  trendUp,
  glow,
}) => (
  <div
    className={`metric-card ${glow ? "glow-danger" : ""}`}
    style={{ "--accent-color": color }}
  >
    <div className="metric-icon">
      <Icon size={22} />
    </div>
    <div className="metric-info">
      <h3>{value || 0}</h3>
      <p>{title}</p>
    </div>
    {trend && (
      <div
        className={`trend-badge ${trendUp ? "trend-up" : "trend-down"}`}
        style={{
          position: "absolute",
          top: "24px",
          right: "24px",
          fontSize: "11px",
          fontWeight: "700",
          padding: "4px 8px",
          borderRadius: "20px",
          background: trendUp
            ? "rgba(239, 68, 68, 0.15)"
            : "rgba(16, 185, 129, 0.15)",
          color: trendUp ? "#ef4444" : "#10b981",
        }}
      >
        {trendUp ? "↑" : "↓"} {trend}
      </div>
    )}
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
  const [fileToDelete, setFileToDelete] = useState(null);
  const [theme, setTheme] = useState(localStorage.getItem("theme") || "dark");
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");

  const [globalQuery, setGlobalQuery] = useState("");
  const [timeFilter, setTimeFilter] = useState("");

  const [blockedList, setBlockedList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [viewFile, setViewFile] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);

  // 🚀 LIVE MODE TRACKERS
  const [isLiveMode, setIsLiveMode] = useState(true);
  const isLiveModeRef = useRef(isLiveMode);

  useEffect(() => {
    isLiveModeRef.current = isLiveMode;
  }, [isLiveMode]);

  const navigate = useNavigate();
  const token = localStorage.getItem("token");
  const WS_URL = token ? `ws://127.0.0.1:8000/ws/alerts?token=${token}` : null;

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  const fetchLiveLogs = useCallback(async () => {
    try {
      if (!isLiveModeRef.current) return;
      const response = await api.getLiveLogs();
      if (!isLiveModeRef.current) return;

      if (
        response &&
        response.status === "success" &&
        Array.isArray(response.data)
      ) {
        const groupedMap = new Map();

        response.data.forEach((l, i) => {
          const ip = l.source_ip || l.ip || "N/A";
          const rawMessage = l.message || l.title || "Unknown Event";
          const msgLower = rawMessage.toLowerCase();
          const eventId =
            l.event_id || (l.raw_data && l.raw_data.event_id) || 0;

          let smartSeverity = (l.severity || "INFO").toUpperCase();
          let smartEngine = l.engine_source || "Agent";

          if (
            eventId === 80 ||
            msgLower.includes("get /") ||
            msgLower.includes("post /")
          ) {
            smartEngine = "WEB-WAF";
            if (
              msgLower.includes("union select") ||
              msgLower.includes("xss") ||
              msgLower.includes("<script>") ||
              msgLower.includes("/etc/passwd")
            ) {
              smartSeverity = "CRITICAL";
            } else if (
              msgLower.includes("failed") ||
              msgLower.includes("unauthorized") ||
              msgLower.includes("403") ||
              msgLower.includes("401")
            ) {
              smartSeverity = "HIGH";
            } else {
              smartSeverity = "MEDIUM";
            }
          } else if (eventId === 4625) {
            smartSeverity = "HIGH";
            smartEngine = "WINDOWS-SEC";
          } else if (eventId === 1102) {
            smartSeverity = "CRITICAL";
            smartEngine = "WINDOWS-SEC";
          } else if (eventId === 4720 || eventId === 4726) {
            smartSeverity = "MEDIUM";
            smartEngine = "WINDOWS-SEC";
          }

          const key = `${ip}-${rawMessage}`;

          if (groupedMap.has(key)) {
            const existing = groupedMap.get(key);
            existing.occurrences += l.occurrences || 1;
            if (new Date(l.timestamp) > new Date(existing.time)) {
              existing.time = l.timestamp;
            }
          } else {
            groupedMap.set(key, {
              id: l._id || i,
              time: l.timestamp,
              level: smartSeverity,
              message: rawMessage,
              ip: ip,
              engine: smartEngine,
              status: "active",
              occurrences: l.occurrences || 1,
              raw_data: l.raw_data || {},
            });
          }
        });

        const aggregatedLogs = Array.from(groupedMap.values()).sort(
          (a, b) => new Date(b.time) - new Date(a.time),
        );
        setLogs(aggregatedLogs);
      }
    } catch (err) {
      console.error("Live Logs Fetch Error:", err);
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const data = await api.getAnalyses();
      if (data && data.status === "success" && Array.isArray(data.data)) {
        setFiles(data.data.map((f) => ({ ...f, name: f.filename })));
      } else if (Array.isArray(data)) {
        setFiles(data.map((f) => ({ ...f, name: f.filename })));
      }
    } catch (err) {}
  }, []);

  const fetchBlockedList = useCallback(async () => {
    try {
      const list = await threatIntel.getBlockedList();
      setBlockedList(Array.isArray(list) ? list.map((i) => i.ip) : []);
    } catch (e) {
      setBlockedList([]);
    }
  }, []);

  useEffect(() => {
    const fetchUserData = async () => {
      if (!token) {
        navigate("/login");
        return;
      }
      try {
        const response = await fetch("http://127.0.0.1:8000/api/v1/auth/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (response.ok) {
          setCurrentUser(await response.json());
        } else {
          localStorage.removeItem("token");
          navigate("/login");
        }
      } catch (e) {
        console.error("Auth Check Error:", e);
      }
    };
    fetchUserData();
    fetchHistory();
    fetchLiveLogs();
    fetchBlockedList();

    const interval = setInterval(() => {
      if (isLiveModeRef.current) fetchLiveLogs();
    }, 5000);
    return () => clearInterval(interval);
  }, [navigate, token, fetchHistory, fetchLiveLogs, fetchBlockedList]);

  const toggleTheme = () =>
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));

  const { lastJsonMessage } = useWebSocket(WS_URL, {
    shouldReconnect: () => true,
  });

// 🚀 LIVE WEBSOCKET LISTENER & SMART PARSER
  useEffect(() => {
    if (lastJsonMessage && isLiveModeRef.current) {
      // 1. Handle Mitigation Success
      if (lastJsonMessage.type === "MITIGATION_SUCCESS") {
        setLogs((prev) =>
          prev.map((log) => log.ip === lastJsonMessage.ip ? { ...log, status: "mitigated" } : log),
        );
        return;
      }

      // 🛡️ THE ULTIMATE UI FIREWALL (Fix for x2, x3)
      const ip = lastJsonMessage.source_ip || lastJsonMessage.ip || "N/A";
      
      // Agar IP blocked list mein hai, toh is log ko foran kachre mein daal do!
      if (blockedList.includes(ip)) {
          console.log("🛡️ Dropped blocked IP log at UI level:", ip);
          return; // Yahan se code wapas mud jayega, table update nahi hogi!
      }

      // 2. Handle Incoming Live Logs
      if ((lastJsonMessage.title || lastJsonMessage.message || lastJsonMessage.severity) && !lastJsonMessage.type) {
        setLogs((prev) => {
          const rawMessage = lastJsonMessage.title || lastJsonMessage.message || "Unknown Event";
          const msgLower = rawMessage.toLowerCase();
          const eventId = lastJsonMessage.event_id || (lastJsonMessage.raw_data && lastJsonMessage.raw_data.event_id) || 0;

          let smartSeverity = (lastJsonMessage.severity || "INFO").toUpperCase();
          let smartEngine = lastJsonMessage.engine_source || "Agent";

          if (eventId === 80 || msgLower.includes("get /") || msgLower.includes("post /")) {
            smartEngine = "WEB-WAF";
            if (msgLower.includes("union select") || msgLower.includes("xss") || msgLower.includes("<script>") || msgLower.includes("/etc/passwd")) {
              smartSeverity = "CRITICAL";
            } else if (msgLower.includes("failed") || msgLower.includes("unauthorized") || msgLower.includes("403") || msgLower.includes("401")) {
              smartSeverity = "HIGH";
            } else {
              smartSeverity = "MEDIUM";
            }
          } else if (eventId === 4625) {
            smartSeverity = "HIGH";
            smartEngine = "WINDOWS-SEC";
          } else if (eventId === 1102) {
            smartSeverity = "CRITICAL";
            smartEngine = "WINDOWS-SEC";
          } else if (eventId === 4720 || eventId === 4726) {
            smartSeverity = "MEDIUM";
            smartEngine = "WINDOWS-SEC";
          }

          const existingIndex = prev.findIndex((l) => l.ip === ip && l.message === rawMessage);

          if (existingIndex !== -1) {
            const updatedLogs = [...prev];
            const existingLog = updatedLogs[existingIndex];
            const updatedLog = {
              ...existingLog,
              occurrences: (existingLog.occurrences || 1) + 1,
              time: lastJsonMessage.timestamp,
              level: smartSeverity,
              engine: smartEngine,
            };
            updatedLogs.splice(existingIndex, 1);
            return [updatedLog, ...updatedLogs];
          } else {
            return [
              {
                id: Date.now(),
                time: lastJsonMessage.timestamp,
                level: smartSeverity,
                message: rawMessage,
                ip: ip,
                engine: smartEngine,
                status: "active",
                occurrences: 1,
              },
              ...prev,
            ];
          }
        });

        if (smartSeverity === "CRITICAL" || msgLower.includes("<script>") || msgLower.includes("union select") || msgLower.includes("/etc/passwd")) {
          toast.error(`🚨 Critical Threat Detected: ${lastJsonMessage.title || "Web Attack"}`);
        }
      }
    }
  }, [lastJsonMessage, blockedList]); // 🚀 Added blockedList to dependencies
  const fetchFileDetails = async (analysisId) => {
    try {
      const res = await fetch(
        `http://127.0.0.1:8000/api/v1/upload/results/${analysisId}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      if (res.ok) {
        const data = await res.json();
        setIsLiveMode(false);
        isLiveModeRef.current = false;
        setSelectedFile(data);
        toast.info(`Viewing File: ${data.filename}`);
      } else {
        toast.error("File not found on server.");
      }
    } catch (e) {
      toast.error("Failed to load file details");
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("http://127.0.0.1:8000/api/v1/upload/analyze", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        await fetchHistory();
        toast.success("File Uploaded & Parsed!");
        if (data.analysis_id) fetchFileDetails(data.analysis_id);
      } else {
        toast.error("Upload failed on server.");
      }
    } catch (err) {
      toast.error("Network Error during upload.");
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  };

  const executeSearch = async (searchQuery, filterDays) => {
    setIsLiveMode(false);
    isLiveModeRef.current = false;

    setSelectedFile(null);
    setLoading(true);

    try {
      let url = `http://127.0.0.1:8000/api/v1/data/search?`;
      if (searchQuery) url += `q=${encodeURIComponent(searchQuery)}&`;
      if (filterDays) url += `days=${filterDays}`;

      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (res.ok) {
        const data = await res.json();
        if (data.results && data.results.length > 0) {
          setLogs(
            data.results.map((f, i) => ({
              id: f._id || i,
              time: f.timestamp,
              level: (f.severity || "INFO").toUpperCase(),
              message: f.message || f.title,
              ip: f.source_ip || f.ip || "N/A",
              engine: f.engine_source || "Historical",
              status: f.status || "active",
              occurrences: f.occurrences || 1,
            })),
          );
          toast.success(`Found ${data.count} alerts in history.`);
        } else {
          toast.info(`No threats found for this search criteria.`);
          setLogs([]);
        }
      } else {
        let errorMsg = "Database Connection Error";
        try {
          const errData = await res.json();
          if (errData.detail) errorMsg = errData.detail;
        } catch (e) {}
        toast.error(`API Error: ${errorMsg}`);
        setLogs([]);
      }
    } catch (err) {
      toast.error("Network Error: Could not connect to API.");
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  const handleGlobalSearch = (e) => {
    if (e.key === "Enter" || e.type === "click") {
      executeSearch(globalQuery.trim(), timeFilter);
    }
  };

  const handleTimeFilterChange = (e) => {
    const selectedDays = e.target.value;
    setTimeFilter(selectedDays);
    executeSearch(globalQuery.trim(), selectedDays);
  };

  const handleBan = async (ip, ipIsBanned) => {
    try {
      ipIsBanned
        ? await threatIntel.revokeIP(ip)
        : await threatIntel.mitigateIP(ip, "Manual Ops");
      setBlockedList((prev) =>
        ipIsBanned ? prev.filter((b) => b !== ip) : [...prev, ip],
      );
    } catch (e) {
      toast.error("Action Failed");
    }
  };

  const confirmDelete = async () => {
    if (!fileToDelete) return;
    try {
      const res = await fetch(
        `http://127.0.0.1:8000/api/v1/upload/results/${fileToDelete}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      if (res.ok) {
        setFiles((prev) =>
          prev.filter((f) => (f.analysisId || f._id) !== fileToDelete),
        );
        toast.success("File deleted successfully.");
      } else {
        toast.error("Failed to delete file from Database.");
      }
    } catch (e) {
      toast.error("Network Error. Cannot reach server.");
    }
    setFileToDelete(null);
  };

  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };

  const handleDownloadReport = () => {
    const dataToReport = logs.length > 0 ? logs : selectedFile?.findings || [];
    if (dataToReport.length === 0) {
      toast.error("No data available to download.");
      return;
    }

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;
    const pageHeight = doc.internal.pageSize.height;

    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 50, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(26);
    doc.setFont("helvetica", "bold");
    doc.text("WarSOC", 14, 25);

    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184);
    doc.setFont("helvetica", "normal");
    doc.text("ADVANCED THREAT INTELLIGENCE REPORT", 14, 32);
    doc.text(`REPORT ID: WS-${Date.now().toString().slice(-6)}`, 14, 38);

    doc.setFontSize(10);
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "normal");
    doc.text("GENERATED BY:", pageWidth - 14, 20, { align: "right" });
    doc.setFont("helvetica", "bold");
    doc.text(
      `${currentUser?.username || "Unknown Analyst"}`,
      pageWidth - 14,
      26,
      { align: "right" },
    );
    doc.setFont("helvetica", "normal");
    doc.text(new Date().toLocaleString(), pageWidth - 14, 36, {
      align: "right",
    });

    const totalLogs = dataToReport.length;
    const criticalCount = dataToReport.filter((l) =>
      ["CRITICAL", "HIGH"].includes(l.level),
    ).length;
    const uniqueIPs = [...new Set(dataToReport.map((l) => l.ip))].length;

    let yPos = 65;

    const drawCard = (x, title, value, color, labelColor) => {
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(x, yPos, 55, 25, 2, 2, "FD");
      doc.setFillColor(...color);
      doc.rect(x, yPos, 2, 25, "F");
      doc.setFontSize(9);
      doc.setTextColor(100, 116, 139);
      doc.text(title, x + 6, yPos + 8);
      doc.setFontSize(16);
      doc.setTextColor(...labelColor);
      doc.setFont("helvetica", "bold");
      doc.text(String(value), x + 6, yPos + 19);
    };

    drawCard(14, "TOTAL LOGS", totalLogs, [59, 130, 246], [15, 23, 42]);
    drawCard(
      74,
      "CRITICAL THREATS",
      criticalCount,
      [239, 68, 68],
      [220, 38, 38],
    );
    drawCard(134, "UNIQUE ASSETS", uniqueIPs, [16, 185, 129], [15, 23, 42]);

    yPos += 40;

    doc.setFontSize(12);
    doc.setTextColor(15, 23, 42);
    doc.text("Forensic Event Log", 14, yPos);
    yPos += 5;

    const tableData = dataToReport.map((l) => [
      formatTime(l.time || l.timestamp),
      l.level || l.severity,
      (l.message || l.title || "").substring(0, 60),
      l.engine || l.engine_source,
      l.ip || l.source_ip,
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [
        [
          "Timestamp",
          "Severity",
          "Event Description",
          "Detection Engine",
          "Source IP",
        ],
      ],
      body: tableData,
      theme: "grid",
      headStyles: {
        fillColor: [30, 41, 59],
        textColor: 255,
        fontStyle: "bold",
        halign: "left",
      },
      styles: { fontSize: 8, cellPadding: 4, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      didParseCell: function (data) {
        if (data.section === "body" && data.column.index === 1) {
          if (data.cell.raw === "CRITICAL") {
            data.cell.styles.fillColor = [254, 226, 226];
            data.cell.styles.textColor = [185, 28, 28];
            data.cell.styles.fontStyle = "bold";
          } else if (data.cell.raw === "HIGH") {
            data.cell.styles.textColor = [234, 88, 12];
            data.cell.styles.fontStyle = "bold";
          }
        }
      },
    });

    let finalY = doc.lastAutoTable.finalY + 15;
    if (finalY > 250) {
      doc.addPage();
      finalY = 20;
    }

    if (criticalCount > 0) {
      doc.setFillColor(255, 241, 242);
      doc.setDrawColor(254, 202, 202);
      doc.roundedRect(14, finalY, pageWidth - 28, 40, 3, 3, "FD");
      doc.setFontSize(11);
      doc.setTextColor(153, 27, 27);
      doc.setFont("helvetica", "bold");
      doc.text("ACTION REQUIRED: CRITICAL THREATS", 20, finalY + 10);
      doc.setFontSize(10);
      doc.setTextColor(60);
      doc.setFont("helvetica", "normal");
      doc.text(
        "Critical threats detected in this session. Recommended actions:",
        20,
        finalY + 18,
      );
      doc.text(
        "• Isolate affected hosts (IPs listed above) from the network immediately.",
        20,
        finalY + 25,
      );
      doc.text(
        "• Change administrative credentials and force logout for suspicious users.",
        20,
        finalY + 31,
      );
    }

    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(50);
      doc.setFont("helvetica", "bold");
      doc.saveGraphicsState();
      doc.setGState(new doc.GState({ opacity: 0.1 }));
      doc.text("CONFIDENTIAL", 40, pageHeight - 100, { angle: 45 });
      doc.restoreGraphicsState();
      doc.setFontSize(8);
      doc.setTextColor(100);
      doc.setGState(new doc.GState({ opacity: 1 }));
      doc.setDrawColor(200);
      doc.line(14, pageHeight - 15, pageWidth - 14, pageHeight - 15);
      doc.text(
        `WarSOC Enterprise Security | Generated by ${currentUser?.username || "Admin"}`,
        14,
        pageHeight - 10,
      );
      doc.text(`Page ${i} of ${pageCount}`, pageWidth - 14, pageHeight - 10, {
        align: "right",
      });
    }
    doc.save(`WarSOC_Pro_Report_${Date.now()}.pdf`);
  };

  useEffect(() => {
    if (selectedFile) {
      if (selectedFile.findings && selectedFile.findings.length > 0) {
        const fileLogs = selectedFile.findings.map((f, i) => ({
          id: i,
          time: f.timestamp,
          level: (f.severity || "INFO").toUpperCase(),
          message: f.message || f.title || "Unknown Event",
          ip: f.source_ip || f.ip || "N/A",
          engine: f.engine_source || "Historical",
          status: "static",
          occurrences: 1,
        }));
        setLogs(fileLogs);
      } else {
        setLogs([]);
        toast.info("No threats found in this file.");
      }
    }
  }, [selectedFile]);

  const activeThreatsCount = logs.filter(
    (log) =>
      log.status !== "mitigated" &&
      !blockedList.includes(log.ip) &&
      log.level !== "INFO",
  ).length;

// ==========================================================
  // 📊 CHART DATA CALCULATION (The "Brain" for our Pro Charts)
  // ==========================================================
  const { volumeData, severityData } = useMemo(() => {
    let crit = 0, high = 0, med = 0, info = 0;
    const timeMap = {};

    // 1. Calculate Data from Logs
    logs.forEach(log => {
      // Calculate Severity Mix
      const level = (log.level || "INFO").toUpperCase();
      if (level === "CRITICAL") crit++;
      else if (level === "HIGH") high++;
      else if (level === "MEDIUM") med++;
      else info++;

      // 🚀 Group Threat Volume by 10-Minute Buckets
      if (log.time) {
        const date = new Date(log.time);
        const mins = date.getMinutes();
        date.setMinutes(Math.floor(mins / 10) * 10);
        date.setSeconds(0); 
        
        const timeKey = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        timeMap[timeKey] = (timeMap[timeKey] || 0) + 1;
      }
    });

    // 2. Format Severity Data for Pie Chart
    const severityData = [
      { name: "Critical", value: crit, color: "#ef4444" },
      { name: "High", value: high, color: "#f97316" },
      { name: "Medium", value: med, color: "#f59e0b" },
      { name: "Info", value: info, color: "#3b82f6" }
    ].filter(d => d.value > 0);

    // 3. Format Volume Data for Area Chart
    let volumeArray = Object.keys(timeMap).map(time => ({
      name: time,
      value: timeMap[time]
    }));

    // Sort chronologically
    volumeArray.sort((a, b) => new Date('1970/01/01 ' + a.name) - new Date('1970/01/01 ' + b.name));

    // 🚀 THE FIX: Force the chart to always draw a line/wave
    if (volumeArray.length === 0) {
      volumeArray = [{ name: "00:00", value: 0 }];
    } else if (volumeArray.length === 1) {
      // Agar sirf 1 bucket hai, toh us se 10 minute pehle ka point (Value 0) bana do
      let prevDate = new Date('1970/01/01 ' + volumeArray[0].name);
      prevDate.setMinutes(prevDate.getMinutes() - 10);
      let prevTime = prevDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      
      // Zero se start hokar peak tak jayega
      volumeArray.unshift({ name: prevTime, value: 0 });
    }

    return { volumeData: volumeArray, severityData };
  }, [logs]);

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

          <div
            className="search-wrapper"
            style={{ display: "flex", gap: "10px" }}
          >
            <div style={{ position: "relative" }}>
              <Search
                size={16}
                className="search-icon"
                style={{
                  position: "absolute",
                  left: "12px",
                  top: "10px",
                  color: "var(--text-sub)",
                }}
              />
              <input
                type="text"
                className="global-search"
                placeholder="Search IP or text..."
                value={globalQuery}
                onChange={(e) => setGlobalQuery(e.target.value)}
                onKeyDown={handleGlobalSearch}
              />
            </div>
            <select
              value={timeFilter}
              onChange={handleTimeFilterChange}
              className="global-search"
              style={{ width: "130px", paddingLeft: "10px", cursor: "pointer" }}
            >
              <option value="">All Time</option>
              <option value="1">Last 24 Hours</option>
              <option value="7">Last 7 Days</option>
              <option value="30">Last 1 Month</option>
            </select>
            <button className="btn-primary" onClick={handleGlobalSearch}>
              Search
            </button>
          </div>

          <div
            className="header-actions"
            style={{ display: "flex", alignItems: "center", gap: "15px" }}
          >
            <button
              onClick={toggleTheme}
              title="Toggle Theme"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                width: "40px",
                height: "40px",
                background: theme === "dark" ? "#1e293b" : "#ffffff",
                border: "1px solid #334155",
                borderRadius: "10px",
                cursor: "pointer",
                padding: "0",
                minWidth: "40px",
              }}
            >
              {theme === "dark" ? (
                <svg
                  width="22"
                  height="22"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#facc15"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  style={{ minWidth: "22px" }}
                >
                  <circle
                    cx="12"
                    cy="12"
                    r="4"
                    fill="rgba(250, 204, 21, 0.2)"
                  />
                  <path d="M12 2v2" />
                  <path d="M12 20v2" />
                  <path d="m4.93 4.93 1.41 1.41" />
                  <path d="m17.66 17.66 1.41 1.41" />
                  <path d="M2 12h2" />
                  <path d="M20 12h2" />
                  <path d="m6.34 17.66-1.41 1.41" />
                  <path d="m19.07 4.93-1.41 1.41" />
                </svg>
              ) : (
                <svg
                  width="22"
                  height="22"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  style={{ minWidth: "22px" }}
                >
                  <path
                    d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"
                    fill="rgba(59, 130, 246, 0.1)"
                  />
                </svg>
              )}
            </button>
            <div
              className={`live-pill ${!isLiveMode ? "offline" : ""}`}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "6px 12px",
                background: !isLiveMode
                  ? "rgba(71, 85, 105, 0.4)"
                  : "rgba(16, 185, 129, 0.1)",
                color: !isLiveMode ? "#94a3b8" : "#10b981",
                fontSize: "12px",
                fontWeight: "700",
                borderRadius: "20px",
                border: !isLiveMode
                  ? "none"
                  : "1px solid rgba(16, 185, 129, 0.2)",
                whiteSpace: "nowrap",
              }}
            >
              <div
                className={isLiveMode ? "pulse" : ""}
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  background: isLiveMode ? "#10b981" : "#94a3b8",
                }}
              ></div>
              {isLiveMode ? "LIVE" : "HISTORICAL"}
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
                    trend="+12%"
                    trendUp={true}
                    glow={activeThreatsCount > 0}
                  />
                  <MetricCard
                    title="Behavioral"
                    value={logs.filter((l) => l.engine === "Stateful").length}
                    icon={BrainCircuit}
                    color="#f59e0b"
                    trend="-2%"
                    trendUp={false}
                  />
                  <MetricCard
                    title="Signature"
                    value={
                      logs.filter(
                        (l) =>
                          l.engine === "Stateless" ||
                          l.engine === "Agent" ||
                          l.engine === "WINDOWS-SEC" ||
                          l.engine === "WEB-WAF",
                      ).length
                    }
                    icon={Zap}
                    color="#3b82f6"
                    trend="+5%"
                    trendUp={true}
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
                    <h4>Threat Volume (24h)</h4>
                    <ResponsiveContainer width="100%" height={250}>
                      <AreaChart
                        data={volumeData}
                        margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                      >
                        <defs>
                          {/* Beautiful Blue Gradient */}
                          <linearGradient
                            id="colorThreats"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop
                              offset="5%"
                              stopColor="#3b82f6"
                              stopOpacity={0.4}
                            />
                            <stop
                              offset="95%"
                              stopColor="#3b82f6"
                              stopOpacity={0}
                            />
                          </linearGradient>
                        </defs>
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="rgba(148, 163, 184, 0.05)"
                          vertical={false}
                        />
                        <XAxis
                          dataKey="name"
                          stroke="#64748b"
                          fontSize={11}
                          tickLine={false}
                          axisLine={false}
                        />
                        <YAxis
                          stroke="#64748b"
                          fontSize={11}
                          tickLine={false}
                          axisLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#1e293b",
                            borderColor: "#334155",
                            borderRadius: "8px",
                            color: "#f8fafc",
                          }}
                          itemStyle={{ color: "#3b82f6", fontWeight: "bold" }}
                        />
                        <Area
                          type="monotone"
                          dataKey="value"
                          stroke="#3b82f6"
                          strokeWidth={3}
                          fillOpacity={1}
                          fill="url(#colorThreats)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="chart-box">
                    <h4>Severity Mix</h4>
                    <ResponsiveContainer width="100%" height={250}>
                      <PieChart>
                        <Pie
                          data={severityData}
                          cx="50%"
                          cy="50%"
                          innerRadius={70}
                          outerRadius={90}
                          paddingAngle={5}
                          dataKey="value"
                          stroke="none"
                        >
                          {severityData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#1e293b",
                            borderColor: "#334155",
                            borderRadius: "8px",
                          }}
                        />
                        <Legend
                          verticalAlign="bottom"
                          height={36}
                          iconType="circle"
                          wrapperStyle={{ fontSize: "12px", color: "#94a3b8" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {isLiveMode && (
                  <div className="agent-logs-section">
                    <AgentLogs logs={logs} />
                  </div>
                )}

                <div className="bottom-split-grid">
                  <div className="logs-table-card">
                    <div className="table-header">
                      <div className="th-left">
                        <FileText size={16} />
                        <span>
                          {isLiveMode
                            ? "Live Inspection (Threats Only)"
                            : `Analyzing Offline File`}
                        </span>
                      </div>
                      <div
                        className="th-right"
                        style={{
                          display: "flex",
                          gap: "12px", // 🚀 Perfect spacing between buttons
                          alignItems: "center",
                        }}
                      >
                        {!isLiveMode && (
                          <button
                            className="btn-primary"
                            style={{
                              background: "rgba(245, 158, 11, 0.15)",
                              color: "#f59e0b",
                              border: "1px solid rgba(245, 158, 11, 0.4)",
                              boxShadow: "none",
                              padding: "0 16px",
                              height: "36px",
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              gap: "6px", // 🚀 Space between icon and text
                              whiteSpace: "nowrap",
                              fontWeight: "700",
                              borderRadius: "8px",
                            }}
                            onClick={() => {
                              setIsLiveMode(true);
                              isLiveModeRef.current = true;
                              setSelectedFile(null);
                              fetchLiveLogs();
                              toast.info("Switched back to Live Agent Feed");
                            }}
                          >
                            <RefreshCw size={14} /> Back to Live
                          </button>
                        )}

                        <button
                          className="btn-primary"
                          onClick={handleDownloadReport}
                          style={{
                            height: "36px",
                            padding: "0 16px",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            gap: "6px", // 🚀 Space between icon and text
                            whiteSpace: "nowrap",
                            fontWeight: "600",
                            borderRadius: "8px",
                          }}
                        >
                          <Download size={14} /> Report
                        </button>
                      </div>
                    </div>
                    <div className="table-body">
                      {logs
                        .filter((l) =>
                          isLiveMode
                            ? l.level !== "INFO" && l.level !== "LOW"
                            : true,
                        )
                        .filter((l) =>
                          (l.message || "")
                            .toLowerCase()
                            .includes(search.toLowerCase()),
                        )
                        .map((log, i) => (
                          <div
                            key={log.id || i}
                            className={`tr ${log.status === "mitigated" ? "dimmed" : ""}`}
                          >
                            {/* 🚀 Typography Fix: Time column dimmed */}
                            <div
                              className="td time"
                              style={{ color: "#64748b", fontWeight: "500" }}
                            >
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
                              <span
                                className="ip-tag"
                                style={{
                                  cursor: "pointer",
                                  transition: "0.2s",
                                }}
                                onClick={() => {
                                  setGlobalQuery(log.ip);
                                  executeSearch(log.ip, timeFilter);
                                  toast.info(
                                    `Investigating Threat Actor: ${log.ip}`,
                                  );
                                }}
                                title="Click to investigate all attacks from this IP"
                              >
                                {log.ip}
                              </span>
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
                      <button
                        onClick={fetchHistory}
                        className="refresh-btn"
                        title="Refresh Data"
                      >
                        <RefreshCw size={16} color="currentColor" />
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
                              {f.uploaded_at
                                ? new Date(f.uploaded_at).toLocaleDateString()
                                : "Live"}
                            </span>
                          </div>
                          <button
                            className="del-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              setFileToDelete(f.analysisId || f._id);
                            }}
                          >
                            <Trash2 size={16} />
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

      {fileToDelete && (
        <div className="modal-overlay">
          <div className="modal-card confirm-box">
            <div style={{ color: "#ef4444", marginBottom: "10px" }}>
              <AlertTriangle size={48} />
            </div>
            <h3>Delete File?</h3>
            <p
              style={{
                color: "var(--text-sub)",
                fontSize: "14px",
                marginBottom: "20px",
              }}
            >
              Are you sure you want to permanently delete this report? This
              action cannot be undone.
            </p>
            <div className="modal-btns">
              <button
                className="btn-cancel"
                onClick={() => setFileToDelete(null)}
              >
                Cancel
              </button>
              <button className="btn-danger" onClick={confirmDelete}>
                Delete Permanently
              </button>
            </div>
          </div>
        </div>
      )}

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
