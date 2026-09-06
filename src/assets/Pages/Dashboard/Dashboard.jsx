import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  useMemo,
} from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../../../api/apiClient";
import { useAuthStore } from "../../../store/authStore";
import useWebSocket from "react-use-websocket";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
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
import ComplianceDashboard from "../Compliance/ComplianceDashboard";
import TeamManagement from "../Team/TeamManagement";
import OperationsViews from "../../Components/OperationsViews/OperationsViews";
import EvidenceCases from "../Evidence/EvidenceCases";
import LegalHolds from "../Evidence/LegalHolds";
import useRole from "../../../hooks/useRole";

import {
  ShieldCheck,
  Users,
  Shield,
  Activity,
  Lock,
  BrainCircuit,
  Zap,
  FileText,
  Globe,
  HardDrive,
  FileSearch,
  LogOut,
  X,
  Download,
  Copy,
  UploadCloud,
  RefreshCw,
  Trash2,
  Search,
  User,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  Server,
  FolderOpen,
  Scale,
  GripVertical,
  Settings2,
  Sparkles,
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
  } catch {
    return "00:00:00";
  }
};

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

const DEFAULT_CHART_ORDER = [
  "incident-trend",
  "source-locations",
  "severity",
  "telemetry-sources",
  "detection-rules",
  "mitre",
  "endpoint-load",
  "operations",
];

const DASHBOARD_WIDGETS = [
  { id: "incident-trend", title: "Incident Volume Trend" },
  { id: "source-locations", title: "Observed Source Locations" },
  { id: "severity", title: "Threat Severity" },
  { id: "telemetry-sources", title: "Telemetry Source Breakdown" },
  { id: "detection-rules", title: "Detection Rule Frequency" },
  { id: "mitre", title: "MITRE ATT&CK Coverage" },
  { id: "endpoint-load", title: "Endpoint Event Load" },
  { id: "operations", title: "Operations Snapshot" },
];

const readChartPreferences = () => {
  try {
    const saved = JSON.parse(localStorage.getItem("warsoc-chart-order") || "null");
    const savedOrder = Array.isArray(saved) ? saved : saved?.order;
    const order = Array.isArray(savedOrder) && DEFAULT_CHART_ORDER.every((id) => savedOrder.includes(id))
      ? savedOrder
      : DEFAULT_CHART_ORDER;
    const hidden = Array.isArray(saved?.hidden) ? saved.hidden.filter((id) => DEFAULT_CHART_ORDER.includes(id)) : [];
    return { order, hidden };
  } catch {
    return { order: DEFAULT_CHART_ORDER, hidden: [] };
  }
};

const ChartTitle = ({ title, meta, onRemove }) => (
  <div className="chart-title-row">
    <div><h4>{title}</h4><span>{meta}</span></div>
    <div className="chart-controls">
      <span className="chart-drag-handle" title="Drag to reorder chart" aria-label="Drag to reorder chart"><GripVertical size={16} /></span>
      <button
        type="button"
        className="chart-remove-button"
        title={`Hide ${title}`}
        aria-label={`Hide ${title}`}
        onClick={(event) => { event.stopPropagation(); onRemove?.(); }}
      >
        <X size={14} />
      </button>
    </div>
  </div>
);

const EndpointContextStrip = ({ fleet, selectedAgentId, onSelectAgent }) => {
  const endpoints = Array.isArray(fleet?.data) ? fleet.data : [];
  const endpoint = endpoints.find((item) => item.agent_id === selectedAgentId) || endpoints[0] || null;
  const value = (candidate) => candidate === undefined || candidate === null || candidate === "" ? "Not recorded" : String(candidate);
  const health = endpoint ? String(endpoint.health || (endpoint.online ? "active" : "offline")).toLowerCase() : "not-configured";
  return (
    <section className="endpoint-context-strip" aria-label="Connected endpoint context">
      <div className="endpoint-context-identity">
        <div className="endpoint-context-icon"><HardDrive size={19} /></div>
        <div>
          <span>Connected endpoint</span>
          <strong>{endpoint ? value(endpoint.endpoint_name) : "No endpoint connected"}</strong>
        </div>
      </div>
      {endpoints.length > 1 && (
        <label className="endpoint-context-selector">Endpoint
          <select value={endpoint?.agent_id || ""} onChange={(event) => onSelectAgent(event.target.value)}>
            {endpoints.map((item) => <option key={item.agent_id} value={item.agent_id}>{value(item.endpoint_name)}</option>)}
          </select>
        </label>
      )}
      <dl className="endpoint-context-details">
        <div><dt>Agent ID</dt><dd>{endpoint ? value(endpoint.agent_id) : "Not recorded"}</dd></div>
        <div><dt>Status</dt><dd><span className={`endpoint-health ${health}`}>{endpoint ? value(endpoint.health) : "Not configured"}</span></dd></div>
        <div><dt>IP address</dt><dd>{endpoint ? value(endpoint.ip_address || endpoint.source_ip || endpoint.ip) : "Not recorded"}</dd></div>
        <div><dt>Version</dt><dd>{endpoint ? value(endpoint.version) : "Not recorded"}</dd></div>
        <div><dt>Signing</dt><dd>{endpoint ? value(endpoint.event_signing?.status) : "Not recorded"}</dd></div>
        <div><dt>Last seen</dt><dd>{endpoint?.last_seen ? new Date(endpoint.last_seen).toLocaleString() : "Not recorded"}</dd></div>
      </dl>
    </section>
  );
};

const UserMenu = ({ user, onProfile, onLogout }) => {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);
  const displayName =
    user?.full_name ||
    user?.name ||
    user?.username ||
    "User";
  const avatar =
    user?.avatar ||
    user?.profile_image ||
    user?.profile_picture ||
    user?.photo_url ||
    user?.image;
  const initials = displayName
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase() || "U";

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
          {avatar ? (
            <img src={avatar} alt={`${displayName} avatar`} />
          ) : (
            initials
          )}
        </div>
        <ChevronDown
          size={14}
          className={`chevron ${isOpen ? "rotate" : ""}`}
        />
      </button>
      {isOpen && (
        <div className="dropdown-menu">
          <div className="dropdown-header">
            <span className="dp-name">{displayName}</span>
            <span className="dp-email">{user?.email}</span>
            {user?.tenant_id && (
              <span
                className="dp-tenant"
                title="Click to copy"
                onClick={() => {
                  navigator.clipboard.writeText(user.tenant_id);
                  toast.success("Tenant ID copied!");
                }}
                style={{
                  cursor: "pointer",
                  fontSize: "11px",
                  color: "#00e5ff",
                  marginTop: "4px",
                  display: "block",
                }}
              >
                Tenant: {user.tenant_id} 📋
              </span>
            )}
          </div>
          <div className="dropdown-divider"></div>
          <button className="dropdown-item" onClick={onProfile}>
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
  const { user: currentUser, role, logout } = useAuthStore();
  const { can: canRole } = useRole();
  const [profileUser, setProfileUser] = useState(null);
  const normalizedRole = String(role || currentUser?.role || "").toLowerCase();
  const canViewOperations = ["admin", "manager", "analyst"].includes(normalizedRole);
  const canManageAlerts = ["admin", "manager"].includes(normalizedRole);
  const canDownloadAgent = normalizedRole === "admin";
  const canViewCompliance = ["admin", "auditor"].includes(normalizedRole);
  const canManageTeam = normalizedRole === "admin";
  const canViewCases = canRole("cases.read");
  const canViewHolds = canRole("holds.read");
  const canViewEndpointTrust = canRole("endpoint.trust.read");
  const relayEnabled = import.meta.env.VITE_NETWORK_RELAY_ENABLED === "true";
  const [relayCapability, setRelayCapability] = useState(null);
  const canViewRelay = relayEnabled && relayCapability?.entitled === true;
  const archiveEnabled = import.meta.env.VITE_ARCHIVE_RETRIEVAL_ENABLED === "true" && canRole("archive.retrieve");
  const [activeTab, setActiveTab] = useState(
    normalizedRole === "auditor" ? "compliance" : "dashboard",
  );
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(
    () => typeof window !== "undefined" && window.innerWidth > 900,
  );
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [fileToDelete, setFileToDelete] = useState(null);
  const [theme, setTheme] = useState(localStorage.getItem("theme") || "dark");
  const [, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [agentEvents, setAgentEvents] = useState([]);
  const [incidentSummary, setIncidentSummary] = useState(null);
  const [incidentLoadState, setIncidentLoadState] = useState("loading");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [incidentDetailLoading, setIncidentDetailLoading] = useState(false);
  const [incidentAssignees, setIncidentAssignees] = useState([]);
  const [incidentAssignmentLoading, setIncidentAssignmentLoading] = useState(false);
  const [globalQuery, setGlobalQuery] = useState("");
  const [timeFilter, setTimeFilter] = useState("1");
  const [blockedList, setBlockedList] = useState([]);
  const [telemetryStatus, setTelemetryStatus] = useState("offline");
  const [fleetStatus, setFleetStatus] = useState(null);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [loading, setLoading] = useState(false);
  const [viewFile, setViewFile] = useState(null);
  // 🚀 ALERT WORKFLOW STATE
  const [resolvingAlert, setResolvingAlert] = useState(null);
  const [resolutionNotes, setResolutionNotes] = useState("");
  const [agentActivation, setAgentActivation] = useState(null);
  const [generatingActivation, setGeneratingActivation] = useState(false);
  const initialChartPreferences = useMemo(() => readChartPreferences(), []);
  const [chartOrder, setChartOrder] = useState(initialChartPreferences.order);
  const [hiddenChartIds, setHiddenChartIds] = useState(initialChartPreferences.hidden);
  const [removingChartIds, setRemovingChartIds] = useState([]);
  const [showWidgetPicker, setShowWidgetPicker] = useState(false);
  const [draggedChart, setDraggedChart] = useState(null);

  const [isLiveMode, setIsLiveMode] = useState(true);
  const isLiveModeRef = useRef(isLiveMode);
  const liveAlertsRequestInFlightRef = useRef(false);
  const agentEventsRequestInFlightRef = useRef(false);
  const wsReconcileTimerRef = useRef(null);
  const wsLastReconcileAtRef = useRef(0);

  useEffect(() => {
    isLiveModeRef.current = isLiveMode;
  }, [isLiveMode]);

  useEffect(() => {
    let cancelled = false;

    const fetchProfileUser = async () => {
      try {
        const { data } = await apiClient.get("/auth/profile");
        if (cancelled) return;
        const apiProfile = data.profile || {};
        setProfileUser({
          ...currentUser,
          ...apiProfile,
          role: data.role || apiProfile.role || currentUser?.role || role,
        });
      } catch (error) {
        console.error("Dashboard profile fetch failed", error);
        if (!cancelled) setProfileUser(null);
      }
    };

    fetchProfileUser();

    return () => {
      cancelled = true;
    };
  }, [currentUser, role]);

  useEffect(() => {
    let cancelled = false;
    if (!relayEnabled || !canViewOperations) {
      setRelayCapability(null);
      return undefined;
    }

    const fetchRelayCapability = async () => {
      try {
        const { data } = await apiClient.get("/network-relay/status");
        if (!cancelled) setRelayCapability(data?.capability?.entitled === true ? data.capability : null);
      } catch {
        if (!cancelled) setRelayCapability(null);
      }
    };

    fetchRelayCapability();
    return () => {
      cancelled = true;
    };
  }, [relayEnabled, canViewOperations]);

  useEffect(
    () => () => {
      if (wsReconcileTimerRef.current) {
        window.clearTimeout(wsReconcileTimerRef.current);
      }
    },
    [],
  );

  const navigate = useNavigate();
  // 🔒 SECURITY FIX: Token moved to HttpOnly cookie, no longer in localStorage
  // WebSocket will automatically send cookie with upgrade request
  const baseForWs =
    import.meta.env.VITE_WS_BASE_URL ||
    apiClient.defaults.baseURL ||
    `${window.location.origin}/api/v1`;
  const parsed = new URL(
    baseForWs.replace(/\/api\/v1\/?$/, ""),
    window.location.origin,
  );
  const wsProto = parsed.protocol === "https:" ? "wss" : "ws";
  const [wsUrl, setWsUrl] = useState(null);
  const [wsTicketNonce, setWsTicketNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;

    if (!canViewOperations) {
      setWsUrl(null);
      return undefined;
    }

    const fetchWsTicket = async () => {
      try {
        const response = await apiClient.post('/ws/ticket');
        if (!cancelled && response.data?.ticket) {
          setWsUrl(`${wsProto}://${parsed.host}/ws/alerts?ticket=${encodeURIComponent(response.data.ticket)}`);
        }
      } catch (error) {
        console.error("WS Ticket Error:", error);
        if (!cancelled) {
          setWsUrl(null);
          window.setTimeout(() => setWsTicketNonce((current) => current + 1), 3000);
        }
      }
    };

    setWsUrl(null);
    fetchWsTicket();

    return () => {
      cancelled = true;
    };
  }, [canViewOperations, parsed.host, wsProto, wsTicketNonce]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem("warsoc-chart-order", JSON.stringify({ order: chartOrder, hidden: hiddenChartIds }));
  }, [chartOrder, hiddenChartIds]);

  const fetchLiveLogs = useCallback(async () => {
    if (
      !canViewOperations ||
      !isLiveModeRef.current ||
      liveAlertsRequestInFlightRef.current
    )
      return;
    liveAlertsRequestInFlightRef.current = true;
    setIncidentLoadState((current) => current === "ready" ? current : "loading");
    try {
      const response = (
        await apiClient.get("/incidents", {
          params: {
            limit: 500,
            include_closed: false,
          },
        })
      ).data;

      if (
        isLiveModeRef.current &&
        response?.status === "success" &&
        Array.isArray(response.data)
      ) {
        const aggregatedLogs = response.data
          .map((log, index) => {
            const context = log.context || {};
            const ip = context.source_address || log.source_ip || log.ip || "N/A";
            const rawMessage = log.message || log.title || "Unknown Event";
            const eventId = log.event_id || 0;
            return {
              id: log.incident_id || `${ip}-${eventId}-${index}`,
              incidentId: log.incident_id,
              time: log.last_seen || log.timestamp,
              firstSeen: log.first_seen || log.timestamp,
              lastSeen: log.last_seen || log.timestamp,
              level: String(log.severity || "INFO").toUpperCase(),
              message: rawMessage,
              ip,
              host: context.endpoint || context.agent_id || "Unknown endpoint",
              engine: log.engine_source || "SIEM",
              eventId,
              eventUids: log.event_uids || [],
              ruleId: log.rule_id,
              mitre: log.mitre || log.mitre_id,
              context,
              actor: context.actor || context.user || "Unknown",
              target: context.target_user || context.target || context.protected_object || "Not recorded",
              bannable: context.bannable === true,
              recordType: "incident",
              status: String(log.status || "NEW").toLowerCase(),
              occurrences: log.occurrences || 1,
            };
          })
          .sort((a, b) => new Date(b.time) - new Date(a.time));
        setLogs(aggregatedLogs);
        setIncidentLoadState("ready");
      }
    } catch (error) {
      console.error("Live Alerts Fetch Error:", error);
      setIncidentLoadState("error");
    } finally {
      liveAlertsRequestInFlightRef.current = false;
    }
  }, [canViewOperations]);

  const fetchIncidentSummary = useCallback(async () => {
    if (!canViewOperations || !isLiveModeRef.current) return;
    try {
      const response = await apiClient.get("/incidents/summary");
      setIncidentSummary(response.data?.data || null);
    } catch (error) {
      console.error("Incident Summary Fetch Error:", error);
    }
  }, [canViewOperations]);

  const fetchAgentEvents = useCallback(async () => {
    if (
      !canViewOperations ||
      !isLiveModeRef.current ||
      agentEventsRequestInFlightRef.current
    )
      return;
    agentEventsRequestInFlightRef.current = true;
    try {
      const response = (
        await apiClient.get("/logs/live", {
          params: {
            source: "siem",
            limit: 100,
            aggregate: true,
          },
        })
      ).data;

      if (
        isLiveModeRef.current &&
        response.status === "success" &&
        Array.isArray(response.data)
      ) {
        setAgentEvents(
          response.data.map((event, index) => {
            const eventId = event.event_id || 0;
            const host =
              event.computer ||
              event.hostname ||
              event.agent_id ||
              "Unknown endpoint";
            return {
              id:
                event._id ||
                event.event_uid ||
                `${host}-${eventId}-${index}`,
              time: event.timestamp || event.ingested_at,
              level: String(event.severity || "INFO").toUpperCase(),
              message:
                event.event_id_meaning ||
                event.summary ||
                (eventId ? `Windows Event ${eventId}` : "Endpoint telemetry"),
              ip: event.source_ip || event.ip || "N/A",
              host,
              engine:
                event.telemetry_family || event.engine_source || "WINDOWS",
              sourceType: event.telemetry_family || event.engine_source || "Not recorded",
              eventId,
              eventUid: event.event_uid,
              context: event.context || {},
              occurrences: event.occurrences || 1,
            };
          }),
        );
      }
    } catch (error) {
      console.error("Agent Evidence Fetch Error:", error);
    } finally {
      agentEventsRequestInFlightRef.current = false;
    }
  }, [canViewOperations]);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await apiClient.get('/upload/results');
      const data = res.data;
      if (data && data.status === "success" && Array.isArray(data.data)) {
        setFiles(data.data.map((f) => ({ ...f, name: f.filename })));
      } else if (Array.isArray(data)) {
        setFiles(data.map((f) => ({ ...f, name: f.filename })));
      }
    } catch (error) {
      console.debug("History fetch failed", error);
    }
  }, []);

  const fetchBlockedList = useCallback(async () => {
    try {
      const res = await apiClient.get('/list');
      const list = res.data;
      setBlockedList(Array.isArray(list) ? list.map((i) => i.ip) : []);
    } catch {
      setBlockedList([]);
    }
  }, []);

  const fetchTelemetryStatus = useCallback(async () => {
    if (!canViewOperations) return;
    try {
      const res = await apiClient.get('/data/status');
      setFleetStatus(res.data || null);
      const firstAgentId = res.data?.data?.[0]?.agent_id || "";
      setSelectedAgentId((current) => current || firstAgentId);
      setTelemetryStatus(
        ["active", "degraded"].includes(res.data?.endpoint_status)
          ? res.data.endpoint_status
          : "offline",
      );
    } catch {
      setTelemetryStatus("offline");
      setFleetStatus(null);
    }
  }, [canViewOperations]);

  useEffect(() => {
    if (!canViewOperations) return undefined;
    fetchHistory();
    fetchLiveLogs();
    fetchIncidentSummary();
    fetchAgentEvents();
    fetchBlockedList();
    fetchTelemetryStatus();

    const alertReconciliationInterval = setInterval(() => {
      if (isLiveModeRef.current) {
        fetchLiveLogs();
        fetchIncidentSummary();
      }
    }, 30000);
    const agentEvidenceInterval = setInterval(() => {
      if (isLiveModeRef.current) fetchAgentEvents();
    }, 10000);
    const telemetryInterval = setInterval(fetchTelemetryStatus, 30000);
    return () => {
      clearInterval(alertReconciliationInterval);
      clearInterval(agentEvidenceInterval);
      clearInterval(telemetryInterval);
    };
  }, [
    canViewOperations,
    navigate,
    fetchHistory,
    fetchLiveLogs,
    fetchIncidentSummary,
    fetchAgentEvents,
    fetchBlockedList,
    fetchTelemetryStatus,
  ]);

  const toggleTheme = () =>
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));

  const { lastJsonMessage } = useWebSocket(wsUrl, {
    shouldReconnect: () => false,
    onClose: () => setWsTicketNonce((current) => current + 1),
    onError: () => {},
  });

  useEffect(() => {
    if (lastJsonMessage && isLiveModeRef.current) {
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
      const ip = lastJsonMessage.source_ip || lastJsonMessage.ip || "N/A";
      if (blockedList.includes(ip)) return;

      if (
        (lastJsonMessage.title ||
          lastJsonMessage.message ||
          lastJsonMessage.severity) &&
        lastJsonMessage.type !== "MITIGATION_SUCCESS"
      ) {
        if (!wsReconcileTimerRef.current) {
          const elapsed = Date.now() - wsLastReconcileAtRef.current;
          const delay = Math.max(250, 5000 - elapsed);
          wsReconcileTimerRef.current = window.setTimeout(() => {
            wsReconcileTimerRef.current = null;
            wsLastReconcileAtRef.current = Date.now();
            fetchLiveLogs();
            fetchIncidentSummary();
          }, delay);
        }

      }
    }
  }, [lastJsonMessage, blockedList, fetchLiveLogs, fetchIncidentSummary]);

  // 🚀 ALERT WORKFLOW FUNCTIONS
  const handleAcknowledge = async (alertId) => {
    const alert = logs.find((item) => item.id === alertId);
    const incidentRef = alert?.incidentId || alertId;
    try {
      await apiClient.patch(
        `/incidents/${encodeURIComponent(incidentRef)}/status`,
        {
          status: "ACKNOWLEDGED",
        },
      );
      setLogs((prev) =>
        prev.map((item) =>
          item.id === alertId ? { ...item, status: "acknowledged" } : item,
        ),
      );
      fetchIncidentSummary();
      toast.info("Incident acknowledged.");
    } catch (error) {
      toast.error(error.userMessage || "Incident acknowledgement failed.");
    }
  };

  const handleResolveSubmit = async () => {
    if (!resolutionNotes.trim()) {
      toast.error(
        "Resolution notes are required before this incident can be closed.",
      );
      return;
    }
    if (!resolvingAlert) return;

    const incidentRef = resolvingAlert.incidentId || resolvingAlert.id;
    try {
      await apiClient.patch(
        `/incidents/${encodeURIComponent(incidentRef)}/status`,
        {
          status: "CLOSED",
          resolution_notes: resolutionNotes.trim(),
        },
      );
      setLogs((prev) => prev.filter((item) => item.id !== resolvingAlert.id));
      fetchIncidentSummary();
      toast.success("Incident resolved and closed.");
      setResolvingAlert(null);
      setResolutionNotes("");
    } catch (error) {
      toast.error(error.userMessage || "Incident resolution failed.");
    }
  };

  const handleOpenIncident = async (incident) => {
    if (!incident?.incidentId) return;
    setIncidentDetailLoading(true);
    setSelectedIncident({ incident, evidence: [] });
    try {
      const response = await apiClient.get(
        `/incidents/${encodeURIComponent(incident.incidentId)}`,
      );
      setSelectedIncident(response.data?.data || { incident, evidence: [] });
      if (canManageAlerts && incidentAssignees.length === 0) {
        try {
          const assigneeResponse = await apiClient.get("/incidents/assignees");
          setIncidentAssignees(assigneeResponse.data?.data || []);
        } catch {
          setIncidentAssignees([]);
        }
      }
    } catch (error) {
      toast.error(error.userMessage || "Unable to load incident evidence.");
      setSelectedIncident(null);
    } finally {
      setIncidentDetailLoading(false);
    }
  };

  const handleAssignIncident = async (assigneeId) => {
    const incidentId = selectedIncident?.incident?.incident_id || selectedIncident?.incident?.incidentId;
    if (!incidentId || !canManageAlerts) return;
    setIncidentAssignmentLoading(true);
    try {
      await apiClient.patch(
        `/incidents/${encodeURIComponent(incidentId)}/status`,
        { assignee_id: assigneeId || null },
      );
      const selectedAssignee = incidentAssignees.find((member) => member.id === assigneeId) || null;
      const detailResponse = await apiClient.get(`/incidents/${encodeURIComponent(incidentId)}`);
      if (detailResponse.data?.data) {
        setSelectedIncident(detailResponse.data.data);
      } else {
        setSelectedIncident((previous) => ({ ...previous, assignee: selectedAssignee }));
      }
      setLogs((previous) => previous.map((item) => (
        item.incidentId === incidentId
          ? { ...item, assigneeId: assigneeId || null }
          : item
      )));
      toast.success(selectedAssignee ? "Incident assigned." : "Incident assignment cleared.");
    } catch (error) {
      toast.error(error.userMessage || "Unable to update incident assignment.");
    } finally {
      setIncidentAssignmentLoading(false);
    }
  };

  const fetchFileDetails = async (analysisId) => {
    try {
      const res = await apiClient.get(`/upload/results/${analysisId}`);
      setIsLiveMode(false);
      isLiveModeRef.current = false;
      setGlobalQuery("");
      setSelectedFile(res.data);
      toast.info(`Viewing File: ${res.data.filename}`);
    } catch (err) {
      if (err.response && err.response.status === 401) {
        navigate('/login');
      } else {
        toast.error("Failed to load file details");
      }
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await apiClient.post('/upload/analyze', formData, {
        timeout: 120000, // 2 minutes allowed for deep CSV analysis
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      await fetchHistory();
      toast.success("File Uploaded & Parsed!");
      if (res.data.analysis_id) await fetchFileDetails(res.data.analysis_id);
    } catch (err) {
      toast.error(err.userMessage || "The file could not be uploaded. Please try again.");
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  };

  const executeSearch = async (searchQuery, filterDays) => {
    setLoading(true);
    try {
      let url = '/data/search?';
      if (searchQuery) url += `q=${encodeURIComponent(searchQuery)}&`;
      if (filterDays) url += `days=${filterDays}`;
      const res = await apiClient.get(url);
      const data = res.data;
      const results = Array.isArray(data.data)
        ? data.data
        : (Array.isArray(data.results) ? data.results : []);
      const resultCount = data.pagination?.count ?? data.count ?? results.length;
      setIsLiveMode(false);
      isLiveModeRef.current = false;
      setSelectedFile(null);
      if (results.length > 0) {
        setLogs(
          results.map((f, i) => {
            const context = f.context || {};
            return {
              id: f._id || i,
              time: f.timestamp || f.ingested_at,
              level: (f.severity || "INFO").toUpperCase(),
              message: f.message || f.title || f.event_id_meaning || "Security record",
              ip: context.source_address || f.source_ip || f.ip || "N/A",
              host: context.endpoint || f.computer || f.agent_id || "Unknown endpoint",
              engine: f.engine_source || f.telemetry_family || "Historical",
              eventId: f.event_id,
              context,
              recordType: f.record_type || "security_record",
              storageTier: f.storage_tier || "hot",
              status: f.status || "historical",
              occurrences: f.occurrences || 1,
              bannable: false,
            };
          }),
        );
        toast.success(`Found ${resultCount} alerts in history.`);
      } else {
        toast.info(`No threats found for this search criteria.`);
        setLogs([]);
      }
    } catch (err) {
      toast.error(err.userMessage || "Search could not be completed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleGlobalSearch = (e) => {
    if (e.key === "Enter" || e.type === "click")
      executeSearch(globalQuery.trim(), timeFilter);
  };

  const handleTimeFilterChange = (e) => {
    const selectedDays = e.target.value;
    setTimeFilter(selectedDays);
    executeSearch(globalQuery.trim(), selectedDays);
  };

  const handleBan = async (ip, ipIsBanned) => {
    try {
      if (ipIsBanned) {
        await apiClient.post('/revoke', { ip: ip, reason: "Manual Unblock" });
      } else {
        await apiClient.post('/mitigate', { ip: ip, reason: "Manual Ops" });
      }
      setBlockedList((prev) =>
        ipIsBanned ? prev.filter((b) => b !== ip) : [...prev, ip],
      );
    } catch {
      toast.error("Action Failed");
    }
  };

  const confirmDelete = async () => {
    if (!fileToDelete) return;
    try {
      await apiClient.delete(`/upload/results/${fileToDelete}`);
      if (
        selectedFile &&
        (selectedFile._id === fileToDelete ||
          selectedFile.analysisId === fileToDelete)
      ) {
        setSelectedFile(null);
        setIsLiveMode(true);
        isLiveModeRef.current = true;
        fetchLiveLogs();
        fetchAgentEvents();
      }
      await fetchHistory();
      toast.success("File deleted successfully.");
    } catch {
      toast.error("The request could not be completed. Please try again.");
    }
    setFileToDelete(null);
  };

  const handleLogout = async () => {
    setShowLogoutModal(false);
    await logout();
  };

  const handlePrepareAgentDownload = async () => {
    setGeneratingActivation(true);
    try {
      const response = await apiClient.post("/agent/generate-activation");
      setAgentActivation({
        code: response.data.activation_code,
        expiresInSeconds: response.data.expires_in_seconds,
      });
    } catch (error) {
      toast.error(error.userMessage || "Unable to generate an activation code.");
    } finally {
      setGeneratingActivation(false);
    }
  };

  const handleCopyActivation = async () => {
    try {
      await navigator.clipboard.writeText(agentActivation.code);
      toast.success("Activation code copied.");
    } catch {
      toast.error("Unable to copy the activation code.");
    }
  };

  const handleAgentInstallerDownload = () => {
    const baseUrl = String(
      apiClient.defaults.baseURL || "/api/v1",
    ).replace(/\/$/, "");
    window.location.assign(`${baseUrl}/agent/download`);
  };

  const handleDownloadReport = () => {
    const dataToReport = logs.length > 0 ? logs : selectedFile?.findings || [];
    if (dataToReport.length === 0) {
      toast.error("No data available to download.");
      return;
    }
    const doc = new jsPDF({ orientation: "landscape", unit: "mm", format: "a4" });
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
    doc.text("OPERATIONAL INCIDENT SUMMARY", 14, 32);
    doc.text(`REPORT ID: WS-${Date.now().toString().slice(-6)}`, 14, 38);
    doc.setTextColor(255, 255, 255);
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
      ["CRITICAL", "HIGH"].includes(
        String(l.level || l.severity || "").toUpperCase(),
      ),
    ).length;
    const uniqueAssets = [
      ...new Set(dataToReport.map((l) => l.host || l.ip).filter(Boolean)),
    ].length;

    let yPos = 65;
    const cardGap = 8;
    const cardWidth = (pageWidth - 28 - cardGap * 2) / 3;
    const drawCard = (x, title, value, color, labelColor) => {
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(x, yPos, cardWidth, 25, 2, 2, "FD");
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

    drawCard(14, "INCIDENTS", totalLogs, [59, 130, 246], [15, 23, 42]);
    drawCard(
      14 + cardWidth + cardGap,
      "CRITICAL THREATS",
      criticalCount,
      [239, 68, 68],
      [220, 38, 38],
    );
    drawCard(
      14 + (cardWidth + cardGap) * 2,
      "AFFECTED ASSETS",
      uniqueAssets,
      [16, 185, 129],
      [15, 23, 42],
    );

    yPos += 40;
    doc.setFontSize(12);
    doc.setTextColor(15, 23, 42);
    doc.text("Incident Timeline", 14, yPos);
    yPos += 5;

    const tableData = dataToReport.map((l) => [
      formatTime(l.time || l.timestamp),
      String(l.level || l.severity || "INFO").toUpperCase(),
      (l.message || l.title || "").substring(0, 60),
      l.host || "Unknown endpoint",
      l.actor || "Unknown",
      `x${l.occurrences || 1}`,
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [
        [
          "Timestamp",
          "Severity",
          "Event Description",
          "Endpoint",
          "Actor",
          "Count",
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
      margin: { left: 14, right: 14 },
      styles: {
        fontSize: 8,
        cellPadding: 2.5,
        overflow: "linebreak",
        valign: "middle",
        textColor: [51, 65, 85],
      },
      columnStyles: {
        0: { cellWidth: 23 },
        1: { cellWidth: 20 },
        2: { cellWidth: 91 },
        3: { cellWidth: 60 },
        4: { cellWidth: 55 },
        5: { cellWidth: 15, halign: "center" },
      },
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
    if (finalY + 45 > pageHeight - 18) {
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
        "- Isolate affected hosts (listed above) from the network immediately.",
        20,
        finalY + 25,
      );
      doc.text(
        "- Change administrative credentials and force logout for suspicious users.",
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
      doc.text("CONFIDENTIAL", pageWidth / 2, pageHeight / 2, {
        angle: 45,
        align: "center",
      });
      doc.restoreGraphicsState();
      doc.setFontSize(8);
      doc.setTextColor(100);
      doc.setGState(new doc.GState({ opacity: 1 }));
      doc.setDrawColor(200);
      doc.line(14, pageHeight - 15, pageWidth - 14, pageHeight - 15);
      doc.text(
        `WarSOC Security Report | Generated by ${currentUser?.username || "Admin"}`,
        14,
        pageHeight - 10,
      );
      doc.text(`Page ${i} of ${pageCount}`, pageWidth - 14, pageHeight - 10, {
        align: "right",
      });
    }
    doc.save(`WarSOC_Incident_Summary_${Date.now()}.pdf`);
  };

  useEffect(() => {
    if (selectedFile) {
      if (selectedFile.findings && selectedFile.findings.length > 0) {
        const fileLogs = selectedFile.findings.map((f, i) => ({
          id: i,
          time: f.timestamp,
          event_id: f.event_id || 0,
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

  const recentOpenIncidentsCount = incidentSummary?.open_total ?? logs.length;

  const correlationCount = incidentSummary?.correlation_open ?? logs.filter((log) =>
    /correlation|stateful/i.test(String(log.engine || "")),
  ).length;

  const ruleMatchCount = incidentSummary?.rule_match_open ?? Math.max(
    0,
    recentOpenIncidentsCount - correlationCount,
  );

  const {
    volumeData,
    severityData,
    logTypeData,
    endpointData,
    ruleData,
    mitreData,
    originData,
    triageStats,
  } = useMemo(() => {
    let crit = 0,
      high = 0,
      med = 0,
      info = 0;
    const timeMap = {};
    const typeMap = {};
    const endpointMap = {};
    const ruleMap = {};
    const mitreMap = {};
    const originMap = {};
    const now = Date.now();
    const selectedRangeMs = (timeFilter === "7" ? 7 : 1) * 24 * 60 * 60 * 1000;
    const rangeStart = now - selectedRangeMs;
    const bucketSize = timeFilter === "7" ? 6 * 60 * 60 * 1000 : 60 * 60 * 1000;

    logs.forEach((log) => {
      const level = (log.level || "INFO").toUpperCase();
      if (level === "CRITICAL") crit++;
      else if (level === "HIGH") high++;
      else if (level === "MEDIUM") med++;
      else info++;
      if (log.time) {
        const date = new Date(log.time);
        if (!Number.isNaN(date.getTime()) && date.getTime() >= rangeStart) {
          const bucket = Math.floor(date.getTime() / bucketSize) * bucketSize;
          timeMap[bucket] = (timeMap[bucket] || 0) + 1;
        }
      }

      const type = String(log.engine || log.recordType || "SIEM").replaceAll("_", " ");
      typeMap[type] = (typeMap[type] || 0) + 1;

      const endpoint = log.host || log.ip || "Unknown";
      endpointMap[endpoint] = (endpointMap[endpoint] || 0) + (log.occurrences || 1);
      const detectionRule = log.context?.rule_name || log.context?.match_reason || log.message;
      if (detectionRule) {
        const safeRuleLabel = String(detectionRule).trim().slice(0, 32) || "WarSOC detection";
        ruleMap[safeRuleLabel] = (ruleMap[safeRuleLabel] || 0) + (log.occurrences || 1);
      }
      const mitre = log.mitre || log.context?.mitre || log.context?.mitre_id;
      if (mitre) String(mitre).split(/[ ,/]+/).filter(Boolean).forEach((technique) => { mitreMap[technique] = (mitreMap[technique] || 0) + 1; });

      const origin =
        log.context?.country ||
        log.context?.geo_country ||
        log.context?.source_country ||
        (log.ip && log.ip !== "N/A" ? "External" : "Internal");
      originMap[origin] = (originMap[origin] || 0) + 1;
    });

    const severityData = [
      { name: "Critical", value: crit, color: "#ef4444" },
      { name: "High", value: high, color: "#f97316" },
      { name: "Medium", value: med, color: "#f59e0b" },
      { name: "Info", value: info, color: "#3b82f6" },
    ].filter((d) => d.value > 0);

    let volumeArray = Object.entries(timeMap)
      .map(([bucket, value]) => ({
        bucket: Number(bucket),
        name: new Date(Number(bucket)).toLocaleString([], {
          hour: "2-digit",
          minute: "2-digit",
          ...(timeFilter === "7" ? { month: "short", day: "numeric" } : {}),
        }),
        value,
      }))
      .sort((a, b) => a.bucket - b.bucket);

    if (volumeArray.length === 0) volumeArray = [{ name: "00:00", value: 0 }];
    else if (volumeArray.length === 1) {
      volumeArray.unshift({ name: "Earlier", value: 0 });
    }

    const logTypeData = Object.entries(typeMap)
      .map(([name, value], index) => ({
        name,
        value,
        color: ["#0d9488", "#3b82f6", "#8b5cf6", "#f59e0b", "#ef4444"][index % 5],
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);

    const endpointData = Object.entries(endpointMap)
      .map(([name, value]) => ({
        name: name.length > 20 ? `${name.slice(0, 18)}...` : name,
        value,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);

    const ruleData = Object.entries(ruleMap).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 5);
    const mitreData = Object.entries(mitreMap).map(([name, value], index) => ({
      name,
      value,
      color: ["#3b82f6", "#22d3ee", "#8b5cf6", "#14b8a6", "#f59e0b", "#ec4899"][index % 6],
    })).sort((a, b) => b.value - a.value).slice(0, 8);

    const originData = Object.entries(originMap)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);

    const triageStats = [
      { label: "New", value: logs.filter((log) => String(log.status || "new").toLowerCase() === "new").length },
      { label: "Ack", value: logs.filter((log) => String(log.status || "").toLowerCase() === "acknowledged").length },
      { label: "Closed", value: logs.filter((log) => ["closed", "resolved", "mitigated"].includes(String(log.status || "").toLowerCase())).length },
    ];

    return {
      volumeData: volumeArray,
      logTypeData: logTypeData.length ? logTypeData : [{ name: "No logs", value: 1, color: "#94a3b8" }],
      endpointData: endpointData.length ? endpointData : [{ name: "No endpoint activity", value: 0 }],
      ruleData,
      mitreData,
      originData: originData.length ? originData : [{ name: "No origin data", value: 0 }],
      severityData: severityData.length ? severityData : [{ name: "No threats", value: 1, color: "#94a3b8" }],
      triageStats,
    };
  }, [logs, timeFilter]);

  const chartClass = (id, base = "") => {
    return `chart-box chart-id-${id} ${base} ${draggedChart === id ? "chart-is-dragging" : ""} ${removingChartIds.includes(id) ? "chart-is-removing" : ""}`;
  };
  const removeChart = (id) => {
    if (removingChartIds.includes(id) || hiddenChartIds.includes(id)) return;
    setRemovingChartIds((current) => [...current, id]);
    window.setTimeout(() => {
      setHiddenChartIds((current) => current.includes(id) ? current : [...current, id]);
      setRemovingChartIds((current) => current.filter((item) => item !== id));
    }, 220);
  };
  const toggleChartVisibility = (id) => {
    setHiddenChartIds((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  };
  const visibleChartCount = DEFAULT_CHART_ORDER.length - hiddenChartIds.length;
  const chartDragProps = (id) => ({
    draggable: true,
    style: { order: chartOrder.indexOf(id) },
    onDragStart: (event) => {
      setDraggedChart(id);
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", id);
    },
    onDragOver: (event) => {
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
    },
    onDrop: (event) => {
      event.preventDefault();
      const sourceId = event.dataTransfer.getData("text/plain") || draggedChart;
      if (!sourceId || sourceId === id) return;
      setChartOrder((current) => {
        const next = current.filter((item) => item !== sourceId);
        const targetIndex = next.indexOf(id);
        next.splice(targetIndex < 0 ? next.length : targetIndex, 0, sourceId);
        return next;
      });
      setDraggedChart(null);
    },
    onDragEnd: () => setDraggedChart(null),
  });

  return (
    <div
      className={`siem-layout ${isMobileMenuOpen ? "" : "sidebar-closed"}`}
      data-theme={theme}
    >
      <ToastContainer
        position="bottom-right"
        theme={theme === "dark" ? "dark" : "light"}
      />

      <aside
        className={`siem-sidebar ${isMobileMenuOpen ? "mobile-open" : ""}`}
      >
        <button
          className="sidebar-close"
          type="button"
          aria-label="Close sidebar"
          title="Close sidebar"
          onClick={() => setIsMobileMenuOpen(false)}
        >
          <X size={20} />
        </button>
        <div className="logo-container">
          <div className="logo-box">
            <span className="brand-mark">
              <img src="/Logo.png" alt="WarSOC" />
            </span>
          </div>
        </div>
        <nav className="nav-links">
          {canViewOperations && (
            <>
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
                <Globe size={18} /> Observed Activity Map
              </button>
              <button
                className={activeTab === "endpoints" ? "active" : ""}
                onClick={() => setActiveTab("endpoints")}
              >
                <HardDrive size={18} /> Endpoints
              </button>
              <button
                className={activeTab === "offline-analysis" ? "active" : ""}
                onClick={() => setActiveTab("offline-analysis")}
              >
                <FileSearch size={18} /> Offline Log Analysis
              </button>
              {canViewRelay && (
                <button className={activeTab === "relays" ? "active" : ""} onClick={() => setActiveTab("relays")}><Server size={18} /> Firewall Relays</button>
              )}
            </>
          )}
          {!canViewOperations && canViewEndpointTrust && (
            <button
              className={activeTab === "endpoints" ? "active" : ""}
              onClick={() => setActiveTab("endpoints")}
            >
              <HardDrive size={18} /> Endpoints
            </button>
          )}
          {archiveEnabled && (
            <button className={activeTab === "archive" ? "active" : ""} onClick={() => setActiveTab("archive")}><FileText size={18} /> Archive Requests</button>
          )}
          {canViewCases && (
            <button className={activeTab === "cases" ? "active" : ""} onClick={() => setActiveTab("cases")}><FolderOpen size={18} /> Evidence Cases</button>
          )}
          {canViewHolds && (
            <button className={activeTab === "holds" ? "active" : ""} onClick={() => setActiveTab("holds")}><Scale size={18} /> Legal Holds</button>
          )}
          {canDownloadAgent && (
            <button
              className="nav-download-agent"
              onClick={handlePrepareAgentDownload}
              disabled={generatingActivation}
            >
              {generatingActivation ? (
                <RefreshCw size={18} className="activation-spinner" />
              ) : (
                <Download size={18} />
              )}
              {generatingActivation ? "Generating..." : "Download Agent"}
            </button>
          )}
          {canViewCompliance && (
            <button
              className={activeTab === "compliance" ? "active" : ""}
              onClick={() => setActiveTab("compliance")}
            >
              <ShieldCheck size={18} /> Compliance & Audit
            </button>
          )}
          {canManageTeam && (
            <button
              className={activeTab === "team" ? "active" : ""}
              onClick={() => setActiveTab("team")}
            >
              <Users size={18} /> Team & Access
            </button>
          )}
        </nav>
      </aside>
      {isMobileMenuOpen && (
        <button
          className="sidebar-scrim"
          type="button"
          aria-label="Close sidebar"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      <main className="siem-main">
        <header className="siem-header">
          <div className="header-brand-cluster">
            <button
              className="menu-toggle"
              type="button"
              aria-label="Open sidebar"
              title="Open sidebar"
              onClick={() => setIsMobileMenuOpen(true)}
            >
              <span className="menu-glyph" aria-hidden="true">
                <i></i>
                <i></i>
                <i></i>
              </span>
            </button>
            {!isMobileMenuOpen && (
              <div className="topbar-brand" aria-label="WarSOC">
                <img src="/Logo.png" alt="WarSOC" />
              </div>
            )}
          </div>
          <div className="search-wrapper">
            <div className="search-field">
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
                placeholder="Search event ID, source IP, user, agent ID or record ID"
                value={globalQuery}
                onChange={(e) => setGlobalQuery(e.target.value)}
                onKeyDown={handleGlobalSearch}
              />
            </div>
            <select
              value={timeFilter}
              onChange={handleTimeFilterChange}
              className="global-search"
            >
              <option value="1">Last 24 Hours</option>
              <option value="7">Last 7 Days</option>
            </select>
            <button className="btn-primary" onClick={handleGlobalSearch}>
              Search
            </button>
          </div>
          <div className="header-actions">
            <button
              className={`theme-toggle ${theme === "light" ? "is-light" : "is-dark"}`}
              onClick={toggleTheme}
              title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            >
              <span className="theme-switch-scene" aria-hidden="true">
                <span className="theme-switch-orb"></span>
                <span className="theme-switch-cloud cloud-one"></span>
                <span className="theme-switch-cloud cloud-two"></span>
              <span className="theme-switch-star star-one"></span>
              <span className="theme-switch-star star-two"></span>
              <span className="theme-switch-star star-three"></span>
            </span>
            </button>
            <div
              className={`live-pill ${!isLiveMode || telemetryStatus === "offline" ? "offline" : ""}`}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "7px 13px",
                background: !isLiveMode || telemetryStatus === "offline"
                  ? theme === "light"
                    ? "#eef2f7"
                    : "rgba(71, 85, 105, 0.28)"
                  : telemetryStatus === "degraded"
                    ? "rgba(245, 158, 11, 0.1)"
                    : "rgba(16, 185, 129, 0.1)",
                color: !isLiveMode || telemetryStatus === "offline"
                  ? theme === "light"
                    ? "#334155"
                    : "#cbd5e1"
                  : telemetryStatus === "degraded"
                    ? "#f59e0b"
                    : "#10b981",
                fontSize: "12px",
                fontWeight: "800",
                borderRadius: "20px",
                border: !isLiveMode || telemetryStatus === "offline"
                  ? theme === "light"
                    ? "1px solid rgba(71, 85, 105, 0.18)"
                    : "1px solid rgba(148, 163, 184, 0.18)"
                  : telemetryStatus === "degraded"
                    ? "1px solid rgba(245, 158, 11, 0.25)"
                    : "1px solid rgba(16, 185, 129, 0.2)",
                boxShadow: !isLiveMode || telemetryStatus === "offline"
                  ? theme === "light"
                    ? "inset 0 1px 0 rgba(255,255,255,0.85)"
                    : "none"
                  : "none",
                whiteSpace: "nowrap",
              }}
            >
              <div
                className={isLiveMode && telemetryStatus === "active" ? "pulse" : ""}
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  background: !isLiveMode || telemetryStatus === "offline"
                    ? theme === "light"
                      ? "#64748b"
                      : "#94a3b8"
                    : telemetryStatus === "degraded"
                      ? "#f59e0b"
                      : "#10b981",
                }}
              ></div>
              {!isLiveMode
                ? "HISTORICAL"
                : telemetryStatus === "active"
                  ? "ACTIVE"
                  : telemetryStatus === "degraded"
                    ? "DEGRADED"
                    : "NOT CONFIGURED"}
            </div>
            <div className="divider-v"></div>
            <UserMenu
              user={profileUser || currentUser}
              onProfile={() => navigate("/profile")}
              onLogout={() => setShowLogoutModal(true)}
            />
          </div>
        </header>

        {canViewOperations && activeTab === "dashboard" && (
          <EndpointContextStrip fleet={fleetStatus} selectedAgentId={selectedAgentId} onSelectAgent={setSelectedAgentId} />
        )}

        <div className="content-scrollable">
          <div className="dashboard-container">
            {activeTab === "dashboard" && (
              <>
                <div className="metrics-grid">
                  <MetricCard
                    title="Active Incidents"
                    value={recentOpenIncidentsCount}
                    icon={Shield}
                    color="#ef4444"
                    glow={recentOpenIncidentsCount > 0}
                  />
                  <MetricCard
                    title="Correlated Events"
                    value={correlationCount}
                    icon={BrainCircuit}
                    color="#f59e0b"
                  />
                  <MetricCard
                    title="Rule Matches"
                    value={ruleMatchCount}
                    icon={Zap}
                    color="#3b82f6"
                  />
                  <MetricCard
                    title="Blocked Addresses"
                    value={blockedList.length}
                    icon={Lock}
                    color="#10b981"
                  />
                </div>

                <div className="dashboard-widget-toolbar">
                  <div>
                    <span className="dashboard-widget-eyebrow">Dashboard layout</span>
                    <span className="dashboard-widget-hint">Drag widgets to reorder them, or hide the ones you do not need.</span>
                  </div>
                  <div className="dashboard-widget-customize">
                    <button type="button" className="widget-customize-button" onClick={() => setShowWidgetPicker((current) => !current)} aria-expanded={showWidgetPicker}>
                      <Settings2 size={15} /> Customize dashboard
                    </button>
                    {showWidgetPicker && (
                      <div className="widget-picker" role="dialog" aria-label="Customize dashboard widgets">
                        <div className="widget-picker-header"><strong>Dashboard widgets</strong><button type="button" className="widget-picker-close" onClick={() => setShowWidgetPicker(false)} aria-label="Close widget picker"><X size={14} /></button></div>
                        <p>Select the widgets you want visible.</p>
                        <div className="widget-picker-list">
                          {DASHBOARD_WIDGETS.map((widget) => {
                            const visible = !hiddenChartIds.includes(widget.id);
                            return <label className="widget-picker-option" key={widget.id}>
                              <input type="checkbox" checked={visible} onChange={() => toggleChartVisibility(widget.id)} />
                              <span>{widget.title}</span>
                            </label>;
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className={`soc-analytics-grid widget-count-${visibleChartCount}`}>
                  {!hiddenChartIds.includes("incident-trend") && <div className={chartClass("incident-trend", "chart-box-wide")} {...chartDragProps("incident-trend")}>
                    <ChartTitle title="Incident Volume Trend" meta={timeFilter === "7" ? "Last 7 days" : "Last 24 hours"} onRemove={() => removeChart("incident-trend")} />
                    <ResponsiveContainer width="100%" height={250}>
                      <AreaChart
                        data={volumeData}
                        margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                      >
                        <defs>
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
                  </div>}

                  {!hiddenChartIds.includes("source-locations") && <div className={chartClass("source-locations", "origin-map-card")} {...chartDragProps("source-locations")}>
                    <ChartTitle title="Observed Source Locations" meta={`${originData.reduce((sum, item) => sum + item.value, 0)} signals`} onRemove={() => removeChart("source-locations")} />
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={originData} layout="vertical" margin={{ top: 8, right: 18, left: 6, bottom: 6 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
                        <XAxis type="number" stroke="var(--dash-dim)" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis type="category" dataKey="name" width={78} stroke="var(--dash-dim)" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: "var(--dash-panel-strong)", borderColor: "var(--dash-border-strong)", borderRadius: "8px", color: "var(--dash-text)" }} />
                        <Bar dataKey="value" name="Signals" radius={[0, 8, 8, 0]} fill="#38bdf8" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>}

                  {!hiddenChartIds.includes("severity") && <div className={chartClass("severity", "chart-box-compact")} {...chartDragProps("severity")}>
                    <ChartTitle title="Threat Severity" meta="Open queue" onRemove={() => removeChart("severity")} />
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie
                          data={severityData}
                          cx="50%"
                          cy="50%"
                          innerRadius={58}
                          outerRadius={78}
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
                            backgroundColor: "var(--dash-panel-strong)",
                            borderColor: "var(--dash-border-strong)",
                            borderRadius: "8px",
                            color: "var(--dash-text)",
                          }}
                        />
                        <Legend
                          verticalAlign="bottom"
                          height={36}
                          iconType="circle"
                          wrapperStyle={{ fontSize: "12px", color: "var(--dash-muted)" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>}

                  {!hiddenChartIds.includes("telemetry-sources") && <div className={chartClass("telemetry-sources", "chart-box-compact")} {...chartDragProps("telemetry-sources")}>
                    <ChartTitle title="Telemetry Source Breakdown" meta="Top sources" onRemove={() => removeChart("telemetry-sources")} />
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie
                          data={logTypeData}
                          cx="50%"
                          cy="50%"
                          innerRadius={56}
                          outerRadius={78}
                          paddingAngle={4}
                          dataKey="value"
                          stroke="none"
                        >
                          {logTypeData.map((entry, index) => (
                            <Cell key={`type-cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "var(--dash-panel-strong)",
                            borderColor: "var(--dash-border-strong)",
                            borderRadius: "8px",
                            color: "var(--dash-text)",
                          }}
                        />
                        <Legend
                          verticalAlign="bottom"
                          height={42}
                          iconType="circle"
                          wrapperStyle={{ fontSize: "11px", color: "var(--dash-muted)" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>}

                  {!hiddenChartIds.includes("detection-rules") && <div className={chartClass("detection-rules", "chart-box-compact")} {...chartDragProps("detection-rules")}>
                    <ChartTitle title="Detection Rule Frequency" meta="WarSOC detections" onRemove={() => removeChart("detection-rules")} />
                    {ruleData.length ? <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={ruleData} layout="vertical" margin={{ top: 5, right: 18, left: 4, bottom: 4 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
                        <XAxis type="number" stroke="var(--dash-dim)" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis type="category" dataKey="name" width={112} stroke="var(--dash-dim)" fontSize={9} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: "var(--dash-panel-strong)", borderColor: "var(--dash-border-strong)", borderRadius: "8px", color: "var(--dash-text)" }} />
                        <Bar dataKey="value" name="Matches" radius={[0, 7, 7, 0]} fill="var(--primary-500)" />
                      </BarChart>
                    </ResponsiveContainer> : <div className="chart-empty-state">No detection rule matches recorded for this period.</div>}
                  </div>}

                  {!hiddenChartIds.includes("mitre") && <div className={chartClass("mitre", "chart-box-compact")} {...chartDragProps("mitre")}>
                    <ChartTitle title="MITRE ATT&CK Coverage" meta="Observed techniques" onRemove={() => removeChart("mitre")} />
                    {mitreData.length ? <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={mitreData} layout="vertical" margin={{ top: 5, right: 18, left: 4, bottom: 4 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
                        <XAxis type="number" stroke="var(--dash-dim)" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis type="category" dataKey="name" width={88} stroke="var(--dash-dim)" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: "var(--dash-panel-strong)", borderColor: "var(--dash-border-strong)", borderRadius: "8px", color: "var(--dash-text)" }} />
                        <Bar dataKey="value" name="Observed detections" radius={[0, 7, 7, 0]} fill="#8b5cf6" />
                      </BarChart>
                    </ResponsiveContainer> : <div className="chart-empty-state">No MITRE techniques recorded for this period.</div>}
                  </div>}

                  {!hiddenChartIds.includes("endpoint-load") && <div className={chartClass("endpoint-load", "chart-box-compact")} {...chartDragProps("endpoint-load")}>
                    <ChartTitle title="Endpoint Event Load" meta="Top assets" onRemove={() => removeChart("endpoint-load")} />
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart
                        data={endpointData}
                        layout="vertical"
                        margin={{ top: 8, right: 12, left: 12, bottom: 8 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
                        <XAxis type="number" stroke="var(--dash-dim)" fontSize={11} tickLine={false} axisLine={false} />
                        <YAxis
                          type="category"
                          dataKey="name"
                          stroke="var(--dash-dim)"
                          fontSize={11}
                          tickLine={false}
                          axisLine={false}
                          width={118}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "var(--dash-panel-strong)",
                            borderColor: "var(--dash-border-strong)",
                            borderRadius: "8px",
                            color: "var(--dash-text)",
                          }}
                        />
                        <Bar dataKey="value" radius={[0, 8, 8, 0]} fill="#0d9488" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>}

                  {!hiddenChartIds.includes("operations") && <div className={chartClass("operations", "chart-box-compact operations-card")} {...chartDragProps("operations")}>
                    <ChartTitle title="Operations Snapshot" meta="Now" onRemove={() => removeChart("operations")} />
                    <div className="ops-scoreboard">
                      {triageStats.map((item) => (
                        <div className="ops-tile" key={item.label}>
                          <strong>{item.value}</strong>
                          <span>{item.label}</span>
                        </div>
                      ))}
                      <div className="ops-tile">
                        <strong>{agentEvents.length}</strong>
                        <span>Telemetry</span>
                      </div>
                    </div>
                    <div className="ops-list">
                      <div className="ops-row">
                        <span>Blocked addresses</span>
                        <strong>{blockedList.length}</strong>
                      </div>
                      <div className="ops-row">
                        <span>Feed mode</span>
                        <strong>{isLiveMode ? "Live" : "History"}</strong>
                      </div>
                    </div>
                    <div className="ops-health">
                      <Server size={18} />
                      <span>{telemetryStatus === "active" ? "Collectors healthy" : telemetryStatus === "degraded" ? "Collector degraded" : "Collector offline"}</span>
                    </div>
                  </div>}
                  {hiddenChartIds.length === DEFAULT_CHART_ORDER.length && (
                    <div className="dashboard-widgets-empty">
                      <Sparkles size={20} />
                      <strong>No widgets here</strong>
                      <span>Click Customize dashboard to add some widgets back.</span>
                    </div>
                  )}
                </div>

                {isLiveMode && (
                  <div className="agent-logs-section">
                    <AgentLogs logs={agentEvents} />
                  </div>
                )}

                <div className="bottom-full-card">
                  <div className="logs-table-card">
                    <div className="table-header">
                      <div className="th-left">
                        <FileText size={16} />
                        <span>
                          {isLiveMode
                            ? "Live Security Threats"
                            : selectedFile ? "Offline Log Analysis" : "Historical Search Results"}
                        </span>
                      </div>
                      <div
                        className="th-right"
                        style={{
                          display: "flex",
                          gap: "12px",
                          alignItems: "center",
                        }}
                      >
                        {!isLiveMode && (
                          <button
                            className="return-live-btn"
                            onClick={async () => {
                              setSelectedFile(null);
                              setLogs([]);
                              setIsLiveMode(true);
                              isLiveModeRef.current = true;
                              await Promise.allSettled([
                                fetchLiveLogs(),
                                fetchIncidentSummary(),
                                fetchAgentEvents(),
                              ]);
                              toast.info("Switched back to Live Agent Feed");
                            }}
                          >
                            <RefreshCw size={14} /> Return to Live Feed
                          </button>
                        )}
                        {/* ── Upload Button ── */}
                        <label
                          className="btn-upload-inline"
                          title={loading ? "Uploading..." : "Upload log file (click or drag & drop)"}
                          style={{ cursor: loading ? "not-allowed" : "pointer" }}
                        >
                          {loading ? (
                            <div className="btn-upload-spinner" />
                          ) : (
                            <UploadCloud size={14} />
                          )}
                          <span>{loading ? "Uploading..." : "Upload Log File"}</span>
                          <input
                            type="file"
                            onChange={handleFileUpload}
                            disabled={loading}
                            style={{ display: "none" }}
                          />
                        </label>

                        <button
                          className="btn-primary"
                          onClick={handleDownloadReport}
                          style={{
                            height: "36px",
                            padding: "0 16px",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            gap: "6px",
                            whiteSpace: "nowrap",
                            fontWeight: "600",
                            borderRadius: "8px",
                          }}
                        >
                          <Download size={14} /> Export Report
                        </button>
                      </div>
                    </div>
                    <div className="table-body">
                      {incidentLoadState === "error" && isLiveMode && (
                        <div className="incident-feed-state incident-feed-state--error">
                          Incident stream temporarily interrupted. Background telemetry collection remains active.
                        </div>
                      )}
                      {incidentLoadState === "loading" && isLiveMode && logs.length === 0 && (
                        <div className="incident-feed-state">Loading threat feed...</div>
                      )}
                      {incidentLoadState === "ready" && isLiveMode && logs.length === 0 && (
                        <div className="incident-feed-state">No active threats detected. Real-time monitoring is active.</div>
                      )}
                      {!isLiveMode && logs.length === 0 && (
                        <div className="incident-feed-state" role="status">No records match this search window.</div>
                      )}
                      {logs.filter((log) => shouldDisplayLog(log, globalQuery, isLiveMode))
                        .map((log, i) => (
                          <div
                            key={log.id || i}
                            className={`tr ${log.status === "mitigated" ? "dimmed" : ""}`}
                            onClick={() => isLiveMode && log.recordType === "incident" && handleOpenIncident(log)}
                            role={isLiveMode && log.recordType === "incident" ? "button" : undefined}
                            tabIndex={isLiveMode && log.recordType === "incident" ? 0 : undefined}
                            onKeyDown={(event) => {
                              if (
                                isLiveMode &&
                                log.recordType === "incident" &&
                                (event.key === "Enter" || event.key === " ")
                              ) {
                                event.preventDefault();
                                handleOpenIncident(log);
                              }
                            }}
                            style={{
                              cursor: isLiveMode && log.recordType === "incident" ? "pointer" : "default",
                              backgroundColor:
                                log.level === "CRITICAL"
                                  ? "rgba(239, 68, 68, 0.08)"
                                  : log.level === "HIGH"
                                    ? "rgba(249, 115, 22, 0.08)"
                                    : "transparent",
                              borderLeft:
                                log.level === "CRITICAL"
                                  ? "3px solid #ef4444"
                                  : "none",
                            }}
                          >
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
                              {log.engine && log.engine !== "Stateless" && (
                                <span className={`engine-badge ${log.engine}`}>
                                  {log.engine}
                                </span>
                              )}
                              <span
                                className="msg-text"
                                style={{
                                  fontWeight:
                                    log.status === "acknowledged"
                                      ? "400"
                                      : "600",
                                }}
                              >
                                {log.message}
                              </span>
                              {log.occurrences > 1 && (
                                <span className="count-badge">
                                  x{log.occurrences}
                                </span>
                              )}
                              {log.status === "acknowledged" && (
                                <span
                                  className="badge info"
                                  style={{
                                    marginLeft: "8px",
                                    fontSize: "10px",
                                  }}
                                >
                                  ACKNOWLEDGED
                                </span>
                              )}
                            </div>
                            <div className="td ip-container">
                              <span
                                className="ip-tag"
                                style={{
                                  cursor: "pointer",
                                  transition: "0.2s",
                                }}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  if (!log.ip || log.ip === "N/A") return;
                                  setGlobalQuery(log.ip);
                                  executeSearch(log.ip, timeFilter);
                                  toast.info(
                                    `Searching source address: ${log.ip}`,
                                  );
                                }}
                                title={log.ip === "N/A" ? "No source address recorded" : "Search records for this address"}
                              >
                                {log.ip}
                              </span>
                            </div>
                            <div className="td action">
                              {isLiveMode && log.recordType === "incident" && canManageAlerts && log.status !== "acknowledged" && (
                                <button
                                  className="act-btn ack-btn"
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    handleAcknowledge(log.id);
                                  }}
                                >
                                  Acknowledge
                                </button>
                              )}
                              {isLiveMode && log.recordType === "incident" && canManageAlerts && (
                                <button
                                  className="act-btn resolve-btn"
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    setResolvingAlert(log);
                                  }}
                                >
                                  <CheckCircle size={13} /> Resolve
                                </button>
                              )}
                              {isLiveMode && log.recordType === "incident" && canManageAlerts && log.bannable && (
                                <button
                                  className={`act-btn ${blockedList.includes(log.ip) ? "unblock-btn" : "block-btn"}`}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    handleBan(
                                      log.ip,
                                      blockedList.includes(log.ip),
                                    );
                                  }}
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
                </div>
              </>
            )}

            {activeTab === "network" && (
              <div className="network-tab-wrapper">
                <div className="chart-box network-topology-card">
                  <div className="panel-header network-panel-header">
                    <h3>Security Topology</h3>
                    <div className="network-legend">
                      <span className="legend-endpoint">Endpoint</span>
                      <span className="legend-external">External source</span>
                      <span className="legend-blocked">Blocked</span>
                    </div>
                  </div>
                  <NetworkMap
                    logs={logs}
                    blockedList={blockedList}
                    canManage={canManageAlerts}
                    onBlockIP={(ip, isBanned) => handleBan(ip, isBanned)}
                  />
                </div>
              </div>
            )}

            {activeTab === "endpoints" && (
              <OperationsViews mode="fleet" onDownloadAgent={canDownloadAgent ? handlePrepareAgentDownload : undefined} />
            )}

            {activeTab === "offline-analysis" && (
              <OperationsViews mode="offline" />
            )}

            {canViewRelay && activeTab === "relays" && <OperationsViews mode="relay" />}
            {canViewCases && activeTab === "cases" && <EvidenceCases />}
            {canViewHolds && activeTab === "holds" && <LegalHolds />}
            {archiveEnabled && activeTab === "archive" && <OperationsViews mode="archive" />}

            {activeTab === "compliance" && (
              <div className="compliance-tab-wrapper">
                <ComplianceDashboard />
              </div>
            )}

            {activeTab === "team" && (
              <div className="team-tab-wrapper" style={{ marginTop: "20px" }}>
                <TeamManagement />
              </div>
            )}
          </div>
        </div>
      </main>

      {agentActivation && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="agent-activation-title">
          <div className="modal-card activation-modal">
            <div className="modal-header">
              <div>
                <h3 id="agent-activation-title" className="modal-filename">Agent Activation</h3>
                <span className="activation-expiry">
                  Single use - expires in {Math.max(1, Math.round(agentActivation.expiresInSeconds / 3600))} hours
                </span>
              </div>
              <button
                type="button"
                onClick={() => setAgentActivation(null)}
                className="close-btn modal-close-button"
                aria-label="Close agent activation"
                title="Close agent activation"
              >
                <span className="modal-close-glyph" aria-hidden="true">X</span>
              </button>
            </div>
            <div className="modal-body activation-body">
              <label className="activation-label">Activation code</label>
              <div className="activation-code-row">
                <code>{agentActivation.code}</code>
                <button type="button" className="activation-copy-btn" onClick={handleCopyActivation} title="Copy activation code">
                  <Copy size={18} />
                </button>
              </div>
            </div>
            <div className="modal-actions-right">
              <button className="btn-cancel" onClick={() => setAgentActivation(null)}>Cancel</button>
              <button className="btn-primary activation-download-btn" onClick={handleAgentInstallerDownload}>
                <Download size={18} /> Download Installer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
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

      {/* Logout Confirmation Modal */}
      {showLogoutModal && (
        <div className="modal-overlay logout-overlay">
          <div className="modal-card logout-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="logout-title">
            <div className="logout-modal-content">
              <div className="logout-icon" aria-hidden="true">
                <LogOut size={23} />
              </div>
              <div className="logout-copy">
                
                <h3 id="logout-title">Sign out of WarSOC?</h3>
                <p>Your active dashboard session will be securely closed on this device.</p>
              </div>
            </div>
            <div className="logout-modal-actions">
              <button
                className="btn-cancel"
                onClick={() => setShowLogoutModal(false)}
              >
                Cancel
              </button>
              <button className="btn-danger" onClick={handleLogout}>
                <LogOut size={16} /> Sign out
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View File Details Modal */}
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

      {selectedIncident && (
        <div
          className="modal-overlay"
          style={{ zIndex: 10000 }}
          onClick={() => setSelectedIncident(null)}
        >
          <div
            className="modal-card incident-detail-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-detail-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="modal-header incident-detail-header">
              <div>
                <span className={`badge ${(selectedIncident.incident?.severity || selectedIncident.incident?.level || "MEDIUM").toUpperCase()}`}>
                  {selectedIncident.incident?.severity || selectedIncident.incident?.level || "MEDIUM"}
                </span>
                <h3 id="incident-detail-title" className="modal-filename">
                  {selectedIncident.incident?.title || selectedIncident.incident?.message || "Security incident"}
                </h3>
                <span className="incident-reference">
                  {selectedIncident.incident?.incident_id || selectedIncident.incident?.incidentId}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="close-btn modal-close-button"
                aria-label="Close incident details"
                title="Close incident details"
              >
                <span className="modal-close-glyph" aria-hidden="true">X</span>
              </button>
            </div>
            <div className="modal-body scroll-custom incident-detail-body">
              {incidentDetailLoading ? (
                <div className="incident-feed-state">Loading incident evidence...</div>
              ) : (
                <>
                  <section className="incident-detail-section">
                    <h4>What happened</h4>
                    <p>{selectedIncident.incident?.message || "Security activity matched a configured detection rule."}</p>
                    <div className="incident-detail-grid">
                      <div><span>First seen</span><strong>{new Date(selectedIncident.incident?.first_seen || selectedIncident.incident?.firstSeen || selectedIncident.incident?.time).toLocaleString()}</strong></div>
                      <div><span>Last seen</span><strong>{new Date(selectedIncident.incident?.last_seen || selectedIncident.incident?.lastSeen || selectedIncident.incident?.time).toLocaleString()}</strong></div>
                      <div><span>Occurrences</span><strong>x{selectedIncident.incident?.occurrences || 1}</strong></div>
                      <div><span>Status</span><strong>{String(selectedIncident.incident?.status || "NEW").replaceAll("_", " ")}</strong></div>
                      <div><span>Workflow version</span><strong>{selectedIncident.incident?.workflow_version ?? 0}</strong></div>
                      <div>
                        <span>Assignee</span>
                        {canManageAlerts ? (
                          <select
                            className="incident-assignee-select"
                            value={selectedIncident.incident?.assignee_id || ""}
                            onChange={(event) => handleAssignIncident(event.target.value)}
                            disabled={incidentAssignmentLoading}
                          >
                            <option value="">Unassigned</option>
                            {incidentAssignees.map((member) => (
                              <option value={member.id} key={member.id}>
                                {member.full_name || member.username || member.email} ({member.role})
                              </option>
                            ))}
                          </select>
                        ) : (
                          <strong>{selectedIncident.assignee?.full_name || selectedIncident.assignee?.username || "Unassigned"}</strong>
                        )}
                      </div>
                    </div>
                  </section>

                  <section className="incident-detail-section">
                    <h4>Who and where</h4>
                    <div className="incident-detail-grid">
                      <div><span>Endpoint</span><strong>{selectedIncident.incident?.context?.endpoint || selectedIncident.incident?.host || "Unknown endpoint"}</strong></div>
                      <div><span>Actor</span><strong>{selectedIncident.incident?.context?.actor || selectedIncident.incident?.actor || "Unknown"}</strong></div>
                      <div><span>Target</span><strong>{selectedIncident.incident?.context?.target_user || selectedIncident.incident?.context?.target || selectedIncident.incident?.target || "Not recorded"}</strong></div>
                      <div><span>Source</span><strong>{selectedIncident.incident?.context?.source_address || selectedIncident.incident?.ip || "Not recorded"}{selectedIncident.incident?.context?.source_port ? `:${selectedIncident.incident.context.source_port}` : ""}</strong></div>
                      <div><span>Actor identity</span><strong>{[selectedIncident.incident?.context?.actor_domain, selectedIncident.incident?.context?.actor_sid].filter(Boolean).join(" / ") || "Not recorded"}</strong></div>
                      <div><span>Agent</span><strong>{selectedIncident.incident?.context?.agent_id || "Not recorded"}</strong></div>
                    </div>
                  </section>

                  <section className="incident-detail-section">
                    <h4>How it happened</h4>
                    <div className="incident-detail-grid">
                      <div><span>Process</span><strong>{selectedIncident.incident?.context?.process_name || "Not recorded"}</strong></div>
                      <div><span>Process ID</span><strong>{selectedIncident.incident?.context?.process_id || "Not recorded"}</strong></div>
                      <div><span>Parent process</span><strong>{selectedIncident.incident?.context?.parent_process || "Not recorded"}</strong></div>
                      <div><span>Parent process ID</span><strong>{selectedIncident.incident?.context?.parent_process_id || "Not recorded"}</strong></div>
                      <div><span>Destination</span><strong>{selectedIncident.incident?.context?.destination_address || "Not recorded"}{selectedIncident.incident?.context?.destination_port ? `:${selectedIncident.incident.context.destination_port}` : ""}</strong></div>
                      <div><span>Protected object</span><strong>{selectedIncident.incident?.context?.protected_object || "Not recorded"}</strong></div>
                      <div><span>Protocol / direction</span><strong>{[selectedIncident.incident?.context?.protocol, selectedIncident.incident?.context?.direction].filter(Boolean).join(" / ") || "Not recorded"}</strong></div>
                      <div><span>Outcome</span><strong>{selectedIncident.incident?.context?.outcome || "Not recorded"}</strong></div>
                    </div>
                    {selectedIncident.incident?.context?.command_line && (
                      <div className="incident-command"><span>Command</span><code>{selectedIncident.incident.context.command_line}</code></div>
                    )}
                  </section>

                  <section className="incident-detail-section">
                    <h4>Why WarSOC raised it</h4>
                    <div className="incident-detail-grid">
                      <div><span>Detection reference</span><strong>Managed detection</strong></div>
                      <div><span>Event ID</span><strong>{selectedIncident.incident?.event_id || selectedIncident.incident?.eventId || "Not recorded"}</strong></div>
                      <div><span>MITRE</span><strong>{selectedIncident.incident?.mitre || "Not mapped"}</strong></div>
                      <div><span>Reason</span><strong>{selectedIncident.incident?.context?.match_reason || selectedIncident.incident?.message || "Configured rule match"}</strong></div>
                      <div><span>Engine</span><strong>{selectedIncident.incident?.engine_source || "SIEM"}</strong></div>
                      <div><span>Evidence channel</span><strong>{[selectedIncident.incident?.context?.channel, selectedIncident.incident?.context?.provider, selectedIncident.incident?.context?.record_id].filter(Boolean).join(" / ") || "Not recorded"}</strong></div>
                    </div>
                  </section>

                  <section className="incident-detail-section">
                    <h4>Evidence</h4>
                    {selectedIncident.evidence_coverage && (
                      <div className="incident-coverage">
                        <span>{selectedIncident.evidence_coverage.returned} returned</span>
                        <span>{selectedIncident.evidence_coverage.hot} hot</span>
                        <span>{selectedIncident.evidence_coverage.cold_archive} secure cloud archive</span>
                        <span>{selectedIncident.evidence_coverage.occurrence_total} occurrences</span>
                        {selectedIncident.evidence_coverage.tracking_bounded && <span>Reference list bounded</span>}
                      </div>
                    )}
                    {(selectedIncident.evidence || []).length === 0 ? (
                      <p>No evidence preview was returned. The incident references remain available through the evidence vault.</p>
                    ) : (
                      <div className="incident-evidence-list">
                        {selectedIncident.evidence.slice(0, 20).map((evidence, index) => (
                          <div className="incident-evidence-row" key={evidence.alert_uid || evidence.event_uid || evidence._id || index}>
                            <span>{formatTime(evidence.timestamp || evidence.ingested_at)}</span>
                            <strong>{evidence.event_id || evidence.type || "Event"}</strong>
                            <span>{evidence.message || evidence.summary || "Security evidence"}</span>
                            <em>{evidence.storage_tier === "cold_archive" ? "Secure cloud archive" : "Hot storage"}</em>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>

                  <section className="incident-detail-section">
                    <h4>Investigation timeline</h4>
                    {(selectedIncident.workflow_history || []).length === 0 ? (
                      <p>No workflow activity has been recorded.</p>
                    ) : (
                      <div className="incident-timeline">
                        {selectedIncident.workflow_history.map((entry, index) => (
                          <div className="incident-timeline-row" key={entry.audit_id || `${entry.timestamp}-${index}`}>
                            <span>{new Date(entry.timestamp).toLocaleString()}</span>
                            <strong>{String(entry.action || "updated").replaceAll("_", " ")}</strong>
                            <p>
                              {entry.operator || "Unknown operator"}
                              {entry.operator_role ? ` (${entry.operator_role})` : ""}
                              {entry.resolution_notes ? `: ${entry.resolution_notes}` : ""}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 🚀 THE NEW ALERT RESOLUTION MODAL */}
{/* 🚀 THE ENTERPRISE ALERT RESOLUTION MODAL */}
      {resolvingAlert && (
        <div className="modal-overlay">
          <div className="modal-card resolution-box">
            
            <div className="modal-head-row">
              <div className="icon-wrapper"><ShieldCheck size={24} /></div>
              <h3>Resolve Incident</h3>
            </div>
            
            <div className="modal-body-content">
              <p className="incident-context">
                You are about to close this incident. Resolution notes become part of its audit history:
              </p>
              <div className="incident-target">
                <strong>{resolvingAlert.message}</strong>
                <span className="target-ip">Source or endpoint: {resolvingAlert.ip || "Not recorded"}</span>
              </div>
              
              <textarea
                className="resolution-input"
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                placeholder="E.g., Isolated the host, verified payload, and reset user credentials..."
                autoFocus
              />
            </div>

            <div className="modal-actions-right">
              <button className="btn-cancel" onClick={() => { setResolvingAlert(null); setResolutionNotes(""); }}>Cancel</button>
              <button className="btn-primary confirm-resolve" onClick={handleResolveSubmit} disabled={!resolutionNotes.trim()}>
                Close Incident
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
import { shouldDisplayLog } from "../../../utils/logSearch";
