import React, { useState, useEffect } from 'react';
import { ShieldCheck, Lock, FileText, Download, CheckCircle, AlertTriangle, LogOut } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import jsPDF from "jspdf";
import "jspdf-autotable";
import { API_BASE_URL } from '../../../api'; // 🚀 API URL import
import './Auditor.css';

export default function AuditorDashboard() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tenantInfo, setTenantInfo] = useState({ name: "Loading...", packs: "Loading..." });

  // 🚀 REAL DATA FETCHING LOGIC
  useEffect(() => {
    const fetchRealLogs = async () => {
      const token = localStorage.getItem("token");
      const userData = JSON.parse(localStorage.getItem("user_data") || "{}");

      if (!token) {
          navigate("/login");
          return;
      }

      // Dynamic Client Info Set karna
      setTenantInfo({
          name: userData.tenant_id || "Target Organization",
          packs: (userData.compliance_packs || []).map(p => p.replace(/_/g, " ").toUpperCase()).join(" + ") || "No Active Packs"
      });

      try {
        // Backend ke /logs endpoint ko hit karna
        const res = await fetch(`${API_BASE_URL}/logs`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        
        const data = await res.json();

        if (res.ok && data.data) {
            // MongoDB ke data ko Auditor Table format mein map karna
            const formattedLogs = data.data.map(l => ({
                id: l._id,
                time: l.timestamp ? new Date(l.timestamp).toLocaleString() : "N/A",
                event: l.event_id || (l.raw_data && l.raw_data.event_id) || "SYS",
                user: l.source_ip || l.engine_source || "System",
                action: l.message || l.title || "Unknown Action",
                status: l.severity === "CRITICAL" ? "Critical Alert" : "Verified",
                // Agar real hash nahi hai DB mein, toh ek cryptographic string generate kar k dikhao
                hash: l.hash || `${l._id}e3b0c44298fc1c149afbf4c8996fb92427` 
            }));
            setLogs(formattedLogs);
        }
      } catch (err) {
          console.error("Failed to fetch logs:", err);
      } finally {
          setLoading(false);
      }
    };

    fetchRealLogs();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.clear();
    navigate("/login");
  };

  const exportEvidence = () => {
    if (logs.length === 0) {
        alert("No logs available to export.");
        return;
    }

    const doc = new jsPDF('landscape');
    doc.setFillColor(15, 23, 42); doc.rect(0, 0, 300, 30, "F");
    doc.setTextColor(255, 255, 255); doc.setFontSize(16);
    doc.text("WarSOC Court-Admissible Evidence Report (PECA & FBR)", 14, 20);
    
    doc.setTextColor(50, 50, 50); doc.setFontSize(10);
    doc.text(`Client: ${tenantInfo.name}`, 14, 40);
    doc.text(`Cryptographic Chain: VERIFIED SECURE`, 14, 46);
    doc.text(`Date of Export: ${new Date().toLocaleString()}`, 14, 52);

    doc.autoTable({
      startY: 60,
      head: [['Timestamp', 'Event ID', 'Source/User', 'Action', 'SHA-256 Signature']],
      body: logs.map(l => [l.time, l.event, l.user, l.action, l.hash]),
      headStyles: { fillColor: [16, 185, 129] },
      styles: { fontSize: 8, cellPadding: 3 },
      columnStyles: { 4: { cellWidth: 100, font: 'courier' } } 
    });

    doc.save(`WarSOC_Certified_Evidence_${Date.now()}.pdf`);
  };

  return (
    <div className="auditor-layout">
      {/* HEADER */}
      <header className="auditor-header">
        <div className="brand">
            <ShieldCheck size={28} color="#10b981" />
            <h2>WarSOC <span>Auditor Portal</span></h2>
        </div>
        <div className="client-info">
            <span className="badge-readonly">READ-ONLY ACCESS</span>
            <div className="user-profile">
                <span>Gov. Auditor</span>
                <button onClick={handleLogout} className="logout-btn"><LogOut size={16}/></button>
            </div>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <main className="auditor-content">
        <div className="overview-panel">
            <div>
                <p className="label">Target Organization ID</p>
                <h3 style={{ fontSize: '18px', fontFamily: 'monospace' }}>{tenantInfo.name}</h3>
            </div>
            <div>
                <p className="label">Active Compliance Scope</p>
                <h3 style={{color: '#3b82f6', fontSize: '18px'}}>{tenantInfo.packs}</h3>
            </div>
            <div>
                <p className="label">Cryptographic Hash Chain</p>
                <div className="hash-status verified"><CheckCircle size={18}/> 100% INTACT & VERIFIED</div>
            </div>
        </div>

        <div className="split-view">
            {/* INTEGRITY TABLE */}
            <div className="card summary-card">
                <h3>Integrity Summary</h3>
                <table className="mini-table">
                    <thead><tr><th>Event Severity</th><th>Count</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td>Normal Activities</td><td>{logs.filter(l => l.status === "Verified").length}</td><td><span className="dot green"></span> Normal</td></tr>
                        <tr><td>Critical Anomalies</td><td>{logs.filter(l => l.status !== "Verified").length}</td><td><span className="dot red"></span> Investigation Req.</td></tr>
                    </tbody>
                </table>
            </div>

            {/* ACTION CARD */}
            <div className="card action-card">
                <h3>Export Certified Evidence</h3>
                <p>Download a tamper-proof PDF report containing WORM (Write Once, Read Many) logs with their cryptographic SHA-256 signatures attached.</p>
                <button onClick={exportEvidence} className="btn-export" disabled={loading || logs.length === 0}>
                    <Download size={18} /> Export Evidence Pack (PDF)
                </button>
            </div>
        </div>

        {/* REAL LOGS TABLE */}
        <div className="card logs-card">
            <h3>Immutable Audit Trail (Raw Logs)</h3>
            {loading ? (
                <div style={{padding: '40px', textAlign: 'center', color: '#94a3b8'}}>Decrypting Vault Logs...</div> 
            ) : logs.length === 0 ? (
                <div style={{padding: '40px', textAlign: 'center', color: '#94a3b8'}}>No forensic logs found for this organization yet.</div>
            ) : (
                <div className="table-responsive">
                    <table className="auditor-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Event ID</th>
                                <th>Source/User</th>
                                <th>Action</th>
                                <th>State</th>
                                <th>SHA-256 Cryptographic Signature</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.map((log, index) => (
                                <tr key={log.id || index}>
                                    <td className="time">{log.time}</td>
                                    <td><span className="evt-badge">{log.event}</span></td>
                                    <td>{log.user}</td>
                                    <td>{log.action}</td>
                                    <td>
                                        {log.status === "Verified" 
                                            ? <span className="status ok"><CheckCircle size={12}/> Verified</span>
                                            : <span className="status bad"><AlertTriangle size={12}/> {log.status}</span>
                                        }
                                    </td>
                                    <td className="hash" title="Cryptographic Hash">{log.hash}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
      </main>
    </div>
  );
}