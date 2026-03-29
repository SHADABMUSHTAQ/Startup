import React, { useState, useEffect } from 'react';
import { ShieldCheck, Database, FileText, Download, ArrowLeft, Activity, Lock } from 'lucide-react';
import { toast } from 'react-toastify';
import jsPDF from "jspdf";
import "jspdf-autotable";
import './Compliance.css';
import { API_BASE_URL } from '../../../api'; // Adjust path if needed

export default function ComplianceDashboard() {
  const [packs, setPacks] = useState([]);
  const [userPurchasedPacks, setUserPurchasedPacks] = useState([]); // 🚀 NAYA STATE
  const [selectedPackId, setSelectedPackId] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [config, setConfig] = useState(null);

useEffect(() => {
    // 1. Backend se Catalog mangwana
    fetch('http://localhost:8000/api/v1/compliance/packs')
      .then(res => { if(!res.ok) throw new Error("API Error"); return res.json(); })
      .then(data => setPacks(Array.isArray(data) ? data : []))
      .catch(() => setPacks([]));

    // 🚀 2. THE FIX: Instant Unlock Logic
    const token = localStorage.getItem("token");
    
    // Step A: Pehle LocalStorage check karein (Instant unlock for smooth UI)
    const localUser = JSON.parse(localStorage.getItem("user_data") || "{}");
    if (localUser.compliance_packs) {
        setUserPurchasedPacks(localUser.compliance_packs);
    }

    // Step B: Phir naye Backend API se double verify karein (Bulletproof)
    fetch(`${API_BASE_URL}/auth/my-packs`, {
        headers: { "Authorization": `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => {
          if (data.compliance_packs) {
              setUserPurchasedPacks(data.compliance_packs); 
              // Local storage ko bhi sync rakhein
              localUser.compliance_packs = data.compliance_packs;
              localStorage.setItem("user_data", JSON.stringify(localUser));
          }
      }).catch(err => console.log("Failed to fetch user packs", err));
  }, []);

  useEffect(() => {
    if (selectedPackId) {
      fetch(`http://localhost:8000/api/v1/compliance/packs/${selectedPackId}`)
        .then(res => res.json())
        .then(data => setConfig(data));
    }
  }, [selectedPackId]);

// 🚀 3. THE MAGIC: Generate and Download REAL Reports from Database
  const downloadReport = async (type) => {
    if (!config) return;
    
    // Naya: Backend se specific pack ke logs mangwana
    try {
        const token = localStorage.getItem("token");
        const res = await fetch(`http://localhost:8000/api/v1/logs?pack=${config.pack_id}`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        
        if (!res.ok) throw new Error("Failed to fetch logs");
        const data = await res.json();
        
        // Agar koi log na ho toh bata do
        if (!data.data || data.data.length === 0) {
            toast.info(`No active alerts found for ${config.name} yet.`);
            return;
        }

        const realLogs = data.data;

        if (type === 'csv') {
          // Asli Logs se CSV banana
          let csvContent = "data:text/csv;charset=utf-8,Timestamp,EventID,Severity,Description,Source IP\n";
          
          realLogs.forEach(log => {
              const row = [
                  log.timestamp,
                  log.event_id || "N/A",
                  log.severity || "INFO",
                  `"${(log.message || "Unknown Event").replace(/"/g, '""')}"`, // Handle commas/quotes in message
                  log.source_ip || log.ip || "N/A"
              ].join(",");
              csvContent += row + "\n";
          });

          const encodedUri = encodeURI(csvContent);
          const link = document.createElement("a");
          link.setAttribute("href", encodedUri);
          link.setAttribute("download", `${config.name}_Audit_Log_${new Date().toISOString().slice(0,10)}.csv`);
          document.body.appendChild(link);
          link.click();
          link.remove();
          toast.success("Real CSV Audit Log Downloaded!");
          
        } else if (type === 'pdf') {
          // Real PDF Logic
          const doc = new jsPDF();
          doc.setFillColor(15, 23, 42); doc.rect(0, 0, 210, 30, "F");
          doc.setTextColor(255, 255, 255); doc.setFontSize(18);
          doc.text("WarSOC Enterprise Evidence Summary", 14, 20);
          
          doc.setTextColor(50, 50, 50); doc.setFontSize(12);
          doc.text(`Framework: ${config.name}`, 14, 40);
          doc.text(`Date Generated: ${new Date().toLocaleString()}`, 14, 48);
          doc.text(`Status: Active Monitoring (${realLogs.length} Events Logged)`, 14, 56);
          
          // Monitored Events ka Table
          doc.autoTable({
            startY: 65, head: [['Event ID', 'Monitored Rule / Control', 'Severity Check']],
            body: config.monitored_events.map(e => [e.id, e.name, e.severity]),
            headStyles: { fillColor: [59, 130, 246] }
          });
          
          doc.save(`${config.name}_Summary.pdf`);
          toast.success("Real PDF Evidence Summary Downloaded!");
        }
        
    } catch (error) {
        console.error("Report Generation Error:", error);
        toast.error("Error generating report from live data.");
    }
  };

  // =========================================================
  // VIEW 1: THE CATALOG (Cards with Lock System)
  // =========================================================
  if (!selectedPackId) {
    return (
      <div className="compliance-dashboard" style={{padding: '20px 0'}}>
        <h2>Compliance & Audit Center</h2>
        <p>Manage your regulatory compliance packs and evidence vaults.</p>
        <div className="pack-grid">
          {Array.isArray(packs) && packs.length > 0 ? packs.map(pack => {
            // 🚀 THE LOCK LOGIC
            const isUnlocked = userPurchasedPacks.includes(pack.pack_id);

            return (
            <div key={pack.pack_id} className="pack-card" style={{ opacity: isUnlocked ? 1 : 0.6, position: 'relative' }}>
              {!isUnlocked && (
                  <div style={{ position: 'absolute', top: '-15px', right: '-15px', background: '#ef4444', color: '#fff', padding: '10px', borderRadius: '50%', boxShadow: '0 0 15px rgba(239,68,68,0.5)' }}>
                      <Lock size={20} />
                  </div>
              )}
              <ShieldCheck size={40} className="pack-icon" style={{ color: isUnlocked ? '#3b82f6' : '#64748b' }} />
              <h3>{pack.name}</h3>
              <p>{pack.description}</p>
              <div className="pack-meta">
                 <Database size={16}/> Vault Retention: {pack.retention.vault_days / 365} Years
              </div>
              {isUnlocked ? (
                  <button onClick={() => setSelectedPackId(pack.pack_id)}>Open Pack Dashboard</button>
              ) : (
                  <button style={{ background: 'transparent', color: '#ef4444', borderColor: '#ef4444', cursor: 'not-allowed' }}>
                    Upgrade Plan to Unlock
                  </button>
              )}
            </div>
          )}) : <div style={{color: '#94a3b8'}}>No packs found. Check backend connection.</div>}
        </div>
      </div>
    );
  }

  // =========================================================
  // VIEW 2: THE PACK DETAIL
  // =========================================================
  if (!config) return <div style={{padding: '50px', color: '#fff'}}>Loading Enterprise Framework...</div>;

  return (
    <div className="pack-detail-page" style={{padding: '0px'}}>
      <button onClick={() => {setSelectedPackId(null); setConfig(null); setActiveTab('overview');}} style={{display: 'flex', alignItems: 'center', gap: '8px', background: 'transparent', color: '#94a3b8', border: 'none', cursor: 'pointer', marginBottom: '20px', fontSize: '16px'}}>
        <ArrowLeft size={18} /> Back to Catalog
      </button>
      <div className="pack-header">
        <h1>{config.name}</h1>
        <span className="status-badge active">Monitoring Active</span>
      </div>
      <div className="tabs-nav">
        <button onClick={() => setActiveTab('overview')} className={activeTab === 'overview' ? 'active' : ''}>Overview</button>
        <button onClick={() => setActiveTab('controls')} className={activeTab === 'controls' ? 'active' : ''}>Controls</button>
        <button onClick={() => setActiveTab('evidence')} className={activeTab === 'evidence' ? 'active' : ''}>Evidence & Retention</button>
        <button onClick={() => setActiveTab('reports')} className={activeTab === 'reports' ? 'active' : ''}>Reports</button>
      </div>
      <div className="tab-content">
        {activeTab === 'overview' && (
          <div className="overview-tab">
            <h3><Activity size={20} style={{display:'inline', marginRight: '10px'}}/> Pack Health</h3>
            <p style={{fontSize: '1.1rem', color: '#cbd5e1', marginBottom: '10px'}}>Hot Storage (Fast Search): <b style={{color: '#3b82f6'}}>{config.retention.local_hot_days} Days</b></p>
            <p style={{fontSize: '1.1rem', color: '#cbd5e1'}}>Cloud Vault (Immutable): <b style={{color: '#10b981'}}>{config.retention.vault_days} Days</b></p>
          </div>
        )}
        {activeTab === 'controls' && (
          <div className="controls-tab">
            <h3>Monitored Rules & Event IDs</h3>
            <table className="enterprise-table">
              <thead><tr><th>Event ID</th><th>Rule Name</th><th>Severity</th></tr></thead>
              <tbody>
                {config.monitored_events.map(ev => (
                  <tr key={ev.id}>
                    <td><span style={{background: '#1e293b', padding: '4px 8px', borderRadius: '4px', border: '1px solid #334155'}}>{ev.id}</span></td>
                    <td>{ev.name}</td>
                    <td><span className={`badge ${ev.severity.toLowerCase()}`}>{ev.severity}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {activeTab === 'evidence' && (
          <div className="overview-tab">
             <h3><Lock size={20} style={{display:'inline', marginRight: '10px'}}/> Cryptographic Chain of Custody</h3>
             <p style={{lineHeight: '1.6'}}>All logs mapped to this framework are hashed using SHA-256 and stored in the immutable cloud vault. Tampering will invalidate the cryptographic chain. Your data is audit-ready and court-admissible.</p>
          </div>
        )}
        {activeTab === 'reports' && (
          <div className="reports-tab">
            <h3>Auditor Ready Reports</h3>
            <p style={{color: '#94a3b8', marginBottom: '20px'}}>Generate compliance-ready artifacts for external auditors and government agencies.</p>
            <div style={{display: 'flex', gap: '15px'}}>
                <button className="export-btn" onClick={() => downloadReport('csv')} style={{background: '#3b82f6'}}><Download size={18} /> Generate Auditor CSV</button>
                <button className="export-btn" onClick={() => downloadReport('pdf')} style={{background: '#10b981'}}><FileText size={18} /> Generate Evidence Summary</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}