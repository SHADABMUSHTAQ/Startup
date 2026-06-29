import React, { useState, useEffect } from 'react';
import { ShieldCheck, Database, FileText, Download, ArrowLeft, Activity, Lock, Key, AlertTriangle } from 'lucide-react';
import { useNavigate } from 'react-router-dom'; // 🚀 NAYA: Pricing page par bhejne ke liye
import { toast } from 'react-toastify';
import jsPDF from "jspdf";
import "jspdf-autotable";
import './Compliance.css';
import apiClient from '../../../api/apiClient';
import { useAuthStore } from '../../../store/authStore'; 

// 🚀 ENTERPRISE FALLBACK CATALOG (In case API is down)
const fallbackCatalog = [
  {
    pack_id: "fbr_pos_shield",
    name: "FBR POS Integrity Shield",
    description: "Continuous monitoring for FBR Point-of-Sale systems. Ensures log immutability.",
    retention: { vault_days: 1095 } // 3 years
  },
  {
    pack_id: "peca_vault",
    name: "PECA Forensic Vault",
    description: "Secure, tamper-proof audit trails meeting PECA digital evidence standards.",
    retention: { vault_days: 1825 } // 5 years
  }
];

const getFallbackConfig = (packId) => {
    if (packId === "fbr_pos_shield") {
        return {
            pack_id: "fbr_pos_shield", name: "FBR POS Integrity Shield",
            retention: { local_hot_days: 90, vault_days: 1095 },
            monitored_events: [
                { id: "FBR-001", name: "POS Receipt Tampering", severity: "CRITICAL" },
                { id: "FBR-002", name: "Tax Engine Bypass", severity: "HIGH" }
            ]
        };
    } else {
        return {
            pack_id: "peca_vault", name: "PECA Forensic Vault",
            retention: { local_hot_days: 180, vault_days: 1825 },
            monitored_events: [
                { id: "PECA-101", name: "Unauthorized Access Attempt", severity: "HIGH" },
                { id: "PECA-102", name: "Forensic Log Deletion", severity: "CRITICAL" }
            ]
        };
    }
};

export default function ComplianceDashboard() {
  const navigate = useNavigate(); // 🚀 Navigation Hook initialization
  const { user, checkAuth } = useAuthStore();
  const [packs, setPacks] = useState([]);
  const [userPurchasedPacks, setUserPurchasedPacks] = useState([]); 
  const [selectedPackId, setSelectedPackId] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [config, setConfig] = useState(null);
  
  const [evidenceLogs, setEvidenceLogs] = useState([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);

    useEffect(() => {
      apiClient.get('/compliance/packs')
        .then(res => {
          if (Array.isArray(res.data) && res.data.length > 0) setPacks(res.data);
          else setPacks(fallbackCatalog);
        })
        .catch(() => setPacks(fallbackCatalog)); 

      if (user?.compliance_packs && Array.isArray(user.compliance_packs)) {
        setUserPurchasedPacks(user.compliance_packs);
      }

      // Silent sync: refresh user state via Zustand instead of manual fetch/localStorage
      checkAuth().then(() => {
          const freshUser = useAuthStore.getState().user;
          if (freshUser?.compliance_packs) {
              setUserPurchasedPacks(freshUser.compliance_packs);
          }
      }).catch(err => console.log("Silent sync failed", err));
    }, [user?.compliance_packs, checkAuth]);

  useEffect(() => {
    if (selectedPackId) {
      apiClient.get(`/compliance/packs/${selectedPackId}`)
        .then(res => setConfig(res.data))
        .catch(() => {
            console.warn("Using fallback config data for presentation");
            setConfig(getFallbackConfig(selectedPackId)); 
        });
    }
  }, [selectedPackId]);

  useEffect(() => {
    if (activeTab === 'evidence' && config) {
        setLoadingEvidence(true);
        apiClient.get(`/compliance/evidence?pack_id=${config.pack_id}`)
        .then(res => {
            setEvidenceLogs(res.data?.data || []);
            setLoadingEvidence(false);
        })
        .catch(err => {
            console.error("Failed to fetch evidence", err);
            setLoadingEvidence(false);
        });
    }
  }, [activeTab, config]);

  const decodeForensicEvidence = (base64String) => {
      try {
          if (!base64String) return "No cryptographic seal found.";
          const binaryString = window.atob(base64String);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
              bytes[i] = binaryString.charCodeAt(i);
          }
          const decoder = new TextDecoder('utf-8');
          return decoder.decode(bytes);
        } catch {
          return "ERROR: Cryptographic seal broken or invalid encoding.";
      }
  };

  const downloadReport = async (type) => {
    if (!config) return;
    try {
        const res = await apiClient.get(`/logs?pack=${config.pack_id}`);
        let realLogs = res.data?.data || [];

        if (realLogs.length === 0) {
            toast.info(`No active alerts found for ${config.name} yet. Generating empty template.`);
        }

        if (type === 'csv') {
          let csvContent = "data:text/csv;charset=utf-8,Timestamp,EventID,Severity,Description,Source IP\n";
          realLogs.forEach(log => {
              const row = [
                  log.timestamp,
                  log.event_id || "N/A",
                  log.severity || "INFO",
                  `"${(log.message || "Unknown Event").replace(/"/g, '""')}"`, 
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
          const doc = new jsPDF();
          doc.setFillColor(15, 23, 42); doc.rect(0, 0, 210, 30, "F");
          doc.setTextColor(255, 255, 255); doc.setFontSize(18);
          doc.text("WarSOC Enterprise Evidence Summary", 14, 20);
          
          doc.setTextColor(50, 50, 50); doc.setFontSize(12);
          doc.text(`Framework: ${config.name}`, 14, 40);
          doc.text(`Date Generated: ${new Date().toLocaleString()}`, 14, 48);
          doc.text(`Status: Active Monitoring (${realLogs.length} Events Logged)`, 14, 56);
          
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
  // VIEW 1: THE CATALOG
  // =========================================================
  if (!selectedPackId) {
    return (
      <div className="compliance-dashboard" style={{padding: '20px 0'}}>
        
        {/* 🚀 UPSELL BANNER: Shows only if user has no packs */}
        {userPurchasedPacks.length === 0 && (
            <div style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '20px', borderRadius: '12px', marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h4 style={{ margin: '0 0 8px 0', color: '#f59e0b', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <AlertTriangle size={20}/> Compliance Vault Locked
                    </h4>
                    <p style={{ margin: 0, color: '#cbd5e1', fontSize: '14px' }}>
                        You currently do not have any active compliance packs. Avoid regulatory fines by enabling FBR or PECA auditing.
                    </p>
                </div>
                <button onClick={() => navigate('/pricing')} style={{ background: '#f59e0b', color: '#000', border: 'none', padding: '12px 20px', borderRadius: '8px', fontWeight: 'bold', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', transition: '0.2s' }}>
                    <Lock size={16}/> Unlock Now
                </button>
            </div>
        )}

        <h2>Compliance & Audit Center</h2>
        <p>Manage your regulatory compliance packs and evidence vaults.</p>
        
        <div className="pack-grid">
          {Array.isArray(packs) && packs.length > 0 ? packs.map(pack => {
            const isUnlocked = userPurchasedPacks.includes(pack.pack_id);

            return (
            <div key={pack.pack_id} className="pack-card" style={{ opacity: isUnlocked ? 1 : 0.8, position: 'relative', border: !isUnlocked ? '1px dashed #ef4444' : '' }}>
              
              {!isUnlocked && (
                  <div style={{ position: 'absolute', top: '-12px', right: '-12px', background: '#ef4444', color: '#fff', padding: '8px', borderRadius: '50%', boxShadow: '0 0 15px rgba(239,68,68,0.5)', zIndex: 10 }}>
                      <Lock size={18} />
                  </div>
              )}

              <ShieldCheck size={40} className="pack-icon" style={{ color: isUnlocked ? '#3b82f6' : '#64748b' }} />
              <h3 style={{ color: isUnlocked ? '#fff' : '#94a3b8' }}>{pack.name}</h3>
              <p style={{ color: isUnlocked ? '#cbd5e1' : '#64748b' }}>{pack.description}</p>
              
              <div className="pack-meta" style={{ color: isUnlocked ? '#94a3b8' : '#475569' }}>
                 <Database size={16}/> Vault Retention: {pack.retention?.vault_days ? pack.retention.vault_days / 365 : 'N/A'} Years
              </div>

              {isUnlocked ? (
                  <button onClick={() => setSelectedPackId(pack.pack_id)}>Open Pack Dashboard</button>
              ) : (
                  // 🚀 ROUTE TO PRICING IF LOCKED
                  <button onClick={() => navigate('/pricing')} style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)', cursor: 'pointer', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px', transition: '0.2s' }} onMouseOver={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)'} onMouseOut={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}>
                    <Lock size={16} /> Upgrade Plan to Unlock
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
            <p style={{fontSize: '1.1rem', color: '#cbd5e1', marginBottom: '10px'}}>Hot Storage (Fast Search): <b style={{color: '#3b82f6'}}>{config.retention?.local_hot_days || 90} Days</b></p>
            <p style={{fontSize: '1.1rem', color: '#cbd5e1'}}>Cloud Vault (Immutable): <b style={{color: '#10b981'}}>{config.retention?.vault_days || 1095} Days</b></p>
          </div>
        )}

        {activeTab === 'controls' && (
          <div className="controls-tab">
            <h3>Monitored Rules & Event IDs</h3>
            <table className="enterprise-table">
              <thead><tr><th>Event ID</th><th>Rule Name</th><th>Severity</th></tr></thead>
              <tbody>
                {config.monitored_events && config.monitored_events.map(ev => (
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
             <p style={{lineHeight: '1.6', marginBottom: '20px'}}>All logs mapped to this framework are hashed using SHA-256. Below are the raw, court-admissible forensic signatures fetched directly from the secure vault.</p>
             
             {loadingEvidence ? (
                 <div style={{color: '#3b82f6'}}>Decrypting Vault Data...</div>
             ) : evidenceLogs.length > 0 ? (
                 <div className="evidence-logs-container" style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
                     {evidenceLogs.map((evidence, idx) => (
                         <div key={idx} style={{background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '15px'}}>
                             <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '10px', color: '#94a3b8', fontSize: '0.85rem'}}>
                                 <span><Key size={14} style={{display:'inline', marginRight:'5px'}}/>Signature Hash</span>
                                 <span>{new Date(evidence.timestamp).toLocaleString()}</span>
                             </div>
                             <pre style={{
                                 background: '#000', 
                                 color: '#4ade80', 
                                 padding: '15px', 
                                 borderRadius: '4px', 
                                 overflowX: 'auto',
                                 fontFamily: 'monospace',
                                 fontSize: '0.9rem',
                                 border: '1px solid #064e3b'
                             }}>
                                 {decodeForensicEvidence(evidence.signed_payload)}
                             </pre>
                         </div>
                     ))}
                 </div>
             ) : (
                 <div style={{color: '#64748b', padding: '20px', background: '#0f172a', borderRadius: '8px', textAlign: 'center'}}>
                     No cryptographic evidence generated for this pack yet.
                 </div>
             )}
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