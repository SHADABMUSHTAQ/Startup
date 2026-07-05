import React, { useState, useEffect } from 'react';
import { ShieldCheck, Database, FileText, Download, ArrowLeft, Activity, Lock, Key, AlertTriangle } from 'lucide-react';
import { useNavigate } from 'react-router-dom'; // 🚀 NAYA: Pricing page par bhejne ke liye
import { toast } from 'react-toastify';
import './Compliance.css';
import apiClient from '../../../api/apiClient';
import { useAuthStore } from '../../../store/authStore'; 

// 🚨 NO FALLBACK CATALOGS: Must fail loud if SSOT is unavailable

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
  const [coverageByPack, setCoverageByPack] = useState({});

  const [apiError, setApiError] = useState(false);
  const [loadingPacks, setLoadingPacks] = useState(true);

  const normalizePackIds = (payload) => {
    const rawPacks = Array.isArray(payload)
      ? payload
      : payload?.compliance_packs || payload?.packs || payload?.data || [];

    if (!Array.isArray(rawPacks)) return [];
    return rawPacks
      .map((pack) => (typeof pack === 'string' ? pack : pack.pack_id || pack.id))
      .filter(Boolean);
  };

    useEffect(() => {
      setLoadingPacks(true);
      apiClient.get('/compliance/packs')
        .then(res => {
          if (Array.isArray(res.data) && res.data.length > 0) {
              setPacks(res.data);
              setApiError(false);
          } else {
              setApiError(true);
          }
        })
        .catch(() => setApiError(true))
        .finally(() => setLoadingPacks(false));

      apiClient.get('/auth/my-packs')
        .then(res => setUserPurchasedPacks(normalizePackIds(res.data)))
        .catch(() => {
          if (user?.compliance_packs && Array.isArray(user.compliance_packs)) {
            setUserPurchasedPacks(user.compliance_packs);
            return;
          }

          // Silent sync only if missing to prevent infinite loops
          checkAuth().then(() => {
              const freshUser = useAuthStore.getState().user;
              if (freshUser?.compliance_packs) {
                  setUserPurchasedPacks(freshUser.compliance_packs);
              }
          }).catch(() => {});
        });

      apiClient.get('/compliance/coverage')
        .then((res) => {
          const rows = Array.isArray(res.data?.coverage) ? res.data.coverage : [];
          setCoverageByPack(
            Object.fromEntries(rows.map((row) => [row.pack_id, row])),
          );
        })
        .catch(() => setCoverageByPack({}));
    }, [checkAuth, user?.compliance_packs]);

  useEffect(() => {
    if (selectedPackId) {
      apiClient.get(`/compliance/packs/${selectedPackId}`)
        .then(res => setConfig(res.data))
        .catch(() => {
            toast.error("Failed to load compliance framework config from SSOT.");
            setSelectedPackId(null);
        });
    }
  }, [selectedPackId]);

  useEffect(() => {
    if (activeTab === 'evidence' && config) {
        setLoadingEvidence(true);
        apiClient.get(`/compliance/evidence/${config.pack_id}`)
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




  const downloadReport = async (type) => {
    if (!config) return;
    try {
        const endpoint = type === 'csv' ? '/export/csv' : '/export/audit-report';
        const query = new URLSearchParams(
          type === 'csv'
            ? { data_type: 'compliance', pack_id: config.pack_id }
            : { pack_id: config.pack_id },
        );
        window.open(
          `${apiClient.defaults.baseURL}${endpoint}?${query.toString()}`,
          '_blank',
          'noopener',
        );
        toast.success(
          type === 'csv'
            ? "Backend CSV export requested."
            : "Backend audit report requested.",
        );
    } catch (error) {
        console.error("Report Generation Error:", error);
        toast.error("Error requesting backend export.");
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
            <div style={{ background: 'rgba(183, 235, 72, 0.1)', border: '1px solid rgba(183, 235, 72, 0.3)', padding: '20px', borderRadius: '12px', marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h4 style={{ margin: '0 0 8px 0', color: '#b7eb48', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <AlertTriangle size={20}/> Compliance Vault Locked
                    </h4>
                    <p style={{ margin: 0, color: '#d8e6f1', fontSize: '14px' }}>
                        You currently do not have any active compliance packs. Avoid regulatory fines by enabling FBR or PECA auditing.
                    </p>
                </div>
                <button onClick={() => navigate('/pricing')} style={{ background: '#b7eb48', color: '#000', border: 'none', padding: '12px 20px', borderRadius: '8px', fontWeight: 'bold', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', transition: '0.2s' }}>
                    <Lock size={16}/> Unlock Now
                </button>
            </div>
        )}

        <h2>Compliance & Audit Center</h2>
        <p>Manage your regulatory compliance packs and evidence vaults.</p>
        
        {apiError && (
            <div style={{ background: '#3f1118', border: '1px solid #7a222f', padding: '15px', borderRadius: '8px', marginBottom: '20px', color: '#ff8a8a', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <AlertTriangle size={24}/>
                <strong>API Synchronization Error:</strong> The system is currently blind to the compliance SSOT catalog. Please contact the deployment team.
            </div>
        )}

        {loadingPacks && !apiError ? (
            <div style={{ padding: '20px', color: '#a6b8c8' }}>Loading compliance framework definitions...</div>
        ) : (
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

              <ShieldCheck size={40} className="pack-icon" style={{ color: isUnlocked ? '#49aff1' : '#7f97ae' }} />
              <h3 style={{ color: isUnlocked ? '#fff' : '#a6b8c8' }}>{pack.name}</h3>
              <p style={{ color: isUnlocked ? '#d8e6f1' : '#7f97ae' }}>{pack.description}</p>
              
              <div className="pack-meta" style={{ color: isUnlocked ? '#a6b8c8' : '#475569' }}>
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
          )}) : (!apiError && <div style={{color: '#a6b8c8'}}>No packs available in catalog.</div>)}
        </div>
        )}
      </div>
    );
  }

  // =========================================================
  // VIEW 2: THE PACK DETAIL
  // =========================================================
  if (!config) return <div style={{padding: '50px', color: '#fff'}}>Loading Enterprise Framework...</div>;

  const selectedCoverage = coverageByPack[config.pack_id];
  const coverageStatus = selectedCoverage?.status || 'not_configured';
  const coverageLabel = {
    active: 'Active',
    degraded: 'Degraded',
    not_configured: 'Not Configured',
  }[coverageStatus] || 'Not Configured';

  return (
    <div className="pack-detail-page" style={{padding: '0px'}}>
      <button onClick={() => {setSelectedPackId(null); setConfig(null); setActiveTab('overview');}} style={{display: 'flex', alignItems: 'center', gap: '8px', background: 'transparent', color: '#a6b8c8', border: 'none', cursor: 'pointer', marginBottom: '20px', fontSize: '16px'}}>
        <ArrowLeft size={18} /> Back to Catalog
      </button>
      <div className="pack-header">
        <h1>{config.name}</h1>
        <span
          className={`status-badge ${coverageStatus.replace('_', '-')}`}
          title={`${selectedCoverage?.ready_agents || 0} of ${selectedCoverage?.registered_agents || 0} registered agents ready`}
        >
          {coverageLabel}
        </span>
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
            <p style={{fontSize: '1.1rem', color: '#d8e6f1', marginBottom: '10px'}}>Hot Storage (Fast Search): <b style={{color: '#49aff1'}}>{config.retention?.local_hot_days || 90} Days</b></p>
            <p style={{fontSize: '1.1rem', color: '#d8e6f1'}}>Cloud Vault (Immutable): <b style={{color: '#b7eb48'}}>{config.retention?.vault_days || 1095} Days</b></p>
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
                    <td><span style={{background: '#102238', padding: '4px 8px', borderRadius: '4px', border: '1px solid #1e3a56'}}>{ev.id}</span></td>
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
             <h3><Lock size={20} style={{display:'inline', marginRight: '10px'}}/> Forensic Evidence Logs</h3>
             <p style={{lineHeight: '1.6', marginBottom: '20px'}}>All compliance evidence logs mapped to this framework, fetched directly from the secure vault.</p>
             
             {loadingEvidence ? (
                 <div style={{color: '#49aff1'}}>Loading Vault Data...</div>
             ) : evidenceLogs.length > 0 ? (
                 <div className="evidence-logs-container" style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
                     {evidenceLogs.map((evidence, idx) => (
                         <div key={idx} style={{background: '#07111f', border: '1px solid #1e3a56', borderRadius: '8px', padding: '15px'}}>
                             <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '10px', color: '#a6b8c8', fontSize: '0.85rem'}}>
                                 <span><Key size={14} style={{display:'inline', marginRight:'5px'}}/>Evidence Record</span>
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
                                 {JSON.stringify(evidence, null, 2)}
                             </pre>
                         </div>
                     ))}
                 </div>
             ) : (
                 <div style={{color: '#7f97ae', padding: '20px', background: '#07111f', borderRadius: '8px', textAlign: 'center'}}>
                     No forensic evidence generated for this pack yet.
                 </div>
             )}
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="reports-tab">
            <h3>Auditor Ready Reports</h3>
            <p style={{color: '#a6b8c8', marginBottom: '20px'}}>Generate compliance-ready artifacts for external auditors and government agencies.</p>
            <div style={{display: 'flex', gap: '15px'}}>
                <button className="export-btn" onClick={() => downloadReport('csv')} style={{background: '#49aff1'}}><Download size={18} /> Generate Auditor CSV</button>
                <button className="export-btn" onClick={() => downloadReport('pdf')} style={{background: '#b7eb48'}}><FileText size={18} /> Generate Evidence Summary</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
