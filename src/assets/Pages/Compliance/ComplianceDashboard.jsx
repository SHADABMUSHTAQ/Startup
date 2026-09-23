import React, { useState, useEffect } from 'react';
import { ShieldCheck, Database, FileText, Download, ArrowLeft, Activity, Lock, Key, AlertTriangle, Eye, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom'; // 🚀 NAYA: Pricing page par bhejne ke liye
import { toast } from 'react-toastify';
import './Compliance.css';
import apiClient from '../../../api/apiClient';
import { useAuthStore } from '../../../store/authStore'; 
import { formatApiError } from '../../../utils/apiError';
import RetentionStatus from './RetentionStatus';
import EvidenceStateBadge from '../../../components/EvidenceStateBadge';

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
  const [evidenceError, setEvidenceError] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [evidenceDetail, setEvidenceDetail] = useState(null);
  const [loadingEvidenceDetail, setLoadingEvidenceDetail] = useState(false);
  const [evidenceDetailError, setEvidenceDetailError] = useState('');
  const [coverageByPack, setCoverageByPack] = useState({});

  const [catalogError, setCatalogError] = useState('');
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
          const catalogPacks = Array.isArray(res.data) ? res.data : [];
          setPacks(catalogPacks);
          setCatalogError('');
        })
        .catch(() => {
          setPacks([]);
          setCatalogError('Compliance information could not be loaded. Please try again shortly.');
        })
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
            toast.error("Compliance details could not be loaded. Please try again.");
            setSelectedPackId(null);
        });
    }
  }, [selectedPackId]);

  useEffect(() => {
    if (activeTab === 'evidence' && config) {
        setSelectedEvidence(null);
        setEvidenceDetail(null);
        setEvidenceDetailError('');
        setLoadingEvidence(true);
        setEvidenceError('');
        apiClient.get(`/compliance/evidence/${config.pack_id}`, {
          params: { skip: 0, limit: 50 },
          // Archive-backed evidence can be slower than normal dashboard APIs.
          // Keep the global timeout strict and relax it only for this bounded read.
          timeout: 30000,
        })
        .then(res => {
            setEvidenceLogs(res.data?.data || []);
        })
        .catch(err => {
            setEvidenceLogs([]);
            setEvidenceError(formatApiError(err, "Compliance evidence could not be loaded."));
        })
        .finally(() => setLoadingEvidence(false));
    }
  }, [activeTab, config]);

  const closeEvidenceDetail = () => {
    setSelectedEvidence(null);
    setEvidenceDetail(null);
    setEvidenceDetailError('');
    setLoadingEvidenceDetail(false);
  };

  const loadEvidenceDetail = async (evidence) => {
    if (!evidence?.id || !evidence?.detail_available) {
      toast.error('Detailed evidence is not available for this record.');
      return;
    }

    setSelectedEvidence(evidence);
    setEvidenceDetail(null);
    setEvidenceDetailError('');
    setLoadingEvidenceDetail(true);
    try {
      const response = await apiClient.get(`/logs/${encodeURIComponent(evidence.id)}/evidence`, {
        timeout: 30000,
      });
      setEvidenceDetail(response.data);
    } catch (error) {
      setEvidenceDetailError(formatApiError(error, 'Detailed evidence could not be loaded.'));
    } finally {
      setLoadingEvidenceDetail(false);
    }
  };




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
            ? "CSV export requested."
            : "Audit report requested.",
        );
    } catch {
        toast.error("The report could not be requested. Please try again.");
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
        
        {catalogError && (
            <div className="compliance-catalog-error">
                <AlertTriangle size={24}/>
                <span>{catalogError}</span>
            </div>
        )}

        {loadingPacks && !catalogError ? (
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
                 <Database size={16}/> Retention: {formatPackRetention(pack.retention)}
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
          )}) : (!catalogError && <div style={{color: '#a6b8c8'}}>No compliance packs are currently available.</div>)}
        </div>
        )}
        <RetentionStatus />
      </div>
    );
  }

  // =========================================================
  // VIEW 2: THE PACK DETAIL
  // =========================================================
  if (!config) return <div style={{padding: '50px', color: '#fff'}}>Loading Compliance Framework...</div>;

  const selectedCoverage = coverageByPack[config.pack_id];
  const coverageStatus = selectedCoverage?.status || 'not_configured';
  const coverageLabel = {
    active: 'Active',
    degraded: 'Degraded',
    not_configured: 'Not Configured',
  }[coverageStatus] || 'Not Configured';

  return (
    <div className="pack-detail-page" style={{padding: '0px'}}>
      <button className="catalog-back-btn" onClick={() => {setSelectedPackId(null); setConfig(null); setActiveTab('overview');}}>
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
            <RetentionStatus />
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
                    <td><span className="event-id-badge">{ev.id}</span></td>
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
             ) : evidenceError ? (
                 <div style={{color: '#ff8a8a', padding: '20px', background: '#3f1118', border: '1px solid #7a222f', borderRadius: '8px', textAlign: 'center'}}>
                     {evidenceError}
                 </div>
             ) : evidenceLogs.length > 0 ? (
                 <div className="evidence-logs-container">
                     {evidenceLogs.map((evidence) => (
                         <article key={evidence.event_uid || evidence.id} className="evidence-summary">
                             <div className="evidence-summary-header">
                                 <span><Key size={14}/> Evidence Record</span>
                                 <time>{evidence.timestamp ? new Date(evidence.timestamp).toLocaleString() : 'Time unavailable'}</time>
                             </div>
                             <div className="evidence-summary-grid">
                               <div><span>Event ID</span><strong>{evidence.event_id || 'Not recorded'}</strong></div>
                               <div><span>Source</span><strong>{evidence.source_ip || evidence.agent_id || 'Not recorded'}</strong></div>
                               <div><span>Actor</span><strong>{evidence.user || 'Not recorded'}</strong></div>
                               <div><span>Storage</span><strong>{evidence.archived ? 'Immutable archive' : 'Hot evidence'}</strong></div>
                             </div>
                             <div className="evidence-state-groups compliance-evidence-states">
                               <EvidenceStateBadge type="observation" state={evidence.observation_state || evidence.observed_state} />
                               <EvidenceStateBadge type="claim" state={evidence.claim_state || evidence.compliance_state} />
                             </div>
                             <p className="evidence-summary-message">
                               {evidence.message || 'No summary message recorded.'}
                             </p>
                             <button
                               type="button"
                               className="evidence-detail-button"
                               onClick={() => loadEvidenceDetail(evidence)}
                               disabled={!evidence.detail_available}
                             >
                               <Eye size={16}/> View evidence
                             </button>
                         </article>
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
      {selectedEvidence && (
        <div className="evidence-detail-backdrop" role="presentation" onMouseDown={closeEvidenceDetail}>
          <section
            className="evidence-detail-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="evidence-detail-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <header>
              <div>
                <span className="evidence-detail-kicker">Forensic evidence</span>
                <h3 id="evidence-detail-title">Event {selectedEvidence.event_id || 'record'}</h3>
              </div>
              <button type="button" className="evidence-detail-close" onClick={closeEvidenceDetail} aria-label="Close evidence detail">
                <X size={20}/>
              </button>
            </header>
            <div className="evidence-detail-body">
              {loadingEvidenceDetail ? (
                <div className="evidence-detail-state">Loading detailed evidence...</div>
              ) : evidenceDetailError ? (
                <div className="evidence-detail-error">{evidenceDetailError}</div>
              ) : evidenceDetail ? (
                <>
                  <div className="evidence-detail-metadata">
                    <span>{selectedEvidence.timestamp ? new Date(selectedEvidence.timestamp).toLocaleString() : 'Time unavailable'}</span>
                    <span>{selectedEvidence.storage_tier === 'cold_archive' ? 'Immutable archive' : 'Hot evidence'}</span>
                  </div>
                  <pre>{JSON.stringify({
                    raw_event_data: evidenceDetail.raw_event_data,
                    raw_data: evidenceDetail.raw_data,
                    processed_data: evidenceDetail.processed_data,
                  }, null, 2)}</pre>
                </>
              ) : null}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
import { formatPackRetention } from '../../../contracts/backendContracts';
