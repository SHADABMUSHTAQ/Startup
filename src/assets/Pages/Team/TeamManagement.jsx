import React, { useState, useEffect } from 'react';
import { Users, Shield, UserPlus, Trash2, Mail, Lock, X, Loader2, Briefcase, Activity } from 'lucide-react';
import { toast } from 'react-toastify';
import apiClient from '../../../api/apiClient';
import { useAuthStore } from '../../../store/authStore';
import { formatApiError } from '../../../utils/apiError';
import './Team.css'; // Make sure your CSS matches the standard dashboard styling

export default function TeamManagement() {
  const [team, setTeam] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const { user } = useAuthStore();
  const currentUserRole = user?.role || 'analyst';

  // Form States (Provisioning Access)
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [selectedRole, setSelectedRole] = useState('analyst'); // Default role: 'admin', 'analyst', 'auditor'
  const [allowedPacks, setAllowedPacks] = useState({ fbr: false, peca: false });
  const [loadingInvite, setLoadingInvite] = useState(false);

  const fetchTeam = async () => {
    setLoadingList(true);
    try {
        const res = await apiClient.get('/auth/team');
        const data = res.data;
        // Backend must return data.team array
        if (data.team && Array.isArray(data.team)) setTeam(data.team);
        else setTeam([]);
    } catch (err) { 
        console.error("Failed to fetch team list", err);
        setTeam([]);
        toast.error(formatApiError(err, "Failed to load team list."));
    } finally { setLoadingList(false); }
  };

  useEffect(() => { fetchTeam(); }, []);

  const handleInvite = async (e) => {
    e.preventDefault();
    setLoadingInvite(true);
    
    // Prepare compliance packs if role is auditor
    let packs = [];
    if (selectedRole === 'auditor') {
        if (allowedPacks.fbr) packs.push("fbr_pos");
        if (allowedPacks.peca) packs.push("peca_forensic");
        if (packs.length === 0) {
            toast.error("Auditor requires at least one compliance pack assigned.");
            setLoadingInvite(false); return;
        }
    } else {
        // Internal roles generally don't need restricted compliance tags, handle based on your DB schema
        packs = []; 
    }

    // 🚀 THE FIX: Dynamic Invite Payload structure for backend protocol
    const invitePayload = { 
        email, 
        password, 
        role: selectedRole, 
        allowed_packs: packs // Should be array of pack IDs or empty if none
    };

    try {
        await apiClient.post('/auth/invite', invitePayload);
        toast.success(`${selectedRole.charAt(0).toUpperCase() + selectedRole.slice(1)} Invited Successfully!`);
        setIsModalOpen(false);
        resetForm();
        fetchTeam(); // 🚀 DYNAMIC: Refresh the team list after invite
    } catch (error) {
        console.error("Invite failed", error);
        toast.error(formatApiError(error, "Network Error. Check console."));
    } finally { setLoadingInvite(false); }
  };

  const handleRevoke = async (userId, userRole) => {
      if(userRole === 'admin') {
          toast.error("Cannot revoke access of another Admin directly.");
          return;
      }
      if(!window.confirm(`Are you sure you want to revoke access for ${userRole}: ${userId}?`)) return;
      
      try {
        // 🚀 THE FIX: DYNAMIC Revoke Call
        await apiClient.delete(`/auth/team/${userId}`);
        toast.success("Access Revoked Successfully.");
        fetchTeam(); // 🚀 DYNAMIC: Refresh list
      } catch (error) { 
          console.error("Revoke failed", error);
          toast.error(formatApiError(error, "Failed to revoke access."));
      }
  };

  const resetForm = () => {
      setEmail(''); setPassword(''); setSelectedRole('analyst'); setAllowedPacks({fbr: false, peca: false});
  };

  return (
    <div className="team-container" style={{ padding: '20px', maxWidth: '1200px', margin: '0 auto', fontFamily: 'Inter, sans-serif' }}>
      <div className="team-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <div>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#fff', margin: '0 0 8px 0' }}>
                <Users size={28} color="var(--primary)" /> Team & Access Control
            </h2>
            <p style={{ color: '#a6b8c8', margin: 0, fontSize: '14px' }}>
                Manage internal SOC analysts and provision read-only access for external compliance auditors.
            </p>
        </div>
        {currentUserRole === 'admin' && (
            <button className="btn-primary" onClick={() => setIsModalOpen(true)} style={{ display: 'flex', gap: '8px', alignItems: 'center', height: '40px', padding: '0 20px', background: 'var(--success)', color: '#000', fontWeight: 'bold', border: 'none', borderRadius: '8px', cursor: 'pointer' }}>
                <UserPlus size={18} /> Provision Access
            </button>
        )}
      </div>

      <div className="team-table-card" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 10px 30px -10px rgba(0,0,0,0.5)' }}>
          <table className="team-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: '700px' }}>
              <thead style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border)' }}>
                  <tr>
                      <th style={{ padding: '16px 20px', color: '#a6b8c8', fontSize: '13px' }}>User Entity</th>
                      <th style={{ padding: '16px 20px', color: '#a6b8c8', fontSize: '13px' }}>Security Role</th>
                      <th style={{ padding: '16px 20px', color: '#a6b8c8', fontSize: '13px' }}>System Scope</th>
                      <th style={{ padding: '16px 20px', color: '#a6b8c8', fontSize: '13px', textAlign: 'right' }}>Actions</th>
                  </tr>
              </thead>
              <tbody>
                  {loadingList ? (
                      <tr><td colSpan="4" style={{ textAlign: 'center', padding: '40px', color: '#a6b8c8' }}>Loading team entity list...</td></tr>
                  ) : team.length === 0 ? (
                      <tr><td colSpan="4" style={{ textAlign: 'center', padding: '40px', color: '#a6b8c8' }}>No team members found for this organization.</td></tr>
                  ) : (
                      team.map(member => (
                          <tr key={member._id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', transition: '0.2s' }}>
                              <td style={{ padding: '16px 20px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                      <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'rgba(73, 175, 241, 0.1)', color: 'var(--primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold', fontSize: '15px' }}>
                                          {member.email.charAt(0).toUpperCase()}
                                      </div>
                                      <span style={{ color: '#f8fafc', fontWeight: '500', fontSize: '14px' }}>{member.email}</span>
                                  </div>
                              </td>
                              <td style={{ padding: '16px 20px' }}>
                                  <span style={{ 
                                      padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.5px',
                                      background: member.role === 'admin' ? 'rgba(239, 68, 68, 0.1)' : member.role === 'auditor' ? 'rgba(183, 235, 72, 0.1)' : 'rgba(73, 175, 241, 0.1)',
                                      color: member.role === 'admin' ? '#ef4444' : member.role === 'auditor' ? '#b7eb48' : 'var(--primary)',
                                      border: `1px solid ${member.role === 'admin' ? 'rgba(239, 68, 68, 0.2)' : member.role === 'auditor' ? 'rgba(183, 235, 72, 0.2)' : 'rgba(73, 175, 241, 0.2)'}`
                                   }}>
                                      {member.role || 'Member'}
                                  </span>
                              </td>
                              <td style={{ padding: '16px 20px' }}>
                                  <div style={{ display: 'flex', gap: '8px' }}>
                                      {member.role === 'admin' || member.role === 'analyst' ? (
                                          <span style={{ color: '#a6b8c8', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}><Activity size={14}/> Full Internal Network</span>
                                      ) : member.compliance_packs && member.compliance_packs.length > 0 ? (
                                          <>
                                              {member.compliance_packs.includes("fbr_pos") && <span style={{ fontSize: '12px', background: 'rgba(183, 235, 72, 0.1)', color: '#b7eb48', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(183, 235, 72, 0.2)' }}>FBR Logs</span>}
                                              {member.compliance_packs.includes("peca_forensic") && <span style={{ fontSize: '12px', background: 'rgba(73, 175, 241, 0.1)', color: '#8fd8ff', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(73, 175, 241, 0.2)' }}>PECA Vault</span>}
                                          </>
                                      ) : <span style={{color:'#7f97ae', fontSize: '13px'}}>No specific tags</span>}
                                  </div>
                              </td>
                              <td style={{ padding: '16px 20px', textAlign: 'right' }}>
                                  {currentUserRole === 'admin' && member.role !== 'admin' && (
                                      <button onClick={() => handleRevoke(member._id, member.role)} style={{ background: 'transparent', border: 'none', color: '#7f97ae', cursor: 'pointer', padding: '6px', transition: '0.2s', borderRadius: '6px' }} onMouseOver={e => {e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}} onMouseOut={e => {e.currentTarget.style.color = '#7f97ae'; e.currentTarget.style.background = 'transparent'}}>
                                          <Trash2 size={18} />
                                      </button>
                                  )}
                              </td>
                          </tr>
                      ))
                  )}
              </tbody>
          </table>
      </div>

      {/* 🚀 ENTERPRISE INVITATION MODAL */}
      {isModalOpen && (
          <div className="modal-overlay" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div className="invite-modal" style={{ background: 'var(--bg-card)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '16px', width: '100%', maxWidth: '450px', overflow: 'hidden', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.5)' }}>
                  <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.01)' }}>
                      <h3 style={{ margin: 0, color: '#f8fafc', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}><Shield size={20} color="var(--primary)"/> Provision System Access</h3>
                      <button type="button" onClick={() => setIsModalOpen(false)} style={{ background: 'none', border: 'none', color: '#a6b8c8', cursor: 'pointer' }}><X size={20} /></button>
                  </div>
                  
                  <form onSubmit={handleInvite} style={{ padding: '24px' }}>
                      
                      {/* ROLE SELECTION */}
                      <div style={{ marginBottom: '20px' }}>
                          <label style={{ display: 'block', color: '#a6b8c8', fontSize: '13px', marginBottom: '8px', fontWeight: '600' }}>Assign Security Role Claims</label>
                          <div style={{ display: 'flex', gap: '10px' }}>
                              {['analyst', 'auditor', 'admin'].map(role => (
                                  <div key={role} onClick={() => setSelectedRole(role)} style={{ 
                                      flex: 1, padding: '10px', textAlign: 'center', borderRadius: '8px', cursor: 'pointer', border: '1px solid', fontSize: '13px', fontWeight: '600', textTransform: 'capitalize', transition: '0.2s',
                                      background: selectedRole === role ? 'rgba(73, 175, 241, 0.1)' : 'transparent',
                                      borderColor: selectedRole === role ? 'var(--primary)' : 'var(--border)',
                                      color: selectedRole === role ? 'var(--primary)' : '#a6b8c8'
                                  }}>
                                      {role}
                                  </div>
                              ))}
                          </div>
                      </div>

                      <div style={{ marginBottom: '20px' }}>
                          <label style={{ display: 'block', color: '#a6b8c8', fontSize: '13px', marginBottom: '8px', fontWeight: '600' }}><Mail size={14} style={{verticalAlign:'middle', marginRight:'4px'}}/> User Entity Email</label>
                          <input type="email" required placeholder="name@company.com / government.gov.pk" value={email} onChange={e => setEmail(e.target.value)} 
                              style={{ width: '100%', padding: '12px', background: 'var(--bg-dark)', border: '1px solid var(--border)', borderRadius: '8px', color: 'white', outline: 'none', fontSize: '14px' }} />
                      </div>

                      <div style={{ marginBottom: '24px' }}>
                          <label style={{ display: 'block', color: '#a6b8c8', fontSize: '13px', marginBottom: '8px', fontWeight: '600' }}><Lock size={14} style={{verticalAlign:'middle', marginRight:'4px'}}/> Temporary System Password</label>
                          <input type="password" required placeholder="Provide a strong temporary secret" value={password} onChange={e => setPassword(e.target.value)}
                              style={{ width: '100%', padding: '12px', background: 'var(--bg-dark)', border: '1px solid var(--border)', borderRadius: '8px', color: 'white', outline: 'none', fontSize: '14px' }} />
                          <small style={{display:'block', marginTop:'6px', color:'#7f97ae', fontSize:'11px'}}>Share this password securely. User will be forced to change on first login.</small>
                      </div>
                      
                      {/* SCOPE SELECTION (ONLY FOR AUDITORS) */}
                      {selectedRole === 'auditor' && (
                          <div style={{ marginBottom: '24px', padding: '16px', background: 'rgba(183, 235, 72, 0.03)', borderRadius: '8px', border: '1px solid rgba(183, 235, 72, 0.15)' }}>
                              <label style={{ display: 'block', color: '#b7eb48', fontSize: '13px', marginBottom: '12px', fontWeight: '700' }}><Briefcase size={14} style={{verticalAlign:'middle', marginRight:'4px'}}/> Strict Data Scope (Auditor Claims)</label>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                  <label style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#f8fafc', fontSize: '13px', cursor: 'pointer' }}>
                                      <input type="checkbox" checked={allowedPacks.fbr} onChange={() => setAllowedPacks(p => ({...p, fbr: !p.fbr}))} style={{ accentColor: 'var(--success)', width: '16px', height: '16px' }} />
                                      FBR Point-of-Sale Integrity Logs
                                  </label>
                                  <label style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#f8fafc', fontSize: '13px', cursor: 'pointer' }}>
                                      <input type="checkbox" checked={allowedPacks.peca} onChange={() => setAllowedPacks(p => ({...p, peca: !p.peca}))} style={{ accentColor: 'var(--success)', width: '16px', height: '16px' }} />
                                      PECA Forensic Evidence Vault
                                  </label>
                              </div>
                          </div>
                      )}

                      <div style={{ display: 'flex', gap: '12px' }}>
                          <button type="button" onClick={() => setIsModalOpen(false)} style={{ flex: 1, padding: '12px', background: 'transparent', border: '1px solid var(--border)', color: '#f8fafc', borderRadius: '8px', fontWeight: '600', cursor: 'pointer', fontSize: '14px' }}>Cancel</button>
                          <button type="submit" disabled={loadingInvite} style={{ flex: 1, padding: '12px', background: 'var(--primary)', border: 'none', color: 'white', borderRadius: '8px', fontWeight: '600', cursor: loadingInvite ? 'not-allowed' : 'pointer', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px', fontSize: '14px' }}>
                              {loadingInvite ? <><Loader2 size={16} className="spinner" /> Granting...</> : "Grant System Access"}
                          </button>
                      </div>
                  </form>
              </div>
          </div>
      )}
    </div>
  );
}
