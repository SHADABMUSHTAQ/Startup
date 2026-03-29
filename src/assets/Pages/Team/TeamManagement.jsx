import React, { useState, useEffect } from 'react';
import { Users, Shield, Plus, Trash2, Mail, Lock, X } from 'lucide-react';
import { toast } from 'react-toastify';
import { API_BASE_URL } from '../../../api'; // Adjust path if needed
import './Team.css';

export default function TeamManagement() {
  const [team, setTeam] = useState([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  
  // Form States
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [allowedPacks, setAllowedPacks] = useState({ fbr: false, peca: false });
  const [loading, setLoading] = useState(false);

  const fetchTeam = async () => {
    const token = localStorage.getItem("token");
    try {
        const res = await fetch(`${API_BASE_URL}/auth/team`, {
            headers: { "Authorization": `Bearer ${token}` }
        });
        const data = await res.json();
        if (data.team) setTeam(data.team);
    } catch (err) { console.error(err); }
  };

  useEffect(() => { fetchTeam(); }, []);

  const handleInvite = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    const packs = [];
    if (allowedPacks.fbr) packs.push("fbr_pos_shield");
    if (allowedPacks.peca) packs.push("peca_vault");

    if (packs.length === 0) {
        toast.error("Please select at least one compliance pack for the auditor.");
        setLoading(false); return;
    }

    try {
        const token = localStorage.getItem("token");
        const res = await fetch(`${API_BASE_URL}/auth/invite`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify({ email, temp_password: password, allowed_packs: packs })
        });
        
        const data = await res.json();
        if (res.ok) {
            toast.success("Auditor Invited Successfully!");
            setIsModalOpen(false);
            setEmail(''); setPassword(''); setAllowedPacks({fbr: false, peca: false});
            fetchTeam(); // Refresh table
        } else {
            toast.error(data.error || "Failed to invite user.");
        }
    } catch (err) {
        toast.error("Network Error.");
    } finally { setLoading(false); }
  };

  const handleRevoke = async (userId) => {
      if(!window.confirm("Are you sure you want to revoke this auditor's access?")) return;
      
      try {
          const token = localStorage.getItem("token");
          const res = await fetch(`${API_BASE_URL}/auth/team/${userId}`, {
              method: "DELETE",
              headers: { "Authorization": `Bearer ${token}` }
          });
          if (res.ok) {
              toast.success("Access Revoked.");
              fetchTeam();
          }
      } catch (err) { toast.error("Failed to revoke access."); }
  };

  return (
    <div className="team-container">
      <div className="team-header">
        <div>
            <h2><Users size={24} style={{display:'inline', marginRight:'10px', color:'#3b82f6'}}/> Access Management</h2>
            <p>Manage auditor access and external roles for your organization.</p>
        </div>
        <button className="btn-invite" onClick={() => setIsModalOpen(true)}>
            <Plus size={18} /> Invite Auditor
        </button>
      </div>

      <div className="team-table-card">
          <table className="team-table">
              <thead>
                  <tr>
                      <th>User Email</th>
                      <th>Role</th>
                      <th>Scope (Allowed Packs)</th>
                      <th>Action</th>
                  </tr>
              </thead>
              <tbody>
                  {team.length === 0 ? (
                      <tr><td colSpan="4" style={{textAlign:'center', padding:'30px', color:'#64748b'}}>No external auditors invited yet.</td></tr>
                  ) : (
                      team.map(member => (
                          <tr key={member._id}>
                              <td style={{fontWeight: 'bold', color: '#fff'}}>{member.email}</td>
                              <td><span className="role-badge auditor">Auditor (Read-Only)</span></td>
                              <td>
                                  <div className="scope-tags">
                                      {member.compliance_packs.includes("fbr_pos_shield") && <span className="tag fbr">FBR Shield</span>}
                                      {member.compliance_packs.includes("peca_vault") && <span className="tag peca">PECA Vault</span>}
                                  </div>
                              </td>
                              <td>
                                  <button className="btn-revoke" onClick={() => handleRevoke(member._id)}>
                                      <Trash2 size={16} /> Revoke
                                  </button>
                              </td>
                          </tr>
                      ))
                  )}
              </tbody>
          </table>
      </div>

      {/* 🚀 MODAL FOR INVITING AUDITOR */}
      {isModalOpen && (
          <div className="modal-overlay">
              <div className="invite-modal">
                  <div className="modal-head">
                      <h3>Invite External Auditor</h3>
                      <button className="btn-close" onClick={() => setIsModalOpen(false)}><X size={20}/></button>
                  </div>
                  <form onSubmit={handleInvite}>
                      <div className="input-group">
                          <label><Mail size={16}/> Auditor's Email</label>
                          <input type="email" required placeholder="e.g., inspector@fbr.gov.pk" value={email} onChange={e => setEmail(e.target.value)} />
                      </div>
                      <div className="input-group">
                          <label><Lock size={16}/> Temporary Password</label>
                          <input type="text" required placeholder="Generate a password to share with them" value={password} onChange={e => setPassword(e.target.value)} />
                          <small>Share this password securely with the auditor.</small>
                      </div>
                      
                      <div className="scope-selection">
                          <label><Shield size={16}/> Select Access Scope</label>
                          <div className="checkbox-group">
                              <label className="custom-check">
                                  <input type="checkbox" checked={allowedPacks.fbr} onChange={() => setAllowedPacks(p => ({...p, fbr: !p.fbr}))} />
                                  <span>FBR POS Integrity Logs</span>
                              </label>
                              <label className="custom-check">
                                  <input type="checkbox" checked={allowedPacks.peca} onChange={() => setAllowedPacks(p => ({...p, peca: !p.peca}))} />
                                  <span>PECA Forensic Evidence</span>
                              </label>
                          </div>
                      </div>

                      <div className="modal-footer">
                          <button type="button" className="btn-cancel" onClick={() => setIsModalOpen(false)}>Cancel</button>
                          <button type="submit" className="btn-submit" disabled={loading}>
                              {loading ? "Sending..." : "Grant Access"}
                          </button>
                      </div>
                  </form>
              </div>
          </div>
      )}
    </div>
  );
}
