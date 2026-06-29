import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { CreditCard, Lock, ShieldCheck, ArrowLeft, Archive } from "lucide-react"; 
import apiClient from '../../../api/apiClient';
import { useAuthStore } from '../../../store/authStore'; 
import "./Payment.css"; 

export default function Payment() {
  const navigate = useNavigate();
  const location = useLocation();
  const [processing, setProcessing] = useState(false);
  const [success, setSuccess] = useState(false);
  const { user, checkAuth } = useAuthStore();

  useEffect(() => {
    if (!location.state) {
      alert("Payment session expired. Please select your plan again.");
      navigate("/pricing", { replace: true });
    }
  }, [location, navigate]);

  const plan = location.state?.plan || "Starter";
  // Pricing passes `finalPrice` from the Pricing builder (monthly or yearly display price)
  const monthlyTotal = location.state?.finalPrice || 0;
  const activationFee = location.state?.activationFee || 5000;
  const cycle = location.state?.cycle || "monthly";
  const customization = location.state?.customization || { endpoints: 1, storageGB: 5, retentionMonths: 0 };
  const addons = location.state?.addons || { fbr: false, peca: false };

  const totalDueToday = monthlyTotal + activationFee;

  const handlePayment = async () => {
    // 🔒 SECURITY FIX: Rely strictly on Zustand / HttpOnly state
    if (!user) { 
        navigate("/login"); 
        return; 
    }

    setProcessing(true);

    try {
      await new Promise(resolve => setTimeout(resolve, 2000)); 

      const purchasedPacks = [];
      // Use canonical pack IDs (SSOT) expected by the backend
      if (addons.fbr === true) purchasedPacks.push("fbr_pos");
      if (addons.peca === true) purchasedPacks.push("eto_forensic");

      // BACKEND API CALL: Route through secure apiClient
      await apiClient.post('/auth/upgrade', {
          plan_type: plan,
          compliance_packs: purchasedPacks,
          endpoints: parseInt(customization.endpoints),
          storage_gb: parseInt(customization.storageGB),
          retention_months: parseInt(customization.retentionMonths),
          billing_cycle: cycle // 🚀 NAYA: Backend now handles price calculation
      });

      // Synchronize the frontend store with the fresh backend state
      await checkAuth();

      setSuccess(true);
      setProcessing(false);

      // REDIRECT TO DASHBOARD
      setTimeout(() => {
          navigate("/dashboard"); 
      }, 2500);
    } catch (error) {
      const errMsg = error.response?.data?.detail || error.message || "Failed to save plan to database.";
      alert("Transaction Failed: " + errMsg);
      setProcessing(false);
    }
  };

  if (!location.state) return null; 

  return (
    <div className="payment-container">
      <div className="glow-bg top"></div>
      <div className="glow-bg bottom"></div>

      <div className="payment-card">
        {success ? (
          <div className="success-view">
            <div className="checkmark-circle"><ShieldCheck size={50} /></div>
            <h2>Payment Successful!</h2>
            <p>Your WarSOC Engine is now active.</p>
            <div className="redirect-msg">Redirecting to Dashboard...</div>
          </div>
        ) : (
          <>
            <div className="payment-header">
              <div className="secure-badge"><Lock size={14} /> Secure SSL Checkout</div>
              <h2>Invoice Summary</h2>
            </div>

            <div className="plan-summary" style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '20px', borderRadius: '12px', border: '1px solid #334155' }}>
              <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#94a3b8' }}>Base Plan ({plan})</span>
                <strong style={{ color: '#fff' }}>Included</strong>
              </div>
              <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#94a3b8' }}>Endpoints Monitored</span>
                <strong style={{ color: '#fff' }}>{customization.endpoints} Devices</strong>
              </div>
              <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#94a3b8' }}>Live Hot Storage</span>
                <strong style={{ color: '#fff' }}>{customization.storageGB} GB</strong>
              </div>
              
              {customization.retentionMonths > 0 && (
                  <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <span style={{ color: '#c4b5fd', display: 'flex', alignItems: 'center', gap: '5px' }}><Archive size={14}/> Cold Archive</span>
                    <strong style={{ color: '#fff' }}>{customization.retentionMonths} Months</strong>
                  </div>
              )}
              
              {addons.fbr && <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}><span style={{ color: '#3b82f6' }}>+ FBR POS Shield</span><strong style={{ color: '#fff' }}>Included</strong></div>}
              {addons.peca && <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}><span style={{ color: '#10b981' }}>+ PECA Vault</span><strong style={{ color: '#fff' }}>Included</strong></div>}
              
              <hr style={{ borderColor: '#334155', margin: '15px 0' }}/>
              
              <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#facc15' }}>Platform Activation Fee</span>
                <strong style={{ color: '#facc15' }}>Rs {activationFee.toLocaleString()}</strong>
              </div>
              
              <div className="summary-row" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '1.4rem', marginTop: '15px' }}>
                <span style={{ color: '#fff' }}>Total Due Today</span>
                <strong style={{ color: '#3b82f6' }}>Rs {totalDueToday.toLocaleString()}</strong>
              </div>
              <small style={{ color: '#64748b', display: 'block', marginTop: '10px', textAlign: 'center' }}>
                  Next month recurring charge: Rs {monthlyTotal.toLocaleString()}
              </small>
            </div>

            <form className="payment-form" style={{ marginTop: '20px' }} onSubmit={(e) => e.preventDefault()}>
               <button className={`pay-btn ${processing ? "processing" : ""}`} onClick={handlePayment} disabled={processing} style={{ width: '100%', padding: '15px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '8px', fontSize: '16px', fontWeight: 'bold', cursor: 'pointer' }}>
                {processing ? "Processing Setup..." : `Pay Rs ${totalDueToday.toLocaleString()} & Activate`}
              </button>
            </form>
            <button className="cancel-link" onClick={() => navigate(-1)} disabled={processing} style={{ width: '100%', padding: '15px', background: 'transparent', color: '#94a3b8', border: 'none', cursor: 'pointer', marginTop: '10px' }}>Cancel</button>
          </>
        )}
      </div>
    </div>
  );
}