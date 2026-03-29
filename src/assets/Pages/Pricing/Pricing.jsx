import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, X, AlertTriangle, CheckCircle, Info, ShieldCheck, HardDrive, Monitor, Zap, ChevronDown, ChevronUp, Settings, PackagePlus, Archive } from "lucide-react"; 
import "./Pricing.css";

export default function Pricing() {
  const [selectedPlan, setSelectedPlan] = useState("Pro"); 
  const [billingCycle, setBillingCycle] = useState("monthly"); 
  const [showAddons, setShowAddons] = useState(false); 
  
  // Customization States
  const [endpoints, setEndpoints] = useState(1); 
  const [storageGB, setStorageGB] = useState(5); 
  const [addons, setAddons] = useState({ fbr: false, peca: false });
  
  // 🚀 NAYA STATE: Log Retention Archive Time
  const [retentionMonths, setRetentionMonths] = useState(0); // 0 = None, 3, 6, 12
  
  const navigate = useNavigate();

  // Pricing Logic (PKR)
  const ACTIVATION_FEE = 5000; 
  const PRICE_PER_ENDPOINT = 1500; 
  const PRICE_PER_GB = 200; 

  const fbrPrice = billingCycle === "monthly" ? 3000 : 30000;
  const pecaPrice = billingCycle === "monthly" ? 5000 : 50000;
  
  // 🚀 Retention Pricing based on Document
  const retentionPrices = {
      0: 0,
      3: 6000,
      6: 10000,
      12: 18000
  };
  const retentionCost = retentionPrices[retentionMonths];
  
  const basePlans = {
      Starter: billingCycle === "monthly" ? 5000 : 50000,
      Pro: billingCycle === "monthly" ? 15000 : 150000,
      Enterprise: billingCycle === "monthly" ? 35000 : 350000
  };

  const plans = [
    { id: 1, name: "Starter", description: "Small retail setups.", features: [{ name: "1 Project", included: true }, { name: "7 Days Hot Storage", included: true }] },
    { id: 2, name: "Pro", description: "Security teams.", isPopular: true, features: [{ name: "10 Projects", included: true }, { name: "30 Days Hot Storage", included: true }] },
    { id: 3, name: "Enterprise", description: "Large organizations.", features: [{ name: "Unlimited Projects", included: true }, { name: "90 Days Hot Storage", included: true }] }
  ];

  const handleChoosePlan = (planName) => {
    const token = localStorage.getItem("token") || localStorage.getItem("warsoc_token");
    if (!token) { navigate("/login"); return; }

    const basePrice = basePlans[planName];
    const endpointsCost = (endpoints - 1) * PRICE_PER_ENDPOINT; 
    const storageCost = storageGB * PRICE_PER_GB;
    const addonsCost = (addons.fbr ? fbrPrice : 0) + (addons.peca ? pecaPrice : 0);
    const monthlyTotal = basePrice + endpointsCost + storageCost + addonsCost + retentionCost; // Added Retention Cost

    navigate("/payment", { 
        state: { 
            plan: planName, monthlyTotal, activationFee: ACTIVATION_FEE, cycle: billingCycle, 
            customization: { endpoints, storageGB, retentionMonths }, // Passing retention to payment
            addons 
        } 
    });
  };

  return (
    <section className="pricing-section" id="pricing">
      <div className="pricing-container">
        <div className="pricing-header">
          <h2 className="section-title">Transparent Pricing</h2>
          <p className="section-subtitle">Secure your infrastructure with the power of WarSOC.</p>
          
          <div className="billing-toggle">
            <span className={billingCycle === "monthly" ? "active" : ""}>Monthly</span>
            <div className={`toggle-switch ${billingCycle === "yearly" ? "toggled" : ""}`} onClick={() => setBillingCycle(billingCycle === "monthly" ? "yearly" : "monthly")}>
              <div className="switch-handle"></div>
            </div>
            <span className={billingCycle === "yearly" ? "active" : ""}>Yearly <span className="discount-badge">-20%</span></span>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '60px' }}> 
            <button 
                onClick={() => setShowAddons(!showAddons)}
                style={{
                    display: 'flex', alignItems: 'center', gap: '10px',
                    background: showAddons ? 'rgba(59, 130, 246, 0.15)' : '#1e293b',
                    border: '1px solid #3b82f6', color: '#fff',
                    padding: '14px 28px', borderRadius: '30px',
                    fontSize: '16px', fontWeight: '600', cursor: 'pointer',
                    transition: 'all 0.3s ease', boxShadow: '0 4px 15px rgba(59, 130, 246, 0.2)'
                }}
            >
                <Settings size={20} color="#3b82f6"/> 
                {showAddons ? "Hide Customization" : "Customize & Add-ons"} 
                {showAddons ? <ChevronUp size={20} color="#3b82f6"/> : <ChevronDown size={20} color="#3b82f6"/>}
            </button>
        </div>

        {/* COLLAPSIBLE PANEL */}
        {showAddons && (
            <div className="customization-wrapper">
                <div className="customization-panel">
                    <h3 style={{ color: '#fff', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}><Zap color="#3b82f6" /> Customize Package Limits</h3>
                    
                    <div className="customization-grid">
                        <div className="input-group">
                            <label><Monitor size={18} color="#3b82f6" /> Devices (Endpoints)</label>
                            <input type="number" min="1" max="1000" value={endpoints} onChange={(e) => setEndpoints(e.target.value)} />
                            <small>Base includes 1. +Rs 1,500/extra.</small>
                        </div>

                        <div className="input-group">
                            <label><HardDrive size={18} color="#10b981" /> Live Hot Storage (GBs)</label>
                            <select value={storageGB} onChange={(e) => setStorageGB(parseInt(e.target.value))}>
                                <option value="5">5 GB (Starter)</option>
                                <option value="10">10 GB (Recommended)</option>
                                <option value="50">50 GB (Enterprise)</option>
                            </select>
                            <small>+Rs 200 per GB for fast dashboard search.</small>
                        </div>

                        {/* 🚀 NAYA: LONG TERM RETENTION ADDON */}
                        <div className="input-group" style={{ border: '1px solid rgba(139, 92, 246, 0.5)', background: 'rgba(139, 92, 246, 0.05)' }}>
                            <label style={{ color: '#c4b5fd' }}><Archive size={18} color="#8b5cf6" /> Long-term Cold Archive</label>
                            <select value={retentionMonths} onChange={(e) => setRetentionMonths(parseInt(e.target.value))}>
                                <option value="0">No Archive (Auto-delete)</option>
                                <option value="3">3 Months Archive (+Rs 6,000)</option>
                                <option value="6">6 Months Archive (+Rs 10,000)</option>
                                <option value="12">12 Months Archive (+Rs 18,000)</option>
                            </select>
                            <small style={{ color: '#a78bfa' }}>We will email you 4 days before data is permanently deleted.</small>
                        </div>
                    </div>
                </div>

                <div className="addons-section">
                <h3 className="addons-title"><ShieldCheck size={24} color="#3b82f6" /> Compliance Add-ons</h3>
                <div className="addons-grid">
                    <label className={`addon-card ${addons.fbr ? 'active-blue' : ''}`}>
                    <input type="checkbox" checked={addons.fbr} onChange={() => setAddons(p => ({ ...p, fbr: !p.fbr }))} />
                    <div className="addon-info">
                        <strong>FBR POS Integrity Shield</strong><span>6 Years Vault Retention included</span>
                    </div>
                    <div className="addon-price">Rs {fbrPrice.toLocaleString()}<small>/mo</small></div>
                    </label>
                    <label className={`addon-card ${addons.peca ? 'active-teal' : ''}`}>
                    <input type="checkbox" checked={addons.peca} onChange={() => setAddons(p => ({ ...p, peca: !p.peca }))} />
                    <div className="addon-info">
                        <strong>PECA Evidence Vault</strong><span>Court-Admissible Chaining included</span>
                    </div>
                    <div className="addon-price teal-price">Rs {pecaPrice.toLocaleString()}<small>/mo</small></div>
                    </label>
                </div>
                </div>
            </div>
        )}

        <div className="pricing-grid">
          {plans.map((plan) => {
             const isSelected = selectedPlan === plan.name;
             const basePrice = basePlans[plan.name];
             const endpointsCost = (endpoints > 0 ? endpoints - 1 : 0) * PRICE_PER_ENDPOINT;
             const storageCost = storageGB * PRICE_PER_GB;
             const addonsCost = (addons.fbr ? fbrPrice : 0) + (addons.peca ? pecaPrice : 0);
             const displayPrice = basePrice + endpointsCost + storageCost + addonsCost + retentionCost; // Included retention

             return (
            <div key={plan.id} className={`pricing-card ${plan.isPopular ? "popular" : ""} ${isSelected ? "selected" : ""}`} onClick={() => setSelectedPlan(plan.name)}>
              {plan.isPopular && <div className="popular-badge">Most Popular</div>}
              
              <div className="card-header">
                <h3 className="plan-name">{plan.name} Plan</h3>
                <p className="plan-desc">{plan.description}</p>
                <div className="plan-price">
                  <span className="currency">Rs</span>
                  <span className="amount">{displayPrice.toLocaleString()}</span>
                  <span className="duration">/{billingCycle === "monthly" ? "mo" : "yr"}</span>
                </div>
                <div style={{ color: '#10b981', fontSize: '13px', fontWeight: '600', marginTop: '8px', opacity: 0.8 }}>
                    + Rs {ACTIVATION_FEE.toLocaleString()} One-time Setup
                </div>
              </div>

              <div className="card-features">
                <ul>
                  {plan.features.map((f, idx) => (
                    <li key={idx}><Check size={18} className="icon-check" /><span>{f.name}</span></li>
                  ))}
                </ul>
              </div>

              {(showAddons || endpoints > 1 || storageGB > 5 || retentionMonths > 0 || addons.fbr || addons.peca) && (
                  <div className="card-invoice-breakdown" style={{ marginTop: '20px', padding: '15px', background: isSelected ? 'rgba(59,130,246,0.08)' : '#0f172a', borderRadius: '8px', border: isSelected ? '1px solid rgba(59,130,246,0.2)' : '1px solid #334155' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#fff', fontSize: '14px', marginBottom: '10px', fontWeight: '600' }}><PackagePlus size={16} color="#3b82f6"/> Package Breakdown</div>
                      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                          {endpoints > 1 && <li style={{ fontSize: '13px', color: '#94a3b8', display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}><span>+ Extra Devices:</span><span style={{ color: '#fff' }}>{endpoints - 1}</span></li>}
                          {storageGB > 5 && <li style={{ fontSize: '13px', color: '#94a3b8', display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}><span>+ Hot Storage:</span><span style={{ color: '#fff' }}>{storageGB} GB</span></li>}
                          
                          {/* 🚀 Render Retention in Breakdown */}
                          {retentionMonths > 0 && <li style={{ fontSize: '13px', color: '#94a3b8', display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}><span style={{ color: '#c4b5fd' }}>+ Cold Archive:</span><span style={{ color: '#fff' }}>{retentionMonths} Months</span></li>}
                          
                          {addons.fbr && <li style={{ fontSize: '13px', color: '#94a3b8', display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}><span style={{ color: '#3b82f6' }}>+ FBR POS Shield:</span><span style={{ color: '#fff' }}>Active</span></li>}
                          {addons.peca && <li style={{ fontSize: '13px', color: '#94a3b8', display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}><span style={{ color: '#10b981' }}>+ PECA Vault:</span><span style={{ color: '#fff' }}>Active</span></li>}
                      </ul>
                  </div>
              )}

              <div className="card-footer">
                <button className={`cta-btn ${plan.isPopular || isSelected ? "primary" : "outline"}`} onClick={(e) => { e.stopPropagation(); handleChoosePlan(plan.name); }}>
                  Continue to Checkout
                </button>
              </div>
            </div>
          )})}
        </div>
      </div>
    </section>
  );
}