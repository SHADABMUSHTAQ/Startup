import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Zap, Monitor, HardDrive, Archive, ShieldCheck, PackagePlus, ArrowRight, ArrowLeft } from "lucide-react"; 
import "./Pricing.css";

export default function Pricing({ standalone = false }) {
  const [billingCycle, setBillingCycle] = useState("monthly"); 
  
  // Customization States
  const [endpoints, setEndpoints] = useState(10);
  const [storageGB, setStorageGB] = useState(5); 
  const [addons, setAddons] = useState({ fbr: false, peca: false });
  const [retentionMonths, setRetentionMonths] = useState(0); 
  
  const navigate = useNavigate();

  // Monthly Pricing Logic (PKR)
  const ACTIVATION_FEE = 5000; 
  const PRICE_PER_ENDPOINT = 2000; 
  const FBR_PRICE = 20000;
  const PECA_PRICE = 25000;

  // Keep estimates aligned with the backend pricing source of truth.
  const endpointsCost = endpoints * PRICE_PER_ENDPOINT;
  const addonsCost = (addons.fbr ? FBR_PRICE : 0) + (addons.peca ? PECA_PRICE : 0);

  const monthlyTotal = endpointsCost + addonsCost;
  
  // If yearly, multiply by 10 (gives them 2 months free equivalent)
  const displayPrice = billingCycle === "monthly" ? monthlyTotal : monthlyTotal * 10;

  const handleQuoteRequest = () => {
    navigate("/request-quote", { 
        state: { 
            plan: "Custom Platform", 
            finalPrice: displayPrice, 
            activationFee: ACTIVATION_FEE, 
            cycle: billingCycle, 
            customization: { endpoints, storageGB, retentionMonths },
            addons 
        } 
    });
  };

  return (
    <section className={`pricing-section ${standalone ? "pricing-standalone" : ""}`} id="pricing">
      <div className="pricing-container">
        {standalone && (
          <Link to="/login" className="pricing-back-link">
            <ArrowLeft size={16} /> Back to Login
          </Link>
        )}
        
        {/* HEADER */}
        <div className="pricing-header">
          <h2 className="section-title">Build Your Platform</h2>
          <p className="section-subtitle">Zero base platform fees. Only pay for the infrastructure and compliance you use.</p>
          
          <div className="billing-toggle">
            <span className={billingCycle === "monthly" ? "active" : ""}>Monthly</span>
            <div className={`toggle-switch ${billingCycle === "yearly" ? "toggled" : ""}`} onClick={() => setBillingCycle(billingCycle === "monthly" ? "yearly" : "monthly")}>
              <div className="switch-handle"></div>
            </div>
            <span className={billingCycle === "yearly" ? "active" : ""}>Yearly <span className="discount-badge">2 Months Free</span></span>
          </div>
        </div>

        {/* MAIN SPLIT LAYOUT */}
        <div className="pricing-builder-grid">
            
            {/* LEFT SIDE: CONTROLS */}
            <div className="builder-controls">
                
                {/* Infrastructure Panel */}
                <div className="customization-panel">
                    <h3 className="panel-title"><Zap color="#3b82f6" /> Infrastructure Limits</h3>
                    
                    <div className="customization-grid">
                        <div className="input-group">
                            <label><Monitor size={18} color="#3b82f6" /> Devices (Endpoints)</label>
                            <input type="number" min="10" max="1000" value={endpoints} onChange={(e) => setEndpoints(Math.max(10, parseInt(e.target.value) || 10))} />
                            <small>B2B minimum: 10 devices. Rs 2,000 per endpoint monthly.</small>
                        </div>

                        <div className="input-group">
                            <label><HardDrive size={18} color="#10b981" /> Live Hot Storage (GBs)</label>
                            <select value={storageGB} onChange={(e) => setStorageGB(parseInt(e.target.value))}>
                                <option value="5">5 GB (Starter)</option>
                                <option value="10">10 GB (Recommended)</option>
                                <option value="50">50 GB (Enterprise)</option>
                            </select>
                            <small>Capacity is confirmed by the deployment team during provisioning.</small>
                        </div>

                        <div className="input-group archive-group">
                            <label><Archive size={18} color="#8b5cf6" /> Long-term Cold Archive</label>
                            <select value={retentionMonths} onChange={(e) => setRetentionMonths(parseInt(e.target.value))}>
                                <option value="0">No Optional General Archive</option>
                                <option value="3">3 Months General Archive</option>
                                <option value="6">6 Months General Archive</option>
                                <option value="12">12 Months General Archive</option>
                            </select>
                            <small>Compliance vault retention is enforced separately by the selected pack.</small>
                        </div>
                    </div>
                </div>

                {/* Add-ons Panel */}
                <div className="addons-section">
                    <h3 className="addons-title"><ShieldCheck size={24} color="#3b82f6" /> Compliance Add-ons</h3>
                    <div className="addons-grid">
                        <label className={`addon-card ${addons.fbr ? 'active-blue' : ''}`}>
                            <input type="checkbox" checked={addons.fbr} onChange={() => setAddons(p => ({ ...p, fbr: !p.fbr }))} />
                            <div className="addon-info">
                                <strong>FBR POS Integrity Shield</strong>
                                {/* <span>6 Years Vault Retention included</span> */}
                            </div>
                            <div className="addon-price">Rs {FBR_PRICE.toLocaleString()}<small>/mo</small></div>
                        </label>
                        
                        <label className={`addon-card ${addons.peca ? 'active-teal' : ''}`}>
                            <input type="checkbox" checked={addons.peca} onChange={() => setAddons(p => ({ ...p, peca: !p.peca }))} />
                            <div className="addon-info">
                                <strong>PECA Evidence Vault</strong>
                                {/* <span>Court-Admissible Chaining included</span> */}
                            </div>
                            <div className="addon-price teal-price">Rs {PECA_PRICE.toLocaleString()}<small>/mo</small></div>
                        </label>
                    </div>
                </div>
            </div>

            {/* RIGHT SIDE: LIVE SUMMARY CARD */}
            <div className="builder-summary">
                <div className="summary-card">
                    <div className="summary-header">
                        <h3>Your Custom Plan</h3>
                        <p>Real-time cost estimation</p>
                    </div>
                    
                    <div className="summary-price-box">
                        <span className="currency">Rs</span>
                        <span className="amount">{displayPrice.toLocaleString()}</span>
                        <span className="duration">/{billingCycle === "monthly" ? "mo" : "yr"}</span>
                    </div>

                    <div className="summary-breakdown">
                        <div className="breakdown-title"><PackagePlus size={16} /> Invoice Breakdown</div>
                        <ul>
                            <li>
                                <span>Platform Base Fee</span>
                                <span className="free-text">Free</span>
                            </li>
                            <li>
                                <span>{endpoints} Endpoint{endpoints > 1 ? 's' : ''}</span>
                                <span>Rs {(endpointsCost * (billingCycle === 'yearly' ? 10 : 1)).toLocaleString()}</span>
                            </li>
                            <li>
                                <span>{storageGB} GB Hot Storage</span>
                                <span>Scoped</span>
                            </li>
                            {retentionMonths > 0 && (
                                <li className="highlight-purple">
                                    <span>{retentionMonths}M Cold Archive</span>
                                    <span>Scoped</span>
                                </li>
                            )}
                            {addons.fbr && (
                                <li className="highlight-blue">
                                    <span>FBR POS Shield</span>
                                    <span>Rs {(FBR_PRICE * (billingCycle === 'yearly' ? 10 : 1)).toLocaleString()}</span>
                                </li>
                            )}
                            {addons.peca && (
                                <li className="highlight-teal">
                                    <span>PECA Vault</span>
                                    <span>Rs {(PECA_PRICE * (billingCycle === 'yearly' ? 10 : 1)).toLocaleString()}</span>
                                </li>
                            )}
                        </ul>
                        
                        <div className="setup-fee">
                            + Rs {ACTIVATION_FEE.toLocaleString()} One-time Setup Fee
                        </div>
                    </div>

                    <button className="cta-btn primary" onClick={handleQuoteRequest} disabled={displayPrice === 0}>
                        Request Custom Quote <ArrowRight size={18} />
                    </button>
                </div>
            </div>

        </div>
      </div>
    </section>
  );
}
