import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Zap, Monitor, Archive, ShieldCheck, PackagePlus, ArrowRight, ArrowLeft } from "lucide-react";
import apiClient from "../../../api/apiClient";
import { formatApiError } from "../../../utils/apiError";
import { calculatePricingEstimate, formatPkr } from "../../../utils/pricing";
import "./Pricing.css";

export default function Pricing({ standalone = false }) {
  const [billingCycle, setBillingCycle] = useState("monthly"); 
  const [catalog, setCatalog] = useState(null);
  const [pricingError, setPricingError] = useState("");
  
  // Customization States
  const [endpoints, setEndpoints] = useState(10);
  const [addons, setAddons] = useState({ fbr: false, peca: false });
  const [retentionMonths, setRetentionMonths] = useState(3);
  
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    apiClient.get("/sales/pricing")
      .then(({ data }) => {
        if (active) setCatalog(data);
      })
      .catch((error) => {
        if (active) setPricingError(formatApiError(error, "Pricing is temporarily unavailable."));
      });
    return () => { active = false; };
  }, []);

  const estimate = useMemo(
    () => calculatePricingEstimate(catalog, {
      endpoints,
      addons,
      cycle: billingCycle,
    }),
    [addons, billingCycle, catalog, endpoints],
  );

  const handleQuoteRequest = () => {
    navigate("/request-quote", { 
        state: { 
            plan: "WarSOC Deployment",
            cycle: billingCycle, 
            customization: { endpoints, retentionMonths },
            addons,
            catalog,
            estimate,
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
          <h2 className="section-title">Configure Your WarSOC Deployment</h2>
          <p className="section-subtitle">Transparent PKR list pricing for 10-50 endpoint deployments. Payment remains by manual invoice.</p>
          
          <div className="billing-toggle">
            <span className={billingCycle === "monthly" ? "active" : ""}>Monthly</span>
            <div className={`toggle-switch ${billingCycle === "yearly" ? "toggled" : ""}`} onClick={() => setBillingCycle(billingCycle === "monthly" ? "yearly" : "monthly")}>
              <div className="switch-handle"></div>
            </div>
            <span className={billingCycle === "yearly" ? "active" : ""}>Annual</span>
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
                            <input type="number" min="10" max="50" value={endpoints} onChange={(e) => setEndpoints(Math.min(50, Math.max(10, parseInt(e.target.value) || 10)))} />
                            <small>B2B pilot range: 10-50 devices.</small>
                        </div>

                        <div className="input-group archive-group">
                            <label><Archive size={18} color="#8b5cf6" /> Long-term Cold Archive</label>
                            <select value={retentionMonths} onChange={(e) => setRetentionMonths(parseInt(e.target.value))}>
                      <option value="3">3 Months General Archive</option>
                      <option value="6">6 Months General Archive</option>
                      <option value="9">9 Months General Archive</option>
                      <option value="12">12 Months General Archive</option>
                            </select>
                            <small>General archive is included. Compliance retention is enforced separately.</small>
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
                            <div className="addon-price">{catalog ? `${formatPkr(catalog.compliance_pack_monthly_prices?.fbr_pos)}/mo` : "Loading"}</div>
                        </label>
                        
                        <label className={`addon-card ${addons.peca ? 'active-teal' : ''}`}>
                            <input type="checkbox" checked={addons.peca} onChange={() => setAddons(p => ({ ...p, peca: !p.peca }))} />
                            <div className="addon-info">
                                <strong>PECA Evidence Vault</strong>
                                {/* <span>Court-Admissible Chaining included</span> */}
                            </div>
                            <div className="addon-price teal-price">{catalog ? `${formatPkr(catalog.compliance_pack_monthly_prices?.peca_forensic)}/mo` : "Loading"}</div>
                        </label>
                    </div>
                </div>
            </div>

            {/* RIGHT SIDE: LIVE SUMMARY CARD */}
            <div className="builder-summary">
                <div className="summary-card">
                    <div className="summary-header">
                        <h3>Your Deployment Estimate</h3>
                        <p>Public list price before applicable taxes</p>
                    </div>
                    
                    <div className="summary-price-box">
                        <span className="amount">{estimate ? formatPkr(estimate.recurringTotal) : "Loading"}</span>
                        <span className="duration">/{billingCycle === "yearly" ? "year" : "month"}</span>
                    </div>

                    <div className="summary-breakdown">
                        <div className="breakdown-title"><PackagePlus size={16} /> Scope Summary</div>
                        <ul>
                            <li>
                                <span>{endpoints} SIEM Endpoints</span>
                                <span>{estimate ? formatPkr(estimate.endpointMonthly * estimate.periodMonths) : "-"}</span>
                            </li>
                            <li>
                                <span>{retentionMonths}M General Archive</span>
                                <span className="free-text">Included</span>
                            </li>
                            {addons.fbr && (
                                <li className="highlight-blue">
                                    <span>FBR POS Shield</span>
                                    <span>{catalog ? formatPkr(Number(catalog.compliance_pack_monthly_prices?.fbr_pos || 0) * (estimate?.periodMonths || 1)) : "-"}</span>
                                </li>
                            )}
                            {addons.peca && (
                                <li className="highlight-teal">
                                    <span>PECA Vault</span>
                                    <span>{catalog ? formatPkr(Number(catalog.compliance_pack_monthly_prices?.peca_forensic || 0) * (estimate?.periodMonths || 1)) : "-"}</span>
                                </li>
                            )}
                        </ul>
                        
                        <div className="setup-fee">
                          One-time setup: {estimate ? formatPkr(estimate.setupFee) : "-"}. Taxes are added where applicable.
                        </div>
                    </div>

                    {pricingError && <div className="pricing-status error">{pricingError}</div>}
                    <button className="cta-btn primary" onClick={handleQuoteRequest} disabled={!catalog || !estimate}>
                        Request Quote <ArrowRight size={18} />
                    </button>
                </div>
            </div>

        </div>
      </div>
    </section>
  );
}
