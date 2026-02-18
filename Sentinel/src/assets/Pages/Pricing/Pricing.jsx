import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, X, AlertTriangle, CheckCircle, Info } from "lucide-react"; 
// ❌ updateUserPlan import HATA diya hai, kyunki yahan activate nahi karna
import "./Pricing.css";

function Pricing() {
  const [selectedPlan, setSelectedPlan] = useState("Pro"); 
  const [billingCycle, setBillingCycle] = useState("monthly"); 
  
  // Custom Toast/Modal States
  const [toast, setToast] = useState(null); 
  const [showLoginModal, setShowLoginModal] = useState(false);

  const navigate = useNavigate();

  // --- Helper: Show Toast ---
  const showToast = (type, title, msg) => {
    setToast({ type, title, msg });
    setTimeout(() => setToast(null), 4000); 
  };

  const plans = [
    {
      id: 1,
      name: "Starter",
      price: billingCycle === "monthly" ? "0" : "0",
      description: "Perfect for students and hobbyists.",
      features: [
        { name: "1 Project", included: true },
        { name: "Community Support", included: true },
        { name: "Basic Security Scan", included: true },
        { name: "Real-time Alerts", included: false },
        { name: "API Access", included: false },
      ],
    },
    {
      id: 2,
      name: "Pro",
      price: billingCycle === "monthly" ? "29" : "290",
      description: "For security professionals & teams.",
      isPopular: true, 
      features: [
        { name: "10 Projects", included: true },
        { name: "Priority Email Support", included: true },
        { name: "Advanced Threat Intel", included: true },
        { name: "Real-time Alerts", included: true },
        { name: "API Access", included: false },
      ],
    },
    {
      id: 3,
      name: "Enterprise",
      price: billingCycle === "monthly" ? "99" : "990",
      description: "For large scale organizations.",
      features: [
        { name: "Unlimited Projects", included: true },
        { name: "24/7 Dedicated Support", included: true },
        { name: "Custom Security Rules", included: true },
        { name: "Real-time Alerts", included: true },
        { name: "Full API Access", included: true },
      ],
    },
  ];

  // ✅ CORRECTED HANDLER: Navigate to Payment Page
  const handleChoosePlan = (plan) => {
    // 1. Auth Check
    const token = localStorage.getItem("token") || localStorage.getItem("warsoc_token");
    
    if (!token) {
      setShowLoginModal(true);
      return;
    }

    if (plan.name === "Enterprise") {
        showToast("info", "Contact Sales", "Please contact sales@warsoc.com for Enterprise licensing.");
        return;
    }

    setSelectedPlan(plan.name);

    // ✅ DIRECT ACTIVATION HATA DI
    // Ab hum user ko Payment Page par bhej rahe hain details ke saath
    navigate("/payment", {
        state: {
            plan: plan.name,
            price: plan.price,
            cycle: billingCycle
        }
    });
  };

  return (
    <section className="pricing-section" id="pricing">
      {/* --- TOAST --- */}
      {toast && (
          <div className={`toast-container`}>
              <div className={`toast ${toast.type}`}>
                  {toast.type === 'success' && <CheckCircle size={20} color="#2ecc71" />}
                  {toast.type === 'error' && <AlertTriangle size={20} color="#ff4d4d" />}
                  {toast.type === 'info' && <Info size={20} color="#4da6ff" />}
                  <div className="toast-content">
                      <h4>{toast.title}</h4>
                      <p>{toast.msg}</p>
                  </div>
                  <button className="toast-close" onClick={() => setToast(null)}>×</button>
              </div>
          </div>
      )}

      {/* --- LOGIN MODAL --- */}
      {showLoginModal && (
          <div className="modal-overlay">
              <div className="modal-box">
                  <div style={{marginBottom: '15px'}}><AlertTriangle size={40} color="#feca57"/></div>
                  <h3>Login Required</h3>
                  <p>You need to be logged in to subscribe to a plan.</p>
                  <div className="modal-actions">
                      <button className="btn-cancel" onClick={() => setShowLoginModal(false)}>Cancel</button>
                      <button className="btn-confirm" onClick={() => navigate("/login")}>Go to Login</button>
                  </div>
              </div>
          </div>
      )}

      <div className="glow-circle top-left"></div>
      <div className="glow-circle bottom-right"></div>

      <div className="pricing-container">
        <div className="pricing-header">
          <h2 className="section-title">Transparent Pricing</h2>
          <p className="section-subtitle">
            Secure your infrastructure with the power of WarSOC. <br />
            Choose the plan that scales with you.
          </p>

          <div className="billing-toggle">
            <span className={billingCycle === "monthly" ? "active" : ""}>Monthly</span>
            <div 
              className={`toggle-switch ${billingCycle === "yearly" ? "toggled" : ""}`}
              onClick={() => setBillingCycle(billingCycle === "monthly" ? "yearly" : "monthly")}
            >
              <div className="switch-handle"></div>
            </div>
            <span className={billingCycle === "yearly" ? "active" : ""}>
              Yearly <span className="discount-badge">-20%</span>
            </span>
          </div>
        </div>

        <div className="pricing-grid">
          {plans.map((plan) => (
            <div
              key={plan.id}
              className={`pricing-card ${plan.isPopular ? "popular" : ""} ${selectedPlan === plan.name ? "selected" : ""}`}
              onClick={() => setSelectedPlan(plan.name)}
            >
              {plan.isPopular && <div className="popular-badge">Most Popular</div>}
              
              <div className="card-header">
                <h3 className="plan-name">{plan.name}</h3>
                <p className="plan-desc">{plan.description}</p>
                <div className="plan-price">
                  <span className="currency">$</span>
                  <span className="amount">{plan.price}</span>
                  <span className="duration">/{billingCycle === "monthly" ? "mo" : "yr"}</span>
                </div>
              </div>

              <div className="card-features">
                <ul>
                  {plan.features.map((feature, index) => (
                    <li key={index} className={feature.included ? "" : "disabled"}>
                      {feature.included ? (
                        <Check size={18} className="icon-check" />
                      ) : (
                        <X size={18} className="icon-cross" />
                      )}
                      <span>{feature.name}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="card-footer">
                <button
                  className={`cta-btn ${plan.isPopular ? "primary" : "outline"}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleChoosePlan(plan);
                  }}
                >
                  {plan.name === "Enterprise" ? "Contact Sales" : "Get Started"}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default Pricing;