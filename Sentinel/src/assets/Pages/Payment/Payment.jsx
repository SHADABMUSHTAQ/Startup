import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { updateUserPlan } from "../../../api"; // ✅ Use Centralized API
import { CreditCard, Lock, ShieldCheck, ArrowLeft } from "lucide-react"; 
import "./Payment.css"; 

const Payment = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [processing, setProcessing] = useState(false);
  const [success, setSuccess] = useState(false);

  // Data receiving from Pricing Page
  const planName = location.state?.plan || "Starter";
  const price = location.state?.price || "$0";
  const cycle = location.state?.cycle || "monthly";

  useEffect(() => {
    const token = localStorage.getItem("token") || localStorage.getItem("warsoc_token");
    if (!token) {
      alert("Session expired. Please login again!");
      navigate("/login", { replace: true });
    }
  }, [navigate]);

  const handlePayment = async () => {
    const userDataStr = localStorage.getItem("user_data");
    
    if (!userDataStr) {
      alert("User session not found. Please relogin.");
      navigate("/login");
      return;
    }

    setProcessing(true);

    try {
      // 1. Fake Payment Delay (To look realistic)
      await new Promise(resolve => setTimeout(resolve, 2000));

      const user = JSON.parse(userDataStr);
      
      // 2. Backend API Call
      console.log(`Activating ${planName} for ${user.username}...`);
      await updateUserPlan(user.username, planName);

      // 3. Local Storage Sync
      user.has_active_plan = true;
      user.plan_type = planName;
      localStorage.setItem("user_data", JSON.stringify(user));

      // 4. Success State Trigger
      setSuccess(true);
      setProcessing(false);

      // 5. Redirect after Success Animation
      setTimeout(() => {
        navigate("/dashboard", { replace: true });
      }, 2500);

    } catch (error) {
      console.error("Payment Error:", error);
      alert("Transaction Failed: " + error.message);
      setProcessing(false);
    }
  };

  return (
    <div className="payment-container">
      {/* Background Decor */}
      <div className="glow-bg top"></div>
      <div className="glow-bg bottom"></div>

      <div className="payment-card">
        {success ? (
          <div className="success-view">
            <div className="checkmark-circle">
              <ShieldCheck size={50} />
            </div>
            <h2>Payment Successful!</h2>
            <p>Your subscription to <strong>{planName} Plan</strong> is now active.</p>
            <div className="redirect-msg">Redirecting to Dashboard...</div>
          </div>
        ) : (
          <>
            <div className="payment-header">
              <div className="secure-badge">
                <Lock size={14} /> Secure SSL Checkout
              </div>
              <h2>Complete Your Order</h2>
              <p>Sentinel Pay Gateway</p>
            </div>

            <div className="plan-summary">
              <div className="summary-row">
                <span>Plan</span>
                <strong className="highlight">{planName} ({cycle})</strong>
              </div>
              <div className="summary-row">
                <span>Total Due</span>
                <strong className="price-tag">${price}</strong>
              </div>
            </div>

            <form className="payment-form" onSubmit={(e) => e.preventDefault()}>
              <div className="input-group">
                <label>Card Number</label>
                <div className="input-wrapper">
                  <CreditCard className="icon" size={18} />
                  <input type="text" value="•••• •••• •••• 4242" disabled className="mock-field" />
                </div>
              </div>
              
              <div className="row">
                <div className="input-group">
                  <label>Expiry</label>
                  <input type="text" value="12 / 28" disabled className="mock-field centered" />
                </div>
                <div className="input-group">
                  <label>CVC</label>
                  <input type="text" value="•••" disabled className="mock-field centered" />
                </div>
              </div>

              <button 
                className={`pay-btn ${processing ? "processing" : ""}`}
                onClick={handlePayment} 
                disabled={processing}
              >
                {processing ? (
                  <span className="loader-text">Processing Payment...</span>
                ) : (
                  <>Activate Subscription <ArrowLeft size={16} style={{rotate:'180deg'}} /></>
                )}
              </button>
            </form>
            
            <button 
              className="cancel-link" 
              onClick={() => navigate(-1)} 
              disabled={processing}
            >
              Cancel Transaction
            </button>
          </>
        )}
      </div>
    </div>
  );
};

export default Payment;