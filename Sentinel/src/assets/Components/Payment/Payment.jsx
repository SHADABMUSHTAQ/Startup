import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "./Payment.css"; 

const Payment = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [processing, setProcessing] = useState(false);
  const [success, setSuccess] = useState(false);

  // Piche se jo Plan aur Price aaya hai usay receive karo
  const plan = location.state?.plan || "Basic";
  const price = location.state?.price || "$9";

  useEffect(() => {
    // Check karo user login hai ya nahi
    const token = localStorage.getItem("token");
    if (!token) {
      alert("Please login to purchase a plan!");
      navigate("/login");
    }
  }, [navigate]);

  const handlePayment = () => {
    setProcessing(true);

    // Fake Processing Delay (3 seconds) taaki real lage
    setTimeout(() => {
      setProcessing(false);
      setSuccess(true);
      
      // ✅✅✅ YE LOGIC ADD KIYA HAI (LOCK KHOLNE KE LIYE) ✅✅✅
      const userData = JSON.parse(localStorage.getItem("user_data")) || {};
      
      // Flag set kar rahe hain ki bande ne paise de diye
      userData.hasPlan = true; 
      userData.planName = plan;
      
      // Wapis save kar rahe hain
      localStorage.setItem("user_data", JSON.stringify(userData));
      // ✅✅✅✅✅✅✅✅✅✅

      // 2 second baad Dashboard par bhej do
      setTimeout(() => {
        alert(`Successfully subscribed to ${plan} Plan! 🚀`);
        navigate("/dashboard");
      }, 2000);
    }, 3000);
  };

  return (
    <div className="payment-container">
      <div className="payment-card">
        {success ? (
          <div className="success-view">
            <div className="checkmark">✔</div>
            <h2>Payment Successful!</h2>
            <p>Your <strong>{plan} Plan</strong> is now active.</p>
            <p>Redirecting to Dashboard...</p>
          </div>
        ) : (
          <>
            <h2>Confirm Subscription</h2>
            <div className="plan-summary">
              <div className="summary-row">
                <span>Selected Plan:</span>
                <strong style={{color: '#4da6ff'}}>{plan}</strong>
              </div>
              <div className="summary-row">
                <span>Total Price:</span>
                <strong style={{fontSize: '1.2rem'}}>{price}/mo</strong>
              </div>
            </div>

            {/* Fake Credit Card Form */}
            <form className="payment-form" onSubmit={(e) => e.preventDefault()}>
              <label>Card Information</label>
              <input type="text" value="4242 4242 4242 4242" disabled className="card-input" />
              
              <div className="row">
                <div style={{flex: 1}}>
                  <input type="text" value="12/28" disabled className="card-input" placeholder="MM/YY" />
                </div>
                <div style={{flex: 1}}>
                  <input type="text" value="123" disabled className="card-input" placeholder="CVC" />
                </div>
              </div>

              <button 
                className="pay-btn" 
                onClick={handlePayment} 
                disabled={processing}
              >
                {processing ? "Processing..." : `Pay ${price}`}
              </button>
            </form>
            
            <p className="secure-text">🔒 256-bit SSL Secure Payment</p>
            
            <button className="cancel-link" onClick={() => navigate(-1)} disabled={processing}>
              Cancel
            </button>
          </>
        )}
      </div>
    </div>
  );
};

export default Payment;