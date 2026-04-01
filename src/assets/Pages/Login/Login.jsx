import React, { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { loginUser, registerUser } from "../../../api"; 
import { Lock, Mail, ArrowRight, ArrowLeft, CheckCircle, Shield, Activity, Database, AlertTriangle, X, User } from "lucide-react";
import "./Login.css";

export default function Login() {
  const [signState, setSignState] = useState("Sign In");
  const [name, setName] = useState("");
  const [email, setEmail] = useState(""); 
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null); 

  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("token");
    const userDataStr = localStorage.getItem("user_data");
    
    if (token && userDataStr) {
      const user = JSON.parse(userDataStr);
      if (user.has_active_plan === true && user.plan_type !== "Free") {
         navigate("/dashboard");
      } else {
         navigate("/pricing");
      }
    }
  }, [navigate]);

  const showToast = (type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (signState === "Sign Up") {
        await registerUser(name, email, password);
        showToast("success", "Account Created! Please Sign In.");
        setName(""); setPassword("");
        setTimeout(() => setSignState("Sign In"), 1500);
      } else {
        const data = await loginUser(email, password);
        
        localStorage.setItem("token", data.access_token);
        
        const userData = {
            username: data.username,
            email: email, 
            has_active_plan: data.has_active_plan, 
            plan_type: data.plan_type,
            tenant_id: data.tenant_id,
            role: data.role || "admin" 
        };
        localStorage.setItem("user_data", JSON.stringify(userData));
        localStorage.setItem("login_timestamp", Date.now()); 
        
        showToast("success", "Login Successful!");

        setTimeout(() => {
            if (userData.role === "auditor") {
                navigate("/auditor"); 
            } else if (userData.has_active_plan === true && userData.plan_type !== "Free") {
                navigate("/dashboard");
            } else {
                navigate("/pricing");
            }
        }, 1000);
      }
    } catch (err) {
      showToast("error", err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="split-login-container">
      {toast && (
        <div className={`toast-notification ${toast.type}`}>
            {toast.type === 'success' ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
            <span>{toast.msg}</span>
            <button onClick={() => setToast(null)}><X size={16} /></button>
        </div>
      )}

      {/* LEFT SIDE: BRANDING & INFO */}
      <div className="login-left">
        {/* 🚀 THE FIX: Sirf Back to Home, No Logo */}
        <Link to="/" className="back-to-home">
            <ArrowLeft size={16} /> Back to Home
        </Link>
        
        <div className="left-content">
            <h1 className="login-headline">Secure Your <br/><span className="gradient-text">Digital Frontier.</span></h1>
            <p className="login-subheadline">
              Log in to access your enterprise-grade SIEM dashboard. Monitor threats, ensure compliance, and manage your infrastructure in real-time.
            </p>
            
            <div className="feature-bullets">
                <div className="bullet-item">
                    <div className="bullet-icon-box"><Shield size={18} /></div>
                    <span>Real-Time Threat Detection & Alerting</span>
                    <CheckCircle size={22} color="#ffffff" fill="#2ecc71" className="check-icon" />
                </div>
                <div className="bullet-item">
                    <div className="bullet-icon-box"><Database size={18} /></div>
                    <span>Immutable Audit Trails (WORM)</span>
                    <CheckCircle size={22} color="#ffffff" fill="#2ecc71" className="check-icon" />
                </div>
                <div className="bullet-item">
                    <div className="bullet-icon-box"><Activity size={18} /></div>
                    <span>Automated Compliance Reporting</span>
                    <CheckCircle size={22} color="#ffffff" fill="#2ecc71" className="check-icon" />
                </div>
            </div>
        </div>
      </div>

      {/* RIGHT SIDE: THE FORM WITH LIGHTNING DIVIDER */}
      <div className="login-right-wrapper">
        <div className="login-right">
          <div className="login-form-box">
              <div className="form-header">
                  <h2>{signState === "Sign In" ? "Welcome Back" : "Create Account"}</h2>
                  <p>Enter your credentials to confirm your identity.</p>
              </div>

              <form onSubmit={handleSubmit} className="auth-form">
                  {signState === "Sign Up" && (
                      <div className="input-group-container">
                          <label>Full Name</label>
                          <div className="input-group">
                              <User className="input-icon" size={18} />
                              <input type="text" placeholder="John Doe" value={name} onChange={(e) => setName(e.target.value)} required />
                          </div>
                      </div>
                  )}
                  
                  <div className="input-group-container">
                      <label>Username or Email</label>
                      <div className="input-group">
                          <Mail className="input-icon" size={18} />
                          <input type="text" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                      </div>
                  </div>
                  
                  <div className="input-group-container">
                      <div className="password-header">
                        <label>Password</label>
                        {signState === "Sign In" && <span className="forgot-password">Forgot Password?</span>}
                      </div>
                      <div className="input-group">
                          <Lock className="input-icon" size={18} />
                          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                      </div>
                  </div>
                  
                  <button type="submit" className="auth-btn" disabled={loading}>
                      {loading ? "Processing..." : <>{signState} <ArrowRight size={18} /></>}
                  </button>
              </form>

              <div className="auth-footer">
                  {signState === "Sign In" ? (
                      <p>New to War-SOC? <span onClick={() => { setSignState("Sign Up"); setToast(null); }}>Create Account</span></p>
                  ) : (
                      <p>Already have an account? <span onClick={() => { setSignState("Sign In"); setToast(null); }}>Sign In</span></p>
                  )}
              </div>
          </div>
        </div>
      </div>
    </div>
  );
}