import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser, registerUser } from "../../../api"; 
import { User, Lock, Mail, ArrowRight, ShieldCheck, CheckCircle, AlertTriangle, X } from "lucide-react";
import "./Login.css";

export default function Login() {
  const [signState, setSignState] = useState("Sign In");
  const [name, setName] = useState("");
  const [email, setEmail] = useState(""); 
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  
  // ✅ TOAST STATE
  const [toast, setToast] = useState(null); 

  const navigate = useNavigate();

  // ✅ 1. AUTO-REDIRECT (Bypassing Pricing)
  // Page load hote hi check karega: Agar token hai toh direct Dashboard!
  useEffect(() => {
    const token = localStorage.getItem("token");
    const userDataStr = localStorage.getItem("user_data");
    
    if (token && userDataStr) {
      console.log("Session Found: Bypassing Pricing & Going to Dashboard");
      navigate("/dashboard"); // 🚀 ALWAYS GO TO DASHBOARD
    }
  }, [navigate]);

  // ✅ HELPER: SHOW TOAST
  const showToast = (type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      if (signState === "Sign Up") {
        // ==============================
        // 🚀 FLOW STEP 1: SIGN UP
        // ==============================
        await registerUser(name, email, password);
        
        // Success Message
        showToast("success", "Account Created! Please Sign In.");
        
        // Form empty karein
        setName("");
        setPassword("");
        
        // ✅ User ko "Sign In" wapas bhejein
        setTimeout(() => setSignState("Sign In"), 1500);
        
      } else {
        // ==============================
        // 🚀 FLOW STEP 2: SIGN IN
        // ==============================
        const data = await loginUser(email, password);
        
        // Data Save
        localStorage.setItem("token", data.access_token);
        
        const userData = {
            username: data.username,
            email: email, 
            has_active_plan: data.has_active_plan, 
            plan_type: data.plan_type
        };
        localStorage.setItem("user_data", JSON.stringify(userData));
        localStorage.setItem("login_timestamp", Date.now()); 
        
        showToast("success", "Login Successful! Loading Dashboard...");

        // ==============================
        // 🚀 FLOW STEP 3: DIRECT TO DASHBOARD (MVP Bypass)
        // ==============================
        setTimeout(() => {
            navigate("/dashboard"); // 🚀 NO MORE PRICING PAGE
        }, 1000);
      }
    } catch (err) {
      console.error("Auth Error:", err);
      showToast("error", err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      
      {/* Toast Notification */}
      {toast && (
        <div className={`toast-notification ${toast.type}`}>
            {toast.type === 'success' ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
            <span>{toast.msg}</span>
            <button onClick={() => setToast(null)}><X size={16} /></button>
        </div>
      )}

      <div className="auth-glow glow-1"></div>
      <div className="auth-glow glow-2"></div>

      <div className="auth-card">
        <div className="auth-header">
          <ShieldCheck size={40} className="auth-logo-icon" />
          <h2>{signState === "Sign In" ? "Welcome Back" : "Create Account"}</h2>
          <p>
            {signState === "Sign In" 
              ? "Enter your credentials to access your secure dashboard." 
              : "Join WarSOC to secure your digital infrastructure."}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {signState === "Sign Up" && (
            <div className="input-group">
              <User className="input-icon" size={20} />
              <input 
                type="text" 
                placeholder="Full Name" 
                value={name} 
                onChange={(e) => setName(e.target.value)} 
                required 
              />
            </div>
          )}

          <div className="input-group">
            <Mail className="input-icon" size={20} />
            <input 
              type="text" 
              placeholder="Username or Email" 
              value={email} 
              onChange={(e) => setEmail(e.target.value)} 
              required 
            />
          </div>

          <div className="input-group">
            <Lock className="input-icon" size={20} />
            <input 
              type="password" 
              placeholder="Password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              required 
            />
          </div>

          <button type="submit" className="auth-btn" disabled={loading}>
            {loading ? "Processing..." : (
              <>
                {signState} <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        <div className="auth-footer">
          {signState === "Sign In" ? (
            <p>
              New to WarSOC?{" "}
              <span onClick={() => { setSignState("Sign Up"); setToast(null); }}>
                Create Account
              </span>
            </p>
          ) : (
            <p>
              Already have an account?{" "}
              <span onClick={() => { setSignState("Sign In"); setToast(null); }}>
                Sign In
              </span>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}