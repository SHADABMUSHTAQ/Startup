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
  const [toast, setToast] = useState(null); 

  const navigate = useNavigate();

useEffect(() => {
    const token = localStorage.getItem("token");
    const userDataStr = localStorage.getItem("user_data");
    
    if (token && userDataStr) {
      const user = JSON.parse(userDataStr);
      // 🚀 THE FIX: Agar plan Free hai toh Pricing par bhejo!
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
        
// Data Save
        localStorage.setItem("token", data.access_token);
        
        const userData = {
            username: data.username,
            email: email, 
            has_active_plan: data.has_active_plan, 
            plan_type: data.plan_type,
            tenant_id: data.tenant_id,
            role: data.role || "admin" // 🚀 NAYA: Backend se role aayega (admin ya auditor)
        };
        localStorage.setItem("user_data", JSON.stringify(userData));
        localStorage.setItem("login_timestamp", Date.now()); 
        
        showToast("success", "Login Successful!");

        // 🚀 THE FIX: Role-based Redirection
        setTimeout(() => {
            if (userData.role === "auditor") {
                navigate("/auditor"); // Auditor ko seedha Read-Only view par bhejo
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
    <div className="auth-container">
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
          <p>{signState === "Sign In" ? "Enter your credentials to access your secure dashboard." : "Join WarSOC to secure your digital infrastructure."}</p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {signState === "Sign Up" && (
            <div className="input-group">
              <User className="input-icon" size={20} />
              <input type="text" placeholder="Full Name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
          )}
          <div className="input-group">
            <Mail className="input-icon" size={20} />
            <input type="text" placeholder="Username or Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="input-group">
            <Lock className="input-icon" size={20} />
            <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <button type="submit" className="auth-btn" disabled={loading}>
            {loading ? "Processing..." : <>{signState} <ArrowRight size={18} /></>}
          </button>
        </form>

        <div className="auth-footer">
          {signState === "Sign In" ? (
            <p>New to WarSOC? <span onClick={() => { setSignState("Sign Up"); setToast(null); }}>Create Account</span></p>
          ) : (
            <p>Already have an account? <span onClick={() => { setSignState("Sign In"); setToast(null); }}>Sign In</span></p>
          )}
        </div>
      </div>
    </div>
  );
}