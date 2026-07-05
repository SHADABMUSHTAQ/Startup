import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Lock, Mail, ArrowRight, ArrowLeft, CheckCircle, Shield, Activity, Database, AlertTriangle, X, Bot } from "lucide-react";
import apiClient from "../../../api/apiClient";
import { useAuthStore } from "../../../store/authStore";
import "./Login.css";

export default function Login() {
  const [email, setEmail] = useState(""); 
  const [password, setPassword] = useState("");
  const [robotVerified, setRobotVerified] = useState(false);
  const [showRobotPuzzle, setShowRobotPuzzle] = useState(false);
  const [puzzleError, setPuzzleError] = useState("");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null); 

  const { checkAuth } = useAuthStore();
  const navigate = useNavigate();
  const puzzleTiles = [
    { id: "mail", label: "Email", icon: Mail },
    { id: "lock", label: "Password", icon: Lock },
    { id: "shield", label: "Security Shield", icon: Shield },
    { id: "database", label: "Database", icon: Database },
    { id: "activity", label: "Activity", icon: Activity },
    { id: "bot", label: "Bot", icon: Bot },
  ];

  const showToast = (type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!robotVerified) {
      showToast("error", "Please verify that you are not a robot.");
      return;
    }

    setLoading(true);
    try {
      await apiClient.post('/auth/login', {
        username: email,
        password: password
      }, {
        headers: { 'Content-Type': 'application/json' }
      });

      const authenticated = await checkAuth();
      if (!authenticated) {
        throw new Error("Login succeeded, but the session could not be verified.");
      }
      const authState = useAuthStore.getState();

      showToast("success", "Login Successful!");

      setTimeout(() => {
        if (authState.role === "auditor" || authState.role === "Auditor" || (authState.plan_type && authState.plan_type !== "Free")) {
          navigate("/dashboard");
        } else {
          navigate("/pricing");
        }
      }, 1000);
    } catch (err) {
      showToast("error", err.userMessage || err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  const openRobotPuzzle = () => {
    if (robotVerified) return;
    setPuzzleError("");
    setShowRobotPuzzle(true);
  };

  const handlePuzzlePick = (tileId) => {
    if (tileId === "shield") {
      setRobotVerified(true);
      setShowRobotPuzzle(false);
      setPuzzleError("");
      showToast("success", "Robot verification complete.");
      return;
    }

    setPuzzleError("Try again: select the security shield tile.");
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

      {showRobotPuzzle && (
        <div className="robot-puzzle-overlay" role="dialog" aria-modal="true" aria-labelledby="robot-puzzle-title">
          <div className="robot-puzzle-modal">
            <button className="robot-puzzle-close" type="button" onClick={() => setShowRobotPuzzle(false)} aria-label="Close verification puzzle">
              <X size={18} />
            </button>
            <div className="robot-puzzle-header">
              <div className="robot-puzzle-badge">
                <Bot size={22} />
              </div>
              <div>
                <h3 id="robot-puzzle-title">Security Check</h3>
                <p>Select the security shield to continue.</p>
              </div>
            </div>
            <div className="robot-puzzle-grid">
              {puzzleTiles.map(({ id, label, icon: Icon }) => (
                <button type="button" className="robot-puzzle-tile" key={id} onClick={() => handlePuzzlePick(id)}>
                  <Icon size={24} />
                  <span>{label}</span>
                </button>
              ))}
            </div>
            {puzzleError && <p className="robot-puzzle-error">{puzzleError}</p>}
          </div>
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
                    <CheckCircle size={22} color="#ffffff" fill="#b7eb48" className="check-icon" />
                </div>
                <div className="bullet-item">
                    <div className="bullet-icon-box"><Database size={18} /></div>
                    <span>Immutable Audit Trails (WORM)</span>
                    <CheckCircle size={22} color="#ffffff" fill="#b7eb48" className="check-icon" />
                </div>
                <div className="bullet-item">
                    <div className="bullet-icon-box"><Activity size={18} /></div>
                    <span>Automated Compliance Reporting</span>
                    <CheckCircle size={22} color="#ffffff" fill="#b7eb48" className="check-icon" />
                </div>
            </div>
        </div>
      </div>

      {/* RIGHT SIDE: THE FORM WITH LIGHTNING DIVIDER */}
      <div className="login-right-wrapper">
        <div className="login-right">
          <div className="login-form-box">
              <div className="form-header">
                  <h2>Welcome Back</h2>
                  <p>Use the credentials issued after WarSOC provisions your environment.</p>
              </div>

              <form onSubmit={handleSubmit} className="auth-form">
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
                      </div>
                      <div className="input-group">
                          <Lock className="input-icon" size={18} />
                          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                      </div>
                  </div>

                  <button type="button" className={`robot-check ${robotVerified ? "verified" : ""}`} onClick={openRobotPuzzle}>
                      <span className="robot-box" aria-hidden="true">
                        {robotVerified && <CheckCircle size={18} />}
                      </span>
                      <span className="robot-copy">
                        <strong>I am not a robot</strong>
                        <small>{robotVerified ? "Verification complete" : "Click to solve puzzle"}</small>
                      </span>
                      <Bot className="robot-icon" size={22} />
                  </button>
                  
                  <button type="submit" className="auth-btn" disabled={loading || !robotVerified}>
                      {loading ? "Processing..." : <>Sign In <ArrowRight size={18} /></>}
                  </button>
              </form>

              <div className="auth-footer">
                  <p>Need access? <Link to="/pricing">Request a custom quote</Link></p>
              </div>
          </div>
        </div>
      </div>
    </div>
  );
}
