import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AlertTriangle, ArrowLeft, ArrowRight, CheckCircle, Lock, Shield } from "lucide-react";
import apiClient from "../../../api/apiClient";
import "../Login/Login.css";

export default function SetPassword() {
  const navigate = useNavigate();
  const token = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") || "";
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!token) {
      setResult({ type: "error", message: "This invitation link is incomplete." });
      return;
    }
    if (password !== confirmation) {
      setResult({ type: "error", message: "Passwords do not match." });
      return;
    }

    setLoading(true);
    try {
      await apiClient.post("/auth/activate-invite", { token, password });
      setResult({ type: "success", message: "Access activated. Redirecting to sign in." });
      window.setTimeout(() => navigate("/login", { replace: true }), 1200);
    } catch (error) {
      setResult({
        type: "error",
        message: error.userMessage || "This invitation is invalid, expired, or already used.",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="split-login-container">
      <div className="login-left">
        <Link to="/" className="back-to-home"><ArrowLeft size={16} /> Back to Home</Link>
        <div className="left-content">
          <h1 className="login-headline">Activate Your <br /><span className="gradient-text">WarSOC Access.</span></h1>
          <p className="login-subheadline">Choose your own password through this one-time invitation. WarSOC never emails passwords.</p>
          <div className="feature-bullets">
            <div className="bullet-item">
              <div className="bullet-icon-box"><Shield size={18} /></div>
              <span>Single-use, expiring activation</span>
              <CheckCircle size={22} color="#ffffff" fill="#b7eb48" className="check-icon" />
            </div>
          </div>
        </div>
      </div>
      <div className="login-right-wrapper">
        <div className="login-right">
          <div className="login-form-box">
            <div className="form-header">
              <h2>Set Your Password</h2>
              <p>Use at least 16 characters with uppercase, lowercase, number, and symbol.</p>
            </div>
            {result && (
              <div className={`toast-notification ${result.type}`} style={{ position: "static", marginBottom: 18 }}>
                {result.type === "success" ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
                <span>{result.message}</span>
              </div>
            )}
            <form onSubmit={handleSubmit} className="auth-form">
              <div className="input-group-container">
                <label>New Password</label>
                <div className="input-group">
                  <Lock className="input-icon" size={18} />
                  <input type="password" minLength={16} maxLength={72} value={password} onChange={(event) => setPassword(event.target.value)} required />
                </div>
              </div>
              <div className="input-group-container">
                <label>Confirm Password</label>
                <div className="input-group">
                  <Lock className="input-icon" size={18} />
                  <input type="password" minLength={16} maxLength={72} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required />
                </div>
              </div>
              <button type="submit" className="auth-btn" disabled={loading || !token}>
                {loading ? "Activating..." : <>Activate Access <ArrowRight size={18} /></>}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
