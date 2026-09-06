import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AlertTriangle, ArrowLeft, ArrowRight, CheckCircle, Eye, EyeOff, Lock } from "lucide-react";
import apiClient from "../../../api/apiClient";
import { useAuthStore } from "../../../store/authStore";
import "./SetPassword.css";

export default function SetPassword() {
  const navigate = useNavigate();
  const token = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") || "";
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const checkAuth = useAuthStore((state) => state.checkAuth);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    const syncTheme = () => setTheme(localStorage.getItem("theme") || "dark");
    window.addEventListener("storage", syncTheme);
    window.addEventListener("focus", syncTheme);
    return () => {
      window.removeEventListener("storage", syncTheme);
      window.removeEventListener("focus", syncTheme);
    };
  }, []);

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
      const activation = await apiClient.post("/auth/activate-invite", { token, password });
      const loginIdentifier = activation.data?.login_identifier;

      if (!loginIdentifier) {
        setResult({ type: "success", message: "Access activated. Continue to sign in." });
        window.setTimeout(() => navigate("/login", { replace: true }), 1200);
        return;
      }

      try {
        const login = await apiClient.post("/auth/login", {
          username: loginIdentifier,
          password,
        });
        if (login.status === 202 || !(await checkAuth())) {
          throw new Error("Session hydration did not complete.");
        }
      } catch {
        setResult({ type: "success", message: "Access activated. Continue to sign in." });
        window.setTimeout(() => navigate("/login", { replace: true }), 1200);
        return;
      }

      setResult({ type: "success", message: "Access activated. Opening your dashboard." });
      navigate("/dashboard", { replace: true });
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
    <main className={`set-password-page set-password-${theme}`}>
      <section className="set-password-card" aria-label="Activate WarSOC access">
        <div className="set-password-form-panel">
          <div className="set-password-form-box">
            <Link to="/" className="set-password-back">
              <ArrowLeft size={16} /> Back to Home
            </Link>
          <div className="set-password-brand">
            <img src="/Logo.png" alt="WarSOC" />
          </div>
            <div className="set-password-form-header">
              <span>Account Setup</span>
              <h2>Set Your Password</h2>
              <p>Use uppercase, lowercase, a number, and a symbol for stronger protection.</p>
            </div>

            {result && (
              <div className={`set-password-alert ${result.type}`}>
                {result.type === "success" ? <CheckCircle size={19} /> : <AlertTriangle size={19} />}
                <span>{result.message}</span>
              </div>
            )}

            {!token && (
              <div className="set-password-alert error">
                <AlertTriangle size={19} />
                <span>This activation link is missing a token.</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="set-password-form">
              <label className="set-password-field">
                <span>New Password</span>
                <div className="set-password-input-wrap">
                  <Lock size={18} />
                  <input
                    type={showPassword ? "text" : "password"}
                    minLength={16}
                    maxLength={72}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Create a strong password"
                    required
                  />
                  <button
                    type="button"
                    className="set-password-eye"
                    onClick={() => setShowPassword((current) => !current)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </label>

              <label className="set-password-field">
                <span>Confirm Password</span>
                <div className="set-password-input-wrap">
                  <Lock size={18} />
                  <input
                    type={showConfirmation ? "text" : "password"}
                    minLength={16}
                    maxLength={72}
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    placeholder="Repeat your password"
                    required
                  />
                  <button
                    type="button"
                    className="set-password-eye"
                    onClick={() => setShowConfirmation((current) => !current)}
                    aria-label={showConfirmation ? "Hide password confirmation" : "Show password confirmation"}
                  >
                    {showConfirmation ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </label>

              <button type="submit" className="set-password-submit" disabled={loading || !token}>
                {loading ? "Activating..." : <>Activate Access <ArrowRight size={18} /></>}
              </button>
            </form>
          </div>
        </div>
      </section>
    </main>
  );
}
