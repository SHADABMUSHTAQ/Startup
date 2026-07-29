import React, { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import {
  Lock,
  Mail,
  Eye,
  EyeOff,
  ArrowRight,
  ArrowLeft,
  CheckCircle,
  AlertTriangle,
  X,
} from "lucide-react";
import apiClient from "../../../api/apiClient";
import { useAuthStore } from "../../../store/authStore";
import "./Login.css";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [totpCode, setTotpCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");

  const { checkAuth } = useAuthStore();
  const navigate = useNavigate();
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    const handleStorage = (event) => {
      if (event.key === "theme" && event.newValue) {
        setTheme(event.newValue);
      }
    };

    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const showToast = (type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    setLoading(true);
    try {
      const response = await apiClient.post(
        "/auth/login",
        {
          username: email,
          password: password,
          ...(mfaRequired ? { totp_code: totpCode } : {}),
        },
        {
          headers: { "Content-Type": "application/json" },
        },
      );

      if (response.status === 202 && response.data?.mfa_required) {
        setMfaRequired(true);
        setTotpCode("");
        return;
      }

      const authenticated = await checkAuth();
      if (!authenticated) {
        throw new Error("Sign-in could not be completed. Please try again.");
      }
      const authState = useAuthStore.getState();

      showToast("success", "Login Successful!");

      setTimeout(() => {
        if (
          authState.role === "auditor" ||
          authState.role === "Auditor" ||
          (authState.plan_type && authState.plan_type !== "Free")
        ) {
          navigate("/dashboard");
        } else {
          navigate("/pricing");
        }
      }, 1000);
    } catch (err) {
      showToast(
        "error",
        mfaRequired && err.response?.status === 401
          ? "Invalid verification code."
          : err.userMessage ||
              "Sign-in could not be completed. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`split-login-container login-${theme}`}>
      {toast && (
        <div className={`toast-notification ${toast.type}`}>
          {toast.type === "success" ? (
            <CheckCircle size={20} />
          ) : (
            <AlertTriangle size={20} />
          )}
          <span>{toast.msg}</span>
          <button type="button" onClick={() => setToast(null)}>
            <X size={16} />
          </button>
        </div>
      )}

      <section className="login-left">
        <Link to="/" className="back-to-home">
          <ArrowLeft size={16} /> Back to Home
        </Link>

        <div className="login-brand-row">
          <img src="/Logo.png" alt="WarSOC" />
        </div>

        <div className="login-right">
          <div className="login-form-box">
            <div className="form-header">
              <h1>Log in to WarSOC</h1>
              <p>
                Use your issued account credentials to enter the secure
                operations dashboard.
              </p>
            </div>

            <form onSubmit={handleSubmit} className="auth-form">
              <div className="input-group-container">
                <label>Username or Email</label>
                <div className="input-group">
                  <Mail className="input-icon" size={18} />
                  <input
                    type="text"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="input-group-container">
                <div className="password-header">
                  <label>Password</label>
                </div>
                <div className="input-group">
                  <Lock className="input-icon" size={18} />
                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="Password"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setMfaRequired(false);
                      setTotpCode("");
                    }}
                    required
                  />
                  <button
                    type="button"
                    className="password-visibility-btn"
                    onClick={() => setShowPassword((current) => !current)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              {mfaRequired && (
                <div className="input-group-container">
                  <label>Authenticator code</label>
                  <div className="input-group">
                    <Lock className="input-icon" size={18} />
                    <input
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      pattern="[0-9]{6}"
                      maxLength={6}
                      placeholder="6-digit code"
                      value={totpCode}
                      onChange={(event) =>
                        setTotpCode(
                          event.target.value.replace(/\D/g, "").slice(0, 6),
                        )
                      }
                      autoFocus
                      required
                    />
                  </div>
                </div>
              )}

              <button type="submit" className="auth-btn" disabled={loading}>
                {loading ? (
                  "Processing..."
                ) : (
                  <>
                    {mfaRequired ? "Verify and Sign In" : "Sign In"}{" "}
                    <ArrowRight size={18} />
                  </>
                )}
              </button>
            </form>

            <div className="auth-footer">
              <p>
                Need access?{" "}
                <Link to="/pricing">View pricing and request access</Link>
              </p>
            </div>
          </div>
        </div>
      </section>

    </div>
  );
}
