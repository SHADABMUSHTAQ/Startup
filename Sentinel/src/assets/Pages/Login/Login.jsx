import React, { useState } from "react";
import { useNavigate } from "react-router-dom"; 
import "./Login.css";
import { registerUser } from "../../../api.js";

export default function Login() {
  const [signState, setSignState] = useState("Sign Up");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  
  // Modal States
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [modalMessage, setModalMessage] = useState({ title: "", body: "" });

  const navigate = useNavigate(); 

  // ✅ UPDATED: Handle Modal Close (Smart Redirect)
  const handleCloseModal = () => {
    setShowSuccessModal(false);

    if (signState === "Sign In") {
      // ✅ Check karo agar user ke paas plan hai
      const userData = JSON.parse(localStorage.getItem("user_data"));
      
      if (userData && userData.hasPlan) {
        navigate("/dashboard"); // Paise diye hain -> Dashboard
      } else {
        navigate("/"); // Paise nahi diye -> Home/Pricing Page
      }
    } 
    else {
      // Signup successful -> Switch to Sign In
      setSignState("Sign In");
      setName("");
      setEmail("");
      setPassword("");
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (signState === "Sign Up") {
      // -------- SIGN UP ----------
      try {
        await registerUser(name, email, password);
        
        setModalMessage({
          title: "Account Created!",
          body: "Your registration was successful. Please login to continue."
        });
        setShowSuccessModal(true);
        
      } catch (err) {
        alert("Signup Failed! " + err.message);
        console.error(err);
      }
    } else {
      // -------- SIGN IN ----------
      try {
        const response = await fetch("http://127.0.0.1:8000/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: email, password }), 
        });
        
        const data = await response.json();

        if (!response.ok) {
          alert(data.detail || "Login Failed!");
          return;
        }

        // 1. Token Save Karo
        localStorage.setItem("token", data.access_token);

        // 2. User Data Save Karo (Purana data delete mat hone do)
        const existingData = JSON.parse(localStorage.getItem("user_data")) || {};
        
        const userData = {
            ...existingData, // ✅ Keep 'hasPlan' flag if exists
            full_name: data.full_name || data.username || email.split('@')[0], 
            email: email,
            username: email
        };
        localStorage.setItem("user_data", JSON.stringify(userData));

        // ✅ 3. Message Logic (Plan check karke message dikhao)
        if (userData.hasPlan) {
          setModalMessage({
            title: "Welcome Back!",
            body: "Redirecting to your dashboard..."
          });
        } else {
          setModalMessage({
            title: "Welcome!",
            body: "Login successful. Please select a subscription plan to continue."
          });
        }
        
        setShowSuccessModal(true);

      } catch (err) {
        alert("Network Error: " + err.message);
        console.error(err);
      }
    }
  };

  return (
    <div className="login">
      
      {/* PROFESSIONAL SUCCESS MODAL */}
      {showSuccessModal && (
        <div className="auth-modal-overlay">
          <div className="auth-modal-content">
            <div className="success-icon-circle">✔</div>
            
            <h2>{modalMessage.title}</h2>
            <p>{modalMessage.body}</p>
            
            <button className="btn-continue" onClick={handleCloseModal}>
              Continue
            </button>
          </div>
        </div>
      )}

      {/* NORMAL FORM */}
      <div className="login-form">
        <h1>{signState}</h1>

        <form onSubmit={handleSubmit}>
          {signState === "Sign Up" && (
            <input type="text" placeholder="Your Name" value={name} onChange={(e) => setName(e.target.value)} required />
          )}

          <input type={signState === "Sign Up" ? "email" : "text"} placeholder={signState === "Sign Up" ? "Email" : "Username"} value={email} onChange={(e) => setEmail(e.target.value)} required />

          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />

          <button type="submit">{signState}</button>
        </form>

        <div className="form-switch">
          {signState === "Sign In" ? (
            <p>New here? <span onClick={() => setSignState("Sign Up")}>Sign Up Now</span></p>
          ) : (
            <p>Already have an account? <span onClick={() => setSignState("Sign In")}>Sign In</span></p>
          )}
        </div>
      </div>
    </div>
  );
}