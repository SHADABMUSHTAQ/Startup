import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Home from "./assets/Pages/Home/Home";
import Login from "./assets/Pages/Login/Login"; 
import Navbar from "./assets/Components/Navbar/Navbar"; 
import Dashboard from "./assets/Pages/Dashboard/Dashboard";
import Payment from "./assets/Pages/Payment/Payment"; 
import Pricing from "./assets/Pages/Pricing/Pricing"; 

// ⏳ SESSION TIMEOUT SETTING (1 Hour = 3600000 ms)
const SESSION_DURATION = 3600000; 

const PrivateRoute = ({ children }) => {
  const [loading, setLoading] = useState(true);
  const [isAuthorized, setIsAuthorized] = useState(false);

  useEffect(() => {
    const verifyAccess = async () => {
      const token = localStorage.getItem("token");
      const userDataStr = localStorage.getItem("user_data");
      const loginTime = localStorage.getItem("login_timestamp");

      // 1. Check if Data Exists
      if (!token || !userDataStr || !loginTime) {
        handleLogout();
        return;
      }

      // 2. CHECK TIMEOUT 
      const now = Date.now();
      if (now - parseInt(loginTime) > SESSION_DURATION) {
        console.log("Session Expired! Logging out...");
        handleLogout(); 
        return;
      }

      let username = null;
      try {
        const userData = JSON.parse(userDataStr);
        username = userData.username;
      } catch {
        handleLogout();
        return;
      }

      try {
        // 3. Database Verification
        const res = await fetch(`http://localhost:8000/api/v1/auth/me?username=${username}`, {
          headers: { "Authorization": `Bearer ${token}` }
        });
        
        if (res.ok) {
            const data = await res.json();
            if (data.has_active_plan === true) {
                setIsAuthorized(true);
            } else {
                setIsAuthorized(false);
            }
        } else {
            handleLogout();
        }
      } catch (error) {
        console.error("Auth Verification Failed:", error);
        setIsAuthorized(false);
      } finally {
        setLoading(false);
      }
    };

    verifyAccess();
  }, []);

  const handleLogout = () => {
    localStorage.clear(); 
    setIsAuthorized(false);
    setLoading(false);
  };

  if (loading) {
    return (
      <div style={{ background: "#0a0b1e", height: "100vh", display: "flex", justifyContent: "center", alignItems: "center", color: "#4da6ff" }}>
        <h2>Verifying Session...</h2>
      </div>
    );
  }

  return isAuthorized ? children : <Navigate to="/login" replace />;
};

const App = () => {
  return (
    <Router>
      <Navbar />
      <Routes>
        {/* 🚀 2. Wrapped Home and Partners in a Fragment (<></>) so they appear together as a single page */}
        <Route 
          path="/" 
          element={
            <>
              <Home />
            </>
          } 
        />
        <Route path="/login" element={<Login />} />
        <Route path="/pricing" element={<Pricing />} /> 
        <Route path="/payment" element={<Payment />} />
        
        <Route 
          path="/dashboard" 
          element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          } 
        />

        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
};

export default App;