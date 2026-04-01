import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from "react-router-dom";
import Home from "./assets/Pages/Home/Home";
import Login from "./assets/Pages/Login/Login"; 
import Navbar from "./assets/Components/Navbar/Navbar"; 
import Dashboard from "./assets/Pages/Dashboard/Dashboard";
import Payment from "./assets/Pages/Payment/Payment"; 
import Pricing from "./assets/Pages/Pricing/Pricing"; 
import AuditorDashboard from "./assets/Pages/Auditor/AuditorDashboard";
import TeamManagement from "./assets/Pages/Team/TeamManagement"; 
import ComplianceDashboard from "./assets/Pages/Compliance/ComplianceDashboard";
import { API_BASE_URL } from "./api";

const SESSION_DURATION = 86400000; 

const PrivateRoute = ({ children }) => {
  const [loading, setLoading] = useState(true);
  const [isAuthorized, setIsAuthorized] = useState(false);

  useEffect(() => {
    const verifyAccess = async () => {
      const token = localStorage.getItem("token");
      const userDataStr = localStorage.getItem("user_data");
      const loginTime = localStorage.getItem("login_timestamp");

      if (!token || !userDataStr || !loginTime) {
        handleLogout();
        return;
      }

      const now = Date.now();
      if (now - parseInt(loginTime) > SESSION_DURATION) {
        handleLogout(); 
        return;
      }

      try {
        const res = await fetch(`${API_BASE_URL}/auth/me`, {
          headers: { "Authorization": `Bearer ${token}` }
        });
        
        if (res.ok) {
            const data = await res.json();
            if (data.has_active_plan === true || data.role === "auditor") {
                setIsAuthorized(true);
            } else {
                setIsAuthorized(false);
            }
        } else {
            handleLogout();
        }
      } catch (error) {
        handleLogout();
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
      <div style={{ background: "#0f172a", height: "100vh", display: "flex", justifyContent: "center", alignItems: "center", color: "#3b82f6" }}>
        <h2>Verifying Security Credentials...</h2>
      </div>
    );
  }

  return isAuthorized ? children : <Navigate to="/login" replace />;
};

// 🚀 THE FIX: Ek naya component banaya taake hum route check kar sakein
const AppContent = () => {
  const location = useLocation();
  
  // Yahan humne wo pages likh diye hain jahan Navbar NAHI dikhana
  const hideNavbarRoutes = ["/dashboard", "/auditor", "/team", "/compliance", "/login", "/payment"];
  
  // Agar current page in mein se nahi hai, toh hi Navbar dikhao
  const showNavbar = !hideNavbarRoutes.includes(location.pathname);

  return (
    <>
      {showNavbar && <Navbar />}
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/pricing" element={<Pricing />} /> 
        <Route path="/payment" element={<Payment />} />
        
        <Route path="/dashboard" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
        <Route path="/auditor" element={<PrivateRoute><AuditorDashboard /></PrivateRoute>} />
        <Route path="/team" element={<PrivateRoute><TeamManagement /></PrivateRoute>} />
        <Route path="/compliance" element={<PrivateRoute><ComplianceDashboard /></PrivateRoute>} />
        
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </>
  );
};

// Main App Component
const App = () => {
  return (
    <Router>
      <AppContent />
    </Router>
  );
};

export default App;