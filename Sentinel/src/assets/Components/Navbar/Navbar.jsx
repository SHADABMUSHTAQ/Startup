import React, { useState, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { HashLink } from "react-router-hash-link";
import "./Navbar.css";

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  
  // --- AUTH STATE ---
  const [user, setUser] = useState(null); 
  const [showDropdown, setShowDropdown] = useState(false);

  // ✅ CHECK: Kya hum Dashboard page par hain?
  const isDashboardPage = location.pathname === "/dashboard";

  // ✅ 1. HELPER: Check if Token is Expired
  const isTokenExpired = (token) => {
    if (!token) return true;
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      const { exp } = JSON.parse(jsonPayload);
      const currentTime = Date.now() / 1000;
      return exp < currentTime;
    } catch (e) {
      return true;
    }
  };

  // ✅ 2. PAGE LOAD CHECK (Auth & Expiry)
  useEffect(() => {
    const storedUser = localStorage.getItem("user_data");
    const token = localStorage.getItem("token");

    if (storedUser && token) {
      if (isTokenExpired(token)) {
        // Agar token purana ho gaya hai to logout karo
        handleLogout();
      } else {
        // Agar sab sahi hai to user set karo
        setUser(JSON.parse(storedUser));
      }
    }
  }, [location]);

  // Resize handler
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 992 && isOpen) setIsOpen(false);
    };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [isOpen]);

  const toggle = () => setIsOpen((s) => !s);
  const close = () => setIsOpen(false);

  // ✅ LOGOUT FUNCTION
  const handleLogout = () => {
    localStorage.removeItem("user_data");
    localStorage.removeItem("token");
    setUser(null);
    setShowDropdown(false);
    close();
    navigate("/login");
  };

  const getInitials = (name) => {
    return name ? name.charAt(0).toUpperCase() : "U";
  };

  return (
    <nav className={`navbar ${isOpen ? "menu-open" : ""}`}>
      <Link to="/" className="logo-link">
         <img className="logo" src="/Logo.png" alt="WarSoc" />
      </Link>

      <button className={`burger ${isOpen ? "open" : ""}`} onClick={toggle}>
        <span></span><span></span><span></span>
      </button>

      <ul className="nav-links" role="menu">
        <li><HashLink smooth to="/#home" onClick={close}>Home</HashLink></li>
        <li><HashLink smooth to="/#about" onClick={close}>About</HashLink></li>
        <li><HashLink smooth to="/#features" onClick={close}>Features</HashLink></li>
        <li><HashLink smooth to="/#pricing" onClick={close}>Pricing</HashLink></li>

        {/* --- MOBILE VIEW --- */}
        {user && isDashboardPage ? (
           <>
            <li className="nav-item-mobile user-info">
                <span>👤 {user.full_name || user.username}</span>
            </li>
            <li className="nav-item-mobile logout-link">
                <span onClick={handleLogout}>Logout</span>
            </li>
           </>
        ) : (
          location.pathname !== "/login" && (
            <li className="nav-login-mobile">
              <Link to="/login" onClick={close}>Login</Link>
            </li>
          )
        )}
      </ul>

      {/* --- DESKTOP VIEW --- */}
      <div className="desktop-auth">
        {user && isDashboardPage ? (
            // ✅ LOGIN HAI + DASHBOARD PAR HAI: Show Avatar
            <div className="profile-container">
              <div 
                className="profile-avatar" 
                onClick={() => setShowDropdown(!showDropdown)}
                title={user.full_name}
              >
                {getInitials(user.full_name || user.username)}
              </div>

              {showDropdown && (
                <div className="profile-dropdown">
                  <div className="dropdown-header">
                    <strong>{user.full_name || user.username}</strong>
                    <small>{user.email}</small>
                  </div>
                  <hr />
                  <div className="dropdown-item logout" onClick={handleLogout}>
                    🚪 Logout
                  </div>
                </div>
              )}
            </div>
        ) : (
          // ❌ BAAKI PAGES: Show Login/Dashboard Button
          location.pathname !== "/login" && (
            <Link to={user ? "/dashboard" : "/login"} className="login-btn desktop-only" onClick={close}>
              {user ? "Dashboard" : "Login"}
            </Link>
          )
        )}
      </div>
    </nav>
  );
};

export default Navbar;