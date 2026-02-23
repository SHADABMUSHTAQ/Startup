import React, { useState, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { HashLink } from "react-router-hash-link";
import { Menu, X, User, LogOut, ChevronDown } from "lucide-react";
import "./Navbar.css";

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  
  const [user, setUser] = useState(null); 
  const [showDropdown, setShowDropdown] = useState(false);

  // Pages Check
  const isDashboardPage = location.pathname.startsWith("/dashboard");
  const isLoginPage = location.pathname === "/login";

  // Check Token Validity
  const isTokenExpired = (token) => {
    if (!token) return true;
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => 
          '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
      ).join(''));
      return JSON.parse(jsonPayload).exp < Date.now() / 1000;
    } catch (e) { return true; }
  };

  useEffect(() => {
    // ✅ FIX: 20 ki jagah 80px kar diya taake thoda scroll hone ke baad pill bane
    const handleScroll = () => setScrolled(window.scrollY > 80);
    
    // Check User Data on Mount & Location Change
    const checkAuth = () => {
        const storedUser = localStorage.getItem("user_data");
        const token = localStorage.getItem("token");

        if (storedUser && token && !isTokenExpired(token)) {
            setUser(JSON.parse(storedUser));
        } else {
            setUser(null);
        }
    };

    checkAuth();

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [location]); 

  useEffect(() => {
    const handleResize = () => { if (window.innerWidth > 992 && isOpen) setIsOpen(false); };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [isOpen]);

  const toggle = () => setIsOpen((s) => !s);
  const close = () => setIsOpen(false);

  const handleLogout = () => {
    localStorage.clear();
    setUser(null);
    setShowDropdown(false);
    close();
    navigate("/login");
  };

  const getInitials = (name) => name ? name.charAt(0).toUpperCase() : "U";

  if (isDashboardPage) return null;

  return (
    <nav className={`navbar-custom ${scrolled ? "scrolled" : ""} ${isOpen ? "menu-open" : ""}`}>
      <div className="navbar-container">
        
        {/* LOGO */}
        <Link to="/" className="logo-link" onClick={close}>
           <img className="navbar-brand-logo" src="/Logo.png" alt="WarSoc" />
        </Link>

        {/* MOBILE TOGGLE */}
        <button className="navbar-mobile-toggle" onClick={toggle}>
          {isOpen ? <X size={28} color="#64ffda" /> : <Menu size={28} color="#e6f1ff" />}
        </button>

        {/* CONTENT WRAPPER */}
        <div className={`navbar-right-content ${isOpen ? "active" : ""}`}>
          <ul className="navbar-menu-links">
            <li><HashLink smooth to="/#home" onClick={close}>Home</HashLink></li>
            <li><HashLink smooth to="/#about" onClick={close}>About</HashLink></li>
            <li><HashLink smooth to="/#features" onClick={close}>Features</HashLink></li>
            <li><HashLink smooth to="/#pricing" onClick={close}>Pricing</HashLink></li>
            {/* ✅ Contact link yahan add kar diya gaya hai */}
            <li><HashLink smooth to="/#Contact" onClick={close}>Contact</HashLink></li>

            {/* MOBILE AUTH */}
            <li className="navbar-mobile-auth">
               {user && !isLoginPage ? (
                 <>
                   <div style={{color:'#64ffda', fontWeight:'bold', fontSize:'1.2rem'}}>{user.full_name}</div>
                   <button onClick={handleLogout} style={{background:'transparent', border:'1px solid #ff6b6b', color:'#ff6b6b', padding:'10px 30px', borderRadius:'4px', fontSize:'1rem'}}>Logout</button>
                 </>
               ) : (
                 !isLoginPage && <Link to="/login" className="navbar-mobile-login-btn" onClick={close}>Login</Link>
               )}
            </li>
          </ul>

          {/* DESKTOP AUTH */}
          <div className="navbar-desktop-auth">
            {user && !isLoginPage ? ( 
              <div className="navbar-profile-container">
                <div className="navbar-profile-trigger" onClick={() => setShowDropdown(!showDropdown)}>
                  <div className="navbar-avatar-circle">
                    {getInitials(user.full_name || user.username)}
                  </div>
                  <ChevronDown size={16} color="#8892b0" />
                </div>

                <div className={`navbar-profile-dropdown ${showDropdown ? "show" : ""}`}>
                  <div className="navbar-dropdown-header">
                    <div style={{color:'#e6f1ff', fontWeight:'600'}}>{user.full_name || user.username}</div>
                    <div style={{color:'#8892b0', fontSize:'0.8rem'}}>{user.email}</div>
                  </div>
                  
                  <div className="navbar-dropdown-item" onClick={() => navigate("/dashboard")}>
                     <User size={16}/> Dashboard
                  </div>
                  
                  <div className="navbar-dropdown-item" onClick={handleLogout} style={{color:'#ff6b6b', borderTop:'1px solid #233554'}}>
                    <LogOut size={16} /> Sign Out
                  </div>
                </div>
              </div>
            ) : (
              !isLoginPage && (
                <Link to="/login" className="navbar-btn-login">
                  Login
                </Link>
              )
            )}
          </div>
        </div>

      </div>
    </nav>
  );
};

export default Navbar;