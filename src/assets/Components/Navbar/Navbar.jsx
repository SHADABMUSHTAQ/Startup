import React, { useState, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { HashLink } from "react-router-hash-link";
import { Menu, X, User, LogOut, ChevronDown } from "lucide-react";
import { useAuthStore } from "../../../store/authStore";
import "./Navbar.css";

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  
  // 🚀 REFACTOR: Bind to Zustand Store
  const { user, logout } = useAuthStore();
  const [showDropdown, setShowDropdown] = useState(false);

  const isDashboardPage = location.pathname.startsWith("/dashboard");
  const isLoginPage = location.pathname === "/login";

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 80);
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []); 

  useEffect(() => {
    const handleResize = () => { if (window.innerWidth > 992 && isOpen) setIsOpen(false); };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
        document.body.style.overflow = 'hidden';
    } else {
        document.body.style.overflow = 'unset';
    }
  }, [isOpen]);

  const toggle = () => setIsOpen((s) => !s);
  const close = () => setIsOpen(false);

  const handleLogout = async () => {
    // 🚀 REFACTOR: Zustand handles the API call and state wiping
    await logout();
    setShowDropdown(false);
    close();
    navigate("/login");
  };

  const getInitials = (name) => name ? name.charAt(0).toUpperCase() : "U";

  if (isDashboardPage) return null;

  return (
    <>
      <div className={`navbar-mobile-overlay ${isOpen ? "active" : ""}`} onClick={close}></div>
      <nav className={`navbar-custom ${isLoginPage ? "login-mode" : (scrolled ? "scrolled" : "")} ${isOpen ? "menu-open" : ""}`}>
        <div className="navbar-container">
          <Link to="/" className="logo-link" onClick={close}>
             <img className="navbar-brand-logo" src="/Logo.png" alt="WarSoc" />
          </Link>
          <button className="navbar-mobile-toggle" onClick={toggle} aria-label="Toggle Menu">
            {isOpen ? <X size={28} color="#B7EA48" /> : <Menu size={28} color="#47A5EF" />}
          </button>
          <div className={`navbar-right-content ${isOpen ? "active" : ""}`}>
            <ul className="navbar-menu-links">
              <li><HashLink smooth to="/#home" onClick={close}>Home</HashLink></li>
              <li><HashLink smooth to="/#about" onClick={close}>About</HashLink></li>
              <li><HashLink smooth to="/#features" onClick={close}>Features</HashLink></li>
              <li><HashLink smooth to="/#pricing" onClick={close}>Pricing</HashLink></li>
              <li><HashLink smooth to="/#Contact" onClick={close}>Contact</HashLink></li>

              <li className="navbar-mobile-auth">
                 {user && !isLoginPage ? (
                   <>
                     <div className="mobile-user-name">{user.full_name || user.username}</div>
                     <button onClick={handleLogout} className="mobile-logout-btn">
                         <LogOut size={18} /> Sign Out
                     </button>
                   </>
                 ) : (
                   !isLoginPage && <Link to="/login" className="navbar-mobile-login-btn" onClick={close}>Log In to Portal</Link>
                 )}
              </li>
            </ul>
            <div className="navbar-desktop-auth">
              {user && !isLoginPage ? ( 
                <div className="navbar-profile-container" onMouseLeave={() => setShowDropdown(false)}>
                  <div className="navbar-profile-trigger" onClick={() => setShowDropdown(!showDropdown)} onMouseEnter={() => setShowDropdown(true)}>
                    <div className="navbar-avatar-circle">
                      {getInitials(user.full_name || user.username)}
                    </div>
                    <ChevronDown size={16} color="#8892b0" className={`chevron ${showDropdown ? 'rotate' : ''}`} />
                  </div>
                  <div className={`navbar-profile-dropdown ${showDropdown ? "show" : ""}`}>
                    <div className="navbar-dropdown-header">
                      <div className="user-name">{user.full_name || user.username}</div>
                      <div className="user-email">{user.email}</div>
                    </div>
                    <div className="navbar-dropdown-item" onClick={() => navigate("/dashboard")}>
                       <User size={16}/> Go to Dashboard
                    </div>
                    <div className="navbar-dropdown-item logout" onClick={handleLogout}>
                      <LogOut size={16} /> Secure Sign Out
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
    </>
  );
};

export default Navbar;