import React, { useState, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { HashLink } from "react-router-hash-link";
import { Menu, X, User, LogOut, ChevronDown, ShieldCheck } from "lucide-react";
import { useAuthStore } from "../../../store/authStore";
import "./Navbar.css";

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");

  // 🚀 REFACTOR: Bind to Zustand Store
  const { user, logout } = useAuthStore();
  const [showDropdown, setShowDropdown] = useState(false);
  const [openNavMenu, setOpenNavMenu] = useState(null);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const profileMenuRef = useRef(null);
  const navMenuRef = useRef(null);

  const isDashboardPage = location.pathname.startsWith("/dashboard");
  const isLoginPage = location.pathname === "/login";

  const displayName =
    user?.full_name ||
    user?.name ||
    user?.username ||
    "User";
  const displayEmail = user?.email || "";
  const avatar = user?.avatar;

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 80);
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 992 && isOpen) setIsOpen(false);
    };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "unset";
    }
  }, [isOpen]);

  useEffect(() => {
    if (!showDropdown) return undefined;

    const handlePointerDown = (event) => {
      if (
        profileMenuRef.current &&
        !profileMenuRef.current.contains(event.target)
      ) {
        setShowDropdown(false);
      }
    };

    const handleKeyDown = (event) => {
      if (event.key === "Escape") setShowDropdown(false);
    };

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [showDropdown]);

  useEffect(() => {
    if (!openNavMenu) return undefined;

    const handlePointerDown = (event) => {
      if (navMenuRef.current && !navMenuRef.current.contains(event.target)) {
        setOpenNavMenu(null);
      }
    };

    const handleKeyDown = (event) => {
      if (event.key === "Escape") setOpenNavMenu(null);
    };

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [openNavMenu]);

  // Redundant API fetch removed to rely strictly on global authStore

  const toggle = () => setIsOpen((s) => !s);
  const close = () => {
    setIsOpen(false);
    setOpenNavMenu(null);
  };
  const toggleTheme = () => setTheme((prev) => (prev === "dark" ? "light" : "dark"));

  const navigateFromMenu = (path) => {
    setShowDropdown(false);
    close();
    navigate(path);
  };

  const requestLogout = () => {
    setShowDropdown(false);
    close();
    setShowLogoutModal(true);
  };

  const handleLogout = async () => {
    setShowLogoutModal(false);
    await logout();
  };

  const getInitials = (name) => {
    return name
      ? name
          .split(" ")
          .filter(Boolean)
          .slice(0, 2)
          .map((part) => part[0])
          .join("")
          .toUpperCase()
      : "U";
  };

  const logoutModal =
    showLogoutModal &&
    createPortal(
      <div className="navbar-modal-overlay navbar-logout-overlay">
        <div
          className="navbar-modal-card navbar-logout-confirm-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="navbar-logout-title"
        >
          <div className="navbar-logout-modal-content">
            <div className="navbar-logout-icon" aria-hidden="true">
              <LogOut size={23} />
            </div>
            <div className="navbar-logout-copy">
              <h3 id="navbar-logout-title">Sign out of WarSOC?</h3>
              <p>Your active session will be securely closed on this device.</p>
            </div>
          </div>
          <div className="navbar-logout-modal-actions">
            <button
              type="button"
              className="navbar-btn-cancel"
              onClick={() => setShowLogoutModal(false)}
            >
              Cancel
            </button>
            <button type="button" className="navbar-btn-danger" onClick={handleLogout}>
              <LogOut size={16} /> Sign out
            </button>
          </div>
        </div>
      </div>,
      document.body,
    );

  if (isDashboardPage) return null;

  return (
    <>
      <div
        className={`navbar-mobile-overlay ${isOpen ? "active" : ""}`}
        onClick={close}
      ></div>
      <nav
        className={`navbar-custom ${isLoginPage ? "login-mode" : scrolled ? "scrolled" : ""} ${isOpen ? "menu-open" : ""}`}
      >
        <div className="navbar-container">
          <Link to="/" className="logo-link" onClick={close} aria-label="WarSOC home">
            <span className="navbar-mark-frame" aria-hidden="true">
              <svg
                className="navbar-brand-logo"
                viewBox="0 0 64 72"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path className="navbar-mark-blue" d="M31.8 68C19.9 61.3 10 51.1 10 34.8V6h21.8v62Z" />
                <path className="navbar-mark-lime" d="M32.2 68C44.1 61.3 54 51.1 54 34.8V6L32.2 25.4V68Z" />
                <path className="navbar-mark-lime-soft" d="M31.8 6v24.6L10 6h21.8Z" />
                <path d="M20.2 35.4 31.9 45.8l12-10.4v10.3L31.9 56 20.2 45.8V35.4Z" fill="var(--navbar-mark-cutout, #ffffff)" />
              </svg>
            </span>
            <span className="navbar-wordmark">
              <span>War</span><span>SOC</span>
            </span>
          </Link>
          <button
            className="navbar-mobile-toggle"
            onClick={toggle}
            aria-label="Toggle Menu"
          >
            {isOpen ? (
              <X size={28} className="navbar-toggle-icon" />
            ) : (
              <Menu size={28} className="navbar-toggle-icon" />
            )}
          </button>
          <div className={`navbar-right-content ${isOpen ? "active" : ""}`}>
            <ul className="navbar-menu-links" ref={navMenuRef}>
              <li>
                <HashLink smooth to="/#home" onClick={close}>
                  Home
                </HashLink>
              </li>
              <li
                className="navbar-menu-item navbar-menu-item-dropdown"
                onMouseEnter={() => setOpenNavMenu("solutions")}
                onMouseLeave={() => setOpenNavMenu(null)}
              >
                <button
                  type="button"
                  className={`navbar-menu-trigger ${openNavMenu === "solutions" ? "is-open" : ""}`}
                  onClick={() => setOpenNavMenu(null)}
                  aria-expanded={openNavMenu === "solutions"}
                  aria-haspopup="true"
                >
                  Solutions <ChevronDown size={15} aria-hidden="true" />
                </button>
                <div className={`navbar-nav-dropdown navbar-solutions-dropdown ${openNavMenu === "solutions" ? "show" : ""}`} role="menu">
                  <div className="navbar-dropdown-feature">
                    <span className="navbar-dropdown-kicker">WarSOC platform</span>
                    <strong>Security operations with context, speed, and proof.</strong>
                    <p>Monitor your environment, respond to threats, and keep evidence ready for audit.</p>
                  </div>
                  <div className="navbar-dropdown-links">
                    <HashLink smooth to="/#features" onClick={close} role="menuitem">
                      <ShieldCheck size={17} />
                      <span><strong>Managed SIEM</strong><small>Unified detection and response</small></span>
                    </HashLink>
                    <HashLink smooth to="/#about" onClick={close} role="menuitem">
                      <User size={17} />
                      <span><strong>Built for your team</strong><small>Practical security, without the noise</small></span>
                    </HashLink>
                    <HashLink smooth to="/#pricing" onClick={close} role="menuitem">
                      <ChevronDown size={17} className="navbar-dropdown-price-icon" />
                      <span><strong>Deployment plans</strong><small>Flexible endpoint-based pricing</small></span>
                    </HashLink>
                  </div>
                </div>
              </li>
              <li>
                <HashLink smooth to="/#features" onClick={close}>
                  Features
                </HashLink>
              </li>
              <li>
                <HashLink smooth to="/#pricing" onClick={close}>
                  Pricing
                </HashLink>
              </li>
              <li
                className="navbar-menu-item navbar-menu-item-dropdown"
                onMouseEnter={() => setOpenNavMenu("resources")}
                onMouseLeave={() => setOpenNavMenu(null)}
              >
                <button
                  type="button"
                  className={`navbar-menu-trigger ${openNavMenu === "resources" ? "is-open" : ""}`}
                  onClick={() => setOpenNavMenu(null)}
                  aria-expanded={openNavMenu === "resources"}
                  aria-haspopup="true"
                >
                  Resources <ChevronDown size={15} aria-hidden="true" />
                </button>
                <div className={`navbar-nav-dropdown navbar-resources-dropdown ${openNavMenu === "resources" ? "show" : ""}`} role="menu">
                  <HashLink smooth to="/#about" onClick={close} role="menuitem">About WarSOC</HashLink>
                  <HashLink smooth to="/#contact" onClick={close} role="menuitem">Talk to our team</HashLink>
                  <Link to="/privacy" onClick={close} role="menuitem">Privacy & security</Link>
                  <Link to="/terms" onClick={close} role="menuitem">Terms of service</Link>
                </div>
              </li>
              <li className="navbar-contact-link"><HashLink smooth to="/#contact" onClick={close}>Contact</HashLink></li>

              <li className="navbar-mobile-auth">
                <button
                  type="button"
                  className={`navbar-theme-toggle mobile-theme-toggle ${theme === "light" ? "is-light" : "is-dark"}`}
                  onClick={toggleTheme}
                  aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                  title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                >
                  <span className="theme-switch-scene" aria-hidden="true">
                    <span className="theme-switch-orb"></span>
                    <span className="theme-switch-cloud cloud-one"></span>
                    <span className="theme-switch-cloud cloud-two"></span>
                    <span className="theme-switch-star star-one"></span>
                    <span className="theme-switch-star star-two"></span>
                    <span className="theme-switch-star star-three"></span>
                  </span>
                  <span className="theme-toggle-label">{theme === "light" ? "Light mode" : "Dark mode"}</span>
                </button>
                {user && !isLoginPage ? (
                  <>
                    <div className="mobile-user-name">{displayName}</div>
                    <Link
                      to="/profile"
                      className="mobile-profile-btn"
                      onClick={close}
                    >
                      <User size={18} /> My Profile
                    </Link>
                    <button
                      onClick={requestLogout}
                      className="mobile-logout-btn"
                    >
                      <LogOut size={18} /> Sign Out
                    </button>
                  </>
                ) : (
                  !isLoginPage && (
                    <Link
                      to="/login"
                      className="navbar-mobile-login-btn"
                      onClick={close}
                    >
                      Log In to Portal
                    </Link>
                  )
                )}
              </li>
            </ul>
            <div className="navbar-desktop-auth">
              <button
                type="button"
                className={`navbar-theme-toggle ${theme === "light" ? "is-light" : "is-dark"}`}
                onClick={toggleTheme}
                aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              >
                <span className="theme-switch-scene" aria-hidden="true">
                  <span className="theme-switch-orb"></span>
                  <span className="theme-switch-cloud cloud-one"></span>
                  <span className="theme-switch-cloud cloud-two"></span>
                  <span className="theme-switch-star star-one"></span>
                  <span className="theme-switch-star star-two"></span>
                  <span className="theme-switch-star star-three"></span>
                </span>
                <span className="theme-toggle-label">
                  {theme === "light" ? "Light" : "Dark"}
                </span>
              </button>
              {user && !isLoginPage ? (
                <div
                  className="navbar-profile-container"
                  ref={profileMenuRef}
                >
                  <button
                    type="button"
                    className="navbar-profile-trigger"
                    onClick={() => setShowDropdown(!showDropdown)}
                    aria-haspopup="menu"
                    aria-expanded={showDropdown}
                  >
                    <div className="navbar-avatar-circle">
                      {avatar ? (
                        <img src={avatar} alt={`${displayName} avatar`} />
                      ) : (
                        getInitials(displayName)
                      )}
                    </div>
                    <ChevronDown
                      size={16}
                      color="#8892b0"
                      className={`chevron ${showDropdown ? "rotate" : ""}`}
                    />
                  </button>
                  <div
                    className={`navbar-profile-dropdown ${showDropdown ? "show" : ""}`}
                    role="menu"
                  >
                    <div className="navbar-dropdown-header">
                      <div className="user-name">{displayName}</div>
                      <div className="user-email">{displayEmail}</div>
                    </div>
                    <button
                      type="button"
                      className="navbar-dropdown-item"
                      onClick={() => navigateFromMenu("/profile")}
                      role="menuitem"
                    >
                      <User size={16} /> My Profile
                    </button>
                    <button
                      type="button"
                      className="navbar-dropdown-item"
                      onClick={() => navigateFromMenu("/dashboard")}
                      role="menuitem"
                    >
                      <ShieldCheck size={16} /> Go to Dashboard
                    </button>
                    <button
                      type="button"
                      className="navbar-dropdown-item logout"
                      onClick={requestLogout}
                      role="menuitem"
                    >
                      <LogOut size={16} /> Secure Sign Out
                    </button>
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
      {logoutModal}
    </>
  );
};

export default Navbar;
