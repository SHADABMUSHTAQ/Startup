import React, { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { HashLink } from "react-router-hash-link";
import "./Navbar.css";

const Navbar = () => {
  const location = useLocation();
  const [isOpen, setIsOpen] = useState(false);

  // Close menu when route changes
  useEffect(() => {
    setIsOpen(false);
  }, [location.pathname]);

  // Close menu automatically when resizing to desktop
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 992 && isOpen) setIsOpen(false);
    };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [isOpen]);

  const toggle = () => setIsOpen((s) => !s);
  const close = () => setIsOpen(false);

  return (
    <nav className={`navbar ${isOpen ? "menu-open" : ""}`}>
      <img className="logo" src="/Logo.png" alt="error image" />

      {/* burger button */}
      <button
        className={`burger ${isOpen ? "open" : ""}`}
        onClick={toggle}
        aria-label={isOpen ? "Close menu" : "Open menu"}
        aria-expanded={isOpen}
      >
        <span></span>
        <span></span>
        <span></span>
      </button>

      {/* links */}
      <ul className="nav-links" role="menu">
        <li>
          <HashLink smooth to="/#home" onClick={close}>
            Home
          </HashLink>
        </li>
        <li>
          <HashLink smooth to="/#about" onClick={close}>
            About
          </HashLink>
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

        {/* mobile only login */}
        {location.pathname !== "/login" && (
          <li className="nav-login-mobile">
            <Link to="/login" onClick={close}>
              Login
            </Link>
          </li>
        )}
      </ul>

      {/* desktop login */}
      {location.pathname !== "/login" && (
        <Link to="/login" className="login-btn desktop-only" onClick={close}>
          Login
        </Link>
      )}
    </nav>
  );
};

export default Navbar;
