import React from "react";
import { HashLink } from "react-router-hash-link";
// ✅ FIXED: Saare icons ek hi line mein import hain (No Duplicates)
import { Github, Twitter, Linkedin, Mail, ArrowRight, Shield } from "lucide-react";
import "./Footer.css";

const Footer = () => {
  return (
    <footer className="footer">
      <div className="footer-container">
        
        {/* Top Section: Brand & Newsletter */}
        <div className="footer-top">
          <div className="footer-brand-section">
            <div className="brand-logo">
              {/* Shield Icon */}
              <Shield size={28} color="#64ffda" className="brand-icon" />
              <h2>WARSOC</h2>
            </div>
            <p className="brand-desc">
              Next-generation SIEM platform securing the digital frontier. 
              We turn chaos into clarity with AI-driven threat intelligence.
            </p>
            <div className="social-links">
              <a href="#" aria-label="GitHub"><Github size={20} /></a>
              <a href="#" aria-label="Twitter"><Twitter size={20} /></a>
              <a href="#" aria-label="LinkedIn"><Linkedin size={20} /></a>
              <a href="mailto:support@warsoc.com" aria-label="Email"><Mail size={20} /></a>
            </div>
          </div>

          {/* Links Grid */}
          <div className="footer-links-grid">
            <div className="link-column">
              <h4>Product</h4>
              <ul>
                <li><HashLink smooth to="/#features">Features</HashLink></li>
                <li><HashLink smooth to="/#pricing">Pricing</HashLink></li>
                <li><a href="#">Integrations</a></li>
                <li><a href="#">API Docs</a></li>
              </ul>
            </div>

            <div className="link-column">
              <h4>Company</h4>
              <ul>
                <li><HashLink smooth to="/#about">About Us</HashLink></li>
                <li><a href="#">Careers</a></li>
                <li><a href="#">Blog</a></li>
                <li><a href="#">Contact</a></li>
              </ul>
            </div>

            <div className="link-column newsletter-col">
              <h4>Stay Updated</h4>
              <p>Get the latest security alerts and news.</p>
              <form className="newsletter-form" onSubmit={(e) => e.preventDefault()}>
                <input type="email" placeholder="Enter your email" required />
                <button type="submit" aria-label="Subscribe">
                  {/* ✅ FIXED: Icon visible hai */}
                  <ArrowRight size={20} color="#ffffff" strokeWidth={2.5} />
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Bottom Section: Copyright & Legal */}
        <div className="footer-bottom">
          <p>© {new Date().getFullYear()} WarSOC Inc. All rights reserved.</p>
          <div className="legal-links">
            <a href="#">Privacy Policy</a>
            <a href="#">Terms of Service</a>
            <a href="#">Security</a>
          </div>
        </div>

      </div>
    </footer>
  );
};

export default Footer;