import React from "react";
import { HashLink } from "react-router-hash-link";
import { Link } from "react-router-dom"; // ✅ Naya import legal links ke liye
import { Github, Twitter, Linkedin, Mail, Shield } from "lucide-react";
import "./Footer.css";

const Footer = () => {
  return (
    <footer className="footer">
      <div className="footer-container">
        
        {/* Top Section: Brand & Navigation */}
        <div className="footer-top">
          
          {/* Brand Info */}
          <div className="footer-brand-section">
            <div className="brand-logo">
              <Shield size={28} color="#64ffda" className="brand-icon" />
              <h2>WARSOC</h2>
            </div>
            <p className="brand-desc">
              Next-generation SIEM platform securing the digital frontier. 
              We turn chaos into clarity with AI-driven threat intelligence.
            </p>
            <div className="social-links">
              {/* Other socials */}
              <a href="#" aria-label="GitHub"><Github size={20} /></a>
              <a href="#" aria-label="Twitter"><Twitter size={20} /></a>
              
              {/* ✅ WarSOC LinkedIn Link Added */}
              <a 
                href="https://www.linkedin.com/search/results/all/?fetchDeterministicClustersOnly=true&heroEntityKey=urn%3Ali%3Aorganization%3A111724372&keywords=warsoc&origin=RICH_QUERY_SUGGESTION&position=0&searchId=6402d616-cfc5-4c40-ad90-1219c2ba3216&sid=%3Bx%40&spellCorrectionEnabled=false" 
                target="_blank" 
                rel="noopener noreferrer" 
                aria-label="LinkedIn"
              >
                <Linkedin size={20} />
              </a>
              
              <a href="mailto:info@warsoc.com" aria-label="Email"><Mail size={20} /></a>
            </div>
          </div>

          {/* Functional Links Grid */}
          <div className="footer-links-grid">
            <div className="link-column">
              <h4>Platform</h4>
              <ul>
                <li><HashLink smooth to="/#home">Home</HashLink></li>
                <li><HashLink smooth to="/#features">Features</HashLink></li>
                <li><HashLink smooth to="/#pricing">Pricing</HashLink></li>
              </ul>
            </div>

            <div className="link-column">
              <h4>Company</h4>
              <ul>
                <li><HashLink smooth to="/#about">About Us</HashLink></li>
                <li><HashLink smooth to="/#contact">Contact Sales</HashLink></li>
                <li><HashLink smooth to="/login">Login Portal</HashLink></li>
              </ul>
            </div>
          </div>
        </div>

        {/* Bottom Section: Copyright & Legal */}
        <div className="footer-bottom">
          <p>© {new Date().getFullYear()} WarSOC Inc. All rights reserved. Incubated at NIC Karachi.</p>
          <div className="legal-links">
            <HashLink smooth to="/#contact">Support</HashLink>
            {/* ✅ Fixed: Ab ye jump nahi karenge */}
            <Link to="/privacy">Privacy Policy</Link>
            <Link to="/terms">Terms of Service</Link>
          </div>
        </div>

      </div>
    </footer>
  );
};

export default Footer;