import React from "react";
import { HashLink } from "react-router-hash-link";
import { Link } from "react-router-dom"; 
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
            </p>
            <div className="social-links">
              {/* Other socials */}
              {/* <a href="#" aria-label="GitHub"><Github size={20} /></a> */}
              
              {/* ✅ UPDATED: WarSOC Official WhatsApp Channel Link */}
              <a href="https://whatsapp.com/channel/0029VbCtKv9InlqYA35GTD2b" target="_blank" rel="noopener noreferrer" aria-label="WarSOC WhatsApp Channel">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M3 21l1.65-3.8a9 9 0 1 1 3.4 2.9L3 21" />
                  <path d="M9 10a.5.5 0 0 0 1 0V9a.5.5 0 0 0-1 0v1a5 5 0 0 0 5 5h1a.5.5 0 0 0 0-1h-1a.5.5 0 0 0 0 1" />
                </svg>
              </a>

              <a href="#" aria-label="Twitter"><Twitter size={20} /></a>
              
              {/* WarSOC LinkedIn Link */}
              <a 
                href="https://www.linkedin.com/search/results/all/?fetchDeterministicClustersOnly=true&heroEntityKey=urn%3Ali%3Aorganization%3A111724372&keywords=warsoc&origin=RICH_QUERY_SUGGESTION&position=0&searchId=6402d616-cfc5-4c40-ad90-1219c2ba3216&sid=%3Bx%40&spellCorrectionEnabled=false" 
                target="_blank" 
                rel="noopener noreferrer" 
                aria-label="LinkedIn"
              >
                <Linkedin size={20} />
              </a>
              
              <a href="mailto:Warosc1@outlook.com" aria-label="Email"><Mail size={20} /></a>
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
            <Link to="/privacy">Privacy Policy</Link>
            <Link to="/terms">Terms of Service</Link>
          </div>
        </div>

      </div>
    </footer>
  );
};

export default Footer;