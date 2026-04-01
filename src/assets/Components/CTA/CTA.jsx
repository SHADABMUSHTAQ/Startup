import React from "react";
import { Link } from "react-router-dom";
import { ArrowRight, ShieldCheck } from "lucide-react";
import "./CTA.css";
import { HashLink } from "react-router-hash-link";

const CTA = () => {
  return (
    <section className="cta-section">
      <div className="cta-wrapper">
        {/* Abstract Background Elements */}
        <div className="cta-glow"></div>
        <div className="cta-grid-pattern"></div>

        <div className="cta-content">
          <div className="icon-badge">
            <ShieldCheck size={24} />
          </div>
          
          <h2>Ready to Secure Your Infrastructure?</h2>
          
          <p>
            Join elite security teams using WarSOC to detect threats, 
            analyze logs, and respond to incidents in real-time.
          </p>
          
          <div className="cta-actions">
            <Link to="/login" className="cta-btn primary">
              Get Started Now <ArrowRight size={18} />
            </Link>
            <HashLink to="/#features" className="cta-btn secondary">
              View Features
            </HashLink>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CTA;