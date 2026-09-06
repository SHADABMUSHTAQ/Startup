import React from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, ArrowRight, PlayCircle } from "lucide-react";
import SocDashboard from "./SocDashboard";
import "./Hero.css";

function Hero() {
  const navigate = useNavigate();

  return (
    <div className="hero-wrapper" id="home">
      {/* Background Glow Effects */}
      <div className="hero-glow glow-left"></div>
      <div className="hero-glow glow-right"></div>

      <div className="hero-container">
        
        {/* Left Side: Text Content */}
        <div className="hero-text">
          {/* <div className="badge-container">
            <span className="badge-icon"><ShieldCheck size={14} /></span>
            <span className="badge-text">Stay secure. Stay compliant.</span>
          </div> */}

          <div className="hero-announcement">
            <span className="hero-announcement-label">LIVE</span>
            <span>WarSOC Cloud SIEM is monitoring your frontier</span>
            <ArrowRight size={14} aria-hidden="true" />
          </div>

          <h1>
            See the threat.
            <br />
            Secure what <span className="gradient-text">matters.</span>
          </h1>
          
          <p>
            Detect threats in real-time with WarSOC's advanced Detection System.
            Secure your infrastructure
          </p>

          <div className="hero-buttons">
            <button className="btn-primary" onClick={() => navigate("/login")}>
              Get Started <ArrowRight size={18} />
            </button>
            
            <button className="btn-secondary" onClick={() => navigate("/#features")}>
              <PlayCircle size={18} /> Explore capabilities
            </button>
          </div>

          <div className="hero-stats">
            <div className="stat-item">
              <strong>24/7</strong>
              <span>monitoring</span>
            </div>
            <div className="stat-divider"></div>
            <div className="stat-item">
              <strong>5-Min</strong>
              <span>Agent Setup</span>
            </div>
          </div>
        </div>

        {/* Right Side: Live SOC Dashboard */}
        <div className="hero-visual">
          <SocDashboard />
        </div>

      </div>
    </div>
  );
}

export default Hero;
