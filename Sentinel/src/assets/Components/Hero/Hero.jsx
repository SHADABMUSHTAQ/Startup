import React from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, ArrowRight, PlayCircle } from "lucide-react"; // Icons
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
          <div className="badge-container">
            <span className="badge-icon"><ShieldCheck size={14} /></span>
            <span className="badge-text">Next-Gen SIEM Architecture</span>
          </div>

          <h1>
            Unlocking The Secret <br /> 
            of <span className="gradient-text">Digital Safety</span>
          </h1>
          
          <p>
            Detect threats in real-time with WarSOC's advanced Detection System.
            Secure your infrastructure
          </p>

          <div className="hero-buttons">
            <button className="btn-primary" onClick={() => navigate("/login")}>
              Get Started <ArrowRight size={18} />
            </button>
            
            {/* <button className="btn-secondary" onClick={() => navigate("/#features")}>
              <PlayCircle size={18} /> Live Demo
            </button> */}
          </div>

          <div className="hero-stats">
            <div className="stat-item">
              <strong>10k+</strong>
              <span>Threats Blocked</span>
            </div>
            <div className="stat-divider"></div>
            <div className="stat-item">
              <strong>99.9%</strong>
              <span>Uptime</span>
            </div>
          </div>
        </div>

        {/* Right Side: Image/Visual */}
        <div className="hero-visual">
          <div className="image-backdrop"></div>
          <img src="/hero-img.png" alt="WarSOC Dashboard Preview" className="floating-img" />
        </div>

      </div>
    </div>
  );
}

export default Hero;