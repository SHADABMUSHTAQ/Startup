import React from "react";
import { ArrowRight, CheckCircle } from "lucide-react";
import "./About.css";

const About = () => {
  const points = [
    "NLP-Powered Log Analysis",      
    "Automated Windows Agent",       
    "Manual Log Upload & Audit",     
    "Real-Time Threat Alerting"      
  ];

  return (
    <section className="about-section" id="about">
      <div className="about-container">
        
        {/* Left Side: Modern Image */}
        <div className="about-image-wrapper">
          {/* ✅ NEW: Background Glow for the blue image */}
          <div className="about-image-glow"></div>
          
          <img src="/2 image.jpg" alt="WarSOC Cyber Defense Node" className="about-img" />
          
          {/* Floating Badge for Startup Vibe */}
          <div className="experience-badge">
            <span className="years" style={{ fontSize: '1.8rem', letterSpacing: '1px' }}>NLP</span>
            <span className="text">Powered<br/>Intelligence</span>
          </div>
        </div>

        {/* Right Side: Content */}
        <div className="about-content">
          <div className="section-tag">About WarSOC</div>
          <h2>
            Democratizing Security For  <span className="highlight">SMBs</span>
          </h2>
          
          <p className="description">
            WarSOC is a B2B SaaS platform redefining modern security operations.
            We combine powerful SIEM capabilities with compliance-ready SOC workflows.
            Our platform unifies monitoring, detection, and response in one system.
            We eliminate operational complexity while ensuring regulatory compliance.
            Built for efficiency, WarSOC cuts security costs without cutting protection.
            Enterprise-grade SOC security — accessible, scalable, and affordable.
          </p>

          <div className="points-grid">
            {points.map((point, index) => (
              <div key={index} className="point-item">
                <CheckCircle size={20} className="point-icon" />
                <span>{point}</span>
              </div>
            ))}
          </div>

          <a href="/about" className="about-btn">
            Discover Our Tech <ArrowRight size={18} />
          </a>
        </div>

      </div>
    </section>
  );
};

export default About;