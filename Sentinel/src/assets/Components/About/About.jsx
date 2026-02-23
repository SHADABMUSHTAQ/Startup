import React from "react";
import { ArrowRight, CheckCircle } from "lucide-react";
import "./About.css";

const About = () => {
  // ✅ UPDATED: Real features based on your project reality
  const points = [
    "NLP-Powered Log Analysis",      // AI ki jagah NLP
    "Automated Windows Agent",       // Agent ka zikar
    "Manual Log Upload & Audit",     // Manual feature ka zikar
    "Real-Time Threat Alerting"      // 24/7 monitoring ka behtar version
  ];

  return (
    <section className="about-section" id="about">
      <div className="about-container">
        
        {/* Left Side: Modern Image */}
        <div className="about-image-wrapper">
          {/* Note: In React/Vite, usually you just use "/2 image.jpg" if it's in the public folder */}
          <img src="/2 image.jpg" alt="WarSOC Cyber Defense Node" className="about-img" />
          
          {/* ✅ UPDATED: Floating Badge for Startup Vibe */}
          <div className="experience-badge">
            {/* "years" class use kar rahe hain taake styling same rahe, par text change kar diya */}
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
          
          {/* ✅ UPDATED: Description reflecting NLP and Hybrid approach */}
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