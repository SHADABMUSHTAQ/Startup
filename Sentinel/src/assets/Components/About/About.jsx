import React from "react";
import { ArrowRight, CheckCircle } from "lucide-react";
import "./About.css";

const About = () => {
  const points = [
    "AI-Driven Threat Analysis",
    "24/7 Real-Time Monitoring",
    "Zero-Trust Architecture",
    "Seamless Cloud Integration"
  ];

  return (
    <section className="about-section" id="about">
      <div className="about-container">
        
        {/* Left Side: Image with Cyber Frame */}
        <div className="about-image-wrapper">
          <div className="img-frame"></div>
          <img src="/hero-img.png" alt="WarSOC Dashboard Analysis" className="about-img" />
          
          {/* Floating Badge */}
          <div className="experience-badge">
            <span className="years">5+</span>
            <span className="text">Years of<br/>Excellence</span>
          </div>
        </div>

        {/* Right Side: Content */}
        <div className="about-content">
          <div className="section-tag">About WarSOC</div>
          <h2>
            Pioneering the Future of <br />
            <span className="highlight">Cyber Defense</span>
          </h2>
          
          <p className="description">
            We are not just a security tool; we are your digital shield. 
            Born from the need for smarter, faster, and more reliable threat detection, 
            WarSOC combines machine learning with human expertise to stop attacks before they happen.
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
            More About Us <ArrowRight size={18} />
          </a>
        </div>

      </div>
    </section>
  );
};

export default About;