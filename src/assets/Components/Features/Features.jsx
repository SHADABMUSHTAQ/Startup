import React, { useEffect, useRef } from "react";
import { Activity, Network, BellRing, Lock, Database, FileCheck } from "lucide-react"; 
import "./Features.css";

function Features() {
  const sectionRef = useRef(null);

  const features = [
    // --- TOP ROW: CORE SIEM CAPABILITIES ---
    { 
        id: 1, 
        title: "Real-Time Threat Detection", 
        description: "Monitor network and endpoint logs 24/7. Identify anomalies instantly via strict correlation rules.", 
        icon: <Activity size={32} /> 
    },
    { 
        id: 2, 
        title: "Unified Log Aggregation", 
        description: "Centralize telemetry. Collect data seamlessly via automated Windows Agents or secure manual uploads.", 
        icon: <Network size={32} /> 
    },
    { 
        id: 3, 
        title: "Instant Threat Alerting", 
        description: "Receive immediate alerts for critical events. Isolate threats and mitigate risks before impact.", 
        icon: <BellRing size={32} /> 
    },

    // --- BOTTOM ROW: COMPLIANCE & AUDIT ---
    { 
        id: 4, 
        title: "Immutable Evidence Vault", 
        description: "Secure logs using WORM technology. Maintain a cryptographic chain of custody for legal admissibility.", 
        icon: <Lock size={32} /> 
    },
    { 
        id: 5, 
        title: "Scalable Log Retention", 
        description: "Fulfill strict regulatory policies. Scale seamlessly from instant hot storage to multi-year cold archives.", 
        icon: <Database size={32} /> 
    },
    { 
        id: 6, 
        title: "Automated Audit Reporting", 
        description: "Generate compliance-ready reports for PCI-DSS, GDPR, and PECA effortlessly with a single click.", 
        icon: <FileCheck size={32} /> 
    },
  ];

  // SCROLL ANIMATION LOGIC
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            if (entry.target.classList.contains('section-header')) {
                const highlight = entry.target.querySelector('.highlight-text');
                if (highlight) {
                    highlight.classList.add('animate-highlight');
                }
            }
          } else {
            entry.target.classList.remove("visible");
             if (entry.target.classList.contains('section-header')) {
                const highlight = entry.target.querySelector('.highlight-text');
                if (highlight) {
                    highlight.classList.remove('animate-highlight');
                }
            }
          }
        });
      },
      { threshold: 0.15 } 
    );

    const elements = document.querySelectorAll(".reveal-on-scroll");
    elements.forEach((el) => observer.observe(el));

    return () => elements.forEach((el) => observer.unobserve(el));
  }, []);

  return (
    <section className="features-section" id="features" ref={sectionRef}>
      {/* Background Decor */}
      <div className="feature-glow"></div>

      <div className="features-container">
        
        {/* HEADER ANIMATION */}
        <div className="section-header reveal-on-scroll">
          <span className="section-badge">Why Choose WarSOC?</span>
          <h2>
            Enterprise-Grade <span className="highlight-text">Security</span>
          </h2>
          <p>Built for modern security teams who demand speed, scale, and accuracy.</p>
        </div>

        {/* CARDS ANIMATION (Staggered Delay) */}
        <div className="feature-grid">
          {features.map((feature, index) => (
            <div 
              key={feature.id} 
              className="feature-card reveal-on-scroll"
              style={{ transitionDelay: `${index * 0.1}s` }} 
            >
              <div className="icon-wrapper">{feature.icon}</div>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}

export default Features;