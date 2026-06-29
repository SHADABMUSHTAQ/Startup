import React, { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Network, BellRing, Lock, Database, FileCheck } from "lucide-react"; 
import "./Features.css";

function Features() {
  const sectionRef = useRef(null);
  const [activeFeatureId, setActiveFeatureId] = useState(null);

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

  const activeFeature = useMemo(
    () => features.find((feature) => feature.id === activeFeatureId) || null,
    [activeFeatureId]
  );

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

            window.setTimeout(() => {
              entry.target.style.removeProperty("--reveal-delay");
            }, 900);

            observer.unobserve(entry.target);
          }
        });
      },
      {
        rootMargin: "0px 0px -10% 0px",
        threshold: 0.12,
      }
    );

    const elements = sectionRef.current?.querySelectorAll(".reveal-on-scroll") || [];
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
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

        <div
          className="feature-orbital reveal-on-scroll"
          onClick={() => setActiveFeatureId(null)}
        >
          <div
            className={`feature-orbit-stage ${activeFeature ? "has-active-card" : ""}`}
            aria-label="WarSOC feature orbit"
          >
            <div className="feature-orbit-ring feature-orbit-ring-main"></div>
            <div className="feature-orbit-scan"></div>

            {features.map((feature, index) => {
              const angle = (360 / features.length) * index - 90;
              const isActive = feature.id === activeFeatureId;

              return (
                <button
                  key={feature.id}
                  type="button"
                  className={`feature-node ${isActive ? "active" : ""}`}
                  style={{
                    "--node-angle": `${angle}deg`,
                    "--node-angle-inverse": `${angle * -1}deg`,
                  }}
                  onClick={(event) => {
                    event.stopPropagation();
                    setActiveFeatureId((currentId) => currentId === feature.id ? null : feature.id);
                  }}
                  aria-pressed={isActive}
                >
                  <span className="feature-node-icon">{feature.icon}</span>
                  <span className="feature-node-title">{feature.title}</span>
                </button>
              );
            })}

            {!activeFeature && (
              <div className="feature-empty-hub" aria-hidden="true">
                <img src="/Logo.png" alt="" />
              </div>
            )}

            {activeFeature && (
              <article
                className="feature-center-card"
                key={activeFeature.id}
                onClick={(event) => event.stopPropagation()}
              >
                <div className="feature-center-meta">
                  <span className="feature-status-pill">ACTIVE</span>
                  <span className="feature-index">Feature 0{activeFeature.id}</span>
                </div>
                <div className="feature-center-heading">
                  <span className="feature-center-icon">{activeFeature.icon}</span>
                  <h3>{activeFeature.title}</h3>
                </div>
                <p>{activeFeature.description}</p>

                <div className="feature-energy">
                  <div className="feature-energy-row">
                    <span>Signal Confidence</span>
                    <strong>{activeFeature.id === 6 ? "94" : 100 - activeFeature.id * 6}%</strong>
                  </div>
                  <div className="feature-energy-track">
                    <span style={{ width: `${activeFeature.id === 6 ? 94 : 100 - activeFeature.id * 6}%` }}></span>
                  </div>
                </div>

                <div className="feature-connected">
                  <span>Connected Capabilities</span>
                  <div>
                    {features
                      .filter((feature) => feature.id !== activeFeature.id)
                      .slice(0, 2)
                      .map((feature) => (
                        <button
                          type="button"
                          key={feature.id}
                          onClick={() => setActiveFeatureId(feature.id)}
                        >
                          {feature.title}
                        </button>
                      ))}
                  </div>
                </div>
              </article>
            )}
          </div>
        </div>

        <div className="feature-grid feature-grid-fallback" aria-hidden="true">
          {features.map((feature, index) => (
            <div 
              key={feature.id} 
              className="feature-card reveal-on-scroll"
              style={{ "--reveal-delay": `${index * 70}ms` }} 
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
