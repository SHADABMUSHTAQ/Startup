import React, { useEffect, useRef } from "react";
import { ShieldCheck, Activity, Zap, Lock, Database, Globe } from "lucide-react"; 
import "./Features.css";

function Features() {
  const sectionRef = useRef(null);

  const features = [
    {
      id: 1,
      title: "Real-Time Threat Detection",
      description: "Analyze millions of events per second with our advanced AI engine to detect anomalies instantly.",
      icon: <Activity size={32} />,
    },
    {
      id: 2,
      title: "Automated Incident Response",
      description: "Trigger automated playbooks to contain threats before they spread across your network.",
      icon: <Zap size={32} />,
    },
    {
      id: 3,
      title: "Global Threat Intelligence",
      description: "Stay ahead of attackers with integrated threat feeds from over 50+ global sources.",
      icon: <Globe size={32} />,
    },
    {
      id: 4,
      title: "Bank-Grade Encryption",
      description: "Your data is secured with AES-256 encryption at rest and TLS 1.3 in transit.",
      icon: <Lock size={32} />,
    },
    {
      id: 5,
      title: "Unlimited Log Retention",
      description: "Store logs for compliance (GDPR, HIPAA, PCI-DSS) with hot and cold storage options.",
      icon: <Database size={32} />,
    },
    {
      id: 6,
      title: "Zero Trust Architecture",
      description: "Verify every request, every time. Strict identity controls for maximum security.",
      icon: <ShieldCheck size={32} />,
    },
  ];

  // SCROLL ANIMATION LOGIC
// SCROLL ANIMATION LOGIC
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            // Jab screen par aaye to animate karo
            entry.target.classList.add("visible");
          } else {
            // ✅ THE FIX: Jab screen se bahar jaye to class hata do!
            // Is se har baar scroll karne par animation dobara chalegi.
            entry.target.classList.remove("visible");
          }
        });
      },
      { threshold: 0.15 } 
    );

    const elements = document.querySelectorAll(".reveal-on-scroll");
    elements.forEach((el) => observer.observe(el));

    return () => {
      elements.forEach((el) => observer.unobserve(el));
    };
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
          <p>
            Built for modern security teams who demand speed, scale, and accuracy.
          </p>
        </div>

        {/* CARDS ANIMATION (Staggered Delay) */}
        <div className="feature-grid">
          {features.map((feature, index) => (
            <div 
              key={feature.id} 
              className="feature-card reveal-on-scroll"
              style={{ transitionDelay: `${index * 0.1}s` }} // Har card 0.1s ke gap se aayega
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