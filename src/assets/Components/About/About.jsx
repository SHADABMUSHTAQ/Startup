import React, { useEffect, useRef, useState } from "react";
import { Shield, Zap, FileCheck, Eye, TrendingUp, Server } from "lucide-react";
import "./About.css";

const stats = [
  { value: "10x", label: "Faster Threat Detection" },
  { value: "99.9%", label: "Platform Uptime" },
  { value: "60%", label: "Cost Reduction" },
  { value: "24/7", label: "SOC Coverage" },
];

const pillars = [
  {
    icon: <Shield size={22} />,
    title: "Unified SIEM",
    desc: "Centralized log monitoring across all endpoints.",
  },
  {
    icon: <Zap size={22} />,
    title: "Real-Time Alerts",
    desc: "Instant threat notifications before damage occurs.",
  },
  {
    icon: <Eye size={22} />,
    title: "SOC Workflows",
    desc: "Compliance-ready workflows for every team size.",
  },
  {
    icon: <FileCheck size={22} />,
    title: "Compliance Audit Logs",
    desc: "SOC 2, ISO 27001 & regulatory audit trails — auto-generated.",
  },
  {
    icon: <Server size={22} />,
    title: "Auto Log Upload",
    desc: "Automated audit trails with zero manual effort.",
  },
  {
    icon: <TrendingUp size={22} />,
    title: "SMB-First Pricing",
    desc: "Enterprise power at a fraction of the cost.",
  },
];

const About = () => {
  const sectionRef = useRef(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setVisible(true);
      },
      { threshold: 0.15 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section className={`about-v2-section ${visible ? "about-v2-visible" : ""}`} ref={sectionRef} id="about">
      {/* Ambient background glows */}
      <div className="about-glow about-glow-1" />
      <div className="about-glow about-glow-2" />

      <div className="about-v2-container">

        {/* ── TOP: Label + Heading ── */}
        <div className={`about-v2-header anim-item ${visible ? "anim-show" : ""}`} style={{ transitionDelay: "0s" }}>
          <span className="about-v2-tag">// Why WarSOC</span>
          <h2 className="about-v2-title">
            Built Different.<br />
            <span className="about-v2-accent">Priced For You.</span>
          </h2>
          <p className="about-v2-subtitle">
            Most SMBs can't afford a full SOC team — so we built one in software.
            WarSOC delivers enterprise-grade detection, compliance, and response
            at a price that makes sense for growing businesses.
          </p>
        </div>

        {/* ── MIDDLE: Stats Row ── */}
        <div className="about-v2-stats">
          {stats.map((stat, i) => (
            <div
              className={`about-stat-card anim-item ${visible ? "anim-show" : ""}`}
              key={i}
              style={{ transitionDelay: `${0.15 + i * 0.1}s` }}
            >
              <div className="about-stat-value">{stat.value}</div>
              <div className="about-stat-label">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* ── BOTTOM: Pillars Grid ── */}
        <div className="about-v2-grid">
          {pillars.map((p, i) => (
            <div
              className={`about-pillar-card anim-item ${visible ? "anim-show" : ""}`}
              key={i}
              style={{ transitionDelay: `${0.55 + i * 0.09}s` }}
            >
              <div className="pillar-icon-wrap">{p.icon}</div>
              <div className="pillar-text">
                <h4>{p.title}</h4>
                <p>{p.desc}</p>
              </div>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
};

export default About;
