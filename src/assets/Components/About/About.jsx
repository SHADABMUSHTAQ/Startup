import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  CheckCircle2,
  LockKeyhole,
  Siren,
} from "lucide-react";
import "./About.css";

const About = () => {
  const sectionRef = useRef(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setVisible(true);
      },
      { threshold: 0.16 },
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      className={`about-v2-section ${visible ? "about-v2-visible" : ""}`}
      ref={sectionRef}
      id="about"
    >
      <div className="about-glow about-glow-1" aria-hidden="true" />
      <div className="about-glow about-glow-2" aria-hidden="true" />
      <div className="about-v2-container">
        <div className="about-v2-copy anim-item anim-show">
          {/* <span className="about-v2-tag">// ABOUT WARSOC</span> */}
          <h2 className="about-v2-title">
            Security operations,
            <br />
            <span className="about-v2-accent">made easier to run.</span>
          </h2>
          <p className="about-v2-subtitle">
            WarSOC gives growing teams a practical command centre for detecting
            threats, understanding endpoint activity, and keeping compliance
            evidence ready without adding another layer of operational noise.
          </p>
          <div className="about-v2-proof-row">
            <div>
              <strong>One workspace</strong>
              <span>Incidents to evidence</span>
            </div>
            <div>
              <strong>Clear context</strong>
              <span>Endpoint-aware decisions</span>
            </div>
            <div>
              <strong>Built for teams</strong>
              <span>Admin to analyst workflows</span>
            </div>
          </div>
          {/* <div className="about-v2-capabilities">
            {capabilities.map(({ icon: Icon, title, text }) => (
              <article className="about-capability" key={title}>
                <span className="about-capability-icon">
                  <Icon size={19} />
                </span>
                <span>
                  <strong>{title}</strong>
                  <small>{text}</small>
                </span>
              </article>
            ))}
          </div> */}
        </div>

        <div
          className="about-dashboard-preview anim-item anim-show"
          aria-label="WarSOC dashboard preview"
        >
          <div className="about-preview-topbar">
            <div className="about-preview-brand">
              <img src="/Logo.png" alt="" />
              <span>WarSOC</span>
            </div>
            <div className="about-preview-search">
              <Activity size={13} /> Search security activity
            </div>
            <span className="about-preview-live">
              <i /> ACTIVE
            </span>
          </div>
          <div className="about-preview-context">
            <div>
              <span>CONNECTED ENDPOINT</span>
              <strong>Endpoint fleet</strong>
            </div>
            <div>
              <span>STATUS</span>
              <strong>
                <b className="about-status-dot" /> Monitoring
              </strong>
            </div>
            <div>
              <span>LAST SEEN</span>
              <strong>Live telemetry</strong>
            </div>
          </div>
          <div className="about-preview-metrics">
            <div>
              <span className="about-metric-icon blue">
                <Activity size={15} />
              </span>
              <b>Incidents</b>
              <strong>Active queue</strong>
            </div>
            <div>
              <span className="about-metric-icon red">
                <Siren size={15} />
              </span>
              <b>Detections</b>
              <strong>Prioritised</strong>
            </div>
            <div>
              <span className="about-metric-icon green">
                <LockKeyhole size={15} />
              </span>
              <b>Endpoints</b>
              <strong>Protected</strong>
            </div>
          </div>
          <div className="about-preview-grid">
            <div className="about-preview-panel about-trend-panel">
              <div className="about-panel-heading">
                <span>INCIDENT VOLUME TREND</span>
                <small>Last 24 hours</small>
              </div>
              <div className="about-sparkline">
                <span />
                <span />
                <span />
                <span />
                <span />
                <span />
                <span />
              </div>
              <div className="about-axis">
                <small>09:00</small>
                <small>12:00</small>
                <small>15:00</small>
                <small>18:00</small>
              </div>
            </div>
            <div className="about-preview-panel about-severity-panel">
              <div className="about-panel-heading">
                <span>THREAT SEVERITY</span>
                <small>Open queue</small>
              </div>
              <div className="about-severity-chart" />
              <div className="about-legend">
                <span>
                  <i className="critical" /> Critical
                </span>
                <span>
                  <i className="high" /> High
                </span>
                <span>
                  <i className="medium" /> Medium
                </span>
              </div>
            </div>
            <div className="about-preview-panel about-source-panel">
              <div className="about-panel-heading">
                <span>TELEMETRY SOURCES</span>
                <small>Top sources</small>
              </div>
              <div className="about-source-row">
                <span>Endpoint</span>
                <i>
                  <b style={{ width: "82%" }} />
                </i>
              </div>
              <div className="about-source-row">
                <span>Network</span>
                <i>
                  <b style={{ width: "56%" }} />
                </i>
              </div>
              <div className="about-source-row">
                <span>Cloud</span>
                <i>
                  <b style={{ width: "34%" }} />
                </i>
              </div>
            </div>
          </div>
          <div className="about-preview-footer">
            <CheckCircle2 size={15} />
            <span>
              Evidence and endpoint context stay connected to every decision.
            </span>
            <strong>
              VIEW WORKSPACE <span>→</span>
            </strong>
          </div>
        </div>
      </div>
    </section>
  );
};

export default About;
