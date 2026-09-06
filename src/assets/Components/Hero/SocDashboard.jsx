import React, { useEffect, useState } from "react";
import { Activity, ShieldCheck, Zap } from "lucide-react";
import "./SocDashboard.css";

const METRICS = [
  { label: "Active threats", value: 247, tone: "danger" },
  { label: "Blocked", value: 239, tone: "safe" },
  { label: "Rules matched", value: 58, tone: "blue" },
];

const LOGS = [
  { time: "14:12", severity: "MED", message: "Recon command chain blocked" },
  { time: "14:09", severity: "HIGH", message: "Suspicious PowerShell isolated" },
  { time: "13:58", severity: "LOW", message: "Agent policy synced" },
];

const BARS = [46, 66, 38, 82, 57, 73, 48, 90, 62];

function useCounter(target, duration = 1100) {
  const [val, setVal] = useState(0);

  useEffect(() => {
    let start = null;
    let raf = 0;

    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      setVal(Math.floor(progress * target));
      if (progress < 1) raf = requestAnimationFrame(step);
    };

    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);

  return val;
}

export default function SocDashboard() {
  const activeThreats = useCounter(METRICS[0].value);
  const blocked = useCounter(METRICS[1].value);
  const rules = useCounter(METRICS[2].value);
  const metricValues = [activeThreats, blocked, rules];

  return (
    <div className="soc-visual-wrapper" aria-label="WarSOC live dashboard preview">
      <div className="soc-console">
        <div className="soc-console-header">
          <div className="soc-window-dots" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <span className="soc-kicker">WarSOC Cloud SIEM</span>
            <strong>Live Threat Command</strong>
          </div>
          <span className="soc-live-pill">LIVE</span>
        </div>

        <div className="soc-metric-grid">
          {METRICS.map((metric, index) => (
            <div className={`soc-metric-card ${metric.tone}`} key={metric.label}>
              <span>{metric.label}</span>
              <strong>{metricValues[index]}</strong>
            </div>
          ))}
        </div>

        <div className="soc-main-grid">
          <div className="soc-radar-panel">
            <div className="soc-panel-title">
              <ShieldCheck size={15} />
              Attack Origin
            </div>
            <div className="soc-radar">
              <span className="soc-radar-ring ring-one" />
              <span className="soc-radar-ring ring-two" />
              <span className="soc-radar-sweep" />
              <span className="soc-node node-one" />
              <span className="soc-node node-two" />
              <span className="soc-node node-three" />
              <span className="soc-center-node" />
            </div>
          </div>

          <div className="soc-chart-panel">
            <div className="soc-panel-title">
              <Activity size={15} />
              Event Rate
            </div>
            <div className="soc-bars">
              {BARS.map((height, index) => (
                <span
                  key={index}
                  className="soc-bar"
                  style={{ height: `${height}%`, animationDelay: `${index * 0.06}s` }}
                />
              ))}
            </div>
            <div className="soc-chart-labels">
              <span>09:55</span>
              <span>10:00</span>
              <span>10:05</span>
            </div>
          </div>
        </div>

        <div className="soc-log-panel">
          <div className="soc-panel-title">
            <Zap size={15} />
            Live Alert Stream
          </div>
          <div className="soc-log-list">
            {LOGS.map((log) => (
              <div className="soc-log-row" key={`${log.time}-${log.message}`}>
                <span className="soc-log-time">{log.time}</span>
                <span className={`soc-log-severity severity-${log.severity.toLowerCase()}`}>
                  {log.severity}
                </span>
                <span className="soc-log-message">{log.message}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="soc-orbit-card">
        <span>96%</span>
        <small>blocked</small>
      </div>
      <div className="soc-visual-glow" />
    </div>
  );
}
