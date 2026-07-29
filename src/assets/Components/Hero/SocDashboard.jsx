import React, { useEffect, useState } from "react";
import "./SocDashboard.css";

/* ── Animated bar chart data ── */
const CHART_DATA = [
  { val: 30, color: "#47a5ef" },
  { val: 55, color: "#b7ea48" },
  { val: 80, color: "#ef4444" },
  { val: 45, color: "#47a5ef" },
  { val: 90, color: "#ef4444" },
  { val: 60, color: "#b7ea48" },
  { val: 75, color: "#ef4444" },
  { val: 40, color: "#47a5ef" },
  { val: 85, color: "#ef4444" },
  { val: 50, color: "#b7ea48" },
  { val: 95, color: "#ef4444" },
  { val: 65, color: "#47a5ef" },
];

const TIMES = ["09:55", "10:00", "10:05"];

/* ── Animated counter hook ── */
function useCounter(target, duration = 1200) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = null;
    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      setVal(Math.floor(progress * target));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration]);
  return val;
}

export default function SocDashboard() {
  const threats  = useCounter(247);
  const blocked  = useCounter(239);
  const uptime   = useCounter(999);   // displayed as 99.9%

  return (
    <div className="soc-visual-wrapper">

      {/* ── CARD 1 (top-left) — Threat Overview ── */}
      <div className="soc-float-card card-top">
        <div className="sfc-header">
          <span className="sfc-dot sfc-dot-red" />
          <span className="sfc-dot sfc-dot-yellow" />
          <span className="sfc-dot sfc-dot-green" />
          <span className="sfc-title">Threat Overview — Live</span>
          <span className="sfc-live">● LIVE</span>
        </div>

        <div className="sfc-metrics">
          <div className="sfc-metric">
            <span className="sfc-val red">{threats}</span>
            <span className="sfc-lbl">Threats Detected</span>
          </div>
          <div className="sfc-sep" />
          <div className="sfc-metric">
            <span className="sfc-val lime">{blocked}</span>
            <span className="sfc-lbl">Blocked</span>
          </div>
          <div className="sfc-sep" />
          <div className="sfc-metric">
            <span className="sfc-val blue">{(uptime / 10).toFixed(1)}%</span>
            <span className="sfc-lbl">Uptime SLA</span>
          </div>
        </div>

        {/* Ring indicator */}
        <div className="sfc-ring-row">
          <div className="sfc-ring-wrap">
            <svg viewBox="0 0 80 80" className="sfc-ring-svg">
              <circle cx="40" cy="40" r="32" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"/>
              <circle
                cx="40" cy="40" r="32"
                fill="none"
                stroke="#b7ea48"
                strokeWidth="8"
                strokeDasharray="201"
                strokeDashoffset="20"
                strokeLinecap="round"
                transform="rotate(-90 40 40)"
                className="sfc-ring-arc"
              />
            </svg>
            <span className="sfc-ring-label">96%<br/><small>Blocked</small></span>
          </div>
          <div className="sfc-ring-legend">
            <div><span className="sfc-leg-dot" style={{background:"#b7ea48"}} /> Blocked</div>
            <div><span className="sfc-leg-dot" style={{background:"#ef4444"}} /> Active</div>
            <div><span className="sfc-leg-dot" style={{background:"#47a5ef"}} /> Monitored</div>
          </div>
        </div>
      </div>

      {/* ── CARD 2 (bottom-right) — Activity Chart ── */}
      <div className="soc-float-card card-bottom">
        <div className="sfc-header">
          <span className="sfc-dot sfc-dot-red" />
          <span className="sfc-dot sfc-dot-yellow" />
          <span className="sfc-dot sfc-dot-green" />
          <span className="sfc-title">Security Event Rate — SLI</span>
        </div>

        {/* Animated bar chart */}
        <div className="sfc-chart">
          <div className="sfc-y-axis">
            <span>100</span>
            <span>50</span>
            <span>0</span>
          </div>
          <div className="sfc-bars-area">
            <div className="sfc-bars-group">
              {CHART_DATA.map((d, i) => (
                <div key={i} className="sfc-bar-col">
                  <div
                    className="sfc-bar"
                    style={{
                      height: `${d.val}%`,
                      background: d.color,
                      opacity: 0.75,
                      animationDelay: `${i * 0.06}s`,
                    }}
                  />
                </div>
              ))}
            </div>
            <div className="sfc-x-labels">
              {TIMES.map((t, i) => (
                <span key={i}>{t}</span>
              ))}
            </div>
          </div>
        </div>

        <div className="sfc-chart-footer">
          <span className="sfc-status-ok">● All agents reporting</span>
          <span className="sfc-agents-count">12 endpoints online</span>
        </div>
      </div>

      {/* Ambient glow behind cards */}
      <div className="soc-visual-glow" />
    </div>
  );
}
