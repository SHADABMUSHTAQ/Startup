import React from 'react';
import { Shield } from 'lucide-react';
import './SessionLoading.css';

/**
 * Full-screen session check UI (replaces non-functional Tailwind classes).
 */
export default function SessionLoading() {
  return (
    <div className="session-gate" role="status" aria-live="polite" aria-busy="true">
      <div className="session-gate__inner">
        <div className="session-gate__mark">
          <div className="session-gate__ring" aria-hidden />
          <div className="session-gate__shield">
            <Shield size={40} strokeWidth={1.75} aria-hidden />
          </div>
        </div>
        <p className="session-gate__label">Verifying session…</p>
      </div>
    </div>
  );
}
