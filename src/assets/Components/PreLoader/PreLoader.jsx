import React, { useEffect, useState } from 'react';
import './PreLoader.css';

const BOOT_SEQUENCE = [
  'Validating tenant trust boundary',
  'Syncing SIEM event streams',
  'Mapping policy controls',
  'Encrypting compliance evidence',
  'Priming response workflows',
  'WarSOC control plane ready'
];

const SIGNALS = ['SOC2', 'ISO', 'PECA', 'FBR'];

export default function PreLoader({ onFinish }) {
  const [step, setStep] = useState(0);
  const [isClosing, setIsClosing] = useState(false);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setStep((currentStep) => Math.min(currentStep + 1, BOOT_SEQUENCE.length - 1));
    }, 520);

    const closeTimer = window.setTimeout(() => {
      setIsClosing(true);
      window.setTimeout(onFinish, 620);
    }, 3800);

    return () => {
      window.clearInterval(interval);
      window.clearTimeout(closeTimer);
    };
  }, [onFinish]);

  const progress = Math.round(((step + 1) / BOOT_SEQUENCE.length) * 100);

  return (
    <div className={`warsoc-preloader ${isClosing ? 'is-closing' : ''}`} role="status" aria-live="polite">
      <div className="loader-grid" />
      <div className="loader-vignette" />

      <div className="loader-stage">
        <div className="loader-orbit" aria-hidden="true">
          <span className="orbit-ring orbit-ring-one" />
          <span className="orbit-ring orbit-ring-two" />
          <span className="orbit-scan" />
          {SIGNALS.map((signal, index) => (
            <span className={`signal-node signal-node-${index + 1}`} key={signal}>
              {signal}
            </span>
          ))}
        </div>

        <div className="loader-core">
          <div className="logo-shell">
            <img src="/Logo.png" alt="WarSOC" className="loader-logo" />
            <span className="logo-sheen" aria-hidden="true" />
          </div>
        </div>

        <div className="loader-copy">
          <span className="loader-kicker">SECURE BOOT</span>
          <h1>WarSOC</h1>
          <p>{BOOT_SEQUENCE[step]}</p>
        </div>

        <div className="loader-progress" aria-label={`Loading ${progress}%`}>
          <span className="progress-track">
            <span className="progress-fill" style={{ width: `${progress}%` }} />
          </span>
          <span className="progress-value">{progress}%</span>
        </div>
      </div>
    </div>
  );
}