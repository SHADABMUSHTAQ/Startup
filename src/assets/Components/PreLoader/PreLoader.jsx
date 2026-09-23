import React, { useEffect, useState } from 'react';
import './PreLoader.css';

const BOOT_SEQUENCE = [
  'Loading',
  'Preparing',
  'Almost ready'
];

export default function PreLoader({ onFinish }) {
  const [step, setStep] = useState(0);
  const [isClosing, setIsClosing] = useState(false);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setStep((currentStep) => Math.min(currentStep + 1, BOOT_SEQUENCE.length - 1));
    }, 650);

    const closeTimer = window.setTimeout(() => {
      setIsClosing(true);
      window.setTimeout(onFinish, 420);
    }, 2400);

    return () => {
      window.clearInterval(interval);
      window.clearTimeout(closeTimer);
    };
  }, [onFinish]);

  const progress = Math.round(((step + 1) / BOOT_SEQUENCE.length) * 100);

  return (
    <div className={`warsoc-preloader ${isClosing ? 'is-closing' : ''}`} role="status" aria-live="polite">
      <div className="preloader-shell">
        <span className="preloader-spinner" aria-hidden="true" />
        <p>{BOOT_SEQUENCE[step]}</p>
        <div className="preloader-progress" aria-label={`Loading ${progress}%`}>
          <span style={{ width: `${progress}%` }} />
        </div>
      </div>
    </div>
  );
}
