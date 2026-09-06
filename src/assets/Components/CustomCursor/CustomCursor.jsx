import { useEffect, useRef } from "react";
import "./CustomCursor.css";

const INTERACTIVE_SELECTOR = "a, button, input, textarea, select, [data-cursor-target]";

export default function CustomCursor() {
  const cursorRef = useRef(null);
  const ringRef = useRef(null);
  const frameRef = useRef(null);
  const positionRef = useRef({ x: -100, y: -100 });

  useEffect(() => {
    const finePointer = window.matchMedia("(pointer: fine)");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

    if (finePointer.matches && !reducedMotion.matches) {
      document.documentElement.classList.add("has-custom-cursor");
    }

    const updateAvailability = () => {
      document.documentElement.classList.toggle(
        "has-custom-cursor",
        finePointer.matches && !reducedMotion.matches,
      );
    };

    const moveCursor = (event) => {
      positionRef.current = { x: event.clientX, y: event.clientY };
      if (frameRef.current) return;

      frameRef.current = window.requestAnimationFrame(() => {
        const { x, y } = positionRef.current;
        if (cursorRef.current) cursorRef.current.style.transform = `translate3d(${x}px, ${y}px, 0)`;
        if (ringRef.current) ringRef.current.style.transform = `translate3d(${x}px, ${y}px, 0)`;
        frameRef.current = null;
      });
    };

    const updateHoverState = (event) => {
      const target = event.target instanceof Element ? event.target.closest(INTERACTIVE_SELECTOR) : null;
      document.documentElement.classList.toggle("custom-cursor-hovering", Boolean(target));
    };

    const updateViewportState = (event) => {
      document.documentElement.classList.toggle("custom-cursor-outside", !event.relatedTarget);
    };

    const pulse = () => {
      document.documentElement.classList.remove("custom-cursor-clicked");
      window.requestAnimationFrame(() => document.documentElement.classList.add("custom-cursor-clicked"));
    };

    const clearPulse = () => document.documentElement.classList.remove("custom-cursor-clicked");

    window.addEventListener("pointermove", moveCursor, { passive: true });
    window.addEventListener("pointerover", updateHoverState, { passive: true });
    window.addEventListener("pointerout", updateHoverState, { passive: true });
    window.addEventListener("pointerover", updateViewportState, { passive: true });
    window.addEventListener("pointerout", updateViewportState, { passive: true });
    window.addEventListener("pointerdown", pulse, { passive: true });
    window.addEventListener("animationend", clearPulse);
    finePointer.addEventListener("change", updateAvailability);
    reducedMotion.addEventListener("change", updateAvailability);

    return () => {
      window.removeEventListener("pointermove", moveCursor);
      window.removeEventListener("pointerover", updateHoverState);
      window.removeEventListener("pointerout", updateHoverState);
      window.removeEventListener("pointerover", updateViewportState);
      window.removeEventListener("pointerout", updateViewportState);
      window.removeEventListener("pointerdown", pulse);
      window.removeEventListener("animationend", clearPulse);
      finePointer.removeEventListener("change", updateAvailability);
      reducedMotion.removeEventListener("change", updateAvailability);
      document.documentElement.classList.remove("has-custom-cursor", "custom-cursor-hovering", "custom-cursor-clicked", "custom-cursor-outside");
      if (frameRef.current) window.cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return (
    <>
      <span ref={ringRef} className="custom-cursor-ring" aria-hidden="true" />
      <span ref={cursorRef} className="custom-cursor-dot" aria-hidden="true" />
    </>
  );
}
