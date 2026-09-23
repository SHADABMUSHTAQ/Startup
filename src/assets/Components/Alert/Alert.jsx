import React, { useEffect } from "react";
import "./Alert.css";
import { X } from "lucide-react"; // icon library (lucide-react)

function Alert({ type = "info", message, onClose, autoClose = 4000 }) {
  // Auto close after some seconds
  useEffect(() => {
    if (autoClose) {
      const timer = setTimeout(() => {
        onClose?.();
      }, autoClose);
      return () => clearTimeout(timer);
    }
  }, [autoClose, onClose]);

  return (
    <div className={`alert alert-${type}`}>
      <span className="alert-message">{message}</span>
      <button className="alert-close" onClick={onClose}>
        <X size={18} />
      </button>
    </div>
  );
}

export default Alert;
