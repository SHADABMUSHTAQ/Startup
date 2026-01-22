import React from "react";
import { Link } from "react-router-dom"; 
import "./CTA.css";

const CTA = () => {
  return (
    <section className="cta-section">
      <div className="cta-content">
        <h2>Ready to Boost Your Productivity?</h2>
        <p>
          Join thousands of professionals using our tool to save time and get
          more done every day.
        </p>
        <Link to="/login" className="cta-btn">
          Get Started Free
        </Link>
      </div>
    </section>
  );
};

export default CTA;
