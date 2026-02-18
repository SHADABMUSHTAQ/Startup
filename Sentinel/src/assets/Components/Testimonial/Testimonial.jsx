import React from "react";
import { Star, Quote } from "lucide-react";
import "./Testimonial.css";

const testimonials = [
  {
    id: 1,
    name: "Elena Rodriguez",
    role: "CISO at FinSecure",
    feedback:
      "WarSOC reduced our Mean Time to Detect (MTTD) by 60%. The AI correlation engine is incredibly accurate and significantly lowered our false positives.",
    image: "public/photo 1.jpg",
    rating: 5,
  },
  {
    id: 2,
    name: "James Chen",
    role: "Lead SOC Analyst",
    feedback:
      "The dashboard visualization allows me to see the entire attack vector in one glance. It's the most intuitive SIEM tool I've used in my 10-year career.",
    image: "public/phot 2.jpg",
    rating: 5,
  },
  {
    id: 3,
    name: "Sarah Jenkins",
    role: "DevSecOps Engineer",
    feedback:
      "Integration with our existing AWS infrastructure was seamless. The automated playbooks save us hours of manual work every single week.",
    image: "public/photo 1.jpg",
    rating: 5,
  },
];

const companies = ["CYBERDYNE", "KVH CORP", "NETGUARD", "OMEGA SEC", "BLUETECH"];

const Testimonial = () => {
  return (
    <section className="testimonial-section">
      {/* Background Decor */}
      <div className="testimonial-glow"></div>

      <div className="testimonial-container">
        {/* Header */}
        <div className="testimonial-header">
          <span className="section-badge">Community Trust</span>
          <h2>Trusted by Security Teams</h2>
          <p>See how world-class organizations secure their infrastructure with WarSOC.</p>
        </div>

        {/* Company Logos (Social Proof) */}
        <div className="company-logos">
          <p className="logos-title">Powering security for:</p>
          <div className="logo-track">
            {companies.map((company, index) => (
              <span key={index} className="company-name">{company}</span>
            ))}
          </div>
        </div>

        {/* Reviews Grid */}
        <div className="testimonial-grid">
          {testimonials.map((t) => (
            <div key={t.id} className="testimonial-card">
              <Quote className="quote-icon" size={40} />
              
              <p className="feedback">"{t.feedback}"</p>
              
              <div className="card-footer">
                <img src={t.image} alt={t.name} className="testimonial-img" />
                <div className="user-info">
                  <h3>{t.name}</h3>
                  <span className="role">{t.role}</span>
                  <div className="stars">
                    {Array(t.rating).fill(0).map((_, i) => (
                      <Star key={i} size={14} fill="#64ffda" stroke="none" />
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Testimonial;