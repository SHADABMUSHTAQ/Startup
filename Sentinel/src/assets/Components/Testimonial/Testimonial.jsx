import React from "react";
import "./Testimonial.css";

const testimonials = [
  {
    name: "Sarah Johnson",
    role: "Product Manager",
    feedback:
      "This tool has completely transformed how our team works. It’s fast, reliable, and super easy to use!",
    image: "https://randomuser.me/api/portraits/women/44.jpg",
    rating: 5,
  },
  {
    name: "Michael Lee",
    role: "Software Engineer",
    feedback:
      "I love the clean UI and advanced features. Customer support is also top-notch!",
    image: "https://randomuser.me/api/portraits/men/32.jpg",
    rating: 5,
  },
  {
    name: "Emma Davis",
    role: "Designer",
    feedback:
      "Honestly one of the best SaaS products I’ve used. Saved me hours every week.",
    image: "https://randomuser.me/api/portraits/women/65.jpg",
    rating: 5,
  },
];

const Testimonial = () => {
  return (
    <section className="testimonial-section">
      <h2 className="testimonial-title">What Our Customers Say</h2>
      <div className="testimonial-container">
        {testimonials.map((t, index) => (
          <div key={index} className="testimonial-card">
            <img src={t.image} alt={t.name} className="testimonial-img" />
            <h3>{t.name}</h3>
            <p className="role">{t.role}</p>
            <p className="feedback">“{t.feedback}”</p>
            <div className="stars">
              {Array(t.rating)
                .fill("⭐")
                .map((star, i) => (
                  <span key={i}>{star}</span>
                ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Testimonial;
