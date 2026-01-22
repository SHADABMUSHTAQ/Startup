import React from "react";
import "./About.css";

const About = () => {
  return (
    <section className="about">
      <div className="about-container">
        <div className="about-text">
          <h2>About Us</h2>
          <p>
            We are a passionate team dedicated to building cutting-edge security
            tools that empower businesses to stay safe in the digital era.  
            With a blend of innovation, expertise, and trust, we deliver solutions 
            that make cybersecurity simple and effective.
          </p>
          <p>
            Our mission is to provide next-generation protection while keeping 
            user experience clean and effortless. Whether you’re a startup or an 
            enterprise, our platform scales with your needs.
          </p>
          <a href="/contact" className="about-btn">Learn More</a>
        </div>

        <div className="about-image">
          <img src="/hero-img.png" alt="error image" />
        </div>
      </div>
    </section>
  );
};

export default About;
