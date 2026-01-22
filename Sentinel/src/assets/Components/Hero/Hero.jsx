import React from "react";
import { useNavigate } from "react-router-dom";
import "./Hero.css";

function Hero() {
  const navigate = useNavigate();

  return (
    <div className="hero-wrapper">
      <div className="hero-container">
        <div className="h-right">
          <span className="hero-span">Welcome To</span>
          <h1>
            Unlocking The Secret <br /> of Digital <span>Safety</span>
          </h1>
          <p>
            Lorem ipsum dolor sit amet consectetur adipisicing elit. Optio
            voluptatum sapiente harum asperiores cumque inventore totam.
          </p>
          <button onClick={() => navigate("/login")}>Get Started</button>
        </div>

        <div className="h-left">
          <img src="/hero-img.png" alt="error image" />
        </div>
      </div>
    </div>
  );
}

export default Hero;
