import React from 'react'
import './Features.css'
import { Zap, Shield, Users, CheckCircle } from "lucide-react";

function Features() {
  const features = [
    {
      id: 1,
      title: "Fast Performance",
      description: "Experience blazing fast speed and smooth interactions.",
      icon: <Zap size={32} />,
    },
    {
      id: 2,
      title: "Secure by Design",
      description: "Built with top-level security features to keep data safe.",
      icon: <Shield size={32} />,
    },
    {
      id: 3,
      title: "Easy Collaboration",
      description: "Work together with your team in real time.",
      icon: <Users size={32} />,
    },
    {
      id: 4,
      title: "Trusted Quality",
      description: "Backed by 1000+ happy customers worldwide.",
      icon: <CheckCircle size={32} />,
    },
  ];

  return (
    <section className="features">
      <h2>Our Features</h2>
      <div className="feature-grid">
        {features.map((feature) => (
          <div key={feature.id} className="feature-card">
            <div className="icon">{feature.icon}</div>
            <h3>{feature.title}</h3>
            <p>{feature.description}</p>
          </div>
        ))}
      </div>
    </section>
  )
}

export default Features
