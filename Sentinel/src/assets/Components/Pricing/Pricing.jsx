import { useState } from "react";
import './Pricing.css'

function Pricing() {
  const [selectedPlan, setSelectedPlan] = useState(null);

  const plans = [
    { id: 1, name: "Basic", price: "$9/mo", features: ["1 Project", "Email Support", "Basic Security"] },
    { id: 2, name: "Pro", price: "$29/mo", features: ["10 Projects", "Priority Support", "Advanced Security"] },
    { id: 3, name: "Enterprise", price: "$99/mo", features: ["Unlimited Projects", "24/7 Support", "Enterprise Security"] },
  ];

  return (
    <section className="pricing">
      <h2>Pricing Plans</h2>
      <div className="pricing-cards">
        {plans.map((plan) => (
          <div
            key={plan.id}
            className={`pricing-card ${selectedPlan === plan.id ? "selected" : ""}`}
            onClick={() => setSelectedPlan(plan.id)}
          >
            <h3>{plan.name}</h3>
            <p className="price">{plan.price}</p>
            <ul>
              {plan.features.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
            <button className="btn">
              {selectedPlan === plan.id ? "Selected" : "Choose Plan"}
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}

export default Pricing;
