import { useState } from "react";
import { useNavigate } from "react-router-dom"; // ✅ Import Added
import './Pricing.css';

function Pricing() {
  const [selectedPlan, setSelectedPlan] = useState(null);
  const navigate = useNavigate(); // ✅ Hook Initialize

  const plans = [
    { id: 1, name: "Basic", price: "$9/mo", features: ["1 Project", "Email Support", "Basic Security"] },
    { id: 2, name: "Pro", price: "$29/mo", features: ["10 Projects", "Priority Support", "Advanced Security"] },
    { id: 3, name: "Enterprise", price: "$99/mo", features: ["Unlimited Projects", "24/7 Support", "Enterprise Security"] },
  ];

  // ✅ New Logic: Handle Plan Selection
  const handleChoosePlan = (e, plan) => {
    e.stopPropagation(); // Taaki card select na ho, bas button click ho
    
    const token = localStorage.getItem("token");

    if (!token) {
      // 1. Agar User Login NAHI hai -> Login page par bhejo
      alert("Please login first to subscribe! 🔒");
      navigate("/login");
    } else {
      // 2. Agar User Login HAI -> Payment page par bhejo
      // Hum plan ka naam aur price saath bhej rahe hain
      navigate("/payment", { state: { plan: plan.name, price: plan.price } });
    }
  };

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
            
            {/* ✅ Button Logic Updated */}
            <button 
                className="btn" 
                onClick={(e) => handleChoosePlan(e, plan)}
            >
              {selectedPlan === plan.id ? "Proceed to Pay" : "Choose Plan"}
            </button>

          </div>
        ))}
      </div>
    </section>
  );
}

export default Pricing;