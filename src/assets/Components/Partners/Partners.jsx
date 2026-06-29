import React from "react";
import "./Partners.css";

// 🚀 CLEAN DATA: Sirf logo aur naam chahiye ticker ke liye. Baqi kachra saaf.
const partnersList = [
  {
    id: 1,
    name: "BranDive Media Solutions",
    companyLogo: "/brandive_recommendation.png",
  },
  {
    id: 2,
    name: "IoT Solutions",
    companyLogo: "public/iotsol_logo.jpeg",
  },
  {
    id: 3,
    name: "CyberZeus Software", // Add more companies like this
    companyLogo: "public/cyberzeus_software_systems_logo.jpeg",
  }
];

export default function Partners() {
  return (
    <section className="partners-section" id="partners">
      <div className="partners-header">
        <h2 className="gradient-text">Trust Verified: Partner Ecosystem</h2>
        <p>
          WarSOC is validated and recommended by industry-leading infrastructure
          and compliance partners.
        </p>
      </div>

      {/* 🚀 INFINITE MARQUEE WRAPPER */}
      <div className="marquee-wrapper">
        <div className="marquee-track">
          {/* Hum list ko 3 dafa render kar rahe hain taake animation seamless (infinite) lagay */}
          {[...partnersList, ...partnersList, ...partnersList].map((partner, idx) => (
            <div key={idx} className="marquee-item">
              <img
                src={partner.companyLogo}
                alt={partner.name}
                className="partner-logo"
                onError={(e) => {
                  e.target.onerror = null;
                  // Fallback: Agar logo image na mile toh UI break nahi hoga
                  e.target.src = `https://ui-avatars.com/api/?name=${partner.name}&background=0f172a&color=fff&size=128&rounded=true`;
                }}
              />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}