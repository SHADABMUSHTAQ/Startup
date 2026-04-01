import React, { useState } from 'react'; 
import { Cloud, Globe, Verified, CalendarDays, Signature, Mail, MapPin, ArrowRight } from 'lucide-react'; 
import './Partners.css';

const partnersList = [
  {
    id: 1,
    name: "BranDive Media Solutions",
    tier: "Strategic Collaboration",
    badgeClass: "badge-platinum",
    icon: Cloud,
    companyLogo: "/brandive_recommendation.png", 
    snippet: "Partnering to deliver enterprise-grade monitoring and compliance automation tailored for SMBs.", // 🚀 New: Card Summary
    
    // 📄 REAL DIGITIZED CONTENT (From PDF)
    lor_header: {
        date: "March 4, 2026",
        address: "Pennsylvania, USA",
        contact: "coo@brandivemedsols.com | Brandivemedsols.com"
    },
    lor_to: "Mr. Hamza Alam\nFounder - WarSOC\nKarachi, Pakistan",
    lor_subject: "Subject: Letter of Intent for Strategic Collaboration",
    lor_body: [
        { type: "p", text: "Dear Mr. Hamza Alam," },
        { type: "p", text: "On behalf of BranDive Media Solutions, we are pleased to express our formal interest in exploring a strategic collaboration with WarSOC." },
        { type: "p", text: "We recognize WarSOC as an emerging and innovative cybersecurity initiative delivering enterprise-grade monitoring and modular compliance automation tailored for SMBs and IT exporters. Your privacy-first architecture, hybrid edge-cloud design, and commitment to automated audit-readiness align strongly with our mission to maintain the highest standards of digital security and data integrity." },
        { type: "p", text: "Through this collaboration, both organizations aim to leverage WarSOC's technical framework to strengthen cybersecurity governance and streamline regulatory compliance workflows." },
        { type: "p", text: "The potential areas of collaboration include:" },
        { type: "li", text: "Pilot Implementation: Deploying WarSOC's Edge-Cloud SIEM for real-time network monitoring." },
        { type: "li", text: "Compliance Automation: Testing automated evidence generation for ISO 27001 and PDPB 2025 standards." },
        { type: "li", text: "Data Sovereignty: Validating localized log filtering to ensure raw data privacy and ethical monitoring." },
        { type: "li", text: "Reporting Refinement: Collaborative optimization of \"Audit-Ready\" dashboards for international digital agencies." },
        { type: "p", text: "This Letter of Intent represents our mutual interest in building a professional partnership. The specific terms, responsibilities, and operational details of this collaboration can be further discussed and formalized through a separate agreement." },
        { type: "p", text: "We look forward to discussing this collaboration further and exploring the possibilities ahead." }
    ],
    lor_signatory: {
        closing: "SINCERELY,",
        name: "Muhammad Haris",
        title: "Chief Operating Officer (COO)"
    }
  },
  {
    id: 2,
    name: "IoT Solutions",
    tier: "Ecosystem Partner",
    badgeClass: "badge-integration",
    icon: Globe,
    companyLogo: "/iot_logo.png",
    snippet: "Collaborating to secure edge devices and IoT infrastructure with zero-trust architecture.", // 🚀 New: Card Summary
    lor_subject: "PENDING VERIFICATION",
    lor_body: [{type: "p", text: "Awaiting Digitized Letter of Recommendation for IoT Solutions ecosystem verification."}],
    lor_signatory: { closing: "", name: "", title: ""}
  }
];

export default function Partners() {
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedPartnerLOR, setSelectedPartnerLOR] = useState(null);

  const openModal = (partnerData) => {
    setSelectedPartnerLOR(partnerData);
    setModalOpen(true);
    document.body.style.overflow = 'hidden'; 
  };

  const closeModal = () => {
    setModalOpen(false);
    setSelectedPartnerLOR(null);
    document.body.style.overflow = 'unset'; 
  };

  return (
    <section className="partners-section" id="partners">
      <div className="partners-header">
        <h2 className="gradient-text">Trust Verified: Partner Ecosystem</h2>
        <p>WarSOC is validated and recommended by industry-leading infrastructure partners. Explore our verified credentials and collaborations.</p>
      </div>

      <div className="partners-grid-enterprise"> 
        {partnersList.map((partner) => {
          const IconComponent = partner.icon;
          return (
            <div 
                key={partner.id} 
                className="enterprise-card"
                onClick={() => openModal(partner)} 
            >
              <div className="card-glow-effect"></div>
              
              <div className="card-top-section">
                  <div className="enterprise-icon-wrapper">
                    <IconComponent size={28} strokeWidth={1.5} />
                  </div>
                  <span className={`enterprise-badge ${partner.badgeClass}`}>{partner.tier}</span>
              </div>

              <div className="card-mid-section">
                  <h4>{partner.name}</h4>
                  <p className="card-snippet">{partner.snippet}</p>
              </div>

              <div className="card-bottom-section">
                  <span className="verify-link">
                      Verify Credential <ArrowRight size={16} className="arrow-icon"/>
                  </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* ==========================================================
          🚀 Modal (Kept your perfected logic & layout)
          ========================================================== */}
      {modalOpen && selectedPartnerLOR && (
        <div className="modal-overlay" onClick={closeModal}> 
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            
            <button className="modal-close-button" onClick={closeModal} title="Close">
                ✕
            </button>
            
            <div className="modal-lor-container">
                <div className="lor-context-sidebar">
                    <img 
                        src={selectedPartnerLOR.companyLogo} 
                        alt={selectedPartnerLOR.name} 
                        className="lor-partner-logo" 
                        onError={(e) => { 
                            e.target.onerror = null; 
                            e.target.src = `https://ui-avatars.com/api/?name=${selectedPartnerLOR.name}&background=0D8ABC&color=fff&size=128&rounded=true&font-size=0.4`; 
                        }} 
                    />
                    <h4>{selectedPartnerLOR.name}</h4>
                    
                    <div className="verification-badge">
                        <Verified size={18} className="verified-icon" />
                        <span>Verified Credential</span>
                    </div>
                    
                    {selectedPartnerLOR.lor_header && (
                        <>
                        <div className="lor-metadata"><CalendarDays size={16} /><span>Issued: {selectedPartnerLOR.lor_header.date}</span></div>
                        <div className="lor-metadata"><MapPin size={16} /><span>{selectedPartnerLOR.lor_header.address}</span></div>
                        <div className="lor-metadata"><Mail size={16} /><span>{selectedPartnerLOR.lor_header.contact}</span></div>
                        </>
                    )}
                </div>
                
                <div className="lor-letter-body">
                    {selectedPartnerLOR.lor_to && (
                        <div className="lor-to-section">
                            <strong>To,</strong><br/>
                            {selectedPartnerLOR.lor_to.split('\n').map((line, i) => <span key={i}>{line}<br/></span>)}
                        </div>
                    )}
                    
                    <h3 className="lor-subject-line">{selectedPartnerLOR.lor_subject}</h3>
                    
                    <div className="lor-paragraphs">
                        {selectedPartnerLOR.lor_body.map((item, index) => (
                            item.type === "p" ? 
                                <p key={index}>{item.text}</p> : 
                                <li key={index} className="lor-bullet">{item.text}</li>
                        ))}
                    </div>
                    
                    <div className="lor-signature-section">
                        <p className="lor-closing">{selectedPartnerLOR.lor_signatory.closing}</p>
                        <div className="signature-area">
                            <Signature size={48} className="signature-icon" />
                        </div>
                        <p className="signatory-name">{selectedPartnerLOR.lor_signatory.name}</p>
                        <p className="signatory-title">{selectedPartnerLOR.lor_signatory.title}</p>
                    </div>
                </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}