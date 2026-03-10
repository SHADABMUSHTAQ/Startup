import React, { useState } from 'react';
import { ShieldAlert, Headset, MapPin, Send, Building2, CheckCircle } from 'lucide-react';
import './Contact.css';

const Contact = () => {
  // Form submission state handle karne ke liye
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    // Form data collect karna
    const formData = new FormData(e.target);
    
    // 👇 Yahan aap apni Web3Forms ki Access Key dalenge
    // Get free key from: https://web3forms.com/
    formData.append("access_key", "aeceb9ba-bc21-4915-835a-2b96714b7337"); 

    try {
      const response = await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        body: formData
      });

      const data = await response.json();

      if (data.success) {
        setIsSubmitted(true); // Success state show karega
      } else {
        alert("Something went wrong. Please try again.");
      }
    } catch (error) {
      console.error("Error submitting form:", error);
      alert("Network error. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="contact-section" id="contact">
      <div className="contact-glow"></div>

      <div className="contact-container">
        {/* Left Side - SIEM Info */}
        <div className="contact-info">
          <span className="section-badge">Talk to Experts</span>
          <h2>
            Secure Your <span className="highlight-text">Infrastructure</span> Today
          </h2>
          <p className="contact-description">
            Whether you need a full platform demo, compliance consultation (PCI-DSS, GDPR), or emergency incident response, the WarSOC team is on standby.
          </p>

          <div className="contact-details">
            <div className="contact-item">
              <div className="icon-box">
                <Headset size={20} />
              </div>
              <div>
                <h4>Sales & Demo</h4>
                <p>Warosc1@outlook.com</p>
              </div>
            </div>
            <div className="contact-item">
              <div className="icon-box alert-box">
                <ShieldAlert size={20} />
              </div>
              <div>
                <h4>24/7 SOC Emergency</h4>
                <p>+92 335 3782134 (Priority Support)</p>
              </div>
            </div>
            <div className="contact-item">
              <div className="icon-box">
                <MapPin size={20} />
              </div>
              <div>
                <h4>Location</h4>
                <p>National Incubation Centre, Karachi</p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Side - B2B Lead Form */}
        <div className="contact-form-wrapper">
          
          {/* Agar form submit ho gaya hai to Success Message dikhaye */}
          {isSubmitted ? (
            <div className="success-message" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
              <CheckCircle size={50} color="#64ffda" style={{ marginBottom: '1rem' }} />
              <h3 style={{ color: '#e6f1ff', fontSize: '1.5rem', marginBottom: '0.5rem' }}>Request Received!</h3>
              <p style={{ color: '#8892b0' }}>Thank you for reaching out. Our security team will contact you shortly.</p>
              <button 
                onClick={() => setIsSubmitted(false)} 
                className="submit-btn" 
                style={{ marginTop: '2rem', width: 'auto' }}
              >
                Send Another Request
              </button>
            </div>
          ) : (
            // Warna normal form dikhaye
            <form className="contact-form" onSubmit={handleSubmit}>
              <h3>Request a Demo / Contact Sales</h3>
              
              <div className="form-row">
                <div className="form-group half-width">
                  <label htmlFor="name">Full Name</label>
                  <input type="text" id="name" name="name" placeholder="John Doe" required />
                </div>
                <div className="form-group half-width">
                  <label htmlFor="company">Company Name</label>
                  <div className="input-with-icon">
                    <Building2 size={16} className="input-icon" />
                    <input type="text" id="company" name="company" placeholder="Acme Corp" style={{paddingLeft: '32px'}} required />
                  </div>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="email">Work Email</label>
                <input type="email" id="email" name="email" placeholder="john@company.com" required />
              </div>

              <div className="form-group">
                <label htmlFor="inquiryType">How can we help you?</label>
                <select id="inquiryType" name="inquiryType" required>
                  <option value="" disabled selected>Select an option...</option>
                  <option value="demo">Request a Platform Demo</option>
                  <option value="compliance">Compliance Audit & Setup</option>
                  <option value="incident">Emergency Incident Response</option>
                  <option value="partnership">MSSP / Partnership Inquiry</option>
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="message">Additional Details</label>
                <textarea id="message" name="message" rows="3" placeholder="Tell us about your infrastructure size and specific security needs..." required></textarea>
              </div>
              
              <button type="submit" className="submit-btn" disabled={isSubmitting}>
                {isSubmitting ? "Sending..." : "Submit Request"} 
                {!isSubmitting && <Send size={16} style={{ marginLeft: '8px' }} />}
              </button>
              <p className="privacy-note">Your data is secured with AES-256 encryption.</p>
            </form>
          )}
        </div>
      </div>
    </section>
  );
};

export default Contact;