import React, { useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  BriefcaseBusiness,
  Building2,
  CheckCircle,
  Mail,
  Phone,
  Send,
  User,
  XCircle,
} from "lucide-react";
import apiClient from "../../../api/apiClient";
import { formatApiError } from "../../../utils/apiError";
import "./RequestQuote.css";

const defaultQuote = {
  plan: "Custom Platform",
  finalPrice: 20000,
  activationFee: 5000,
  cycle: "monthly",
  customization: {
    endpoints: 10,
    storageGB: 5,
    retentionMonths: 0,
  },
  addons: {
    fbr: false,
    peca: false,
  },
};

export default function RequestQuote() {
  const navigate = useNavigate();
  const location = useLocation();
  const quote = location.state || defaultQuote;
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [status, setStatus] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");

  const quoteSummary = useMemo(() => {
    const addons = [];
    if (quote.addons?.fbr) addons.push("FBR POS Integrity Shield");
    if (quote.addons?.peca) addons.push("PECA Evidence Vault");

    return [
      `Plan: ${quote.plan}`,
      `Billing cycle: ${quote.cycle}`,
      `Estimated price: Rs ${Number(quote.finalPrice || 0).toLocaleString()}`,
      `One-time activation fee: Rs ${Number(quote.activationFee || 0).toLocaleString()}`,
      `Endpoints: ${quote.customization?.endpoints || 10}`,
      `Hot storage requirement: ${quote.customization?.storageGB || 5} GB`,
      `Optional general archive: ${quote.customization?.retentionMonths || 0} months`,
      `Add-ons: ${addons.length ? addons.join(", ") : "None"}`,
    ].join("\n");
  }, [quote]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setIsSubmitting(true);
    setStatus(null);
    setErrorMessage("");

    const formData = new FormData(event.currentTarget);
    const compliancePacks = [];
    if (quote.addons?.fbr) compliancePacks.push("fbr_pos");
    if (quote.addons?.peca) compliancePacks.push("peca_forensic");

    try {
      await apiClient.post("/sales/request-quote", {
        contact_name: String(formData.get("name") || "").trim(),
        contact_email: String(formData.get("email") || "").trim(),
        contact_phone: String(formData.get("phone") || "").trim() || null,
        company_name: String(formData.get("company") || "").trim(),
        plan_type: quote.plan || "Custom Platform",
        endpoints: Math.max(10, Number(quote.customization?.endpoints) || 10),
        compliance_packs: compliancePacks,
        billing_cycle: quote.cycle === "yearly" ? "yearly" : "monthly",
        frontend_calculated_total: Number(quote.finalPrice || 0),
      });

      setStatus("success");
      event.currentTarget.reset();
    } catch (error) {
      console.error("Quote request error:", error);
      setStatus("error");
      setErrorMessage(formatApiError(error, "Could not submit the quote request."));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="quote-page">
      <div className="quote-shell">
        <div className="quote-topbar">
          <button type="button" className="quote-back-btn" onClick={() => navigate("/pricing")}>
            <ArrowLeft size={15} /> Back
          </button>
          <span className="quote-badge">Enterprise B2B Quote</span>
        </div>

        <header className="quote-header">
          <h1>Request Custom Quote</h1>
          <p>Provide your contact details. Our deployment engineers will review your architecture and contact you within 24 hours.</p>
        </header>

        <div className="quote-grid">
          <section className="quote-summary-card" aria-label="Architecture summary">
            <div className="quote-card-head">
              <div>
                <span>Architecture Summary</span>
                <h2>{quote.plan}</h2>
              </div>
              <strong>{quote.cycle}</strong>
            </div>

            <dl className="quote-details">
              <div><dt>Base Engine</dt><dd>Included</dd></div>
              <div><dt>Endpoints Monitored</dt><dd>{quote.customization?.endpoints || 10} Devices</dd></div>
              <div><dt>Live Hot Storage</dt><dd>{quote.customization?.storageGB || 5} GB</dd></div>
              {(quote.customization?.retentionMonths || 0) > 0 && (
                <div><dt>General Cold Archive</dt><dd>{quote.customization.retentionMonths} Months</dd></div>
              )}
              {quote.addons?.fbr && <div><dt>FBR POS Shield</dt><dd>Included</dd></div>}
              {quote.addons?.peca && <div><dt>PECA Vault</dt><dd>Included</dd></div>}
            </dl>

            <div className="quote-total">
              <span>Estimated Price</span>
              <strong>Rs {Number(quote.finalPrice || 0).toLocaleString()}</strong>
            </div>
          </section>

          <section className="quote-form-card" aria-label="Contact details">
            <div className="quote-card-head">
              <div>
                <span>Contact Details</span>
                <h2>Where should we send this?</h2>
              </div>
              <BriefcaseBusiness size={20} />
            </div>

            {status === "success" ? (
              <div className="quote-status success">
                <CheckCircle size={42} />
                <h3>Request Received</h3>
                <p>Your request is stored securely and queued for the WarSOC sales team.</p>
                <Link to="/login">Return to Login</Link>
              </div>
            ) : (
              <form className="quote-form" onSubmit={handleSubmit}>
                <input type="hidden" name="quote_summary" value={quoteSummary} />

                <label>
                  <span><Building2 size={13} /> Company Name *</span>
                  <input name="company" type="text" placeholder="e.g. Acme Corp" required />
                </label>
                <label>
                  <span><User size={13} /> Full Name *</span>
                  <input name="name" type="text" placeholder="e.g. Jane Doe" required />
                </label>
                <label>
                  <span><Mail size={13} /> Work Email *</span>
                  <input name="email" type="email" placeholder="jane@acme.com" required />
                </label>
                <label>
                  <span><Phone size={13} /> Direct Phone Number</span>
                  <input name="phone" type="tel" placeholder="+92 300 1234567" />
                </label>

                {status === "error" && (
                  <div className="quote-error">
                    <XCircle size={16} /> {errorMessage}
                  </div>
                )}

                <button type="submit" className="quote-submit" disabled={isSubmitting}>
                  {isSubmitting ? "Sending Request..." : "Request Custom Quote"}
                  {!isSubmitting && <Send size={16} />}
                </button>
                <p>No payment required. Our deployment team will confirm the final scope.</p>
              </form>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
