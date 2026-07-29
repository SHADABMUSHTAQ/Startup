import React, { useEffect, useMemo, useState } from "react";
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
import { calculatePricingEstimate, formatPkr } from "../../../utils/pricing";
import "./RequestQuote.css";

const defaultQuote = {
  plan: "WarSOC Deployment",
  cycle: "monthly",
  customization: {
    endpoints: 10,
    retentionMonths: 3,
  },
  addons: {
    fbr: false,
    peca: false,
  },
};

export default function RequestQuote() {
  const navigate = useNavigate();
  const location = useLocation();
  const quote = useMemo(() => ({
    ...defaultQuote,
    ...(location.state || {}),
    plan: "WarSOC Deployment",
    customization: {
      ...defaultQuote.customization,
      ...(location.state?.customization || {}),
    },
    addons: {
      ...defaultQuote.addons,
      ...(location.state?.addons || {}),
    },
  }), [location.state]);
  const [catalog, setCatalog] = useState(location.state?.catalog || null);
  const [pricingError, setPricingError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [status, setStatus] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    if (catalog) return undefined;

    let active = true;
    apiClient.get("/sales/pricing")
      .then(({ data }) => {
        if (active) setCatalog(data);
      })
      .catch((error) => {
        if (active) {
          setPricingError(formatApiError(error, "Pricing is temporarily unavailable."));
        }
      });

    return () => { active = false; };
  }, [catalog]);

  const estimate = useMemo(
    () => calculatePricingEstimate(catalog, {
      endpoints: quote.customization.endpoints,
      addons: quote.addons,
      cycle: quote.cycle,
    }),
    [catalog, quote],
  );

  const quoteSummary = useMemo(() => {
    const addons = [];
    if (quote.addons?.fbr) addons.push("FBR POS Integrity Shield");
    if (quote.addons?.peca) addons.push("PECA Evidence Vault");

    return [
      `Plan: ${quote.plan}`,
      `Billing cycle: ${quote.cycle}`,
      `Endpoints: ${quote.customization?.endpoints || 10}`,
      `General archive: ${quote.customization?.retentionMonths || 3} months (included)`,
      `Add-ons: ${addons.length ? addons.join(", ") : "None"}`,
      estimate ? `Recurring estimate: ${formatPkr(estimate.recurringTotal)}` : "",
    ].join("\n");
  }, [estimate, quote]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setIsSubmitting(true);
    setStatus(null);
    setErrorMessage("");

    const formData = new FormData(event.currentTarget);
    const compliancePacks = [];
    if (quote.addons?.fbr) compliancePacks.push("fbr_pos");
    if (quote.addons?.peca) compliancePacks.push("peca_forensic");
    const endpoints = Math.min(50, Math.max(10, Number(quote.customization?.endpoints) || 10));
    const retentionMonths = Number(quote.customization?.retentionMonths) || 3;

    if (!catalog || !estimate) {
      setStatus("error");
      setErrorMessage("Pricing is temporarily unavailable. Refresh the page and try again.");
      setIsSubmitting(false);
      return;
    }

    try {
      await apiClient.post("/sales/request-quote", {
        contact_name: String(formData.get("name") || "").trim(),
        contact_email: String(formData.get("email") || "").trim(),
        contact_phone: String(formData.get("phone") || "").trim() || null,
        company_name: String(formData.get("company") || "").trim(),
        plan_type: quote.plan || "WarSOC Deployment",
        endpoints,
        compliance_packs: compliancePacks,
        billing_cycle: quote.cycle === "yearly" ? "yearly" : "monthly",
        pricing_version: catalog.version,
        customization: {
          endpoints,
          retentionMonths,
        },
      });

      setStatus("success");
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
          <span className="quote-badge">Manual Invoice</span>
        </div>

        <header className="quote-header">
          <h1>Request Your WarSOC Quote</h1>
          <p>Review the public list-price estimate and provide your contact details. No online payment is collected.</p>
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
              <div><dt>General Cold Archive</dt><dd>{quote.customization?.retentionMonths || 3} Months Included</dd></div>
              {quote.addons?.fbr && <div><dt>FBR POS Shield</dt><dd>{catalog ? `${formatPkr(catalog.compliance_pack_monthly_prices?.fbr_pos)}/mo` : "Loading"}</dd></div>}
              {quote.addons?.peca && <div><dt>PECA Vault</dt><dd>{catalog ? `${formatPkr(catalog.compliance_pack_monthly_prices?.peca_forensic)}/mo` : "Loading"}</dd></div>}
            </dl>

            <div className="quote-total">
              <span>{quote.cycle === "yearly" ? "Annual Recurring" : "Monthly Recurring"}</span>
              <strong>{estimate ? formatPkr(estimate.recurringTotal) : "Loading"}</strong>
            </div>
            <div className="quote-cost-notes">
              <span>One-time setup: {estimate ? formatPkr(estimate.setupFee) : "-"}</span>
              <span>Estimated first invoice: {estimate ? formatPkr(estimate.firstInvoice) : "-"}</span>
              <span>Taxes are additional where applicable.</span>
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
                <p>Your requested scope is stored securely for the WarSOC sales team.</p>
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

                {pricingError && status !== "error" && (
                  <div className="quote-error">
                    <XCircle size={16} /> {pricingError}
                  </div>
                )}

                <button type="submit" className="quote-submit" disabled={isSubmitting || !catalog || !estimate}>
                  {isSubmitting ? "Sending Request..." : "Request Quote"}
                  {!isSubmitting && <Send size={16} />}
                </button>
                <p>No payment is collected online. WarSOC issues the final manual invoice after confirming the deployment scope.</p>
              </form>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
