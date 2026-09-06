import React, { useEffect, useState } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import "./LegalPage.css";

const legalDocuments = {
  privacy: {
    title: "Privacy Policy",
    subtitle: "WarSOC - Compliance-First SOC-as-a-Service",
    effectiveDate: "June 16, 2026",
    lastUpdated: "June 16, 2026",
    version: "1.2",
    intro:
      'Welcome to WarSOC ("we," "us," "our," or "WarSOC"). We are a Pakistan-based Business-to-Business (B2B) cybersecurity Software-as-a-Service (SaaS) platform providing Security Operations Center (SOC) services, compliance monitoring, forensic logging, and managed cybersecurity solutions to small, medium, and enterprise businesses.',
    sections: [
      {
        heading: "1. Introduction",
        paragraphs: [
          "This Privacy Policy explains how we collect, use, store, protect, share, and dispose of information when you access our website (warsoc.pk) or use our services. By accessing our website or using our services, you acknowledge that you have read, understood, and agree to be bound by this Privacy Policy.",
          "This Privacy Policy is designed to comply with:",
        ],
        bullets: [
          "Prevention of Electronic Crimes Act (PECA) 2016",
          "Electronic Transactions Ordinance (ETO) 2002",
          "Income Tax Ordinance 2001 (Section 174(3))",
          "Personal Data Protection Bill (PDPB) 2023 (pending enactment)",
          "State Bank of Pakistan (SBP) BPRD Circular No. 4 of 2020",
          "Pakistan Telecommunication Authority (PTA) CTDISR-2025",
          "Federal Board of Revenue (FBR) regulations including Section 165AB of Finance Bill 2026-27",
        ],
      },
      {
        heading: "2. Information We Collect",
        groups: [
          {
            title: "2.1 Information Collected from Website Visitors",
            items: [
              "IP address (anonymized for analytics purposes)",
              "Browser type, version, and language preferences",
              "Operating system and device information",
              "Pages visited, time spent, and click patterns",
              "Referring website and exit pages",
              "Cookie identifiers",
              "Geographic location (country/city level only)",
            ],
          },
          {
            title: "2.2 Information Collected from Business Customers",
            items: [
              "Company name and business registration details",
              "Business type, industry, and size",
              "Authorized contact person's name, designation, business email, and phone number",
              "National Tax Number (NTN)",
              "Sales Tax Registration Number (STRN)",
              "Computerized National Identity Card (CNIC) details for authorized representatives, used exclusively for NADRA VeriSys institutional verification",
              "Billing address and payment account information",
              "Business banking details for invoice processing",
            ],
          },
          {
            title: "2.3 Operational, Security, and Monitoring Data",
            items: [
              "Network traffic metadata, including source/destination IP addresses, ports, protocols, and session timestamps",
              "DNS query logs",
              "HTTP/HTTPS metadata, including URL paths, methods, and SNI fields, without content",
              "Windows Event Logs",
              "Native Windows Security and System channel event data",
              "Endpoint Detection and Response (EDR) alerts",
              "FBR POS Integrity events, including system tampering attempts, time changes, and audit log clearing",
              "Server, application, and user authentication logs",
            ],
          },
          {
            title: "2.4 Information We Do Not Collect",
            items: [
              "Email content, chat, SMS, or phone call recordings",
              "Financial payload data, including sales amounts, item-wise descriptions, GST calculations, and IRNs",
              "Credit card or payment card data, including PAN and CVV",
              "Customer-of-customer Personally Identifiable Information (PII) beyond operational necessity",
              "Telecom-grade subscriber data, including tower locations, SIM details, and CDR records",
              "Personal browsing history outside the corporate network scope",
            ],
          },
        ],
      },
      {
        heading: "3. How We Use Your Information",
        paragraphs: [
          "We use collected information to provide SOC monitoring, generate compliance reports (PECA, FBR, ETO), manage accounts and manual billing, improve platform performance, and comply with Pakistani legal and regulatory obligations.",
        ],
      },
      {
        heading: "4. Data Storage, Retention, and Sovereignty",
        groups: [
          {
            title: "4.1 Tiered Storage Architecture",
            intro:
              "WarSOC operates a hybrid, tiered storage architecture optimized for performance, cost-efficiency, and compliance:",
            items: [
              "Hot Storage: A bounded operational window supports dashboards, investigation, and detection.",
              "Cold Archive: Encrypted Azure object storage preserves evidence for the customer's selected WarSOC retention entitlement.",
              "Legal Hold: An authorized hold can preserve selected evidence beyond its normal entitlement while the hold remains active.",
            ],
          },
          {
            title: "4.2 Retention Responsibility",
            items: [
              "WarSOC applies the retention entitlement recorded for the customer's tenant to security, PECA, and FBR monitoring evidence.",
              "WarSOC FBR functionality monitors POS and invoice integrity; it is not the customer's statutory tax-record repository.",
              "Customers remain responsible for selecting retention appropriate to their contracts, legal obligations, and regulatory advice.",
            ],
          },
          {
            title: "4.3 Data Sovereignty (Pilot Phase Disclosure)",
            intro:
              "WarSOC may process and archive customer evidence in the cloud regions identified in the applicable service agreement. Access controls, encryption, tenant isolation, and retention settings remain part of the service's technical safeguards.",
          },
        ],
      },
      {
        heading: "5. Sharing and Disclosure of Information",
        paragraphs: [
          "WarSOC does not sell or rent your information. We share information only in limited circumstances:",
        ],
        groups: [
          {
            title: "5.1 Service Providers and Partners (Sub-processors)",
            intro:
              "Infrastructure providers process data as described in the applicable service agreement. Current platform providers include:",
            items: [
              "Oracle Cloud Infrastructure - Backend hosting",
              "Azure (Microsoft) - Evidence archives and release artifacts",
              "Vercel - Frontend hosting",
            ],
          },
          {
            title: "5.2 Legal Compliance",
            intro:
              "We may disclose data when legally compelled by valid court orders, FIA, FBR, SBP, or PTA directives. We will notify affected clients within 24 hours of receiving such requests unless legally prohibited.",
          },
        ],
      },
      {
        heading: "6. Your Rights and Choices",
        paragraphs: [
          "You have the right to access, correct, delete, port, restrict, or object to the processing of your data, subject to legal retention obligations. To exercise these rights, email privacy@warsoc.pk.",
        ],
      },
      {
        heading: "7. Data Security Measures",
        paragraphs: [
          "We implement AES-256 encryption at rest, TLS 1.3 in transit, MFA, RBAC, and cryptographically signed audit logs (ETO 2002 compliant). In the event of a confirmed breach, we will notify affected clients within 72 hours.",
        ],
      },
      {
        heading: "8. Compliance Boundary Statement",
        paragraphs: [
          "WarSOC explicitly does not process or transmit real-time FBR POS API sales transactions, financial accounting data, tax calculations, or banking transaction details.",
        ],
      },
      {
        heading: "9. Contact Information",
        contact: [
          "Privacy Inquiries: ceo@warsoc.tech",
          "Legal Matters: ceo@warsoc.tech",
          "Business Hours: Monday - Friday, 9:00 AM to 6:00 PM (PKT)",
        ],
      },
    ],
  },
  terms: {
    title: "Terms of Service",
    subtitle: "WarSOC - Compliance-First SOC-as-a-Service",
    effectiveDate: "June 16, 2026",
    lastUpdated: "June 16, 2026",
    version: "1.2",
    intro:
      'WarSOC provides a unified B2B cybersecurity and compliance platform. This section serves as a high-level summary of our legal commitments to you. Please note that while this summary provides clarity, the complete Terms of Service, Privacy Policy, and Data Processing Agreement (DPA) constitute the final binding legal contract between WarSOC and the Client. By accessing our services, you agree to these terms in their entirety. ',
    sections: [
      {
        heading: "1. Acceptance of Terms",
        paragraphs: [
          'By accessing, browsing, registering for, or using WarSOC\'s website, services, dashboards, or APIs (collectively, the "Services"), you agree to be legally bound by these Terms of Service. These Terms constitute a binding legal contract governed by the laws of Pakistan.',
        ],
      },
      {
        heading: "2. Description of Services",
        paragraphs: [
          "WarSOC provides B2B cybersecurity services including SOC monitoring, EDR, FBR POS Integrity Shielding, PECA Evidence Vault logging, and compliance reporting. WarSOC does not provide financial accounting, POS sales reporting, tax calculation, or banking transaction processing.",
        ],
      },
      {
        heading: "3. Account Registration and Eligibility",
        groups: [
          {
            title: "3.1 Eligibility Requirements",
            intro:
              "To use WarSOC services, you must be a legally registered business entity in Pakistan, provide valid NTN/STRN, and successfully complete NADRA VeriSys institutional verification, typically 3-10 business days based on processing times and documentation requirements.",
          },
        ],
      },
      {
        heading: "4. Subscription, Pricing, and Payment",
        groups: [
          {
            title: "4.1 Unified Subscription Model",
            intro:
              'WarSOC operates on a customized, usage-based subscription model. To ensure complete legal and cryptographic protection, WarSOC is delivered strictly as a "Unified Compliance Vault" bundling FBR POS Integrity Monitoring and PECA Evidence Logging. Specific pricing, onboarding fees, and storage limits will be exclusively detailed in the Client\'s Master Service Agreement (MSA).',
          },
          {
            title: "4.2 Invoicing and Late Payments",
            intro:
              "WarSOC operates on manual invoicing via bank transfer. Invoices include applicable Sindh Sales Tax (SST). Payments are due within 7 days. Late payments may incur a 2% monthly surcharge and result in service suspension.",
          },
          {
            title: "4.7 Refund Policy",
            items: [
              "Annual prepayments: Pro-rated refund minus a 25% cancellation fee.",
              "Monthly subscriptions: No refund for partial months.",
              "Service failure refunds: Issued strictly as service credits per our SLA.",
              "Pilot Program: No refund applicable (free service).",
            ],
          },
        ],
      },
      {
        heading: "5. Pilot Program Terms",
        groups: [
          {
            title: "5.1 Pilot Offering and Limitations",
            intro:
              "WarSOC offers a 30-day free pilot for up to 5 endpoints. The pilot does not include the full PECA Evidence Vault (long-term court-admissible export) or Advanced SOAR capabilities.",
          },
          {
            title: "5.4 Pilot Liability Cap",
            intro:
              'During the free pilot, WarSOC\'s total aggregate liability shall not exceed PKR 50,000 or the maximum extent permitted by Pakistani law, whichever is lower. The pilot is provided "as-is" without express or implied warranties.',
          },
        ],
      },
      {
        heading: "6. Client Responsibilities",
        paragraphs: [
          "Client agrees to use Services lawfully, maintain client-side infrastructure security, cooperate during incident response, and make timely payments.",
        ],
      },
      {
        heading: "7. Service Level Agreement (SLA) & Infrastructure",
        groups: [
          {
            title: "7.1 Uptime & Support ",
            items: [
              "Uptime: 99.5% monthly guarantee for dashboard and threat detection. • Support Response: We prioritize issues based on impact, ranging from 1 hour (Critical) to 24 hours (Low).  ",
            ],
          },
          {
            title: "7.2 Backend Architecture",
            items: [
              "Our platform uses authenticated ingestion, durable queues, separate SIEM/PECA/FBR processing, tenant-scoped persistence, and archive-before-delete safeguards. The production API runs on Oracle Cloud Infrastructure, while eligible evidence is archived to encrypted Azure storage according to the tenant retention entitlement.",
            ],
          },
          {
            title: "7.3 Disaster Recovery ",
            items: [
              "Backup retention, recovery objectives, processing regions, and data-location commitments are defined by the applicable customer agreement and the accepted production runbook.",
            ],
          },
        ],
      },
      {
        heading: "8. Data Ownership and Compliance Boundaries",
        groups: [
          {
            title: "8.3 Unified Vault Mandate & Unbundling Disclaimer",
            intro:
              "Client expressly acknowledges that WarSOC delivers features exclusively through a continuous Unified Compliance Vault. FBR POS Integrity Monitoring and PECA Forensic Evidence Logging cannot be technically or legally unbundled. If the Client requests to bypass or unbundle any module, the forensic integrity chain is broken. In such events, WarSOC shall be technically unable to provide court-admissible evidence, and Client assumes 100% full legal and financial responsibility for any subsequent breaches, audits, or FBR anomalies.",
          },
        ],
      },
      {
        heading: "9. Intellectual Property & Confidentiality",
        paragraphs: [
          "All proprietary technology remains WarSOC's property. Both parties agree to maintain strict confidentiality of proprietary information for the duration of the Terms and 5 years thereafter.",
        ],
      },
      {
        heading: "10. Limitation of Liability & Indemnification",
        paragraphs: [
          "To the maximum extent permitted by Pakistani law, WarSOC's total aggregate liability shall not exceed the total fees paid by Client in the preceding 12 months. Client agrees to indemnify WarSOC against claims arising from Client's misuse, legal non-compliance, or tampered configurations.",
        ],
      },
      {
        heading: "11. Force Majeure",
        paragraphs: [
          "Neither party is liable for delays caused by events beyond reasonable control, including natural disasters, public health emergencies, telecommunications outages, or third-party cyber attacks.",
        ],
      },
      {
        heading: "12. Governing Law and Dispute Resolution",
        groups: [
          {
            title: "12.3 Dispute Resolution Process",
            intro: "Before initiating litigation, parties agree to attempt resolution through:",
            items: [
              "Step 1: Good-faith negotiation between authorized representatives (30 days).",
              "Step 2: Binding Arbitration in Karachi under the Arbitration Act, 1940 (60 days).",
              "Step 3: Litigation in the courts of Karachi only if arbitration fails or for injunctive relief.",
            ],
          },
        ],
      },
      {
        heading: "13. Contact Information",
        paragraphs: ["For support, legal, or general inquiries, please contact us at:"],
        contact: [
          "Email: ceo@warsoc.tech",
          "Business Hours: Monday - Friday, 9:00 AM to 6:00 PM (PKT)",
        ],
      },
    ],
    closing:
      "By using WarSOC services, you acknowledge that you have read, understood, and agree to be bound by these Terms of Service and the Privacy Policy.",
  },
};

const SectionContent = ({ section }) => (
  <div className="legal-section-copy">

    {section.paragraphs?.map((paragraph) => (
      <p key={paragraph}>{paragraph}</p>
    ))}

    {section.bullets && (
      <ul>
        {section.bullets.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    )}

    {section.groups?.map((group) => (
      <div className="legal-subsection" key={group.title}>
        <h3>{group.title}</h3>
        {group.intro && <p>{group.intro}</p>}
        {group.items && (
          <ul>
            {group.items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </div>
    ))}

    {section.contact && (
      <div className="legal-contact-box">
        {section.contact.map((item) => (
          <p key={item}>{item}</p>
        ))}
      </div>
    )}
  </div>
);

const getSectionId = (heading) =>
  heading
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

const LegalTitle = ({ title }) => {
  const words = title.split(" ");
  const accent = words.pop();

  return (
    <>
      {words.join(" ")} <span>{accent}</span>
    </>
  );
};

const LegalPage = ({ type: routeType }) => {
  const { type: paramType } = useParams();
  const type = routeType || paramType;
  const legalDocument = legalDocuments[type];
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");

  useEffect(() => {
    window.document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    const syncTheme = () => setTheme(localStorage.getItem("theme") || "dark");
    window.addEventListener("storage", syncTheme);
    window.addEventListener("focus", syncTheme);
    return () => {
      window.removeEventListener("storage", syncTheme);
      window.removeEventListener("focus", syncTheme);
    };
  }, []);

  if (!legalDocument) {
    return <Navigate to="/" replace />;
  }

  return (
    <main className={`legal-page legal-${theme}`}>
      <header className="legal-topbar">
        <Link to="/" className="legal-back-link">
          <ArrowLeft size={17} />
          Back to WarSOC
        </Link>
      </header>

      <nav className="legal-tabs" aria-label="Legal documents">
        <Link className={type === "privacy" ? "active" : ""} to="/privacy">
          Privacy Policy
        </Link>
        <Link className={type === "terms" ? "active" : ""} to="/terms">
          Terms of Service
        </Link>
      </nav>

      <section className="legal-hero">
        <div className="legal-hero-inner">
          <h1>
            <LegalTitle title={legalDocument.title} />
          </h1>
          <p>{legalDocument.subtitle}</p>

          <dl className="legal-meta-grid">
            <div>
              <dt>Effective Date</dt>
              <dd>{legalDocument.effectiveDate}</dd>
            </div>
            <div>
              <dt>Last Updated</dt>
              <dd>{legalDocument.lastUpdated}</dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{legalDocument.version}</dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="legal-document-wrap">
        <aside className="legal-sidebar" aria-label={`${legalDocument.title} sections`}>
          <p>On this page</p>
          <a href="#overview">Overview</a>
          {legalDocument.sections.map((section) => (
            <a href={`#${getSectionId(section.heading)}`} key={section.heading}>
              {section.heading.replace(/^\d+\.\s*/, "")}
            </a>
          ))}
        </aside>

        <article className="legal-document">
          <div className="legal-lead" id="overview">
            <p>{legalDocument.intro}</p>
          </div>

          {legalDocument.sections.map((section) => (
            <section className="legal-section-row" id={getSectionId(section.heading)} key={section.heading}>
              <h2>{section.heading}</h2>
              <SectionContent section={section} />
            </section>
          ))}

          {legalDocument.closing && <p className="legal-closing">{legalDocument.closing}</p>}

          <footer className="legal-document-footer">
            <span>© 2026 WarSOC. All Rights Reserved.</span>
          </footer>
        </article>
      </section>
    </main>
  );
};

export default LegalPage;
