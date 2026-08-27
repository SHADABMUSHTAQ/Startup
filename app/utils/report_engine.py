import io
import html
import os
import re
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from pathlib import Path
import json

from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from app.utils.compliance_chain import verify_ledger_sequence

DEFAULT_REPORTS_DIR = "/app/data/reports"


def _safe_path_segment(value: str) -> str:
    """Reduce untrusted path input to a filesystem-safe segment."""
    segment = os.path.basename(str(value or "")).strip()
    segment = re.sub(r"[^A-Za-z0-9_.-]", "_", segment)
    return segment or "unknown"


def get_reports_base_dir() -> Path:
    configured = os.getenv("REPORTS_DIR")
    if configured:
        return Path(configured)
    if Path("/app").exists():
        return Path(DEFAULT_REPORTS_DIR)
    return Path(__file__).resolve().parents[2] / "data" / "reports"

class ComplianceReportGenerator:
    def __init__(self, tenant_id: str, db):
        self.tenant_id = tenant_id
        self.db = db
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle('TitleStyle', parent=self.styles['Heading1'], alignment=1, fontSize=18, spaceAfter=20, textColor=colors.HexColor("#1e293b"))
        self.header_style = ParagraphStyle('HeaderStyle', parent=self.styles['Heading2'], fontSize=14, spaceAfter=10, textColor=colors.HexColor("#334155"))
        self.body_style = self.styles["BodyText"]
        self.footer_style = ParagraphStyle('FooterStyle', parent=self.styles['Italic'], fontSize=8, alignment=1, textColor=colors.grey)

    async def generate_monthly_report(self, year: int, month: int, report_type: str = "fbr_pos") -> str:
        """
        Generates a monthly compliance report and saves it to disk.
        Returns the filename.
        """
        # Determine date range
        start_date = datetime(year, month, 1, tzinfo=timezone.utc)
        if month == 12:
            end_date = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end_date = datetime(year, month + 1, 1, tzinfo=timezone.utc)

        start_str = start_date.strftime("%Y-%m-%d")
        end_str = end_date.strftime("%Y-%m-%d")

        # Query the ledgers for the month
        cursor = self.db["daily_forensic_ledgers"].find({
            "tenant_id": self.tenant_id,
            "date": {"$gte": start_str, "$lt": end_str}
        }).sort("date", 1)
        ledgers = await cursor.to_list(length=31)
        chain_result = verify_ledger_sequence(ledgers)

        # Get total log count
        total_logs = sum(l.get("log_count", 0) for l in ledgers)
        
        # Build PDF
        safe_tenant_id = _safe_path_segment(self.tenant_id)
        report_dir = get_reports_base_dir() / safe_tenant_id
        report_dir.mkdir(parents=True, exist_ok=True)
        filename = f"warsoc_{report_type}_{year}_{month:02d}.pdf"
        filepath = report_dir / filename

        doc = SimpleDocTemplate(str(filepath), pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        elements = []

        # --- Header & Title ---
        title_text = (
            "WarSOC FBR Evidence Readiness Report"
            if report_type == "fbr_pos"
            else "WarSOC PECA-Oriented Evidence Ledger"
        )
        elements.append(Paragraph(f"<b>{title_text}</b>", self.title_style))
        elements.append(Paragraph(f"<b>Tenant ID:</b> {html.escape(self.tenant_id)}", self.body_style))
        elements.append(Paragraph(f"<b>Period:</b> {start_date.strftime('%B %Y')}", self.body_style))
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", self.body_style))
        elements.append(Paragraph(f"<b>Total Secured Events:</b> {total_logs}", self.body_style))
        elements.append(Paragraph(f"<b>Daily Chain Verification:</b> {chain_result['status']}", self.body_style))
        elements.append(Spacer(1, 0.3 * inch))

        # --- Section 1: Daily evidence integrity chain ---
        elements.append(Paragraph("SECTION 1: DAILY EVIDENCE INTEGRITY CHAIN", self.header_style))
        if chain_result["status"] == "VERIFIED":
            chain_description = (
                "Every listed daily root passed SHA-256 recomputation and continuity checks "
                "for the records present in this report period."
            )
        elif chain_result["status"] == "VERIFIED_WITH_RESET":
            chain_description = (
                "Every listed daily root passed SHA-256 recomputation. The chain includes an "
                "explicit reset from a missing or legacy ledger, so historical continuity before "
                "that reset is not asserted."
            )
        else:
            chain_description = (
                "UNVERIFIED: one or more entries are legacy, malformed, or have a broken "
                "continuity link. This report must not be represented as a verified chain."
            )
        elements.append(Paragraph(chain_description, self.body_style))
        elements.append(Spacer(1, 0.1 * inch))

        ledger_data = [["Date", "Events", "Daily Root Hash (SHA-256)"]]
        for l in ledgers:
            ledger_data.append([
                l.get("date", "Unknown"),
                str(l.get("log_count", 0)),
                l.get("daily_root_hash", "N/A")
            ])

        ledger_table = Table(ledger_data, colWidths=[1.2*inch, 0.8*inch, 4.5*inch])
        ledger_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(ledger_table)
        elements.append(Spacer(1, 0.4 * inch))

        # --- Section 2: Monitored Ruleset (SSOT) ---
        elements.append(Paragraph("SECTION 2: MONITORED RULESET", self.header_style))
        elements.append(Paragraph("The following compliance events are actively monitored and secured in this ledger as per the system's Single Source of Truth (SSOT).", self.body_style))
        elements.append(Spacer(1, 0.1 * inch))

        # Fetch the framework rules from the catalog
        catalog_key = "peca_forensic" if report_type == "peca_forensic" else report_type
        framework_data = COMPLIANCE_CATALOG.get(catalog_key, {})
        rules = framework_data.get("rules", [])

        rule_data = [["Rule ID", "Event ID", "Name", "Severity"]]
        for rule in rules:
            rule_data.append([
                str(rule.get("id", "N/A")),
                str(rule.get("event_id", "N/A")),
                str(rule.get("name", "N/A")),
                str(rule.get("severity", "N/A"))
            ])

        if len(rule_data) > 1:
            rule_table = Table(rule_data, colWidths=[1.2*inch, 0.8*inch, 3.5*inch, 1.0*inch])
            rule_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(rule_table)
        else:
            elements.append(Paragraph("No rules defined for this framework.", self.body_style))

        elements.append(Spacer(1, 0.4 * inch))

        # --- Footer ---
        elements.append(Spacer(1, 0.5 * inch))
        footer_text = (
            "Generated by the WarSOC Compliance Engine. Daily chain status: "
            f"{chain_result['status']}. Individual PECA evidence records may include separate "
            "RSA-PSS signatures. Legal admissibility depends on applicable law, custody, and "
            "independent verification."
        )
        elements.append(Paragraph(footer_text, self.footer_style))

        # Build Document
        doc.build(elements)
        return str(filepath)
