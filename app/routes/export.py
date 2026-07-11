import csv
import io
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone
from typing import Any, Optional
from cryptography.fernet import Fernet
from app.database import get_db
from app.routes.auth import require_premium_plan
from app.config.config import get_settings
from app.utils.compliance_catalog import COMPLIANCE_CATALOG
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import json
import re
from pathlib import Path
from app.utils.report_engine import get_reports_base_dir
from app.utils.archive_reader import fetch_archived_documents

def _load_runtime_config() -> dict:
    config_path = Path(__file__).resolve().parent.parent / "config" / "config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

_RUNTIME_CONFIG = _load_runtime_config()

from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List

router = APIRouter()

_settings = get_settings()
try:
    _fernet = Fernet(_settings.encryption_key.encode()) if _settings.encryption_key else None
except Exception:
    _fernet = None

_SENSITIVE_COMPLIANCE_FIELDS = (
    "message",
    "raw_event",
    "raw_event_data",
    "raw_data",
    "processed_data",
)


_PACK_ALIASES = {
    "peca": "peca_forensic",
    "peca_forensic": "peca_forensic",
    "peca_vault": "peca_forensic",
    "eto": "peca_forensic",
    "eto_forensic": "peca_forensic",
    "fbr": "fbr_pos",
    "fbr_pos": "fbr_pos",
    "fbr_pos_shield": "fbr_pos",
}


def _normalize_pack_id(pack_id: str | None) -> str:
    key = str(pack_id or "").strip().lower()
    if key not in _PACK_ALIASES:
        raise HTTPException(status_code=404, detail="Compliance pack not found")
    return _PACK_ALIASES[key]


def _get_entitled_packs(current_user: dict) -> set[str]:
    packs_raw = current_user.get("compliance_packs", [])
    if not isinstance(packs_raw, list):
        return set()

    entitled = set()
    for pack in packs_raw:
        key = str(pack or "").strip().lower()
        if key in _PACK_ALIASES:
            entitled.add(_PACK_ALIASES[key])
    return entitled


def _resolve_requested_pack(pack_id: str | None, entitled_packs: set[str]) -> str:
    if pack_id:
        normalized = _normalize_pack_id(pack_id)
        if normalized not in entitled_packs:
            raise HTTPException(status_code=403, detail="Not entitled to this compliance pack")
        return normalized

    if len(entitled_packs) == 1:
        return next(iter(entitled_packs))
    if "peca_forensic" in entitled_packs:
        return "peca_forensic"
    if "fbr_pos" in entitled_packs:
        return "fbr_pos"
    raise HTTPException(status_code=403, detail="No active compliance pack entitlement")


def _collection_for_pack(pack_id: str) -> str:
    return "fbr_pos_logs" if pack_id == "fbr_pos" else "peca_forensic_logs"


def _safe_path_segment(value: str) -> str:
    segment = Path(str(value or "")).name.strip()
    segment = re.sub(r"[^A-Za-z0-9_.-]", "_", segment)
    return segment or "unknown"


def _decrypt_export_field(value: Any) -> Any:
    if not value or not isinstance(value, str) or not _fernet:
        return value
    try:
        plaintext = _fernet.decrypt(value.encode()).decode()
    except Exception:
        return value
    try:
        return json.loads(plaintext)
    except Exception:
        return plaintext


def _prepare_csv_export_doc(doc: dict, *, decrypt_sensitive: bool) -> dict:
    prepared = dict(doc)
    if decrypt_sensitive:
        for field in _SENSITIVE_COMPLIANCE_FIELDS:
            if field in prepared:
                prepared[field] = _decrypt_export_field(prepared.get(field))
    return prepared

def _parse_time(time_str: str) -> Optional[datetime]:
    if not time_str:
        return None
    try:
        parsed = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


async def csv_generator(cursor, fieldnames):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    yield buffer.getvalue().encode("utf-8")
    buffer.seek(0)
    buffer.truncate(0)

    async for doc in cursor:
        row = {}
        for field in fieldnames:
            value = doc.get(field, "")
            if isinstance(value, (dict, list)):
                value = str(value)
            row[field] = value
        writer.writerow(row)
        yield buffer.getvalue().encode("utf-8")
        buffer.seek(0)
        buffer.truncate(0)


async def csv_list_generator(docs: list[dict], fieldnames):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    yield buffer.getvalue().encode("utf-8")
    buffer.seek(0)
    buffer.truncate(0)

    for doc in docs:
        row = {}
        for field in fieldnames:
            value = doc.get(field, "")
            if isinstance(value, (dict, list)):
                value = str(value)
            row[field] = value
        writer.writerow(row)
        yield buffer.getvalue().encode("utf-8")
        buffer.seek(0)
        buffer.truncate(0)

@router.get("/csv")
async def export_csv(
    data_type: str = Query(..., description="Type of data to export: 'alerts', 'logs', or 'compliance'"),
    pack_id: Optional[str] = Query(None, description="Optional compliance pack for data_type=compliance"),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(5000, le=50000),
    db = Depends(get_db),
    current_user: dict = Depends(require_premium_plan)
):
    """
    Enterprise CSV Export Engine.
    Dynamically generates CSV reports for SIEM alerts, raw logs, or compliance evidence.
    Restricted to Professional and Enterprise tiers via require_premium_plan.
    """
    tenant_id = _safe_path_segment(current_user.get("tenant_id"))
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    role = str(current_user.get("role") or "").strip().lower()
    if data_type == "alerts":
        if role not in {"admin", "manager", "analyst"}:
            raise HTTPException(status_code=403, detail="Role is not permitted to export alerts")
        collection_name = "security_alerts"
    elif data_type == "compliance":
        if role not in {"admin", "auditor"}:
            raise HTTPException(status_code=403, detail="Role is not permitted to export compliance evidence")
        entitled_packs = _get_entitled_packs(current_user)
        selected_pack = _resolve_requested_pack(pack_id, entitled_packs)
        collection_name = _collection_for_pack(selected_pack)
    else:
        if role not in {"admin", "manager", "analyst"}:
            raise HTTPException(status_code=403, detail="Role is not permitted to export logs")
        collection_name = "siem_cold_vault"

    collection = db[collection_name]
    query = {"tenant_id": tenant_id}
    
    # Secure Time Bounds
    start_dt = _parse_time(start_time)
    end_dt = _parse_time(end_time)
    
    if start_dt or end_dt:
        time_bounds = {}
        str_bounds = {}
        if start_dt:
            time_bounds["$gte"] = start_dt
            str_bounds["$gte"] = start_dt.isoformat()
        if end_dt:
            time_bounds["$lte"] = end_dt
            str_bounds["$lte"] = end_dt.isoformat()

        # Handle mixed BSON Date and ISO String formats
        query["$or"] = [
            {"timestamp": time_bounds},
            {"timestamp": str_bounds},
            {"ingested_at": time_bounds},
            {"ingested_at": str_bounds}
        ]

    cursor = collection.find(query).sort("timestamp", -1).limit(limit)
    hot_docs = await cursor.to_list(length=limit)
    archived_docs, _ = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=[collection_name],
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=None,
        limit=limit,
    )
    export_docs = sorted(
        [*hot_docs, *archived_docs],
        key=lambda doc: _parse_time(str(doc.get("timestamp") or doc.get("ingested_at") or "")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:limit]
    export_docs = [
        _prepare_csv_export_doc(doc, decrypt_sensitive=data_type == "compliance")
        for doc in export_docs
    ]

    fieldnames = set()
    for doc in export_docs[:100]:
        fieldnames.update(doc.keys())

    if not export_docs:
        raise HTTPException(status_code=404, detail="No data found for the given criteria.")

    # Strip internal fields to prevent data leakage
    for internal in [
        "_id",
        "tenant_id",
        "_retention_ts",
        "_expire_at",
        "_archived",
        "_source_collection",
        "_archive_blob_name",
        "digital_signature",
    ]:
        fieldnames.discard(internal)

    fieldnames = sorted(list(fieldnames))
    filename = f"warsoc_export_{data_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    
    return StreamingResponse(
        csv_list_generator(export_docs, fieldnames),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/audit-report")
async def export_audit_report(
    pack_id: str = Query(..., description="Compliance pack ID: 'peca_forensic' or 'fbr_pos'"),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    db = Depends(get_db),
    current_user: dict = Depends(require_premium_plan)
):
    """
    Generate a tenant-scoped forensic evidence summary for auditors.

    The source PECA records can carry RSA-PSS signatures. The generated PDF is
    a summary artifact and is not itself digitally signed.
    """
    tenant_id = _safe_path_segment(current_user.get("tenant_id"))
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if str(current_user.get("role") or "").strip().lower() not in {"admin", "auditor"}:
        raise HTTPException(status_code=403, detail="Role is not permitted to export compliance evidence")

    normalized_id = _normalize_pack_id(pack_id)
    entitled_packs = _get_entitled_packs(current_user)
    if normalized_id not in entitled_packs:
        raise HTTPException(status_code=403, detail="Not entitled to this compliance pack")

    pack = COMPLIANCE_CATALOG.get(normalized_id)
    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    collection_name = _collection_for_pack(normalized_id)
    collection = db[collection_name]
    alerts_coll = db["security_alerts"]
    
    query = {"tenant_id": tenant_id}
    start_dt = _parse_time(start_time)
    end_dt = _parse_time(end_time)
    
    if start_dt or end_dt:
        time_bounds = {}
        str_bounds = {}
        if start_dt:
            time_bounds["$gte"] = start_dt
            str_bounds["$gte"] = start_dt.isoformat()
        if end_dt:
            time_bounds["$lte"] = end_dt
            str_bounds["$lte"] = end_dt.isoformat()

        query["$or"] = [
            {"timestamp": time_bounds},
            {"timestamp": str_bounds},
            {"ingested_at": time_bounds},
            {"ingested_at": str_bounds}
        ]

    # Pull Forensic Logs (Ledger)
    logs_cursor = collection.find(query).sort("timestamp", -1).limit(500)
    forensic_logs = await logs_cursor.to_list(length=500)
    archived_forensic_logs, _ = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=[collection_name],
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=None,
        limit=500,
    )
    forensic_logs = sorted(
        [*forensic_logs, *archived_forensic_logs],
        key=lambda doc: _parse_time(str(doc.get("timestamp") or doc.get("ingested_at") or "")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:500]

    # Pull Alert Summary (Scorecard)
    pack_alert_filters = [
        {"pack_id": normalized_id},
        {"pack": normalized_id},
        {"compliance_pack": normalized_id},
        {"required_pack": normalized_id},
    ]
    alerts_query = {
        "tenant_id": tenant_id,
        "$and": [{"$or": pack_alert_filters}],
    }
    if (start_dt or end_dt) and "$or" in query:
        alerts_query["$and"].append({"$or": query["$or"]})
    
    alerts_cursor = alerts_coll.find(alerts_query)
    all_alerts = await alerts_cursor.to_list(length=5000)
    archived_alerts, _ = await fetch_archived_documents(
        db,
        tenant_id=tenant_id,
        collections=["security_alerts"],
        start_dt=start_dt,
        end_dt=end_dt,
        event_id=None,
        limit=5000,
    )
    archived_alerts = [
        alert for alert in archived_alerts
        if any(str(alert.get(field) or "") == normalized_id for field in ("pack_id", "pack", "compliance_pack", "required_pack"))
    ]
    all_alerts.extend(archived_alerts)
    
    # Aggregate Alert Counts
    alert_counts = {}
    for alert in all_alerts:
        eid = alert.get("event_id")
        alert_counts[eid] = alert_counts.get(eid, 0) + 1

    # 2. Generate PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], alignment=1, fontSize=18, spaceAfter=20, textColor=colors.HexColor("#1e293b"))
    header_style = ParagraphStyle('HeaderStyle', parent=styles['Heading2'], fontSize=14, spaceAfter=10, textColor=colors.HexColor("#334155"))
    body_style = styles["BodyText"]
    footer_style = ParagraphStyle('FooterStyle', parent=styles['Italic'], fontSize=8, alignment=1, textColor=colors.grey)

    # --- Header & Title ---
    elements.append(Paragraph(f"<b>WarSOC Forensic Evidence Summary</b>", title_style))
    elements.append(Paragraph(f"<b>Tenant ID:</b> {tenant_id}", body_style))
    elements.append(Paragraph(f"<b>Pack:</b> {pack['name']}", body_style))
    elements.append(Paragraph(f"<b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
    if start_dt or end_dt:
        range_str = f"{start_time or 'Beginning'} to {end_time or 'Present'}"
        elements.append(Paragraph(f"<b>Range:</b> {range_str}", body_style))
    elements.append(Spacer(1, 0.3 * inch))

    # --- Section 1: Compliance Scorecard ---
    elements.append(Paragraph("SECTION 1: COMPLIANCE SCORECARD", header_style))
    scorecard_data = [["Rule ID", "Control Description", "Severity", "Alert Count"]]
    
    for rule in pack["rules"]:
        eid = rule["event_id"]
        count = alert_counts.get(eid, 0)
        scorecard_data.append([rule["id"], rule["name"], rule["severity"], str(count)])

    scorecard_table = Table(scorecard_data, colWidths=[1.2*inch, 2.5*inch, 1*inch, 1*inch])
    scorecard_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(scorecard_table)
    elements.append(Spacer(1, 0.4 * inch))

    # --- Section 2: Forensic Ledger ---
    elements.append(Paragraph("SECTION 2: FORENSIC EVIDENCE LEDGER", header_style))
    elements.append(Paragraph("The following records were retrieved from the tenant-isolated compliance vault for audit review.", body_style))
    elements.append(Spacer(1, 0.1 * inch))

    ledger_data = [["Timestamp", "Event", "Source IP", "Forensic Seal (Partial)"]]
    for log in forensic_logs[:50]: # Limit to 50 for performance
        ts = log.get("timestamp")
        if isinstance(ts, datetime):
            ts = ts.strftime("%Y-%m-%d %H:%M")
        elif isinstance(ts, str):
            ts = ts[:16].replace("T", " ")
            
        eid = log.get("event_id")
        seal = log.get("forensic_seal", "N/A")
        ledger_data.append([
            str(ts),
            f"ID:{eid}",
            log.get("source_ip", "Unknown"),
            f"{seal[:20]}..." if seal else "N/A"
        ])

    ledger_table = Table(ledger_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 2*inch])
    ledger_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#64748b")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ]))
    elements.append(ledger_table)
    
    if len(forensic_logs) > 50:
        elements.append(Paragraph(f"<i>... and {len(forensic_logs)-50} more records (truncated for summary)</i>", body_style))

    # --- Footer ---
    elements.append(Spacer(1, 0.5 * inch))
    signed_records = sum(
        1
        for record in forensic_logs
        if record.get("forensic_seal") and record.get("signed_payload")
    )
    footer_text = (
        f"Source records carrying PECA signature material: {signed_records}/{len(forensic_logs)}. "
        "This PDF is an evidence summary and is not itself digitally signed. Legal admissibility "
        "depends on applicable law, chain of custody, and independent signature verification."
    )
    elements.append(Paragraph(footer_text, footer_style))

    doc.build(elements)
    buffer.seek(0)
    
    filename = f"warsoc_audit_{pack_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

class ReportItem(BaseModel):
    report_id: str
    report_type: str
    year: int
    month: int
    size_bytes: int
    created_at: str

@router.get("/list", response_model=List[ReportItem])
async def list_reports(current_user: dict = Depends(require_premium_plan)):
    """
    Returns a list of all available monthly PDFs for the tenant.
    """
    tenant_id = current_user.get("tenant_id")
    report_dir = get_reports_base_dir() / _safe_path_segment(tenant_id)
    
    reports = []
    if report_dir.exists():
        for file in report_dir.glob("*.pdf"):
            # Example filename: warsoc_fbr_pos_2026_04.pdf
            try:
                parts = file.stem.split("_")
                year = int(parts[-2])
                month = int(parts[-1])
                report_type = "_".join(parts[1:-2])
                
                reports.append(ReportItem(
                    report_id=file.name,
                    report_type=report_type,
                    year=year,
                    month=month,
                    size_bytes=file.stat().st_size,
                    created_at=datetime.fromtimestamp(file.stat().st_ctime, timezone.utc).isoformat()
                ))
            except Exception:
                continue
                
    return sorted(reports, key=lambda x: (x.year, x.month), reverse=True)

@router.get("/download/{report_id}")
async def download_report(report_id: str, current_user: dict = Depends(require_premium_plan)):
    """
    Streams a specific PDF report securely to the client's browser.
    """
    tenant_id = current_user.get("tenant_id")
    
    # Path traversal protection
    if "/" in report_id or "\\" in report_id or ".." in report_id:
        raise HTTPException(status_code=400, detail="Invalid report_id")
        
    report_path = get_reports_base_dir() / _safe_path_segment(tenant_id) / report_id
    
    if not report_path.exists() or not report_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
        
    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=report_id
    )
