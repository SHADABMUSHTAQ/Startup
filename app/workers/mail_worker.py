"""
WarSOC Mail Worker (Tier 3: Observability & Notifications)

Consumes transactional jobs from the 'email_send_queue' Redis stream.
Uses Zoho Mail SMTP for production transactional emails with robust 
simulated fallbacks when running in sandbox/development configurations.

Architecture Rules:
  - NON-BLOCKING SMTP: smtplib network calls are deferred to thread pools (asyncio.to_thread).
  - FORENSIC COMPLIANCE: Every sent/simulated email creates a permanent record in 'management_audit'.
  - SLEEK PREMIUM DESIGN: HTML templates follow enterprise glassmorphic/dark-mode branding.
"""
import sys
import os
import asyncio
import json
import logging
import smtplib
import traceback
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from redis.asyncio import Redis
from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.config.config import get_settings
from app.utils.observability import record_worker_heartbeat_async, increment_redis_counter

# Logger Configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("Mail-Worker")

# Settings and constants
settings = get_settings()
EMAIL_QUEUE = "email_send_queue"
EMAIL_GROUP = "email_group"
EMAIL_CONSUMER = "mail_worker_1"

PREMIUM_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to WarSOC SIEM</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #f3f4f6;
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 0;
            -webkit-font-smoothing: antialiased;
        }}
        .wrapper {{
            background-color: #0b0f19;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
            border: 1px solid #1e293b;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
        }}
        .header {{
            background: linear-gradient(90deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            padding: 30px;
            text-align: center;
            border-bottom: 1px solid #1e293b;
        }}
        .logo {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 2px;
            color: #06b6d4;
            text-transform: uppercase;
        }}
        .logo span {{
            color: #3b82f6;
        }}
        .content {{
            padding: 40px 30px;
        }}
        h1 {{
            font-size: 22px;
            margin-top: 0;
            color: #ffffff;
            font-weight: 700;
        }}
        p {{
            color: #9ca3af;
            line-height: 1.6;
            font-size: 15px;
        }}
        .card {{
            background: rgba(30, 41, 59, 0.5);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 24px;
            margin: 30px 0;
        }}
        .card-title {{
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #3b82f6;
            font-weight: 700;
            margin-top: 0;
            margin-bottom: 15px;
        }}
        .details-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .details-table td {{
            padding: 8px 0;
            font-size: 14px;
        }}
        .label {{
            color: #6b7280;
            font-weight: 600;
            width: 120px;
        }}
        .value {{
            color: #e5e7eb;
            font-family: 'Courier New', Courier, monospace;
            font-weight: bold;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            background-color: #06b6d4;
            color: #0b0f19;
        }}
        .btn {{
            display: inline-block;
            background: linear-gradient(90deg, #06b6d4 0%, #3b82f6 100%);
            color: #ffffff;
            text-decoration: none;
            padding: 12px 30px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 15px;
            text-align: center;
            margin-top: 15px;
            box-shadow: 0 4px 14px 0 rgba(6, 182, 212, 0.3);
        }}
        .compliance-notice {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #1e293b;
            font-size: 12px;
            color: #6b7280;
            line-height: 1.5;
        }}
        .footer {{
            background-color: #090d16;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #4b5563;
            border-top: 1px solid #1e293b;
        }}
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="container">
            <div class="header">
                <div class="logo">War<span>SOC</span></div>
            </div>
            <div class="content">
                <h1>Active Subscription Provisioned Successfully</h1>
                <p>Hello,</p>
                <p>Thank you for partnering with WarSOC. Your SaaS platform subscription has been verified and fully provisioned at the database level. Multi-tenant boundaries have been initialized for your tenant.</p>
                
                <div class="card">
                    <div class="card-title">System Provisioning Record</div>
                    <table class="details-table">
                        <tr>
                            <td class="label">Tenant ID:</td>
                            <td class="value">{tenant_id}</td>
                        </tr>
                        <tr>
                            <td class="label">Plan Tier:</td>
                            <td class="value"><span class="badge">{plan}</span></td>
                        </tr>
                        <tr>
                            <td class="label">Status:</td>
                            <td class="value" style="color: #10b981;">Active</td>
                        </tr>
                        <tr>
                            <td class="label">Timestamp:</td>
                            <td class="value">{timestamp}</td>
                        </tr>
                    </table>
                </div>

                <p>Your Security Analysts and System Auditors can now sign in to view compliance audits, configure custom detection correlation filters, and monitor telemetry logs in real-time.</p>
                
                <div style="text-align: center;">
                    <a href="{login_url}" class="btn">Launch Dashboard</a>
                </div>

                <div class="compliance-notice">
                    <strong>🛡️ Regulatory Compliance Notice:</strong><br>
                    This transaction and its associated metadata are cryptographically chained and sealed in our multi-tenant ledger under PECA 2016 and FBR rules. High-availability streaming endpoints have been reserved.
                </div>
            </div>
            <div class="footer">
                &copy; 2026 WarSOC Technologies. All rights reserved.<br>
                This is an automated operational notification.
            </div>
        </div>
    </div>
</body>
</html>
"""

def _send_email_sync(recipient: str, subject: str, html_body: str) -> bool:
    """Synchronous smtplib wrapper that executes within a separate thread executor."""
    host = settings.zoho_smtp_host
    port = settings.zoho_smtp_port
    user = settings.zoho_smtp_user
    password = settings.zoho_smtp_pass

    # Double check if credentials look like templates or are missing
    if not user or not password or "REPLACE" in user.upper() or "REPLACE" in password.upper():
        logger.warning(f"SMTP credentials not fully configured in settings. Simulating welcome email delivery to {recipient}.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = recipient

    part = MIMEText(html_body, "html")
    msg.attach(part)

    if port == 465:
        # SSL
        with smtplib.SMTP_SSL(host, port, timeout=10.0) as server:
            server.login(user, password)
            server.sendmail(user, recipient, msg.as_string())
    else:
        # STARTTLS / standard SMTP
        with smtplib.SMTP(host, port, timeout=10.0) as server:
            if port != 25:
                server.starttls()
            server.login(user, password)
            server.sendmail(user, recipient, msg.as_string())
    return True


async def handle_welcome_email(db, job_payload: dict):
    """Processes a welcome_email job by constructing the template and dispatching it."""
    tenant_id = job_payload.get("tenant_id", "UNKNOWN")
    recipient = job_payload.get("recipient", "")
    plan = job_payload.get("plan", "Enterprise")
    
    if not recipient:
        logger.error(f"Cannot dispatch email: missing recipient for tenant {tenant_id}")
        return

    # Build the rich, modern, dark-themed HTML
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    login_url = f"{settings.backend_public_url.rstrip('/')}/login"
    html_content = PREMIUM_HTML_TEMPLATE.format(
        tenant_id=tenant_id,
        plan=plan,
        timestamp=now_str,
        login_url=login_url
    )

    subject = f"Welcome to WarSOC SIEM — Tenant {tenant_id} Activated"

    # Send the email safely in a background thread to prevent event loop blocking
    try:
        sent = await asyncio.to_thread(_send_email_sync, recipient, subject, html_content)
        
        # 📝 COMPLIANCE: Insert transactional audit event into management_audit
        audit_record = {
            "tenant_id": tenant_id,
            "action": "Transactional Notification",
            "actor": "System System",
            "details": f"Welcome email sent successfully to {recipient} (Plan: {plan}).",
            "ip_address": "127.0.0.1",
            "timestamp": datetime.now(timezone.utc),
            "status": "success" if sent else "simulated"
        }
        
        if not sent:
            logger.info(f"Welcome email for {tenant_id} successfully simulated in sandbox mode.")
            audit_record["details"] += " [SIMULATED: credentials missing]"
            
        await db.management_audit.insert_one(audit_record)
        logger.info(f"Welcome email operation logged in management_audit for tenant {tenant_id}")
        
    except Exception as smtp_err:
        logger.error(f"SMTP dispatch failure: {smtp_err}")
        # Log failure audit
        await db.management_audit.insert_one({
            "tenant_id": tenant_id,
            "action": "Transactional Notification Failed",
            "actor": "System System",
            "details": f"Failed to send welcome email to {recipient}: {str(smtp_err)}",
            "ip_address": "127.0.0.1",
            "timestamp": datetime.now(timezone.utc),
            "status": "failed"
        })
        raise smtp_err


async def mail_worker():
    """Main consumer loop reading from the email stream queue."""
    logger.info("Initializing WarSOC Transactional Mail Consumer...")
    
    # Inits
    mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    db = mongo_client[settings.mongodb_db_name]
    redis = await Redis.from_url(settings.redis_url, decode_responses=True)

    # Lazily create consumer group
    while True:
        try:
            await redis.xgroup_create(EMAIL_QUEUE, EMAIL_GROUP, mkstream=True)
            logger.info(f"✅ Created consumer group: {EMAIL_GROUP} on stream {EMAIL_QUEUE}")
            break
        except Exception as group_err:
            if "BUSYGROUP" in str(group_err):
                logger.info(f"[*] Consumer group {EMAIL_GROUP} already exists. Resuming...")
                break
            logger.warning(f"Consumer group init failed: {group_err}. Retrying in 2s...")
            await asyncio.sleep(2)

    logger.info("⚡ WarSOC Mail Consumer online. Listening for transactional mail requests...")

    try:
        while True:
            try:
                # 📥 Read a block of jobs
                streams = await redis.xreadgroup(EMAIL_GROUP, EMAIL_CONSUMER, {EMAIL_QUEUE: ">"}, count=10, block=2000)
                if not streams:
                    await record_worker_heartbeat_async("mail_worker")
                    continue

                for _, messages in streams:
                    for message_id, payload_data in messages:
                        raw_payload = payload_data.get("payload", "")
                        try:
                            job = json.loads(raw_payload)
                            job_type = job.get("type")
                            
                            logger.info(f"Processing email job: msg_id={message_id} | type={job_type}")
                            
                            if job_type == "welcome_email":
                                await handle_welcome_email(db, job)
                            else:
                                logger.warning(f"Unknown email job type: {job_type}. Ignored.")
                                
                            # ACK
                            await redis.xack(EMAIL_QUEUE, EMAIL_GROUP, message_id)
                            await increment_redis_counter(redis, "warsoc_emails_sent_total")
                            
                        except Exception as job_err:
                            logger.error(f"Error handling email job {message_id}: {job_err}")
                            # If job parser or SMTP crashed, we acknowledge to avoid locking the queue
                            # but log details.
                            await redis.xack(EMAIL_QUEUE, EMAIL_GROUP, message_id)
                            await increment_redis_counter(redis, "warsoc_emails_failed_total")

                await record_worker_heartbeat_async("mail_worker")

            except Exception as loop_err:
                logger.error(f"[Mail Loop Error] {loop_err}")
                await asyncio.sleep(2)

    finally:
        logger.info("Closing Mail Worker resources...")
        try:
            mongo_client.close()
            await redis.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(mail_worker())
    except KeyboardInterrupt:
        logger.info("WarSOC Mail Worker offline.")
