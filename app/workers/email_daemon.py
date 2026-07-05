import asyncio
import json
import logging
import os
import smtplib
import socket
import uuid
from html import escape
from email.message import EmailMessage
from typing import Any

from redis.asyncio import Redis

from app.config.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [EMAIL-DAEMON] %(message)s")
logger = logging.getLogger("Email-Daemon")

settings = get_settings()
EMAIL_QUEUE = "email_alert_queue"
EMAIL_PROCESSING_QUEUE = "email_alert_queue:processing"
EMAIL_DEAD_LETTER_QUEUE = "email_alert_queue:dead"
QUEUE_TIMEOUT_SECONDS = 5
SMTP_TIMEOUT_SECONDS = 20
MAX_DELIVERY_ATTEMPTS = max(1, int(os.getenv("EMAIL_MAX_DELIVERY_ATTEMPTS", "3")))
MAX_CONCURRENT_SENDS = max(1, int(os.getenv("EMAIL_MAX_CONCURRENT_SENDS", "3")))
DEFAULT_FROM_ADDRESS = settings.zoho_smtp_user or os.getenv("MAIL_FROM", "no-reply@warsoc.local")


def _parse_job(raw_payload: Any) -> dict:
    if isinstance(raw_payload, bytes):
        raw_payload = raw_payload.decode("utf-8", errors="ignore")
    if isinstance(raw_payload, str):
        return json.loads(raw_payload)
    if isinstance(raw_payload, dict):
        return raw_payload
    return {}


def _build_message(job: dict) -> EmailMessage:
    job_type = str(job.get("type") or "security_alert_email").strip()
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}

    recipient = (
        job.get("recipient")
        or payload.get("recipient")
        or payload.get("tenant_id")
        or ""
    )
    if not recipient:
        raise ValueError("Missing recipient in email job")

    subject: str
    body: str

    if job_type == "welcome_email":
        tenant_id = str(job.get("tenant_id") or payload.get("tenant_id") or recipient)
        plan = str(job.get("plan") or payload.get("plan") or "standard").strip()
        subject = f"WarSOC onboarding complete for {tenant_id}"
        body = (
            f"Hello,\n\n"
            f"Your WarSOC tenant {tenant_id} is now active on the {plan} plan.\n"
            f"The platform is ready to receive alerts and compliance events.\n\n"
            f"Regards,\nWarSOC Security Operations"
        )
        message = EmailMessage()
        message["From"] = DEFAULT_FROM_ADDRESS
        message["To"] = str(recipient)
        message["Subject"] = subject
        message.set_content(body)
    elif job_type == "sales_quote":
        contact_name = payload.get("contact_name", "Unknown")
        contact_email = payload.get("contact_email", "Unknown")
        contact_phone = payload.get("contact_phone", "Not Provided")
        company = payload.get("company_name", "Unknown")
        plan = payload.get("plan_type", "Unknown")
        endpoints = payload.get("endpoints", 0)
        packs = ", ".join(payload.get("compliance_packs", [])) or "None"
        billing = payload.get("billing_cycle", "monthly")
        mrr = payload.get("frontend_calculated_total", 0)
        activation_fee = payload.get("activation_fee", 5000)
        initial_payment = payload.get("backend_initial_payment", 0)
        subject = f"HOT LEAD: {company} - {plan}"
        body = (
            f" NEW INBOUND B2B LEAD \n\n"
            f"Company Name: {company}\n"
            f"Contact Person: {contact_name} ({contact_email})\n"
            f"Direct Phone: {contact_phone}\n"
            f"Selected Package: {plan}\n"
            f"Compliance Packs: {packs}\n"
            f"Estimated Endpoints: {endpoints}\n"
            f"Billing Cycle: {billing.capitalize()}\n"
            f"Calculated MRR: ${mrr}\n"
            f"Activation Setup Fee: ${activation_fee}\n"
            f"Total Initial Payment Due: ${initial_payment}\n\n"
            f"Dial this lead within 60 seconds."
        )
        message = EmailMessage()
        message["From"] = DEFAULT_FROM_ADDRESS
        message["To"] = str(recipient)
        message["Subject"] = subject
        message.set_content(body)
    elif job_type == "sales_quote_confirmation":
        contact_name = payload.get("contact_name", "Unknown")
        company = payload.get("company_name", "Unknown")
        plan = payload.get("plan_type", "Unknown")
        endpoints = payload.get("endpoints", 0)
        packs = ", ".join(payload.get("compliance_packs", [])) or "None"
        billing = payload.get("billing_cycle", "monthly")
        total = payload.get("frontend_total", 0)
        subject = f"Your Custom WarSOC Enterprise Quote - {company}"
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #0056b3;">WarSOC Security Operations</h2>
                <p>Dear {contact_name},</p>
                <p>Thank you for requesting a custom quote for <strong>WarSOC Enterprise ({plan} Tier)</strong>.</p>
                <p>We have successfully received your requested architecture details:</p>
                <ul>
                    <li><strong>Endpoints:</strong> {endpoints}</li>
                    <li><strong>Compliance Packs:</strong> {packs}</li>
                    <li><strong>Billing Cycle:</strong> {billing.title()}</li>
                    <li><strong>Estimated Total:</strong> ${total}</li>
                </ul>
                <p>A member of our elite WarSOC deployment team will be contacting you shortly to finalize your network requirements and provide your official B2B contract.</p>
                <br/>
                <p>Securely yours,<br/><strong>WarSOC Deployments</strong></p>
            </body>
        </html>
        """
        message = EmailMessage()
        message["From"] = DEFAULT_FROM_ADDRESS
        message["To"] = str(recipient)
        message["Subject"] = subject
        message.set_content("Thank you for requesting a custom quote. Please view this email in an HTML client.")
        message.add_alternative(html_body, subtype='html')
    elif job_type == "sales_contact":
        contact_name = payload.get("contact_name", "Unknown")
        contact_email = payload.get("contact_email", "Unknown")
        company = payload.get("company_name", "Unknown")
        inquiry_type = str(payload.get("inquiry_type", "demo")).replace("_", " ").title()
        message_text = payload.get("message", "")
        user_agent = payload.get("user_agent", "Unknown")
        client_ip = payload.get("client_ip", "Unknown")
        created_at = payload.get("created_at", "")
        subject = f"CONTACT LEAD: {company} - {inquiry_type}"
        body = (
            f"NEW HOMEPAGE CONTACT LEAD\n\n"
            f"Company Name: {company}\n"
            f"Contact Person: {contact_name} ({contact_email})\n"
            f"Inquiry Type: {inquiry_type}\n"
            f"Submitted At: {created_at}\n"
            f"Client IP: {client_ip}\n"
            f"User Agent: {user_agent}\n\n"
            f"Message:\n{message_text}\n\n"
            f"Follow up from the WarSOC sales mailbox."
        )
        message = EmailMessage()
        message["From"] = DEFAULT_FROM_ADDRESS
        message["To"] = str(recipient)
        message["Subject"] = subject
        message.set_content(body)
    elif job_type == "sales_contact_confirmation":
        contact_name = escape(str(payload.get("contact_name", "there")))
        company = escape(str(payload.get("company_name", "your organization")))
        inquiry_type = escape(str(payload.get("inquiry_type", "demo")).replace("_", " ").title())
        subject = "We received your WarSOC request"
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #0056b3;">WarSOC Security Operations</h2>
                <p>Dear {contact_name},</p>
                <p>Thank you for contacting WarSOC about <strong>{inquiry_type}</strong> for <strong>{company}</strong>.</p>
                <p>Our team has received your request and will contact you shortly.</p>
                <br/>
                <p>Securely yours,<br/><strong>WarSOC Deployments</strong></p>
            </body>
        </html>
        """
        message = EmailMessage()
        message["From"] = DEFAULT_FROM_ADDRESS
        message["To"] = str(recipient)
        message["Subject"] = subject
        message.set_content("Thank you for contacting WarSOC. Our team will contact you shortly.")
        message.add_alternative(html_body, subtype="html")
    else:
        tenant_id = str(job.get("tenant_id") or payload.get("tenant_id") or "unknown")
        severity = str(payload.get("severity") or "HIGH").upper()
        rule_id = str(payload.get("rule_id") or "unknown")
        name = str(payload.get("name") or "Security Event")
        source_ip = str(payload.get("source_ip") or "Unknown")
        timestamp = str(payload.get("timestamp") or "")
        subject = f"[{severity}] WarSOC alert for {tenant_id}: {name}"
        body = (
            f"Security alert triggered for tenant {tenant_id}.\n\n"
            f"Rule ID: {rule_id}\n"
            f"Event: {name}\n"
            f"Severity: {severity}\n"
            f"Source IP: {source_ip}\n"
            f"Timestamp: {timestamp}\n\n"
            f"This message was queued by the alert bridge and delivered by the email daemon."
        )
        message = EmailMessage()
        message["From"] = DEFAULT_FROM_ADDRESS
        message["To"] = str(recipient)
        message["Subject"] = subject
        message.set_content(body)

    return message


def _send_email(message: EmailMessage) -> None:
    host = settings.zoho_smtp_host
    port = int(settings.zoho_smtp_port)
    username = settings.zoho_smtp_user
    password = settings.zoho_smtp_pass

    if not username or not password:
        if host != "mailhog":
            raise RuntimeError("SMTP credentials are not configured")

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS) as client:
            client.login(username, password)
            client.send_message(message)
        return

    with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS) as client:
        client.ehlo()
        # mailhog doesn't support starttls by default in some configurations, 
        # so we only starttls if not mailhog
        if host != "mailhog":
            client.starttls()
            client.ehlo()
            client.login(username, password)
        client.send_message(message)


async def _increment_metric(redis_client: Redis, metric: str) -> None:
    try:
        await redis_client.incr(metric)
    except Exception:
        logger.debug("Unable to increment email metric %s", metric, exc_info=True)


async def _ack_processing_job(redis_client: Redis, raw_payload: str) -> None:
    removed = await redis_client.lrem(EMAIL_PROCESSING_QUEUE, 1, raw_payload)
    if int(removed or 0) != 1:
        raise RuntimeError("Email processing acknowledgement did not remove exactly one job")


async def _retry_or_quarantine(
    redis_client: Redis,
    raw_payload: str,
    job: dict,
    error: Exception,
) -> None:
    attempt = int(job.get("_delivery_attempt") or 0) + 1
    job_id = str(job.get("_job_id") or uuid.uuid4().hex)
    job["_job_id"] = job_id
    job["_delivery_attempt"] = attempt
    error_text = f"{type(error).__name__}: {error}"[:500]

    if attempt < MAX_DELIVERY_ATTEMPTS:
        await asyncio.sleep(min(2 ** (attempt - 1), 8))
        retry_payload = json.dumps(job, separators=(",", ":"), default=str)
        async with redis_client.pipeline(transaction=True) as pipe:
            pipe.lrem(EMAIL_PROCESSING_QUEUE, 1, raw_payload)
            pipe.lpush(EMAIL_QUEUE, retry_payload)
            result = await pipe.execute()
        if int(result[0] or 0) != 1:
            raise RuntimeError("Email retry could not atomically consume the processing job")
        await _increment_metric(redis_client, "warsoc_email_retries_total")
        logger.warning(
            "Email job %s failed attempt %s/%s and was requeued: %s",
            job_id,
            attempt,
            MAX_DELIVERY_ATTEMPTS,
            error_text,
        )
        return

    dead_letter = {
        "job_id": job_id,
        "attempts": attempt,
        "error": error_text,
        "job": job,
    }
    dead_payload = json.dumps(dead_letter, separators=(",", ":"), default=str)
    async with redis_client.pipeline(transaction=True) as pipe:
        pipe.lrem(EMAIL_PROCESSING_QUEUE, 1, raw_payload)
        pipe.lpush(EMAIL_DEAD_LETTER_QUEUE, dead_payload)
        result = await pipe.execute()
    if int(result[0] or 0) != 1:
        raise RuntimeError("Email DLQ move could not atomically consume the processing job")
    await _increment_metric(redis_client, "warsoc_email_dlq_total")
    logger.error(
        "Email job %s exhausted %s attempts and was quarantined: %s",
        job_id,
        attempt,
        error_text,
    )


async def _process_job(
    raw_payload: str,
    redis_client: Redis,
    semaphore: asyncio.Semaphore,
) -> None:
    job: dict = {}
    try:
        job = _parse_job(raw_payload)
        if not job:
            raise ValueError("Empty email job payload")
        message = _build_message(job)
        async with semaphore:
            await asyncio.to_thread(_send_email, message)
        await _ack_processing_job(redis_client, raw_payload)
        await _increment_metric(redis_client, "warsoc_email_delivered_total")
        logger.info("Delivered %s to %s", job.get("type", "security_alert_email"), message["To"])
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        try:
            await _retry_or_quarantine(redis_client, raw_payload, job, exc)
        except Exception:
            # The original payload remains in the processing queue when the
            # atomic retry/DLQ transition fails, so startup recovery can replay it.
            logger.exception("Email job recovery failed; payload remains pending")


async def _recover_processing_queue(redis_client: Redis) -> int:
    recovered = 0
    while True:
        payload = await redis_client.rpoplpush(EMAIL_PROCESSING_QUEUE, EMAIL_QUEUE)
        if payload is None:
            return recovered
        recovered += 1


async def run_email_daemon() -> None:
    redis_url = getattr(settings, "redis_url", None)
    if not redis_url:
        raise RuntimeError("REDIS_URL is required for the email daemon")

    redis_client = Redis.from_url(
        redis_url,
        decode_responses=True,
        socket_timeout=QUEUE_TIMEOUT_SECONDS + 10,
        socket_connect_timeout=5,
        health_check_interval=30,
    )
    logger.info("Email daemon online on host %s", socket.gethostname())
    
    recovered = await _recover_processing_queue(redis_client)
    if recovered:
        logger.warning("Recovered %s interrupted email jobs", recovered)

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SENDS)
    active_tasks: set[asyncio.Task] = set()

    try:
        while True:
            try:
                raw_payload = await redis_client.brpoplpush(
                    EMAIL_QUEUE,
                    EMAIL_PROCESSING_QUEUE,
                    timeout=QUEUE_TIMEOUT_SECONDS,
                )
                if raw_payload is None:
                    continue

                task = asyncio.create_task(_process_job(raw_payload, redis_client, semaphore))
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                continue
            except Exception as exc:
                logger.warning("Email daemon loop error, retrying: %s", exc)
                await asyncio.sleep(1)
    finally:
        if active_tasks:
            for task in active_tasks:
                task.cancel()
            await asyncio.gather(*active_tasks, return_exceptions=True)
        try:
            await redis_client.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(run_email_daemon())
    except KeyboardInterrupt:
        logger.info("Email daemon shutting down cleanly")
