Email daemon

This repository includes `app/workers/email_daemon.py` which consumes `email_alert_queue` from Redis and sends transactional emails.

Run via Docker Compose (uses `docker-compose.email.yml`):

```bash
# Copy env template and edit
cp .env.example .env
# Start the email daemon service
docker-compose -f docker-compose.email.yml up -d --build
```

Or run locally with the virtualenv:

```bash
# activate your .venv
. .venv/Scripts/activate
# ensure dependencies installed
python -m pip install -r requirements.txt
# run
python -u app/workers/email_daemon.py
```

Environment variables required:
- `REDIS_URL` (e.g., redis://redis:6379/0)
- `ZOHO_SMTP_HOST`, `ZOHO_SMTP_PORT`, `ZOHO_SMTP_USER`, `ZOHO_SMTP_PASS`
- Optional: `MAIL_FROM` to override default From address

Notes:
- SMTP credentials must be stored securely (do not commit). Use Docker secrets or environment injection in production.
- The daemon will block on `BRPOP` and process items one at a time.
- To inspect the queue without delivering, use `redis-cli --raw BRPOP email_alert_queue 0` on the redis instance.
