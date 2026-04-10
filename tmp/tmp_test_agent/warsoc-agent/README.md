# WarSOC Agent Setup

## Requirements
- Windows 10/11 or Windows Server
- Python 3.10+
- Administrator privileges (for Windows Event Log access)

## Installation
1. Open PowerShell as Administrator
2. Navigate to this folder
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the agent:
   ```
   python warsoc_agent.py
   ```

## What it monitors
- **Windows Security Events**: Login attempts, account changes, audit log clearing
- **Web Server Logs**: Apache/Nginx access logs (configure WEB_LOG_PATH in .env)
- **Firewall Enforcement**: Automatically blocks IPs flagged by WarSOC

## Configuration
Edit the `.env` file to change:
- `BACKEND_URL` — Your WarSOC server address
- `WEB_LOG_PATH` — Path to your web server access log
- `AGENT_MASTER_SECRET` — Your agent authentication key

Your Tenant ID is pre-configured. Do not change it.
