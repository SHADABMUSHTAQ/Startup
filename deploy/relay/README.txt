WarSOC Firewall Relay Setup Kit
================================

Purpose
-------
This kit installs the WarSOC relay as an automatic Windows service. The relay
receives pfSense firewall syslog on the customer LAN and sends signed batches
to WarSOC over HTTPS. It does not capture network packet payloads.

Before installation
-------------------
1. Use the WarSOC Firewall Relays screen to create a relay setup.
2. Before extracting this unsigned pilot kit, run:

     Get-FileHash .\warsoc_relay_setup-1.0.0.zip -Algorithm SHA256

   Confirm the result exactly matches the SHA-256 displayed by WarSOC. Stop if
   it differs. Windows may display Unknown publisher for this pilot release.
3. Download relay-config.json from the WarSOC screen.
4. Copy relay-config.json into this extracted folder.
5. Keep the one-time activation code available. Do not save it in the config.
6. Use an always-on Windows Server host. Workstation or agent co-location
   requires an explicit approved override.

Install
-------
Open PowerShell as Administrator in this folder and run:

  Set-ExecutionPolicy -Scope Process Bypass
  .\install_warsoc_relay.ps1 `
    -RelayExecutable .\warsoc_relay.exe `
    -NssmExecutable .\nssm.exe `
    -ConfigFile .\relay-config.json

The installer requests the one-time activation code securely. It creates the
WarSOC_Relay service, restricted local directories, and source-limited Windows
Firewall rules derived from relay-config.json.

pfSense
-------
In pfSense, open Status > System Logs > Settings. Enable remote logging for
firewall events and send UDP syslog to the relay LAN IP and port shown in the
WarSOC setup. Do not forward pfSense directly to the public WarSOC API.

Verify
------
1. Confirm the WarSOC_Relay Windows service is Running.
2. Return to Firewall Relays in WarSOC and select Refresh.
3. Confirm the relay heartbeat appears, then generate a harmless logged
   firewall event and confirm the pfSense device becomes active.

Do not email or share activation codes, relay identity files, spool files, or
customer configuration files.
