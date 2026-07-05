# WarSOC Pilot Unsigned-Agent Policy

This policy is temporary for directly managed pilot deployments. Microsoft
Defender Antivirus, cloud protection, tamper protection, and real-time
protection must remain enabled.

## Release procedure

1. Build `warsoc_agent.exe` and `warsoc_installer.exe` from the approved commit.
2. Generate `Output/pilot_hash_manifest.json`:

   ```powershell
   .\scripts\generate_pilot_hash_manifest.ps1
   ```

3. Confirm the manifest contains the installer, agent, NSSM service manager,
   and native telemetry PowerShell script.
4. Transfer the installer and manifest to the customer through an authenticated
   channel.
5. The customer IT administrator verifies the downloaded installer with
   `Get-FileHash -Algorithm SHA256`.
6. The customer chooses one managed allow mechanism:
   - Microsoft Defender for Endpoint: create an Allow file indicator for the
     supplied SHA-256 after enabling file-hash computation.
   - App Control for Business (WDAC): create a supplemental policy from the
     supplied binaries using Hash as the fallback rule level. WDAC uses
     Authenticode/PE image hashes, so IT must generate the policy from the files
     rather than pasting the flat manifest hash into an unrelated policy field.
7. Test the policy in WDAC audit mode before enforcing it on pilot endpoints.
8. Submit affected executable files to Microsoft Security Intelligence as a
   software developer if Defender classifies an artifact incorrectly.

## Restrictions

- Never disable antivirus, cloud protection, SmartScreen, or tamper protection.
- Never exclude the entire WarSOC directory or all `.exe` files.
- Never reuse a hash approval after rebuilding either binary.
- A hash allow rule does not create publisher identity or SmartScreen
  reputation. Authenticode signing remains the required long-term release path.

## Microsoft references

- App Control file rule levels:
  https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create
- Defender for Endpoint file indicators:
  https://learn.microsoft.com/defender-endpoint/indicator-file
- Microsoft file submission:
  https://www.microsoft.com/wdsi/filesubmission
