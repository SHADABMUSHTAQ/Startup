# WarSOC Multiple-User Onboarding Method

## Create a New Customer

1. WarSOC operations creates a separate tenant for the customer.
2. Set the customer's endpoint limit and FBR/PECA entitlements.
3. Create the customer's first Admin account.
4. Give the Admin their login credentials securely.
5. Do not add two different customers to the same tenant.

## Add Multiple Users to One Customer

Repeat these steps for every user:

1. Customer Admin signs in at `https://warsoc.tech`.
2. Open **Team & Access**.
3. Click **Provision Access**.
4. Enter the user's work email.
5. Select a role:
   - **Manager:** can manage incidents.
   - **Analyst:** can view and investigate operational data.
   - **Auditor:** can view assigned FBR/PECA evidence.
   - **Admin:** full tenant access.
6. For an Auditor, select FBR, PECA, or both.
7. Submit the invitation.
8. The user receives a one-time setup link by email.
9. The user opens the link within 24 hours.
10. The user creates a password containing at least 16 characters.
11. The user signs in with their email and new password.
12. Admin checks **Team & Access** and confirms the user is active with the correct role.

## If the Email Does Not Arrive

1. Check spam and email quarantine.
2. Confirm the entered email address.
3. Confirm the user appears as pending in **Team & Access**.
4. Send the invitation again to the same email.
5. The old setup link becomes invalid and the new link remains valid for 24 hours.

## Remove a User

1. Admin opens **Team & Access**.
2. Find the Manager, Analyst, or Auditor.
3. Select revoke access.
4. Confirm removal.

Another Admin cannot currently be removed from the customer dashboard. WarSOC operations must handle that case.

## Install Agents on Customer Computers

User invitations do not install agents.

For every Windows computer:

1. Admin clicks **Download Agent**.
2. WarSOC generates one activation code.
3. Admin downloads the installer or gives the approved installer to customer IT.
4. Customer IT runs the installer on one Windows computer.
5. Enter the activation code and `https://api.warsoc.tech`.
6. Enter POS directories when FBR file monitoring is required.
7. Complete installation.
8. Confirm the agent appears active on the dashboard.
9. Generate a new activation code for the next computer.

Each agent consumes one endpoint seat. Dashboard users do not consume endpoint seats.
