# WarSOC Azure Account and Storage Creation Runbook

**Status:** Authoritative infrastructure preparation guide
**Updated:** 2026-07-30
**Scope:** Create and verify the Azure subscriptions, identities, storage accounts, containers, retention controls, and cost safeguards needed by WarSOC. This document does not migrate compute or enable a feature.

The production accounts created by this runbook replace the pilot artifact/evidence routing. The old public pilot artifact may be removed after the new versioned installer and manifest pass preflight. A legacy evidence container with a locked immutability policy cannot be deleted early; stop new writes, remove it from production routing, restrict access and retain it until expiry.

## 1. Decisions and Boundaries

WarSOC currently uses two distinct Azure responsibilities:

1. **Artifact delivery:** a public container serves only versioned Windows installer artifacts and their non-secret hash manifests.
2. **Evidence custody:** private containers hold SIEM, PECA, and FBR archive blobs. They may contain PII and must never permit anonymous access.
3. **Database recovery:** encrypted MongoDB backups are operational recovery material, not immutable compliance evidence.
4. **Retrieval staging:** temporary private copies support future asynchronous archive download. Staging is not WORM evidence and requires automatic deletion.

Do not place evidence, backups, reports, uploads, secrets, or raw telemetry in the public artifact account.

The Azure $200 credit is a temporary compute runway, not a continuity guarantee. Microsoft documents that exhausting a spending limit can deallocate VMs and disable services. A budget alert warns; it does not prevent the stop. A paying deployment must move to a durable commercial subscription before the promotional subscription expires.

## 2. What Cannot Be Done Only by Terminal

Azure account creation, identity verification, payment/billing acceptance, student-benefit activation, and subscription enrollment require the Azure web flow. Complete those steps in a trusted browser with MFA.

After the subscription exists, use Azure Cloud Shell or a trusted machine with Azure CLI for all commands below.

## 3. Record the Inputs

Fill these values before creating resources:

```text
Azure tenant ID:                    ______________________________
Existing storage subscription ID:  ______________________________
Temporary compute subscription ID: ______________________________
Approved region:                    southeastasia / _____________
Artifact storage account:           ______________________________
Evidence storage account:           ______________________________
Operator:                           ______________________________
Change record/date:                 ______________________________
```

Storage-account names are globally unique, 3-24 characters, and lowercase letters/numbers only.

## 4. Authenticate and Select the Correct Subscription

Run from Azure Cloud Shell or a trusted Linux shell:

```bash
az login --use-device-code
az account list --output table

export STORAGE_SUBSCRIPTION_ID='<existing-student-storage-subscription-id>'
export COMPUTE_SUBSCRIPTION_ID='<temporary-compute-subscription-id>'

az account set --subscription "$STORAGE_SUBSCRIPTION_ID"
az account show --query '{name:name,id:id,state:state,tenantId:tenantId}' --output table
```

Stop if the selected subscription is not `Enabled` or is not the intended storage subscription.

Register the resource providers used by storage, monitoring, identity, backup, networking, and compute:

```bash
for provider in \
  Microsoft.Storage \
  Microsoft.Insights \
  Microsoft.ManagedIdentity \
  Microsoft.Network \
  Microsoft.Compute \
  Microsoft.RecoveryServices
do
  az provider register --namespace "$provider"
done

az provider list \
  --query "[?namespace=='Microsoft.Storage' || namespace=='Microsoft.Insights' || namespace=='Microsoft.ManagedIdentity' || namespace=='Microsoft.Network' || namespace=='Microsoft.Compute' || namespace=='Microsoft.RecoveryServices'].[namespace,registrationState]" \
  --output table
```

## 5. Define Storage Variables

Use the approved geography. The example keeps existing storage in Germany West Central; do not move regulated data between regions without a recorded decision.

```bash
export STORAGE_RG='rg-warsoc-storage-prod'
export STORAGE_LOCATION='germanywestcentral'

# Replace these with globally unique lowercase names.
export ARTIFACT_ACCOUNT='warsocartifacts<unique>'
export EVIDENCE_ACCOUNT='warsocevidence<unique>'

az group create \
  --name "$STORAGE_RG" \
  --location "$STORAGE_LOCATION" \
  --output table
```

If the current artifact/evidence accounts already exist, do not create replacements during the emergency compute migration. Set the variables to the existing names and continue with verification.

## 6. Public Artifact Account

Create this account only if it does not already exist:

```bash
az storage account create \
  --resource-group "$STORAGE_RG" \
  --name "$ARTIFACT_ACCOUNT" \
  --location "$STORAGE_LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --https-only true \
  --allow-blob-public-access true \
  --default-action Allow \
  --output table
```

Create the blob-only public container. Container listing remains private; only exact blob URLs are anonymous:

```bash
az storage container create \
  --account-name "$ARTIFACT_ACCOUNT" \
  --name warsoc-agent-public \
  --public-access blob \
  --auth-mode login \
  --output table
```

Upload only a versioned installer and its manifest:

```bash
export AGENT_VERSION='4.2.8'
export INSTALLER="Output/warsoc_installer-${AGENT_VERSION}.exe"
export MANIFEST="Output/pilot_hash_manifest-${AGENT_VERSION}.json"

test -f "$INSTALLER"
test -f "$MANIFEST"
sha256sum "$INSTALLER"

az storage blob upload \
  --account-name "$ARTIFACT_ACCOUNT" \
  --container-name warsoc-agent-public \
  --name "warsoc_installer-${AGENT_VERSION}.exe" \
  --file "$INSTALLER" \
  --overwrite false \
  --auth-mode login

az storage blob upload \
  --account-name "$ARTIFACT_ACCOUNT" \
  --container-name warsoc-agent-public \
  --name "pilot_hash_manifest-${AGENT_VERSION}.json" \
  --file "$MANIFEST" \
  --overwrite false \
  --auth-mode login
```

Do not run these upload commands until the matching versioned binary and manifest actually exist. Source version `4.2.8` is not an artifact release by itself.

## 7. Private Evidence Account

Create this account only if it does not already exist:

```bash
az storage account create \
  --resource-group "$STORAGE_RG" \
  --name "$EVIDENCE_ACCOUNT" \
  --location "$STORAGE_LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --https-only true \
  --allow-blob-public-access false \
  --allow-shared-key-access true \
  --default-action Allow \
  --output table
```

`allow-shared-key-access` stays enabled because the current archiver uses `AZURE_STORAGE_CONNECTION_STRING`. Disable it only after the application is migrated and proven with managed identity. Do not claim that the current archiver uses managed identity.

Create the private containers:

```bash
for container in \
  warsoc-retention-90 \
  warsoc-retention-180 \
  warsoc-retention-270 \
  warsoc-retention-360 \
  warsoc-peca-365 \
  warsoc-fbr-2190 \
  warsoc-retrieval-staging \
  warsoc-db-backups
do
  az storage container create \
    --account-name "$EVIDENCE_ACCOUNT" \
    --name "$container" \
    --public-access off \
    --auth-mode login \
    --output none
done
```

The existing `warsoc-cold-storage` fallback may already be locked for 2,190 days. Do not delete, rename, shorten, or move its governed blobs.

## 8. Retention Policy Creation and Locking

Retention lock and access tier are separate controls. Do not call a container "Archive tier." WarSOC currently uploads block blobs; lifecycle/tiering is a later storage-policy decision.

Create policies **unlocked** first:

```bash
declare -A RETENTION_DAYS=(
  [warsoc-retention-90]=90
  [warsoc-retention-180]=180
  [warsoc-retention-270]=270
  [warsoc-retention-360]=360
  [warsoc-peca-365]=365
  [warsoc-fbr-2190]=2190
)

for container in "${!RETENTION_DAYS[@]}"; do
  az storage container immutability-policy create \
    --resource-group "$STORAGE_RG" \
    --account-name "$EVIDENCE_ACCOUNT" \
    --container-name "$container" \
    --period "${RETENTION_DAYS[$container]}" \
    --allow-protected-append-writes false \
    --output table
done
```

Do not apply an immutability policy to `warsoc-retrieval-staging`; temporary copies must expire. The database-backup container follows the approved recovery-retention policy, not the FBR evidence lock.

### 8.1 Test each unlocked policy

For every immutable container, upload and read a harmless object. Deletion will be blocked while the retention interval applies; that is expected. Verify the policy duration before lock:

```bash
printf 'WarSOC immutability validation %s\n' "$(date -u +%FT%TZ)" > /tmp/warsoc-policy-test.txt

for container in "${!RETENTION_DAYS[@]}"; do
  az storage blob upload \
    --account-name "$EVIDENCE_ACCOUNT" \
    --container-name "$container" \
    --name "policy-validation/$(date -u +%Y%m%dT%H%M%SZ).txt" \
    --file /tmp/warsoc-policy-test.txt \
    --auth-mode login \
    --overwrite false \
    --output none

  az storage container immutability-policy show \
    --resource-group "$STORAGE_RG" \
    --account-name "$EVIDENCE_ACCOUNT" \
    --container-name "$container" \
    --query '{state:state,days:immutabilityPeriodSinceCreationInDays,etag:etag}' \
    --output table
done
```

Compare every result with `RETENTION_DAYS`. A mismatch blocks locking.

### 8.2 Lock the verified policies

Locking is irreversible for the retention interval: it cannot be shortened or deleted, although Azure permits limited extensions. Use a two-person review before this loop.

```bash
read -r -p 'Type LOCK-WARSOC-RETENTION to continue: ' CONFIRM
test "$CONFIRM" = 'LOCK-WARSOC-RETENTION'

for container in "${!RETENTION_DAYS[@]}"; do
  etag="$(az storage container immutability-policy show \
    --resource-group "$STORAGE_RG" \
    --account-name "$EVIDENCE_ACCOUNT" \
    --container-name "$container" \
    --query etag --output tsv)"

  az storage container immutability-policy lock \
    --resource-group "$STORAGE_RG" \
    --account-name "$EVIDENCE_ACCOUNT" \
    --container-name "$container" \
    --if-match "$etag" \
    --output table
done
```

Final verification:

```bash
for container in "${!RETENTION_DAYS[@]}"; do
  az storage container immutability-policy show \
    --resource-group "$STORAGE_RG" \
    --account-name "$EVIDENCE_ACCOUNT" \
    --container-name "$container" \
    --query '{container:`'"$container"'`,state:state,days:immutabilityPeriodSinceCreationInDays}' \
    --output table
done
```

## 9. Retrieval Staging Lifecycle

Archive retrieval remains disabled until this staging control and a real rehydration test pass. Apply a management policy that deletes staged block blobs after three days:

```bash
cat > /tmp/warsoc-staging-lifecycle.json <<'JSON'
{
  "rules": [
    {
      "enabled": true,
      "name": "delete-warsoc-retrieval-staging-after-3-days",
      "type": "Lifecycle",
      "definition": {
        "actions": {
          "baseBlob": {"delete": {"daysAfterModificationGreaterThan": 3}}
        },
        "filters": {
          "blobTypes": ["blockBlob"],
          "prefixMatch": ["warsoc-retrieval-staging/"]
        }
      }
    }
  ]
}
JSON

az storage account management-policy create \
  --resource-group "$STORAGE_RG" \
  --account-name "$EVIDENCE_ACCOUNT" \
  --policy @/tmp/warsoc-staging-lifecycle.json \
  --output table
```

If this storage account already has lifecycle rules, do not overwrite them. Export the existing policy, merge this rule, review the full JSON, and then update it.

## 10. Identity and RBAC for Retrieval

The archive worker must not use an account-wide public SAS. It needs a managed identity or service principal with least privilege to the evidence and staging containers plus permission to request a user-delegation key.

Recommended after the Azure VM exists:

```bash
export COMPUTE_RG='rg-warsoc-backend-prod'
export VM_NAME='warsoc-backend-prod'

az account set --subscription "$COMPUTE_SUBSCRIPTION_ID"
PRINCIPAL_ID="$(az vm identity assign \
  --resource-group "$COMPUTE_RG" \
  --name "$VM_NAME" \
  --query systemAssignedIdentity --output tsv)"

az account set --subscription "$STORAGE_SUBSCRIPTION_ID"
EVIDENCE_SCOPE="$(az storage account show \
  --resource-group "$STORAGE_RG" \
  --name "$EVIDENCE_ACCOUNT" \
  --query id --output tsv)"

az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role 'Storage Blob Data Contributor' \
  --scope "$EVIDENCE_SCOPE"

az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role 'Storage Blob Delegator' \
  --scope "$EVIDENCE_SCOPE"
```

Do not enable `ARCHIVE_RETRIEVAL_ENABLED=true` merely because roles were assigned. The worker, staging cleanup, user-delegation SAS, SHA-256 validation, tenant isolation, and rehydration lifecycle must all pass first.

## 11. Storage Network Boundary

The emergency migration may initially use the evidence account public endpoint with anonymous access disabled and authentication enforced. After the Azure VM public IP is known, restrict the evidence account to approved networks or implement a private endpoint.

Do not switch `--default-action Deny` until the VM and operator access paths are proven; doing so too early can stop archival. Long term, use a private endpoint and the `privatelink.blob.core.windows.net` private DNS zone.

Minimum controlled-public-endpoint sequence:

```bash
export AZURE_VM_PUBLIC_IP='<static-azure-vm-ip>'

az storage account network-rule add \
  --resource-group "$STORAGE_RG" \
  --account-name "$EVIDENCE_ACCOUNT" \
  --ip-address "$AZURE_VM_PUBLIC_IP"

az storage account update \
  --resource-group "$STORAGE_RG" \
  --name "$EVIDENCE_ACCOUNT" \
  --default-action Deny

az storage account show \
  --resource-group "$STORAGE_RG" \
  --name "$EVIDENCE_ACCOUNT" \
  --query '{publicAccess:allowBlobPublicAccess,defaultAction:networkRuleSet.defaultAction,tls:minimumTlsVersion,httpsOnly:enableHttpsTrafficOnly}' \
  --output table
```

Prove archive upload and backup upload from the Azure VM immediately after this change. Roll back the network rule, not the evidence lock, if access fails.

## 12. Environment Mapping

Do not add duration-specific variables until every referenced policy is locked and verified. Keep the existing six-year fallback unchanged during the compute migration.

```dotenv
AZURE_STORAGE_CONTAINER=warsoc-cold-storage
AZURE_IMMUTABILITY_REQUIRED=true
AZURE_IMMUTABILITY_SCOPE=container
AZURE_CONTAINER_IMMUTABILITY_LOCKED=true
AZURE_CONTAINER_IMMUTABILITY_DAYS=2190

AZURE_STORAGE_CONTAINER_FBR=warsoc-fbr-2190
AZURE_CONTAINER_IMMUTABILITY_LOCKED_FBR=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_FBR=2190

AZURE_STORAGE_CONTAINER_PECA=warsoc-peca-365
AZURE_CONTAINER_IMMUTABILITY_LOCKED_PECA=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_PECA=365

AZURE_STORAGE_CONTAINER_SIEM_90=warsoc-retention-90
AZURE_STORAGE_CONTAINER_GENERAL_90=warsoc-retention-90
AZURE_CONTAINER_IMMUTABILITY_LOCKED_SIEM_90=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_90=90
AZURE_CONTAINER_IMMUTABILITY_LOCKED_GENERAL_90=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_GENERAL_90=90

AZURE_STORAGE_CONTAINER_SIEM_180=warsoc-retention-180
AZURE_STORAGE_CONTAINER_GENERAL_180=warsoc-retention-180
AZURE_CONTAINER_IMMUTABILITY_LOCKED_SIEM_180=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_180=180
AZURE_CONTAINER_IMMUTABILITY_LOCKED_GENERAL_180=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_GENERAL_180=180

AZURE_STORAGE_CONTAINER_SIEM_270=warsoc-retention-270
AZURE_STORAGE_CONTAINER_GENERAL_270=warsoc-retention-270
AZURE_CONTAINER_IMMUTABILITY_LOCKED_SIEM_270=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_270=270
AZURE_CONTAINER_IMMUTABILITY_LOCKED_GENERAL_270=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_GENERAL_270=270

AZURE_STORAGE_CONTAINER_SIEM_360=warsoc-retention-360
AZURE_STORAGE_CONTAINER_GENERAL_360=warsoc-retention-360
AZURE_CONTAINER_IMMUTABILITY_LOCKED_SIEM_360=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_SIEM_360=360
AZURE_CONTAINER_IMMUTABILITY_LOCKED_GENERAL_360=true
AZURE_CONTAINER_IMMUTABILITY_DAYS_GENERAL_360=360

ARCHIVE_RETRIEVAL_ENABLED=false
AZURE_RETRIEVAL_STAGING_CONTAINER=warsoc-retrieval-staging
AZURE_STORAGE_ACCOUNT_URL=https://<evidence-account>.blob.core.windows.net
```

## 13. Cost and Expiry Safeguards

Create a budget alert in the temporary compute subscription. It is an alert, not an automatic continuity mechanism:

```bash
az account set --subscription "$COMPUTE_SUBSCRIPTION_ID"
az consumption budget list --output table
```

Use Cost Management in the portal to create alerts at 50%, 75%, 90%, and 100% of the available credit because budget-create CLI behavior varies by subscription/billing scope.

Operational deadlines for a credit ending on 2026-08-19:

- **2026-08-12 (T-7):** choose a commercial destination or controlled shutdown; create and verify encrypted backup.
- **2026-08-16 (T-3):** restore rehearsal in the destination and lower DNS TTL.
- **2026-08-18 (T-1):** move production or stop accepting new evidence writes.
- **2026-08-19:** do not rely on the promotional subscription remaining writable.

Serial creation of promotional accounts is not a production architecture and may conflict with offer eligibility. It also repeats DNS, identity, backup, and evidence-transfer risk. Use it only if Microsoft explicitly permits it and no paying/regulated workload is present.

## 14. Acceptance Checklist

- Correct subscription and region recorded.
- Artifact account contains only approved versioned public artifacts.
- Evidence account rejects anonymous access.
- Six immutable containers have the exact locked durations.
- Existing six-year fallback remains intact.
- Staging and backup containers are private and not governed by the FBR lock.
- Staging lifecycle cleanup is installed without deleting unrelated lifecycle rules.
- Storage firewall/private endpoint path is proven from the backend.
- Connection string and keys are stored outside Git with mode `600` on the host.
- Retrieval remains disabled until its separate acceptance test passes.
- Budget alerts and the T-7/T-3/T-1 expiry calendar are active.

## 15. Official References

- [Azure subscription states](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/subscription-states)
- [Azure spending limit behavior](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/spending-limit)
- [Configure container-scoped immutability](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-container-scope)
- [Azure Storage network security](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-set-default-access)
- [Azure Storage private endpoints](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints)
- [Create user-delegation SAS with Azure CLI](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-user-delegation-sas-create-cli)
