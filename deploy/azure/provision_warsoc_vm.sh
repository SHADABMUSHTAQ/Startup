#!/usr/bin/env bash
set -Eeuo pipefail

: "${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
: "${ADMIN_SSH_PUBLIC_KEY:?Set ADMIN_SSH_PUBLIC_KEY to an existing .pub file}"
: "${ADMIN_SOURCE_CIDR:?Set ADMIN_SOURCE_CIDR, for example 203.0.113.10/32}"

RESOURCE_GROUP="${RESOURCE_GROUP:-rg-warsoc-backend-prod}"
LOCATION="${LOCATION:-southeastasia}"
VM_NAME="${VM_NAME:-warsoc-backend-prod}"
VM_SIZE="${VM_SIZE:-Standard_F4s_v2}"
ADMIN_USER="${ADMIN_USER:-warsocops}"
VNET_NAME="${VNET_NAME:-vnet-warsoc-prod}"
SUBNET_NAME="${SUBNET_NAME:-snet-backend}"
NSG_NAME="${NSG_NAME:-nsg-warsoc-backend-prod}"
PUBLIC_IP_NAME="${PUBLIC_IP_NAME:-pip-warsoc-backend-prod}"
NIC_NAME="${NIC_NAME:-nic-warsoc-backend-prod}"
OS_DISK_GB="${OS_DISK_GB:-240}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

for command_name in az ssh-keygen; do
    command -v "${command_name}" >/dev/null 2>&1 || {
        echo "Required command is unavailable: ${command_name}" >&2
        exit 1
    }
done

[[ -f "${ADMIN_SSH_PUBLIC_KEY}" ]] || {
    echo "SSH public key not found: ${ADMIN_SSH_PUBLIC_KEY}" >&2
    exit 1
}
ssh-keygen -l -f "${ADMIN_SSH_PUBLIC_KEY}" >/dev/null
if [[ "${ADMIN_SOURCE_CIDR}" == "0.0.0.0/0" || "${ADMIN_SOURCE_CIDR}" == "::/0" ]]; then
    echo "Refusing to expose SSH to the public internet. Use an administrator /32 or controlled CIDR." >&2
    exit 1
fi

az account set --subscription "${AZURE_SUBSCRIPTION_ID}"
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" --output none
az network vnet create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VNET_NAME}" \
    --address-prefixes 10.42.0.0/16 \
    --subnet-name "${SUBNET_NAME}" \
    --subnet-prefixes 10.42.1.0/24 \
    --output none
az network nsg create --resource-group "${RESOURCE_GROUP}" --name "${NSG_NAME}" --output none

az network nsg rule create --resource-group "${RESOURCE_GROUP}" --nsg-name "${NSG_NAME}" \
    --name Allow-SSH-Admin --priority 100 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes "${ADMIN_SOURCE_CIDR}" --destination-port-ranges 22 --output none
az network nsg rule create --resource-group "${RESOURCE_GROUP}" --nsg-name "${NSG_NAME}" \
    --name Allow-HTTPS --priority 110 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes Internet --destination-port-ranges 443 --output none
az network nsg rule create --resource-group "${RESOURCE_GROUP}" --nsg-name "${NSG_NAME}" \
    --name Allow-HTTP-ACME --priority 120 --access Allow --protocol Tcp --direction Inbound \
    --source-address-prefixes Internet --destination-port-ranges 80 --output none

az network public-ip create --resource-group "${RESOURCE_GROUP}" --name "${PUBLIC_IP_NAME}" \
    --sku Standard --allocation-method Static --version IPv4 --output none
az network nic create --resource-group "${RESOURCE_GROUP}" --name "${NIC_NAME}" \
    --vnet-name "${VNET_NAME}" --subnet "${SUBNET_NAME}" \
    --network-security-group "${NSG_NAME}" --public-ip-address "${PUBLIC_IP_NAME}" --output none

az vm create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${VM_NAME}" \
    --nics "${NIC_NAME}" \
    --image Canonical:ubuntu-24_04-lts:server:latest \
    --size "${VM_SIZE}" \
    --admin-username "${ADMIN_USER}" \
    --ssh-key-values "${ADMIN_SSH_PUBLIC_KEY}" \
    --authentication-type ssh \
    --security-type TrustedLaunch \
    --enable-secure-boot true \
    --enable-vtpm true \
    --os-disk-size-gb "${OS_DISK_GB}" \
    --storage-sku Premium_LRS \
    --custom-data "${SCRIPT_DIR}/cloud-init.yml" \
    --output none

public_ip="$(az network public-ip show --resource-group "${RESOURCE_GROUP}" --name "${PUBLIC_IP_NAME}" --query ipAddress -o tsv)"
echo "Azure WarSOC VM provisioned."
echo "Public IP: ${public_ip}"
echo "SSH: ssh ${ADMIN_USER}@${public_ip}"
echo "MongoDB, Redis, and FastAPI ports were not opened in the Azure NSG."
