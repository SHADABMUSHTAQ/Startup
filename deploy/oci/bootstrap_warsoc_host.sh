#!/usr/bin/env bash
set -Eeuo pipefail

readonly EXPECTED_OS_ID="ubuntu"
readonly EXPECTED_OS_VERSION="22.04"
readonly EXPECTED_ARCH="arm64"
readonly DOCKER_KEYRING="/etc/apt/keyrings/docker.asc"
readonly DOCKER_SOURCE="/etc/apt/sources.list.d/docker.sources"
readonly FIREWALL_SCRIPT="/usr/local/sbin/warsoc-docker-firewall"
readonly FIREWALL_SERVICE="/etc/systemd/system/warsoc-docker-firewall.service"

log() {
    printf '[WarSOC OCI bootstrap] %s\n' "$*"
}

fail() {
    printf '[WarSOC OCI bootstrap] ERROR: %s\n' "$*" >&2
    exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this script as root: sudo bash $0"
fi

if [[ ! -r /etc/os-release ]]; then
    fail "/etc/os-release is unavailable."
fi

# shellcheck disable=SC1091
source /etc/os-release

[[ "${ID:-}" == "${EXPECTED_OS_ID}" ]] || fail "Expected Ubuntu; found ${ID:-unknown}."
[[ "${VERSION_ID:-}" == "${EXPECTED_OS_VERSION}" ]] || fail "Expected Ubuntu 22.04; found ${VERSION_ID:-unknown}."

host_arch="$(dpkg --print-architecture)"
[[ "${host_arch}" == "${EXPECTED_ARCH}" ]] || fail "Expected ARM64; found ${host_arch}."

cpu_count="$(nproc)"
(( cpu_count >= 4 )) || fail "Expected at least 4 OCPU; found ${cpu_count}."

memory_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
(( memory_kb >= 20971520 )) || fail "Expected at least 20 GiB usable RAM."

root_total_kb="$(df --output=size / | tail -n 1 | tr -d ' ')"
(( root_total_kb >= 41943040 )) || fail "Expected a root volume of at least 40 GiB."

root_free_kb="$(df --output=avail / | tail -n 1 | tr -d ' ')"
if (( root_free_kb < 15728640 )); then
    fail "Less than 15 GiB is free on /. Expand or clean the OCI boot volume first."
fi

export DEBIAN_FRONTEND=noninteractive

log "Updating Ubuntu packages."
apt-get update
apt-get upgrade -y

log "Installing host prerequisites."
apt-get install -y --no-install-recommends \
    ca-certificates \
    certbot \
    curl \
    git \
    iptables \
    jq \
    openssl \
    rsync \
    ufw

# Remove distribution packages that conflict with Docker CE. This is safe to
# repeat because Docker CE uses the containerd.io package, not containerd.
for package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "${package}" 2>/dev/null | grep -q '^ii'; then
        apt-get remove -y "${package}"
    fi
done

log "Configuring Docker's official Ubuntu repository for ${host_arch}."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "${DOCKER_KEYRING}"
chmod a+r "${DOCKER_KEYRING}"

cat >"${DOCKER_SOURCE}" <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: ${host_arch}
Signed-By: ${DOCKER_KEYRING}
EOF

apt-get update
apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

systemctl enable --now containerd.service docker.service

# Redis background persistence can fail even with free RAM when Linux memory
# overcommit is disabled. Persist the required setting across OCI reboots.
cat >/etc/sysctl.d/60-warsoc-redis.conf <<'EOF'
vm.overcommit_memory = 1
EOF
sysctl --system >/dev/null

login_user="${SUDO_USER:-ubuntu}"
if id "${login_user}" >/dev/null 2>&1 && [[ "${login_user}" != "root" ]]; then
    usermod -aG docker "${login_user}"
fi

log "Applying the host firewall policy."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'WarSOC SSH'
ufw allow 80/tcp comment 'WarSOC HTTP'
ufw allow 443/tcp comment 'WarSOC HTTPS'
ufw deny 6379/tcp comment 'Block public Redis'
ufw deny 27017/tcp comment 'Block public MongoDB'
ufw --force enable

# Docker-published traffic is processed before ordinary UFW INPUT rules. Keep
# a separate DOCKER-USER guard on the public interface. Restricting by ingress
# interface preserves traffic inside WarSOC's private Docker bridge.
cat >"${FIREWALL_SCRIPT}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

public_interface="$(ip -4 route show default | awk 'NR == 1 {print $5}')"
if [[ -z "${public_interface}" ]]; then
    printf 'Unable to determine the public interface.\n' >&2
    exit 1
fi

ensure_drop_rule() {
    local command="$1"
    local protocol="$2"
    local port="$3"

    if ! "${command}" -nL DOCKER-USER >/dev/null 2>&1; then
        return 0
    fi

    if ! "${command}" -C DOCKER-USER -i "${public_interface}" -p "${protocol}" --dport "${port}" -j DROP 2>/dev/null; then
        "${command}" -I DOCKER-USER 1 -i "${public_interface}" -p "${protocol}" --dport "${port}" -j DROP
    fi
}

for blocked_tcp_port in 6379 27017 8000 8443; do
    ensure_drop_rule iptables tcp "${blocked_tcp_port}"
    if command -v ip6tables >/dev/null 2>&1; then
        ensure_drop_rule ip6tables tcp "${blocked_tcp_port}"
    fi
done

ensure_drop_rule iptables udp 5140
if command -v ip6tables >/dev/null 2>&1; then
    ensure_drop_rule ip6tables udp 5140
fi
EOF
chmod 0755 "${FIREWALL_SCRIPT}"

cat >"${FIREWALL_SERVICE}" <<EOF
[Unit]
Description=WarSOC Docker public-port firewall guard
Requires=docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=${FIREWALL_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now warsoc-docker-firewall.service

log "Verifying the host bootstrap."
[[ "$(systemctl is-active docker.service)" == "active" ]] || fail "Docker is not active."
[[ "$(systemctl is-enabled docker.service)" == "enabled" ]] || fail "Docker is not enabled at boot."
[[ "$(systemctl is-active warsoc-docker-firewall.service)" == "active" ]] || fail "Docker firewall guard is not active."

docker version --format 'Docker server: {{.Server.Version}} ({{.Server.Arch}})'
docker compose version
printf 'Host resources: %s OCPU, %s GiB RAM, %s GiB root volume\n' \
    "${cpu_count}" \
    "$((memory_kb / 1024 / 1024))" \
    "$((root_total_kb / 1024 / 1024))"
ufw status verbose
iptables -S DOCKER-USER

if ss -lntH | awk '{print $4}' | grep -Eq '(^|:)(6379|27017)$'; then
    fail "Redis or MongoDB is listening on a host TCP socket."
fi

if [[ -f /var/run/reboot-required ]]; then
    log "A reboot is required by Ubuntu updates. Reboot before deploying WarSOC."
fi

apt-get clean
log "Bootstrap complete. Sign out and reconnect before using Docker without sudo."
