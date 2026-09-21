from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "docker-compose.wazuh-compute-b.yml"
MANAGER_CONFIG_PATH = ROOT / "deploy" / "wazuh" / "manager" / "ossec-manager-only.conf"
AGENT_CONFIGURATION_PATH = ROOT / "scripts" / "configure_wazuh_sca_agent.ps1"
HOST_BOOTSTRAP_PATH = ROOT / "deploy" / "oci" / "bootstrap_warsoc_host.sh"


def _compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_manager_is_pinned_private_persistent_and_bounded():
    compose = _compose()
    manager = compose["services"]["wazuh-manager"]
    config_init = compose["services"]["wazuh-manager-config-init"]
    assert manager["image"].startswith("wazuh/wazuh-manager:4.14.7@sha256:")
    assert manager["ports"] == [
        "${WAZUH_AGENT_BIND_IP:?WAZUH_AGENT_BIND_IP is required}:1514:1514/tcp"
    ]
    assert manager["restart"] == "unless-stopped"
    assert manager["healthcheck"]["test"][0] == "CMD-SHELL"
    assert manager["deploy"]["resources"]["limits"] == {
        "cpus": "1.50",
        "memory": "2G",
        "pids": 512,
    }
    destinations = {entry.split(":", 1)[1] for entry in manager["volumes"] if not entry.startswith("./")}
    assert "/var/ossec/etc" in destinations
    assert "/var/ossec/logs" in destinations
    assert "/var/ossec/queue" in destinations
    assert config_init["restart"] == "no"
    assert config_init["user"] == "0:0"
    assert "warsoc_wazuh_manager_etc:/target" in config_init["volumes"]
    assert manager["depends_on"]["wazuh-manager-config-init"]["condition"] == "service_completed_successfully"
    assert "./deploy/wazuh/rules:/var/ossec/etc/warsoc-rules:ro" in manager["volumes"]


def test_manager_config_accepts_bridge_projection_and_pre_enrolled_secure_agents():
    config = MANAGER_CONFIG_PATH.read_text(encoding="utf-8")
    assert "<port>15140</port>" in config
    assert "<protocol>tcp</protocol>" in config
    assert "<allowed-ips>172.31.40.20</allowed-ips>" in config
    assert "<local_ip>172.31.40.10</local_ip>" in config
    assert "<connection>secure</connection>" in config
    assert "<port>1514</port>" in config
    assert "<queue_size>131072</queue_size>" in config
    assert "<port>1515</port>" not in config
    assert "<auth>\n    <disabled>yes</disabled>" in config
    assert "<email_notification>no</email_notification>" in config
    assert "<logall>no</logall>" in config
    assert "<logall_json>no</logall_json>" in config
    assert "<active-response>" not in config
    assert "<disabled>yes</disabled>" in config
    assert "<rule_dir>etc/warsoc-rules</rule_dir>" in config


def test_bridge_is_mtls_private_and_uses_the_manager_alert_volume():
    compose = _compose()
    bridge = compose["services"]["warsoc-wazuh-bridge"]
    assert bridge["ports"] == [
        "${WAZUH_BRIDGE_BIND_IP:?WAZUH_BRIDGE_BIND_IP is required}:${WAZUH_BRIDGE_PORT:-9443}:8020"
    ]
    assert bridge["environment"]["WAZUH_BRIDGE_MANAGER_HOST"] == "wazuh.manager"
    assert "--ssl-cert-reqs" in bridge["command"]
    assert "2" in bridge["command"]
    assert "warsoc_wazuh_manager_logs:/var/ossec/logs:ro" in bridge["volumes"]
    assert (
        "./deploy/wazuh/registry/warsoc-projected-shadow-v3.json:"
        "/etc/warsoc-wazuh/rule-registry.json:ro"
    ) in bridge["volumes"]
    assert bridge["networks"]["wazuh_compute_b_private"]["ipv4_address"] == "172.31.40.20"
    assert compose["networks"]["wazuh_compute_b_private"]["internal"] is True


def test_indexer_dashboard_bundled_agent_and_enrollment_port_are_absent():
    services = _compose()["services"]
    assert "wazuh-indexer" not in services
    assert "wazuh-dashboard" not in services
    assert "wazuh-agent" not in services
    assert all(":1515:" not in item for item in services["wazuh-manager"]["ports"])
    assert all("0.0.0.0" not in item for item in services["wazuh-manager"]["ports"])
    assert (ROOT / "deploy" / "wazuh" / "manager" / "filebeat.down").is_file()


def test_native_agent_operator_path_does_not_accept_a_plaintext_key_argument():
    script = AGENT_CONFIGURATION_PATH.read_text(encoding="utf-8")
    assert "[string]$EnrollmentKeyPath" in script
    assert "[string]$EnrollmentKey," not in script
    assert "Get-Content -LiteralPath $EnrollmentKeyPath -Raw" in script
    assert "Remove-Item -LiteralPath $EnrollmentKeyPath -Force" in script
    assert "Run this script from an elevated PowerShell window." in script


def test_host_firewall_blocks_native_wazuh_ports_on_the_public_interface():
    script = HOST_BOOTSTRAP_PATH.read_text(encoding="utf-8")
    assert "for blocked_tcp_port in 1514 1515 6379 9443 27017 8000 8443" in script
