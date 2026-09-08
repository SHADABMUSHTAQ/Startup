from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "provision_azure_retention.ps1"


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_script_has_approved_duration_allowlist_and_legacy_guard():
    source = _source()

    assert "$approvedRetentionDays = @(90, 180, 270, 365)" in source
    assert '"warsoc-siem-$RetentionDays"' in source
    assert '"warsoc-general-$RetentionDays"' in source
    assert "$RetentionDays -notin $approvedRetentionDays" in source
    assert '$legacyContainer = "warsoc-cold-storage"' in source
    assert "$legacyResource = Get-ContainerResource -ContainerName $legacyContainer" in source
    assert "legacy_container_mutated = $false" in source
    assert "migrate-vlw" not in source


def test_script_defaults_to_read_only_and_separates_irreversible_lock():
    source = _source()

    assert '[string]$Mode = "Inspect"' in source
    assert '[ValidateSet("Inspect", "Prepare", "Verify", "Lock")]' in source
    assert '"LOCK-WARSOC-$RetentionDays-DAY-RETENTION"' in source
    assert 'if ($Mode -eq "Lock"' in source
    assert '"--if-match", [string]$row.policy_etag' in source
    assert '$ErrorActionPreference = "Continue"' in source
    assert "PSNativeCommandUseErrorActionPreference" in source
    assert 'ConvertFrom-Json -DateKind String' in source


def test_prepare_contract_is_private_versioned_cold_and_non_overwriting():
    source = _source()

    required_fragments = (
        '[version]"2.27.0"',
        '"--enable-versioning", "true"',
        '"--enable-vlw", "true"',
        '"--public-access", "off"',
        '"--fail-on-exist"',
        '"--period", "$RetentionDays"',
        '"--tier", "Cold"',
        '"--auth-mode", "login"',
        '"--overwrite", "false"',
        "versionId",
        "Get-FileHash",
    )
    for fragment in required_fragments:
        assert fragment in source

    assert '"--fail-on-exist", "true"' not in source


def test_report_emits_complete_exact_route_activation_contract():
    source = _source()

    assert '"AZURE_STORAGE_CONTAINER_${retentionClass}_$RetentionDays"' in source
    assert '"AZURE_STORAGE_TIER_${retentionClass}_$RetentionDays"' in source
    assert '"AZURE_IMMUTABILITY_SCOPE_${retentionClass}_$RetentionDays"' in source
    assert '"AZURE_CONTAINER_IMMUTABILITY_LOCKED_${retentionClass}_$RetentionDays"' in source
    assert '"AZURE_CONTAINER_IMMUTABILITY_DAYS_${retentionClass}_$RetentionDays"' in source
    assert '] = "blob"' in source


def test_script_contains_no_cloud_delete_or_secret_auth_path():
    source = _source().lower()

    forbidden = (
        '"storage", "container-rm", "delete"',
        '"storage", "container", "delete"',
        '"storage", "blob", "delete"',
        "connection-string",
        "account-key",
        "sas-token",
        '"--overwrite", "true"',
    )
    for fragment in forbidden:
        assert fragment not in source
