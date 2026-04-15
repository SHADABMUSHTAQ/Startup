$ErrorActionPreference = 'Continue'

$archiveRoot = ".archive\legacy_tests"
$destructiveRoot = ".archive\destructive_scripts"

if (-not (Test-Path $archiveRoot)) { New-Item -ItemType Directory -Force -Path $archiveRoot | Out-Null }
if (-not (Test-Path $destructiveRoot)) { New-Item -ItemType Directory -Force -Path $destructiveRoot | Out-Null }

Write-Output "Archive roots: $archiveRoot  (legacy), $destructiveRoot (destructive)"

# Move malformed capture logs at repo root
Get-ChildItem -Path . -Filter "malformed_capture_*.log" -File -ErrorAction SilentlyContinue | ForEach-Object {
    $rel = $_.Name
    Write-Output "Processing log: $rel"
    try {
        git ls-files --error-unmatch $rel 2>$null
        if ($LASTEXITCODE -eq 0) { git mv $rel $archiveRoot; Write-Output "git mv $rel -> $archiveRoot" } else { Move-Item $rel $archiveRoot -Force; Write-Output "Move-Item $rel -> $archiveRoot" }
    } catch {
        Move-Item $rel $archiveRoot -Force
        Write-Output "Fallback Move-Item $rel -> $archiveRoot"
    }
}

# Files and dirs to archive
$files = @(
    "smoke_out.txt",
    "package-lock.json"
)

$dirs = @("tmp","spool")

foreach ($f in $files) {
    if (Test-Path $f) {
        Write-Output "Processing file: $f"
        try {
            git ls-files --error-unmatch $f 2>$null
            if ($LASTEXITCODE -eq 0) { git mv $f $archiveRoot; Write-Output "git mv $f -> $archiveRoot" } else { Move-Item $f $archiveRoot -Force; Write-Output "Move-Item $f -> $archiveRoot" }
        } catch {
            Move-Item $f $archiveRoot -Force
            Write-Output "Fallback Move-Item $f -> $archiveRoot"
        }
    } else {
        Write-Output "Not found: $f"
    }
}

foreach ($d in $dirs) {
    if (Test-Path $d) {
        Write-Output "Processing dir: $d"
        try {
            git ls-files --error-unmatch $d 2>$null
            if ($LASTEXITCODE -eq 0) { git mv $d $archiveRoot; Write-Output "git mv $d -> $archiveRoot" } else { Move-Item $d $archiveRoot -Force; Write-Output "Move-Item $d -> $archiveRoot" }
        } catch {
            Move-Item $d $archiveRoot -Force
            Write-Output "Fallback Move-Item $d -> $archiveRoot"
        }
    } else {
        Write-Output "Not found: $d"
    }
}

# Script files to archive (non-destructive)
$scriptFiles = @(
    "scripts/attack_battery.py",
    "scripts/load_http.py",
    "scripts/load_pipeline.py",
    "scripts/run_load_http_with_env.py",
    "scripts/seed_mongo_user.py",
    "scripts/seed_redis.py",
    "scripts/insert_signed_peca.py",
    "scripts/tmp_login.json",
    "scripts/tmp_signup.json",
    "scripts/auth_test.py",
    "scripts/test_auth.py",
    "scripts/integration_auth_check.py",
    "scripts/check_log_age.py",
    "scripts/check_logs.py",
    "scripts/fast_diag.py"
)

foreach ($p in $scriptFiles) {
    if (Test-Path $p) {
        Write-Output "Processing script: $p"
        try {
            git ls-files --error-unmatch $p 2>$null
            if ($LASTEXITCODE -eq 0) { git mv $p $archiveRoot; Write-Output "git mv $p -> $archiveRoot" } else { Move-Item $p $archiveRoot -Force; Write-Output "Move-Item $p -> $archiveRoot" }
        } catch {
            Move-Item $p $archiveRoot -Force
            Write-Output "Fallback Move-Item $p -> $archiveRoot"
        }
    } else { Write-Output "Not found: $p" }
}

# Destructive scripts - move to destructive archive
$destructive = @(
    "scripts/clean_slate.py",
    "scripts/final_cleanup.py",
    "scripts/purge_test_data.py"
)

foreach ($p in $destructive) {
    if (Test-Path $p) {
        Write-Output "Processing DESTRUCTIVE script: $p"
        try {
            git ls-files --error-unmatch $p 2>$null
            if ($LASTEXITCODE -eq 0) { git mv $p $destructiveRoot; Write-Output "git mv $p -> $destructiveRoot" } else { Move-Item $p $destructiveRoot -Force; Write-Output "Move-Item $p -> $destructiveRoot" }
        } catch {
            Move-Item $p $destructiveRoot -Force
            Write-Output "Fallback Move-Item $p -> $destructiveRoot"
        }
    } else { Write-Output "Not found: $p" }
}

# Stage and commit changes if any
Write-Output "Staging changes..."
try {
    git add -A
    $status = git status --porcelain
    if ($status) {
        git commit -m "Archive deprecated test & junk files to .archive"
        Write-Output "Committed archive changes."
    } else {
        Write-Output "No changes to commit."
    }
} catch {
    Write-Output "Git commit failed or git not available: $_"
}

# Append .gitignore entries (only if not present)
$gitignore = ".gitignore"
$entries = @("/.archive/","/tmp/","/spool/","package-lock.json")
if (-not (Test-Path $gitignore)) { New-Item -Path $gitignore -ItemType File -Force | Out-Null }
$existing = Get-Content $gitignore -ErrorAction SilentlyContinue
foreach ($e in $entries) {
    if ($existing -notcontains $e) { Add-Content -Path $gitignore -Value $e; Write-Output "Added to .gitignore: $e" }
}

# Commit .gitignore update
try {
    git add .gitignore
    $status2 = git status --porcelain
    if ($status2) {
        git commit -m "Ignore archives and temp dirs (.gitignore)"
        Write-Output "Committed .gitignore updates."
    } else {
        Write-Output "No .gitignore changes to commit."
    }
} catch {
    Write-Output "Git commit for .gitignore failed or git not available: $_"
}

Write-Output "Archive script completed."
