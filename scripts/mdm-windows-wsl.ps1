<#
.SYNOPSIS
    OpenClaw Scanner — MDM deployment script for Windows (WSL scanning).

.DESCRIPTION
    Designed for Microsoft Intune or any MDM that runs PowerShell scripts.

    This script:
      1. Checks if WSL is available
      2. Enumerates all WSL distributions for the current user
      3. Downloads the latest Linux scanner binary into each distro
      4. Runs the scanner as each Linux user within each distro
      5. Reports results to the Prompt Security dashboard via API key

    The API key must be set in the environment before calling this script:
      $env:SCANNER_REPORT_API_KEY = "your-key-here"

    MDM bootstrap — paste this into your Intune script field:
      $env:SCANNER_REPORT_API_KEY = "YOUR_API_KEY_HERE"
      Invoke-WebRequest -Uri "https://github.com/prompt-security/openclaw-scanner/releases/latest/download/mdm-windows-wsl.ps1" -OutFile "$env:TEMP\scan-openclaw.ps1"
      & "$env:TEMP\scan-openclaw.ps1"

.NOTES
    Intune Configuration:
    - Run this script using the logged on credentials: Yes
    - Enforce script signature check: No
    - Run script in 64-bit PowerShell: Yes
#>

# --- Validate API key ---
$SCANNER_REPORT_API_KEY = $env:SCANNER_REPORT_API_KEY
if (-not $SCANNER_REPORT_API_KEY) {
    Write-Error "SCANNER_REPORT_API_KEY environment variable is not set."
    Write-Error "Set it before running: `$env:SCANNER_REPORT_API_KEY = 'your-key'"
    exit 1
}

$REPO = "prompt-security/openclaw-scanner"

# --- Check WSL availability ---
$wslPath = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wslPath) {
    Write-Output "WSL is not installed on this machine. Nothing to scan."
    exit 0
}

# --- Enumerate WSL distros ---
# wsl --list --quiet may output UTF-16 with null bytes; clean them up
$rawOutput = & wsl.exe --list --quiet 2>&1
if ($LASTEXITCODE -ne 0 -or -not $rawOutput) {
    Write-Output "No WSL distributions found for current user."
    exit 0
}

$distros = ($rawOutput | Out-String) -replace "`0", "" -split "`r`n|`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" }

if ($distros.Count -eq 0) {
    Write-Output "No WSL distributions found for current user."
    exit 0
}

Write-Output "Found $($distros.Count) WSL distribution(s): $($distros -join ', ')"
Write-Output ""

$scanSuccess = 0
$scanFail = 0

foreach ($distro in $distros) {
    Write-Output "=== Scanning distro: $distro ==="

    # Detect architecture inside WSL
    $archRaw = & wsl.exe -d $distro -- uname -m 2>&1
    $arch = ($archRaw | Out-String).Trim() -replace "`0", ""

    switch ($arch) {
        "x86_64" { $asset = "openclaw-scanner-linux-x64" }
        default {
            Write-Output "  Unsupported architecture: $arch (only x86_64 supported) - skipping"
            continue
        }
    }

    $downloadUrl = "https://github.com/$REPO/releases/latest/download/$asset"
    $scannerPath = "/tmp/openclaw-scanner"

    # Download scanner binary inside WSL
    Write-Output "  Downloading scanner ($asset)..."
    & wsl.exe -d $distro -- bash -c "curl -fsSL -o '$scannerPath' '$downloadUrl' && chmod +x '$scannerPath'" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Output "  ERROR: Failed to download scanner in distro: $distro"
        $scanFail++
        continue
    }

    # Enumerate Linux users (UID >= 1000, < 65534)
    $usersRaw = & wsl.exe -d $distro -- bash -c "getent passwd | awk -F: '`$3 >= 1000 && `$3 < 65534 { print `$1 }'" 2>&1
    $users = ($usersRaw | Out-String) -replace "`0", "" -split "`r`n|`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne "" }

    if ($users.Count -eq 0) {
        Write-Output "  No regular users found in distro: $distro - skipping"
        continue
    }

    foreach ($user in $users) {
        Write-Output "  Scanning user: $user"
        & wsl.exe -d $distro -u $user -- bash -c "export SCANNER_REPORT_API_KEY='$SCANNER_REPORT_API_KEY'; '$scannerPath'" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Output "  Scanner returned exit code $LASTEXITCODE for user: $user"
            $scanFail++
        }
        else {
            Write-Output "  OK: scan complete for user: $user"
            $scanSuccess++
        }
    }
}

Write-Output ""
Write-Output "Scan finished. Success: $scanSuccess, Failures: $scanFail"
exit 0
