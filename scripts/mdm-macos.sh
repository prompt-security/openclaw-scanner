#!/bin/sh
# OpenClaw Scanner — MDM deployment script for macOS
# Designed for Jamf Pro, Microsoft Intune, or any MDM that runs shell scripts as root.
#
# This script:
#   1. Detects macOS architecture (arm64 / x86_64)
#   2. Downloads the latest scanner binary from GitHub releases
#   3. Runs the scanner as each local user
#   4. Reports results to the Prompt Security dashboard via API key
#
# The API key must be set in the environment before calling this script:
#   export SCANNER_REPORT_API_KEY="your-key-here"
#
# Usage (standalone):
#   export SCANNER_REPORT_API_KEY="sk-..."
#   curl -fsSL -o /tmp/mdm-macos.sh https://github.com/prompt-security/openclaw-scanner/releases/latest/download/mdm-macos.sh
#   sh /tmp/mdm-macos.sh
#
# Usage (MDM bootstrap — paste this into your MDM script field):
#   #!/bin/sh
#   export SCANNER_REPORT_API_KEY="YOUR_API_KEY_HERE"
#   curl -fsSL -o /tmp/mdm-macos.sh https://github.com/prompt-security/openclaw-scanner/releases/latest/download/mdm-macos.sh
#   sh /tmp/mdm-macos.sh

set -eu

# --- Validate API key ---
if [ -z "${SCANNER_REPORT_API_KEY:-}" ]; then
    echo "ERROR: SCANNER_REPORT_API_KEY environment variable is not set." >&2
    echo "Set it before running this script: export SCANNER_REPORT_API_KEY=\"your-key\"" >&2
    exit 1
fi

# --- Detect platform and architecture ---
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  ASSET="openclaw-scanner-macos-arm64" ;;
      x86_64) ASSET="openclaw-scanner-macos-x64" ;;
      *)
        echo "ERROR: Unsupported macOS architecture: $ARCH" >&2
        exit 1
        ;;
    esac
    ;;
  Linux)
    ASSET="openclaw-scanner-linux-x64"
    ;;
  *)
    echo "ERROR: Unsupported OS: $OS (expected Darwin or Linux)" >&2
    exit 1
    ;;
esac

REPO="prompt-security/openclaw-scanner"
OUT="/tmp/openclaw-scanner"

# --- Download scanner binary ---
echo "Downloading $ASSET..."
curl -fsSL -o "$OUT" \
  "https://github.com/$REPO/releases/latest/download/$ASSET"

chmod +x "$OUT"

# Remove macOS quarantine flag if present
[ "$OS" = Darwin ] && xattr -d com.apple.quarantine "$OUT" 2>/dev/null || true

# --- Run scanner per user ---
if [ "$(id -u)" -eq 0 ]; then
    # Running as root — enumerate and scan all users
    if [ "$OS" = "Darwin" ]; then
        users=$(dscl . -list /Users UniqueID | awk '$2 >= 500 && $1 !~ /^_/ { print $1 }')
    else
        users=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }')
    fi

    scanned=0
    failed=0
    for user in $users; do
        echo "Scanning user: $user"
        su - "$user" <<EOF || { echo "  WARNING: scan failed for user $user"; failed=$((failed + 1)); continue; }
export SCANNER_REPORT_API_KEY="$SCANNER_REPORT_API_KEY"
"$OUT"
EOF
        scanned=$((scanned + 1))
    done
    echo ""
    echo "Scan complete. Users scanned: $scanned, failures: $failed"
else
    # Running as regular user — scan current user only
    echo "Scanning current user: $(whoami)"
    "$OUT"
fi
