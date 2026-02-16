# OpenClaw Scanner

Scan and analyze OpenClaw/Moltbot installations — and compatible variants **nanobot** and **picoclaw** — for usage patterns, active skills, and configuration status.

## Overview

OpenClaw Scanner auto-detects which variant is installed and collects information about:

- Active skills and their configurations
- Session logs and tools/apps usage
- Cron jobs, plugins, channels, nodes, and models
- Provider configurations and API key status
- Security audit results

Supports macOS and Linux.

### Supported Variants

| Variant | Language | Config Dir |
|---------|----------|------------|
| **OpenClaw** | Node.js | `~/.openclaw/` |
| **Clawdbot** | Node.js | `~/.clawdbot/` |
| **Moltbot** | Node.js | `~/.moltbot/` |
| **picoclaw** | Go | `~/.picoclaw/` |
| **nanobot** | Python | `~/.nanobot/` |

## Installation

### Option 1: Standalone Executable

Download from [Releases](https://github.com/prompt-security/openclaw-scanner/releases):

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `openclaw-scanner-macos-arm64` |
| macOS (Intel) | `openclaw-scanner-macos-x64` |
| Linux (x64) | `openclaw-scanner-linux-x64` |

On macOS, remove quarantine before first run:

```bash
chmod +x openclaw-scanner-macos-arm64
xattr -d com.apple.quarantine openclaw-scanner-macos-arm64
```

### Option 2: Python Package

Requires Python 3.9+

```bash
pip install openclaw_scanner-0.1.0-py3-none-any.whl
```

## Usage

```bash
openclaw-scanner [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--cli PATH` | Specify CLI command or path (auto-detects by default) |
| `--scanner-report-api-key KEY` | API key for sending report to server (or set `SCANNER_REPORT_API_KEY` env variable) |
| `--compact` | Output compact JSON (no indentation) |
| `--full` | Include full details in output |
| `--limit N` | Limit recent tool calls in output (default: 50) |

### Examples

```bash
# Run with auto-detection
openclaw-scanner

# Specify CLI path explicitly
openclaw-scanner --cli /usr/local/bin/openclaw

# Compact output for piping
openclaw-scanner --compact | jq .
```

## Output

Returns JSON with the following fields:

| Field | Description |
|-------|-------------|
| `openclaw_path` | Path to `.openclaw` folder |
| `cli_command` | Detected CLI command |
| `active_skills` | Active skills and configurations |
| `cron_jobs` | Scheduled jobs |
| `security_audit` | Security audit results |
| `plugins` | Installed plugins |
| `channels` | Configured channels |
| `nodes` | Available nodes |
| `models` | Available models |
| `session_analysis` | Usage statistics from session logs |

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Developed by [Prompt Security](https://prompt.security), a SentinelOne company.
