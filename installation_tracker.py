#!/usr/bin/env python3
"""
Installation Tracker for clawbot/moltbot/openclaw
Detects installations, active status, and connection resources.
"""

import argparse
import glob
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from platform_compat import compat
from structures import (
    AccessedApp,
    AccessedAppsSummary,
    ApiKeyInfo,
    Integration,
    ScanResult,
    ServiceStats,
    SkillInfo,
    ToolConfig,
    WorkspaceLibrary,
)


# Try to import yaml, fallback to basic parsing if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Configuration - Add your API key here (or set SCANNER_REPORT_API_KEY env variable)
SCANNER_REPORT_API_KEY = os.environ.get("SCANNER_REPORT_API_KEY", "YOUR_API_KEY_HERE")

# Known services/apps for categorization
KNOWN_SERVICES = {
    # AI/ML Services
    "anthropic": {"name": "Anthropic Claude", "category": "AI/ML"},
    "openai": {"name": "OpenAI", "category": "AI/ML"},
    "api.openai.com": {"name": "OpenAI API", "category": "AI/ML"},
    "api.anthropic.com": {"name": "Anthropic API", "category": "AI/ML"},
    "huggingface": {"name": "Hugging Face", "category": "AI/ML"},
    "cohere": {"name": "Cohere", "category": "AI/ML"},
    "replicate": {"name": "Replicate", "category": "AI/ML"},
    "palm": {"name": "Google PaLM", "category": "AI/ML"},
    "gemini": {"name": "Google Gemini", "category": "AI/ML"},
    "vertex": {"name": "Google Vertex AI", "category": "AI/ML"},
    "bedrock": {"name": "AWS Bedrock", "category": "AI/ML"},
    "azure.openai": {"name": "Azure OpenAI", "category": "AI/ML"},

    # Cloud Providers
    "amazonaws.com": {"name": "AWS", "category": "Cloud"},
    "aws": {"name": "AWS", "category": "Cloud"},
    "s3.": {"name": "AWS S3", "category": "Cloud Storage"},
    "ec2.": {"name": "AWS EC2", "category": "Cloud Compute"},
    "lambda.": {"name": "AWS Lambda", "category": "Cloud Compute"},
    "azure": {"name": "Microsoft Azure", "category": "Cloud"},
    "blob.core.windows": {"name": "Azure Blob Storage", "category": "Cloud Storage"},
    "googleapis.com": {"name": "Google Cloud", "category": "Cloud"},
    "storage.googleapis": {"name": "Google Cloud Storage", "category": "Cloud Storage"},
    "digitalocean": {"name": "DigitalOcean", "category": "Cloud"},

    # Version Control
    "github.com": {"name": "GitHub", "category": "Version Control"},
    "api.github.com": {"name": "GitHub API", "category": "Version Control"},
    "gitlab": {"name": "GitLab", "category": "Version Control"},
    "bitbucket": {"name": "Bitbucket", "category": "Version Control"},

    # Databases
    "mongodb": {"name": "MongoDB", "category": "Database"},
    "postgres": {"name": "PostgreSQL", "category": "Database"},
    "mysql": {"name": "MySQL", "category": "Database"},
    "redis": {"name": "Redis", "category": "Database"},
    "elasticsearch": {"name": "Elasticsearch", "category": "Database"},
    "dynamodb": {"name": "AWS DynamoDB", "category": "Database"},
    "firestore": {"name": "Google Firestore", "category": "Database"},
    "supabase": {"name": "Supabase", "category": "Database"},

    # Calendar Services
    "calendar": {"name": "Calendar Service", "category": "Calendar"},
    "google.com/calendar": {"name": "Google Calendar", "category": "Calendar"},
    "calendar.google.com": {"name": "Google Calendar", "category": "Calendar"},
    "googleapis.com/calendar": {"name": "Google Calendar API", "category": "Calendar"},
    "www.googleapis.com/calendar": {"name": "Google Calendar API", "category": "Calendar"},
    "outlook.office.com/calendar": {"name": "Outlook Calendar", "category": "Calendar"},
    "outlook.office365.com": {"name": "Microsoft 365 Calendar", "category": "Calendar"},
    "graph.microsoft.com": {"name": "Microsoft Graph API", "category": "Calendar"},
    "calendly": {"name": "Calendly", "category": "Calendar"},
    "calendly.com": {"name": "Calendly", "category": "Calendar"},
    "api.calendly.com": {"name": "Calendly API", "category": "Calendar"},
    "cal.com": {"name": "Cal.com", "category": "Calendar"},
    "ical": {"name": "iCalendar", "category": "Calendar"},
    "caldav": {"name": "CalDAV", "category": "Calendar"},
    "webcal": {"name": "Web Calendar", "category": "Calendar"},
    "nylas": {"name": "Nylas Calendar", "category": "Calendar"},
    "cronofy": {"name": "Cronofy", "category": "Calendar"},
    "timekit": {"name": "Timekit", "category": "Calendar"},
    "acuityscheduling": {"name": "Acuity Scheduling", "category": "Calendar"},
    "doodle": {"name": "Doodle", "category": "Calendar"},
    "eventbrite": {"name": "Eventbrite", "category": "Calendar"},
    "meetup": {"name": "Meetup", "category": "Calendar"},
    "zoom": {"name": "Zoom", "category": "Calendar"},
    "teams.microsoft": {"name": "Microsoft Teams", "category": "Calendar"},
    "meet.google": {"name": "Google Meet", "category": "Calendar"},

    # Note-taking / Knowledge Management
    "obsidian": {"name": "Obsidian", "category": "Notes"},
    "obsidian.md": {"name": "Obsidian", "category": "Notes"},
    "sync.obsidian.md": {"name": "Obsidian Sync", "category": "Notes"},
    "publish.obsidian.md": {"name": "Obsidian Publish", "category": "Notes"},
    "api.obsidian.md": {"name": "Obsidian API", "category": "Notes"},
    "roam": {"name": "Roam Research", "category": "Notes"},
    "roamresearch": {"name": "Roam Research", "category": "Notes"},
    "logseq": {"name": "Logseq", "category": "Notes"},
    "evernote": {"name": "Evernote", "category": "Notes"},
    "onenote": {"name": "OneNote", "category": "Notes"},
    "bear": {"name": "Bear Notes", "category": "Notes"},
    "craft": {"name": "Craft", "category": "Notes"},
    "apple.notes": {"name": "Apple Notes", "category": "Notes"},
    "standardnotes": {"name": "Standard Notes", "category": "Notes"},
    "simplenote": {"name": "Simplenote", "category": "Notes"},
    "joplin": {"name": "Joplin", "category": "Notes"},
    "dendron": {"name": "Dendron", "category": "Notes"},
    "remnote": {"name": "RemNote", "category": "Notes"},
    "mem.ai": {"name": "Mem", "category": "Notes"},
    "capacities": {"name": "Capacities", "category": "Notes"},
    "anytype": {"name": "Anytype", "category": "Notes"},
    "tana": {"name": "Tana", "category": "Notes"},
    "coda": {"name": "Coda", "category": "Notes"},

    # Communication
    "slack": {"name": "Slack", "category": "Communication"},
    "slack.com": {"name": "Slack", "category": "Communication"},
    "hooks.slack.com": {"name": "Slack Webhook", "category": "Communication"},
    "discord": {"name": "Discord", "category": "Communication"},
    "discord.com": {"name": "Discord", "category": "Communication"},
    "discordapp.com": {"name": "Discord", "category": "Communication"},
    "telegram": {"name": "Telegram", "category": "Communication"},
    "telegram.org": {"name": "Telegram", "category": "Communication"},
    "api.telegram.org": {"name": "Telegram Bot API", "category": "Communication"},
    "t.me": {"name": "Telegram Link", "category": "Communication"},
    "core.telegram.org": {"name": "Telegram Core", "category": "Communication"},
    "twilio": {"name": "Twilio", "category": "Communication"},
    "sendgrid": {"name": "SendGrid", "category": "Communication"},
    "mailgun": {"name": "Mailgun", "category": "Communication"},
    "whatsapp": {"name": "WhatsApp", "category": "Communication"},
    "signal": {"name": "Signal", "category": "Communication"},

    # Authentication
    "auth0": {"name": "Auth0", "category": "Authentication"},
    "okta": {"name": "Okta", "category": "Authentication"},
    "oauth": {"name": "OAuth Provider", "category": "Authentication"},
    "cognito": {"name": "AWS Cognito", "category": "Authentication"},

    # Monitoring/Logging
    "datadog": {"name": "Datadog", "category": "Monitoring"},
    "sentry": {"name": "Sentry", "category": "Monitoring"},
    "newrelic": {"name": "New Relic", "category": "Monitoring"},
    "splunk": {"name": "Splunk", "category": "Monitoring"},
    "grafana": {"name": "Grafana", "category": "Monitoring"},
    "prometheus": {"name": "Prometheus", "category": "Monitoring"},

    # CI/CD
    "jenkins": {"name": "Jenkins", "category": "CI/CD"},
    "circleci": {"name": "CircleCI", "category": "CI/CD"},
    "travis": {"name": "Travis CI", "category": "CI/CD"},
    "actions.github": {"name": "GitHub Actions", "category": "CI/CD"},

    # Container/Orchestration
    "docker": {"name": "Docker", "category": "Container"},
    "kubernetes": {"name": "Kubernetes", "category": "Orchestration"},
    "k8s": {"name": "Kubernetes", "category": "Orchestration"},

    # Project Management / Productivity
    "jira": {"name": "Jira", "category": "Project Management"},
    "atlassian": {"name": "Atlassian", "category": "Project Management"},
    "trello": {"name": "Trello", "category": "Project Management"},
    "asana": {"name": "Asana", "category": "Project Management"},
    "notion": {"name": "Notion", "category": "Productivity"},
    "airtable": {"name": "Airtable", "category": "Productivity"},
    "monday": {"name": "Monday.com", "category": "Project Management"},
    "clickup": {"name": "ClickUp", "category": "Project Management"},
    "linear": {"name": "Linear", "category": "Project Management"},

    # Payment / E-commerce
    "stripe": {"name": "Stripe", "category": "Payment"},
    "paypal": {"name": "PayPal", "category": "Payment"},
    "shopify": {"name": "Shopify", "category": "E-commerce"},

    # CRM / Marketing
    "salesforce": {"name": "Salesforce", "category": "CRM"},
    "hubspot": {"name": "HubSpot", "category": "CRM"},
    "zendesk": {"name": "Zendesk", "category": "Support"},
    "intercom": {"name": "Intercom", "category": "Support"},
    "mailchimp": {"name": "Mailchimp", "category": "Marketing"},

    # Analytics
    "segment": {"name": "Segment", "category": "Analytics"},
    "mixpanel": {"name": "Mixpanel", "category": "Analytics"},
    "amplitude": {"name": "Amplitude", "category": "Analytics"},
    "google-analytics": {"name": "Google Analytics", "category": "Analytics"},
    "analytics.google": {"name": "Google Analytics", "category": "Analytics"},

    # Automation / Integration Platforms
    "zapier": {"name": "Zapier", "category": "Automation"},
    "hooks.zapier": {"name": "Zapier Webhook", "category": "Automation"},
    "ifttt": {"name": "IFTTT", "category": "Automation"},
    "make.com": {"name": "Make (Integromat)", "category": "Automation"},
    "n8n": {"name": "n8n", "category": "Automation"},
    "pipedream": {"name": "Pipedream", "category": "Automation"},

    # Local Services
    "localhost": {"name": "Localhost", "category": "Local"},
    "127.0.0.1": {"name": "Localhost", "category": "Local"},
    "0.0.0.0": {"name": "All Interfaces", "category": "Local"},
}

# Known installation paths and configurations
# Based on actual moltbot/clawdbot source code from paths.ts:
# - State dir: ~/.moltbot (new) or ~/.clawdbot (legacy)
# - Config files: moltbot.json or clawdbot.json in state dir
# - Logs: macOS unified log (subsystem: bot.molt) + /tmp/moltbot-gateway.log
# - Default port: 18789
TOOL_CONFIGS: Dict[str, ToolConfig] = {
    "openclaw": {
        # openclaw is the same as moltbot (different branding)
        "config_paths": [
            "~/.moltbot/moltbot.json",
            "~/.moltbot/clawdbot.json",
            "~/.clawdbot/moltbot.json",
            "~/.clawdbot/clawdbot.json",
            "~/.openclaw/openclaw.json",
            "~/.openclaw/config.json",
            "~/.config/openclaw/config.json",
        ],
        "log_paths": [
            "/tmp/moltbot-gateway.log",
            "/tmp/clawdbot-gateway.log",
            "~/.moltbot/logs/*.log",
            "~/.clawdbot/logs/*.log",
            "~/.openclaw/logs/*.log",
        ],
        "workspace_path": "~/.moltbot",
        # Specific process patterns - avoid generic 'node'
        "process_names": ["moltbot gateway", "moltbot-gateway", "clawdbot gateway", "clawdbot-gateway", "openclaw gateway", "openclaw-gateway"],
        "default_port": 18789,
        "binary_names": ["moltbot", "clawdbot", "openclaw"],
        "macos_log_subsystem": "bot.molt",  # macOS unified logging subsystem
    },
    "moltbot": {
        "config_paths": [
            "~/.moltbot/moltbot.json",
            "~/.moltbot/clawdbot.json",
            "~/.clawdbot/moltbot.json",
            "~/.clawdbot/clawdbot.json",
            "~/.config/moltbot/config.json",
        ],
        "log_paths": [
            "/tmp/moltbot-gateway.log",
            "/tmp/clawdbot-gateway.log",
            "~/.moltbot/logs/*.log",
            "~/.clawdbot/logs/*.log",
        ],
        "workspace_path": "~/.moltbot",
        # Specific process patterns - avoid generic 'node'
        "process_names": ["moltbot gateway", "moltbot-gateway", "clawdbot gateway", "clawdbot-gateway"],
        "default_port": 18789,
        "binary_names": ["moltbot"],
        "macos_log_subsystem": "bot.molt",
    },
    "clawbot": {
        # clawbot/clawdbot is the legacy name for moltbot
        "config_paths": [
            "~/.clawdbot/clawdbot.json",
            "~/.clawdbot/moltbot.json",
            "~/.moltbot/clawdbot.json",
            "~/.moltbot/moltbot.json",
            "~/.clawbot/config.json",
            "~/.config/clawbot/config.json",
        ],
        "log_paths": [
            "/tmp/moltbot-gateway.log",
            "/tmp/clawdbot-gateway.log",
            "~/.clawdbot/logs/*.log",
            "~/.moltbot/logs/*.log",
            "~/.clawbot/logs/*.log",
        ],
        "workspace_path": "~/.clawdbot",
        # Specific process patterns - avoid generic 'node'
        "process_names": ["clawdbot gateway", "clawdbot-gateway", "moltbot gateway", "moltbot-gateway"],
        "default_port": 18789,
        "binary_names": ["clawdbot", "clawbot", "moltbot"],
        "macos_log_subsystem": "bot.molt",
    },
}


class InstallationTracker:
    def __init__(self, api_key: str = SCANNER_REPORT_API_KEY):
        self.api_key = api_key
        self.username = self._get_current_username()
        self.hostname = socket.gethostname()
        self.results: Dict[str, Any] = {}

    def _get_current_username(self) -> str:
        """Get the current system username."""
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    def _expand_path(self, path: str) -> str:
        """Expand ~ and environment variables in path."""
        return os.path.expanduser(os.path.expandvars(path))

    def _check_binary_installed(self, binary_name: str) -> Optional[str]:
        """Check if a binary is installed and return its path."""
        # Use shutil.which for cross-platform binary lookup
        return shutil.which(binary_name)

    def _check_npm_package(self, package_name: str) -> Optional[Dict[str, str]]:
        """Check if an npm package is installed globally."""
        try:
            result = subprocess.run(
                ["npm", "list", "-g", package_name, "--json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if "dependencies" in data and package_name in data["dependencies"]:
                    return {
                        "version": data["dependencies"][package_name].get("version", "unknown"),
                        "path": data.get("path", "unknown")
                    }
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return None

    def _check_port_listening(self, port: int) -> bool:
        """Check if a port is listening."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("127.0.0.1", port))
                return result == 0
        except socket.error:
            return False

    def _read_config_file(self, config_path: str) -> Optional[Dict[str, Any]]:
        """Read and parse a JSON or YAML configuration file."""
        expanded_path = self._expand_path(config_path)
        if os.path.exists(expanded_path):
            try:
                with open(expanded_path, "r") as f:
                    content = f.read()

                # Determine file type by extension
                is_yaml = expanded_path.lower().endswith(('.yaml', '.yml'))

                if is_yaml:
                    return self._parse_yaml(content, expanded_path)
                else:
                    # Handle JSON with comments or trailing commas
                    content = re.sub(r'//.*?\n', '\n', content)
                    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                    content = re.sub(r',(\s*[}\]])', r'\1', content)
                    parsed: Dict[str, Any] = json.loads(content)
                    return parsed
            except (json.JSONDecodeError, IOError) as e:
                return {"_error": str(e), "_path": expanded_path}
        return None

    def _parse_yaml(self, content: str, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse YAML content, with fallback if PyYAML not installed."""
        if YAML_AVAILABLE:
            try:
                # Use safe_load to prevent arbitrary code execution
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    return data
                return {"_data": data, "_type": type(data).__name__}
            except yaml.YAMLError as e:
                return {"_error": str(e), "_path": filepath}
        else:
            # Basic YAML parsing fallback (handles simple key: value pairs)
            return self._basic_yaml_parse(content, filepath)

    def _basic_yaml_parse(self, content: str, filepath: str) -> Dict[str, Any]:
        """Basic YAML parser for simple configs when PyYAML is not available."""
        result: Dict[str, Any] = {"_warning": "PyYAML not installed, using basic parser", "_path": filepath}
        current_dict: Dict[str, Any] = result
        indent_stack: List[tuple[int, Dict[str, Any]]] = [(0, result)]

        for line in content.split('\n'):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # Calculate indent level
            indent = len(line) - len(line.lstrip())

            # Find the key-value pair
            if ':' in stripped:
                key, _, value_str = stripped.partition(':')
                key = key.strip()
                value: Any = value_str.strip()

                # Remove quotes from value
                if value and value[0] in '"\'':
                    value = value[1:-1] if len(value) > 1 and value[-1] == value[0] else value[1:]

                # Handle nested structures
                while indent_stack and indent <= indent_stack[-1][0]:
                    if len(indent_stack) > 1:
                        indent_stack.pop()
                    else:
                        break

                current_dict = indent_stack[-1][1]

                if value:
                    # Convert common types
                    if value.lower() == 'true':
                        value = True
                    elif value.lower() == 'false':
                        value = False
                    elif value.lower() in ('null', 'none', '~'):
                        value = None
                    elif value.isdigit():
                        value = int(value)
                    elif re.match(r'^-?\d+\.\d+$', value):
                        value = float(value)

                    current_dict[key] = value
                else:
                    # Nested dict
                    new_dict: Dict[str, Any] = {}
                    current_dict[key] = new_dict
                    indent_stack.append((indent + 1, new_dict))

        return result

    def _find_log_files(self, log_patterns: List[str]) -> List[str]:
        """Find all log files matching the patterns."""
        log_files = []
        for pattern in log_patterns:
            expanded_pattern = self._expand_path(pattern)
            log_files.extend(glob.glob(expanded_pattern))
        return sorted(log_files, key=os.path.getmtime, reverse=True) if log_files else []

    def _parse_log_connections(self, log_file: str, max_lines: int = 1000) -> List[Dict[str, Any]]:
        """Parse log file for connection information."""
        connections = []
        connection_patterns = [
            r'connect(?:ed|ing)?\s+(?:to\s+)?["\']?([a-zA-Z0-9\-._]+(?::\d+)?)["\']?',
            r'(?:api|server|host|endpoint|url)["\s:=]+["\']?(https?://[^\s"\']+)["\']?',
            r'(?:websocket|ws|wss)://([^\s"\']+)',
            r'(?:authenticated|login|auth)\s+(?:to|with|as)\s+["\']?([^\s"\']+)["\']?',
            r'model["\s:=]+["\']?([^\s"\']+)["\']?',
        ]

        try:
            with open(log_file, "r", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
                for line in lines:
                    for pattern in connection_patterns:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            connections.append({
                                "resource": match,
                                "log_file": log_file,
                                "pattern": pattern[:30] + "...",
                                "line_sample": line.strip()[:100]
                            })
        except IOError:
            pass

        # Deduplicate by resource
        seen = set()
        unique_connections = []
        for conn in connections:
            if conn["resource"] not in seen:
                seen.add(conn["resource"])
                unique_connections.append(conn)

        return unique_connections

    def _parse_log_for_accessed_apps(self, log_file: str, max_lines: int = 2000) -> List[AccessedApp]:
        """Parse log file to identify apps/services accessed or attempted to access."""
        accessed_apps: List[AccessedApp] = []

        # Patterns for identifying access attempts and their status
        access_patterns = [
            # HTTP/API requests
            (r'(?:GET|POST|PUT|DELETE|PATCH)\s+["\']?(https?://[^\s"\']+)["\']?', "http_request"),
            (r'(?:request|fetch|call)(?:ing|ed)?\s+(?:to\s+)?["\']?(https?://[^\s"\']+)["\']?', "api_call"),
            (r'(?:api|endpoint)["\s:=]+["\']?(https?://[^\s"\'<>]+)["\']?', "api_endpoint"),

            # URLs and hosts
            (r'(?:url|host|server|endpoint)["\s:=]+["\']?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d+)?)["\']?', "host"),
            (r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?:[:/]|$)', "url_host"),

            # Connection events
            (r'connect(?:ed|ing|ion)?\s+(?:to\s+)?["\']?([a-zA-Z0-9][-a-zA-Z0-9.]+(?::\d+)?)["\']?', "connection"),
            (r'(?:establish|open)(?:ed|ing)?\s+(?:connection\s+)?(?:to\s+)?["\']?([^\s"\']+)["\']?', "connection"),

            # Authentication
            (r'(?:auth|login|signin|authenticate)(?:ed|ing|ation)?\s+(?:to|with|for|at)\s+["\']?([^\s"\']+)["\']?', "auth"),
            (r'(?:oauth|sso|saml)\s+(?:to|with|for)\s+["\']?([^\s"\']+)["\']?', "oauth"),
            (r'(?:token|credential|key)\s+(?:for|from)\s+["\']?([^\s"\']+)["\']?', "credential"),

            # WebSocket
            (r'(?:websocket|ws|wss)://([^\s"\']+)', "websocket"),

            # Database connections
            (r'(?:mongodb|postgres|mysql|redis|elasticsearch)(?:://)?([^\s"\']+)', "database"),
            (r'(?:database|db)\s+(?:connection|host)["\s:=]+["\']?([^\s"\']+)["\']?', "database"),

            # Service-specific
            (r'(?:github|gitlab|bitbucket)\.com[/:]?([^\s"\']*)', "vcs"),

            # Messaging services - improved patterns
            (r'(api\.telegram\.org[^\s"\']*)', "telegram"),
            (r'(telegram\.org[^\s"\']*)', "telegram"),
            (r'(t\.me[/][^\s"\']*)', "telegram"),
            (r'telegram["\s:=]+["\']?([^\s"\']+)["\']?', "telegram"),
            (r'(slack\.com[^\s"\']*)', "slack"),
            (r'(hooks\.slack\.com[^\s"\']*)', "slack"),
            (r'(discord\.com[^\s"\']*)', "discord"),
            (r'(discordapp\.com[^\s"\']*)', "discord"),
            (r'(?:slack|discord|telegram)(?:_|-)(?:bot|api|webhook|token|key)["\s:=]+["\']?([^\s"\']+)["\']?', "messaging_config"),
            (r'(?:send|post|message)(?:ing|ed)?\s+(?:to\s+)?(?:telegram|slack|discord)[^\s]*["\']?([^\s"\']*)["\']?', "messaging"),

            # Bot tokens
            (r'bot[_-]?token["\s:=]+["\']?([^\s"\']+)["\']?', "bot_token"),
            (r'(\d+:[\w-]{35,})', "telegram_bot_token"),  # Telegram bot token format

            # Calendar services
            (r'(calendar\.google\.com[^\s"\']*)', "google_calendar"),
            (r'(www\.googleapis\.com/calendar[^\s"\']*)', "google_calendar_api"),
            (r'(googleapis\.com/calendar[^\s"\']*)', "google_calendar_api"),
            (r'(outlook\.office\.com/calendar[^\s"\']*)', "outlook_calendar"),
            (r'(outlook\.office365\.com[^\s"\']*)', "outlook_calendar"),
            (r'(graph\.microsoft\.com[^\s"\']*)', "microsoft_graph"),
            (r'(calendly\.com[^\s"\']*)', "calendly"),
            (r'(api\.calendly\.com[^\s"\']*)', "calendly_api"),
            (r'(cal\.com[^\s"\']*)', "cal_com"),
            (r'(?:calendar|event|meeting|schedule|appointment)["\s:=]+["\']?([^\s"\']+)["\']?', "calendar_config"),
            (r'(?:ical|ics|caldav|webcal)(?:://|["\s:=]+)["\']?([^\s"\']+)["\']?', "calendar_protocol"),
            (r'(cronofy\.com[^\s"\']*)', "cronofy"),
            (r'(nylas\.com[^\s"\']*)', "nylas"),
            (r'(api\.nylas\.com[^\s"\']*)', "nylas_api"),
            (r'(zoom\.us[^\s"\']*)', "zoom"),
            (r'(api\.zoom\.us[^\s"\']*)', "zoom_api"),
            (r'(teams\.microsoft\.com[^\s"\']*)', "ms_teams"),
            (r'(meet\.google\.com[^\s"\']*)', "google_meet"),
            (r'(?:create|add|sync|fetch)(?:ing|ed)?\s+(?:calendar|event|meeting|appointment)[^\s]*', "calendar_action"),
            (r'calendar[_-]?(?:id|api|key|token|secret)["\s:=]+["\']?([^\s"\']+)["\']?', "calendar_credential"),
            (r'google[_-]?calendar["\s:=]+["\']?([^\s"\']+)["\']?', "google_calendar"),
            (r'outlook[_-]?calendar["\s:=]+["\']?([^\s"\']+)["\']?', "outlook_calendar"),

            # Obsidian and note-taking apps
            (r'(obsidian\.md[^\s"\']*)', "obsidian"),
            (r'(sync\.obsidian\.md[^\s"\']*)', "obsidian_sync"),
            (r'(publish\.obsidian\.md[^\s"\']*)', "obsidian_publish"),
            (r'(api\.obsidian\.md[^\s"\']*)', "obsidian_api"),
            (r'obsidian["\s:=]+["\']?([^\s"\']+)["\']?', "obsidian_config"),
            (r'obsidian[_-]?(?:vault|sync|api|token|key)["\s:=]+["\']?([^\s"\']+)["\']?', "obsidian_config"),
            (r'(?:vault|workspace)["\s:=]+["\']?([^\s"\']*obsidian[^\s"\']*)["\']?', "obsidian_vault"),
            (r'(roamresearch\.com[^\s"\']*)', "roam"),
            (r'(logseq\.com[^\s"\']*)', "logseq"),
            (r'(evernote\.com[^\s"\']*)', "evernote"),
            (r'(notion\.so[^\s"\']*)', "notion"),
            (r'(api\.notion\.com[^\s"\']*)', "notion_api"),

            (r's3://([^\s"\']+)', "s3"),
            (r'(?:bucket|container)["\s:=]+["\']?([^\s"\']+)["\']?', "storage"),

            # File system access
            (r'(?:read|write|access|open)(?:ing|ed)?\s+(?:file\s+)?["\']?(/[^\s"\']+)["\']?', "file"),
            (r'(?:path|file|directory)["\s:=]+["\']?(/[^\s"\']+)["\']?', "file"),

            # Model/AI service
            (r'(?:model|llm)["\s:=]+["\']?([^\s"\']+)["\']?', "model"),
            (r'(?:claude|gpt|gemini|llama|mistral)[-\s]?[\d.]*', "ai_model"),

            # Generic integration detection
            (r'(?:integration|plugin|addon|extension|connector)["\s:=]+["\']?([^\s"\']+)["\']?', "integration"),
            (r'(?:integrat|connect|link|sync)(?:ing|ed|ion)?\s+(?:to|with)\s+["\']?([^\s"\']+)["\']?', "integration_action"),
            (r'(?:webhook|hook|callback)["\s_-]?(?:url|endpoint)?["\s:=]+["\']?(https?://[^\s"\']+)["\']?', "webhook"),
            (r'(?:api|service)[_-]?(?:key|token|secret|credential)["\s:=]+["\']?([^\s"\']+)["\']?', "api_credential"),
            (r'(?:oauth|access)[_-]?token["\s:=]+["\']?([^\s"\']+)["\']?', "oauth_token"),
            (r'(?:client)[_-]?(?:id|secret)["\s:=]+["\']?([^\s"\']+)["\']?', "oauth_client"),
            (r'(?:enabled|active|configured)\s+(?:integration|service|plugin)["\s:]*["\']?([^\s"\']+)["\']?', "enabled_integration"),

            # Third-party services
            (r'(jira\.atlassian\.com[^\s"\']*)', "jira"),
            (r'(api\.atlassian\.com[^\s"\']*)', "atlassian"),
            (r'(trello\.com[^\s"\']*)', "trello"),
            (r'(api\.trello\.com[^\s"\']*)', "trello_api"),
            (r'(asana\.com[^\s"\']*)', "asana"),
            (r'(api\.asana\.com[^\s"\']*)', "asana_api"),
            (r'(notion\.so[^\s"\']*)', "notion"),
            (r'(api\.notion\.com[^\s"\']*)', "notion_api"),
            (r'(airtable\.com[^\s"\']*)', "airtable"),
            (r'(api\.airtable\.com[^\s"\']*)', "airtable_api"),
            (r'(monday\.com[^\s"\']*)', "monday"),
            (r'(clickup\.com[^\s"\']*)', "clickup"),
            (r'(linear\.app[^\s"\']*)', "linear"),
            (r'(stripe\.com[^\s"\']*)', "stripe"),
            (r'(api\.stripe\.com[^\s"\']*)', "stripe_api"),
            (r'(paypal\.com[^\s"\']*)', "paypal"),
            (r'(shopify\.com[^\s"\']*)', "shopify"),
            (r'(salesforce\.com[^\s"\']*)', "salesforce"),
            (r'(hubspot\.com[^\s"\']*)', "hubspot"),
            (r'(zendesk\.com[^\s"\']*)', "zendesk"),
            (r'(intercom\.com[^\s"\']*)', "intercom"),
            (r'(mailchimp\.com[^\s"\']*)', "mailchimp"),
            (r'(twilio\.com[^\s"\']*)', "twilio"),
            (r'(segment\.com[^\s"\']*)', "segment"),
            (r'(mixpanel\.com[^\s"\']*)', "mixpanel"),
            (r'(amplitude\.com[^\s"\']*)', "amplitude"),
            (r'(zapier\.com[^\s"\']*)', "zapier"),
            (r'(hooks\.zapier\.com[^\s"\']*)', "zapier_webhook"),
            (r'(ifttt\.com[^\s"\']*)', "ifttt"),
            (r'(make\.com[^\s"\']*)', "make"),
            (r'(n8n\.io[^\s"\']*)', "n8n"),
            (r'(pipedream\.com[^\s"\']*)', "pipedream"),
        ]

        # Status indicators
        success_indicators = ['success', 'ok', '200', '201', '204', 'connected', 'authenticated', 'completed', 'done']
        failure_indicators = ['fail', 'error', 'denied', 'refused', 'timeout', '401', '403', '404', '500', '502', '503', 'rejected', 'unauthorized']
        attempt_indicators = ['attempt', 'trying', 'connecting', 'requesting', 'fetching']

        try:
            with open(log_file, "r", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]

                for line_num, line in enumerate(lines):
                    line_lower = line.lower()

                    # Determine access status from line context
                    status = "unknown"
                    if any(ind in line_lower for ind in success_indicators):
                        status = "success"
                    elif any(ind in line_lower for ind in failure_indicators):
                        status = "failed"
                    elif any(ind in line_lower for ind in attempt_indicators):
                        status = "attempted"

                    # Try to extract timestamp
                    timestamp = None
                    timestamp_patterns = [
                        r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})',
                        r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
                        r'\[(\d+)\]',  # Unix timestamp
                    ]
                    for ts_pattern in timestamp_patterns:
                        ts_match = re.search(ts_pattern, line)
                        if ts_match:
                            timestamp = ts_match.group(1)
                            break

                    # Find all access patterns
                    for pattern, access_type in access_patterns:
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]

                            # Skip empty or too short matches
                            if not match or len(match) < 3:
                                continue

                            # Categorize the service
                            service_info = self._categorize_service(match)

                            app_entry: AccessedApp = {
                                "resource": match,
                                "access_type": access_type,
                                "status": status,
                                "timestamp": timestamp,
                                "service_name": service_info.get("name"),
                                "service_category": service_info.get("category", "Unknown"),
                                "log_file": log_file,
                                "line_number": line_num + 1,
                                "line_sample": line.strip()[:150]
                            }
                            accessed_apps.append(app_entry)

        except IOError:
            pass

        return accessed_apps

    def _categorize_service(self, resource: str) -> Dict[str, str]:
        """Categorize a resource/service based on known patterns."""
        resource_lower = resource.lower()

        for pattern, info in KNOWN_SERVICES.items():
            if pattern.lower() in resource_lower:
                return info

        # Try to identify by domain patterns
        if re.search(r'\.gov$', resource_lower):
            return {"name": "Government Service", "category": "Government"}
        if re.search(r'\.edu$', resource_lower):
            return {"name": "Educational Institution", "category": "Education"}
        if re.search(r'\.internal$|\.local$|\.corp$', resource_lower):
            return {"name": "Internal Service", "category": "Internal"}
        if re.search(r'api\.', resource_lower):
            return {"name": "API Service", "category": "API"}

        return {"name": "Unknown", "category": "Unknown"}

    def _parse_system_log_for_integrations(self, tool_name: str) -> Dict[str, Any]:
        """Parse system log for integration/connection info.

        Uses platform compat layer to read system logs:
        - macOS: unified log via 'log show'
        - Linux: journalctl

        Returns dictionary with connections, integrations, accessed services.
        """
        if platform.system() == "Darwin":
            log_source = "macos_unified_log"
        else:
            log_source = "linux_journalctl"

        result: Dict[str, Any] = {
            "log_source": log_source,
            "connections": [],
            "accessed_apps": [],
            "integrations": []
        }

        config: ToolConfig = TOOL_CONFIGS.get(tool_name, {})
        subsystem = config.get("macos_log_subsystem")  # Also used as systemd unit on Linux

        if not subsystem:
            return result

        # Use compat layer to read system log (cross-platform)
        log_lines = compat.read_system_log(subsystem, time_range="24h", max_lines=1000)

        if not log_lines:
            return result

        # Write to temp file and parse using existing methods
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write('\n'.join(log_lines))
            temp_log_path = f.name

        try:
            result["connections"] = self._parse_log_connections(temp_log_path)
            result["accessed_apps"] = self._parse_log_for_accessed_apps(temp_log_path)
        finally:
            os.unlink(temp_log_path)

        return result

    def _aggregate_accessed_apps(self, apps: List[AccessedApp]) -> AccessedAppsSummary:
        """Aggregate accessed apps into a summary with statistics."""
        by_category: Dict[str, List[ServiceStats]] = {}
        unique_services: List[ServiceStats] = []
        summary: AccessedAppsSummary = {
            "total_access_events": len(apps),
            "by_category": by_category,
            "by_status": {"success": 0, "failed": 0, "attempted": 0, "unknown": 0},
            "unique_services": unique_services,
            "access_timeline": [],
        }

        seen_services: Dict[str, ServiceStats] = {}

        for app in apps:
            # Count by status
            status = app.get("status", "unknown")
            if status in summary["by_status"]:
                summary["by_status"][status] += 1

            # Group by category
            category = app.get("service_category", "Unknown")
            if category not in by_category:
                by_category[category] = []

            # Track unique services per category
            resource = app.get("resource", "")
            service_key = f"{category}:{resource}"

            if service_key not in seen_services:
                seen_services[service_key] = {
                    "resource": resource,
                    "service_name": app.get("service_name"),
                    "category": category,
                    "access_count": 0,
                    "success_count": 0,
                    "failure_count": 0,
                    "first_seen": app.get("timestamp"),
                    "last_seen": app.get("timestamp"),
                    "access_types": [],
                }
                by_category[category].append(seen_services[service_key])

            # Update service stats
            seen_services[service_key]["access_count"] += 1
            access_type = app.get("access_type", "unknown")
            if access_type not in seen_services[service_key]["access_types"]:
                seen_services[service_key]["access_types"].append(access_type)
            if status == "success":
                seen_services[service_key]["success_count"] += 1
            elif status == "failed":
                seen_services[service_key]["failure_count"] += 1
            if app.get("timestamp"):
                seen_services[service_key]["last_seen"] = app.get("timestamp")

        # Build unique_services list
        for service in seen_services.values():
            unique_services.append(service)

        # Sort unique services by access count
        unique_services.sort(key=lambda x: x["access_count"], reverse=True)

        return summary

    def _extract_integrations_from_config(self, config: Dict[str, Any], tool_name: str) -> List[Integration]:
        """Extract integrations/channels from tool configuration."""
        integrations: List[Integration] = []

        if not isinstance(config, dict):
            return integrations

        # OpenClaw specific: channels.* configuration
        if "channels" in config and isinstance(config["channels"], dict):
            for channel_name, channel_config in config["channels"].items():
                integration: Integration = {
                    "name": channel_name,
                    "type": "channel",
                    "source": f"{tool_name} config",
                    "enabled": True,
                    "config": channel_config if isinstance(channel_config, dict) else {"value": channel_config}
                }
                integrations.append(integration)

        # OpenClaw specific: agent.model (AI provider integration)
        if "agent" in config and isinstance(config["agent"], dict):
            if "model" in config["agent"]:
                model = config["agent"]["model"]
                provider = model.split("/")[0] if "/" in model else model
                integrations.append({
                    "name": provider,
                    "type": "ai_provider",
                    "source": f"{tool_name} config",
                    "enabled": True,
                    "config": {"model": model}
                })

        # OpenClaw specific: gateway settings
        if "gateway" in config and isinstance(config["gateway"], dict):
            gateway = config["gateway"]
            if gateway.get("auth", {}).get("mode"):
                integrations.append({
                    "name": "gateway_auth",
                    "type": "authentication",
                    "source": f"{tool_name} config",
                    "enabled": True,
                    "config": gateway.get("auth", {})
                })
            if gateway.get("tailscale", {}).get("mode"):
                integrations.append({
                    "name": "tailscale",
                    "type": "network",
                    "source": f"{tool_name} config",
                    "enabled": True,
                    "config": gateway.get("tailscale", {})
                })

        # Generic integration patterns
        integration_keys = [
            "integrations", "plugins", "extensions", "addons",
            "connections", "services", "providers", "webhooks"
        ]

        def search_integrations(d: Dict[str, Any], path: str = "") -> None:
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()

                # Check if this key suggests an integration
                if key_lower in integration_keys:
                    if isinstance(value, dict):
                        for int_name, int_config in value.items():
                            integrations.append({
                                "name": int_name,
                                "type": key_lower,
                                "source": f"{tool_name} config ({current_path})",
                                "enabled": True,
                                "config": int_config if isinstance(int_config, dict) else {"value": int_config}
                            })
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                integrations.append({
                                    "name": item,
                                    "type": key_lower,
                                    "source": f"{tool_name} config ({current_path})",
                                    "enabled": True,
                                    "config": {}
                                })
                            elif isinstance(item, dict):
                                item_name = item.get("name") or item.get("id") or "unknown"
                                integrations.append({
                                    "name": item_name,
                                    "type": key_lower,
                                    "source": f"{tool_name} config ({current_path})",
                                    "enabled": item.get("enabled", True),
                                    "config": item
                                })

                # Check for known service names as keys
                known_services = [
                    # Messaging
                    "telegram", "slack", "discord", "whatsapp", "signal",
                    "teams", "matrix", "google_chat", "imessage", "webchat",
                    # Dev tools
                    "github", "gitlab", "jira", "notion", "trello", "linear",
                    "asana", "clickup", "monday", "basecamp",
                    # Calendar
                    "calendar", "google_calendar", "outlook_calendar", "calendly",
                    "cal", "ical", "caldav", "zoom", "meet",
                    # Notes
                    "obsidian", "roam", "logseq", "evernote", "onenote", "bear",
                    "craft", "notion", "coda", "remnote", "mem", "tana",
                    # Cloud
                    "google", "microsoft", "aws", "azure", "gcp",
                    # AI
                    "openai", "anthropic", "claude", "gpt", "gemini", "llama",
                    # Storage
                    "dropbox", "drive", "onedrive", "box", "s3",
                    # Other
                    "zapier", "ifttt", "make", "n8n", "webhooks"
                ]
                if key_lower in known_services and value:
                    integrations.append({
                        "name": key,
                        "type": "service",
                        "source": f"{tool_name} config ({current_path})",
                        "enabled": value.get("enabled", True) if isinstance(value, dict) else bool(value),
                        "config": value if isinstance(value, dict) else {"value": value}
                    })

                # Recurse into nested dicts
                if isinstance(value, dict) and key_lower not in integration_keys:
                    search_integrations(value, current_path)

        search_integrations(config)
        return integrations

    def _scan_skills_directory(self, workspace_path: str) -> List[SkillInfo]:
        """Scan for installed skills/plugins in workspace directory."""
        skills: List[SkillInfo] = []
        skills_path = os.path.join(self._expand_path(workspace_path), "skills")

        if os.path.exists(skills_path):
            try:
                for skill_name in os.listdir(skills_path):
                    skill_dir = os.path.join(skills_path, skill_name)
                    if os.path.isdir(skill_dir):
                        skill_info: SkillInfo = {
                            "name": skill_name,
                            "type": "skill",
                            "path": skill_dir,
                            "has_skill_md": os.path.exists(os.path.join(skill_dir, "SKILL.md")),
                            "files": []
                        }
                        # List files in skill directory
                        try:
                            skill_info["files"] = os.listdir(skill_dir)[:10]  # Limit to 10 files
                        except OSError:
                            pass
                        skills.append(skill_info)
            except OSError:
                pass

        return skills

    def _parse_tools_md(self, tools_md_path: str) -> List[Integration]:
        """Parse a TOOLS.md file for user-defined integrations/tools.

        TOOLS.md contains user-specific notes about:
        - Cameras, SSH hosts, TTS voices, speakers
        - Device nicknames, custom configurations
        - Environment-specific settings
        """
        integrations: List[Integration] = []

        if not os.path.exists(tools_md_path):
            return integrations

        try:
            with open(tools_md_path, 'r') as f:
                content = f.read()

            # Parse markdown sections for integrations
            current_section: Optional[str] = None
            section_items: List[Dict[str, str]] = []

            for line in content.split('\n'):
                line = line.strip()

                # Detect section headers (## or ### Cameras, SSH, etc.)
                if line.startswith('##') and not line.startswith('#####'):
                    # Save previous section
                    if current_section and section_items:
                        for item in section_items:
                            integrations.append({
                                "name": item.get("name", "unknown"),
                                "type": current_section.lower(),
                                "source": "TOOLS.md",
                                "description": item.get("description", ""),
                                "details": item
                            })
                    current_section = line.lstrip('#').strip()
                    section_items = []

                # Parse list items (- name → description)
                elif line.startswith('-') and current_section:
                    item_text = line.lstrip('- ').strip()
                    if '→' in item_text:
                        name, desc = item_text.split('→', 1)
                        section_items.append({
                            "name": name.strip(),
                            "description": desc.strip()
                        })
                    elif ':' in item_text:
                        name, desc = item_text.split(':', 1)
                        section_items.append({
                            "name": name.strip(),
                            "description": desc.strip()
                        })
                    else:
                        section_items.append({
                            "name": item_text,
                            "description": ""
                        })

            # Don't forget last section
            if current_section and section_items:
                for item in section_items:
                    integrations.append({
                        "name": item.get("name", "unknown"),
                        "type": current_section.lower(),
                        "source": "TOOLS.md",
                        "description": item.get("description", ""),
                        "details": item
                    })

        except IOError:
            pass

        return integrations

    def _scan_workspace_library(self, tool_name: str) -> WorkspaceLibrary:
        """Scan the workspace library for connected apps and integrations.

        Scans:
        - TOOLS.md for user-defined integrations
        - skills/ directory for installed skills
        - extensions/ directory for installed extensions
        - plugins/ directory for installed plugins
        - channels from config (telegram, slack, discord, etc.)
        - skills.entries from config for configured skills
        - MCP servers configuration
        - OAuth credentials
        """
        result: WorkspaceLibrary = {
            "connected_apps": [],
            "channels": [],
            "skills": [],
            "skills_from_config": [],
            "extensions": [],
            "plugins": [],
            "mcp_servers": [],
            "oauth_credentials": [],
            "tools_md_integrations": [],
        }

        # Check multiple possible workspace locations
        workspace_dirs = [
            "~/.moltbot",
            "~/.clawdbot",
            "~/.openclaw",
            f"~/.{tool_name}",
        ]

        for ws_dir in workspace_dirs:
            ws_path = self._expand_path(ws_dir)
            if not os.path.exists(ws_path):
                continue

            # Parse TOOLS.md for user-defined integrations
            tools_md_path = os.path.join(ws_path, "TOOLS.md")
            if os.path.exists(tools_md_path):
                tools_integrations = self._parse_tools_md(tools_md_path)
                result["tools_md_integrations"].extend(tools_integrations)
                for intg in tools_integrations:
                    connected_app: Integration = {
                        "name": intg["name"],
                        "type": f"tools_md_{intg.get('type', 'unknown')}",
                        "source": tools_md_path,
                    }
                    result["connected_apps"].append(connected_app)

            # Scan skills directory
            skills_path = os.path.join(ws_path, "skills")
            if os.path.exists(skills_path):
                for item in os.listdir(skills_path):
                    item_path = os.path.join(skills_path, item)
                    if os.path.isdir(item_path):
                        parsed_skill = self._parse_skill_or_extension(item_path, "skill")
                        if parsed_skill:
                            result["skills"].append(parsed_skill)
                            skill_app: Integration = {
                                "name": parsed_skill["name"],
                                "type": "skill",
                                "source": skills_path,
                            }
                            result["connected_apps"].append(skill_app)

            # Scan extensions directory
            extensions_path = os.path.join(ws_path, "extensions")
            if os.path.exists(extensions_path):
                for item in os.listdir(extensions_path):
                    item_path = os.path.join(extensions_path, item)
                    if os.path.isdir(item_path):
                        ext_info = self._parse_skill_or_extension(item_path, "extension")
                        if ext_info:
                            result["extensions"].append(ext_info)
                            ext_app: Integration = {
                                "name": ext_info["name"],
                                "type": "extension",
                                "source": extensions_path,
                            }
                            result["connected_apps"].append(ext_app)

            # Scan plugins directory
            plugins_path = os.path.join(ws_path, "plugins")
            if os.path.exists(plugins_path):
                for item in os.listdir(plugins_path):
                    item_path = os.path.join(plugins_path, item)
                    if os.path.isdir(item_path):
                        plugin_info = self._parse_skill_or_extension(item_path, "plugin")
                        if plugin_info:
                            result["plugins"].append(plugin_info)
                            plugin_app: Integration = {
                                "name": plugin_info["name"],
                                "type": "plugin",
                                "source": plugins_path,
                            }
                            result["connected_apps"].append(plugin_app)

            # Check for OAuth credentials
            creds_path = os.path.join(ws_path, "credentials")
            if os.path.exists(creds_path):
                oauth_file = os.path.join(creds_path, "oauth.json")
                if os.path.exists(oauth_file):
                    try:
                        with open(oauth_file, 'r') as f:
                            oauth_data = json.load(f)
                            for provider, creds in oauth_data.items():
                                result["oauth_credentials"].append({
                                    "provider": provider,
                                    "has_token": bool(creds.get("access_token") or creds.get("token")),
                                    "scopes": creds.get("scopes", []),
                                })
                                result["connected_apps"].append({
                                    "name": provider,
                                    "type": "oauth_provider",
                                    "source": oauth_file,
                                    "details": {"has_credentials": True}
                                })
                    except (json.JSONDecodeError, IOError):
                        pass

            # Parse main config for channels
            for config_name in ["moltbot.json", "clawdbot.json", "config.json"]:
                config_path = os.path.join(ws_path, config_name)
                if os.path.exists(config_path):
                    config_data = self._read_config_file(config_path)
                    if config_data:
                        # Extract channels
                        channels_config = config_data.get("channels", {})
                        channel_types = ["telegram", "slack", "discord", "whatsapp", "signal",
                                        "googlechat", "imessage", "msteams", "matrix", "webchat"]
                        for ch_type in channel_types:
                            ch_config = channels_config.get(ch_type)
                            if ch_config and ch_config.get("enabled", True) is not False:
                                ch_info: Integration = {
                                    "name": ch_type.title(),
                                    "type": ch_type,
                                    "enabled": ch_config.get("enabled", True),
                                    "config": {"has_token": bool(ch_config.get("token") or ch_config.get("botToken"))},
                                }
                                result["channels"].append(ch_info)
                                result["connected_apps"].append(ch_info)

                        # Extract MCP servers
                        mcp_config = config_data.get("mcpServers", {})
                        for server_name, server_config in mcp_config.items():
                            server_info: Integration = {
                                "name": server_name,
                                "type": "mcp_server",
                                "source": config_path,
                                "enabled": server_config.get("enabled", True),
                                "config": {"command": server_config.get("command", "")},
                            }
                            result["mcp_servers"].append(server_info)
                            result["connected_apps"].append(server_info)

                        # Extract skills entries from config
                        skills_config = config_data.get("skills", {}).get("entries", {})
                        for skill_name, skill_config in skills_config.items():
                            cfg_skill_info: SkillInfo = {
                                "name": skill_name,
                                "enabled": skill_config.get("enabled", True),
                                "has_api_key": bool(skill_config.get("apiKey")),
                                "has_env": bool(skill_config.get("env")),
                                "has_config": bool(skill_config.get("config")),
                                "source": config_path,
                            }
                            result["skills_from_config"].append(cfg_skill_info)
                            if skill_config.get("enabled", True):
                                cfg_skill_app: Integration = {
                                    "name": skill_name,
                                    "type": "skill_config",
                                    "source": config_path,
                                }
                                result["connected_apps"].append(cfg_skill_app)

                        # Extract bundled skills allowlist
                        bundled_skills = config_data.get("skills", {}).get("allowBundled", [])
                        for skill_name in bundled_skills:
                            bundled_app: Integration = {
                                "name": skill_name,
                                "type": "bundled_skill",
                                "source": config_path,
                            }
                            result["connected_apps"].append(bundled_app)

        return result

    def _parse_skill_or_extension(self, path: str, item_type: str) -> Optional[SkillInfo]:
        """Parse a skill, extension, or plugin directory."""
        name = os.path.basename(path)
        info: SkillInfo = {
            "name": name,
            "type": item_type,
            "path": path,
            "has_manifest": False,
            "description": None,
            "connected_services": [],
        }

        # Check for SKILL.md or manifest files
        manifest_files = ["SKILL.md", "EXTENSION.md", "PLUGIN.md", "manifest.json", "package.json"]
        for manifest in manifest_files:
            manifest_path = os.path.join(path, manifest)
            if os.path.exists(manifest_path):
                info["has_manifest"] = True
                try:
                    with open(manifest_path, 'r') as f:
                        content = f.read()
                        # Try to extract description
                        if manifest.endswith('.md'):
                            # Look for first paragraph or summary line
                            lines = content.split('\n')
                            for line in lines:
                                if line.strip() and not line.startswith('#') and not line.startswith('---'):
                                    info["description"] = line.strip()[:200]
                                    break
                        elif manifest == "package.json":
                            pkg = json.loads(content)
                            info["description"] = pkg.get("description", "")[:200]

                        # Look for connected services in content
                        service_patterns = [
                            "telegram", "slack", "discord", "github", "gitlab",
                            "google", "microsoft", "aws", "openai", "anthropic",
                            "notion", "obsidian", "calendar", "gmail", "drive",
                            "dropbox", "trello", "jira", "linear", "asana"
                        ]
                        content_lower = content.lower()
                        for svc in service_patterns:
                            if svc in content_lower:
                                info["connected_services"].append(svc)
                except (IOError, json.JSONDecodeError):
                    pass
                break

        return info

    def scan_available_skills(self, source_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan openclaw/moltbot source directories for available skills.

        Args:
            source_paths: List of paths to scan. If None, uses default locations.

        Returns:
            Dictionary with available skills and their details.
        """
        if source_paths is None:
            # Default locations to look for moltbot/openclaw source
            source_paths = [
                "~/dev/moltbot",
                "~/dev/openclaw",
                "~/dev/clawdbot",
                "~/moltbot",
                "~/openclaw",
                "/opt/moltbot",
                "/opt/openclaw",
            ]

        available_skills: List[SkillInfo] = []
        skills_by_category: Dict[str, List[str]] = {}
        source_paths_checked: List[str] = []

        for src_path in source_paths:
            expanded = self._expand_path(src_path)
            source_paths_checked.append(expanded)

            if not os.path.exists(expanded):
                continue

            # Look for skills directory
            skills_dirs = [
                os.path.join(expanded, "skills"),
                os.path.join(expanded, "src", "skills"),
                os.path.join(expanded, "extensions"),
            ]

            for skills_dir in skills_dirs:
                if not os.path.exists(skills_dir):
                    continue

                try:
                    for skill_name in os.listdir(skills_dir):
                        skill_path = os.path.join(skills_dir, skill_name)
                        if not os.path.isdir(skill_path):
                            continue

                        skill_md = os.path.join(skill_path, "SKILL.md")
                        if os.path.exists(skill_md):
                            skill_info = self._parse_skill_md(skill_md, skill_name, skill_path)
                            if skill_info:
                                available_skills.append(skill_info)

                                # Categorize by connected service
                                for svc in skill_info.get("connected_services", []):
                                    if svc not in skills_by_category:
                                        skills_by_category[svc] = []
                                    skills_by_category[svc].append(skill_info["name"])
                except OSError:
                    pass

        return {
            "source_paths_checked": source_paths_checked,
            "available_skills": available_skills,
            "skills_by_category": skills_by_category,
            "total_count": len(available_skills),
        }

    def _parse_skill_md(self, skill_md_path: str, skill_name: str, skill_path: str) -> Optional[SkillInfo]:
        """Parse a SKILL.md file to extract skill metadata."""
        info: SkillInfo = {
            "name": skill_name,
            "path": skill_path,
            "description": None,
            "homepage": None,
            "emoji": None,
            "requires": [],
            "install_methods": [],
            "connected_services": [],
        }

        try:
            with open(skill_md_path, 'r') as f:
                content = f.read()

            # Parse YAML frontmatter
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    frontmatter = parts[1].strip()
                    # Simple YAML parsing for common fields
                    for line in frontmatter.split('\n'):
                        if ':' in line:
                            key, _, value = line.partition(':')
                            key = key.strip()
                            value = value.strip().strip('"\'')

                            if key == 'name':
                                info['name'] = value
                            elif key == 'description':
                                info['description'] = value
                            elif key == 'homepage':
                                info['homepage'] = value
                            elif key == 'metadata':
                                # Try to parse JSON metadata
                                try:
                                    # Find JSON in the value
                                    json_match = re.search(r'\{.*\}', value)
                                    if json_match:
                                        metadata = json.loads(json_match.group())
                                        moltbot_meta = metadata.get('moltbot', {})
                                        info['emoji'] = moltbot_meta.get('emoji')
                                        requires = moltbot_meta.get('requires', {})
                                        info['requires'] = requires.get('bins', [])
                                        install = moltbot_meta.get('install', [])
                                        info['install_methods'] = [i.get('id') for i in install if i.get('id')]
                                except json.JSONDecodeError:
                                    pass

            # Detect connected services from content
            content_lower = content.lower()
            service_patterns = {
                "telegram": ["telegram", "t.me"],
                "slack": ["slack", "slack.com"],
                "discord": ["discord", "discordapp"],
                "github": ["github", "github.com"],
                "notion": ["notion", "notion.so"],
                "obsidian": ["obsidian", "obsidian.md"],
                "google": ["google", "googleapis"],
                "calendar": ["calendar", "ical", "caldav"],
                "trello": ["trello"],
                "jira": ["jira", "atlassian"],
                "spotify": ["spotify"],
                "openai": ["openai", "gpt"],
                "anthropic": ["anthropic", "claude"],
                "apple": ["apple", "icloud"],
                "whatsapp": ["whatsapp", "wa.me"],
                "email": ["email", "imap", "smtp", "himalaya"],
                "weather": ["weather", "forecast"],
                "notes": ["notes", "bear", "apple-notes"],
                "reminders": ["reminders", "todo", "things"],
                "music": ["spotify", "sonos", "music"],
                "home": ["hue", "homekit", "smart home"],
                "voice": ["whisper", "tts", "speech"],
                "image": ["image", "dall-e", "stable diffusion"],
            }

            for service, patterns in service_patterns.items():
                if any(p in content_lower for p in patterns):
                    if service not in info["connected_services"]:
                        info["connected_services"].append(service)

        except IOError:
            return None

        return info

    def _extract_api_keys_from_config(self, config: Dict[str, Any]) -> List[ApiKeyInfo]:
        """Extract potential API keys from configuration."""
        api_keys: List[ApiKeyInfo] = []
        key_patterns = ["api_key", "apikey", "api-key", "token", "secret", "auth_token"]

        def search_dict(d: Dict[str, Any], path: str = "") -> None:
            for k, v in d.items():
                current_path = f"{path}.{k}" if path else k
                if isinstance(v, dict):
                    search_dict(v, current_path)
                elif isinstance(v, str):
                    k_lower = k.lower()
                    if any(pattern in k_lower for pattern in key_patterns):
                        # Mask the key for security
                        masked_value = v[:4] + "****" + v[-4:] if len(v) > 8 else "****"
                        api_keys.append({
                            "path": current_path,
                            "value_masked": masked_value,
                            "length": len(v)
                        })

        if isinstance(config, dict):
            search_dict(config)
        return api_keys

    def scan_tool(self, tool_name: str) -> ScanResult:
        """Scan for a specific tool installation and status."""
        config: ToolConfig = TOOL_CONFIGS.get(tool_name, {})
        result: ScanResult = {
            "tool_name": tool_name,
            "installed": False,
            "installation_details": {},
            "active": False,
            "processes": [],
            "port_listening": False,
            "config_files": [],
            "log_files": [],
            "connections": [],
            "api_keys_found": [],
            "accessed_apps": [],
            "accessed_apps_summary": {"total_access_events": 0, "by_category": {}, "by_status": {}, "unique_services": [], "access_timeline": []},
            "integrations": [],
            "skills": [],
            "workspace_library": {"connected_apps": [], "channels": [], "skills": [], "skills_from_config": [], "extensions": [], "plugins": [], "mcp_servers": [], "oauth_credentials": [], "tools_md_integrations": []},
        }

        # Check binary installation
        for binary in config.get("binary_names", []):
            binary_path = self._check_binary_installed(binary)
            if binary_path:
                result["installed"] = True
                result["installation_details"]["binary_path"] = binary_path

        # Check npm installation
        npm_info = self._check_npm_package(tool_name)
        if npm_info:
            result["installed"] = True
            result["installation_details"]["npm"] = npm_info

        # Check workspace directory
        workspace_path = self._expand_path(config.get("workspace_path", ""))
        if os.path.exists(workspace_path):
            result["installed"] = True
            result["installation_details"]["workspace_exists"] = True
            result["installation_details"]["workspace_path"] = workspace_path

        # Check running processes
        processes = compat.find_processes(config.get("process_names", []))
        if processes:
            result["active"] = True
            result["processes"] = processes

        # Check default port
        default_port = config.get("default_port")
        if default_port:
            port_listening = self._check_port_listening(default_port)
            result["port_listening"] = port_listening
            result["default_port"] = default_port
            if port_listening:
                result["active"] = True

        # Read configuration files
        for config_path in config.get("config_paths", []):
            config_data = self._read_config_file(config_path)
            if config_data:
                result["config_files"].append({
                    "path": self._expand_path(config_path),
                    "data": config_data
                })
                # Extract API keys from config
                api_keys = self._extract_api_keys_from_config(config_data)
                result["api_keys_found"].extend(api_keys)

                # Extract integrations from config
                integrations = self._extract_integrations_from_config(config_data, tool_name)
                result["integrations"].extend(integrations)

        # Scan skills directory
        workspace_path = config.get("workspace_path", f"~/.{tool_name}/workspace")
        skills = self._scan_skills_directory(workspace_path)
        result["skills"] = skills

        # Scan workspace library for connected apps
        workspace_library = self._scan_workspace_library(tool_name)
        result["workspace_library"] = workspace_library
        # Add workspace connected apps to integrations
        for app in workspace_library.get("connected_apps", []):
            result["integrations"].append({
                "name": app["name"],
                "type": app["type"],
                "source": app.get("source", "workspace_library"),
                "enabled": app.get("details", {}).get("enabled", True),
                "config": app.get("details", {})
            })

        # Find and parse log files
        log_files = self._find_log_files(config.get("log_paths", []))
        result["log_files"] = log_files[:10]  # Limit to 10 most recent

        # Parse connections from logs
        for log_file in log_files[:5]:  # Parse top 5 most recent logs
            connections = self._parse_log_connections(log_file)
            result["connections"].extend(connections)

        # Parse logs for accessed apps/services
        all_accessed_apps: List[AccessedApp] = []
        for log_file in log_files[:5]:  # Parse top 5 most recent logs
            accessed = self._parse_log_for_accessed_apps(log_file)
            all_accessed_apps.extend(accessed)

        # Also try to read system logs (macOS unified log / Linux journalctl)
        system_log_data = self._parse_system_log_for_integrations(tool_name)
        if system_log_data.get("connections"):
            result["connections"].extend(system_log_data["connections"])
        if system_log_data.get("accessed_apps"):
            all_accessed_apps.extend(system_log_data["accessed_apps"])
        if system_log_data.get("log_source"):
            result["log_sources"] = result.get("log_sources", [])
            result["log_sources"].append(system_log_data["log_source"])

        result["accessed_apps"] = all_accessed_apps
        result["accessed_apps_summary"] = self._aggregate_accessed_apps(all_accessed_apps)

        return result

    def scan_all(self, tools: Optional[List[str]] = None, include_available_skills: bool = True) -> Dict[str, Any]:
        """Scan for specified tools or all known tools if none specified."""
        user_info = compat.get_user_info(self.username)
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "machine_info": {
                "hostname": self.hostname,
                "api_key_provided": self.api_key[:4] + "****" if len(self.api_key) > 4 else "****",
                "user": user_info,
            },
            "tools": {},
            "available_skills": {},
        }

        # Use provided tools list or default to all configured tools
        tools_to_scan = tools if tools else list(TOOL_CONFIGS.keys())

        for tool_name in tools_to_scan:
            if tool_name in TOOL_CONFIGS:
                self.results["tools"][tool_name] = self.scan_tool(tool_name)
            else:
                # For custom tools not in TOOL_CONFIGS, create a generic config
                self.results["tools"][tool_name] = self.scan_custom_tool(tool_name)

        # Also scan for available skills from source directories
        if include_available_skills:
            self.results["available_skills"] = self.scan_available_skills()

        return self.results

    def scan_custom_tool(self, tool_name: str) -> ScanResult:
        """Scan for a custom tool using generic paths based on tool name."""
        # Generate generic config paths based on tool name
        generic_config: ToolConfig = {
            "config_paths": [
                f"~/.{tool_name}/config.json",
                f"~/.{tool_name}/config.yaml",
                f"~/.{tool_name}/config.yml",
                f"~/.{tool_name}/{tool_name}.json",
                f"~/.{tool_name}/{tool_name}.yaml",
                f"~/.{tool_name}/{tool_name}.yml",
                f"~/.config/{tool_name}/config.json",
                f"~/.config/{tool_name}/config.yaml",
                f"~/.config/{tool_name}/config.yml",
                f"/etc/{tool_name}/config.yaml",
                f"/etc/{tool_name}/config.yml",
            ],
            "log_paths": [
                f"~/.{tool_name}/logs/*.log",
                f"~/.{tool_name}/*.log",
                f"/var/log/{tool_name}/*.log",
            ],
            "workspace_path": f"~/.{tool_name}/workspace",
            "process_names": [tool_name, f"{tool_name}-agent", f"{tool_name}-daemon", f"{tool_name}-server"],
            "default_port": None,
            "binary_names": [tool_name],
        }

        # Temporarily add to TOOL_CONFIGS
        TOOL_CONFIGS[tool_name] = generic_config
        result = self.scan_tool(tool_name)
        # Remove after scanning
        del TOOL_CONFIGS[tool_name]

        return result

    def add_custom_tool(self, tool_name: str, config: Optional[ToolConfig] = None) -> None:
        """Add a custom tool configuration."""
        if config:
            TOOL_CONFIGS[tool_name] = config
        else:
            # Use generic config
            generic_config: ToolConfig = {
                "config_paths": [
                    f"~/.{tool_name}/config.json",
                    f"~/.{tool_name}/config.yaml",
                    f"~/.{tool_name}/config.yml",
                    f"~/.config/{tool_name}/config.json",
                    f"~/.config/{tool_name}/config.yaml",
                ],
                "log_paths": [
                    f"~/.{tool_name}/logs/*.log",
                    f"~/.{tool_name}/*.log",
                    f"/var/log/{tool_name}/*.log",
                ],
                "workspace_path": f"~/.{tool_name}/workspace",
                "process_names": [tool_name, f"{tool_name}-agent", f"{tool_name}-daemon"],
                "default_port": None,
                "binary_names": [tool_name],
            }
            TOOL_CONFIGS[tool_name] = generic_config

    def generate_report(self) -> str:
        """Generate a human-readable report."""
        if not self.results:
            self.scan_all()

        user_info = self.results['machine_info'].get('user', {})
        lines = [
            "=" * 60,
            "INSTALLATION TRACKER REPORT",
            f"Scan Time: {self.results['scan_timestamp']}",
            "=" * 60,
            "",
            "MACHINE INFORMATION:",
            f"  Hostname: {self.results['machine_info']['hostname']}",
            f"  Computer Name: {user_info.get('computer_name', 'N/A')}",
            f"  Local Hostname: {user_info.get('local_hostname', 'N/A')}",
            f"  API Key (masked): {self.results['machine_info']['api_key_provided']}",
            "",
            "USER INFORMATION:",
            f"  Username: {user_info.get('username', 'N/A')}",
            f"  Full Name: {user_info.get('full_name', 'N/A')}",
            f"  User ID: {user_info.get('user_id', 'N/A')}",
            f"  Group ID: {user_info.get('group_id', 'N/A')}",
            f"  Home Directory: {user_info.get('home_directory', 'N/A')}",
            f"  Shell: {user_info.get('shell', 'N/A')}",
            f"  Groups: {', '.join(user_info.get('groups', [])) or 'N/A'}",
            "",
        ]

        for tool_name, tool_data in self.results["tools"].items():
            lines.append("-" * 40)
            lines.append(f"TOOL: {tool_name.upper()}")
            lines.append("-" * 40)
            lines.append(f"  Installed: {'YES' if tool_data['installed'] else 'NO'}")
            lines.append(f"  Active: {'YES' if tool_data['active'] else 'NO'}")

            if tool_data["installation_details"]:
                lines.append("  Installation Details:")
                for k, v in tool_data["installation_details"].items():
                    lines.append(f"    {k}: {v}")

            if tool_data["processes"]:
                lines.append(f"  Running Processes ({len(tool_data['processes'])}):")
                for proc in tool_data["processes"][:5]:
                    lines.append(f"    PID {proc['pid']}: {proc['command'][:50]}...")

            if tool_data["port_listening"]:
                lines.append(f"  Port {tool_data['default_port']}: LISTENING")

            if tool_data["config_files"]:
                lines.append(f"  Config Files ({len(tool_data['config_files'])}):")
                for cf in tool_data["config_files"]:
                    lines.append(f"    - {cf['path']}")

            if tool_data["api_keys_found"]:
                lines.append(f"  API Keys Found ({len(tool_data['api_keys_found'])}):")
                for ak in tool_data["api_keys_found"]:
                    lines.append(f"    - {ak['path']}: {ak['value_masked']}")

            # Show integrations/channels
            if tool_data.get("integrations"):
                lines.append("")
                lines.append(f"  CONFIGURED INTEGRATIONS ({len(tool_data['integrations'])}):")
                for intg in tool_data["integrations"]:
                    status = "enabled" if intg.get("enabled", True) else "disabled"
                    lines.append(f"    - {intg['name']} [{intg['type']}] ({status})")

            # Show installed skills
            if tool_data.get("skills"):
                lines.append("")
                lines.append(f"  INSTALLED SKILLS ({len(tool_data['skills'])}):")
                for skill in tool_data["skills"]:
                    lines.append(f"    - {skill['name']}")

            # Show workspace library connected apps
            ws_lib = tool_data.get("workspace_library", {})
            if ws_lib.get("channels"):
                lines.append("")
                lines.append(f"  CONNECTED CHANNELS ({len(ws_lib['channels'])}):")
                for ch in ws_lib["channels"]:
                    status = "enabled" if ch.get("enabled", True) else "disabled"
                    token_status = "(has token)" if ch.get("has_token") else "(no token)"
                    lines.append(f"    - {ch['name']} [{status}] {token_status}")

            if ws_lib.get("mcp_servers"):
                lines.append("")
                lines.append(f"  MCP SERVERS ({len(ws_lib['mcp_servers'])}):")
                for srv in ws_lib["mcp_servers"]:
                    lines.append(f"    - {srv['name']}: {srv.get('command', 'N/A')[:50]}")

            if ws_lib.get("extensions"):
                lines.append("")
                lines.append(f"  EXTENSIONS ({len(ws_lib['extensions'])}):")
                for ext in ws_lib["extensions"]:
                    desc = f" - {ext['description'][:40]}..." if ext.get("description") else ""
                    lines.append(f"    - {ext['name']}{desc}")

            if ws_lib.get("oauth_credentials"):
                lines.append("")
                lines.append(f"  OAUTH CREDENTIALS ({len(ws_lib['oauth_credentials'])}):")
                for cred in ws_lib["oauth_credentials"]:
                    lines.append(f"    - {cred['provider']} (has_token: {cred['has_token']})")

            # Show TOOLS.md integrations
            if ws_lib.get("tools_md_integrations"):
                lines.append("")
                lines.append(f"  TOOLS.MD INTEGRATIONS ({len(ws_lib['tools_md_integrations'])}):")
                by_type: Dict[str, List[Integration]] = {}
                for intg in ws_lib["tools_md_integrations"]:
                    intg_type = intg.get("type", "unknown")
                    if intg_type not in by_type:
                        by_type[intg_type] = []
                    by_type[intg_type].append(intg)
                for intg_type, items in by_type.items():
                    lines.append(f"    [{intg_type}]:")
                    for item in items:
                        desc = f" → {item['description']}" if item.get('description') else ""
                        lines.append(f"      - {item['name']}{desc}")

            # Show skills from config entries
            if ws_lib.get("skills_from_config"):
                lines.append("")
                lines.append(f"  SKILLS FROM CONFIG ({len(ws_lib['skills_from_config'])}):")
                for skill in ws_lib["skills_from_config"]:
                    status = "enabled" if skill.get("enabled", True) else "disabled"
                    extras = []
                    if skill.get("has_api_key"):
                        extras.append("has API key")
                    if skill.get("has_env"):
                        extras.append("has env vars")
                    extra_str = f" ({', '.join(extras)})" if extras else ""
                    lines.append(f"    - {skill['name']} [{status}]{extra_str}")

            if ws_lib.get("connected_apps"):
                lines.append("")
                lines.append(f"  ALL CONNECTED APPS ({len(ws_lib['connected_apps'])}):")
                # Group by type
                apps_by_type: Dict[str, List[str]] = {}
                for app in ws_lib["connected_apps"]:
                    app_type = app.get("type", "unknown")
                    if app_type not in apps_by_type:
                        apps_by_type[app_type] = []
                    apps_by_type[app_type].append(app["name"])
                for app_type, app_names in apps_by_type.items():
                    lines.append(f"    [{app_type}]: {', '.join(app_names)}")

            if tool_data["log_files"]:
                lines.append(f"  Log Files ({len(tool_data['log_files'])}):")
                for lf in tool_data["log_files"][:3]:
                    lines.append(f"    - {lf}")

            if tool_data["connections"]:
                lines.append(f"  Connections Found ({len(tool_data['connections'])}):")
                for conn in tool_data["connections"][:10]:
                    lines.append(f"    - {conn['resource']}")

            # Accessed Apps/Integrations - Simple flat list
            summary = tool_data.get("accessed_apps_summary", {})
            unique_services = summary.get("unique_services", [])
            if unique_services:
                lines.append("")
                lines.append("  ACCESSED APPS/INTEGRATIONS:")
                for svc in unique_services:
                    resource = svc.get("resource", "")
                    if resource:
                        lines.append(f"    - {resource}")

            lines.append("")

        # Add available skills section
        available_skills = self.results.get("available_skills", {})
        if available_skills.get("available_skills"):
            lines.append("=" * 60)
            lines.append("AVAILABLE SKILLS FROM SOURCE")
            lines.append("=" * 60)
            lines.append(f"Total: {available_skills.get('total_count', 0)} skills")
            lines.append("")

            # Group by category for compact display
            by_category = available_skills.get("skills_by_category", {})
            if by_category:
                lines.append("BY SERVICE/CATEGORY:")
                for category, skills in sorted(by_category.items()):
                    lines.append(f"  [{category}]: {', '.join(sorted(skills))}")
                lines.append("")

            # List all skills with details
            lines.append("SKILLS LIST:")
            for skill in sorted(available_skills["available_skills"], key=lambda x: x['name']):
                emoji = skill.get('emoji') or '📦'
                name = skill['name']
                desc = (skill.get('description') or '')[:50]
                if desc:
                    desc = f" - {desc}"
                services = skill.get('connected_services', [])
                svc_str = f" [{', '.join(services[:3])}]" if services else ""
                lines.append(f"  {emoji} {name}{desc}{svc_str}")

            lines.append("")

        return "\n".join(lines)

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export results as JSON."""
        if not self.results:
            self.scan_all()

        # Add flat list of all accessed apps/integrations at top level
        all_accessed = []
        seen = set()
        for tool_name, tool_data in self.results.get("tools", {}).items():
            for svc in tool_data.get("accessed_apps_summary", {}).get("unique_services", []):
                resource = svc.get("resource", "")
                if resource and resource not in seen:
                    seen.add(resource)
                    all_accessed.append(resource)

        self.results["accessed_integrations"] = all_accessed

        output = json.dumps(self.results, indent=2, default=str)

        if filepath:
            with open(filepath, "w") as f:
                f.write(output)

        return output

    def generate_access_report(self, as_json: bool = False) -> str:
        """Generate a focused report on accessed apps and servers based on events."""
        if not self.results:
            self.scan_all()

        # Collect all accessed apps across all tools
        all_apps = []
        all_events = []

        for tool_name, tool_data in self.results.get("tools", {}).items():
            for app in tool_data.get("accessed_apps", []):
                app["source_tool"] = tool_name
                all_events.append(app)

            for svc in tool_data.get("accessed_apps_summary", {}).get("unique_services", []):
                svc["source_tool"] = tool_name
                all_apps.append(svc)

        # Aggregate by resource across all tools
        aggregated = {}
        for app in all_apps:
            resource = app.get("resource", "")
            if resource not in aggregated:
                aggregated[resource] = {
                    "resource": resource,
                    "service_name": app.get("service_name"),
                    "category": app.get("category", "Unknown"),
                    "total_access_count": 0,
                    "success_count": 0,
                    "failure_count": 0,
                    "access_types": set(),
                    "source_tools": set(),
                    "first_seen": app.get("first_seen"),
                    "last_seen": app.get("last_seen"),
                }
            aggregated[resource]["total_access_count"] += app.get("access_count", 0)
            aggregated[resource]["success_count"] += app.get("success_count", 0)
            aggregated[resource]["failure_count"] += app.get("failure_count", 0)
            aggregated[resource]["access_types"].update(app.get("access_types", []))
            aggregated[resource]["source_tools"].add(app.get("source_tool", ""))

        # Convert sets to lists for JSON
        for item in aggregated.values():
            item["access_types"] = list(item["access_types"])
            item["source_tools"] = list(item["source_tools"])

        # Sort by access count
        sorted_apps = sorted(aggregated.values(), key=lambda x: x["total_access_count"], reverse=True)

        # Group by category
        by_category: Dict[str, List[Any]] = {}
        for app in sorted_apps:
            cat = app.get("category", "Unknown")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(app)

        # Calculate stats
        stats = {
            "total_unique_resources": len(sorted_apps),
            "total_events": len(all_events),
            "successful_accesses": sum(a.get("success_count", 0) for a in sorted_apps),
            "failed_accesses": sum(a.get("failure_count", 0) for a in sorted_apps),
            "categories": list(by_category.keys()),
        }

        report_data = {
            "report_type": "accessed_apps_and_servers",
            "generated_at": datetime.now().isoformat(),
            "statistics": stats,
            "by_category": by_category,
            "all_resources": sorted_apps,
            "recent_events": all_events[-100:],  # Last 100 events
        }

        if as_json:
            return json.dumps(report_data, indent=2, default=str)

        # Generate text report
        lines = [
            "=" * 70,
            "ACCESSED APPS AND SERVERS REPORT",
            f"Generated: {report_data['generated_at']}",
            "=" * 70,
            "",
            "SUMMARY:",
            f"  Total Unique Resources: {stats['total_unique_resources']}",
            f"  Total Access Events: {stats['total_events']}",
            f"  Successful Accesses: {stats['successful_accesses']}",
            f"  Failed Accesses: {stats['failed_accesses']}",
            f"  Categories: {', '.join(stats['categories'])}",
            "",
        ]

        # List by category
        for category in sorted(by_category.keys()):
            apps = by_category[category]
            lines.append("=" * 70)
            lines.append(f"[{category.upper()}] - {len(apps)} resource(s)")
            lines.append("=" * 70)

            for app in apps:
                resource = app.get("resource", "N/A")
                service_name = app.get("service_name", "")
                access_count = app.get("total_access_count", 0)
                success = app.get("success_count", 0)
                failure = app.get("failure_count", 0)
                access_types = ", ".join(app.get("access_types", []))
                tools = ", ".join(app.get("source_tools", []))

                lines.append("")
                lines.append(f"  Resource: {resource}")
                if service_name and service_name != "Unknown":
                    lines.append(f"  Service:  {service_name}")
                lines.append(f"  Access Count: {access_count} (success: {success}, failed: {failure})")
                if access_types:
                    lines.append(f"  Access Types: {access_types}")
                if tools:
                    lines.append(f"  Source Tools: {tools}")
                lines.append("  " + "-" * 40)

            lines.append("")

        # Recent events section
        if all_events:
            lines.append("=" * 70)
            lines.append("RECENT ACCESS EVENTS (last 20)")
            lines.append("=" * 70)

            for event in all_events[-20:]:
                resource = event.get("resource", "N/A")
                status = event.get("status", "unknown")
                access_type = event.get("access_type", "N/A")
                timestamp = event.get("timestamp", "N/A")
                tool = event.get("source_tool", "N/A")

                status_icon = "✓" if status == "success" else "✗" if status == "failed" else "?"
                lines.append(f"  [{status_icon}] {resource[:50]}")
                lines.append(f"      Type: {access_type} | Status: {status} | Tool: {tool}")
                if timestamp:
                    lines.append(f"      Time: {timestamp}")
                lines.append("")

        return "\n".join(lines)

    def get_accessed_apps_list(self) -> List[Dict[str, Any]]:
        """Get a simple list of all accessed apps/servers."""
        if not self.results:
            self.scan_all()

        apps_list = []
        seen = set()

        for tool_name, tool_data in self.results.get("tools", {}).items():
            for svc in tool_data.get("accessed_apps_summary", {}).get("unique_services", []):
                resource = svc.get("resource", "")
                if resource and resource not in seen:
                    seen.add(resource)
                    apps_list.append({
                        "resource": resource,
                        "service_name": svc.get("service_name"),
                        "category": svc.get("category"),
                        "access_count": svc.get("access_count", 0),
                        "success_count": svc.get("success_count", 0),
                        "failure_count": svc.get("failure_count", 0),
                        "source_tool": tool_name,
                    })

        return sorted(apps_list, key=lambda x: x["access_count"], reverse=True)

    def auto_discover_log_files(self, tools_only: bool = False, tool_names: Optional[List[str]] = None) -> List[str]:
        """Automatically discover log files on the system.

        Args:
            tools_only: If True, only search for logs from tracked tools (clawbot/moltbot/openclaw)
            tool_names: Optional list of specific tool names to search for
        """
        discovered_logs = []

        # If tools_only, only search for specific tool logs
        if tools_only or tool_names:
            tools = tool_names or list(TOOL_CONFIGS.keys())
            log_locations = []
            for tool in tools:
                log_locations.extend([
                    f"~/.{tool}/*.log",
                    f"~/.{tool}/logs/*.log",
                    f"~/.{tool}/log/*.log",
                    f"~/.{tool}/**/*.log",
                    f"~/.config/{tool}/*.log",
                    f"~/.config/{tool}/logs/*.log",
                    f"~/.local/share/{tool}/*.log",
                    f"~/.local/share/{tool}/logs/*.log",
                    f"/var/log/{tool}/*.log",
                    f"/var/log/{tool}*/*.log",
                    f"/tmp/{tool}*.log",
                    f"~/Library/Logs/{tool}/*.log",
                    f"~/Library/Logs/{tool.capitalize()}/*.log",
                    f"~/Library/Application Support/{tool}/logs/*.log",
                    f"~/Library/Application Support/{tool.capitalize()}/logs/*.log",
                ])
        else:
            # Common log file locations to search
            log_locations = [
                # User home directory logs
                "~/.*/logs/*.log",
                "~/.*/log/*.log",
                "~/.*/logs/*.txt",
                "~/.*/log/*.txt",
                "~/.*/output.log",
                "~/.*/debug.log",
                "~/.*/error.log",
                "~/.*/app.log",
                "~/.*/*.log",

                # Config directories
                "~/.config/*/logs/*.log",
                "~/.config/*/*.log",
                "~/.local/share/*/logs/*.log",
                "~/.local/state/*/*.log",

                # Application specific
                "~/.npm/_logs/*.log",
                "~/.yarn/logs/*.log",
                "~/.docker/*.log",
                "~/.kube/*.log",

                # AI/Bot tools
                "~/.claude/*.log",
                "~/.claude/logs/*.log",
                "~/.anthropic/*.log",
                "~/.openai/*.log",
                "~/.copilot/*.log",
                "~/.cursor/*.log",
                "~/.tabnine/*.log",
                "~/.codeium/*.log",

                # Common app directories
                "~/.vscode/*.log",
                "~/.vscode/logs/*.log",
                "~/Library/Logs/*/*.log",
                "~/Library/Logs/*.log",
                "~/Library/Application Support/*/logs/*.log",

                # System logs (if accessible)
                "/var/log/*.log",
                "/var/log/*/*.log",
                "/tmp/*.log",

                # Current directory and project logs
                "./*.log",
                "./logs/*.log",
                "./log/*.log",
            ]

        for pattern in log_locations:
            expanded = self._expand_path(pattern)
            try:
                matches = glob.glob(expanded, recursive=False)
                for match in matches:
                    if os.path.isfile(match) and os.access(match, os.R_OK):
                        # Skip very large files (>50MB) and binary files
                        try:
                            size = os.path.getsize(match)
                            if size > 50 * 1024 * 1024:  # 50MB
                                continue
                            # Quick check if file is text
                            with open(match, 'rb') as f:
                                chunk = f.read(1024)
                                if b'\x00' in chunk:  # Binary file
                                    continue
                            discovered_logs.append(match)
                        except (IOError, OSError):
                            continue
            except (OSError, PermissionError):
                continue

        # Remove duplicates and sort by modification time (newest first)
        discovered_logs = list(set(discovered_logs))
        try:
            discovered_logs.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        except OSError:
            pass

        return discovered_logs

    def scan_log_files(self, log_file_patterns: List[str]) -> Dict[str, Any]:
        """Scan specific log files directly for accessed apps/services."""
        user_info = compat.get_user_info(self.username)

        # Expand glob patterns and collect all log files
        all_log_files = []
        for pattern in log_file_patterns:
            expanded = self._expand_path(pattern)
            if '*' in expanded or '?' in expanded:
                all_log_files.extend(glob.glob(expanded))
            elif os.path.exists(expanded):
                all_log_files.append(expanded)

        # Remove duplicates and sort
        all_log_files = sorted(set(all_log_files))

        # Parse all log files
        all_accessed_apps: List[AccessedApp] = []
        all_connections = []

        for log_file in all_log_files:
            accessed = self._parse_log_for_accessed_apps(log_file)
            all_accessed_apps.extend(accessed)

            connections = self._parse_log_connections(log_file)
            all_connections.extend(connections)

        # Build results
        self.results = {
            "scan_timestamp": datetime.now().isoformat(),
            "scan_type": "custom_log_files",
            "machine_info": {
                "hostname": self.hostname,
                "api_key_provided": self.api_key[:4] + "****" if len(self.api_key) > 4 else "****",
                "user": user_info,
            },
            "log_files_scanned": all_log_files,
            "log_files_count": len(all_log_files),
            "tools": {
                "custom_logs": {
                    "tool_name": "custom_logs",
                    "installed": True,
                    "installation_details": {"source": "custom_log_files"},
                    "active": True,
                    "processes": [],
                    "port_listening": False,
                    "config_files": [],
                    "api_keys_found": [],
                    "log_files": all_log_files,
                    "connections": all_connections,
                    "accessed_apps": all_accessed_apps,
                    "accessed_apps_summary": self._aggregate_accessed_apps(all_accessed_apps),
                }
            }
        }

        return self.results


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Track tool installations (clawbot/moltbot/openclaw and custom tools)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default tools (openclaw, moltbot, clawbot)
  python installation_tracker.py

  # Scan specific tools from the default list
  python installation_tracker.py --tools openclaw moltbot

  # Scan custom tools (will use generic paths based on tool name)
  python installation_tracker.py --tools mytool anothertool

  # Mix default and custom tools
  python installation_tracker.py --tools openclaw mytool custombot

  # Output as JSON
  python installation_tracker.py --tools openclaw --json

  # Save to file
  python installation_tracker.py --tools openclaw moltbot -o report.json --json

  # List accessed apps and servers (focused report)
  python installation_tracker.py --access-report
  python installation_tracker.py --access-report --json

  # Simple list of accessed resources
  python installation_tracker.py --list-accessed
  python installation_tracker.py --list-accessed --json

  # Scan specific log files directly
  python installation_tracker.py --log-files /path/to/app.log
  python installation_tracker.py --log-files /var/log/*.log ~/.myapp/logs/*.log
  python installation_tracker.py --log-files /path/to/*.log --access-report
        """
    )
    parser.add_argument(
        "--scanner-report-api-key",
        default=SCANNER_REPORT_API_KEY,
        help="API key for sending report to server (or set SCANNER_REPORT_API_KEY env variable)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of text report"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path"
    )
    parser.add_argument(
        "--tool",
        help="Scan only a specific tool (deprecated, use --tools instead)"
    )
    parser.add_argument(
        "--tools",
        "-t",
        nargs="+",
        help="List of tools to scan (e.g., --tools openclaw moltbot mytool)"
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all predefined tools and exit"
    )
    parser.add_argument(
        "--access-report",
        action="store_true",
        help="Generate a focused report on accessed apps and servers"
    )
    parser.add_argument(
        "--list-accessed",
        action="store_true",
        help="Output a simple list of accessed apps/servers"
    )
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Output a simple flat list of all resources (no categories, just the list)"
    )
    parser.add_argument(
        "--log-files",
        "-l",
        nargs="+",
        help="Scan specific log files directly (e.g., --log-files /path/to/app.log /var/log/*.log)"
    )
    parser.add_argument(
        "--auto-discover",
        "-a",
        action="store_true",
        help="Automatically discover and scan log files on the system"
    )
    parser.add_argument(
        "--tools-only",
        action="store_true",
        help="Only search for logs from tracked tools (clawbot/moltbot/openclaw)"
    )
    parser.add_argument(
        "--show-discovered",
        action="store_true",
        help="Show discovered log files without scanning"
    )
    parser.add_argument(
        "--scan-skills",
        action="store_true",
        help="Scan openclaw/moltbot source directories for available skills"
    )
    parser.add_argument(
        "--skills-path",
        type=str,
        nargs="+",
        help="Custom paths to scan for skills (use with --scan-skills)"
    )

    args = parser.parse_args()

    # Handle --list-tools
    if args.list_tools:
        print("Predefined tools:")
        for tool_name, config in TOOL_CONFIGS.items():
            print(f"  {tool_name}:")
            print(f"    Port: {config.get('default_port', 'N/A')}")
            print(f"    Processes: {', '.join(config.get('process_names', []))}")
        print("\nYou can also specify custom tool names with --tools")
        return

    tracker = InstallationTracker(api_key=args.api_key)

    # Handle --scan-skills
    if args.scan_skills:
        skills_paths = args.skills_path if args.skills_path else None
        print("Scanning for available openclaw/moltbot skills...")
        skills_result = tracker.scan_available_skills(skills_paths)

        if args.json:
            print(json.dumps(skills_result, indent=2))
        else:
            print(f"\n{'='*60}")
            print("AVAILABLE SKILLS")
            print(f"{'='*60}")
            print(f"\nTotal skills found: {skills_result['total_count']}")
            print("\nSource paths checked:")
            for p in skills_result['source_paths_checked']:
                exists = "✓" if os.path.exists(p) else "✗"
                print(f"  [{exists}] {p}")

            if skills_result['available_skills']:
                print(f"\n{'-'*40}")
                print("SKILLS LIST:")
                print(f"{'-'*40}")
                for skill in sorted(skills_result['available_skills'], key=lambda x: x['name']):
                    emoji = skill.get('emoji') or '📦'
                    name = skill['name']
                    desc = (skill.get('description') or 'No description')[:60]
                    if len(skill.get('description') or '') > 60:
                        desc += '...'
                    services = ', '.join(skill.get('connected_services', []))[:30]
                    requires = ', '.join(skill.get('requires', []))

                    print(f"\n  {emoji} {name}")
                    print(f"      {desc}")
                    if services:
                        print(f"      Services: {services}")
                    if requires:
                        print(f"      Requires: {requires}")

                print(f"\n{'-'*40}")
                print("BY CATEGORY:")
                print(f"{'-'*40}")
                for category, skills in sorted(skills_result['skills_by_category'].items()):
                    print(f"  [{category}]: {', '.join(sorted(skills))}")
            else:
                print("\nNo skills found. Make sure moltbot/openclaw source is available.")

        if args.output:
            with open(args.output, 'w') as f:
                if args.json:
                    f.write(json.dumps(skills_result, indent=2))
                else:
                    f.write(f"Available Skills: {skills_result['total_count']}\n")
                    for skill in skills_result['available_skills']:
                        f.write(f"- {skill['name']}: {skill.get('description', 'N/A')}\n")
            print(f"\nOutput saved to {args.output}")
        return

    # Handle --show-discovered
    if args.show_discovered:
        tools_filter: Optional[List[str]] = args.tools if args.tools else (list(TOOL_CONFIGS.keys()) if args.tools_only else None)
        if args.tools_only and tools_filter:
            print(f"Discovering log files for tools: {', '.join(tools_filter)}...")
        else:
            print("Discovering log files...")
        discovered = tracker.auto_discover_log_files(
            tools_only=args.tools_only,
            tool_names=args.tools
        )
        if discovered:
            print(f"\nFound {len(discovered)} log files:\n")
            for log_file in discovered:
                try:
                    size = os.path.getsize(log_file)
                    size_str = f"{size / 1024:.1f}KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f}MB"
                    print(f"  {log_file} ({size_str})")
                except OSError:
                    print(f"  {log_file}")
        else:
            print("No log files found.")
        return

    # Determine which tools to scan
    tools_to_scan = None
    if args.tools:
        tools_to_scan = args.tools
    elif args.tool:
        tools_to_scan = [args.tool]

    # Perform scan - auto-discover, custom log files, or tool-based
    if args.auto_discover:
        if args.tools_only:
            tools_filter = args.tools if args.tools else list(TOOL_CONFIGS.keys())
            print(f"Auto-discovering log files for: {', '.join(tools_filter)}...")
        else:
            print("Auto-discovering log files...")
        discovered = tracker.auto_discover_log_files(
            tools_only=args.tools_only,
            tool_names=args.tools
        )
        if discovered:
            print(f"Found {len(discovered)} log files, scanning...\n")
            tracker.scan_log_files(discovered)
        else:
            print("No log files found. Running standard tool scan.\n")
            tracker.scan_all(tools=tools_to_scan)
    elif args.log_files:
        tracker.scan_log_files(args.log_files)
    else:
        tracker.scan_all(tools=tools_to_scan)

    # Generate appropriate output
    if args.access_report:
        # Focused report on accessed apps/servers
        output = tracker.generate_access_report(as_json=args.json)
    elif args.simple:
        # Simple flat list - just resources, no categories
        apps_list = tracker.get_accessed_apps_list()
        if args.json:
            # Just the resource names
            output = json.dumps([app['resource'] for app in apps_list], indent=2)
        else:
            if apps_list:
                output = "\n".join([app['resource'] for app in apps_list])
            else:
                output = "No accessed apps/servers found."
    elif args.list_accessed:
        # Simple list of accessed apps/servers
        apps_list = tracker.get_accessed_apps_list()
        if args.json:
            output = json.dumps(apps_list, indent=2, default=str)
        else:
            lines = [
                "ACCESSED APPS AND SERVERS LIST",
                "=" * 50,
                ""
            ]
            if apps_list:
                for app in apps_list:
                    status = f"✓{app['success_count']}" if app['success_count'] else ""
                    if app['failure_count']:
                        status += f" ✗{app['failure_count']}"
                    category = f"[{app['category']}]" if app['category'] else ""
                    lines.append(f"  {app['resource']}")
                    lines.append(f"    {category} Count: {app['access_count']} {status}")
                    lines.append("")
            else:
                lines.append("  No accessed apps/servers found in logs.")
            output = "\n".join(lines)
    elif tools_to_scan and len(tools_to_scan) == 1:
        # Single tool scan - output just that tool's data
        tool_name = tools_to_scan[0]
        result = tracker.results.get("tools", {}).get(tool_name, {})
        output = json.dumps(result, indent=2, default=str)
    else:
        # Full report
        if args.json:
            output = tracker.export_json()
        else:
            output = tracker.generate_report()

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
