#!/usr/bin/env python3
"""
OpenClaw Usage Scanner
Scans bot data directory, detects active skills, and session logs for tools/apps usage.
Outputs JSON with all collected data.
"""

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict

import certifi

from platform_compat import compat as _compat
from platform_compat.common import build_install_info_from_cli, detect_clawd_install, find_bot_cli_only, get_system_info
from structures import CLAWDBOT_VARIANT_NAMES, CliCommand, ClawdbotInstallInfo
from output_structures import OutputSkillEntry, OutputSummary
from nano_scanner import scan_nano

API_ENDPOINT = "https://oneclaw.prompt.security/api/reports"


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context using certifi certificates."""
    return ssl.create_default_context(cafile=certifi.where())


class CliExecError(Exception):
    """Raised when CLI command execution fails."""


def _run_bot_cli(bot_cli_cmd: Optional[CliCommand], *args: str, timeout: int = 30) -> str:
    """Run bot CLI command and return stdout on success.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.
        *args: Command arguments (e.g., "nodes", "list")
        timeout: Command timeout in seconds

    Returns:
        stdout as string on success

    Raises:
        CliExecError: On any failure (not found, timeout, non-zero exit, etc.)
    """
    # Auto-detect bot CLI if not provided
    if bot_cli_cmd is None:
        install_info = detect_clawd_install()
        if install_info is None:
            raise CliExecError("Bot CLI not found")
        bot_cli_cmd = install_info.bot_cli_cmd

    # Build environment with node in PATH if CLI is from nvm
    # The CLI binary uses "#!/usr/bin/env node" which needs node in PATH
    env = os.environ.copy()
    cli_path = Path(bot_cli_cmd[0]) if bot_cli_cmd else None
    if cli_path and ".nvm" in str(cli_path):
        # Add the bin directory containing node to PATH
        nvm_bin_dir = str(cli_path.parent)
        current_path = env.get("PATH", "")
        if nvm_bin_dir not in current_path:
            env["PATH"] = f"{nvm_bin_dir}:{current_path}"

    try:
        result = subprocess.run(
            bot_cli_cmd + list(args), capture_output=True, text=True, timeout=timeout, env=env, check=False
        )

        if result.returncode != 0:
            raise CliExecError(f"Command failed: {result.stderr.strip()}")

        return result.stdout

    except subprocess.TimeoutExpired as e:
        raise CliExecError("Command timed out") from e
    except FileNotFoundError as e:
        raise CliExecError(f"Bot CLI not found: {' '.join(bot_cli_cmd)}") from e
    except Exception as e:
        if isinstance(e, CliExecError):
            raise
        raise CliExecError(str(e)) from e


def get_bot_version(bot_cli_cmd: Optional[CliCommand] = None) -> Optional[str]:
    """Get bot version via --version flag.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Version string (e.g., "2026.1.24", "v0.1.0") or None on failure
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "--version", timeout=10)
        # Extract semver-like version from first line of output.
        # Handles decorated output like "🦞 picoclaw v0.1.1\n  Build: ...\n  Go: go1.25.7"
        # and "🐈 nanobot v0.1.0" and plain "2026.1.24".
        first_line = stdout.strip().splitlines()[0] if stdout.strip() else ""
        match = re.search(r"v?\d+\.\d+(?:\.\d+)?", first_line)
        return match.group(0) if match else first_line.strip() or None
    except CliExecError:
        return None


class SkillsResult(TypedDict, total=False):
    """Return type for get_active_skills()."""
    active_skills: List[OutputSkillEntry]  # Shape from openclaw skills list --json
    count: int
    total: int           # Only on success
    error: str           # Only on error
    cli_searched: bool   # Only when auto-detection was attempted



def get_active_skills(bot_cli_cmd: Optional[CliCommand] = None) -> SkillsResult:
    """Run openclaw skills list and filter only active skills.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        SkillsResult with active_skills list and counts (or error on failure)
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "skills", "list", "--json")
    except CliExecError as e:
        return {"error": str(e), "active_skills": [], "count": 0}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}", "active_skills": [], "count": 0}

    all_skills = data.get("skills", [])

    # Filter for active/eligible skills (not disabled)
    active_skills = [
        skill for skill in all_skills
        if skill.get("eligible", False) and not skill.get("disabled", False)
    ]

    return {
        "active_skills": active_skills,
        "count": len(active_skills),
        "total": len(all_skills)
    }


def get_cron_jobs(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw cron list to get scheduled cron jobs.

    Args:
        bot_cli_cmd: Bot CLI base command as list. If None, auto-detects.

    Returns:
        Dict with cron jobs list and count
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "cron", "list")
    except CliExecError as e:
        return {"error": str(e), "cron_jobs": [], "count": 0}

    # Try to parse as JSON first
    try:
        data = json.loads(stdout)
        cron_jobs = data if isinstance(data, list) else data.get("cron_jobs", data.get("jobs", []))
        return {"cron_jobs": cron_jobs, "count": len(cron_jobs) if isinstance(cron_jobs, list) else 0}
    except json.JSONDecodeError:
        # If not JSON, parse the text output
        lines = stdout.strip().split("\n")
        cron_jobs = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith(("#", "No cron", "CRON")):
                cron_jobs.append({"raw": line})

        return {
            "cron_jobs": cron_jobs,
            "count": len(cron_jobs),
            "raw_output": stdout.strip()
        }


def get_security_audit(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw security audit to check for security issues.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with security audit results
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "security", "audit", timeout=60)
        passed = True
    except CliExecError as e:
        # Security audit may return non-zero on findings - that's not an error
        error_str = str(e)
        if "Command failed (exit" in error_str:
            # Extract any output from the error for parsing
            passed = False
            stdout = ""  # We lost the output in this case
        else:
            return {"error": error_str}

    output = stdout.strip()

    # Try to parse as JSON first
    try:
        data = json.loads(output)
        return {
            "audit_results": data,
            "issues_found": len(data) if isinstance(data, list) else data.get("issues", []),
            "passed": passed
        }
    except json.JSONDecodeError:
        return {"raw_output": output or None, "passed": passed}


def get_plugins_list(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw plugins list to get active plugins only.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with active plugins list and count
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "plugins", "list", "--json")
    except CliExecError as e:
        return {"error": str(e), "active_plugins": [], "count": 0}

    try:
        data = json.loads(stdout)
        all_plugins = data if isinstance(data, list) else data.get("plugins", [])

        # Filter for active plugins only - exclude disabled ones
        active_plugins = []
        for plugin in all_plugins:
            if not isinstance(plugin, dict):
                continue
            # Skip if explicitly disabled
            if plugin.get("enabled") is False:
                continue
            if plugin.get("status") == "disabled":
                continue
            if plugin.get("disabled") is True:
                continue
            if plugin.get("active") is False:
                continue
            active_plugins.append(plugin)

        return {
            "active_plugins": active_plugins,
            "count": len(active_plugins),
            "total": len(all_plugins)
        }
    except json.JSONDecodeError:
        lines = stdout.strip().split("\n")
        plugins = [{"raw": line.strip()} for line in lines if line.strip()]
        return {
            "active_plugins": plugins,
            "count": len(plugins),
            "raw_output": stdout.strip()
        }


def get_channels_list(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw channels list to get configured channels/integrations.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.
    Returns:
        Dict with channels list and count
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "channels", "list")
    except CliExecError as e:
        return {"error": str(e), "channels": [], "count": 0}

    try:
        data = json.loads(stdout)
        channels = data if isinstance(data, list) else data.get("channels", [])
        return {"channels": channels, "count": len(channels) if isinstance(channels, list) else 0}
    except json.JSONDecodeError:
        lines = stdout.strip().split("\n")
        channels = [{"raw": line.strip()} for line in lines if line.strip()]
        return {
            "channels": channels,
            "count": len(channels),
            "raw_output": stdout.strip()
        }


def get_nodes_list(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw nodes list to get connected/paired nodes.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with nodes list and count
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "nodes", "list")
    except CliExecError as e:
        return {"error": str(e), "nodes": [], "count": 0}

    try:
        data = json.loads(stdout)
        nodes = data if isinstance(data, list) else data.get("nodes", [])
        return {"nodes": nodes, "count": len(nodes) if isinstance(nodes, list) else 0}
    except json.JSONDecodeError:
        lines = stdout.strip().split("\n")
        nodes = [{"raw": line.strip()} for line in lines if line.strip()]
        return {
            "nodes": nodes,
            "count": len(nodes),
            "raw_output": stdout.strip()
        }


def get_models_status(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw models status to get authentication and model status.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.
    Returns:
        Dict with models status including auth info
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "models", "status")
    except CliExecError as e:
        return {"error": str(e)}

    try:
        return {"models_status": json.loads(stdout), "has_auth": True}
    except json.JSONDecodeError:
        return {"raw_output": stdout.strip(), "passed": True}


def get_agent_config(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw config get agents to get agent concurrency settings.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with max_concurrent and autonomous_mode flag
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "config", "get", "agents", "--json")
    except CliExecError as e:
        return {"error": str(e), "max_concurrent": None, "autonomous_mode": None}

    try:
        data = json.loads(stdout)
        max_concurrent = data.get("defaults", {}).get("maxConcurrent", 1)
        # maxConcurrent > 1 indicates autonomous/parallel execution
        return {
            "max_concurrent": max_concurrent,
            "autonomous_mode": max_concurrent > 1,
            "subagent_max_concurrent": data.get("defaults", {}).get("subagents", {}).get("maxConcurrent"),
            "workspace": data.get("defaults", {}).get("workspace"),
        }
    except json.JSONDecodeError:
        return {"raw_output": stdout.strip(), "autonomous_mode": None}


def get_exec_approvals(bot_cli_cmd: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw approvals get to get execution permissions/approvals.

    Args:
        bot_cli_cmd: Bot CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with approvals and permissions info
    """
    try:
        stdout = _run_bot_cli(bot_cli_cmd, "approvals", "get", "--json")
    except CliExecError as e:
        return {"error": str(e), "permissions": []}

    try:
        data = json.loads(stdout)
        file_data = data.get("file", {})
        permissions: List[str] = []

        # Extract socket permissions
        for socket_name in file_data.get("socket", {}).keys():
            permissions.append(f"socket:{socket_name}")

        # Extract default permissions
        for perm_name in file_data.get("defaults", {}).keys():
            permissions.append(f"default:{perm_name}")

        # Extract agent-specific permissions
        for agent_name in file_data.get("agents", {}).keys():
            permissions.append(f"agent:{agent_name}")

        return {
            "approvals_path": data.get("path"),
            "approvals_exist": data.get("exists", False),
            "permissions": permissions,
            "permissions_count": len(permissions),
        }
    except json.JSONDecodeError:
        return {"raw_output": stdout.strip(), "permissions": []}


def scan_session_logs(bot_config_dir: Path) -> Dict[str, Any]:
    """Scan session logs and extract tools and apps used.

    Args:
        bot_config_dir: Path to the bot config folder (e.g., ~/.openclaw)

    Returns:
        Dict with tool calls, usage summary, and apps used
    """
    sessions_dir = bot_config_dir / "agents" / "main" / "sessions"

    if not sessions_dir.exists():
        return {
            "error": f"Sessions directory not found: {sessions_dir}",
            "tool_calls": [],
            "tools_summary": {},
            "apps_summary": {}
        }

    tool_calls = []

    # Find all session .jsonl files (sorted for deterministic processing)
    session_files = sorted([f for f in sessions_dir.glob("*.jsonl") if f.name != "sessions.json"])

    for session_file in session_files:
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                for line in f:
                    # Quick check before parsing JSON
                    if "toolCall" not in line:
                        continue
                    try:
                        data = json.loads(line.strip())
                        if data.get("type") != "message":
                            continue
                        message = data.get("message", {})
                        content = message.get("content", [])

                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "toolCall":
                                arguments = item.get("arguments", {})
                                command = arguments.get("command", "")
                                apps = _compat.extract_app_names(command) if command else []

                                tool_calls.append({
                                    "tool_name": item.get("name"),
                                    "tool_id": item.get("id"),
                                    "timestamp": data.get("timestamp"),
                                    "session": session_file.stem,
                                    "arguments": arguments,
                                    "apps_detected": apps
                                })
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue

    # Sort by timestamp (most recent first)
    tool_calls.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Build tools usage summary
    tools_summary: Dict[str, int] = {}
    for tc in tool_calls:
        name = tc.get("tool_name", "unknown")
        tools_summary[name] = tools_summary.get(name, 0) + 1

    # Sort by count (descending)
    tools_summary = dict(sorted(tools_summary.items(), key=lambda x: x[1], reverse=True))

    # Build apps usage summary and collect full commands per app
    apps_summary: Dict[str, int] = {}
    apps_commands: Dict[str, List[Dict[str, str]]] = {}
    for tc in tool_calls:
        command = tc.get("arguments", {}).get("command", "")
        timestamp = tc.get("timestamp", "")
        for app in tc.get("apps_detected", []):
            apps_summary[app] = apps_summary.get(app, 0) + 1
            if command:
                if app not in apps_commands:
                    apps_commands[app] = []
                apps_commands[app].append({
                    "command": command,
                    "timestamp": timestamp,
                    "session": tc.get("session", ""),
                })

    apps_summary = dict(sorted(apps_summary.items(), key=lambda x: x[1], reverse=True))
    apps_commands = {app: apps_commands[app] for app in apps_summary if app in apps_commands}

    # Extract web activity from tool calls (browser, web_fetch, web_search)
    browser_urls: List[Dict[str, str]] = []
    fetched_urls: List[Dict[str, str]] = []
    search_queries: List[Dict[str, str]] = []

    for tc in tool_calls:
        tool_name = tc.get("tool_name", "")
        tc_args = tc.get("arguments", {})
        tc_timestamp = tc.get("timestamp", "")
        tc_session = tc.get("session", "")

        if tool_name == "browser":
            url = tc_args.get("targetUrl", "") or tc_args.get("url", "")
            if url:
                browser_urls.append({
                    "url": url,
                    "action": tc_args.get("action", "open"),
                    "timestamp": tc_timestamp,
                    "session": tc_session,
                })
        elif tool_name == "web_fetch":
            url = tc_args.get("url", "")
            if url:
                fetched_urls.append({
                    "url": url,
                    "timestamp": tc_timestamp,
                    "session": tc_session,
                })
        elif tool_name == "web_search":
            query = tc_args.get("query", "")
            if query:
                search_queries.append({
                    "query": query,
                    "timestamp": tc_timestamp,
                    "session": tc_session,
                })

    web_activity: Dict[str, Any] = {
        "browser_urls": browser_urls,
        "fetched_urls": fetched_urls,
        "search_queries": search_queries,
        "browser_urls_count": len(browser_urls),
        "fetched_urls_count": len(fetched_urls),
        "search_queries_count": len(search_queries),
    }

    return {
        "tool_calls": tool_calls,
        "tools_summary": tools_summary,
        "apps_summary": apps_summary,
        "apps_commands": apps_commands,
        "web_activity": web_activity,
        "total_tool_calls": len(tool_calls),
        "unique_tools": len(tools_summary),
        "unique_apps": len(apps_summary),
        "sessions_scanned": len([f for f in session_files if f.name != "sessions.json"])
    }


def send_report(report_data: Dict[str, Any], api_key: str, verify_ssl: bool = True) -> Dict[str, Any]:
    """Send scan report to the API endpoint.

    Args:
        report_data: The scan report to send
        api_key: API key for authorization
        verify_ssl: Whether to verify SSL certificates (default True)

    Returns:
        Dict with success status and response or error message
    """
    # Remove api_key from the payload (it's used in header, not body)
    payload = {k: v for k, v in report_data.items() if k != "api_key"}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "OpenClaw-Scanner/1.0"
    }

    response = None
    response_body = None

    # Set up SSL context
    if verify_ssl:
        ssl_context = create_ssl_context()
    else:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            API_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
            response_body = response.read().decode("utf-8")
            return {
                "success": True,
                "status_code": response.status,
                "response": json.loads(response_body) if response_body else {}
            }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        return {
            "success": False,
            "status_code": e.code,
            "error": f"HTTP {e.code}: {e.reason}",
            "response": error_body
        }
    except urllib.error.URLError as e:
        return {
            "success": False,
            "error": f"Connection error: {e.reason}"
        }
    except json.JSONDecodeError:
        return {
            "success": True,
            "status_code": response.status if response is not None else 0,
            "response": response_body
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def scan_openclaw(install_info: ClawdbotInstallInfo, full: bool = False, limit: int = 50) -> Dict[str, Any]:
    """Scan an OpenClaw/Clawdbot variant using CLI commands.
    Returns result dict with scan_timestamp, bot_variant, system_info, summary, etc.
    """
    bot_cli_cmd = install_info.bot_cli_cmd
    bot_cli_str = " ".join(install_info.bot_cli_cmd)
    bot_config_dir = install_info.bot_config_dir
    bot_variant = install_info.bot_variant
    bot_version = get_bot_version(bot_cli_cmd)

    # Collect scan data
    skills_result = get_active_skills(bot_cli_cmd)
    logs_result = scan_session_logs(bot_config_dir)
    system_info = get_system_info()
    cron_result = get_cron_jobs(bot_cli_cmd)
    security_result = get_security_audit(bot_cli_cmd)  # CISO-critical
    plugins_result = get_plugins_list(bot_cli_cmd)  # attack surface
    channels_result = get_channels_list(bot_cli_cmd)  # external integrations
    nodes_result = get_nodes_list(bot_cli_cmd)  # remote connections
    models_result = get_models_status(bot_cli_cmd)  # auth posture
    agent_config = get_agent_config(bot_cli_cmd)  # autonomous mode
    exec_approvals = get_exec_approvals(bot_cli_cmd)  # permissions

    # Limit tool calls in output
    logs_result["tool_calls"] = logs_result["tool_calls"][:limit]

    # Build summary
    active_skills_list = skills_result.get("active_skills", [])
    apps_summary = logs_result.get("apps_summary", {})
    tool_names = list(logs_result.get("tools_summary", {}).keys())

    summary: OutputSummary = {
        "active_skills": active_skills_list,
        "active_skills_count": len(active_skills_list),
        "apps_detected": list(apps_summary.keys()),
        "apps_detected_count": len(apps_summary),
        "apps_call_count": apps_summary,
        "apps_commands": logs_result.get("apps_commands", {}),
        "tools_used": tool_names,
        "tools_used_count": len(tool_names),
        "tools_call_count": logs_result.get("tools_summary", {}),
        "total_tool_calls": logs_result.get("total_tool_calls", 0),
        "sessions_scanned": logs_result.get("sessions_scanned", 0),
        "cron_jobs": cron_result.get("cron_jobs", []),
        "cron_jobs_count": cron_result.get("count", 0),
        # CISO-relevant data
        "security_audit": security_result,
        "active_plugins": plugins_result.get("active_plugins", []),
        "active_plugins_count": plugins_result.get("count", 0),
        "channels": channels_result.get("channels", []),
        "channels_count": channels_result.get("count", 0),
        "nodes": nodes_result.get("nodes", []),
        "nodes_count": nodes_result.get("count", 0),
        "models_status": models_result,
        # Agent config (autonomous mode)
        "autonomous_mode": agent_config.get("autonomous_mode"),
        "max_concurrent": agent_config.get("max_concurrent"),
        # Exec approvals (permissions)
        "permissions": exec_approvals.get("permissions", []),
        "permissions_count": exec_approvals.get("permissions_count", 0),
        # Web activity (browser, fetch, search)
        "web_activity": logs_result.get("web_activity", {}),
    }

    # Build output based on --full flag
    if full:
        result: Dict[str, Any] = {
            "scan_timestamp": datetime.now().isoformat(),
            "bot_cli_cmd": bot_cli_str,
            "bot_variant": bot_variant,
            "bot_version": bot_version,
            "system_info": system_info,
            "bot_config_dir": str(bot_config_dir),
            "summary": summary,
            "active_skills": skills_result,
            "session_analysis": logs_result,
            "cron_jobs": cron_result,
            # CISO-relevant detailed data
            "security_audit": security_result,
            "active_plugins": plugins_result,
            "channels": channels_result,
            "nodes": nodes_result,
            "models_status": models_result,
            "agent_config": agent_config,
            "exec_approvals": exec_approvals,
        }
    else:
        result = {
            "scan_timestamp": datetime.now().isoformat(),
            "bot_cli_cmd": bot_cli_str,
            "bot_variant": bot_variant,
            "bot_version": bot_version,
            "bot_config_dir": str(bot_config_dir),
            "system_info": system_info,
            "summary": summary
        }

    return result


def main():
    """CLI entry point for openclaw-scanner."""
    parser = argparse.ArgumentParser(
        description="Scan OpenClaw usage: active skills, tools, and apps. Outputs JSON."
    )
    parser.add_argument(
        "--scanner-report-api-key",
        type=str,
        default=os.environ.get("SCANNER_REPORT_API_KEY"),
        help="API key for sending report to the server (or set SCANNER_REPORT_API_KEY env var)"
    )
    parser.add_argument(
        "--cli",
        type=str,
        default=None,
        help="Bot CLI command/path. If not provided, auto-detects (openclaw, clawdbot)"
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact JSON output (no indentation)"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Include full response with all details (default: only user and summary)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Limit number of recent tool calls to include in full output (default: 50)"
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (use only if behind a corporate proxy)"
    )

    args = parser.parse_args()

    # Detect install: either via bot CLI command specified on cmdline, or using auto-detect
    if args.cli:
        install_info = build_install_info_from_cli(args.cli.split())
    else:
        install_info = detect_clawd_install()

    if install_info is None:
        # Detect failed - figure out why for better error message
        home = Path.home()
        checked_variants = CLAWDBOT_VARIANT_NAMES
        checked_config_paths = [str(home / f".{v}") for v in checked_variants]

        # Check if CLI exists but config dir doesn't (installed but never used)
        cli_only = find_bot_cli_only()
        if cli_only:
            variant_name, cli_cmd = cli_only
            version = get_bot_version(cli_cmd)
            result = {
                "error": "Bot installed but never used (no config found)",
                "bot_variant": variant_name,
                "bot_version": version,
                "bot_cli_cmd": " ".join(cli_cmd),
                "bot_config_dir": str(home / f".{variant_name}"),
            }
        else:
            result = {
                "error": "No bot installed",
                "checked_variants": checked_variants,
                "checked_config_paths": checked_config_paths,
            }
        print(json.dumps(result, indent=None if args.compact else 2))
        sys.exit(1)

    # Scan using strategy-appropriate function
    if install_info.scanning_strategy == "nano":
        result = scan_nano(install_info, full=args.full, limit=args.limit)
    else:
        result = scan_openclaw(install_info, full=args.full, limit=args.limit)

    if result is None:
        result = {
            "error": f"{install_info.bot_variant} detected but scan failed",
            "bot_variant": install_info.bot_variant,
            "bot_config_dir": str(install_info.bot_config_dir),
        }
        print(json.dumps(result, indent=None if args.compact else 2))
        sys.exit(1)

    # Send report to API if scanner-report-api-key is provided
    if args.scanner_report_api_key:
        api_result = send_report(result, args.scanner_report_api_key, verify_ssl=not args.no_ssl_verify)
        result["api_report"] = api_result

    # Output JSON
    if args.compact:
        print(json.dumps(result))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
