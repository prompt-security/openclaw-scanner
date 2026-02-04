#!/usr/bin/env python3
"""
OpenClaw Usage Scanner
Scans .openclaw folder, active skills, and session logs for tools/apps usage.
Outputs JSON with all collected data.
"""

import json
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, TypedDict

from platform_compat.common import get_system_info
from platform_compat import compat as _compat
from structures import CliCommand

API_ENDPOINT = "https://oneclaw.prompt.security/api/reports"


class CliExecError(Exception):
    """Raised when CLI command execution fails."""
    pass


def _run_cli(cli_command: Optional[CliCommand], *args: str, timeout: int = 30) -> str:
    """Run OpenClaw CLI command and return stdout on success.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.
        *args: Command arguments (e.g., "nodes", "list")
        timeout: Command timeout in seconds

    Returns:
        stdout as string on success

    Raises:
        CliExecError: On any failure (not found, timeout, non-zero exit, etc.)
    """
    # Auto-detect CLI if not provided
    if cli_command is None:
        cli_command = _compat.find_openclaw_binary("openclaw")
        if cli_command is None:
            raise CliExecError("CLI not found")

    try:
        result = subprocess.run(cli_command + list(args), capture_output=True, text=True, timeout=timeout)

        if result.returncode != 0:
            raise CliExecError(f"Command failed: {result.stderr.strip()}")

        return result.stdout

    except subprocess.TimeoutExpired as e:
        raise CliExecError("Command timed out") from e
    except FileNotFoundError as e:
        raise CliExecError(f"CLI not found: {' '.join(cli_command)}") from e
    except Exception as e:
        if isinstance(e, CliExecError):
            raise
        raise CliExecError(str(e)) from e


class SkillsResult(TypedDict, total=False):
    """Return type for get_active_skills()."""
    active_skills: List[Dict[str, Any]]  # Skill structure from CLI
    count: int
    total: int           # Only on success
    error: str           # Only on error
    cli_searched: bool   # Only when auto-detection was attempted


def find_openclaw_folder() -> Optional[Path]:
    """Find the .openclaw folder in the user's home directory.

    Returns:
        Path to .openclaw folder or None if not found
    """
    openclaw_path = Path.home() / ".openclaw"

    if openclaw_path.exists() and openclaw_path.is_dir():
        return openclaw_path

    return None


def get_active_skills(cli_command: Optional[CliCommand] = None) -> SkillsResult:
    """Run openclaw skills list and filter only active skills.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.

    Returns:
        SkillsResult with active_skills list and counts (or error on failure)
    """
    try:
        stdout = _run_cli(cli_command, "skills", "list", "--json")
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


def get_cron_jobs(cli_command: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw cron list to get scheduled cron jobs.

    Args:
        cli_command: CLI base command as list. If None, auto-detects.

    Returns:
        Dict with cron jobs list and count
    """
    try:
        stdout = _run_cli(cli_command, "cron", "list")
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


def get_security_audit(cli_command: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw security audit to check for security issues.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with security audit results
    """
    try:
        stdout = _run_cli(cli_command, "security", "audit", timeout=60)
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


def get_plugins_list(cli_command: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw plugins list to get active plugins only.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with active plugins list and count
    """
    try:
        stdout = _run_cli(cli_command, "plugins", "list", "--json")
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


def get_channels_list(cli_command: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw channels list to get configured channels/integrations.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.
    Returns:
        Dict with channels list and count
    """
    try:
        stdout = _run_cli(cli_command, "channels", "list")
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


def get_nodes_list(cli_command: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw nodes list to get connected/paired nodes.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.

    Returns:
        Dict with nodes list and count
    """
    try:
        stdout = _run_cli(cli_command, "nodes", "list")
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


def get_models_status(cli_command: Optional[CliCommand] = None) -> Dict[str, Any]:
    """Run openclaw models status to get authentication and model status.

    Args:
        cli_command: CLI base command as list of string parts. If None, auto-detects.
    Returns:
        Dict with models status including auth info
    """
    try:
        stdout = _run_cli(cli_command, "models", "status")
    except CliExecError as e:
        return {"error": str(e)}

    try:
        return {"models_status": json.loads(stdout), "has_auth": True}
    except json.JSONDecodeError:
        return {"raw_output": stdout.strip(), "passed": True}


def scan_session_logs(openclaw_path: Path) -> Dict[str, Any]:
    """Scan session logs and extract tools and apps used.

    Args:
        openclaw_path: Path to the .openclaw folder

    Returns:
        Dict with tool calls, usage summary, and apps used
    """
    sessions_dir = openclaw_path / "agents" / "main" / "sessions"

    if not sessions_dir.exists():
        return {
            "error": f"Sessions directory not found: {sessions_dir}",
            "tool_calls": [],
            "tools_summary": {},
            "apps_summary": {}
        }

    tool_calls = []

    # Find all session .jsonl files
    session_files = [f for f in sessions_dir.glob("*.jsonl") if f.name != "sessions.json"]

    for session_file in session_files:
        try:
            with open(session_file, "r") as f:
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
                                    "session": session_file.name,
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

    # Build apps usage summary
    apps_summary: Dict[str, int] = {}
    for tc in tool_calls:
        for app in tc.get("apps_detected", []):
            apps_summary[app] = apps_summary.get(app, 0) + 1

    apps_summary = dict(sorted(apps_summary.items(), key=lambda x: x[1], reverse=True))

    return {
        "tool_calls": tool_calls,
        "tools_summary": tools_summary,
        "apps_summary": apps_summary,
        "total_tool_calls": len(tool_calls),
        "unique_tools": len(tools_summary),
        "unique_apps": len(apps_summary),
        "sessions_scanned": len([f for f in session_files if f.name != "sessions.json"])
    }


def send_report(report_data: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Send scan report to the API endpoint.

    Args:
        report_data: The scan report to send
        api_key: API key for authorization

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

    try:
        req = urllib.request.Request(
            API_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as response:
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
            "status_code": response.status,
            "response": response_body
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan OpenClaw usage: active skills, tools, and apps. Outputs JSON."
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key for sending report to the server"
    )
    parser.add_argument(
        "--cli",
        type=str,
        default=None,
        help="CLI command/path to use. If not provided, auto-detects (openclaw, moltbot, clawdbot)"
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

    args = parser.parse_args()

    openclaw_path = find_openclaw_folder()
    if openclaw_path is None:
        result = {
            "error": ".openclaw folder not found",
            "expected_path": str(Path.home() / ".openclaw"),
            "openclaw_path": None,
            "active_skills": None,
            "session_analysis": None
        }
        print(json.dumps(result, indent=None if args.compact else 2))
        sys.exit(1)

    # Collect scan data
    cli = args.cli.split() if args.cli else _compat.find_openclaw_binary("openclaw")
    cli_str = " ".join(cli) if cli else None
    skills_result = get_active_skills(cli)
    logs_result = scan_session_logs(openclaw_path)
    system_info = get_system_info()
    cron_result = get_cron_jobs(cli)
    security_result = get_security_audit(cli)  # CISO-critical
    plugins_result = get_plugins_list(cli)  # attack surface
    channels_result = get_channels_list(cli)  # external integrations
    nodes_result = get_nodes_list(cli)  # remote connections
    models_result = get_models_status(cli)  # auth posture

    # Limit tool calls in output
    logs_result["tool_calls"] = logs_result["tool_calls"][:args.limit]

    # Build summary
    active_skills_list = skills_result.get("active_skills", [])
    app_names = list(logs_result.get("apps_summary", {}).keys())
    tool_names = list(logs_result.get("tools_summary", {}).keys())

    summary = {
        "active_skills": active_skills_list,
        "active_skills_count": len(active_skills_list),
        "apps_detected": app_names,
        "apps_detected_count": len(app_names),
        "tools_used": tool_names,
        "tools_used_count": len(tool_names),
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
        "models_status": models_result
    }

    # Build output based on --full flag
    if args.full:
        result = {
            "scan_timestamp": datetime.now().isoformat(),
            "cli_command": cli_str,
            "system_info": system_info,
            "openclaw_path": str(openclaw_path),
            "summary": summary,
            "active_skills": skills_result,
            "session_analysis": logs_result,
            "cron_jobs": cron_result,
            # CISO-relevant detailed data
            "security_audit": security_result,
            "active_plugins": plugins_result,
            "channels": channels_result,
            "nodes": nodes_result,
            "models_status": models_result
        }
    else:
        result = {
            "scan_timestamp": datetime.now().isoformat(),
            "cli_command": cli_str,
            "system_info": system_info,
            "summary": summary
        }

    # Send report to API if api-key is provided
    if args.api_key:
        api_result = send_report(result, args.api_key)
        result["api_report"] = api_result

    # Output JSON
    if args.compact:
        print(json.dumps(result))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
