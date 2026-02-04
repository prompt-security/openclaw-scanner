#!/usr/bin/env python3
"""
List Active Skills
Fetches active skills from OpenClaw using the CLI and outputs them in JSON format.
Includes local machine user details and recent tool calls.
"""

import getpass
import glob
import json
import os
import platform
import re
import socket
import subprocess
import sys
from collections import Counter
from typing import Any, Dict, List, Optional


# Known macOS apps to detect in commands
KNOWN_APPS = [
    "Notes", "Calendar", "Safari", "Chrome", "Firefox", "Brave", "Edge",
    "Mail", "Messages", "Reminders", "Finder", "Terminal", "iTerm",
    "Slack", "Discord", "Zoom", "Teams", "Spotify", "Music",
    "Photos", "Preview", "TextEdit", "Pages", "Numbers", "Keynote",
    "Xcode", "VSCode", "Sublime", "Atom", "IntelliJ", "PyCharm",
    "Word", "Excel", "PowerPoint", "Outlook",
    "System Preferences", "System Settings", "Activity Monitor"
]


def get_user_details() -> Dict[str, Any]:
    """Get local machine user details in simplified format."""
    return {
        "username": getpass.getuser(),
        "home_dir": os.path.expanduser("~"),
        "current_dir": os.getcwd(),
        "hostname": socket.gethostname(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "shell": os.environ.get("SHELL", ""),
        "lang": os.environ.get("LANG", ""),
    }


def extract_apps_from_command(command: str) -> List[str]:
    """Extract app names from a command string.

    Args:
        command: The command string to analyze

    Returns:
        List of detected app names
    """
    apps = []

    # Check for 'open -a AppName' pattern
    open_app_match = re.findall(r'open\s+-a\s+["\']?([^"\'>\s]+)["\']?', command, re.IGNORECASE)
    apps.extend(open_app_match)

    # Check for 'tell application "AppName"' pattern (AppleScript)
    tell_app_match = re.findall(r'tell\s+application\s+["\']([^"\']+)["\']', command, re.IGNORECASE)
    apps.extend(tell_app_match)

    # Check for known app names in the command
    command_lower = command.lower()
    for app in KNOWN_APPS:
        if app.lower() in command_lower and app not in apps:
            # Verify it's likely an app reference, not just a word
            if re.search(rf'\b{re.escape(app)}\b', command, re.IGNORECASE):
                apps.append(app)

    # Normalize app names
    normalized = []
    for app in apps:
        # Capitalize first letter of each word
        normalized_name = app.strip().title()
        if normalized_name and normalized_name not in normalized:
            normalized.append(normalized_name)

    return normalized


def find_session_files() -> List[str]:
    """Find OpenClaw session files."""
    possible_paths = [
        os.path.expanduser("~/.openclaw/sessions/*.jsonl"),
        os.path.expanduser("~/.moltbot/sessions/*.jsonl"),
        os.path.expanduser("~/.clawdbot/sessions/*.jsonl"),
        os.path.expanduser("~/.config/openclaw/sessions/*.jsonl"),
        os.path.expanduser("~/.local/share/openclaw/sessions/*.jsonl"),
    ]

    session_files = []
    for pattern in possible_paths:
        session_files.extend(glob.glob(pattern))

    # Sort by modification time (newest first)
    session_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return session_files


def parse_session_file(filepath: str) -> List[Dict[str, Any]]:
    """Parse a session JSONL file and extract tool calls.

    Args:
        filepath: Path to the session file

    Returns:
        List of tool call entries
    """
    tool_calls = []
    session_filename = os.path.basename(filepath)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)

                    # Look for tool calls in various formats
                    if entry.get("type") == "tool_call" or "tool" in entry:
                        tool_name = entry.get("name") or entry.get("tool", {}).get("name", "")
                        tool_id = entry.get("id") or entry.get("tool_call_id", "")
                        timestamp = entry.get("timestamp") or entry.get("created_at", "")
                        arguments = entry.get("arguments") or entry.get("input") or entry.get("tool", {}).get("input", {})

                        if isinstance(arguments, str):
                            try:
                                arguments = json.loads(arguments)
                            except json.JSONDecodeError:
                                arguments = {"raw": arguments}

                        # Extract apps from exec commands
                        apps = []
                        if tool_name in ["exec", "bash", "shell", "command"]:
                            cmd = arguments.get("command", "") or arguments.get("cmd", "")
                            apps = extract_apps_from_command(cmd)

                        tool_calls.append({
                            "name": tool_name,
                            "id": tool_id,
                            "timestamp": timestamp,
                            "session_file": session_filename,
                            "arguments": arguments,
                            "apps": apps,
                        })

                except json.JSONDecodeError:
                    continue

    except (IOError, OSError):
        pass

    return tool_calls


def get_recent_tool_calls(limit: int = 15) -> Dict[str, Any]:
    """Get recent tool calls from session files.

    Args:
        limit: Maximum number of tool calls to return

    Returns:
        Dict containing recent tool calls
    """
    session_files = find_session_files()

    if not session_files:
        return {"recent_calls": [], "error": "No session files found"}

    all_calls = []
    for session_file in session_files[:10]:  # Check last 10 session files
        calls = parse_session_file(session_file)
        all_calls.extend(calls)

    # Sort by timestamp (newest first)
    all_calls.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "recent_calls": all_calls[:limit]
    }


def get_app_statistics(tool_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate app usage statistics from tool calls.

    Args:
        tool_calls: List of tool call entries

    Returns:
        Dict containing app usage statistics
    """
    app_counter: Counter[str] = Counter()

    for call in tool_calls:
        for app in call.get("apps", []):
            app_counter[app] += 1

    return {
        "apps_used": dict(app_counter.most_common()),
        "total_app_interactions": sum(app_counter.values()),
        "unique_apps": len(app_counter),
    }


def run_skills_list(cli_command: str = "openclaw", timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Run openclaw skills list command and return JSON output."""
    cmd = [cli_command, "skills", "list", "--json"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return None
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "command": " ".join(cmd)}
    except json.JSONDecodeError:
        return {"error": "invalid_json", "raw_output": result.stdout[:500]}
    except FileNotFoundError:
        return {"error": "cli_not_found", "command": cli_command}
    except Exception as e:
        return {"error": str(e)}


def find_available_cli() -> Optional[str]:
    """Find an available OpenClaw CLI command."""
    cli_names = ["openclaw", "moltbot", "clawdbot"]

    for cli in cli_names:
        try:
            result = subprocess.run(
                [cli, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return cli
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


def filter_active_skills(skills_data: Any) -> List[Dict[str, Any]]:
    """Filter and return only active (ready) skills."""
    if not skills_data:
        return []

    if isinstance(skills_data, list):
        return [
            skill for skill in skills_data
            if isinstance(skill, dict) and skill.get("ready", False)
        ]
    elif isinstance(skills_data, dict):
        if "error" in skills_data:
            return []
        active = []
        for key, value in skills_data.items():
            if isinstance(value, dict):
                skill_entry = {"name": key, **value}
                if value.get("ready", True):  # Include if ready or no ready field
                    active.append(skill_entry)
        return active

    return []


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="List active OpenClaw skills and user details in JSON format"
    )
    parser.add_argument(
        "--cli",
        type=str,
        help="CLI command to use (openclaw, moltbot, clawdbot)"
    )
    parser.add_argument(
        "--apps",
        action="store_true",
        help="Show only app usage statistics"
    )
    parser.add_argument(
        "--skills",
        action="store_true",
        help="Include active skills from CLI"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=15,
        help="Number of recent tool calls to include (default: 15)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Save output to file"
    )

    args = parser.parse_args()

    # Get recent tool calls for app stats
    recent_calls_data = get_recent_tool_calls(args.limit)
    recent_calls = recent_calls_data.get("recent_calls", [])

    # If --apps flag, only show app statistics
    if args.apps:
        result = get_app_statistics(recent_calls)
    else:
        # Build full result
        result = {
            "user": get_user_details(),
            "recent_tool_calls": recent_calls_data,
        }

        # Include skills if requested
        if args.skills:
            cli_command = args.cli or find_available_cli()
            if cli_command:
                skills_data = run_skills_list(cli_command)
                active_skills = filter_active_skills(skills_data) if skills_data else []
                result["active_skills"] = {
                    "cli_command": cli_command,
                    "count": len(active_skills),
                    "skills": active_skills,
                }
            else:
                result["active_skills"] = {
                    "error": "OpenClaw CLI not found"
                }

    # Output JSON with indentation
    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Output saved to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
