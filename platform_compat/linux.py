"""Linux implementation."""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional

from structures import CliCommand

from .base import PlatformCompat, ProcessInfo, ToolPaths, UserInfo
from .common import (
    run_cmd, get_user_id, get_group_id,
    get_groups, get_uname, find_processes as _find_processes,
    get_base_tool_paths, find_openclaw_binary_common,
    extract_apps_from_config_folders, dedupe_apps,
)


class LinuxCompat(PlatformCompat):
    """Linux-specific implementation."""

    def get_user_info(self, username: Optional[str] = None) -> UserInfo:
        if username is None:
            username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

        # Linux: getent passwd for full name (GECOS field)
        full_name: Optional[str] = None
        output = run_cmd(["getent", "passwd", username])
        if output:
            parts = output.split(":")
            if len(parts) >= 5 and parts[4]:
                full_name = parts[4].split(",")[0]

        return {
            "username": username,
            "home_directory": os.path.expanduser("~"),
            "user_id": get_user_id(),
            "group_id": get_group_id(),
            "full_name": full_name,
            "shell": os.environ.get("SHELL", "unknown"),
            "groups": get_groups(),
            "system_info": get_uname(),
            "computer_name": run_cmd(["hostname"]),
            "local_hostname": None,
        }

    def find_processes(self, process_names: List[str]) -> List[ProcessInfo]:
        return _find_processes(process_names)

    def get_tool_paths(self, tool_name: str) -> ToolPaths:
        paths = get_base_tool_paths(tool_name)
        # Linux-specific: add /var/log
        paths["logs"].append(f"/var/log/{tool_name}/*.log")
        return paths

    def read_system_log(self, subsystem: str, time_range: str,
                        max_lines: int = 500) -> List[str]:
        """Read Linux systemd journal. subsystem = systemd unit name."""
        # Convert time_range (e.g., "24h", "1h", "30m") to journalctl --since format
        since = self._convert_time_range(time_range)
        try:
            cmd = [
                "journalctl", "-u", subsystem,
                "-n", str(max_lines),
                "--no-pager", "-q"
            ]
            if since:
                cmd.extend(["--since", since])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return [line for line in result.stdout.strip().split('\n') if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return []

    @staticmethod
    def _convert_time_range(time_range: str) -> Optional[str]:
        """Convert '24h', '1h', '30m', '1d' to journalctl --since format."""
        match = re.match(r'^(\d+)([hmd])$', time_range.lower())
        if not match:
            return None
        value, unit = match.groups()
        unit_map = {'h': 'hours', 'm': 'minutes', 'd': 'days'}
        return f"{value} {unit_map.get(unit, 'hours')} ago"

    def extract_app_names(self, command: str) -> List[str]:
        """Extract app names from a command string (Linux-specific patterns).

        Args:
            command: The command string to parse

        Returns:
            List of app names found in the command
        """
        apps: List[str] = []

        # Pattern: xdg-open (generic Linux file/URL opener)
        # xdg-open doesn't specify app, so we skip it

        # Pattern: gtk-launch appname
        gtk_launch_pattern = r'gtk-launch\s+([^\s;|&]+)'
        apps.extend(re.findall(gtk_launch_pattern, command, re.IGNORECASE))

        # Pattern: snap run appname
        snap_pattern = r'snap\s+run\s+([^\s;|&]+)'
        apps.extend(re.findall(snap_pattern, command, re.IGNORECASE))

        # Pattern: flatpak run com.app.Name
        flatpak_pattern = r'flatpak\s+run\s+([^\s;|&]+)'
        apps.extend(re.findall(flatpak_pattern, command, re.IGNORECASE))

        # Generic: config folder references (.obsidian, .vscode, etc.)
        apps.extend(extract_apps_from_config_folders(command))

        return dedupe_apps(apps)

    def find_openclaw_binary(self, cli_name: str = "openclaw") -> Optional[CliCommand]:
        """Find OpenClaw CLI binary (Linux-specific paths).

        Adds Linux-specific locations:
            - /snap/bin/openclaw (Snap packages, if ever available)
            - ~/.local/bin/openclaw (pip/pipx style user installs)
            - Nix profile paths
        """
        home = Path.home()

        # Linux-specific paths to check
        linux_paths = [
            # User local bin (pip/pipx style)
            home / ".local" / "bin" / cli_name,
            # Snap (if ever available)
            Path("/snap/bin") / cli_name,
            # Nix profile
            home / ".nix-profile" / "bin" / cli_name,
            # NixOS system profile
            Path("/run/current-system/sw/bin") / cli_name,
        ]

        return find_openclaw_binary_common(cli_name, extra_paths=linux_paths)
