"""Common utilities shared across platform implementations."""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from structures import CliCommand, ProcessInfo, SystemInfo, ToolPaths


def dedupe_apps(apps: List[str]) -> List[str]:
    """Remove duplicates while preserving order (case-insensitive)."""
    seen: set[str] = set()
    unique_apps: List[str] = []
    for app in apps:
        app_lower = app.lower()
        if app_lower not in seen:
            seen.add(app_lower)
            unique_apps.append(app)
    return unique_apps


def get_system_info() -> SystemInfo:
    """Get system and user information for the host being scanned.

    Returns:
        SystemInfo dict with system, user, and environment information
    """
    return {
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "home_dir": str(Path.home()),
        "current_dir": os.getcwd(),
        "hostname": platform.node(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "shell": os.getenv("SHELL", "unknown"),
        "lang": os.getenv("LANG", "unknown"),
    }


def run_cmd(cmd: List[str], timeout: int = 5) -> Optional[str]:
    """Run command, return stripped stdout or None on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_user_id() -> Optional[str]:
    """Get current user ID (works on macOS and Linux)."""
    return run_cmd(["id", "-u"])


def get_group_id() -> Optional[str]:
    """Get current group ID (works on macOS and Linux)."""
    return run_cmd(["id", "-g"])


def get_groups() -> List[str]:
    """Get user's groups (works on macOS and Linux)."""
    output = run_cmd(["groups"])
    return output.split() if output else []


def get_uname() -> Optional[str]:
    """Get system info via uname -a (works on macOS and Linux)."""
    return run_cmd(["uname", "-a"])


def find_processes(process_names: List[str]) -> List[ProcessInfo]:
    """Find processes matching any of the given names.
    
    Works identically on macOS and Linux (ps aux format).
    """
    processes: List[ProcessInfo] = []
    exclude_patterns = ["installation_tracker", "grep", "ps aux"]

    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                line_lower = line.lower()

                if any(excl in line_lower for excl in exclude_patterns):
                    continue

                for proc_name in process_names:
                    if proc_name.lower() in line_lower:
                        parts = line.split()
                        if len(parts) >= 11:
                            processes.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu": parts[2],
                                "mem": parts[3],
                                "command": " ".join(parts[10:]),
                                "process_name": proc_name,
                            })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return processes


def get_base_tool_paths(tool_name: str) -> ToolPaths:
    """Get tool paths common to all platforms."""
    home = os.path.expanduser("~")
    return {
        "config": [
            os.path.join(home, f".{tool_name}", f"{tool_name}.json"),
            os.path.join(home, f".{tool_name}", "config.json"),
            os.path.join(home, ".config", tool_name, "config.json"),
        ],
        "logs": [
            os.path.join(home, f".{tool_name}", "logs", "*.log"),
            os.path.join(home, f".{tool_name}", "*.log"),
            f"/tmp/{tool_name}/*.log",
            f"/tmp/{tool_name}*.log",
            f"/tmp/{tool_name}-gateway.log",
        ]
    }


def find_openclaw_binary_common(cli_name: str = "openclaw", 
                                extra_paths: Optional[List[Path]] = None) -> Optional[CliCommand]:
    """Find the OpenClaw CLI binary - common implementation.
    
    Platform-specific implementations call this with their own extra_paths.
    
    Returns:
        Command as list (e.g. ["/usr/bin/openclaw"] or ["npx", "openclaw"]), or None
    """
    home = Path.home()
    
    # 1. Check PATH first (works if user configured correctly)
    path_result = shutil.which(cli_name)
    if path_result:
        return [path_result]
    
    # 2. npm global bin (most common install method)
    npm_prefix = run_cmd(["npm", "prefix", "-g"])
    if npm_prefix:
        npm_path = Path(npm_prefix) / "bin" / cli_name
        if npm_path.exists():
            return [str(npm_path)]
    
    # 3. pnpm global root (alternative package manager)
    pnpm_root = run_cmd(["pnpm", "root", "-g"])
    if pnpm_root:
        # pnpm root -g returns .../node_modules, bin is at ../bin
        pnpm_path = Path(pnpm_root).parent / "bin" / cli_name
        if pnpm_path.exists():
            return [str(pnpm_path)]
    
    # 4. Git source install (common dev setup)
    #    Default git dir per installer docs: ~/openclaw
    git_paths = [
        home / "openclaw" / "openclaw.mjs",
        home / cli_name / f"{cli_name}.mjs",
    ]
    for p in git_paths:
        if p.exists():
            return [str(p)]
    
    # 5. Platform-specific paths (passed by caller)
    if extra_paths:
        for p in extra_paths:
            if p.exists():
                return [str(p)]
    
    # 6. Common fallback locations
    fallbacks = [
        home / ".npm-global" / "bin" / cli_name,
        Path("/usr/local/bin") / cli_name,
    ]
    for p in fallbacks:
        if p.exists():
            return [str(p)]
    
    # 7. npx fallback - verify package actually exists
    if shutil.which("npx"):
        result = run_cmd(["npx", cli_name, "--version"])
        if result:
            return ["npx", cli_name]
    
    return None
