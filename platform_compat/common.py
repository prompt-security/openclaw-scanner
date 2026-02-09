"""Common utilities shared across platform implementations."""

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from structures import CliCommand, ClawdbotInstallInfo, ProcessInfo, SystemInfo, ToolPaths, CLAWDBOT_VARIANT_NAMES


# Folders that aren't apps - skip these
SKIP_CONFIG_FOLDERS = {
    'git', 'ssh', 'env', 'tmp', 'cache', 'config', 'local', 'log', 'bin',
    'npm', 'yarn', 'nvm', 'pyenv', 'rbenv', 'goenv', 'jenv', 'sdkman',
    'bundle', 'gem', 'pip', 'poetry', 'venv', 'virtualenv', 'conda',
    'kube',
    'bash', 'zsh', 'fish', 'profile', 'bashrc', 'zshrc',
    'gnupg', 'password-store', 'netrc', 'curlrc', 'wgetrc',
}


def extract_command_binaries(command: str) -> List[str]:
    """Extract the binary name from each command in a pipeline/chain.

    Splits on shell operators (&&, ||, |, ;) and takes the first token
    of each sub-command, stripping any path prefix.

    Args:
        command: The command string to parse

    Returns:
        List of binary names found (e.g., ['aws', 'grep', 'curl'])
    """
    binaries: List[str] = []
    parts = re.split(r'[;&|]+', command)
    for part in parts:
        tokens = part.strip().split()
        if not tokens:
            continue
        binary = tokens[0].rsplit('/', maxsplit=1)[-1]
        binaries.append(binary)
    return binaries


def _is_valid_app_name(name: str) -> bool:
    """Check if a detected name looks like a real app, not a shell command or artifact."""
    name = name.strip()
    # Too short (e.g., "1", "\"") or too long
    if len(name) < 2 or len(name) > 50:
        return False
    # Must start with a letter or digit
    if not name[0].isalnum():
        return False
    # Names starting with a digit must also contain letters (allows "1Password", rejects "1")
    if name[0].isdigit() and not any(c.isalpha() for c in name):
        return False
    # Reject names with quotes, parens, equals, or other artifacts
    if re.search(r'["\'\(\)=;|&><`{}\[\]#~^]', name):
        return False
    # Must be alphanumeric (allow spaces, hyphens, dots for real names)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9 ._-]*$', name):
        return False
    return True



def dedupe_apps(apps: List[str]) -> List[str]:
    """Remove duplicates and filter out artifacts (keeps both apps and shell commands)."""
    seen: set[str] = set()
    unique_apps: List[str] = []
    for app in apps:
        app_clean = app.strip()
        app_lower = app_clean.lower()
        if app_lower not in seen and _is_valid_app_name(app_clean):
            seen.add(app_lower)
            unique_apps.append(app_clean)
    return unique_apps


def extract_apps_from_config_folders(command: str) -> List[str]:
    """Extract app names from config folder references in a command.

    Detects patterns like .obsidian, .vscode, .cursor etc. and converts
    them to app names (capitalized).

    Args:
        command: The command string to parse

    Returns:
        List of app names found (e.g., ['Obsidian', 'Vscode'])
    """
    apps: List[str] = []

    # Pattern: find .foldername in command (e.g., /.obsidian or .obsidian/)
    # Matches: /.appname, .appname/, ".appname", '.appname'
    config_folder_pattern = r'[/\s"\']\.([a-zA-Z][a-zA-Z0-9_-]{2,20})(?:[/\s"\']|$)'

    for match in re.findall(config_folder_pattern, command):
        if match.lower() not in SKIP_CONFIG_FOLDERS:
            apps.append(match.capitalize())

    return apps


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


def _find_clawdbot_cli_binary(cli_name: str,
 extra_paths: Optional[List[Path]] = None) -> Optional[CliCommand]:
    """Find a CLI binary by name - internal helper.

    Args:
        cli_name: Binary name to search for (e.g., "openclaw", "clawdbot")
        extra_paths: Platform-specific paths to check

    Returns:
        Command as list (e.g. ["/usr/bin/openclaw"]), or None
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
    # Add nvm paths - check all installed node versions
    # Sort by version (newest first) for deterministic, predictable behavior
    nvm_dir = home / ".nvm" / "versions" / "node"
    if nvm_dir.exists():
        node_versions = sorted(nvm_dir.iterdir(), key=lambda p: p.name, reverse=True)
        for node_version in node_versions:
            if node_version.is_dir():
                fallbacks.append(node_version / "bin" / cli_name)

    for p in fallbacks:
        if p.exists():
            return [str(p)]

    return None


def find_bot_cli_only(extra_paths_fn=None) -> Optional[tuple[str, CliCommand]]:
    """Find bot CLI binary only (ignores config dir).

    Used for error reporting to distinguish 'not installed' vs 'installed but never used'.

    Returns:
        Tuple of (variant_name, cli_command) or None if no CLI found
    """
    for name in CLAWDBOT_VARIANT_NAMES:
        extra_paths = extra_paths_fn(name) if extra_paths_fn else None
        bot_cli_cmd = _find_clawdbot_cli_binary(name, extra_paths)
        if bot_cli_cmd:
            return (name, bot_cli_cmd)
    return None


def detect_clawd_install(extra_paths_fn=None) -> Optional[ClawdbotInstallInfo]:
    """Auto-detect installed OpenClaw/Clawdbot.

    Strategy: CLI-first with newest-to-oldest priority.
    Tries: openclaw → clawdbot

    Args:
        extra_paths_fn: Optional callable(cli_name) -> List[Path] for platform-specific paths

    Returns:
        ClawdbotInstallInfo or None if not found
    """
    home = Path.home()
    for name in CLAWDBOT_VARIANT_NAMES:
        extra_paths = extra_paths_fn(name) if extra_paths_fn else None
        bot_cli_cmd = _find_clawdbot_cli_binary(name, extra_paths)
        bot_config_dir = home / f".{name}"

        # Both CLI and config dir must exist for valid detection
        if bot_cli_cmd and bot_config_dir.exists():
            return ClawdbotInstallInfo(bot_variant=name, bot_cli_cmd=bot_cli_cmd, bot_config_dir=bot_config_dir)

    return None


def build_install_info_from_cli(bot_cli_cmd: CliCommand) -> Optional[ClawdbotInstallInfo]:
    """Build ClawdbotInstallInfo from explicit bot CLI command (e.g., from --cli arg).

    Infers product name from the command. If unrecognized, defaults to "openclaw".
    Returns None if bot config dir doesn't exist.
    """
    cmd_str = " ".join(bot_cli_cmd).lower()

    name = "openclaw"  # default
    for n in CLAWDBOT_VARIANT_NAMES:
        if n in cmd_str:
            name = n
            break

    bot_config_dir = Path.home() / f".{name}"
    if not bot_config_dir.exists():
        return None

    return ClawdbotInstallInfo(bot_variant=name, bot_cli_cmd=bot_cli_cmd, bot_config_dir=bot_config_dir)


# Legacy alias for backward compatibility with platform_compat/{linux,darwin}.py
def find_openclaw_binary_common(cli_name: str = "openclaw",
                                extra_paths: Optional[List[Path]] = None) -> Optional[CliCommand]:
    """Legacy wrapper - use detect_install() instead."""
    return _find_clawdbot_cli_binary(cli_name, extra_paths)
