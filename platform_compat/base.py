"""
Platform compatibility interface.

Returns Dict to match main code expectations (serialized to JSON).
For cross-platform stdlib, use directly:
  - shutil.which(binary)
  - socket operations for port checks
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from structures import ProcessInfo, ToolPaths, UserInfo, CliCommand

__all__ = ["PlatformCompat", "ProcessInfo", "ToolPaths", "UserInfo", "CliCommand"]


class PlatformCompat(ABC):
    """
    Abstract interface for platform-specific operations.
    
    Implementations: DarwinCompat, LinuxCompat, WindowsCompat
    """

    @abstractmethod
    def get_user_info(self, username: Optional[str] = None) -> UserInfo:
        """Get current user information.
        
        Args:
            username: Override username (uses env USER/USERNAME if None)
        """
        ...

    @abstractmethod
    def find_processes(self, process_names: List[str]) -> List[ProcessInfo]:
        """
        Find running processes matching any of the given names.
        
        Args:
            process_names: Substrings to match against command line.
                           e.g. ["openclaw gateway", "moltbot-gateway"]
        
        Note: "process_name" in result = which filter matched this process.
        """
        ...

    @abstractmethod
    def get_tool_paths(self, tool_name: str) -> ToolPaths:
        """
        Get platform-appropriate config and log paths for a tool.
        
        Args:
            tool_name: e.g. "openclaw", "moltbot"
            
        Platform differences:
            - macOS/Linux: ~/.tool/, /tmp/, /var/log/
            - Windows: %APPDATA%/tool/, %TEMP%/
        """
        ...

    def read_system_log(self, subsystem: str, time_range: str,
                        max_lines: int = 500) -> List[str]:
        """
        Read system log entries for a subsystem.
        
        Args:
            subsystem: macOS: unified log subsystem
                       Linux: systemd unit name
                       Windows: not implemented
            max_lines: max entries to return (from end)
            time_range: e.g. "24h", "1h" (macOS only)
        
        Returns:
            Log lines, newest last. Empty if unsupported/error.
        """
        return []

    @abstractmethod
    def extract_app_names(self, command: str) -> List[str]:
        """
        Extract application names from a command string.
        
        Platform-specific patterns:
            - macOS: osascript, open -a, killall, /Applications/*.app
            - Linux: xdg-open, gtk-launch, snap run, flatpak run, etc.
            - Windows: Start-Process, shell:AppsFolder, etc.
        
        Also maps common CLI tools to their app names (chrome -> Google Chrome).
        
        Args:
            command: The command string to parse
            
        Returns:
            List of app names found in the command (unique, order preserved)
        """
        ...

    @abstractmethod
    def find_openclaw_binary(self, cli_name: str = "openclaw") -> Optional[CliCommand]:
        """
        Find the OpenClaw CLI binary path.
        
        Searches in order:
            1. PATH (shutil.which)
            2. npm global prefix ($npm_prefix/bin/openclaw)
            3. pnpm global root ($pnpm_root/../bin/openclaw)
            4. Git source install (~/openclaw/openclaw.mjs)
            5. Platform-specific locations (macOS app bundle, Nix store)
            6. Common fallback paths
            7. npx fallback
        
        Args:
            cli_name: The CLI binary name (openclaw, moltbot, clawdbot)
            
        Returns:
            Command as list (e.g. ["/usr/bin/openclaw"] or ["npx", "openclaw"]), or None
        """
        ...
